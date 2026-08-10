// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * evm_json: support for export and import
 *
 * Copyright (C) 2025 IBM
 *
 * Authors:
 * Ken Goldman kgoldman@us.ibm.com
 *
 * File evm_json.c
 */

#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "evm_json.h"
#include "utils.h"

/*
 * Define USE_FPRINTF before the below include.  Otherwise logging goes to
 * /var/log/messages.
 */
#define USE_FPRINTF
#include "imaevm.h"

static const char *s_hash_algo = NULL;
static const char *s_evmfile = NULL;

/*
 * bin2hexascii - write the binary 'data' of length 'len' to 'string'
 *
 * @string: output hexascii
 * @data: input binary
 * @len: length of the input binary
 *
 * bin2hexascii assumes that string is preallocated to 2 * len +1 for the NUL
 * terminator.
 *
 * Returns:
 *	0 success
 *	-1 error
 */
static int bin2hexascii(char *string,
			const unsigned char *data, size_t len)
{
	size_t i = 0;

	while (i < len) {
		sprintf(string, "%02x", data[i]);
		string += 2;
		i++;
	}
	*string = '\0';
	return 0;
}

/*
 * bin2json - Append a key/value pair to the (already allocated) json object
 * json_object.
 *
 * @json_object: an already allocated json object
 * @infile: string json key
 * @data: binary json value
 * @len: length of the data
 *
 * The key is infile as text, the value is binary data converted here to
 * hexascii.
 *
 * Returns:
 *	0 success
 *	-1 error
 */
static int bin2json(json_object *json_object,
		    const char *infile,
		    const unsigned char *data, size_t len)
{
	int err = 0;
	char *string = NULL;
	size_t string_length = (len * 2) + 1;

	string = malloc(string_length);			/* freed @1 */
	if (string == NULL) {
		log_err("cannot malloc %zu bytes\n", string_length);
		err = -1;
		goto out;
	}
	/* convert the binary data to the string */
	err = bin2hexascii(string, data, len);
	if (err) {
		goto out;
	}
	log_debug("json value hexascii string: %s\n", string);
	/* add the key/value pair to the json object */
	/*
	 * at export time, the json_object_to_json_string_ext() function escapes
	 * characters in the file name, so no special handling is needed here
	 */
	json_object_object_add(json_object,
			       infile,		/* key */
			       json_object_new_string(string));
 out:
	free(string);	/* @1*/
	return err;
}

/*
 * read_file - read a file into 'buffer' of 'length'.
 *
 * @buffer: output, contents of the file plus NUL terminator
 * @length: output, length of string
 * @filename: input, name of file to be read

 * 'buffer' must be NULL on entry (to prevent memory leaks) and must be freed by
 * the caller. The call adds the NUL terminator.
 *
 * Returns:
 *	0 success
 *	-1 error
 */
static int read_file(char **buffer,     /* must be freed by the caller */
		     size_t *length,
		     const char *filename)
{
	int err = 0;
	int irc = 0;
	ssize_t	src = 0;
	int fd = -1;
	struct stat st;

	if (*buffer != NULL) {
		log_err("*buffer is not NULL\n");
		err = -1;
		goto out;
	}
	fd = open(filename, O_RDONLY);	/* closed @1 */
	if (fd == -1) {
		log_err("File %s open for read failed\n", filename);
		err = -1;
		goto out;
	}
	irc = fstat(fd, &st);
	if (irc == -1) {
		log_err("File %s fstat failed\n", filename);
		err = -1;
		goto out;
	}
	if (st.st_size < 0) {
		log_err("File %s fstat returned negative size\n", filename);
		err = -1;
		goto out;
	}
	if (st.st_size > (SIZE_MAX - 1)) {
		log_err("File %s fstat returned size greater that SIZE_MAX\n",
			filename);
		err = -1;
		goto out;
	}
	*length = (size_t)st.st_size;
	if (*length == 0) {
		log_err("Filename %s length 0\n", filename);
		err = -1;
		goto out;
	}
	*buffer = malloc((*length) + 1);	/* freed by caller */
	if (*buffer == NULL) {
		log_err("Allocating %zu bytes\n", *length);
		err = -1;
		goto out;
	}
	src = read(fd, *buffer, *length);
	if (src <= 0) {
		log_err("read %s\n", filename);
		err = -1;
		goto out;
	} else {
		if ((size_t)src != *length) {
			log_err("Reading %s, %zu bytes, got %zu\n",
				filename, *length, (size_t)src);
			err = -1;
			goto out;
		}
	}
	(*buffer)[*length] = '\0';		/* NUL terminate */
 out:
	if (fd != -1) {
		irc = close(fd);		/* @1 */
		if (irc == -1) {
			log_err("Closing %s\n", filename);
			err = -1;
		}
	}
	if (err) {
		free(*buffer);
		*buffer = NULL;
	}
	return err;
}

/* Must use a static here because do_cmd() cannot take other variables */
static json_object *s_json_object = NULL;	/* for export */

/*
 * export_evmhash - calculates and outputs the EVM hash (digest to be signed) in
 * json.
 *
 * @file: string file name to be processed
 *
 * This is the recursive callback for cmd_export_evmhash(). Each hash is
 * appended to the global json object.
 *
 * Returns
 *	-1 error
 *	0 success
 */
static int export_evmhash(const char *file)
{
	unsigned char ima_hash[MAX_DIGEST_SIZE + 2]; /* +2 byte xattr header */
	unsigned char evm_hash[MAX_DIGEST_SIZE];
	size_t ima_hash_len;
	size_t evm_hash_len;
	int err;

	log_debug("in file: %s out file: %s\n",
		  file, s_evmfile);
	/* hash the file, prepend the header */
	err = evm_hash_ima_common(file, s_hash_algo, ima_hash, &ima_hash_len);
	if (err != 0) {
		return err;
	}
	/* hash the file metadata, which will include the file data hash */
	err = evm_calc_evm_hash(file, s_hash_algo, evm_hash,
				ima_hash, ima_hash_len);
	if (err <= 1) {		/* errors are actually <= 0 */
		return -1;
	}
	evm_hash_len = (size_t)err;
	log_debug("evm hash: ");
	log_dump(evm_hash, evm_hash_len);
#if 0
	/* output the binary hash for local test signing */
	err = bin2file(s_evmfile, "bin", evm_hash, evm_hash_len);
	if (err == 0) {
		return -1;
	}
#endif
	/* add the key / value pair to the json object */
	/* s_json_object is static because do_cmd() cannot pass variables */
	err = bin2json(s_json_object,
		       file,			/* key */
		       evm_hash, evm_hash_len);	/* value */
	return err;
}

/*
 * evm_export_evmhash - export a file of hashes in json format
 *
 * @cmd: pointer to a CLI command structure
 * @evmfile: string json out file of hashes
 * @hash_algo: signing hash algorithm string
 *
 * This is the callback for the export_evmhash command. It uses do_cmd() to
 * call export_evmhash() against either one file command line argument or
 * recursively through a directory command line argument.
 *
 * For both one file and recursive, the json file is written once here.
 *
 * Returns:
 *	-1 error
 *	0 success
 */
int evm_export_evmhash(struct command *cmd,
		       const char *evmfile,
		       const char *hash_algo)
{
	int err = 0;
	const char *json_string = NULL;
	size_t len;		/* length of serialized json record */
	FILE *outfile = NULL;	/* the export output json file */

	if (evmfile == NULL) {
		log_err("missing export json file name\n");
		err = -1;
		goto out;
	}
	s_hash_algo = hash_algo;	/* save for the callback */
	s_evmfile = evmfile;		/* save for the callback */
	/*
	 * create the json object once because do_cmd() can recurse down through
	 * subdirectories
	 */
	s_json_object = json_object_new_object();	/* @2 */
	if (s_json_object == NULL) {
		log_err("could not allocate json object for export\n");
		err = -1;
		goto out;
	}
	/*
	 * open the file once before do_cmd(), because it can change and then
	 * recurse down through subdirectories
	 */
	log_info("json filename %s\n", evmfile);
	outfile = fopen(evmfile, "w");	/* closed @1 */
	if (outfile == NULL) {
		log_err("output file %s open failed\n", evmfile);
		err = -1;
		goto out;
	}
	err = do_cmd(cmd, export_evmhash);	/* this potentially recurses */
	if (err) {
		goto out;
	}
	/* convert the json object to a string */
	json_string = json_object_to_json_string_ext(s_json_object,
						     JSON_C_TO_STRING_PRETTY);
	if (json_string == NULL) {
		log_err("could not convert export json object to string\n");
		err = -1;
		goto out;
	}
	len = strlen(json_string);
	if (len == 0) {
		log_err("export json object is zero length\n");
		err = -1;
		goto out;
	}
	log_info("%s\n", json_string);
	err = fwrite(json_string, len, 1, outfile);
	if (err == 1) {		/* success fwrite return */
		err = 0;
	} else {
		log_err("export json fwrite %s failed\n", evmfile);
		err = -1;
	}
 out:
	/* cleanup, whether or not there is an error */
	if (outfile != NULL) {
		fclose(outfile);		/* @1 */
	}
	if (s_json_object != NULL) {
		json_object_put(s_json_object); /* @2 */
		s_json_object = NULL;
	}
	return err;
}

/*
 * evm_sign_exported_evmhash - sign a file of hashes in json format
 *
 * @cmd: pointer to a CLI command structure
 * @hash_algo: signing hash algorithm string
 * @keyfile: signing key in pem format
 * @infile: string json input file of hashes
 * @outfile: string json output file of signatures
 *
 * This is the callback for the sign_exported_evmhash command.
 *
 * evm_sign_exported_evmhash reads the json file of hashes, iterates through
 * each file name (the json key), reads the hash (the json value), and signs the
 * hash with the private key. It writes the json file of file names (the json
 * key) and signatures (the json value).
 *
 * The hash algorithm is taken from the --hashalgo argument.
 * The signing private key is taken from the --key argument.
 * The hash file is taken from the --infile argument.
 * The signature file is taken from the --outfile argument.
 *
 * Returns:
 *
 *	0 success
 *	-1 error
 */
int evm_sign_exported_evmhash(struct command *cmd __attribute__((unused)),
			      const char *hash_algo,
			      const char *keyfile,
			      const char *infile,
			      const char *outfilename)
{
	int err = 0;
	char *buffer = NULL;
	size_t length = 0;
	json_object *root = NULL;		/* input */
	json_type type;
	json_object *out_json_object = NULL;    /* for output */
	unsigned char digest[MAX_DIGEST_SIZE];	/* binary digest */
	size_t digestlen;			/* length of binary */
	size_t digeststrlen;			/* length of string */
	unsigned char *signature = NULL;
	size_t siglen;
	EVP_PKEY *pkey = NULL;
	FILE *fp = NULL;
	FILE *outfile = NULL;
	const char *json_string = NULL;
	size_t len;
	/*
	 * read the private key
	 */
	fp = fopen(keyfile, "r");	/* closed @1 */
	if (fp == NULL) {
		log_err("Failed to open keyfile: %s\n", keyfile);
		err = -1;
		goto out;
	}
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);	/* freed @2 */
	if (pkey == NULL) {
		log_err("Failed to read keyfile: %s\n", keyfile);
		err = -1;
		goto out;
	}
	/*
	 * read the json hash file
	 */
	/* read the json file to a NUL terminated string */
	err = read_file(&buffer,	      /* freed @3 */
			&length,
			infile);
	if (err != 0)
		goto out;
	log_debug("json contents:\n%s\n", buffer);
	/* parse the import string to a json object */
	root = json_tokener_parse(buffer);	/* freed @4 */
	if (root == NULL) {
		log_err("Input file %s parse failed\n", infile);
		err = -1;
		goto out;
	}
	type = json_object_get_type(root);
	if (type != json_type_object) {
		log_err("Input file %s parse type failed\n", infile);
		err = -1;
		goto out;
	}
	out_json_object = json_object_new_object();       /* freed @5 */
	if (out_json_object == NULL) {
		log_err("Could not allocate json object for %s\n", outfilename);
		err = -1;
		goto out;
	}
	/* for each key (file name) / value (hash) pair */
	json_object_object_foreach(root,
				   filename,		/* key char * */
				   json_hash) {		/* json object * */
		const char *hash_string = NULL;

		log_debug("Filename: %s\n", filename);
		/* get the value (hash) associated with the key (file
		 * name)
		 */
		hash_string = json_object_get_string(json_hash);
		log_debug("Hash: %s\n", hash_string);

		digeststrlen = strlen(hash_string);
		if ((digeststrlen % 2) != 0) {
			log_err("hash string length is odd\n");
			err = -1;
			goto out;
		}
		digestlen = digeststrlen / 2;
		if (digestlen > sizeof(digest)) {
			log_err("hash is too large\n");
			err = -1;
			goto out;
		}
		err = hex2bin(digest, hash_string, digestlen);
		if (err != 0) {
			log_err("File hash is not hexascii %s\n",
				hash_string);
			err = -1;
			goto out;
		}
		log_debug("Binary hash\n");
		log_dump(digest, digestlen);
		err = imaevm_sign_hash_raw(hash_algo,
					   pkey,
					   digest,
					   digestlen,
					   &signature,	/* freed @7 */
					   &siglen);
		if (err != 0) {
			log_err("imaevm_sign_hash_raw() failed\n");
			err = -1;
			goto out;
		}
		err = bin2json(out_json_object,
			       filename,		/* key */
			       signature, siglen);	/* value */
		free(signature);	/* @1 */
		signature = NULL;
		if (err != 0) {
			log_err("bin2json() failed\n");
			err = -1;
			goto out;
		}
	}
	/* convert the json object to a string */
	json_string = json_object_to_json_string_ext(out_json_object,
						     JSON_C_TO_STRING_PRETTY);
	if (json_string == NULL) {
		log_err("Could not convert json object to string\n");
		err = -1;
		goto out;
	}
	len = strlen(json_string);
	if (len == 0) {
		log_err("json object is zero length\n");
		err = -1;
		goto out;
	}
	log_info("%s\n", json_string);
	outfile = fopen(outfilename, "w");	/* closed @6 */
	if (outfile == NULL) {
		log_err("output file %s open failed\n", outfilename);
		err = -1;
		goto out;
	}
	err = fwrite(json_string, len, 1, outfile);
	if (err == 1) {		/* normal fwrite return */
		err = 0;
	} else {
		err = -1;
	}

 out:
	if (fp != NULL) {
		fclose(fp);		/* @1 */
	}
	EVP_PKEY_free(pkey);		/* @2 */
	free(buffer);			/* @3 */
	if (root != NULL) {
		json_object_put(root);	/* @4 */
		root = NULL;
	}
	if (out_json_object != NULL) {
		json_object_put(out_json_object); /* @5 */
		out_json_object = NULL;
	}
	if (outfile != NULL) {
		fclose(outfile);	/* @6 */
	}
	return err;
}
