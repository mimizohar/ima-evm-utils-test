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

#include "evm_json.h"

static const char *s_hash_algo = NULL;
static const char *s_evmfile = NULL;

static int bin2json(json_object *json_object,
		    const char *infile,
		    const unsigned char *data, size_t len);

/*
 * Define USE_FPRINTF before the below include.  Otherwise logging goes to
 * /var/log/messages.
 */
#define USE_FPRINTF
#include "imaevm.h"

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

	g_use_path = true;
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

