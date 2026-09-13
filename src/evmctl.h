// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * evm_json: support for export and import
 *
 * Copyright (C) 2025 IBM
 *
 * Authors:
 * Ken Goldman kgoldman@us.ibm.com
 *
 * File evmctl.h
 */

#ifndef _EVMCTL_H
#define _EVMCTL_H

#include <stdbool.h>

struct command {
	char *name;
	int (*func)(struct command *cmd);
	int cmd;
	char *arg;
	char *msg;              /* extra info message */
};

typedef int (*find_cb_t)(const char *path);

int do_cmd(struct command *cmd, find_cb_t func);
int evm_hash_ima_common(const char *file,
			const char *hashalgo,
			unsigned char *hash_out, size_t *len);
int evm_calc_evm_hash(const char *file, const char *hash_algo,
		      unsigned char *evm_hash,
		      const unsigned char *ima_hash,
		      size_t ima_hash_len);
int evm_add_evm_signature(const char *filename, const char *sig_string);

#endif
