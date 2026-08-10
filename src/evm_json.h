// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * evm_json: support for export and import
 *
 * Copyright (C) 2025 IBM
 *
 * Authors:
 * Ken Goldman kgoldman@us.ibm.com
 *
 * File evm_json.h
 */

#ifndef _EVM_JSON_H
#define _EVM_JSON_H

#include "evmctl.h"

#ifdef EVM_HAS_JSON

#include <json-c/json.h>

int evm_export_evmhash(struct command *cmd,
		       const char *evmfile,
		       const char *hash_algo);

# else	/* no json */

#define USE_FPRINTF
#include "imaevm.h"

struct json_object;

static inline int evm_export_evmhash(struct command *cmd,
				     const char *evmfile,
				     const char *hash_algo)
{
	log_err("json-c library isn't available\n");
	return -1;
}

#endif	/* EVM_HAS_JSON */

#endif
