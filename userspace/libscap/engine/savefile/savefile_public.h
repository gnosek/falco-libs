// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <libscap/scap_procs.h>

#define SAVEFILE_ENGINE "savefile"

#ifdef __cplusplus
extern "C" {
#endif
struct scap_platform;
typedef struct scap_reader scap_reader_t;

typedef int32_t (*scap_block_parser_t)(scap_reader_t *r,
	uint32_t block_type,
	uint32_t block_length,
	bool import_users,
	void *arg,
	char *error);

struct scap_savefile_engine_params {
	int fd;                 ///< If non-zero, will be used instead of fname.
	const char* fname;      ///< The name of the file to open.
	uint64_t start_offset;  ///< Used to start reading a capture file from an arbitrary offset. This
	                        ///< is leveraged when opening merged files.
	uint32_t fbuffer_size;  ///< If non-zero, offline captures will read from file using a buffer of
	                        ///< this size.

	scap_block_parser_t block_parser; ///< Used to parse each block in savefile (except the event
	                                  ///< block). If null, non-event blocks are ignored
	void* block_parser_arg;           ///< Argument to pass to the block parser
};

struct scap_platform* scap_savefile_alloc_platform(proc_entry_callback proc_callback,
                                                   void* proc_callback_context);

struct scap_linux_block_parser_args {
	struct scap_platform* platform;

};

int32_t scap_parse_linux_block(scap_reader_t *r,
	uint32_t block_type,
	uint32_t block_length,
	bool import_users,
	void *platform, /* actually struct scap_platform* but make it usable as a block parser */
	char *error);

#ifdef __cplusplus
};
#endif
