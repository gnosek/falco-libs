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

// this header is designed to be useful to platform *implementors*
// i.e. different platforms

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SCAP_HANDLE_T
#define SCAP_HANDLE_T void
#endif

#include "engine_handle.h"
#include "scap_machine_info.h"

#include "linux-schema/schema.h"

struct scap_dumper;
struct scap_open_args;
struct scap_platform;
struct scap_proclist;
struct scap_reader;
struct ppm_proclist_info;

#define DUMP_FLAGS_RESCAN_PROC (1<<0)

#define READ_FLAGS_IMPORT_USERS (1<<0)

// a method table for platform-specific operations
struct scap_platform_vtable
{
	// initialize the platform-specific structure
	// at this point the engine is fully initialized and operational
	int32_t (*init_platform)(struct scap_platform* platform, char* lasterr, struct scap_engine_handle engine, struct scap_open_args* oargs);

	// refresh the interface list and place it inside
	// platform->m_addrlist
	int32_t (*refresh_addr_list)(struct scap_platform* platform);

	struct scap_threadinfo* (*get_proc)(struct scap_platform*, struct scap_proclist* proclist, int64_t tid, bool scan_sockets);

	int32_t (*refresh_proc_table)(struct scap_platform*, struct scap_proclist* proclist);
	bool (*is_thread_alive)(struct scap_platform*, int64_t pid, int64_t tid, const char* comm);
	int32_t (*get_threadlist)(struct scap_platform* platform, struct ppm_proclist_info **procinfo_p, char *lasterr);

	int32_t (*read_block)(struct scap_platform *platform, struct scap_reader *r, uint32_t block_length,
			      uint32_t block_type, uint64_t flags, char *error);

	int32_t (*dump_state)(struct scap_platform *platform, struct scap_dumper *d, uint64_t flags);

	// do *not* use this in any new code
	struct scap_linux_storage* (*get_linux_storage)(struct scap_platform* platform);

	// close the platform structure
	// clean up all data, make it ready for another call to `init_platform`
	int32_t (*close_platform)(struct scap_platform* platform);

	// free the structure
	// it must have been previously closed (using `close_platform`)
	// to ensure there are no memory leaks
	void (*free_platform)(struct scap_platform* platform);
};

// the parts of the platform struct shared across all implementations
// this *must* be the first member of all implementations
// (the pointers are cast back&forth between the two)
struct scap_platform
{
	const struct scap_platform_vtable* m_vtable;
};

#ifdef __cplusplus
};
#endif
