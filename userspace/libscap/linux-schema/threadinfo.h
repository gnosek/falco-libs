/*
Copyright (C) 2022 The Falco Authors.

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

#include <stdint.h>

#include "scap_const.h"
#include "scap_limits.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "uthash.h"

typedef struct scap_fdinfo scap_fdinfo;

/*!
  \brief Process information
*/
typedef struct scap_threadinfo
{
	uint64_t tid; ///< The thread/task id.
	uint64_t pid; ///< The id of the process containing this thread. In single thread processes, this is equal to tid.
	uint64_t ptid; ///< The id of the thread that created this thread.
	uint64_t sid; ///< The session id of the process containing this thread.
	uint64_t vpgid; ///< The process group of this thread, as seen from its current pid namespace
	char comm[SCAP_MAX_PATH_SIZE+1]; ///< Command name (e.g. "top")
	char exe[SCAP_MAX_PATH_SIZE+1]; ///< argv[0] (e.g. "sshd: user@pts/4")
	char exepath[SCAP_MAX_PATH_SIZE+1]; ///< full executable path
	bool exe_writable; ///< true if the original executable is writable by the same user that spawned it.
	bool exe_upper_layer; //< True if the original executable belongs to upper layer in overlayfs
	char args[SCAP_MAX_ARGS_SIZE+1]; ///< Command line arguments (e.g. "-d1")
	uint16_t args_len; ///< Command line arguments length
	char env[SCAP_MAX_ENV_SIZE+1]; ///< Environment
	uint16_t env_len; ///< Environment length
	char cwd[SCAP_MAX_PATH_SIZE+1]; ///< The current working directory
	int64_t fdlimit; ///< The maximum number of files this thread is allowed to open
	uint32_t flags; ///< the process flags.
	uint32_t uid; ///< user id
	uint32_t gid; ///< group id
	uint64_t cap_permitted; ///< permitted capabilities
	uint64_t cap_effective; ///< effective capabilities
	uint64_t cap_inheritable; ///< inheritable capabilities
	uint64_t exe_ino; ///< executable inode ino
	uint64_t exe_ino_ctime; ///< executable inode ctime (last status change time)
	uint64_t exe_ino_mtime; ///< executable inode mtime (last modification time)
	uint64_t exe_ino_ctime_duration_clone_ts; ///< duration in ns between executable inode ctime (last status change time) and clone_ts
	uint64_t exe_ino_ctime_duration_pidns_start; ///< duration in ns between pidns start ts and executable inode ctime (last status change time) if pidns start predates ctime
	uint32_t vmsize_kb; ///< total virtual memory (as kb)
	uint32_t vmrss_kb; ///< resident non-swapped memory (as kb)
	uint32_t vmswap_kb; ///< swapped memory (as kb)
	uint64_t pfmajor; ///< number of major page faults since start
	uint64_t pfminor; ///< number of minor page faults since start
	int64_t vtid;  ///< The virtual id of this thread.
	int64_t vpid; ///< The virtual id of the process containing this thread. In single thread threads, this is equal to vtid.
	uint64_t pidns_init_start_ts; ///<The pid_namespace init task start_time ts.
	char cgroups[SCAP_MAX_CGROUPS_SIZE];
	uint16_t cgroups_len;
	char root[SCAP_MAX_PATH_SIZE+1];
	int filtered_out; ///< nonzero if this entry should not be saved to file
	scap_fdinfo* fdlist; ///< The fd table for this process
	uint64_t clone_ts; ///< When the clone that started this process happened.
	int32_t tty; ///< Number of controlling terminal
    int32_t loginuid; ///< loginuid (auid)

	UT_hash_handle hh; ///< makes this structure hashable
}scap_threadinfo;


typedef void (*proc_entry_callback)(void* context,
				    int64_t tid,
				    scap_threadinfo* tinfo,
				    scap_fdinfo* fdinfo);

struct scap_proclist
{
	proc_entry_callback m_proc_callback;
	void* m_proc_callback_context;

	scap_threadinfo* m_proclist;
};

#ifdef __cplusplus
}
#endif
