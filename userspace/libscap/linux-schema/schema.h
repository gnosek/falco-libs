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

#include "linux-schema/fdinfo.h"
#include "linux-schema/ifinfo.h"
#include "linux-schema/threadinfo.h"
#include "linux-schema/userinfo.h"
#include "scap_machine_info.h"

#ifdef __cplusplus
extern "C" {
#endif

struct scap_open_args;

struct scap_linux_storage
{
	scap_machine_info m_machine_info;

	struct scap_addrlist *m_addrlist;
	struct scap_userlist *m_userlist;
	struct scap_proclist m_proclist;
};

int32_t scap_linux_storage_init(struct scap_linux_storage* storage, char* lasterr, struct scap_open_args* oargs);
int32_t scap_linux_storage_close(struct scap_linux_storage* storage);

// Free the process table
void scap_proc_free_table(struct scap_proclist* proclist);
// Return the process info entry given a tid
// Free an fd table and set it to NULL when done
void scap_fd_free_table(scap_fdinfo** fds);
// Free a process' fd table
void scap_fd_free_proc_fd_table(scap_threadinfo* pi);
// Add the file descriptor info pointed by fdi to the fd table for process pi.
// Note: silently skips if fdi->type is SCAP_FD_UNKNOWN.
int32_t scap_add_fd_to_proc_table(struct scap_proclist* proclist, scap_threadinfo* pi, scap_fdinfo* fdi, char *error);
// Free a previously allocated list of interfaces
void scap_free_iflist(scap_addrlist* ifhandle);
// Free a previously allocated list of users
void scap_free_userlist(scap_userlist* uhandle);
// Allocate a file descriptor
int32_t scap_fd_allocate_fdinfo(scap_fdinfo **fdi, int64_t fd, scap_fd_type type);
// Free a file descriptor
void scap_fd_free_fdinfo(scap_fdinfo **fdi);


#ifdef __cplusplus
}
#endif