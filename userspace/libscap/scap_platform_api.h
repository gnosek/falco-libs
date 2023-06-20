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

#include <stdbool.h>
#include <stdint.h>

// this header is designed to be useful to scap consumers,
// using the scap_t wrapper functions

#ifdef __cplusplus
extern "C" {
#endif

struct ppm_proclist_info;
struct scap;
struct scap_addrlist;
struct _scap_machine_info;
struct scap_threadinfo;

// Get the information about a process.
// The returned pointer must be freed via scap_proc_free by the caller.
struct scap_threadinfo* scap_proc_get(struct scap* handle, int64_t tid, bool scan_sockets);

int32_t scap_refresh_proc_table(struct scap* handle);

/*!
  \brief Get the process list for the given capture instance

  \param handle Handle to the capture instance.

  \return Pointer to the process list.

  for live captures, the process list is created when the capture starts by scanning the
  proc file system. For offline captures, it is retrieved from the file.
  The process list contains information about the processes that were already open when
  the capture started. It can be traversed with uthash, using the following syntax:

  \code
  scap_threadinfo *pi;
  scap_threadinfo *tpi;
  scap_threadinfo *table = scap_get_proc_table(phandle);

  HASH_ITER(hh, table, pi, tpi)
  {
    // do something with pi
  }
  \endcode

  Refer to the documentation of the \ref scap_threadinfo struct for details about its
  content.
*/
struct scap_threadinfo* scap_get_proc_table(struct scap* handle);

// Check if the given thread exists in /proc
bool scap_is_thread_alive(struct scap* handle, int64_t pid, int64_t tid, const char* comm);

/*!
  \brief Get the process list.
*/
int32_t scap_get_threadlist(struct scap* handle, struct ppm_proclist_info** proclist_p);

#ifdef __cplusplus
};
#endif
