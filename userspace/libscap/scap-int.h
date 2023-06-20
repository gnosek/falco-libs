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

////////////////////////////////////////////////////////////////////////////
// Private definitions for the scap library
////////////////////////////////////////////////////////////////////////////

#pragma once

#ifndef SCAP_HANDLE_T
#define SCAP_HANDLE_T void
#endif

#include "engine_handle.h"
#include "scap_vtable.h"

#include "settings.h"
#include "scap_assert.h"
#include "scap_suppress.h"

#ifdef __linux__
#include "linux-schema/event_schema.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// The open instance handle
//
struct scap
{
	const struct scap_vtable *m_vtable;
	struct scap_engine_handle m_engine;
	struct scap_platform *m_platform;

	scap_mode_t m_mode;
	char m_lasterr[SCAP_LASTERR_SIZE];

	uint64_t m_evtcnt;

	// Function which may be called to log a debug event
	void(*m_debug_log_fn)(const char* msg);
};

//
// Internal library functions
//

int32_t scap_proc_fill_cgroups(char* error, int cgroup_version, struct scap_threadinfo* tinfo, const char* procdirname);

int32_t scap_proc_fill_pidns_start_ts(char* error, struct scap_threadinfo* tinfo, const char* procdirname);

// Determine whether or not the provided event should be suppressed,
// based on its event type and parameters. May update the set of
// suppressed tids as a side-effect.
//
// Returns SCAP_FAILURE if we tried to add the tid to the suppressed
// tid set, but it could *not* be added, SCAP_SUCCESS otherwise.
int32_t scap_check_suppressed(struct scap_suppress *suppress, scap_evt *pevent,
			      bool *suppressed, char *error);

//
// Retrieve machine info.
//
void scap_retrieve_machine_info(scap_machine_info* machine_info, uint64_t boot_time);

//
//
// Useful stuff
//
#ifndef MIN
#define MIN(X,Y) ((X) < (Y)? (X):(Y))
#define MAX(X,Y) ((X) > (Y)? (X):(Y))
#endif

#ifdef __cplusplus
}
#endif
