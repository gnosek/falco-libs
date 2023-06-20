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

#include <stdio.h>

#include "scap.h"
#include "strerror.h"
#include "strlcpy.h"
#include "scap-int.h"

#ifdef HAS_ENGINE_NODRIVER
#include "settings.h"
#endif

#include "scap_engine_util.h"
#include "scap_platform.h"

#define SCAP_HANDLE_T void
#include "scap_engines.h"
#include "scap_platforms.h"

const char* scap_getlasterr(scap_t* handle)
{
	return handle ? handle->m_lasterr : "null scap handle";
}

int32_t scap_init_int(scap_t* handle, scap_open_args* oargs, const struct scap_vtable* vtable, struct scap_platform* platform)
{
	int32_t rc;

	//
	// Preliminary initializations
	//
	handle->m_mode = vtable->mode;
	handle->m_vtable = vtable;
	handle->m_platform = platform;

	handle->m_engine.m_handle = handle->m_vtable->alloc_handle(handle, handle->m_lasterr);
	if(!handle->m_engine.m_handle)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error allocating the engine structure");
		return SCAP_FAILURE;
	}

	handle->m_debug_log_fn = oargs->debug_log_fn;

	if(handle->m_vtable->init && (rc = handle->m_vtable->init(handle, oargs)) != SCAP_SUCCESS)
	{
		return rc;
	}

	rc = check_api_compatibility(handle->m_vtable, handle->m_engine, handle->m_lasterr);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	scap_stop_dropping_mode(handle);

	if((rc = scap_platform_init(handle->m_platform, handle->m_lasterr, handle->m_engine, oargs)) != SCAP_SUCCESS)
	{
		return rc;
	}

	return SCAP_SUCCESS;
}

scap_t* scap_alloc(void)
{
	return calloc(1, sizeof(scap_t));
}

uint32_t scap_restart_capture(scap_t* handle)
{
	if(handle->m_vtable->savefile_ops)
	{
		return handle->m_vtable->savefile_ops->restart_capture(handle);
	}
	else
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "capture restart supported only in capture mode");
		return SCAP_FAILURE;
	}
}

void scap_deinit(scap_t* handle)
{
	if(handle->m_platform)
	{
		scap_platform_close(handle->m_platform);
		scap_platform_free(handle->m_platform);
	}

	if(handle->m_vtable)
	{
		/* The capture should be stopped before
		 * closing the engine, here we only enforce it.
		 * Please note that there are some corner cases in which
		 * we call `scap_close` before the engine is validated
		 * so we need to pay attention to NULL pointers in the
		 * following v-table methods.
		 */
		handle->m_vtable->stop_capture(handle->m_engine);
		handle->m_vtable->close(handle->m_engine);
		handle->m_vtable->free_handle(handle->m_engine);
	}
}

void scap_free(scap_t* handle)
{
	//
	// Release the handle
	//
	free(handle);
}

void scap_close(scap_t* handle)
{
	scap_deinit(handle);
	scap_free(handle);
}

uint64_t scap_get_engine_flags(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_flags(handle->m_engine);
	}
	return 0;
}

uint32_t scap_get_ndevs(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_n_devs(handle->m_engine);
	}
	return 1;
}

int32_t scap_readbuf(scap_t* handle, uint32_t cpuid, OUT char** buf, OUT uint32_t* len)
{
	// engines do not even necessarily have a concept of a buffer
	// that you read events from
	return SCAP_NOT_SUPPORTED;
}

uint64_t scap_max_buf_used(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_max_buf_used(handle->m_engine);
	}
	return 0;
}

int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	int32_t res = SCAP_FAILURE;
	if(handle->m_vtable)
	{
		res = handle->m_vtable->next(handle->m_engine, pevent, pcpuid);
	}
	else
	{
		ASSERT(false);
		res = SCAP_FAILURE;
	}

	if(res == SCAP_SUCCESS)
	{
		handle->m_evtcnt++;
	}

	return res;
}

//
// Return the number of dropped events for the given handle.
//
int32_t scap_get_stats(scap_t* handle, OUT scap_stats* stats)
{
	if(stats == NULL)
	{
		return SCAP_FAILURE;
	}

	stats->n_evts = 0;
	stats->n_drops = 0;
	stats->n_drops_buffer = 0;
	stats->n_drops_buffer_clone_fork_enter = 0;
	stats->n_drops_buffer_clone_fork_exit = 0;
	stats->n_drops_buffer_execve_enter = 0;
	stats->n_drops_buffer_execve_exit = 0;
	stats->n_drops_buffer_connect_enter = 0;
	stats->n_drops_buffer_connect_exit = 0;
	stats->n_drops_buffer_open_enter = 0;
	stats->n_drops_buffer_open_exit = 0;
	stats->n_drops_buffer_dir_file_enter = 0;
	stats->n_drops_buffer_dir_file_exit = 0;
	stats->n_drops_buffer_other_interest_enter = 0;
	stats->n_drops_buffer_other_interest_exit = 0;
	stats->n_drops_scratch_map = 0;
	stats->n_drops_pf = 0;
	stats->n_drops_bug = 0;
	stats->n_preemptions = 0;

	if(handle->m_vtable)
	{
		return handle->m_vtable->get_stats(handle->m_engine, stats);
	}

	ASSERT(false);
	return SCAP_FAILURE;
}

//
// Return engine statistics (including counters and `bpftool prog show` like stats)
//
const struct scap_stats_v2* scap_get_stats_v2(scap_t* handle, uint32_t flags, OUT uint32_t* nstats, OUT int32_t* rc)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_stats_v2(handle->m_engine, flags, nstats, rc);
	}
	ASSERT(false);
	*nstats = 0;
	*rc = SCAP_FAILURE;
	return NULL;
}

//
// Stop capturing the events
//
int32_t scap_stop_capture(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->stop_capture(handle->m_engine);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	ASSERT(false);
	return SCAP_FAILURE;
}

//
// Start capturing the events
//
int32_t scap_start_capture(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->start_capture(handle->m_engine);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_enable_tracers_capture(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_TRACERS_CAPTURE, 1, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_stop_dropping_mode(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_SAMPLING_RATIO, 1, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio)
{
	switch(sampling_ratio)
	{
		case 1:
		case 2:
		case 4:
		case 8:
		case 16:
		case 32:
		case 64:
		case 128:
			break;
		default:
			return snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "invalid sampling ratio size");
	}

	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_SAMPLING_RATIO, sampling_ratio, 1);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	ASSERT(false);
	return SCAP_FAILURE;
}

int32_t scap_set_snaplen(scap_t* handle, uint32_t snaplen)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_SNAPLEN, snaplen, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

int64_t scap_get_readfile_offset(scap_t* handle)
{
	if(handle->m_vtable->savefile_ops)
	{
		return handle->m_vtable->savefile_ops->get_readfile_offset(handle->m_engine);
	}
	else
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_get_readfile_offset only works on captures");
		return SCAP_FAILURE;
	}
}

int32_t scap_set_ppm_sc(scap_t* handle, ppm_sc_code ppm_sc, bool enabled)
{
	if (handle == NULL)
	{
		return SCAP_FAILURE;
	}
	if (ppm_sc >= PPM_SC_MAX)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s(%d) wrong param", __FUNCTION__, ppm_sc);
		ASSERT(false);
		return SCAP_FAILURE;
	}

	uint32_t op =  enabled ? SCAP_PPM_SC_MASK_SET : SCAP_PPM_SC_MASK_UNSET;

	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_PPM_SC_MASK, op, ppm_sc);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

int32_t scap_set_dropfailed(scap_t* handle, bool enabled) {
	if(handle && handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_DROP_FAILED, enabled, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

uint32_t scap_event_get_dump_flags(scap_t* handle)
{
	if(handle->m_vtable->savefile_ops)
	{
		return handle->m_vtable->savefile_ops->get_event_dump_flags(handle->m_engine);
	}
	else
	{
		return 0;
	}
}

int32_t scap_enable_dynamic_snaplen(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_DYNAMIC_SNAPLEN, 1, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

int32_t scap_disable_dynamic_snaplen(scap_t* handle)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_DYNAMIC_SNAPLEN, 0, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

uint64_t scap_ftell(scap_t *handle)
{
	if(handle->m_vtable->savefile_ops)
	{
		return handle->m_vtable->savefile_ops->ftell_capture(handle->m_engine);
	}
	else
	{
		return 0;
	}
}

void scap_fseek(scap_t *handle, uint64_t off)
{
	if(handle->m_vtable->savefile_ops)
	{
		handle->m_vtable->savefile_ops->fseek_capture(handle->m_engine, off);
	}
}

int32_t scap_get_n_tracepoint_hit(scap_t* handle, long* ret)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->get_n_tracepoint_hit(handle->m_engine, ret);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

bool scap_check_current_engine(scap_t *handle, const char* engine_name)
{
	if(engine_name && handle && handle->m_vtable)
	{
		return strcmp(handle->m_vtable->name, engine_name) == 0;
	}
	return false;
}

int32_t scap_set_fullcapture_port_range(scap_t* handle, uint16_t range_start, uint16_t range_end)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_FULLCAPTURE_PORT_RANGE, range_start, range_end);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

int32_t scap_set_statsd_port(scap_t* const handle, const uint16_t port)
{
	if(handle->m_vtable)
	{
		return handle->m_vtable->configure(handle->m_engine, SCAP_STATSD_PORT, port, 0);
	}

	snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "operation not supported");
	return SCAP_FAILURE;
}

uint64_t scap_get_driver_api_version(scap_t* handle)
{
	if(handle->m_vtable && handle->m_vtable->get_api_version)
	{
		return handle->m_vtable->get_api_version(handle->m_engine);
	}

	return 0;
}

uint64_t scap_get_driver_schema_version(scap_t* handle)
{
	if(handle->m_vtable && handle->m_vtable->get_schema_version)
	{
		return handle->m_vtable->get_schema_version(handle->m_engine);
	}

	return 0;
}
