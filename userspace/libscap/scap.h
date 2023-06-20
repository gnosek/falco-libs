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

#include "scap_const.h"
#include "scap_platform_api.h"
#include "scap_stats_v2.h"

#include "linux-schema/schema.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
	\mainpage libscap documentation

	\section Introduction

	libscap is the low-level component that exports the following functionality:
	- live capture control (start/stop/pause...)
	- trace file management
	- event retrieval
	- extraction of system state from /proc

	This manual includes the following sections:
	- \ref scap_defs
	- \ref scap_functs
*/

///////////////////////////////////////////////////////////////////////////////
// Public structs and defines
///////////////////////////////////////////////////////////////////////////////

/** @defgroup scap_defs public definitions and structures
 *  @{
 */

//
// Forward declarations
//
typedef struct scap scap_t;
typedef struct ppm_evt_hdr scap_evt;

//
// Core types
//
#include <time.h>
#include <stdarg.h>
#include "uthash.h"
#include "../common/types.h"
#include "../../driver/ppm_api_version.h"
#include "../../driver/ppm_events_public.h"
#include "../../driver/capture_macro.h"
#ifdef _WIN32
#include <time.h>
#endif

#include "scap_limits.h"
#include "scap_open.h"
#include "scap_machine_info.h"

/* Include engine-specific params. */
#include <engine/bpf/bpf_public.h>
#include <engine/gvisor/gvisor_public.h>
#include <engine/kmod/kmod_public.h>
#include <engine/modern_bpf/modern_bpf_public.h>
#include <engine/nodriver/nodriver_public.h>
#include <engine/savefile/savefile_public.h>
#include <engine/source_plugin/source_plugin_public.h>
#include <engine/test_input/test_input_public.h>
#include <engine/udig/udig_public.h>

//
// The minimum API and schema versions the driver has to support before we can use it
//
// The reason to increment these would be a bug in the driver that userspace
// cannot or does not want to work around.
//
// Note: adding new events or event fields should not need a version bump
// here, since libscap has to suport old event formats anyway (for capture
// files).
//
// If a consumer relies on events or APIs added in a new version, it should
// call `scap_get_driver_api_version()` and/or `scap_get_driver_schema_version()`
// and handle the result
//
#define SCAP_MINIMUM_DRIVER_API_VERSION PPM_API_VERSION(4, 0, 0)
#define SCAP_MINIMUM_DRIVER_SCHEMA_VERSION PPM_API_VERSION(2, 0, 0)

// 
// This is the dimension we used before introducing the variable buffer size.
//
#define DEFAULT_DRIVER_BUFFER_BYTES_DIM 8 * 1024 * 1024

//
// Value for proc_scan_timeout_ms field in scap_open_args, to specify
// that scan should run to completion without any timeout imposed
//
#define SCAP_PROC_SCAN_TIMEOUT_NONE 0

//
// Value for proc_scan_log_interval_ms field in scap_open_args, to specify
// that no progress logging should be performed
//
#define SCAP_PROC_SCAN_LOG_NONE 0

/*!
  \brief Statistics about an in progress capture
*/
typedef struct scap_stats
{
	uint64_t n_evts; ///< Total number of events that were received by the driver.
	uint64_t n_drops; ///< Number of dropped events.
	uint64_t n_drops_buffer; ///< Number of dropped events caused by full buffer.
	uint64_t n_drops_buffer_clone_fork_enter;
	uint64_t n_drops_buffer_clone_fork_exit;
	uint64_t n_drops_buffer_execve_enter;
	uint64_t n_drops_buffer_execve_exit;
	uint64_t n_drops_buffer_connect_enter;
	uint64_t n_drops_buffer_connect_exit;
	uint64_t n_drops_buffer_open_enter;
	uint64_t n_drops_buffer_open_exit;
	uint64_t n_drops_buffer_dir_file_enter;
	uint64_t n_drops_buffer_dir_file_exit;
	uint64_t n_drops_buffer_other_interest_enter;
	uint64_t n_drops_buffer_other_interest_exit;
	uint64_t n_drops_scratch_map; ///< Number of dropped events caused by full frame scratch map.
	uint64_t n_drops_pf; ///< Number of dropped events caused by invalid memory access.
	uint64_t n_drops_bug; ///< Number of dropped events caused by an invalid condition in the kernel instrumentation.
	uint64_t n_preemptions; ///< Number of preemptions.
	uint64_t n_suppressed; ///< Number of events skipped due to the tid being in a set of suppressed tids.
	uint64_t n_tids_suppressed; ///< Number of threads currently being suppressed.
}scap_stats;

#define USERBLOCK_TYPE_USER 0
#define USERBLOCK_TYPE_GROUP 1

//
// Misc definitions
//

/*!
  \brief Indicates if an event is an enter one or an exit one
*/
typedef enum event_direction
{
	SCAP_ED_IN = 0,
	SCAP_ED_OUT = 1
}event_direction;

/*!
  \brief Flags for scap_dump
*/
typedef enum scap_dump_flags
{
	SCAP_DF_NONE = 0,
	SCAP_DF_STATE_ONLY = 1,		///< The event should be used for state update but it should
								///< not be shown to the user
	SCAP_DF_TRACER = (1 << 1),	///< This event is a tracer
	SCAP_DF_LARGE = (1 << 2)	///< This event has large payload (up to UINT_MAX Bytes, ie 4GB)
}scap_dump_flags;

/*!
  \brief Structure used to pass a buffer and its size.
*/
struct scap_sized_buffer {
	void* buf;
	size_t size;
};
typedef struct scap_sized_buffer scap_sized_buffer;

/*!
  \brief Structure used to pass a read-only buffer and its size.
*/
struct scap_const_sized_buffer {
	const void* buf;
	size_t size;
};
typedef struct scap_const_sized_buffer scap_const_sized_buffer;

/*@}*/

///////////////////////////////////////////////////////////////////////////////
// Structs and defines used internally
///////////////////////////////////////////////////////////////////////////////

#define IN
#define OUT

///////////////////////////////////////////////////////////////////////////////
// API functions
///////////////////////////////////////////////////////////////////////////////

/** @defgroup scap_functs API Functions
 *  @{
 */

/*!
  \brief Allocate a handle

  \return The capture instance handle in case of success. NULL in case of failure.
  Before the handle can be used, \ref scap_init must be called on it.
*/
scap_t* scap_alloc(void);

/*!
  \brief Initialize a handle

  \param oargs a \ref scap_open_args structure containing the open parameters.

  \return the scap return code describing whether the function succeeded or failed.
  The error string in case the function fails is accessible via \ref scap_getlasterr

  If this function fails, the only thing you can safely do with the handle is to call
  \ref scap_deinit on it.
*/
int32_t scap_init(scap_t* handle, scap_open_args* oargs);

/*!
  \brief Allocate and initialize a handle

  This function combines scap_alloc and scap_init in a single call.
  It's more convenient to use if you do not rely on having access to the handle
  address while it's being initialized.

  One notable example where you do need the address is the process callback:
  without calling scap_alloc/scap_init it can't know where the handle is
  (it's first called from scap_init)

  \param oargs a \ref scap_open_args structure containing the open parameters.
  \param error Pointer to a buffer that will contain the error string in case the
    function fails. The buffer must have size SCAP_LASTERR_SIZE.
  \param rc Integer pointer that will contain the scap return code in case the
    function fails.

  \return The capture instance handle in case of success. NULL in case of failure.
*/
scap_t* scap_open(scap_open_args* oargs, char *error, int32_t *rc);

/*!
  \brief Deinitialize a capture handle.

  \param handle Handle to the capture instance.
*/
void scap_deinit(scap_t* handle);

/*!
  \brief Free a capture handle.

  \param handle Handle to the capture instance.

  You need to call \ref scap_deinit before calling this function
  or you risk leaking memory. Or just call \ref scap_close.
*/
void scap_free(scap_t* handle);

/*!
  \brief Close a capture handle.

  \param handle Handle to the capture instance.
*/
void scap_close(scap_t* handle);

/*!
  \brief Restart the current event capture.
    Only supported for captures in SCAP_MODE_CAPTURE mode.
	This deinitializes the scap internal state, and then re-initializes
	it by trying to read the scap header section. The underlying instance
	of scap_reader_t is preserved, and the header section is read starting
	from its current offset.

  \param handle Handle to the capture instance.
*/
uint32_t scap_restart_capture(scap_t* handle);

/*!
  \brief Return a string with the last error that happened on the given capture.
*/
const char* scap_getlasterr(scap_t* handle);

/*!
 * \brief returns the maximum amount of memory used by any driver queue
 */
uint64_t scap_max_buf_used(scap_t* handle);

/*!
  \brief Get the next event from the from the given capture instance

  \param handle Handle to the capture instance.
  \param pevent User-provided event pointer that will be initialized with address of the event.
  \param pcpuid User-provided event pointer that will be initialized with the ID if the CPU
    where the event was captured.

  \return SCAP_SUCCESS if the call is successful and pevent and pcpuid contain valid data.
   SCAP_TIMEOUT in case the read timeout expired and no event is available.
   SCAP_EOF when the end of an offline capture is reached.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain the cause of the error.
*/
int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid);

/*!
  \brief Get the length of an event

  \param e pointer to an event returned by \ref scap_next.

  \return The event length in bytes.
*/
uint32_t scap_event_getlen(scap_evt* e);

/*!
  \brief Get the timestamp of an event

  \param e pointer to an event returned by \ref scap_next.

  \return The event timestamp, in nanoseconds since epoch.
*/
uint64_t scap_event_get_ts(scap_evt* e);

/*!
  \brief Get the number of events that have been captured from the given capture
  instance

  \param handle Handle to the capture instance.

  \return The total number of events.
*/
uint64_t scap_event_get_num(scap_t* handle);

/*!
  \brief Return the meta-information describing the given event

  \param e pointer to an event returned by \ref scap_next.

  \return The pointer to the the event table entry for the given event.
*/
const struct ppm_event_info* scap_event_getinfo(const scap_evt* e);

/*!
  \brief Return the dump flags for the last event received from this handle

  \param handle Handle to the capture instance.

  \return The flags if the capture is offline, 0 if the capture is live.
*/
uint32_t scap_event_get_dump_flags(scap_t* handle);

/*!
  \brief Return the current offset in the file opened by scap_open_offline(),
  or -1 if this is a live capture.

  \param handle Handle to the capture instance.
*/
int64_t scap_get_readfile_offset(scap_t* handle);

/*!
  \brief Return the capture statistics for the given capture handle.

  \param handle Handle to the capture instance.
  \param stats Pointer to a \ref scap_stats structure that will be filled with the
  statistics.

  \return SCAP_SECCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_get_stats(scap_t* handle, OUT scap_stats* stats);

/*!
  \brief Get engine statistics (including counters and `bpftool prog show` like stats)

  \param handle Handle to the capture instance.
  \param flags holding statistics category flags.
  \param nstats Pointer reflecting number of statistics in returned buffer.
  \param rc Pointer to return code.

  \return Pointer to a \ref scap_stats_v2 structure filled with the statistics.
*/
const struct scap_stats_v2* scap_get_stats_v2(scap_t* handle, uint32_t flags, OUT uint32_t* nstats, OUT int32_t* rc);

/*!
  \brief Returns the set of ppm_sc whose events have EF_MODIFIES_STATE flag or whose syscall have UF_NEVER_DROP flag.
*/
int scap_get_modifies_state_ppm_sc(OUT uint8_t ppm_sc_array[PPM_SC_MAX]);

/*!
  \brief Take an array of `ppm_sc` as input and provide the associated array of events as output.
*/
int scap_get_events_from_ppm_sc(IN const uint8_t ppm_sc_array[PPM_SC_MAX], OUT uint8_t events_array[PPM_EVENT_MAX]);

/*!
  \brief Take an array of `ppm_event_code` as input and provide the associated array of ppm_sc as output.
*/
int scap_get_ppm_sc_from_events(IN const uint8_t events_array[PPM_EVENT_MAX], OUT uint8_t ppm_sc_array[PPM_SC_MAX]);

/*!
  \brief Given a name, returns associated ppm_sc.
*/
ppm_sc_code scap_ppm_sc_from_name(const char *name);

/*!
  \brief Convert a native syscall nr to ppm_sc
*/
ppm_sc_code scap_native_id_to_ppm_sc(int native_id);

/*!
  \brief Convert a native ppm_sc to native syscall id, if syscall
*/
int scap_ppm_sc_to_native_id(ppm_sc_code sc_code);

/*!
  \brief This function can be used to temporarily interrupt event capture.

  \param handle Handle to the capture that will be stopped.

  \return SCAP_SUCCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_stop_capture(scap_t* handle);

/*!
  \brief Start capture the events, if it was stopped with \ref scap_stop_capture.

  \param handle Handle to the capture that will be started.

  \return SCAP_SUCCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_start_capture(scap_t* handle);

/*!
  \brief Retrieve the table with the description of every event type that
  the capture driver supports.

  \return The pointer to a table of \ref scap_userlist entries, each of which describes
  one of the events that can come from the driver. The table contains PPM_EVENT_MAX entries,
  and the position of each entry in the table corresponds to its event ID.
  The ppm_event_info contains the full information necessary to decode an event coming from
  \ref scap_next.
*/
const struct ppm_event_info* scap_get_event_info_table();

/*!
  \brief Retrieve the syscall category of the event.
  The event category is composed of 2 parts:
  1. The highest bits represent the event category:
    - `EC_SYSCALL`
    - `EC_TRACEPOINT
    - `EC_PLUGIN`
    - `EC_METAEVENT`
 
  2. The lowest bits represent the syscall category to which the specific event belongs.
  
  With this method, we are retrieving the syscall category
*/
enum ppm_event_category scap_get_syscall_category_from_event(ppm_event_code ev);

/*!
  \brief Retrieve the event category of the event
  The event category is composed of 2 parts:
  1. The highest bits represent the event category:
    - `EC_SYSCALL`
    - `EC_TRACEPOINT
    - `EC_PLUGIN`
    - `EC_METAEVENT`
 
  2. The lowest bits represent the syscall category to which the specific event belongs.
  
  With this method, we are retrieving the event category
*/
enum ppm_event_category scap_get_event_category_from_event(ppm_event_code ev);

/*!
  \brief Retrieve the name associated with the specified ppm_sc.
*/
const char* scap_get_ppm_sc_name(ppm_sc_code sc);

/*!
  \brief Set the capture snaplen, i.e. the maximum size an event parameter can
  reach before the driver starts truncating it.

  \param handle Handle to the capture instance.
  \param snaplen the snaplen for this capture instance, in bytes.

  \note This function can only be called for live captures.
  \note By default, the driver captures the first 80 bytes of the buffers coming from
  events like read, write, send, recv, etc.
  If you're not interested in payloads, smaller values will save capture buffer space and
  make capture files smaller.
  Conversely, big values should be used with care because they can easily generate huge
  capture files.
*/
int32_t scap_set_snaplen(scap_t* handle, uint32_t snaplen);

/*!
  \brief (Un)Set the ppm_sc bit in the syscall mask so that
  users can (drop)receive the related syscall. Useful for offloading
  operations such as evt.type=open

  \param handle Handle to the capture instance.
  \param ppm_sc id (example PPM_SC_EXECVE)
  \param enabled whether to enable or disable the syscall
  \note This function can only be called for live captures.
*/
int32_t scap_set_ppm_sc(scap_t* handle, uint32_t ppm_sc, bool enabled);

/*!
  \brief (Un)Set the drop failed feature of the drivers.
  When enabled, drivers will stop sending failed syscalls (exit) events.

  \param handle Handle to the capture instance.
  \param enabled whether to enable or disable the feature
  \note This function can only be called for live captures.
*/
int32_t scap_set_dropfailed(scap_t* handle, bool enabled);

/*!
  \brief Get the root directory of the system. This usually changes
  if running in a container, so that all the information for the
  host can be correctly extracted.
*/
const char* scap_get_host_root();

/*!
  \brief Check if the current engine name matches the provided engine_name
*/
bool scap_check_current_engine(scap_t *handle, const char* engine_name);

/*!
  \brief stop returning events for all subsequently spawned
  processes with the provided comm, as well as their children.
  This includes fork()/clone()ed processes that might later
  exec to a different comm.

  returns SCAP_FAILURE if there are already MAX_SUPPRESSED_COMMS comm
  values, SCAP_SUCCESS otherwise.
*/

int32_t scap_suppress_events_comm(scap_t* handle, const char *comm);

/*!
  \brief return whether the provided tid is currently being suppressed.
*/

bool scap_check_suppressed_tid(scap_t *handle, int64_t tid);

/*!
  \brief Get (at most) n parameters for this event.
 
  \param e The scap event.
  \param params An array large enough to contain at least one entry per event parameter (which is at most PPM_MAX_EVENT_PARAMS).
 */
uint32_t scap_event_decode_params(const scap_evt *e, struct scap_sized_buffer *params);

/*!
  \brief Create an event from the parameters given as arguments.

  Create any event from the event_table passing the type, n and the parameters as variadic arguments as follows:
   - Any integer type is passed from the correct type
   - String types (including PT_FSPATH, PT_FSRELPATH) are passed via a null-terminated char*
   - Buffer types, variable size types and similar, including PT_BYTEBUF, PT_SOCKTUPLE are passed with
     a struct scap_const_sized_buffer
  
  If the event was written successfully, SCAP_SUCCESS is returned. If the supplied buffer is not large enough to contain
  the event, SCAP_INPUT_TOO_SMALL is returned and event_size is set with the required size to contain the entire event.

  \param event_buf The buffer where to store the encoded event.
  \param event_size Output value that will be filled with the size of the event.
  \param error A pointer to a scap error string to be filled in case of error.
  \param event_type The event type (normally PPME_*)
  \param n The number of parameters for this event. This is required as the number of parameters used for each event can change between versions.
  \param ...
  \return int32_t The error value. If the event was written successfully, SCAP_SUCCESS is returned.
  If the supplied buffer is not large enough for the event SCAP_INPUT_TOO_SMALL is returned and event_size
  is set with the required size to contain the entire event. In other error cases, SCAP_FAILURE is returned.

 */
int32_t scap_event_encode_params(struct scap_sized_buffer event_buf, size_t *event_size, char *error, ppm_event_code event_type, uint32_t n, ...);
int32_t scap_event_encode_params_v(struct scap_sized_buffer event_buf, size_t *event_size, char *error, ppm_event_code event_type, uint32_t n, va_list args);

/*@}*/

///////////////////////////////////////////////////////////////////////////////
// Non public functions
///////////////////////////////////////////////////////////////////////////////

//
// Return the number of event capture devices that the library is handling. Each processor
// has its own event capture device.
//
uint32_t scap_get_ndevs(scap_t* handle);

// Retrieve a buffer of events from one of the cpus
extern int32_t scap_readbuf(scap_t* handle, uint32_t cpuid, OUT char** buf, OUT uint32_t* len);

#ifdef PPM_ENABLE_SENTINEL
// Get the sentinel at the beginning of the event
uint32_t scap_event_get_sentinel_begin(scap_evt* e);
#endif

struct scap_threadinfo *scap_proc_alloc(scap_t* handle);
void scap_proc_free(scap_t* handle, struct scap_threadinfo* procinfo);
int32_t scap_stop_dropping_mode(scap_t* handle);
int32_t scap_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio);
int32_t scap_enable_dynamic_snaplen(scap_t* handle);
int32_t scap_disable_dynamic_snaplen(scap_t* handle);
uint64_t scap_ftell(scap_t *handle);
void scap_fseek(scap_t *handle, uint64_t off);
int32_t scap_enable_tracers_capture(scap_t* handle);
int32_t scap_proc_add(scap_t* handle, uint64_t tid, scap_threadinfo* tinfo);
int32_t scap_fd_add(scap_t *handle, scap_threadinfo* tinfo, uint64_t fd, scap_fdinfo* fdinfo);

int32_t scap_get_n_tracepoint_hit(scap_t* handle, long* ret);
int32_t scap_set_fullcapture_port_range(scap_t* handle, uint16_t range_start, uint16_t range_end);

/**
 * By default we have an expanded snaplen for the default statsd port. If the
 * statsd port is non-standard, communicate that port value to the kernel to
 * get the expanded snaplen for the correct port.
 */
int32_t scap_set_statsd_port(scap_t* handle, uint16_t port);

/**
 * Get API version supported by the driver
 * If the API version is unavailable for whatever reason,
 * it's equivalent to version 0.0.0
 */
uint64_t scap_get_driver_api_version(scap_t* handle);

/**
 * Get schema version supported by the driver
 * If the schema version is unavailable for whatever reason,
 * it's equivalent to version 0.0.0
 */
uint64_t scap_get_driver_schema_version(scap_t* handle);

#ifdef __cplusplus
}
#endif
