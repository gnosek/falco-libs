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

#include "scap_linux_platform.h"

#include "ppm_events_public.h"
#include "scap_assert.h"
#include "scap_linux.h"
#include "scap_linux_int.h"
#include "scap_machine_info.h"
#include "scap_open.h"
#include "scap_stats_v2.h"
#include "strerror.h"

#include "compat/misc.h"
#include "linux-schema/linux_savefile_write.h"
#include "strlcpy.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <unistd.h>

#define SECOND_TO_NS 1000000000

static int32_t scap_linux_close_platform(struct scap_platform* platform)
{
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;

	scap_linux_storage_close(&linux_platform->m_storage);

	return SCAP_SUCCESS;
}

static void scap_linux_free_platform(struct scap_platform* platform)
{
	free(platform);
}

static int scap_get_cgroup_version()
{
	char dir_name[256];
	int cgroup_version = -1;
	FILE* f;
	char line[SCAP_MAX_ENV_SIZE];

	snprintf(dir_name, sizeof(dir_name), "%s/proc/filesystems", scap_get_host_root());
	f = fopen(dir_name, "r");
	if (f)
	{
		while(fgets(line, sizeof(line), f) != NULL)
		{
			// NOTE: we do not support mixing cgroups v1 v2 controllers.
			// Neither docker nor podman support this: https://github.com/docker/for-linux/issues/1256
			if (strstr(line, "cgroup2"))
			{
				return 2;
			}
			if (strstr(line, "cgroup"))
			{
				cgroup_version = 1;
			}
		}
		fclose(f);
	}

	return cgroup_version;
}

static uint64_t scap_linux_get_host_boot_time_ns(char* last_err)
{
	uint64_t btime = 0;
	char proc_stat[SCAP_MAX_PATH_SIZE];
	char line[512];

	/* Get boot time from btime value in /proc/stat
	 * ref: https://github.com/falcosecurity/libs/issues/932
	 * /proc/uptime and btime in /proc/stat are fed by the same kernel sources.
	 *
	 * Multiple ways to get boot time:
	 *	btime in /proc/stat
	 *	calculation via clock_gettime(CLOCK_REALTIME - CLOCK_BOOTTIME)
	 *	calculation via time(NULL) - sysinfo().uptime
	 *
	 * Maintainers preferred btime in /proc/stat because:
	 *	value does not depend on calculation using current timestamp
	 *	btime is "static" and doesn't change once set
	 *	btime is available in kernels from 2008
	 *	CLOCK_BOOTTIME is available in kernels from 2011 (2.6.38
	 *
	 * By scraping btime from /proc/stat,
	 * it is both the heaviest and most likely to succeed
	 */
	snprintf(proc_stat, sizeof(proc_stat), "%s/proc/stat", scap_get_host_root());
	FILE* f = fopen(proc_stat, "r");
	if (f == NULL)
	{
		ASSERT(false);
		return 0;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(sscanf(line, "btime %" PRIu64, &btime) == 1)
		{
			fclose(f);
			return btime * (uint64_t) SECOND_TO_NS;
		}
	}
	fclose(f);
	ASSERT(false);
	return 0;
}

static void scap_get_bpf_stats_enabled(scap_machine_info* machine_info)
{
	machine_info->flags &= ~PPM_BPF_STATS_ENABLED;
	FILE* f;
	if((f = fopen("/proc/sys/kernel/bpf_stats_enabled", "r")))
	{
		uint32_t bpf_stats_enabled = 0;
		if(fscanf(f, "%u", &bpf_stats_enabled) == 1)
		{
			if (bpf_stats_enabled != 0)
			{
				machine_info->flags |= PPM_BPF_STATS_ENABLED;
			}
		}
		fclose(f);
	}
}

static void scap_gethostname(char* buf, size_t size)
{
	char *env_hostname = getenv(SCAP_HOSTNAME_ENV_VAR);
	if(env_hostname != NULL)
	{
		snprintf(buf, size, "%s", env_hostname);
	}
	else
	{
		gethostname(buf, size);
	}
}

static int32_t scap_linux_fill_machine_info(struct scap_platform* platform, scap_machine_info* machine_info)
{
	// this isn't actually even used by scap_linux_get_host_boot_time_ns
	char lasterr[SCAP_LASTERR_SIZE];

	machine_info->num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	machine_info->memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
	scap_gethostname(machine_info->hostname, sizeof(machine_info->hostname));
	machine_info->boot_ts_epoch = scap_linux_get_host_boot_time_ns(lasterr);
	if(machine_info->boot_ts_epoch == 0)
	{
		return SCAP_FAILURE;
	}
	scap_get_bpf_stats_enabled(machine_info);
	machine_info->reserved3 = 0;
	machine_info->reserved4 = 0;

	machine_info->flags |= SCAP_OS_LINUX;
#if defined(__amd64__)
	machine_info->flags |= SCAP_ARCH_X64;
#elif defined(__aarch64__)
	machine_info->flags |= SCAP_ARCH_AARCH64;
#elif defined(__i386__)
	machine_info->flags |= SCAP_ARCH_I386;
#else
#warning "Unsupported architecture, please define a SCAP_ARCH_* flag for it"
	ASSERT(false);
#endif

	return SCAP_SUCCESS;
}

int32_t scap_linux_init_platform(struct scap_platform* platform, char* lasterr, struct scap_engine_handle engine, struct scap_open_args* oargs)
{
	int rc;
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;
	linux_platform->m_lasterr = lasterr;
	linux_platform->m_engine = engine;

	rc = scap_linux_fill_machine_info(platform, &linux_platform->m_storage.m_machine_info);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	rc = scap_linux_storage_init(&linux_platform->m_storage, lasterr, oargs);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	linux_platform->m_proc_scan_timeout_ms = oargs->proc_scan_timeout_ms;
	linux_platform->m_proc_scan_log_interval_ms = oargs->proc_scan_log_interval_ms;
	linux_platform->m_debug_log_fn = oargs->debug_log_fn;

	linux_platform->m_cgroup_version = scap_get_cgroup_version();
	if(linux_platform->m_cgroup_version < 1)
	{
		ASSERT(false);
		return scap_errprintf(lasterr, errno, "failed to fetch cgroup version information");
	}

	rc = scap_linux_create_iflist(platform);
	if(rc != SCAP_SUCCESS)
	{
		scap_linux_free_platform(platform);
		return rc;
	}

	if(oargs->import_users)
	{
		rc = scap_linux_create_userlist(platform);
		if(rc != SCAP_SUCCESS)
		{
			scap_linux_free_platform(platform);
			return rc;
		}
	}

	linux_platform->m_lasterr[0] = '\0';
	char proc_scan_err[SCAP_LASTERR_SIZE];
	rc = scap_linux_refresh_proc_table(platform, &linux_platform->m_storage.m_proclist);
	if(rc != SCAP_SUCCESS)
	{
		snprintf(linux_platform->m_lasterr, SCAP_LASTERR_SIZE, "scap_open_live_int() error creating the process list: %s. Make sure you have root credentials.", proc_scan_err);
		scap_linux_free_platform(platform);
		return rc;
	}

	return SCAP_SUCCESS;
}

static inline int32_t scap_dump_rescan_proc(struct scap_platform* platform)
{
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;
	int32_t ret = SCAP_SUCCESS;
	proc_entry_callback tcb = linux_platform->m_storage.m_proclist.m_proc_callback;
	linux_platform->m_storage.m_proclist.m_proc_callback = NULL;
	ret = scap_linux_refresh_proc_table(platform, &linux_platform->m_storage.m_proclist);
	linux_platform->m_storage.m_proclist.m_proc_callback = tcb;
	return ret;
}

static int32_t linux_dump_state(struct scap_platform *platform, struct scap_dumper *d, uint64_t flags)
{
	int32_t res;
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;
	if(flags & DUMP_FLAGS_RESCAN_PROC)
	{
		if(scap_dump_rescan_proc(platform) != SCAP_SUCCESS)
		{
			return SCAP_FAILURE;
		}
	}

	res = scap_savefile_write_linux_platform(&linux_platform->m_storage, d);

	//
	// If the user doesn't need the thread table, free it
	//
	if(linux_platform->m_storage.m_proclist.m_proc_callback != NULL)
	{
		scap_proc_free_table(&linux_platform->m_storage.m_proclist);
	}

	return res;
}

struct scap_linux_storage* scap_linux_get_storage(struct scap_platform* platform)
{
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;
	return &linux_platform->m_storage;
}

static const struct scap_platform_vtable scap_linux_platform = {
	.init_platform = scap_linux_init_platform,
	.refresh_addr_list = scap_linux_create_iflist,
	.get_proc = scap_linux_proc_get,
	.refresh_proc_table = scap_linux_refresh_proc_table,
	.is_thread_alive = scap_linux_is_thread_alive,
	.get_threadlist = scap_linux_get_threadlist,
	.dump_state = linux_dump_state,
	.get_linux_storage = scap_linux_get_storage,
	.close_platform = scap_linux_close_platform,
	.free_platform = scap_linux_free_platform,
};

struct scap_platform* scap_linux_alloc_platform()
{
	struct scap_linux_platform* platform = calloc(sizeof(*platform), 1);

	if(platform == NULL)
	{
		return NULL;
	}

	struct scap_platform* generic = &platform->m_generic;
	generic->m_vtable = &scap_linux_platform;

	return generic;
}

const char* scap_get_host_root()
{
	char* p = getenv(SCAP_HOST_ROOT_ENV_VAR_NAME);
	static char env_str[SCAP_MAX_PATH_SIZE + 1];
	static bool inited = false;
	if (! inited) {
		strlcpy(env_str, p ? p : "", sizeof(env_str));
		inited = true;
	}

	return env_str;
}

// wtf the absolutely wrong place for this
bool scap_alloc_proclist_info(struct ppm_proclist_info **proclist_p, uint32_t n_entries, char* error)
{
	uint32_t memsize;

	if(n_entries >= SCAP_DRIVER_PROCINFO_MAX_SIZE)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "driver process list too big");
		return false;
	}

	memsize = sizeof(struct ppm_proclist_info) +
		  sizeof(struct ppm_proc_info) * n_entries;

	struct ppm_proclist_info *procinfo = (struct ppm_proclist_info*) realloc(*proclist_p, memsize);
	if(procinfo == NULL)
	{
		free(*proclist_p);
		*proclist_p = NULL;
		snprintf(error, SCAP_LASTERR_SIZE, "driver process list allocation error");
		return false;
	}

	if(*proclist_p == NULL)
	{
		procinfo->n_entries = 0;
	}

	procinfo->max_entries = n_entries;
	*proclist_p = procinfo;

	return true;
}