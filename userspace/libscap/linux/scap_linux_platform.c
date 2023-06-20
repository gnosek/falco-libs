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

#include "scap.h"
#include "scap-int.h"
#include "scap_machine_info.h"
#include "scap_linux_int.h"
#include "strerror.h"

#include "compat/misc.h"

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

	// Free the device table
	if(linux_platform->m_dev_list != NULL)
	{
		scap_free_device_table(linux_platform->m_dev_list);
		linux_platform->m_dev_list = NULL;
	}

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

static void scap_linux_retrieve_agent_info(scap_agent_info* agent_info)
{
	agent_info->start_ts_epoch = 0;
	agent_info->start_time = 0;

	/* Info 1:
	 *
	 * Get epoch timestamp based on procfs stat, only used for (constant) agent start time reporting.
	 */
	struct stat st = {0};
	if(stat("/proc/self/cmdline", &st) == 0)
	{
		agent_info->start_ts_epoch = st.st_ctim.tv_sec * (uint64_t) SECOND_TO_NS + st.st_ctim.tv_nsec;
	}

	/* Info 2:
	 *
	 * Get /proc/self/stat start_time (22nd item) to calculate subsequent snapshots of the elapsed time
	 * of the agent for CPU usage calculations, e.g. sysinfo uptime - /proc/self/stat start_time.
	 */
	FILE* f;
	if((f = fopen("/proc/self/stat", "r")))
	{
		unsigned long long stat_start_time = 0; // unit: USER_HZ / jiffies / clock ticks
		long hz = 100;
#ifdef _SC_CLK_TCK
		if ((hz = sysconf(_SC_CLK_TCK)) < 0)
		{
			hz = 100;
			ASSERT(false);
		}
#endif
		if(fscanf(f, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*u %llu", &stat_start_time))
		{
			agent_info->start_time = (double)stat_start_time / hz; // unit: seconds as type (double)
		}
		fclose(f);
	}

	/* Info 3:
	 *
	 * Kernel release `uname -r` of the machine the agent is running on.
	 */

	struct utsname uts;
	uname(&uts);
	snprintf(agent_info->uname_r, sizeof(agent_info->uname_r), "%s", uts.release);
}

static uint64_t scap_linux_get_host_boot_time_ns(char* last_err)
{
	uint64_t btime = 0;
	char proc_stat[PPM_MAX_PATH_SIZE];
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

int32_t scap_linux_init_platform(struct scap_platform* platform, char* lasterr, struct scap_engine_handle engine, struct scap_open_args* oargs)
{
	int rc;
	struct scap_linux_platform* linux_platform = (struct scap_linux_platform*)platform;
	linux_platform->m_lasterr = lasterr;
	linux_platform->m_engine = engine;

	platform->m_machine_info.num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	platform->m_machine_info.memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
	scap_gethostname(platform->m_machine_info.hostname, sizeof(platform->m_machine_info.hostname));
	platform->m_machine_info.boot_ts_epoch = scap_linux_get_host_boot_time_ns(lasterr);
	if(platform->m_machine_info.boot_ts_epoch == 0)
	{
		return SCAP_FAILURE;
	}
	scap_get_bpf_stats_enabled(&platform->m_machine_info);
	platform->m_machine_info.reserved3 = 0;
	platform->m_machine_info.reserved4 = 0;

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
	rc = scap_linux_refresh_proc_table(platform, &platform->m_proclist);
	if(rc != SCAP_SUCCESS)
	{
		snprintf(linux_platform->m_lasterr, SCAP_LASTERR_SIZE, "scap_open_live_int() error creating the process list: %s. Make sure you have root credentials.", proc_scan_err);
		scap_linux_free_platform(platform);
		return rc;
	}

	scap_linux_retrieve_agent_info(&platform->m_agent_info);

	return SCAP_SUCCESS;
}

static const struct scap_platform_vtable scap_linux_platform = {
	.init_platform = scap_linux_init_platform,
	.refresh_addr_list = scap_linux_create_iflist,
	.get_device_by_mount_id = scap_linux_get_device_by_mount_id,
	.get_proc = scap_linux_proc_get,
	.refresh_proc_table = scap_linux_refresh_proc_table,
	.is_thread_alive = scap_linux_is_thread_alive,
	.get_global_pid = scap_linux_getpid_global,
	.get_threadlist = scap_linux_get_threadlist,
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
