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

#include "sinsp_platform_linux.h"
#include "addrlist_linux.h"
#include "machineinfo.h"
#include "sinsp_dumper_utils.h"
#include "linux/scap_linux.h"
#include <sys/stat.h>
#include <sys/utsname.h>

#if HAVE_SYS_MKDEV_H
#include <sys/mkdev.h>
#endif
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif

#define SECOND_TO_NS 1000000000

namespace
{
uint64_t get_host_boot_time_ns(char *last_err)
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
	FILE *f = fopen(proc_stat, "r");
	if(f == NULL)
	{
		DEBUG_THROW(sinsp_errprintf(errno, "Failed to open %s", proc_stat));
		return 0;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(sscanf(line, "btime %" PRIu64, &btime) == 1)
		{
			fclose(f);
			return btime * (uint64_t)SECOND_TO_NS;
		}
	}
	fclose(f);
	DEBUG_THROW(sinsp_errprintf(errno, "Could not find btime in %s", proc_stat));
	return 0;
}

void scap_gethostname(char *buf, size_t size)
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

}

int32_t libsinsp::linux_platform::init_platform(struct scap_engine_handle engine, struct scap_open_args *oargs)
{
	int32_t rc = scapwrapper_platform::init_platform(engine, oargs);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	fill_machine_info();

	libsinsp::platform_linux::get_interfaces(*m_network_interfaces);

	return SCAP_SUCCESS;
}

uint32_t libsinsp::linux_platform::get_device_by_mount_id(const char *procdir, unsigned long requested_mount_id)
{
	char fd_dir_name[SCAP_MAX_PATH_SIZE];
	char line[SCAP_MAX_PATH_SIZE];
	FILE *finfo;

	auto it = m_dev_map.find(requested_mount_id);
	if(it != m_dev_map.end())
	{
		return it->second;
	}

	snprintf(fd_dir_name, SCAP_MAX_PATH_SIZE, "%smountinfo", procdir);
	finfo = fopen(fd_dir_name, "r");
	if(finfo == NULL)
	{
		return 0;
	}

	while(fgets(line, sizeof(line), finfo) != NULL)
	{
		uint32_t mount_id, major, minor;
		if(sscanf(line, "%u %*u %u:%u", &mount_id, &major, &minor) != 3)
		{
			continue;
		}

		if(mount_id == requested_mount_id)
		{
			uint32_t dev = makedev(major, minor);
			m_dev_map[mount_id] = dev;
			fclose(finfo);
			return dev;
		}
	}
	fclose(finfo);
	return 0;
}

int32_t libsinsp::linux_platform::get_agent_info(agent_info &agent_info)
{
	agent_info.start_ts_epoch = 0;
	agent_info.start_time = 0;

	/* Info 1:
	 *
	 * Get epoch timestamp based on procfs stat, only used for (constant) agent start time reporting.
	 */
	struct stat st = {0};
	if(stat("/proc/self/cmdline", &st) == 0)
	{
		agent_info.start_ts_epoch = st.st_ctim.tv_sec * (uint64_t) SECOND_TO_NS + st.st_ctim.tv_nsec;
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
			DEBUG_THROW(sinsp_errprintf(errno, "sysconf(_SC_CLK_TCK) failed"));
		}
#endif
		if(fscanf(f, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*u %llu", &stat_start_time))
		{
			agent_info.start_time = (double)stat_start_time / hz; // unit: seconds as type (double)
		}
		fclose(f);
	}

	/* Info 3:
	 *
	 * Kernel release `uname -r` of the machine the agent is running on.
	 */

	struct utsname uts = {};
	uname(&uts);
	snprintf(agent_info.uname_r, sizeof(agent_info.uname_r), "%s", uts.release);

	return SCAP_SUCCESS;
}

void libsinsp::linux_platform::fill_machine_info()
{
	// this isn't actually even used by scap_linux_get_host_boot_time_ns
	char lasterr[SCAP_LASTERR_SIZE];

	m_machine_info.num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	m_machine_info.memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
	scap_gethostname(m_machine_info.hostname, sizeof(m_machine_info.hostname));
	m_machine_info.boot_ts_epoch = get_host_boot_time_ns(lasterr);
	if(m_machine_info.boot_ts_epoch == 0)
	{
		throw sinsp_exception("Failed to get current boot time");
	}
	m_machine_info.reserved3 = 0;
	m_machine_info.reserved4 = 0;

	m_machine_info.flags |= SCAP_OS_LINUX;
#if defined(__amd64__)
	m_machine_info.flags |= SCAP_ARCH_X64;
#elif defined(__aarch64__)
	m_machine_info.flags |= SCAP_ARCH_AARCH64;
#elif defined(__i386__)
	m_machine_info.flags |= SCAP_ARCH_I386;
#else
#warning "Unsupported architecture, please define a SCAP_ARCH_* flag for it"
	throw sinsp_exception("Unsupported architecture, please define a SCAP_ARCH_* flag for it");
#endif
}

int64_t libsinsp::linux_platform::get_global_pid()
{
	char lasterr[SCAP_LASTERR_SIZE];
	int64_t pid;

	auto platform = get_scap_platform();
	auto linux_vtable = platform->m_linux_vtable;
	auto engine_handle = platform->m_engine;
	if(linux_vtable && linux_vtable->getpid_global)
	{
		if(linux_vtable->getpid_global(engine_handle, &pid, lasterr) != SCAP_SUCCESS)
		{
			throw sinsp_exception(lasterr);
		}
		else
		{
			return pid;
		}
	}

	char filename[SCAP_MAX_PATH_SIZE];
	char line[512];

	snprintf(filename, sizeof(filename), "%s/proc/self/status", scap_get_host_root());

	FILE* f = fopen(filename, "r");
	if(f == NULL)
	{
		throw sinsp_errprintf(errno, "can not open status file %s", filename);
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(sscanf(line, "Tgid: %" PRId64, &pid) == 1)
		{
			fclose(f);
			return pid;
		}
	}

	fclose(f);
	throw sinsp_errprintf(0, "could not find tgid in status file %s", filename);
}

int32_t libsinsp::linux_platform::dump_state(struct scap_dumper *d, uint64_t flags)
{
	libsinsp::platform_linux::dump_machine_info(m_machine_info).dump(d);

	int32_t rc = scapwrapper_platform::dump_state(d, flags);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

#ifdef _DEBUG
	struct scap_addrlist *addrlist = get_linux_storage()->m_addrlist;
	if(addrlist != nullptr)
	{
		throw sinsp_exception("scap addrlist not empty");
	}
#endif

	libsinsp::platform_linux::dump_addrlist(*m_network_interfaces).dump(d);

	return SCAP_SUCCESS;
}
