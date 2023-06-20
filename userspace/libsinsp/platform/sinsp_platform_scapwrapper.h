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

#include "platform/sinsp_platform.h"
#include "linux/scap_linux_platform.h"
#include "sinsp_exception.h"
#include <unistd.h>

namespace libsinsp
{
class scapwrapper_platform : public platform
{
protected:
	inline const struct scap_platform_vtable* vt()
	{
		return m_scap_platform->m_vtable;
	}

public:
	explicit scapwrapper_platform(scap_platform* scap_platform);

	~scapwrapper_platform() override;

	int32_t init_platform(struct scap_engine_handle engine, struct scap_open_args* oargs) override;

	int32_t get_agent_info(agent_info &agent_info) override
	{
		return SCAP_FAILURE;
	}

	uint32_t get_device_by_mount_id(const char *procdir, unsigned long requested_mount_id) override
	{
		return 0;
	}

	struct scap_threadinfo* get_proc(struct scap_proclist* proclist, int64_t tid, bool scan_sockets) override
	{
		return vt()->get_proc(m_scap_platform, proclist, tid, scan_sockets);
	}

	int32_t refresh_proc_table(struct scap_proclist* proclist) override
	{
		return vt()->refresh_proc_table(m_scap_platform, proclist);
	}

	bool is_thread_alive(int64_t pid, int64_t tid, const char* comm) override
	{
		return vt()->is_thread_alive(m_scap_platform, pid, tid, comm);
	}

	int64_t get_global_pid() override
	{
		return getpid();
	}

	int32_t get_threadlist(struct ppm_proclist_info **procinfo_p) override
	{
		char lasterr[SCAP_LASTERR_SIZE];

		int32_t rc = vt()->get_threadlist(m_scap_platform, procinfo_p, lasterr);
		if(rc != SCAP_SUCCESS)
		{
			throw sinsp_exception(lasterr);
		}
		return rc;
	}

	int32_t read_block(struct scap_reader* r, uint32_t block_length, uint32_t block_type, uint64_t flags) override
	{
		char lasterr[SCAP_LASTERR_SIZE];

		int32_t rc = vt()->read_block(m_scap_platform, r, block_length, block_type, flags, lasterr);
		if(rc != SCAP_SUCCESS)
		{
			throw sinsp_exception(lasterr);
		}
		return rc;
	}

	int32_t dump_state(struct scap_dumper *d, uint64_t flags) override
	{
		return vt()->dump_state(m_scap_platform, d, flags);
	}

	struct scap_linux_storage* get_linux_storage() override
	{
		return vt()->get_linux_storage(m_scap_platform);
	}

	int32_t close_platform() override
	{
		return vt()->close_platform(m_scap_platform);
	}

	sinsp_network_interfaces& network_interfaces() override
	{
		return *m_network_interfaces;
	}

	void get_machine_info(scap_machine_info& machine_info) override
	{
		machine_info = get_linux_storage()->m_machine_info;
	}

protected:
	scap_platform* m_scap_platform;
	std::unique_ptr<sinsp_network_interfaces> m_network_interfaces;
};
}