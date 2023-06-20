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

#include <cstdint>
#include <memory>

#include "scap_platform_impl.h"
#include "savefile/scap_savefile_api.h"
#define SINSP_PUBLIC
#include "settings.h"
#include "event.h"
#include "tuples.h"
#include "threadinfo.h"
#include "ifinfo.h"
#include "userlist_linux.h"

class sinsp_usergroup_manager;

extern "C" const struct scap_platform_vtable cpp_platform_vtable;

namespace libsinsp
{
	class platform
	{
	public:
		/*!
		  \brief Agent information, not intended for scap file use
		*/
		struct agent_info
		{
			uint64_t start_ts_epoch; ///< Agent start timestamp, stat /proc/self/cmdline approach, unit: epoch in nanoseconds
			double start_time; ///< /proc/self/stat start_time divided by HZ, unit: seconds
			char uname_r[128]; ///< Kernel release `uname -r`
		};

		virtual ~platform() = default;

		virtual int32_t init_platform(struct scap_engine_handle engine, struct scap_open_args* oargs) = 0;

		virtual int32_t get_agent_info(agent_info &agent_info) = 0;
		virtual uint32_t get_device_by_mount_id(const char *procdir, unsigned long requested_mount_id) = 0;

		virtual struct scap_threadinfo* get_proc(struct scap_proclist* proclist, int64_t tid, bool scan_sockets) = 0;

		virtual int32_t refresh_proc_table(struct scap_proclist* proclist) = 0;
		virtual bool is_thread_alive(int64_t pid, int64_t tid, const char* comm) = 0;
		virtual int64_t get_global_pid() = 0;
		virtual int32_t get_threadlist(struct ppm_proclist_info **procinfo_p) = 0;

		virtual int32_t read_block(struct scap_reader* r, uint32_t block_length, uint32_t block_type,
					   uint64_t flags) = 0;

		virtual int32_t dump_state(struct scap_dumper *d, uint64_t flags) = 0;

		virtual struct scap_linux_storage* get_linux_storage() = 0;

		virtual int32_t close_platform() = 0;

		// ---

		inline sinsp_network_interfaces& network_interfaces()
		{
			return m_network_interfaces;
		}

		inline const scap_machine_info* get_machine_info() const {
			return  &m_machine_info;
		};

		void get_users(sinsp_usergroup_manager &usergroup_manager);

	protected:
		scap_machine_info m_machine_info {.num_cpus = (uint32_t)-1};
		sinsp_network_interfaces m_network_interfaces;
		libsinsp::platform_linux::userlist_storage m_users;
	};

	struct platform_struct
	{
		struct ::scap_platform m_generic;
		std::shared_ptr<platform> m_platform;

		platform_struct() :
			m_generic({}) {}

		static std::unique_ptr<platform_struct> wrap(std::shared_ptr<platform>&& plat)
		{
			auto platform = std::make_unique<platform_struct>();
			platform->m_platform = std::move(plat);
			platform->m_generic.m_vtable = &cpp_platform_vtable;

			return platform;
		}

		template<class T> static std::unique_ptr<platform_struct> alloc()
		{
			return wrap(std::move(std::make_unique<T>()));
		}
	};
}

