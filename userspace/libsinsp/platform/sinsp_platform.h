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

extern "C" const struct scap_platform_vtable cpp_platform_vtable;

namespace libsinsp
{
	class platform
	{
	public:
		virtual ~platform() = default;

		virtual int32_t init_platform(struct scap_engine_handle engine, struct scap_open_args* oargs) = 0;

		virtual int32_t get_agent_info(scap_agent_info* agent_info) = 0;
		virtual int32_t refresh_addr_list() = 0;

		virtual uint32_t get_device_by_mount_id(const char *procdir, unsigned long requested_mount_id) = 0;

		virtual struct scap_threadinfo* get_proc(struct scap_proclist* proclist, int64_t tid, bool scan_sockets) = 0;

		virtual int32_t refresh_proc_table(struct scap_proclist* proclist) = 0;
		virtual bool is_thread_alive(int64_t pid, int64_t tid, const char* comm) = 0;
		virtual int32_t get_global_pid(int64_t *pid) = 0;
		virtual int32_t get_threadlist(struct ppm_proclist_info **procinfo_p) = 0;

		virtual int32_t read_block(struct scap_reader* r, uint32_t block_length, uint32_t block_type,
					   uint64_t flags) = 0;

		virtual int32_t dump_state(struct scap_dumper *d, uint64_t flags) = 0;

		virtual struct scap_linux_storage* get_linux_storage() = 0;

		virtual int32_t close_platform() = 0;
	};

	struct platform_struct
	{
		struct ::scap_platform m_generic;
		std::unique_ptr<platform> m_platform;

		platform_struct() :
			m_generic({}) {}

		static std::unique_ptr<platform_struct> wrap(std::unique_ptr<platform>&& plat)
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

