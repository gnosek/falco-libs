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

#include "sinsp_platform.h"
#include "strlcpy.h"
#include "sinsp.h"

extern "C" {
	int32_t cpp_init_platform(struct scap_platform* platform, char* lasterr, struct scap_engine_handle engine, struct scap_open_args* oargs)
	{
		auto cpp_plat = reinterpret_cast<libsinsp::platform_struct*>(platform);
		try
		{
			return cpp_plat->m_platform->init_platform(engine, oargs);
		}
		catch(const std::exception& e)
		{
			strlcpy(lasterr, e.what(), SCAP_LASTERR_SIZE);
			return SCAP_FAILURE;
		}
	}

	struct scap_threadinfo* cpp_get_proc(struct scap_platform* platform, struct scap_proclist* proclist, int64_t tid, bool scan_sockets)
	{
		auto cpp_plat = reinterpret_cast<libsinsp::platform_struct*>(platform);
		return cpp_plat->m_platform->get_proc(proclist, tid, scan_sockets);
	}

	int32_t cpp_refresh_proc_table(struct scap_platform* platform, struct scap_proclist* proclist)
	{
		auto cpp_plat = reinterpret_cast<libsinsp::platform_struct*>(platform);
		return cpp_plat->m_platform->refresh_proc_table(proclist);

	}

	bool cpp_is_thread_alive(struct scap_platform* platform, int64_t pid, int64_t tid, const char* comm)
	{
		auto cpp_plat = reinterpret_cast<libsinsp::platform_struct*>(platform);
		return cpp_plat->m_platform->is_thread_alive(pid, tid, comm);
	}

	int32_t cpp_get_threadlist(struct scap_platform* platform, struct ppm_proclist_info **procinfo_p, char *lasterr)
	{
		auto cpp_plat = reinterpret_cast<libsinsp::platform_struct*>(platform);
		try
		{
			return cpp_plat->m_platform->get_threadlist(procinfo_p);
		}
		catch(const std::exception& e)
		{
			strlcpy(lasterr, e.what(), SCAP_LASTERR_SIZE);
			return SCAP_FAILURE;
		}
	}

	int32_t cpp_read_block(struct scap_platform *platform, struct scap_reader *r, uint32_t block_length,
			      uint32_t block_type, uint64_t flags, char *error)
	{
		auto cpp_plat = reinterpret_cast<libsinsp::platform_struct*>(platform);
		try
		{
			return cpp_plat->m_platform->read_block(r, block_length, block_type, flags);
		}
		catch(const std::exception& e)
		{
			strlcpy(error, e.what(), SCAP_LASTERR_SIZE);
			return SCAP_FAILURE;
		}
	}

	int32_t cpp_dump_state(struct scap_platform *platform, struct scap_dumper *d, uint64_t flags)
	{
		auto cpp_plat = reinterpret_cast<libsinsp::platform_struct*>(platform);
		return cpp_plat->m_platform->dump_state(d, flags);
	}

	struct scap_linux_storage* cpp_get_linux_storage(struct scap_platform* platform)
	{
		auto cpp_plat = reinterpret_cast<libsinsp::platform_struct*>(platform);
		return cpp_plat->m_platform->get_linux_storage();
	}

	int32_t cpp_close_platform(struct scap_platform* platform)
	{
		auto cpp_plat = reinterpret_cast<libsinsp::platform_struct*>(platform);
		return cpp_plat->m_platform->close_platform();
	}

	void cpp_free_platform(struct scap_platform* platform)
	{
		auto cpp_plat = reinterpret_cast<libsinsp::platform_struct*>(platform);
		delete cpp_plat;
	}

	const struct scap_platform_vtable cpp_platform_vtable = {
		.init_platform = cpp_init_platform,
		.get_proc = cpp_get_proc,
		.refresh_proc_table = cpp_refresh_proc_table,
		.is_thread_alive = cpp_is_thread_alive,
		.get_threadlist = cpp_get_threadlist,
		.read_block = cpp_read_block,
		.dump_state = cpp_dump_state,
		.get_linux_storage = cpp_get_linux_storage,
		.close_platform = cpp_close_platform,
		.free_platform = cpp_free_platform,
	};

}

void libsinsp::platform::get_users(sinsp_usergroup_manager& usergroup_manager)
{
	for(const auto& [_uid, userinfo] : m_users.m_users)
	{
		usergroup_manager.add_user("", -1, userinfo.uid, userinfo.gid, userinfo.name, userinfo.homedir, userinfo.shell);
	}

	for(const auto& [_gid, groupinfo] : m_users.m_groups)
	{
		usergroup_manager.add_group("", -1, groupinfo.gid, groupinfo.name);
	}
}
