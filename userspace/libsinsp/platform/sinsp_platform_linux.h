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

#include <unordered_map>
#include "sinsp_platform_scapwrapper.h"

namespace libsinsp
{
class linux_platform : public scapwrapper_platform
{
public:
	explicit linux_platform() :
		scapwrapper_platform(scap_linux_alloc_platform()) {
	}

	inline struct scap_linux_platform* get_scap_platform()
	{
		return reinterpret_cast<scap_linux_platform*>(m_scap_platform);
	}

	int32_t init_platform(struct scap_engine_handle engine, struct scap_open_args* oargs) override;
	int32_t get_agent_info(agent_info &agent_info) override;
	uint32_t get_device_by_mount_id(const char *procdir, unsigned long requested_mount_id) override;
	int64_t get_global_pid() override;

	int32_t dump_state(struct scap_dumper *d, uint64_t flags) override;
protected:
	void fill_machine_info();

	std::unordered_map<unsigned long, uint32_t> m_dev_map;
};
}