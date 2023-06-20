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

#include "sinsp_platform_scapwrapper.h"
#include "userlist_linux.h"
#include "engine/savefile/savefile_public.h"

namespace libsinsp
{
class savefile_platform : public scapwrapper_platform
{
public:
	explicit savefile_platform() :
		scapwrapper_platform(scap_savefile_alloc_platform()) {
	}

	inline struct scap_savefile_platform* get_scap_platform()
	{
		return reinterpret_cast<scap_savefile_platform*>(m_scap_platform);
	}

	int32_t dump_state(struct scap_dumper *d, uint64_t flags) override;

	int32_t read_block(struct scap_reader *r, uint32_t block_length, uint32_t block_type, uint64_t flags) override;

protected:
	libsinsp::platform_linux::userlist_storage m_users;
};
}