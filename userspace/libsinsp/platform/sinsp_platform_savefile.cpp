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

#include "sinsp_platform_savefile.h"
#include "savefile/scap_savefile.h"
#include "addrlist_linux.h"
#include "sinsp_reader_utils.h"
#include "sinsp_dumper_utils.h"
#include "machineinfo.h"

int32_t libsinsp::savefile_platform::read_block(struct scap_reader *r, uint32_t block_length, uint32_t block_type,
						uint64_t flags)
{
	switch(block_type)
	{
	case MI_BLOCK_TYPE:
	case MI_BLOCK_TYPE_INT:
	{
		libsinsp::reader::outer_block block(r, block_type, block_length);
		libsinsp::platform_linux::read_machine_info(block, m_machine_info);
	}

	case IL_BLOCK_TYPE:
	case IL_BLOCK_TYPE_INT:
	case IL_BLOCK_TYPE_V2:
	{
		libsinsp::reader::outer_block block(r, block_type, block_length);
		libsinsp::platform_linux::read_addrlist(block, m_network_interfaces);
	}
	default:
		return scapwrapper_platform::read_block(r, block_length, block_type, flags);
	}
}

int32_t libsinsp::savefile_platform::dump_state(struct scap_dumper *d, uint64_t flags)
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

	libsinsp::platform_linux::dump_addrlist(m_network_interfaces).dump(d);

	return SCAP_SUCCESS;
}
