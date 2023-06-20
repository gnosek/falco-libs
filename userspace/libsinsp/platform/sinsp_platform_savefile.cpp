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

int32_t libsinsp::savefile_platform::read_block(struct scap_reader *r, uint32_t block_length, uint32_t block_type,
						uint64_t flags)
{
	switch(block_type)
	{
	case IL_BLOCK_TYPE:
	case IL_BLOCK_TYPE_INT:
	case IL_BLOCK_TYPE_V2:
	{
		libsinsp::reader::outer_block block(r, block_type, block_length);
		libsinsp::platform_linux::read_addrlist(block, *m_network_interfaces);
	}
	default:
		return scapwrapper_platform::read_block(r, block_length, block_type, flags);
	}
}
