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

#include "machineinfo.h"

#include "sinsp_dumper_utils.h"
#include "sinsp_reader_utils.h"

libsinsp::dumper::outer_block libsinsp::platform_linux::dump_machine_info(scap_machine_info &machine_info)
{
	auto block = libsinsp::dumper::outer_block(MI_BLOCK_TYPE);
	block.append(machine_info);
	return block;
}

void libsinsp::platform_linux::read_machine_info(libsinsp::reader::outer_block &block, scap_machine_info &machine_info)
{
	block.consume(machine_info);
	block.finish();

	if(!scap_machine_info_os_arch_present(&machine_info))
	{
		// a reasonable assumption for captures without the platform
		machine_info.flags |= SCAP_OS_LINUX;
		machine_info.flags |= SCAP_ARCH_X64;
	}
}
