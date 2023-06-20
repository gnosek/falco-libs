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

#include "sinsp_platform_scapwrapper.h"

#include "sinsp.h"

libsinsp::scapwrapper_platform::scapwrapper_platform(scap_platform *scap_platform):
	m_scap_platform(scap_platform), m_network_interfaces(std::make_unique<sinsp_network_interfaces>())
{
}

libsinsp::scapwrapper_platform::~scapwrapper_platform()
{
	if(m_scap_platform)
	{
		scap_platform_close(m_scap_platform);
		scap_platform_free(m_scap_platform);
	}
}

int32_t libsinsp::scapwrapper_platform::init_platform(struct scap_engine_handle engine, struct scap_open_args *oargs)
{
	char lasterr[SCAP_LASTERR_SIZE];

	int32_t rc = vt()->init_platform(m_scap_platform, lasterr, engine, oargs);
	if(rc != SCAP_SUCCESS)
	{
		throw sinsp_exception(lasterr);
	}

	struct scap_addrlist* addrlist = get_linux_storage()->m_addrlist;
	m_network_interfaces->import_interfaces(addrlist);

	return rc;
}

void libsinsp::scapwrapper_platform::refresh_addr_list()
{
	char lasterr[SCAP_LASTERR_SIZE];

	int32_t rc = vt()->refresh_addr_list(m_scap_platform);
	if(rc != SCAP_SUCCESS)
	{
		throw sinsp_exception(lasterr);
	}

	struct scap_addrlist* addrlist = get_linux_storage()->m_addrlist;
	m_network_interfaces->clear();
	m_network_interfaces->import_interfaces(addrlist);
}
