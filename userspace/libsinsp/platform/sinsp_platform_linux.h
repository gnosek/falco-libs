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

namespace libsinsp
{
class linux_platform : public scapwrapper_platform
{
public:
	explicit linux_platform(const struct scap_linux_vtable* linux_vtable = nullptr):
		scapwrapper_platform(scap_linux_alloc_platform()) {
		auto linux_plat = reinterpret_cast<scap_linux_platform*>(m_scap_platform);
		linux_plat->m_linux_vtable = linux_vtable;
	}

	static struct scap_platform* alloc(const struct scap_linux_vtable* linux_vtable = nullptr)
	{
		auto* platform = new platform_struct;
		platform->m_platform = std::make_unique<linux_platform>();
		platform->m_generic.m_vtable = &cpp_platform_vtable;

		return reinterpret_cast<struct scap_platform*>(platform);
	}
};
}