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
};
}