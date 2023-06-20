/*
Copyright (C) 2022 The Falco Authors.

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

#include "scap_config.h"
#include "scap_platform.h"

#ifdef __linux__
#include "linux/scap_linux_platform.h"
#endif

#ifdef HAS_ENGINE_GVISOR
#include "engine/gvisor/gvisor_public.h"
#endif

#ifdef HAS_ENGINE_SAVEFILE
#include "engine/savefile/savefile_platform.h"
#endif

#ifdef HAS_ENGINE_TEST_INPUT
#include "engine/test_input/test_input_platform.h"
#endif
