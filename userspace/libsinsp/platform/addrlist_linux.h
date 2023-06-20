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

class sinsp_network_interfaces;

namespace libsinsp
{
namespace dumper {
class outer_block;
}
namespace platform_linux
{

void get_interfaces(sinsp_network_interfaces &interfaces);
libsinsp::dumper::outer_block dump_addrlist(sinsp_network_interfaces& interfaces);

}
}