// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <libscap/scap_const.h>
#include <driver/ppm_events_public.h>
#include <converter/table.h>

const std::unordered_map<conversion_key, conversion_info> g_conversion_table = {
        ////////////////////////////
        // READ
        ////////////////////////////
        {{PPME_SYSCALL_READ_E, 2}, {.action = C_ACTION_STORE}},
        {{PPME_SYSCALL_READ_X, 2},
         {.action = C_ACTION_ADD_PARAMS,
          .instr = {{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}}}},
        ////////////////////////////
        // PREAD
        ////////////////////////////
        {{PPME_SYSCALL_PREAD_E, 3}, {.action = C_ACTION_STORE}},
        {{PPME_SYSCALL_PREAD_X, 2},
         {.action = C_ACTION_ADD_PARAMS,
          .instr = {{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}, {C_INSTR_FROM_ENTER, 2}}}},
};