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

#include "linux-schema/fdinfo.h"
#include "linux-schema/ifinfo.h"
#include "linux-schema/mountinfo.h"
#include "linux-schema/threadinfo.h"
#include "linux-schema/userinfo.h"

#ifdef __cplusplus
extern "C" {
#endif

struct scap_open_args;

struct scap_linux_storage
{
	struct scap_addrlist *m_addrlist;
	struct scap_userlist *m_userlist;
	struct scap_proclist m_proclist;
};

int32_t scap_linux_storage_init(struct scap_linux_storage* storage, char* lasterr, struct scap_open_args* oargs);
int32_t scap_linux_storage_close(struct scap_linux_storage* storage);

#ifdef __cplusplus
}
#endif