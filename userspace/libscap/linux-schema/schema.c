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

#include "schema.h"
#include "scap_open.h"

int32_t scap_linux_storage_init(struct scap_linux_storage* storage, char* lasterr, struct scap_open_args* oargs)
{
	storage->m_machine_info.num_cpus = -1u;
	storage->m_proclist.m_proc_callback = oargs->proc_callback;
	storage->m_proclist.m_proc_callback_context = oargs->proc_callback_context;
	storage->m_proclist.m_proclist = NULL;

	return SCAP_SUCCESS;
}

int32_t scap_linux_storage_close(struct scap_linux_storage* storage)
{
	if (storage->m_addrlist)
	{
		scap_free_iflist(storage->m_addrlist);
		storage->m_addrlist = NULL;
	}

	if (storage->m_userlist)
	{
		scap_free_userlist(storage->m_userlist);
		storage->m_userlist = NULL;
	}

	if(storage->m_proclist.m_proclist != NULL)
	{
		scap_proc_free_table(&storage->m_proclist);
		storage->m_proclist.m_proclist = NULL;
	}

	return SCAP_SUCCESS;
}

