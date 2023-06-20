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

#include "sinsp_platform_linux.h"

#if HAVE_SYS_MKDEV_H
#include <sys/mkdev.h>
#endif
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif

uint32_t libsinsp::linux_platform::get_device_by_mount_id(const char *procdir, unsigned long requested_mount_id)
{
	char fd_dir_name[SCAP_MAX_PATH_SIZE];
	char line[SCAP_MAX_PATH_SIZE];
	FILE *finfo;

	auto it = m_dev_map.find(requested_mount_id);
	if(it != m_dev_map.end())
	{
		return it->second;
	}

	snprintf(fd_dir_name, SCAP_MAX_PATH_SIZE, "%smountinfo", procdir);
	finfo = fopen(fd_dir_name, "r");
	if(finfo == NULL)
	{
		return 0;
	}

	while(fgets(line, sizeof(line), finfo) != NULL)
	{
		uint32_t mount_id, major, minor;
		if(sscanf(line, "%u %*u %u:%u", &mount_id, &major, &minor) != 3)
		{
			continue;
		}

		if(mount_id == requested_mount_id)
		{
			uint32_t dev = makedev(major, minor);
			m_dev_map[mount_id] = dev;
			fclose(finfo);
			return dev;
		}
	}
	fclose(finfo);
	return 0;
}
