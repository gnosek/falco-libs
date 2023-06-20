/*
Copyright (C) 2021 The Falco Authors.

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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include "scap_limits.h"
#include "user.h"
#include "sinsp_exception.h"


#include <pwd.h>
#include <grp.h>

namespace libsinsp::platform_linux
{

void get_users(sinsp_usergroup_manager &usergroup_manager)
{
	bool file_lookup = false;
	FILE *f = NULL;
	char filename[SCAP_MAX_PATH_SIZE];
	struct passwd *p;
	struct group *g;

	//
	// If the list of users was already allocated for this handle (for example because this is
	// not the first user list block), free it
	//
	// Note: not supported by sinsp_usergroup_manager. Do we care?

	// check for host root
	const char *host_root = scap_get_host_root();
	if(host_root[0] == '\0')
	{
		file_lookup = false;
	}
	else
	{
		file_lookup = true;
	}

	// users
	if(file_lookup)
	{
		snprintf(filename, sizeof(filename), "%s/etc/passwd", host_root);
		f = fopen(filename, "r");
		if(f == nullptr)
		{
			// if we don't have it inside the host root, we'll proceed without a list
			return;
		}
	}
	else
	{
		setpwent();
	}

	while(file_lookup ? (p = fgetpwent(f)) : (p = getpwent()))
	{
		usergroup_manager.add_user("", -1, p->pw_uid, p->pw_gid, p->pw_name ? p->pw_name : "",
					   p->pw_dir ? p->pw_dir : "", p->pw_shell ? p->pw_shell : "");
	}

	if(file_lookup)
	{
		fclose(f);
	}
	else
	{
		endpwent();
	}

	// groups
	if(file_lookup)
	{
		snprintf(filename, sizeof(filename), "%s/etc/group", host_root);
		f = fopen(filename, "r");
		if(f == nullptr)
		{
			// if we reached this point we had passwd but we don't have group
			throw sinsp_errprintf(errno, "Failed to open %s", filename);
		}
	}
	else
	{
		setgrent();
	}

	while(file_lookup ? (g = fgetgrent(f)) : (g = getgrent()))
	{
		usergroup_manager.add_group("", -1, g->gr_gid, g->gr_name ? g->gr_name : "");
	}

	if(file_lookup)
	{
		fclose(f);
	}
	else
	{
		endgrent();
	}
}

}