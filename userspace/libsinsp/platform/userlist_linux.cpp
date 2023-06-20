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
#include "sinsp_dumper_utils.h"
#include "sinsp_reader_utils.h"
#include "userlist_linux.h"
#include "strlcpy.h"

#include <pwd.h>
#include <grp.h>

namespace
{
libsinsp::dumper::inner_block dump_userinfo(const scap_userinfo &userinfo)
{
	uint16_t namelen = strnlen(userinfo.name, MAX_CREDENTIALS_STR_LEN);
	uint16_t homedirlen = strnlen(userinfo.homedir, SCAP_MAX_PATH_SIZE);
	uint16_t shelllen = strnlen(userinfo.shell, SCAP_MAX_PATH_SIZE);

	libsinsp::dumper::inner_block user_block;

	user_block.append((uint8_t)USERBLOCK_TYPE_USER);
	user_block.append(userinfo.uid);
	user_block.append(userinfo.gid);
	user_block.append(namelen);
	user_block.append(userinfo.name, namelen);
	user_block.append(homedirlen);
	user_block.append(userinfo.homedir, homedirlen);
	user_block.append(shelllen);
	user_block.append(userinfo.shell, shelllen);

	return user_block;
}

libsinsp::dumper::inner_block dump_groupinfo(const scap_groupinfo &groupinfo)
{
	uint16_t namelen = strnlen(groupinfo.name, MAX_CREDENTIALS_STR_LEN);

	libsinsp::dumper::inner_block user_block;

	user_block.append((uint8_t)USERBLOCK_TYPE_GROUP);
	user_block.append(groupinfo.gid);
	user_block.append(namelen);
	user_block.append(groupinfo.name, namelen);

	return user_block;
}

void read_userlist_entry(libsinsp::reader::inner_block& entry, libsinsp::platform_linux::userlist_storage &users)
{
	uint8_t uinfo_type;
	entry.read(uinfo_type);
	switch(uinfo_type)
	{
	case USERBLOCK_TYPE_USER:
	{
		struct scap_userinfo userinfo {};
		entry.read(userinfo.uid);
		entry.read(userinfo.gid);

		uint16_t namelen;
		entry.read(namelen);
		if(namelen >= sizeof(userinfo.name))
		{
			throw sinsp_errprintf(0, "user name too long (%u bytes)", namelen);
		}
		entry.read(userinfo.name, namelen);

		uint16_t dirlen;
		entry.read(dirlen);
		if(dirlen >= sizeof(userinfo.homedir))
		{
			throw sinsp_errprintf(0, "user dir too long (%u bytes)", dirlen);
		}
		entry.read(userinfo.homedir, dirlen);

		uint16_t shelllen;
		entry.read(shelllen);
		if(shelllen >= sizeof(userinfo.shell))
		{
			throw sinsp_errprintf(0, "user shell too long (%u bytes)", shelllen);
		}
		entry.read(userinfo.shell, shelllen);

		users.m_users.emplace(userinfo.uid, userinfo);
		return;
	}
	case USERBLOCK_TYPE_GROUP:
	{
		scap_groupinfo groupinfo {};
		entry.read(groupinfo.gid);
		uint16_t namelen;
		entry.read(namelen);
		if(namelen >= sizeof(groupinfo.name))
		{
			throw sinsp_errprintf(0, "user name too long (%u bytes)", namelen);
		}
		entry.read(groupinfo.name, namelen);

		users.m_groups.emplace(groupinfo.gid, groupinfo);
		return;
	}
	default:
		throw sinsp_errprintf(0, "Unsupported userlist info type %u", uinfo_type);
	}
}

void read_userlist_v1(libsinsp::reader::outer_block& block, libsinsp::platform_linux::userlist_storage &users)
{
	std::vector<unsigned char> buf;

	block.consume_append(buf, block.remaining());

	auto cursor = buf.cbegin();
	auto end = buf.cend();

	while(std::distance(cursor, end) >= sizeof(uint32_t))
	{
		libsinsp::reader::inner_block blk(block.block_type(), cursor, end);
		read_userlist_entry(blk, users);
		cursor = blk.cursor();
	}

	block.finish();
}

void read_userlist_v2(libsinsp::reader::outer_block& block, libsinsp::platform_linux::userlist_storage &users)
{
	while(true)
	{
		auto entry = block.next();
		if(!entry)
		{
			return;
		}

		read_userlist_entry(*entry, users);
	}
}
}

namespace libsinsp::platform_linux
{

void get_users(userlist_storage &users)
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
		scap_userinfo user {
			.uid = p->pw_uid,
			.gid = p->pw_gid,
		};

		if(p->pw_name)
		{
			strlcpy(user.name, p->pw_name, sizeof(user.name));
		}

		if(p->pw_dir)
		{
			strlcpy(user.homedir, p->pw_dir, sizeof(user.homedir));
		}

		if(p->pw_shell)
		{
			strlcpy(user.shell, p->pw_shell, sizeof(user.shell));
		}

		users.m_users.emplace(p->pw_uid, user);
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
		scap_groupinfo group {
			.gid = g->gr_gid
		};

		if(g->gr_name)
		{
			strlcpy(group.name, g->gr_name, sizeof(group.name));
		}

		users.m_groups.emplace(g->gr_gid, group);
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

libsinsp::dumper::outer_block dump_userlist(const userlist_storage &users)
{
	libsinsp::dumper::outer_block userlist_block(UL_BLOCK_TYPE_V2);

	for(const auto& [_uid, userinfo] : users.m_users)
	{
		userlist_block.append(dump_userinfo(userinfo));
	}

	for(const auto& [_gid, groupinfo] : users.m_groups)
	{
		userlist_block.append(dump_groupinfo(groupinfo));
	}

	return userlist_block;
}

void read_userlist(libsinsp::reader::outer_block& block, userlist_storage &users)
{
	switch(block.block_type())
	{
	case UL_BLOCK_TYPE:
	case UL_BLOCK_TYPE_INT:
		read_userlist_v1(block, users);
		return;
	case UL_BLOCK_TYPE_V2:
		read_userlist_v2(block, users);
		return;
	default:
		throw sinsp_errprintf(0, "Tried to read userlist from block type %u", block.block_type());
	}
}
}