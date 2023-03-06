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

#include <stdint.h>

#include "scap_limits.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CREDENTIALS_STR_LEN 256
/*!
  \brief Information about one of the machine users
*/
typedef struct scap_userinfo
{
	uint32_t uid; ///< User ID
	uint32_t gid; ///< Group ID
	char name[MAX_CREDENTIALS_STR_LEN]; ///< Username
	char homedir[SCAP_MAX_PATH_SIZE]; ///< Home directory
	char shell[SCAP_MAX_PATH_SIZE]; ///< Shell program
}scap_userinfo;

/*!
  \brief Information about one of the machine user groups
*/
typedef struct scap_groupinfo
{
	uint32_t gid; ///< Group ID
	char name[MAX_CREDENTIALS_STR_LEN]; ///< Group name
}scap_groupinfo;

/*!
  \brief List of the machine users and groups
*/
typedef struct scap_userlist
{
	uint32_t nusers; ///< Number of users
	uint32_t ngroups; ///< Number of groups
	uint32_t totsavelen; ///< For internal use
	scap_userinfo* users;  ///< User list
	scap_groupinfo* groups; ///< Group list
}scap_userlist;

#ifdef __cplusplus
}
#endif
