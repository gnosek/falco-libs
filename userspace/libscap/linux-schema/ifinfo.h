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

#ifdef __cplusplus
extern "C" {
#endif

#include "uthash.h"

//
// The following stuff is byte aligned because we save it to disk.
//
#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#elif defined __sun
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

/*!
  \brief Interface address type
*/
typedef enum scap_ifinfo_type
{
	SCAP_II_UNKNOWN = 0,
	SCAP_II_IPV4 = 1,
	SCAP_II_IPV6 = 2,
	SCAP_II_IPV4_NOLINKSPEED = 3,
	SCAP_II_IPV6_NOLINKSPEED = 4,
}scap_ifinfo_type;

/*!
  \brief IPv4 interface address information
*/
typedef struct scap_ifinfo_ipv4
{
	// NB: new fields must be appended
	uint16_t type; ///< Interface type
	uint16_t ifnamelen;
	uint32_t addr; ///< Interface address
	uint32_t netmask; ///< Interface netmask
	uint32_t bcast; ///< Interface broadcast address
	uint64_t linkspeed; ///< Interface link speed
	char ifname[SCAP_MAX_PATH_SIZE]; ///< interface name (e.g. "eth0")
}scap_ifinfo_ipv4;

/*!
  \brief IPv6 interface address information
*/
typedef struct scap_ifinfo_ipv6
{
	// NB: new fields must be appended
	uint16_t type;
	uint16_t ifnamelen;
	char addr[SCAP_IPV6_ADDR_LEN]; ///< Interface address
	char netmask[SCAP_IPV6_ADDR_LEN]; ///< Interface netmask
	char bcast[SCAP_IPV6_ADDR_LEN]; ///< Interface broadcast address
	uint64_t linkspeed; ///< Interface link speed
	char ifname[SCAP_MAX_PATH_SIZE]; ///< interface name (e.g. "eth0")
}scap_ifinfo_ipv6;

#if defined __sun
#pragma pack()
#else
#pragma pack(pop)
#endif

/*!
  \brief List of the machine network interfaces
*/
typedef struct scap_addrlist
{
	uint32_t n_v4_addrs; ///< Number of IPv4 addresses
	uint32_t n_v6_addrs; ///< Number of IPv6 addresses
	uint32_t totlen; ///< For internal use
	scap_ifinfo_ipv4* v4list; ///< List of IPv4 Addresses
	scap_ifinfo_ipv6* v6list; ///< List of IPv6 Addresses
}scap_addrlist;


#ifdef __cplusplus
}
#endif
