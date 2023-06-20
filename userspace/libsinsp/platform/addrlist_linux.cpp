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

#include "addrlist_linux.h"

#include "sinsp.h"
#include "sinsp_dumper_utils.h"

#include "strlcpy.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>

namespace {
libsinsp::dumper::inner_block dump_ipv4_addr(const sinsp_ipv4_ifinfo& ifinfo)
{
	libsinsp::dumper::inner_block ifinfo_block;
	ifinfo_block.append((uint16_t)SCAP_II_IPV4); // entry type
	ifinfo_block.append((uint16_t)ifinfo.m_name.size());
	ifinfo_block.append((uint32_t)ifinfo.m_addr);
	ifinfo_block.append((uint32_t)ifinfo.m_netmask);
	ifinfo_block.append((uint32_t)ifinfo.m_bcast);
	ifinfo_block.append((uint64_t)0); // link speed
	ifinfo_block.append(ifinfo.m_name);

	return ifinfo_block;
}

libsinsp::dumper::inner_block dump_ipv6_addr(const sinsp_ipv6_ifinfo& ifinfo)
{
	libsinsp::dumper::inner_block ifinfo_block;
	ifinfo_block.append((uint16_t)SCAP_II_IPV6); // entry type
	ifinfo_block.append((uint16_t)ifinfo.m_name.size());
	ifinfo_block.append(ifinfo.m_net.m_b);
	ifinfo_block.append(ifinfo.m_netmask.m_b);
	ifinfo_block.append(ifinfo.m_bcast.m_b);
	ifinfo_block.append((uint64_t)0); // link speed
	ifinfo_block.append(ifinfo.m_name);

	return ifinfo_block;
}
}

namespace libsinsp::platform_linux {

//
// Allocate and return the list of interfaces on this system
//
void get_interfaces(sinsp_network_interfaces &interfaces)
{
	struct ifaddrs *interfaceArray = nullptr, *tempIfAddr = nullptr;
	int rc = 0;

	//
	// If the list of interfaces was already allocated for this handle (for example because this is
	// not the first interface list block), free it
	//
	interfaces.clear();

	rc = getifaddrs(&interfaceArray);  /* retrieve the current interfaces */
	if(rc != 0)
	{
		throw sinsp_errprintf(errno, "getifaddrs() failed");
	}

	for(tempIfAddr = interfaceArray; tempIfAddr != nullptr; tempIfAddr = tempIfAddr->ifa_next)
	{
		if(tempIfAddr->ifa_addr == nullptr)
		{
			// "eql" interface like on EC2
			continue;
		}

		if(tempIfAddr->ifa_addr->sa_family == AF_INET)
		{
			sinsp_ipv4_ifinfo ipaddr(0, 0, 0, tempIfAddr->ifa_name);

			ipaddr.m_addr = ((struct sockaddr_in *)tempIfAddr->ifa_addr)->sin_addr.s_addr;

			if(tempIfAddr->ifa_netmask)
			{
				ipaddr.m_netmask = ((struct sockaddr_in *)tempIfAddr->ifa_netmask)->sin_addr.s_addr;
			}

			if(tempIfAddr->ifa_ifu.ifu_broadaddr)
			{
				ipaddr.m_bcast = ((struct sockaddr_in *)tempIfAddr->ifa_ifu.ifu_broadaddr)->sin_addr.s_addr;
			}

			interfaces.import_ipv4_interface(ipaddr);
		}
		else if(tempIfAddr->ifa_addr->sa_family == AF_INET6)
		{
			sinsp_ipv6_ifinfo ipaddr;
			ipaddr.m_name = tempIfAddr->ifa_name;

			memcpy(ipaddr.m_net.m_b, &((struct sockaddr_in6 *)tempIfAddr->ifa_addr)->sin6_addr, SCAP_IPV6_ADDR_LEN);

			if(tempIfAddr->ifa_netmask)
			{
				memcpy(ipaddr.m_netmask.m_b, &((struct sockaddr_in *)tempIfAddr->ifa_netmask)->sin_addr.s_addr, SCAP_IPV6_ADDR_LEN);
			}

			if(tempIfAddr->ifa_ifu.ifu_broadaddr)
			{
				memcpy(ipaddr.m_bcast.m_b, &((struct sockaddr_in *)tempIfAddr->ifa_ifu.ifu_broadaddr)->sin_addr.s_addr, SCAP_IPV6_ADDR_LEN);
			}

			interfaces.import_ipv6_interface(ipaddr);
		}
		else
		{
			continue;
		}
	}

	//
	// Memory cleanup
	//
	freeifaddrs(interfaceArray);
}

libsinsp::dumper::outer_block dump_addrlist(sinsp_network_interfaces& interfaces)
{
	libsinsp::dumper::outer_block addrlist_block(IL_BLOCK_TYPE_V2);

	for(const auto& ipv4 : interfaces.get_ipv4_list())
	{
		addrlist_block.append(dump_ipv4_addr(ipv4));
	}

	for(const auto& ipv6 : interfaces.get_ipv6_list())
	{
		addrlist_block.append(dump_ipv6_addr(ipv6));
	}

	return addrlist_block;
}
}
