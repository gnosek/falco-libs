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

//
// The `flags` field in scap_machine_info is laid out as follows:
// |<--SCAP_ARCH_BITS-->|<--SCAP_OS_BITS-->|<--SCAP_FLAGS_BITS-->|
//
// The top 8 bits describe the CPU architecture using one of the SCAP_ARCH_* constants
// The next 8 bits describe the OS using one of the SCAP_OS_* constants
// The final 48 bits describe any other remaining flags
//

#define SCAP_FLAGS_BITS 64

#define SCAP_ARCH_BITS 8
#define SCAP_ARCH_SHIFT (SCAP_FLAGS_BITS - SCAP_ARCH_BITS)
#define SCAP_ARCH_MASK (((1ULL << SCAP_ARCH_BITS) - 1) << SCAP_ARCH_SHIFT)

#define SCAP_ARCH_I386    (1ULL << SCAP_ARCH_SHIFT)
#define SCAP_ARCH_X64     (2ULL << SCAP_ARCH_SHIFT)
#define SCAP_ARCH_AARCH64 (3ULL << SCAP_ARCH_SHIFT)

#define SCAP_OS_BITS 8
#define SCAP_OS_SHIFT (SCAP_ARCH_SHIFT - SCAP_OS_BITS)
#define SCAP_OS_MASK (((1ULL << SCAP_OS_BITS) - 1) << SCAP_OS_SHIFT)

#define SCAP_OS_LINUX   (1ULL << SCAP_OS_SHIFT)
#define SCAP_OS_WINDOWS (2ULL << SCAP_OS_SHIFT)
#define SCAP_OS_MACOS   (3ULL << SCAP_OS_SHIFT)

/*!
  \brief Machine information
*/
typedef struct _scap_machine_info
{
	uint32_t num_cpus;	///< Number of processors
	uint64_t memory_size_bytes; ///< Physical memory size
	uint64_t max_pid; ///< Highest PID number on this machine
	char hostname[128]; ///< The machine hostname
	uint64_t boot_ts_epoch; ///< Host boot ts in nanoseconds (epoch)
	uint64_t flags; ///< flags
	uint64_t reserved3; ///< reserved for future use
	uint64_t reserved4; ///< reserved for future use, note: because of scap file captures needs to remain uint64_t, use flags if possible
}scap_machine_info;

#if defined __sun
#pragma pack()
#else
#pragma pack(pop)
#endif

static inline bool scap_machine_info_os_arch_present(scap_machine_info* machine_info)
{
	return machine_info->flags & (SCAP_ARCH_MASK | SCAP_OS_MASK);
}

#ifdef __cplusplus
}
#endif
