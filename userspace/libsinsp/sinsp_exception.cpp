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

#include "sinsp_exception.h"

/* ensure we're getting the XSI definition of strerror_r, not the GNU one */
#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200112L

#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "scap_const.h"

#ifndef _WIN32
static inline int strerror_s(char* buf, size_t size, int errnum)
{
	if(strerror_r(errnum, buf, size) == nullptr)
	{
		return errno;
	}
	else
	{
		return 0;
	}
}
#endif

sinsp_exception sinsp_errprintf_unchecked(int errnum, const char* fmt, ...)
{
	char buf[SCAP_LASTERR_SIZE];
	int len;

	va_list va;
	va_start(va, fmt);
	// no error, just print the message
	len = vsnprintf(buf, SCAP_LASTERR_SIZE, fmt, va);
	va_end(va);

	if (errnum > 0 && len < SCAP_LASTERR_SIZE - 1)
	{
		char err_buf[SCAP_LASTERR_SIZE];
		if(strerror_s(err_buf, sizeof(err_buf), errnum) < 0)
		{
			snprintf(err_buf, sizeof(err_buf), "Unknown error %d", errnum);
		}
		snprintf(buf + len, SCAP_LASTERR_SIZE - len, ": %s", err_buf);
	}

	// so you can throw sinsp_errprintf(...) directly
	return {buf};
}
