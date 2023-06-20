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
#pragma once

#include <stdexcept>
#include <string>

/*!
  \brief sinsp library exception.
*/
class sinsp_exception : public std::runtime_error
{
public:
	sinsp_exception(const std::string& error_str):
		std::runtime_error(error_str)
	{ }

	sinsp_exception(const char* const error_str):
		std::runtime_error(error_str)
	{ }
};

sinsp_exception sinsp_errprintf_unchecked(int errnum, const char* fmt, ...);

#ifdef __GNUC__
sinsp_exception sinsp_errprintf_unchecked(int errnum, const char* fmt, ...) __attribute__ ((format (printf, 2, 3)));
#define sinsp_errprintf sinsp_errprintf_unchecked
#else

#include <stdio.h>

#define sinsp_errprintf(ERRNUM, ...) ((void)sizeof(printf(__VA_ARGS__)), sinsp_errprintf_unchecked(ERRNUM, __VA_ARGS__))
int32_t sinsp_errprintf_unchecked(int errnum, const char* fmt, ...);
#endif

#ifdef _DEBUG
#define DEBUG_THROW(exc) throw exc
#else
#define DEBUG_THROW(exc)
#endif