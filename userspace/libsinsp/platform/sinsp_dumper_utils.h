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

#pragma once

#include <vector>

#include "sinsp_exception.h"
#include "savefile/scap_savefile.h"

namespace libsinsp::dumper
{

class inner_block
{
public:
	template<typename T> size_t append(T val)
	{
		const char* begin = (const char*)&val;
		const char* end = begin + sizeof(val);

		m_buf.insert(m_buf.end(), begin, end);
		return sizeof(val);
	}

	size_t append(const char* str, size_t len)
	{
		m_buf.insert(m_buf.end(), str, str + len);
		return len;
	}

	size_t append(const std::string& str)
	{
		m_buf.insert(m_buf.end(), str.begin(), str.end());
		return str.size();
	}

	[[nodiscard]] const std::vector<unsigned char>& data() const { return m_buf; }

private:
	std::vector<unsigned char> m_buf;
};

class outer_block
{
public:
	explicit outer_block(uint32_t block_type) : m_block_type(block_type) {}

	template<typename T> size_t append(T val)
	{
		const char* begin = (const char*)&val;
		const char* end = begin + sizeof(val);

		m_buf.insert(m_buf.end(), begin, end);
		return sizeof(val);
	}

	void append(const inner_block& block);

	void dump(struct scap_dumper* d);

private:
	uint32_t m_block_type;
	std::vector<unsigned char> m_buf;
};

}
