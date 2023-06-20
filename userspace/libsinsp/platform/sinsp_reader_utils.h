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

#include <memory>
#include <vector>
#include <cstring>
#include "engine/savefile/scap_reader.h"
#include "sinsp_exception.h"
#include "savefile/scap_savefile.h"

namespace libsinsp::reader {

class inner_block
{
public:
	using iter = std::vector<unsigned char>::const_iterator;
	inner_block(uint32_t block_type, iter begin, iter end) : m_block_type(block_type), m_end(end), m_cursor(begin) {}

	[[nodiscard]] uint32_t get_block_type() const { return m_block_type; }

	template<typename T> void read(T& val)
	{
		if(remaining() < sizeof(val))
		{
			throw sinsp_errprintf(0, "Failed to read %ld bytes from scap file inner block", sizeof(val));
		}

		memcpy(&val, &(*m_cursor), sizeof(val));
		std::advance(m_cursor, sizeof(val));
	}

	void read(bool& val)
	{
		unsigned char byte;
		read(byte);
		val = byte;
	}

	void read(std::string& str, size_t len)
	{
		str.resize(len);
		read(str.data(), len);
	}

	void read(void* buf, size_t len)
	{
		if(remaining() < len)
		{
			throw sinsp_errprintf(0, "Failed to read %ld bytes from scap file inner block", len);
		}

		memcpy(buf, &(*m_cursor), len);
		std::advance(m_cursor, len);
	}

	[[nodiscard]] iter cursor() const { return m_cursor; }

	[[nodiscard]] size_t remaining() const { return std::distance(m_cursor, m_end); }

protected:
	uint32_t m_block_type;
	iter m_end;
	iter m_cursor;
};

class outer_block
{
public:
	explicit outer_block(scap_reader_t* reader): m_remaining(0), m_reader(reader) {}

	outer_block(scap_reader_t* reader, uint32_t block_type, uint32_t data_len):
		m_bh({.block_type = block_type, .block_total_length = (uint32_t)(data_len + sizeof(m_bh) + sizeof(uint32_t))}),
		m_remaining(data_len),
		m_reader(reader) {}

	[[nodiscard]] uint32_t block_type();

	std::unique_ptr<inner_block> next();

	[[nodiscard]] uint32_t remaining() const { return m_remaining; }

	template<typename T> void consume(T& val)
	{
		if(m_bh.block_type == 0)
		{
			read_header();
		}

		read(val);
	}

	void consume_append(std::vector<unsigned char>& buf, size_t len)
	{
		if(m_bh.block_type == 0)
		{
			read_header();
		}

		buf.resize(buf.size() + len);

		raw_read(buf.data() +buf.size(), len);
	}

	void finish();
protected:
	void raw_read(void* buf, size_t len)
	{
		if(m_remaining < len)
		{
			throw sinsp_errprintf(0, "Not enough data left in block (wanted %zu bytes, got %u)", len, m_remaining);
		}
		size_t nread = m_reader->read(m_reader, buf, len);
		m_remaining -= nread;
		if(nread != len)
		{
			throw sinsp_errprintf(0, "Failed to read %ld bytes from scap file", len);
		}
	}

	template<typename T> void read(T& val)
	{
		raw_read(&val, sizeof(val));
	}

	void read_header()
	{
		read(m_bh);
		m_remaining = m_bh.block_total_length - sizeof(m_bh) - sizeof(uint32_t);
	}

	block_header m_bh{};
	uint32_t m_remaining;
	scap_reader_t* m_reader;
	std::vector<unsigned char> m_buf;
};

}