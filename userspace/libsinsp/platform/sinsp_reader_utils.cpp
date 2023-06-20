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

#include "sinsp_reader_utils.h"

using namespace libsinsp::reader;

uint32_t outer_block::block_type()
{
	if(m_bh.block_type == 0)
	{
		read_header();
	}

	return m_bh.block_type;
}

std::unique_ptr<inner_block> libsinsp::reader::outer_block::next()
{
	if(m_bh.block_type == 0)
	{
		read_header();
	}

	if(m_remaining < sizeof(uint32_t))
	{
		finish();
	}

	int32_t len;
	read(len);

	m_buf.resize(len);
	raw_read(m_buf.data(), m_buf.size());

	return std::make_unique<inner_block>(m_bh.block_type, m_buf.begin(), m_buf.end());
}
void outer_block::finish()
{
	uint32_t trailer;
	raw_read(&trailer, m_remaining); // padding
	read(trailer);

	if(trailer != m_bh.block_total_length)
	{
		throw sinsp_errprintf(0, "Mismatched header/trailer lengths: %u vs %u", m_bh.block_total_length, trailer);
	}
}
