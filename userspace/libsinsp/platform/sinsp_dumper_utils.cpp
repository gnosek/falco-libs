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

#include "sinsp_dumper_utils.h"
#include "savefile/scap_savefile_api.h"

void libsinsp::dumper::outer_block::append(const inner_block& block)
{
	const auto& block_buf = block.data();
	uint32_t block_len = block_buf.size();

	// every inner block is prepended by its length
	const char* begin = (const char*)&block_len;
	const char* end = begin + sizeof(block);
	m_buf.insert(m_buf.end(), begin, end);
	m_buf.insert(m_buf.end(), block_buf.begin(), block_buf.end());
}

void libsinsp::dumper::outer_block::dump(struct scap_dumper* d)
{
	// pad the data to a multiple of 4 bytes
	size_t padding = scap_normalize_block_len(m_buf.size()) - m_buf.size();
	m_buf.insert(m_buf.end(), 0, padding);

	// prepare the block header and trailer
	uint32_t bt; // block trailer
	block_header bh = {
		.block_type = m_block_type,
		.block_total_length = (uint32_t)(sizeof(bh) + m_buf.size() + sizeof(bt)),
	};
	bt = bh.block_total_length;

	if (scap_dump_write(d, &bh, sizeof(bh)) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_dump_getlasterr(d));
	}

	if (scap_dump_write(d, m_buf.data(), m_buf.size()) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_dump_getlasterr(d));
	}

	if (scap_dump_write(d, &bt, sizeof(bt)) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_dump_getlasterr(d));
	}
}
