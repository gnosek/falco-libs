#include "sinsp_reader.h"

#include <cstring>
#include <engine/savefile/scap_reader.h>

int32_t sinsp_mem_reader_read(scap_reader_t* r, void* buf, uint32_t len) {
	auto reader = static_cast<sinsp_mem_reader*>(r->handle);
	return reader->read(buf, len);
}

scap_reader_t sinsp_mem_reader::get_reader() {
	scap_reader_t reader;

	reader.handle = this;
	reader.read = sinsp_mem_reader_read;
	return reader;
}

int32_t sinsp_mem_reader::read(void* buf, uint32_t len) {
	auto buffer = m_cursor;
	auto buffer_end = m_buffer.data() + m_buffer.size();
	auto buffer_len = buffer_end - buffer;
	auto read_len = std::min(len, static_cast<uint32_t>(buffer_len));
	memcpy(buf, buffer, read_len);
	m_cursor += read_len;
	return read_len;
}
