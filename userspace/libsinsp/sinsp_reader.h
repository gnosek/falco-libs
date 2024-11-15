#pragma once
#include <vector>
#include <engine/savefile/scap_reader.h>

class sinsp_mem_reader {
public:
  explicit sinsp_mem_reader(std::vector<char>& buffer)
	: m_buffer(buffer), m_cursor(m_buffer.data()) {}

  scap_reader_t get_reader();
  int32_t read(void* buf, uint32_t len);

private:
  std::vector<char>& m_buffer;
  char* m_cursor;
};
