set (sinsp_platform_SOURCES sinsp_platform.cpp sinsp_platform_scapwrapper.cpp sinsp_dumper_utils.cpp sinsp_reader_utils.cpp ../sinsp_exception.cpp)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	list(APPEND sinsp_platform_SOURCES sinsp_platform_linux.cpp addrlist_linux.cpp)
endif()

add_library(sinsp_platform ${sinsp_platform_SOURCES})