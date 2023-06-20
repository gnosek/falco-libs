if(NOT DEFINED SCAP_HOSTNAME_ENV_VAR)
	set(SCAP_HOSTNAME_ENV_VAR "SCAP_HOSTNAME")
endif()
add_definitions(-DSCAP_HOSTNAME_ENV_VAR="${SCAP_HOSTNAME_ENV_VAR}")

set (sinsp_platform_SOURCES sinsp_platform.cpp sinsp_platform_scapwrapper.cpp sinsp_platform_savefile.cpp sinsp_dumper_utils.cpp sinsp_reader_utils.cpp ../sinsp_exception.cpp machineinfo.cpp)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	list(APPEND sinsp_platform_SOURCES sinsp_platform_linux.cpp addrlist_linux.cpp)
endif()

add_library(sinsp_platform ${sinsp_platform_SOURCES})