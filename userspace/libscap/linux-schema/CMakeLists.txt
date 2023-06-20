add_library(scap_linux_schema linux_savefile_write.c linux_savefile_read.c linux_savefile_read.h scap_fds.c scap_iflist.c scap_procs.c scap_userlist.c schema.c)

target_link_libraries(scap_linux_schema scap_savefile)