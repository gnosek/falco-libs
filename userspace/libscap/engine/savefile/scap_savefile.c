/*
Copyright (C) 2022 The Falco Authors.

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


#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <unistd.h>
#include <sys/uio.h>
#else
struct iovec {
	void  *iov_base;    /* Starting address */
	size_t iov_len;     /* Number of bytes to transfer */
};
#endif

#define SCAP_HANDLE_T struct savefile_engine
#include "savefile.h"
#include "scap.h"
#include "scap-int.h"
#include "scap_platform.h"
#include "scap_savefile.h"
#include "savefile_platform.h"
#include "scap_reader.h"
#include "../noop/noop.h"

#include "strlcpy.h"
#include "linux-schema/linux_savefile_read.h"

//
// Read the section header block
//
inline static int read_block_header(struct savefile_engine* handle, struct scap_reader *r, block_header* h)
{
	int res = sizeof(block_header);
	if (!handle->m_use_last_block_header)
	{
		res = r->read(r, &handle->m_last_block_header, sizeof(block_header));
	}
	memcpy(h, &handle->m_last_block_header, sizeof(block_header));
	handle->m_use_last_block_header = false;
	return res;
}

//
// Load the machine info block
//
static int32_t scap_read_machine_info(scap_reader_t* r, uint32_t block_length, uint32_t block_type, struct scap_platform* platform, char* error)
{
	scap_machine_info* machine_info = &platform->m_machine_info;
	//
	// Read the section header block
	//
	if(r->read(r, machine_info, sizeof(*machine_info)) !=
		sizeof(*machine_info))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error reading from file (1)");
		return SCAP_FAILURE;
	}

	if(!scap_machine_info_os_arch_present(machine_info))
	{
		// a reasonable assumption for captures without the platform
		machine_info->flags |= SCAP_OS_LINUX;
		machine_info->flags |= SCAP_ARCH_X64;
	}

	return SCAP_SUCCESS;
}

static int32_t scap_read_section_header(scap_reader_t* r, char* error)
{
	section_header_block sh;
	uint32_t bt;

	//
	// Read the section header block
	//
	if(r->read(r, &sh, sizeof(sh)) != sizeof(sh) ||
	   r->read(r, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error reading from file (1)");
		return SCAP_FAILURE;
	}

	if(sh.byte_order_magic != 0x1a2b3c4d)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "invalid magic number");
		return SCAP_FAILURE;
	}

	if(sh.major_version > CURRENT_MAJOR_VERSION)
	{
		snprintf(error, SCAP_LASTERR_SIZE,
			 "cannot correctly parse the capture. Upgrade your version.");
		return SCAP_VERSION_MISMATCH;
	}

	return SCAP_SUCCESS;
}

//
// Parse the headers of a trace file and load the tables
//
static int32_t scap_read_init(struct savefile_engine *handle, scap_reader_t* r, struct scap_platform* platform, char* error)
{
	block_header bh;
	uint32_t bt;
	size_t readsize;
	size_t toread;
	int fseekres;
	int32_t rc;
	int8_t found_ev = 0;

	//
	// Read the section header block
	//
	if(read_block_header(handle, r, &bh) != sizeof(bh))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error reading from file (1)");
		return SCAP_FAILURE;
	}

	if(bh.block_type != SHB_BLOCK_TYPE)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "invalid block type");
		return SCAP_FAILURE;
	}

	if((rc = scap_read_section_header(r, error)) != SCAP_SUCCESS)
	{
		return rc;
	}

	//
	// Read the metadata blocks (processes, FDs, etc.)
	//
	while(true)
	{
		readsize = read_block_header(handle, r, &bh);

		//
		// If we don't find the event block header,
		// it means there is no event in the file.
		//
		if (readsize == 0 && !found_ev)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "no events in file");
			return SCAP_FAILURE;
		}

		CHECK_READ_SIZE_ERR(readsize, sizeof(bh), error);

		switch(bh.block_type)
		{
		case MI_BLOCK_TYPE:
		case MI_BLOCK_TYPE_INT:
			if(scap_read_machine_info(
				   r,
				   bh.block_total_length - sizeof(block_header) - 4,
				   bh.block_type,
				   platform,
				   error) != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;

		case EV_BLOCK_TYPE:
		case EV_BLOCK_TYPE_INT:
		case EV_BLOCK_TYPE_V2:
		case EVF_BLOCK_TYPE:
		case EVF_BLOCK_TYPE_V2:
		case EV_BLOCK_TYPE_V2_LARGE:
		case EVF_BLOCK_TYPE_V2_LARGE:
			//
			// We're done with the metadata headers.
			//
			found_ev = 1;
			handle->m_use_last_block_header = true;
			break;

		default:
			rc = scap_read_linux_block(r, bh.block_total_length - sizeof(block_header) - 4, bh.block_type,
						   platform, error);

			if(rc == SCAP_NOT_SUPPORTED)
			{
				//
				// Unknown block type. Skip the block.
				//
				toread = bh.block_total_length - sizeof(block_header) - 4;
				fseekres = (int) r->seek(r, (long)toread, SEEK_CUR);
				if(fseekres == -1)
				{
					snprintf(error, SCAP_LASTERR_SIZE, "corrupted input file. Can't skip block of type %x and size %u.",
						 (int)bh.block_type,
						 (unsigned int)toread);
					return SCAP_FAILURE;
				}
			}
			else if(rc != SCAP_SUCCESS)
			{
				return SCAP_FAILURE;
			}
			break;
		}

		if(found_ev)
		{
			break;
		}

		//
		// Read and validate the trailer
		//
		readsize = r->read(r, &bt, sizeof(bt));
		CHECK_READ_SIZE_ERR(readsize, sizeof(bt), error);

		if(bt != bh.block_total_length)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "wrong block total length, header=%u, trailer=%u",
			         bh.block_total_length,
			         bt);
			return SCAP_FAILURE;
		}
	}

	//
	// NOTE: can't require a user list block, interface list block, or machine info block
	//       any longer--with the introduction of source plugins, it is legitimate to have
	//       trace files that don't contain those blocks
	//

	return SCAP_SUCCESS;
}

//
// Read an event from disk
//
static int32_t next(struct scap_engine_handle engine, scap_evt **pevent, uint16_t *pcpuid)
{
	struct savefile_engine* handle = engine.m_handle;
	block_header bh;
	size_t readsize;
	uint32_t readlen;
	size_t hdr_len;
	scap_reader_t* r = handle->m_reader;

	ASSERT(r != NULL);

	//
	// We may have to repeat the whole process
	// if the capture contains new syscalls
	//
	while(true)
	{
		//
		// Read the block header
		//
		readsize = read_block_header(handle, r, &bh);

		if(readsize != sizeof(bh))
		{
			int err_no = 0;
#ifdef _WIN32
			const char* err_str = "read error";
#else
			const char* err_str = r->error(r, &err_no);
#endif
			if(err_no)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error reading file: %s, ernum=%d", err_str, err_no);
				return SCAP_FAILURE;
			}

			if(readsize == 0)
			{
				//
				// We read exactly 0 bytes. This indicates a correct end of file.
				//
				return SCAP_EOF;
			}
			else
			{
				CHECK_READ_SIZE(readsize, sizeof(bh));
			}
		}

		if(bh.block_type != EV_BLOCK_TYPE &&
		   bh.block_type != EV_BLOCK_TYPE_V2 &&
		   bh.block_type != EV_BLOCK_TYPE_V2_LARGE &&
		   bh.block_type != EV_BLOCK_TYPE_INT &&
		   bh.block_type != EVF_BLOCK_TYPE &&
		   bh.block_type != EVF_BLOCK_TYPE_V2 &&
		   bh.block_type != EVF_BLOCK_TYPE_V2_LARGE)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "unexpected block type %u", (uint32_t)bh.block_type);
			handle->m_use_last_block_header = true;
			return SCAP_UNEXPECTED_BLOCK;
		}

		hdr_len = sizeof(struct ppm_evt_hdr);
		if(bh.block_type != EV_BLOCK_TYPE_V2 &&
		   bh.block_type != EV_BLOCK_TYPE_V2_LARGE &&
		   bh.block_type != EVF_BLOCK_TYPE_V2 &&
		   bh.block_type != EVF_BLOCK_TYPE_V2_LARGE)
		{
			hdr_len -= 4;
		}

		if(bh.block_total_length < sizeof(bh) + hdr_len + 4)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "block length too short %u", (uint32_t)bh.block_total_length);
			return SCAP_FAILURE;
		}

		//
		// Read the event
		//
		readlen = bh.block_total_length - sizeof(bh);
		// Non-large block types have an uint16_max maximum size
		if (bh.block_type != EV_BLOCK_TYPE_V2_LARGE && bh.block_type != EVF_BLOCK_TYPE_V2_LARGE) {
			if(readlen > READER_BUF_SIZE) {
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "event block length %u greater than NON-LARGE read buffer size %u",
					 readlen,
					 READER_BUF_SIZE);
				return SCAP_FAILURE;
			}
		} else if (readlen > handle->m_reader_evt_buf_size) {
			// Try to allocate a buffer large enough
			char *tmp = realloc(handle->m_reader_evt_buf, readlen);
			if (!tmp) {
				free(handle->m_reader_evt_buf);
				handle->m_reader_evt_buf = NULL;
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "event block length %u greater than read buffer size %zu",
					 readlen,
					 handle->m_reader_evt_buf_size);
				return SCAP_FAILURE;
			}
			handle->m_reader_evt_buf = tmp;
			handle->m_reader_evt_buf_size = readlen;
		}

		readsize = r->read(r, handle->m_reader_evt_buf, readlen);
		CHECK_READ_SIZE(readsize, readlen);

		//
		// EVF_BLOCK_TYPE has 32 bits of flags
		//
		*pcpuid = *(uint16_t *)handle->m_reader_evt_buf;

		if(bh.block_type == EVF_BLOCK_TYPE || bh.block_type == EVF_BLOCK_TYPE_V2 || bh.block_type == EVF_BLOCK_TYPE_V2_LARGE)
		{
			handle->m_last_evt_dump_flags = *(uint32_t*)(handle->m_reader_evt_buf + sizeof(uint16_t));
			*pevent = (struct ppm_evt_hdr *)(handle->m_reader_evt_buf + sizeof(uint16_t) + sizeof(uint32_t));
		}
		else
		{
			handle->m_last_evt_dump_flags = 0;
			*pevent = (struct ppm_evt_hdr *)(handle->m_reader_evt_buf + sizeof(uint16_t));
		}

		if((*pevent)->type >= PPM_EVENT_MAX)
		{
			//
			// We're reading a capture that contains new syscalls.
			// We can't do anything else that skips them.
			//
			continue;
		}

		if(bh.block_type != EV_BLOCK_TYPE_V2 &&
		   bh.block_type != EV_BLOCK_TYPE_V2_LARGE &&
		   bh.block_type != EVF_BLOCK_TYPE_V2 &&
		   bh.block_type != EVF_BLOCK_TYPE_V2_LARGE)
		{
			//
			// We're reading an old capture whose events don't have nparams in the header.
			// Convert it to the current version.
			//
			if((readlen + sizeof(uint32_t)) > READER_BUF_SIZE)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "cannot convert v1 event block to v2 (%lu greater than read buffer size %u)",
					 readlen + sizeof(uint32_t),
					 READER_BUF_SIZE);
				return SCAP_FAILURE;
			}

			memmove((char *)*pevent + sizeof(struct ppm_evt_hdr),
				(char *)*pevent + sizeof(struct ppm_evt_hdr) - sizeof(uint32_t),
				readlen - ((char *)*pevent - handle->m_reader_evt_buf) - (sizeof(struct ppm_evt_hdr) - sizeof(uint32_t)));
			(*pevent)->len += sizeof(uint32_t);

			// In old captures, the length of PPME_NOTIFICATION_E and PPME_INFRASTRUCTURE_EVENT_E
			// is not correct. Adjust it, otherwise the following code will never find a match
			if((*pevent)->type == PPME_NOTIFICATION_E || (*pevent)->type == PPME_INFRASTRUCTURE_EVENT_E)
			{
				(*pevent)->len -= 3;
			}

			//
			// The number of parameters needs to be calculated based on the block len.
			// Use the current number of parameters as starting point and decrease it
			// until size matches.
			//
			char *end = (char *)*pevent + (*pevent)->len;
			uint16_t *lens = (uint16_t *)((char *)*pevent + sizeof(struct ppm_evt_hdr));
			uint32_t nparams;
			bool done = false;
			for(nparams = g_event_info[(*pevent)->type].nparams; (int)nparams >= 0; nparams--)
			{
				char *valptr = (char *)lens + nparams * sizeof(uint16_t);
				if(valptr > end)
				{
					continue;
				}
				uint32_t i;
				for(i = 0; i < nparams; i++)
				{
					valptr += lens[i];
				}
				if(valptr < end)
				{
					snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "cannot convert v1 event block to v2 (corrupted trace file - can't calculate nparams).");
					return SCAP_FAILURE;
				}
				ASSERT(valptr >= end);
				if(valptr == end)
				{
					done = true;
					break;
				}
			}
			if(!done)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "cannot convert v1 event block to v2 (corrupted trace file - can't calculate nparams) (2).");
				return SCAP_FAILURE;
			}
			(*pevent)->nparams = nparams;
		}

		break;
	}

	return SCAP_SUCCESS;
}

uint64_t scap_savefile_ftell(struct scap_engine_handle engine)
{
	scap_reader_t* reader = engine.m_handle->m_reader;
	return reader->tell(reader);
}

void scap_savefile_fseek(struct scap_engine_handle engine, uint64_t off)
{
	scap_reader_t* reader = engine.m_handle->m_reader;
	reader->seek(reader, off, SEEK_SET);
}

static int32_t
scap_savefile_init_platform(struct scap_platform *platform, char *lasterr, struct scap_engine_handle engine,
			    struct scap_open_args *oargs)
{
	platform->m_machine_info.num_cpus = (uint32_t)-1;

	return SCAP_SUCCESS;
}

static int32_t scap_savefile_close_platform(struct scap_platform* platform)
{
	return SCAP_SUCCESS;
}

static void scap_savefile_free_platform(struct scap_platform* platform)
{
	free(platform);
}

bool scap_savefile_is_thread_alive(struct scap_platform* platform, int64_t pid, int64_t tid, const char* comm)
{
	return false;
}

static const struct scap_platform_vtable scap_savefile_platform_vtable = {
	.init_platform = scap_savefile_init_platform,
	.is_thread_alive = scap_savefile_is_thread_alive,
	.close_platform = scap_savefile_close_platform,
	.free_platform = scap_savefile_free_platform,
};

struct scap_platform* scap_savefile_alloc_platform()
{
    struct scap_savefile_platform* platform = calloc(sizeof(*platform), 1);

	if(platform == NULL)
	{
		return NULL;
	}

	platform->m_generic.m_vtable = &scap_savefile_platform_vtable;
	return &platform->m_generic;
}

static struct savefile_engine* alloc_handle(struct scap* main_handle, char* lasterr_ptr)
{
	struct savefile_engine *engine = calloc(1, sizeof(struct savefile_engine));
	if(engine)
	{
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;

}

static int32_t init(struct scap* main_handle, struct scap_open_args* oargs)
{
	gzFile gzfile;
	int res;
	struct savefile_engine *handle = main_handle->m_engine.m_handle;
	struct scap_savefile_engine_params* params = oargs->engine_params;
	struct scap_platform *platform = main_handle->m_platform;
	int fd = params->fd;
	const char* fname = params->fname;
	uint64_t start_offset = params->start_offset;
	uint32_t fbuffer_size = params->fbuffer_size;

	if(fd != 0)
	{
		gzfile = gzdopen(fd, "rb");
	}
	else
	{
		gzfile = gzopen(fname, "rb");
	}

	if(gzfile == NULL)
	{
		if(fd != 0)
		{
			snprintf(main_handle->m_lasterr, SCAP_LASTERR_SIZE, "can't open fd %d", fd);
		}
		else
		{
			snprintf(main_handle->m_lasterr, SCAP_LASTERR_SIZE, "can't open file %s", fname);
		}
		return SCAP_FAILURE;
	}

	scap_reader_t* reader = scap_reader_open_gzfile(gzfile);
	if(!reader)
	{
		gzclose(gzfile);
		return SCAP_FAILURE;
	}

	if (fbuffer_size > 0)
	{
		scap_reader_t* buffered_reader = scap_reader_open_buffered(reader, fbuffer_size, true);
		if(!buffered_reader)
		{
			reader->close(reader);
			return SCAP_FAILURE;
		}
		reader = buffered_reader;
	}

	//
	// If this is a merged file, we might have to move the read offset to the next section
	//
	if(start_offset != 0)
	{
		scap_fseek(main_handle, start_offset);
	}

	handle->m_use_last_block_header = false;

	res = scap_read_init(
		handle,
		reader,
		platform,
		main_handle->m_lasterr
	);

	if(res != SCAP_SUCCESS)
	{
		reader->close(reader);
		return res;
	}

	handle->m_reader_evt_buf = (char*)malloc(READER_BUF_SIZE);
	if(!handle->m_reader_evt_buf)
	{
		snprintf(main_handle->m_lasterr, SCAP_LASTERR_SIZE, "error allocating the read buffer");
		return SCAP_FAILURE;
	}
	handle->m_reader_evt_buf_size = READER_BUF_SIZE;
	handle->m_reader = reader;

	if(!oargs->import_users)
	{
		if(platform->m_userlist != NULL)
		{
			scap_free_userlist(platform->m_userlist);
			platform->m_userlist = NULL;
		}
	}

	return SCAP_SUCCESS;
}

static void free_handle(struct scap_engine_handle engine)
{
	free(engine.m_handle);
}

static int32_t scap_savefile_close(struct scap_engine_handle engine)
{
	struct savefile_engine* handle = engine.m_handle;
	if (handle->m_reader)
	{
		handle->m_reader->close(handle->m_reader);
		handle->m_reader = NULL;
	}

	if(handle->m_reader_evt_buf)
	{
		free(handle->m_reader_evt_buf);
		handle->m_reader_evt_buf = NULL;
	}

	return SCAP_SUCCESS;
}

static int32_t scap_savefile_restart_capture(scap_t* handle)
{
	struct savefile_engine *engine = handle->m_engine.m_handle;
	struct scap_platform *platform = handle->m_platform;
	int32_t res;

	scap_platform_close(platform);

	if((res = scap_read_init(
		engine,
		engine->m_reader,
		platform,
		handle->m_lasterr)) != SCAP_SUCCESS)
	{
		char error[SCAP_LASTERR_SIZE];
		snprintf(error, SCAP_LASTERR_SIZE, "could not restart capture: %s", scap_getlasterr(handle));
		strlcpy(handle->m_lasterr, error, SCAP_LASTERR_SIZE);
	}
	return res;
}

static int64_t get_readfile_offset(struct scap_engine_handle engine)
{
	return engine.m_handle->m_reader->offset(engine.m_handle->m_reader);
}

static uint32_t get_event_dump_flags(struct scap_engine_handle engine)
{
	return engine.m_handle->m_last_evt_dump_flags;
}

static struct scap_savefile_vtable savefile_ops = {
	.ftell_capture = scap_savefile_ftell,
	.fseek_capture = scap_savefile_fseek,

	.restart_capture = scap_savefile_restart_capture,
	.get_readfile_offset = get_readfile_offset,
	.get_event_dump_flags = get_event_dump_flags,
};

struct scap_vtable scap_savefile_engine = {
	.name = SAVEFILE_ENGINE,
	.mode = SCAP_MODE_CAPTURE,
	.savefile_ops = &savefile_ops,

	.alloc_handle = alloc_handle,
	.init = init,
	.free_handle = free_handle,
	.close = scap_savefile_close,
	.next = next,
	.start_capture = noop_start_capture,
	.stop_capture = noop_stop_capture,
	.configure = noop_configure,
	.get_stats = noop_get_stats,
	.get_stats_v2 = noop_get_stats_v2,
	.get_n_tracepoint_hit = noop_get_n_tracepoint_hit,
	.get_n_devs = noop_get_n_devs,
	.get_max_buf_used = noop_get_max_buf_used,
	.get_api_version = NULL,
	.get_schema_version = NULL,
};
