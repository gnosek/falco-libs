/*
Copyright (C) 2021 The Falco Authors.

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

#include "scap.h"
#include "scap-int.h"
#include "scap_platform_impl.h"
#include "scap_savefile_api.h"
#include "scap_savefile.h"
#include "strlcpy.h"
#include "linux-schema/linux_savefile_write.h"

const char* scap_dump_getlasterr(scap_dumper_t* d)
{
	return d ? d->m_lasterr : "null dumper";
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// WRITE FUNCTIONS
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

//
// Write data into a dump file
//
int scap_dump_write(scap_dumper_t *d, void* buf, unsigned len)
{
	if(d->m_type == DT_FILE)
	{
		return gzwrite(d->m_f, buf, len);
	}
	else
	{
		if(d->m_targetbufcurpos + len >= d->m_targetbufend)
		{
			if(d->m_type == DT_MEM)
			{
				return -1;
			}

			// DT_MANAGED_BUF, try to increase the size
			size_t targetbufsize = PPM_DUMPER_MANAGED_BUF_RESIZE_FACTOR * (d->m_targetbufend - d->m_targetbuf);

			uint8_t *targetbuf = (uint8_t *)realloc(
				d->m_targetbuf,
				targetbufsize);
			if(targetbuf == NULL)
			{
				free(d->m_targetbuf);
				return -1;
			}

			size_t offset = (d->m_targetbufcurpos - d->m_targetbuf);
			d->m_targetbuf = targetbuf;
			d->m_targetbufcurpos = targetbuf + offset;
			d->m_targetbufend = targetbuf + targetbufsize;
		}

		memcpy(d->m_targetbufcurpos, buf, len);

		d->m_targetbufcurpos += len;
		return len;
	}
}

int scap_dump_writev(scap_dumper_t *d, const struct iovec *iov, int iovcnt)
{
	unsigned totlen = 0;
	int i;

	for (i = 0; i < iovcnt; i++)
	{
		if(scap_dump_write(d, iov[i].iov_base, iov[i].iov_len) < 0)
		{
			return -1;
		}

		totlen += iov[i].iov_len;
	}

	return totlen;
}

uint8_t* scap_get_memorydumper_curpos(scap_dumper_t *d)
{
	return d->m_targetbufcurpos;
}

//
// Create the dump file headers and add the tables
//
static int32_t scap_setup_dump(scap_dumper_t *d, struct scap_platform *platform, const char *fname, bool skip_proc_scan)
{
	block_header bh;
	section_header_block sh;
	uint32_t bt;
	scap_machine_info mi;

	//
	// Write the section header
	//
	bh.block_type = SHB_BLOCK_TYPE;
	bh.block_total_length = sizeof(block_header) + sizeof(section_header_block) + 4;

	sh.byte_order_magic = SHB_MAGIC;
	sh.major_version = CURRENT_MAJOR_VERSION;
	sh.minor_version = CURRENT_MINOR_VERSION;
	sh.section_length = 0xffffffffffffffffLL;

	bt = bh.block_total_length;

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh) ||
	        scap_dump_write(d, &sh, sizeof(sh)) != sizeof(sh) ||
	        scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file %s  (5)", fname);
		return SCAP_FAILURE;
	}

	if(!platform)
	{
		return SCAP_SUCCESS;
	}

	if(!platform->m_vtable->dump_state)
	{
		return SCAP_SUCCESS;
	}

	//
	// If we're dumping in live mode, refresh the process tables list
	// so we don't lose information about processes created in the interval
	// between opening the handle and starting the dump
	//
	uint64_t flags = skip_proc_scan ? 0 : DUMP_FLAGS_RESCAN_PROC;
	return platform->m_vtable->dump_state(platform, d, flags);
}

// fname is only used for log messages in scap_setup_dump
static scap_dumper_t *scap_dump_open_gzfile(struct scap_platform *platform, gzFile gzfile, const char *fname,
					    char *lasterr, bool skip_proc_scan)
{
	scap_dumper_t* res = (scap_dumper_t*)malloc(sizeof(scap_dumper_t));
	res->m_f = gzfile;
	res->m_type = DT_FILE;
	res->m_targetbuf = NULL;
	res->m_targetbufcurpos = NULL;
	res->m_targetbufend = NULL;

	if(scap_setup_dump(res, platform, fname, skip_proc_scan) != SCAP_SUCCESS)
	{
		strlcpy(lasterr, res->m_lasterr, SCAP_LASTERR_SIZE);
		free(res);
		res = NULL;
	}

	return res;
}

//
// Open a "savefile" for writing.
//
scap_dumper_t *scap_dump_open(struct scap_platform* platform, const char *fname, compression_mode compress, bool skip_proc_scan, char* lasterr)
{
	gzFile f = NULL;
	int fd = -1;
	const char* mode;

	switch(compress)
	{
	case SCAP_COMPRESSION_GZIP:
		mode = "wb";
		break;
	case SCAP_COMPRESSION_NONE:
		mode = "wbT";
		break;
	default:
		ASSERT(false);
		snprintf(lasterr, SCAP_LASTERR_SIZE, "invalid compression mode");
		return NULL;
	}

	if(fname[0] == '-' && fname[1] == '\0')
	{
#ifndef	_WIN32
		fd = dup(STDOUT_FILENO);
#else
		fd = 1;
#endif
		if(fd != -1)
		{
			f = gzdopen(fd, mode);
			fname = "standard output";
		}
	}
	else
	{
		f = gzopen(fname, mode);
	}

	if(f == NULL)
	{
#ifndef	_WIN32
		if(fd != -1)
		{
			close(fd);
		}
#endif

		snprintf(lasterr, SCAP_LASTERR_SIZE, "can't open %s", fname);
		return NULL;
	}

	return scap_dump_open_gzfile(platform, f, fname, lasterr, skip_proc_scan);
}

//
// Open a savefile for writing, using the provided fd
scap_dumper_t* scap_dump_open_fd(struct scap_platform* platform, int fd, compression_mode compress, bool skip_proc_scan, char* lasterr)
{
	gzFile f = NULL;

	switch(compress)
	{
	case SCAP_COMPRESSION_GZIP:
		f = gzdopen(fd, "wb");
		break;
	case SCAP_COMPRESSION_NONE:
		f = gzdopen(fd, "wbT");
		break;
	default:
		ASSERT(false);
		snprintf(lasterr, SCAP_LASTERR_SIZE, "invalid compression mode");
		return NULL;
	}
	
	if(f == NULL)
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "can't open fd %d", fd);
		return NULL;
	}

	return scap_dump_open_gzfile(platform, f, "", lasterr, skip_proc_scan);
}

//
// Open a memory "savefile"
//
scap_dumper_t *scap_memory_dump_open(struct scap_platform* platform, uint8_t* targetbuf, uint64_t targetbufsize, char* lasterr)
{
	scap_dumper_t* res = (scap_dumper_t*)malloc(sizeof(scap_dumper_t));
	if(res == NULL)
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "scap_dump_memory_open memory allocation failure (1)");
		return NULL;
	}

	res->m_f = NULL;
	res->m_type = DT_MEM;
	res->m_targetbuf = targetbuf;
	res->m_targetbufcurpos = targetbuf;
	res->m_targetbufend = targetbuf + targetbufsize;

	if(scap_setup_dump(res, platform, "", 0) != SCAP_SUCCESS)
	{
		strlcpy(lasterr, res->m_lasterr, SCAP_LASTERR_SIZE);
		free(res);
		res = NULL;
	}

	return res;
}

//
// Create a dumper with an internally managed buffer
//
scap_dumper_t *scap_managedbuf_dump_create()
{
	scap_dumper_t *res = (scap_dumper_t *)malloc(sizeof(scap_dumper_t));
	if(res == NULL)
	{
		return NULL;
	}

	res->m_f = NULL;
	res->m_type = DT_MANAGED_BUF;
	res->m_targetbuf = (uint8_t *)malloc(PPM_DUMPER_MANAGED_BUF_SIZE);
	res->m_targetbufcurpos = res->m_targetbuf;
	res->m_targetbufend = res->m_targetbuf + PPM_DUMPER_MANAGED_BUF_SIZE;

	return res;
}

//
// Close a "savefile" opened with scap_dump_open
//
void scap_dump_close(scap_dumper_t *d)
{
	if(d->m_type == DT_FILE)
	{
		gzclose(d->m_f);
	}
	else if (d->m_type == DT_MANAGED_BUF)
	{
		free(d->m_targetbuf);
	}

	free(d);
}

//
// Return the current size of a tracefile
//
int64_t scap_dump_get_offset(scap_dumper_t *d)
{
	if(d->m_type == DT_FILE)
	{
		return gzoffset(d->m_f);
	}
	else
	{
		return (int64_t)d->m_targetbufcurpos - (int64_t)d->m_targetbuf;
	}
}

int64_t scap_dump_ftell(scap_dumper_t *d)
{
	if(d->m_type == DT_FILE)
	{
		return gztell(d->m_f);
	}
	else
	{
		return (int64_t)d->m_targetbufcurpos - (int64_t)d->m_targetbuf;
	}
}

void scap_dump_flush(scap_dumper_t *d)
{
	if(d->m_type == DT_FILE)
	{
		gzflush(d->m_f, Z_FULL_FLUSH);
	}
}

//
// Write an event to a dump file
//
int32_t scap_dump(scap_dumper_t *d, scap_evt *e, uint16_t cpuid, uint32_t flags)
{
	block_header bh;
	uint32_t bt;
	bool large_payload = flags & SCAP_DF_LARGE;

	flags &= ~SCAP_DF_LARGE;
	if(flags == 0)
	{
		//
		// Write the section header
		//
		bh.block_type = large_payload ? EV_BLOCK_TYPE_V2_LARGE : EV_BLOCK_TYPE_V2;
		bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + sizeof(cpuid) + e->len + 4);
		bt = bh.block_total_length;

		if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh) ||
				scap_dump_write(d, &cpuid, sizeof(cpuid)) != sizeof(cpuid) ||
				scap_dump_write(d, e, e->len) != e->len ||
				scap_write_padding(d, sizeof(cpuid) + e->len) != SCAP_SUCCESS ||
				scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (6)");
			return SCAP_FAILURE;
		}
	}
	else
	{
		//
		// Write the section header
		//
		bh.block_type = large_payload ? EVF_BLOCK_TYPE_V2_LARGE : EVF_BLOCK_TYPE_V2;
		bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + sizeof(cpuid) + sizeof(flags) + e->len + 4);
		bt = bh.block_total_length;

		if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh) ||
				scap_dump_write(d, &cpuid, sizeof(cpuid)) != sizeof(cpuid) ||
				scap_dump_write(d, &flags, sizeof(flags)) != sizeof(flags) ||
				scap_dump_write(d, e, e->len) != e->len ||
				scap_write_padding(d, sizeof(cpuid) + e->len) != SCAP_SUCCESS ||
				scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (7)");
			return SCAP_FAILURE;
		}
	}

	//
	// Enable this to make sure that everything is saved to disk during the tests
	//
#if 0
	fflush(f);
#endif

	return SCAP_SUCCESS;
}
