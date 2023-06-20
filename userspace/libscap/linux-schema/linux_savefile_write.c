#include "linux_savefile_write.h"

#include "fdinfo.h"
#include "ifinfo.h"
#include "userinfo.h"
#include "scap_assert.h"
#include "savefile/scap_savefile.h"
#include "savefile/scap_savefile_api.h"
#include "scap_platform_impl.h"

#include <stdio.h>

//
// Write the machine info block
//
static int32_t scap_write_machine_info(scap_dumper_t *d, scap_machine_info *machine_info)
{
	block_header bh;
	uint32_t bt;

	//
	// Write the section header
	//
	bh.block_type = MI_BLOCK_TYPE;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + sizeof(scap_machine_info) + 4);

	bt = bh.block_total_length;

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh) ||
	   scap_dump_write(d, machine_info, sizeof(*machine_info)) != sizeof(*machine_info) ||
	   scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (MI1)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the interface list block
//
static int32_t scap_write_iflist(scap_dumper_t* d, scap_addrlist* addrlist)
{
	block_header bh;
	uint32_t bt;
	uint32_t entrylen;
	uint32_t totlen = 0;
	uint32_t j;

	//
	// Get the interface list
	//
	if(addrlist == NULL)
	{
		//
		// This can happen when the event source is a capture that was generated by a plugin, no big deal
		//
		return SCAP_SUCCESS;
	}

	//
	// Create the block
	//
	bh.block_type = IL_BLOCK_TYPE_V2;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + (addrlist->n_v4_addrs + addrlist->n_v6_addrs)*sizeof(uint32_t) +
							 addrlist->totlen + 4);

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh))
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF1)");
		return SCAP_FAILURE;
	}

	//
	// Dump the ipv4 list
	//
	for(j = 0; j < addrlist->n_v4_addrs; j++)
	{
		scap_ifinfo_ipv4 *entry = &(addrlist->v4list[j]);

		entrylen = sizeof(scap_ifinfo_ipv4) + entry->ifnamelen - SCAP_MAX_PATH_SIZE;

		if(scap_dump_write(d, &entrylen, sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(entry->type), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(entry->ifnamelen), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(entry->addr), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(entry->netmask), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(entry->bcast), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(entry->linkspeed), sizeof(uint64_t)) != sizeof(uint64_t) ||
		   scap_dump_write(d, &(entry->ifname), entry->ifnamelen) != entry->ifnamelen)
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF2)");
			return SCAP_FAILURE;
		}

		totlen += sizeof(uint32_t) + entrylen;
	}

	//
	// Dump the ipv6 list
	//
	for(j = 0; j < addrlist->n_v6_addrs; j++)
	{
		scap_ifinfo_ipv6 *entry = &(addrlist->v6list[j]);

		entrylen = sizeof(scap_ifinfo_ipv6) + entry->ifnamelen - SCAP_MAX_PATH_SIZE;

		if(scap_dump_write(d, &entrylen, sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(entry->type), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(entry->ifnamelen), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(entry->addr), SCAP_IPV6_ADDR_LEN) != SCAP_IPV6_ADDR_LEN ||
		   scap_dump_write(d, &(entry->netmask), SCAP_IPV6_ADDR_LEN) != SCAP_IPV6_ADDR_LEN ||
		   scap_dump_write(d, &(entry->bcast), SCAP_IPV6_ADDR_LEN) != SCAP_IPV6_ADDR_LEN ||
		   scap_dump_write(d, &(entry->linkspeed), sizeof(uint64_t)) != sizeof(uint64_t) ||
		   scap_dump_write(d, &(entry->ifname), entry->ifnamelen) != entry->ifnamelen)
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF2)");
			return SCAP_FAILURE;
		}

		totlen += sizeof(uint32_t) + entrylen;
	}

	//
	// Blocks need to be 4-byte padded
	//
	if(scap_write_padding(d, totlen) != SCAP_SUCCESS)
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the user list block
//
static int32_t scap_write_userlist(scap_dumper_t* d, struct scap_userlist *userlist)
{
	block_header bh;
	uint32_t bt;
	uint32_t j;
	uint16_t namelen;
	uint16_t homedirlen;
	uint16_t shelllen;
	uint8_t type;
	uint32_t totlen = 0;

	//
	// Make sure we have a user list interface list
	//
	if(userlist == NULL)
	{
		//
		// This can happen when the event source is a capture that was generated by a plugin, no big deal
		//
		return SCAP_SUCCESS;
	}

	uint32_t* lengths = calloc(userlist->nusers + userlist->ngroups, sizeof(uint32_t));
	if(lengths == NULL)
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "scap_write_userlist memory allocation failure (1)");
		return SCAP_FAILURE;
	}

	//
	// Calculate the lengths
	//
	for(j = 0; j < userlist->nusers; j++)
	{
		scap_userinfo* info = &userlist->users[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);
		homedirlen = (uint16_t)strnlen(info->homedir, SCAP_MAX_PATH_SIZE);
		shelllen = (uint16_t)strnlen(info->shell, SCAP_MAX_PATH_SIZE);

		// NB: new fields must be appended
		size_t ul = sizeof(uint32_t) + sizeof(type) + sizeof(info->uid) + sizeof(info->gid) + sizeof(uint16_t) +
			    namelen + sizeof(uint16_t) + homedirlen + sizeof(uint16_t) + shelllen;
		totlen += ul;
		lengths[j] = ul;
	}

	for(j = 0; j < userlist->ngroups; j++)
	{
		scap_groupinfo* info = &userlist->groups[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);

		// NB: new fields must be appended
		uint32_t gl = sizeof(uint32_t) + sizeof(type) + sizeof(info->gid) + sizeof(uint16_t) + namelen;
		totlen += gl;
		lengths[userlist->nusers + j] = gl;
	}

	//
	// Create the block
	//
	bh.block_type = UL_BLOCK_TYPE_V2;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + totlen + 4);

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh))
	{
		free(lengths);
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF1)");
		return SCAP_FAILURE;
	}

	//
	// Dump the users
	//
	type = USERBLOCK_TYPE_USER;
	for(j = 0; j < userlist->nusers; j++)
	{
		scap_userinfo* info = &userlist->users[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);
		homedirlen = (uint16_t)strnlen(info->homedir, SCAP_MAX_PATH_SIZE);
		shelllen = (uint16_t)strnlen(info->shell, SCAP_MAX_PATH_SIZE);

		if(scap_dump_write(d, &(lengths[j]), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(type), sizeof(type)) != sizeof(type) ||
		   scap_dump_write(d, &(info->uid), sizeof(info->uid)) != sizeof(info->uid) ||
		   scap_dump_write(d, &(info->gid), sizeof(info->gid)) != sizeof(info->gid) ||
		   scap_dump_write(d, &namelen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, info->name, namelen) != namelen ||
		   scap_dump_write(d, &homedirlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, info->homedir, homedirlen) != homedirlen ||
		   scap_dump_write(d, &shelllen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, info->shell, shelllen) != shelllen)
		{
			free(lengths);
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (U1)");
			return SCAP_FAILURE;
		}
	}

	//
	// Dump the groups
	//
	type = USERBLOCK_TYPE_GROUP;
	for(j = 0; j < userlist->ngroups; j++)
	{
		scap_groupinfo* info = &userlist->groups[j];

		namelen = (uint16_t)strnlen(info->name, MAX_CREDENTIALS_STR_LEN);

		if(scap_dump_write(d, &(lengths[userlist->nusers + j]), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(type), sizeof(type)) != sizeof(type) ||
		   scap_dump_write(d, &(info->gid), sizeof(info->gid)) != sizeof(info->gid) ||
		   scap_dump_write(d, &namelen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, info->name, namelen) != namelen)
		{
			free(lengths);
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (U2)");
			return SCAP_FAILURE;
		}
	}

	free(lengths);

	//
	// Blocks need to be 4-byte padded
	//
	if(scap_write_padding(d, totlen) != SCAP_SUCCESS)
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (IF4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Since the process list isn't thread-safe, we at least reduce the
// time window and write everything at once with a secondary dumper.
// By doing so, the likelihood of having a wrong total length is lower.
//
scap_dumper_t *scap_write_proclist_begin()
{
	return scap_managedbuf_dump_create();
}

//
// Write the process list block
//
static int32_t scap_write_proclist_header(scap_dumper_t *d, uint32_t totlen)
{
	block_header bh;

	//
	// Create the block header
	//
	bh.block_type = PL_BLOCK_TYPE_V9;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + totlen + 4);

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh))
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (1)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the process list block
//
static int32_t scap_write_proclist_trailer(scap_dumper_t *d, uint32_t totlen)
{
	block_header bh;
	uint32_t bt;

	bh.block_type = PL_BLOCK_TYPE_V9;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + totlen + 4);

	//
	// Blocks need to be 4-byte padded
	//
	if(scap_write_padding(d, totlen) != SCAP_SUCCESS)
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int scap_write_proclist_end(scap_dumper_t *d, scap_dumper_t *proclist_dumper, uint32_t totlen)
{
	ASSERT(proclist_dumper != NULL);
	ASSERT(proclist_dumper->m_type == DT_MANAGED_BUF);

	int res = SCAP_SUCCESS;

	do
	{
		scap_dump_flush(proclist_dumper);

		if(scap_write_proclist_header(d, totlen) != SCAP_SUCCESS)
		{
			res = SCAP_FAILURE;
			break;
		}
		if(scap_dump_write(d, proclist_dumper->m_targetbuf, totlen) <= 0)
		{
			res = SCAP_FAILURE;
			break;
		}
		if(scap_write_proclist_trailer(d, totlen) != SCAP_SUCCESS)
		{
			res = SCAP_FAILURE;
			break;
		}
	} while(false);

	scap_dump_close(proclist_dumper);

	return res;
}

//
// Write the process list block
//
static int32_t scap_write_proclist_entry(scap_dumper_t *d, struct scap_threadinfo *tinfo, uint32_t *len)
{
	struct iovec args = {tinfo->args, tinfo->args_len};
	struct iovec env = {tinfo->env, tinfo->env_len};
	struct iovec cgroups = {tinfo->cgroups, tinfo->cgroups_len};

	return scap_write_proclist_entry_bufs(d, tinfo, len,
					      tinfo->comm,
					      tinfo->exe,
					      tinfo->exepath,
					      &args, 1,
					      &env, 1,
					      tinfo->cwd,
					      &cgroups, 1,
					      tinfo->root);
}

static uint16_t iov_size(const struct iovec *iov, uint32_t iovcnt)
{
	uint16_t len = 0;
	uint32_t i;

	for (i = 0; i < iovcnt; i++)
	{
		len += iov[i].iov_len;
	}

	return len;
}

int32_t scap_write_proclist_entry_bufs(scap_dumper_t *d, struct scap_threadinfo *tinfo, uint32_t *len,
				       const char *comm,
				       const char *exe,
				       const char *exepath,
				       const struct iovec *args, int argscnt,
				       const struct iovec *envs, int envscnt,
				       const char *cwd,
				       const struct iovec *cgroups, int cgroupscnt,
				       const char *root)
{
	uint16_t commlen;
	uint16_t exelen;
	uint16_t exepathlen;
	uint16_t cwdlen;
	uint16_t rootlen;
	uint16_t argslen;
	uint16_t envlen;
	uint16_t cgroupslen;

	commlen = (uint16_t)strnlen(comm, SCAP_MAX_PATH_SIZE);
	exelen = (uint16_t)strnlen(exe, SCAP_MAX_PATH_SIZE);
	exepathlen = (uint16_t)strnlen(exepath, SCAP_MAX_PATH_SIZE);
	cwdlen = (uint16_t)strnlen(cwd, SCAP_MAX_PATH_SIZE);
	rootlen = (uint16_t)strnlen(root, SCAP_MAX_PATH_SIZE);

	argslen = iov_size(args, argscnt);
	envlen = iov_size(envs, envscnt);
	cgroupslen = iov_size(cgroups, cgroupscnt);

	//
	// NB: new fields must be appended
	//
	*len = (uint32_t)(sizeof(uint32_t) + // len
			  sizeof(uint64_t) + // tid
			  sizeof(uint64_t) + // pid
			  sizeof(uint64_t) + // ptid
			  sizeof(uint64_t) + // sid
			  sizeof(uint64_t) + // vpgid
			  2 + commlen +
			  2 + exelen +
			  2 + exepathlen +
			  2 + argslen +
			  2 + cwdlen +
			  sizeof(uint64_t) + // fdlimit
			  sizeof(uint32_t) + // flags
			  sizeof(uint32_t) + // uid
			  sizeof(uint32_t) + // gid
			  sizeof(uint32_t) + // vmsize_kb
			  sizeof(uint32_t) + // vmrss_kb
			  sizeof(uint32_t) + // vmswap_kb
			  sizeof(uint64_t) + // pfmajor
			  sizeof(uint64_t) + // pfminor
			  2 + envlen +
			  sizeof(int64_t) + // vtid
			  sizeof(int64_t) + // vpid
			  2 + cgroupslen +
			  2 + rootlen +
			  sizeof(uint64_t) + // pidns_init_start_ts
			  sizeof(int32_t) +  // tty
			  sizeof(int32_t) +  // loginuid
			  sizeof(uint8_t) +  // exe_writable
			  sizeof(uint64_t) + // cap_inheritable
			  sizeof(uint64_t) + // cap_permitted
			  sizeof(uint64_t) + // cap_effective
			  sizeof(uint8_t) + // exe_upper_layer
			  sizeof(uint64_t) + // exe_ino
			  sizeof(uint64_t) + // exe_ino_ctime
			  sizeof(uint64_t)); // exe_ino_mtime

	if(scap_dump_write(d, len, sizeof(uint32_t)) != sizeof(uint32_t) ||
	   scap_dump_write(d, &(tinfo->tid), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->pid), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->ptid), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->sid), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->vpgid), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &commlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
	   scap_dump_write(d, (char *) comm, commlen) != commlen ||
	   scap_dump_write(d, &exelen, sizeof(uint16_t)) != sizeof(uint16_t) ||
	   scap_dump_write(d, (char *) exe, exelen) != exelen ||
	   scap_dump_write(d, &exepathlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
	   scap_dump_write(d, (char *) exepath, exepathlen) != exepathlen ||
	   scap_dump_write(d, &argslen, sizeof(uint16_t)) != sizeof(uint16_t) ||
	   scap_dump_writev(d, args, argscnt) != argslen ||
	   scap_dump_write(d, &cwdlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
	   scap_dump_write(d, (char *) cwd, cwdlen) != cwdlen ||
	   scap_dump_write(d, &(tinfo->fdlimit), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->flags), sizeof(uint32_t)) != sizeof(uint32_t) ||
	   scap_dump_write(d, &(tinfo->uid), sizeof(uint32_t)) != sizeof(uint32_t) ||
	   scap_dump_write(d, &(tinfo->gid), sizeof(uint32_t)) != sizeof(uint32_t) ||
	   scap_dump_write(d, &(tinfo->vmsize_kb), sizeof(uint32_t)) != sizeof(uint32_t) ||
	   scap_dump_write(d, &(tinfo->vmrss_kb), sizeof(uint32_t)) != sizeof(uint32_t) ||
	   scap_dump_write(d, &(tinfo->vmswap_kb), sizeof(uint32_t)) != sizeof(uint32_t) ||
	   scap_dump_write(d, &(tinfo->pfmajor), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->pfminor), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &envlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
	   scap_dump_writev(d, envs, envscnt) != envlen ||
	   scap_dump_write(d, &(tinfo->vtid), sizeof(int64_t)) != sizeof(int64_t) ||
	   scap_dump_write(d, &(tinfo->vpid), sizeof(int64_t)) != sizeof(int64_t) ||
	   scap_dump_write(d, &(cgroupslen), sizeof(uint16_t)) != sizeof(uint16_t) ||
	   scap_dump_writev(d, cgroups, cgroupscnt) != cgroupslen ||
	   scap_dump_write(d, &rootlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
	   scap_dump_write(d, (char *) root, rootlen) != rootlen ||
	   scap_dump_write(d, &(tinfo->pidns_init_start_ts), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->tty), sizeof(int32_t)) != sizeof(int32_t) ||
	   scap_dump_write(d, &(tinfo->loginuid), sizeof(uint32_t)) != sizeof(uint32_t) ||
	   scap_dump_write(d, &(tinfo->exe_writable), sizeof(uint8_t)) != sizeof(uint8_t) ||
	   scap_dump_write(d, &(tinfo->cap_inheritable), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->cap_permitted), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->cap_effective), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->exe_upper_layer), sizeof(uint8_t)) != sizeof(uint8_t) ||
	   scap_dump_write(d, &(tinfo->exe_ino), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->exe_ino_ctime), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(tinfo->exe_ino_mtime), sizeof(uint64_t)) != sizeof(uint64_t))
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (2)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the process list block
//
static int32_t scap_write_proclist(scap_dumper_t *d, struct scap_proclist *proclist)
{
	//
	// Exit immediately if the process list is empty
	//
	if(HASH_COUNT(proclist->m_proclist) == 0)
	{
		return SCAP_SUCCESS;
	}

	scap_dumper_t *proclist_dumper = scap_write_proclist_begin();
	if(proclist_dumper == NULL)
	{
		return SCAP_FAILURE;
	}


	uint32_t totlen = 0;
	struct scap_threadinfo *tinfo;
	struct scap_threadinfo *ttinfo;
	HASH_ITER(hh, proclist->m_proclist, tinfo, ttinfo)
	{
		if(tinfo->filtered_out)
		{
			continue;
		}

		uint32_t len = 0;
		if(scap_write_proclist_entry(proclist_dumper, tinfo, &len) != SCAP_SUCCESS)
		{
			scap_dump_close(proclist_dumper);
			return SCAP_FAILURE;
		}

		totlen += len;
	}

	return scap_write_proclist_end(d, proclist_dumper, totlen);
}

//
// Calculate the length on disk of an fd entry's info
//
static uint32_t scap_fd_info_len(scap_fdinfo *fdi)
{
	//
	// NB: new fields must be appended
	//

	uint32_t res = sizeof(uint32_t) + sizeof(fdi->ino) + 1 + sizeof(fdi->fd);

	switch(fdi->type)
	{
	case SCAP_FD_IPV4_SOCK:
		res +=  4 +     // sip
			4 +     // dip
			2 +     // sport
			2 +     // dport
			1;      // l4proto
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		res +=  4 +     // ip
			2 +     // port
			1;      // l4proto
		break;
	case SCAP_FD_IPV6_SOCK:
		res += 	sizeof(uint32_t) * 4 + // sip
			      sizeof(uint32_t) * 4 + // dip
			      sizeof(uint16_t) + // sport
			      sizeof(uint16_t) + // dport
			      sizeof(uint8_t); // l4proto
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		res += 	sizeof(uint32_t) * 4 + // ip
			      sizeof(uint16_t) + // port
			      sizeof(uint8_t); // l4proto
		break;
	case SCAP_FD_UNIX_SOCK:
		res +=
			sizeof(uint64_t) + // unix source
			sizeof(uint64_t) +  // unix destination
			(uint32_t)strnlen(fdi->info.unix_socket_info.fname, SCAP_MAX_PATH_SIZE) + 2;
		break;
	case SCAP_FD_FILE_V2:
		res += sizeof(uint32_t) + // open_flags
		       (uint32_t)strnlen(fdi->info.regularinfo.fname, SCAP_MAX_PATH_SIZE) + 2 +
		       sizeof(uint32_t); // dev
		break;
	case SCAP_FD_FIFO:
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
	case SCAP_FD_UNSUPPORTED:
	case SCAP_FD_EVENT:
	case SCAP_FD_SIGNALFD:
	case SCAP_FD_EVENTPOLL:
	case SCAP_FD_INOTIFY:
	case SCAP_FD_TIMERFD:
	case SCAP_FD_NETLINK:
	case SCAP_FD_BPF:
	case SCAP_FD_USERFAULTFD:
	case SCAP_FD_IOURING:
		res += (uint32_t)strnlen(fdi->info.fname, SCAP_MAX_PATH_SIZE) + 2;    // 2 is the length field before the string
		break;
	default:
		ASSERT(false);
		break;
	}

	return res;
}

//
// Write the given fd info to disk
//
static int32_t scap_fd_write_to_disk(scap_dumper_t *d, scap_fdinfo *fdi, uint32_t len)
{

	uint8_t type = (uint8_t)fdi->type;
	uint16_t stlen;
	if(scap_dump_write(d, &(len), sizeof(uint32_t)) != sizeof(uint32_t) ||
	   scap_dump_write(d, &(fdi->fd), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(fdi->ino), sizeof(uint64_t)) != sizeof(uint64_t) ||
	   scap_dump_write(d, &(type), sizeof(uint8_t)) != sizeof(uint8_t))
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi1)");
		return SCAP_FAILURE;
	}

	switch(fdi->type)
	{
	case SCAP_FD_IPV4_SOCK:
		if(scap_dump_write(d, &(fdi->info.ipv4info.sip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(fdi->info.ipv4info.dip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(fdi->info.ipv4info.sport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(fdi->info.ipv4info.dport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(fdi->info.ipv4info.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi2)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		if(scap_dump_write(d, &(fdi->info.ipv4serverinfo.ip), sizeof(uint32_t)) != sizeof(uint32_t) ||
		   scap_dump_write(d, &(fdi->info.ipv4serverinfo.port), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(fdi->info.ipv4serverinfo.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi3)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_IPV6_SOCK:
		if(scap_dump_write(d, (char*)fdi->info.ipv6info.sip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		   scap_dump_write(d, (char*)fdi->info.ipv6info.dip, sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		   scap_dump_write(d, &(fdi->info.ipv6info.sport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(fdi->info.ipv6info.dport), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(fdi->info.ipv6info.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi7)");
		}
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		if(scap_dump_write(d, &(fdi->info.ipv6serverinfo.ip), sizeof(uint32_t) * 4) != sizeof(uint32_t) * 4 ||
		   scap_dump_write(d, &(fdi->info.ipv6serverinfo.port), sizeof(uint16_t)) != sizeof(uint16_t) ||
		   scap_dump_write(d, &(fdi->info.ipv6serverinfo.l4proto), sizeof(uint8_t)) != sizeof(uint8_t))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi8)");
		}
		break;
	case SCAP_FD_UNIX_SOCK:
		if(scap_dump_write(d, &(fdi->info.unix_socket_info.source), sizeof(uint64_t)) != sizeof(uint64_t) ||
		   scap_dump_write(d, &(fdi->info.unix_socket_info.destination), sizeof(uint64_t)) != sizeof(uint64_t))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi4)");
			return SCAP_FAILURE;
		}
		stlen = (uint16_t)strnlen(fdi->info.unix_socket_info.fname, SCAP_MAX_PATH_SIZE);
		if(scap_dump_write(d, &stlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		   (stlen > 0 && scap_dump_write(d, fdi->info.unix_socket_info.fname, stlen) != stlen))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi5)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_FILE_V2:
		if(scap_dump_write(d, &(fdi->info.regularinfo.open_flags), sizeof(uint32_t)) != sizeof(uint32_t))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi1)");
			return SCAP_FAILURE;
		}
		stlen = (uint16_t)strnlen(fdi->info.regularinfo.fname, SCAP_MAX_PATH_SIZE);
		if(scap_dump_write(d, &stlen, sizeof(uint16_t)) != sizeof(uint16_t) ||
		   (stlen > 0 && scap_dump_write(d, fdi->info.regularinfo.fname, stlen) != stlen))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi1)");
			return SCAP_FAILURE;
		}
		if(scap_dump_write(d, &(fdi->info.regularinfo.dev), sizeof(uint32_t)) != sizeof(uint32_t))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (dev)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_FIFO:
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
	case SCAP_FD_UNSUPPORTED:
	case SCAP_FD_EVENT:
	case SCAP_FD_SIGNALFD:
	case SCAP_FD_EVENTPOLL:
	case SCAP_FD_INOTIFY:
	case SCAP_FD_TIMERFD:
	case SCAP_FD_NETLINK:
	case SCAP_FD_BPF:
	case SCAP_FD_USERFAULTFD:
	case SCAP_FD_IOURING:
		stlen = (uint16_t)strnlen(fdi->info.fname, SCAP_MAX_PATH_SIZE);
		if(scap_dump_write(d, &stlen,  sizeof(uint16_t)) != sizeof(uint16_t) ||
		   (stlen > 0 && scap_dump_write(d, fdi->info.fname, stlen) != stlen))
		{
			snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fi6)");
			return SCAP_FAILURE;
		}
		break;
	case SCAP_FD_UNKNOWN:
		// Ignore UNKNOWN fds without failing
		ASSERT(false);
		break;
	default:
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "Unknown fdi type %d", fdi->type);
		ASSERT(false);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_write_proc_fds(scap_dumper_t *d, struct scap_threadinfo *tinfo)
{
	block_header bh;
	uint32_t bt;
	uint32_t totlen = sizeof(tinfo->tid);  // This includes the tid
	uint32_t idx = 0;
	struct scap_fdinfo *fdi;
	struct scap_fdinfo *tfdi;

	uint32_t* lengths = calloc(HASH_COUNT(tinfo->fdlist), sizeof(uint32_t));
	if(lengths == NULL)
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "scap_write_proc_fds memory allocation failure");
		return SCAP_FAILURE;
	}

	//
	// First pass of the table to calculate the lengths
	//
	HASH_ITER(hh, tinfo->fdlist, fdi, tfdi)
	{
		if(fdi->type != SCAP_FD_UNINITIALIZED &&
		   fdi->type != SCAP_FD_UNKNOWN)
		{
			uint32_t fl = scap_fd_info_len(fdi);
			lengths[idx++] = fl;
			totlen += fl;
		}
	}
	idx = 0;

	//
	// Create the block
	//
	bh.block_type = FDL_BLOCK_TYPE_V2;
	bh.block_total_length = scap_normalize_block_len(sizeof(block_header) + totlen + 4);

	if(scap_dump_write(d, &bh, sizeof(bh)) != sizeof(bh))
	{
		free(lengths);
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd1)");
		return SCAP_FAILURE;
	}

	//
	// Write the tid
	//
	if(scap_dump_write(d, &tinfo->tid, sizeof(tinfo->tid)) != sizeof(tinfo->tid))
	{
		free(lengths);
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd2)");
		return SCAP_FAILURE;
	}

	//
	// Second pass of the table to dump it
	//
	HASH_ITER(hh, tinfo->fdlist, fdi, tfdi)
	{
		if(fdi->type != SCAP_FD_UNINITIALIZED && fdi->type != SCAP_FD_UNKNOWN)
		{
			if(scap_fd_write_to_disk(d, fdi, lengths[idx++]) != SCAP_SUCCESS)
			{
				free(lengths);
				return SCAP_FAILURE;
			}
		}
	}

	free(lengths);

	//
	// Add the padding
	//
	if(scap_write_padding(d, totlen) != SCAP_SUCCESS)
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd3)");
		return SCAP_FAILURE;
	}

	//
	// Create the trailer
	//
	bt = bh.block_total_length;
	if(scap_dump_write(d, &bt, sizeof(bt)) != sizeof(bt))
	{
		snprintf(d->m_lasterr, SCAP_LASTERR_SIZE, "error writing to file (fd4)");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

//
// Write the fd list blocks
//
static int32_t scap_write_fdlist(scap_dumper_t *d, struct scap_proclist *proclist)
{
	struct scap_threadinfo *tinfo;
	struct scap_threadinfo *ttinfo;
	int32_t res;

	HASH_ITER(hh, proclist->m_proclist, tinfo, ttinfo)
	{
		if(!tinfo->filtered_out)
		{
			res = scap_write_proc_fds(d, tinfo);
			if(res != SCAP_SUCCESS)
			{
				return res;
			}
		}
	}

	return SCAP_SUCCESS;
}

int32_t scap_savefile_write_linux_platform(struct scap_linux_storage *storage, struct scap_dumper *d)
{
	//
	// Write the machine info
	//
	if(scap_write_machine_info(d, &storage->m_machine_info) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Write the interface list
	//
	if(scap_write_iflist(d, storage->m_addrlist) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Write the user list
	//
	if(scap_write_userlist(d, storage->m_userlist) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Write the process list
	//
	if(scap_write_proclist(d, &storage->m_proclist) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Write the fd lists
	//
	if(scap_write_fdlist(d, &storage->m_proclist) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}
