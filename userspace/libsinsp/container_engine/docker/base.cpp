#include "base.h"

#include "sinsp.h"

using namespace libsinsp::container_engine;

void docker_base::cleanup()
{
	m_docker_info_source.reset(NULL);
}

bool
docker_base::resolve_impl(sinsp_threadinfo *tinfo, const docker_lookup_request& request, bool query_os_for_missing_info)
{
	container_cache_interface *cache = &container_cache();
	if(!m_docker_info_source)
	{
		g_logger.log("docker_async: Creating docker async source",
			     sinsp_logger::SEV_DEBUG);
		uint64_t max_wait_ms = 10000;
		auto src = new docker_async_source(docker_async_source::NO_WAIT_LOOKUP, max_wait_ms, cache);
		m_docker_info_source.reset(src);
	}

	tinfo->m_container_id = request.container_id;

	sinsp_container_info::ptr_t container_info = cache->get_container(request.container_id);

	if(!container_info)
	{
		if(!query_os_for_missing_info)
		{
			auto container = std::make_shared<sinsp_container_info>();
			container->m_type = request.container_type;
			container->m_id = request.container_id;
			cache->notify_new_container(*container);
			return true;
		}

#ifdef HAS_CAPTURE
		if(cache->should_lookup(request.container_id, request.container_type))
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"docker_async (%s): No existing container info",
					request.container_id.c_str());

			// give docker a chance to return metadata for this container
			cache->set_lookup_status(request.container_id, request.container_type, sinsp_container_lookup_state::STARTED);
			parse_docker_async(request, cache);
		}
#endif
		return false;
	}

	// Returning true will prevent other container engines from
	// trying to resolve the container, so only return true if we
	// have complete metadata.
	return container_info->is_successful();
}

void docker_base::parse_docker_async(const docker_lookup_request& request, container_cache_interface *cache)
{
	auto cb = [cache](const docker_lookup_request& request, const sinsp_container_info& res)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"docker_async (%s): Source callback result=%d",
				request.container_id.c_str(),
				res.m_lookup_state);

		cache->notify_new_container(res);
	};

	sinsp_container_info result;

	if(m_docker_info_source->lookup(request, result, cb))
	{
		// if a previous lookup call already found the metadata, process it now
		cb(request, result);

		// This should *never* happen, as ttl is 0 (never wait)
		g_logger.format(sinsp_logger::SEV_ERROR,
				"docker_async (%s): Unexpected immediate return from docker_info_source.lookup()",
				request.container_id.c_str());
	}
}

