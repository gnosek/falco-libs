// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <driver/ppm_events_public.h>
#include <converter/table.h>
#include <converter/results.h>
#include <converter/debug_macro.h>
#include <stdarg.h>
#include <cstdio>
#include <cassert>
#include <string>
#include <stdexcept>
#include <memory>

typedef std::shared_ptr<scap_evt> safe_scap_evt_t;

static inline safe_scap_evt_t safe_scap_evt(scap_evt *evt) {
	return safe_scap_evt_t{evt, free};
}

// use a shared pointer to store the events
static std::unordered_map<uint64_t, safe_scap_evt_t> evt_storage = {};

extern const struct ppm_event_info g_event_info[];

static const char *get_event_name(ppm_event_code event_type) {
	const struct ppm_event_info *event_info = &g_event_info[event_type];
	return event_info->name;
}

static char get_direction_char(ppm_event_code event_type) {
	if(PPME_IS_ENTER(event_type)) {
		return 'E';
	} else {
		return 'X';
	}
}

static void clear_evt(uint64_t tid) {
	if(evt_storage.find(tid) != evt_storage.end()) {
		evt_storage[tid].reset();
	}
}

static void store_evt(uint64_t tid, scap_evt *evt) {
	// if there was a previous event for this tid, we can overwrite the pointer because it means we
	// don't need it anymore. We need to keep the enter event until we retrieve it in the
	// corresponding exit event, but if the same thread is doing another enter event it means the
	// previous syscall is already completed.

	clear_evt(tid);

	scap_evt *tmp_evt = (scap_evt *)malloc(evt->len);
	if(!tmp_evt) {
		throw std::runtime_error("Cannot allocate memory for the enter event.");
	}
	memcpy(tmp_evt, evt, evt->len);
	evt_storage[tid] = safe_scap_evt(tmp_evt);
}

static scap_evt *retrieve_evt(uint64_t tid) {
	if(evt_storage.find(tid) != evt_storage.end()) {
		return evt_storage[tid].get();
	}
	return nullptr;
}

static uint16_t get_param_len(scap_evt *evt, uint8_t num_param) {
	if(evt->nparams <= num_param) {
		std::string error = "Try to access len of param num '" + std::to_string(num_param) +
		                    "' for event " + get_event_name((ppm_event_code)evt->type) + "_" +
		                    get_direction_char((ppm_event_code)evt->type) +
		                    " (num parameters: " + std::to_string(evt->type) + ").";
		throw std::runtime_error(error);
	}

	// todo!: we need to manage LARGE_PAYLOAD events
	uint16_t off_len = sizeof(scap_evt) + sizeof(uint16_t) * num_param;
	uint16_t len = 0;
	memcpy(&len, (char *)evt + off_len, sizeof(uint16_t));
	return (uint32_t)len;
}

static char *get_param_ptr(scap_evt *evt, uint8_t num_param) {
	if(evt->nparams <= num_param) {
		std::string error = "Try to access param num '" + std::to_string(num_param) +
		                    "' for event " + get_event_name((ppm_event_code)evt->type) + "_" +
		                    get_direction_char((ppm_event_code)evt->type) +
		                    " (num parameters: " + std::to_string(evt->type) + ").";
		throw std::runtime_error(error);
	}

	char *ptr = (char *)evt + sizeof(scap_evt) + sizeof(uint16_t) * evt->nparams;
	uint16_t ptr_off = 0;
	for(auto i = 0; i < num_param; i++) {
		uint16_t len = 0;
		memcpy(&len, (char *)evt + sizeof(scap_evt) + sizeof(uint16_t) * i, sizeof(uint16_t));
		ptr_off += len;
	}

	return ptr + ptr_off;
}

// This writes len + the param
static void push_default_parameter(scap_evt *evt, uint16_t *params_offset, uint8_t param_num) {
	// Please ensure that `new_evt->type` is already the final type you want to obtain.
	// Otherwise we will access the wrong entry in the event table.
	const struct ppm_event_info *event_info = &(g_event_info[evt->type]);
	uint16_t len = scap_get_size_bytes_from_type(event_info->params[param_num].type);
	uint16_t lens_offset = sizeof(scap_evt) + param_num * sizeof(uint16_t);

	PRINT_MESSAGE(
	        "push default param (%d, type: %d) with len (%d) at {params_offest (%d), "
	        "lens_offset (%d)}\n",
	        param_num,
	        event_info->params[param_num].type,
	        len,
	        *params_offset,
	        lens_offset);

	// The default param will be always 0 so we just need to copy the right number of 0 bytes.
	// `uint64_t` should be enough for all the types considering that types like CHARBUF, BYTEBUF
	// have `len==0`
	uint64_t val = 0;
	memcpy((char *)evt + *params_offset, (char *)&val, len);
	*params_offset += len;
	memcpy((char *)evt + lens_offset, &len, sizeof(uint16_t));
}

// This writes len + the param
static void push_parameter(scap_evt *new_evt,
                           scap_evt *tmp_evt,
                           uint16_t *params_offset,
                           uint8_t new_evt_param_num,
                           uint8_t tmp_evt_param_num) {
	// we need to write the len into the event.
	uint16_t lens_offset = sizeof(scap_evt) + new_evt_param_num * sizeof(uint16_t);
	uint16_t len = get_param_len(tmp_evt, tmp_evt_param_num);
	char *ptr = get_param_ptr(tmp_evt, tmp_evt_param_num);

	PRINT_MESSAGE(
	        "push param (%d, type: %d) with len (%d) at {params_offest: %d, "
	        "lens_offset: %d} from event type '%d', param '%d'\n",
	        new_evt_param_num,
	        g_event_info[tmp_evt->type].params[tmp_evt_param_num].type,
	        len,
	        *params_offset,
	        lens_offset,
	        tmp_evt->type,
	        tmp_evt_param_num);

	memcpy((char *)new_evt + *params_offset, ptr, len);
	*params_offset += len;
	memcpy((char *)new_evt + lens_offset, &len, sizeof(uint16_t));
}

static uint16_t copy_old_params(scap_evt *new_evt, scap_evt *evt_to_convert) {
	// Copy the lengths array
	uint16_t new_evt_offset = sizeof(scap_evt);
	uint16_t old_evt_offset = sizeof(scap_evt);
	uint16_t size_to_copy = evt_to_convert->nparams * sizeof(uint16_t);
	memcpy((char *)new_evt + new_evt_offset, (char *)evt_to_convert + old_evt_offset, size_to_copy);

	PRINT_MESSAGE(
	        "Copy lengths array (size %d) from old event offset '%d' to new event "
	        "offset '%d'\n",
	        size_to_copy,
	        old_evt_offset,
	        new_evt_offset);

	// Copy the parameters (we left some space for the missing lengths)
	new_evt_offset = sizeof(scap_evt) + new_evt->nparams * sizeof(uint16_t);
	old_evt_offset = sizeof(scap_evt) + evt_to_convert->nparams * sizeof(uint16_t);
	size_to_copy =
	        evt_to_convert->len - (sizeof(scap_evt) + evt_to_convert->nparams * sizeof(uint16_t));
	memcpy((char *)new_evt + new_evt_offset, (char *)evt_to_convert + old_evt_offset, size_to_copy);

	PRINT_MESSAGE(
	        "Copy parameters (size %d) from old event offset '%d' to new event "
	        "offset '%d'\n",
	        size_to_copy,
	        old_evt_offset,
	        new_evt_offset);

	return new_evt_offset + size_to_copy;
}

extern "C" bool is_conversion_needed(scap_evt *evt_to_convert) {
	assert(evt_to_convert->type < PPM_EVENT_MAX);
	const struct ppm_event_info *event_info = &(g_event_info[evt_to_convert->type]);

	// todo!: we need to cleanup this logic when we can mark enter events as `EF_OLD_VERSION`

	// If the event is not yet managed by the converter we never need a conversion
	if((event_info->flags & EF_TMP_CONVERTER_MANAGED) == 0) {
		return false;
	}

	// If the event is managed by the converter and it is an enter event it will always need a
	// conversion.
	if(PPME_IS_ENTER(evt_to_convert->type)) {
		return true;
	}

	// If it is an exit event it needs a conversion when:
	// - it is an `EF_OLD_VERSION`
	// - the number of parameters is different from the one in the event table

	// If we are a new event type we need to check the number of parameters.
	assert(evt_to_convert->nparams <= event_info->nparams);

	// If the number of parameters is different from the one in the event table we need a
	// conversion.
	if((event_info->flags & EF_OLD_VERSION) || (evt_to_convert->nparams != event_info->nparams)) {
		return true;
	}
	return false;
}

extern "C" scap_evt *scap_retrieve_evt_from_converter_storage(uint64_t tid) {
	return retrieve_evt(tid);
}

extern "C" void scap_clear_converter_storage() {
	evt_storage.clear();
}

static conversion_result convert_event(scap_evt *new_evt,
                                       scap_evt *evt_to_convert,
                                       const conversion_info &ci,
                                       char *error) {
	/////////////////////////////
	// Dispatch the action
	/////////////////////////////

	uint16_t params_offset = 0;
	int param_to_populate = 0;

	switch(ci.action) {
	case C_ACTION_SKIP:
		return CONVERSION_SKIP;

	case C_ACTION_STORE:
		store_evt(evt_to_convert->tid, evt_to_convert);
		return CONVERSION_SKIP;

	case C_ACTION_ADD_PARAMS:
		memcpy(new_evt, evt_to_convert, sizeof(scap_evt));
		// The new number of params is the previous one plus the number of conversion instructions.
		new_evt->nparams = evt_to_convert->nparams + ci.instr.size();
		params_offset = copy_old_params(new_evt, evt_to_convert);
		param_to_populate = evt_to_convert->nparams;
		break;

	case C_ACTION_CHANGE_TYPE:
		memcpy(new_evt, evt_to_convert, sizeof(scap_evt));
		// The new number of params is the number of conversion instructions.
		new_evt->nparams = ci.instr.size();
		new_evt->type = ci.desired_type;
		params_offset = sizeof(scap_evt) + new_evt->nparams * sizeof(uint16_t);
		param_to_populate = 0;
		break;

	default:
		snprintf(error, SCAP_LASTERR_SIZE, "Unhandled conversion action '%d'.", ci.action);
		return CONVERSION_ERROR;
	}

	/////////////////////////////
	// Fill the event to its most recent version
	/////////////////////////////

	PRINT_MESSAGE("New event header (the len is still the old one):\n");
	PRINT_EVENT(new_evt, PRINT_HEADER);

	scap_evt *tmp_evt = NULL;
	// If this is true at the end of the for loop we will free its memory.
	bool used_enter_event = false;

	// We iterate over the instructions
	for(int i = 0; i < ci.instr.size(); i++, param_to_populate++) {
		PRINT_MESSAGE("Instruction n° %d. Param to populate: %d\n", i, param_to_populate);

		switch(ci.instr[i].flags) {
		case C_INSTR_FROM_DEFAULT:
			tmp_evt = NULL;
			break;

		case C_INSTR_FROM_ENTER:
			tmp_evt = retrieve_evt(evt_to_convert->tid);
			if(!tmp_evt) {
				// It could be due to different reasons:
				// - we dropped the enter event in the capture
				// - we jump here from a previous conversion. For example, we jump from `BRK_1_X` to
				// `BRK_4_X` but in this case we don't have the enter event BRK_4_E because we don't
				// convert `BRK_1_E` to `BRK_4_E`. It would be meaningless, they would't bring the
				// same info.
				break;
			}

			// todo!: undestand if we can pretend this is an error or it is a normal situation.
			if(tmp_evt->type != evt_to_convert->type - 1) {
				snprintf(error,
				         SCAP_LASTERR_SIZE,
				         "The enter event for '%s_%c' is not the right one! Event found '%s_%c'.",
				         get_event_name((ppm_event_code)evt_to_convert->type),
				         get_direction_char((ppm_event_code)evt_to_convert->type),
				         get_event_name((ppm_event_code)tmp_evt->type),
				         get_direction_char((ppm_event_code)tmp_evt->type));
				return CONVERSION_ERROR;
			}
			used_enter_event = true;
			break;

		case C_INSTR_FROM_OLD:
			tmp_evt = evt_to_convert;
			if(tmp_evt->nparams <= ci.instr[i].param_num) {
				// todo!: this sounds like an error but let's see in the future. At the moment we
				// fail
				snprintf(error,
				         SCAP_LASTERR_SIZE,
				         "We want to take parameter '%d' from event '%d' but this event has only "
				         "'%d' parameters!",
				         ci.instr[i].param_num,
				         tmp_evt->type,
				         tmp_evt->nparams);
				return CONVERSION_ERROR;
			}
			break;

		default:
			snprintf(error,
			         SCAP_LASTERR_SIZE,
			         "Unknown instruction (flags: %d, param_num: %d).",
			         ci.instr[i].flags,
			         ci.instr[i].param_num);
			return CONVERSION_ERROR;
		}

		if(!tmp_evt) {
			push_default_parameter(new_evt, &params_offset, param_to_populate);
		} else {
			push_parameter(new_evt,
			               tmp_evt,
			               &params_offset,
			               param_to_populate,
			               ci.instr[i].param_num);
		}
	}

	if(used_enter_event) {
		// We can free the enter event because we don't need it anymore.
		clear_evt(evt_to_convert->tid);
	}

	new_evt->len = params_offset;

	PRINT_MESSAGE("Final event:\n");
	PRINT_EVENT(new_evt, PRINT_FULL);
	return is_conversion_needed(new_evt) ? CONVERSION_CONTINUE : CONVERSION_COMPLETED;
}

extern "C" conversion_result scap_convert_event(scap_evt *new_evt,
                                                scap_evt *evt_to_convert,
                                                char *error) {
	// This should be checked by the caller but just double check here
	if(!is_conversion_needed(evt_to_convert)) {
		snprintf(error,
		         SCAP_LASTERR_SIZE,
		         "Conversion not need for event type '%d' nparams '%d'. Please double check",
		         evt_to_convert->type,
		         evt_to_convert->nparams);
		return CONVERSION_ERROR;
	}

	// If we need a conversion but we don't have an entry in the table we have an error.
	auto conv_key = conversion_key{evt_to_convert->type, (uint8_t)evt_to_convert->nparams};
	if(g_conversion_table.find(conv_key) == g_conversion_table.end()) {
		snprintf(error,
		         SCAP_LASTERR_SIZE,
		         "Event '%d' has '%d' parameters, but we don't handle it in the table.",
		         evt_to_convert->type,
		         evt_to_convert->nparams);
		return CONVERSION_ERROR;
	}

	// If we reached this point we have for sure an entry in the conversion table.
	return convert_event(new_evt, evt_to_convert, g_conversion_table.at(conv_key), error);
}