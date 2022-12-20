#include "../../event_class/event_class.h"

#ifdef __NR_mlock2

#include <sys/mman.h>

TEST(SyscallExit, mlock2X)
{
	auto evt_test = get_syscall_event_test(__NR_mlock2, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	unsigned long mock_addr{0};
	unsigned long mock_flags{0};
	size_t mock_len{1024};
	assert_syscall_state(SYSCALL_FAILURE, "mlock2", syscall(__NR_mlock2, NULL, mock_len, mock_flags));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: addr (type: PT_UINT64) */
	evt_test->assert_numeric_param(2, mock_addr);

	/* Parameter 3: len (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, mock_len);

	/* Parameter 4: flags (type: PT_UINT64) */
	evt_test->assert_numeric_param(4, mock_flags);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
