/*
 * Understanding the sigcontext and sigreturn frame on x86_64
 * Stick with sigaction() rather than signal()
 * https://stackoverflow.com/questions/231912/what-is-the-difference-between-sigaction-and-signal
 * Aug 11, 2018
 * root@davejingtian.org
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>

static void sig_handler(int signum, siginfo_t *info,
			ucontext_t *uc)
{
	unsigned long rsp_c;
	unsigned long rbp_c;
	unsigned long rip_c;

	printf("%s: signum %d|%d, info [%p-0x%lx] size 0x%x, "
		"uc [%p-0x%lx] size 0x%x\n",
		__func__, signum, info->si_signo,
		info, (unsigned long)info + sizeof(*info),
		sizeof(*info),
		uc, (unsigned long)uc + sizeof(*uc),
		sizeof(*uc));

	asm volatile ("mov %%rbp, %0\n\t"
			"mov %%rsp, %1\n\t"
			"lea (%%rip), %2\n\t"
			: "=r"(rbp_c), "=r"(rsp_c), "=r"(rip_c)
			: : );

	printf("Current: rbp 0x%lx, rsp 0x%lx, rip 0x%lx\n"
		"Ucontext: rbp 0x%lx, rsp 0x%lx, rip 0x%lx\n"
		"Reserved stack area [%p-0x%lx] size 0x%lx\n",
		rbp_c, rsp_c, rip_c,
		uc->uc_mcontext.gregs[REG_RBP],
		uc->uc_mcontext.gregs[REG_RSP],
		uc->uc_mcontext.gregs[REG_RIP],
		uc, uc->uc_mcontext.gregs[REG_RSP],
		uc->uc_mcontext.gregs[REG_RSP] - (unsigned long)(uc));

	return;
}

int main(void)
{
	struct sigaction action;

	memset(&action, 0x0, sizeof(action));
	action.sa_handler = (void (*)(int))sig_handler;
	action.sa_flags = SA_SIGINFO;

	if (sigaction(SIGINT, &action, NULL)) {
		printf("Error: sigaction failed with error %s\n",
			strerror(errno));
		return -1;
	}

	while (1) {
		sleep(2);
		printf("Love is for suckers!\n");
	}

	return 0;
}

