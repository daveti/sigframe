/*
 * Kernel sigframe
 * Aug 11, 2018
 * root@davejingtian.org
 * https://davejingtian.org
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kprobes.h>

static const char *target = "sig";
static struct kprobe kp = {
	.symbol_name = "get_sigframe",
};

static inline int is_not_target(void)
{
	char comm[TASK_COMM_LEN];

	get_task_comm(comm, current);

	return strcmp(target, comm);
}

static int kp_entry(struct kprobe *p, struct pt_regs *regs)
{
	if (is_not_target())
		return 0;

	pr_info("kp: %s: rip [0x%lx]\n",
		__func__, regs->ip);
	dump_stack();

	return 0;
}

static void kp_ret(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	if (is_not_target())
		return;

	pr_info("kp: %s: ip [0x%lx]\n",
		__func__, regs->ip);
	return;
}

static int kp_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	pr_info("kp: %s: ip [0x%lx], trap [%d]\n",
		__func__, regs->ip, trapnr);
	return 0;
}

static int __init ksig_init(void)
{
	int ret;

	pr_info("ksig: Entering: %s\n", __func__);

	/* kp part */
	kp.pre_handler = kp_entry;
	kp.post_handler = kp_ret;
	kp.fault_handler = kp_fault;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("kp: register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("kp: kprobe at %p\n", kp.addr);

	return 0;
}

static void __exit ksig_exit(void)
{
	pr_info("exiting ksig module\n");
	unregister_kprobe(&kp);
}

module_init(ksig_init);
module_exit(ksig_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ksig module");
MODULE_AUTHOR("daveti");
