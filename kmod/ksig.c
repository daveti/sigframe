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

static inline int not_target(void)
{
	char comm[TASK_COMM_LEN];
	get_task_comm(comm, current);
	return strcmp(target, comm);
}

static int kp_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pt_regs *uregs;
	size_t frame_size;

	if (not_target())
		return 0;

	pr_info("kp: %s: rip [0x%lx]\n",
		__func__, regs->ip);
	dump_stack();

	uregs = (void *)regs->si;
	frame_size = (size_t)regs->dx;

	pr_info("kp: %s: urges [%p], frame_size [%lu]\n"
		"urbp 0x%lx, ursp 0x%lx, urip 0x%lx\n",
		__func__, uregs, frame_size,
		uregs->ip, uregs->bp, uregs->sp);

	return 0;
}

static int kp_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (not_target())
		return 0;

	pr_info("kp: %s: ip [0x%lx]\n"
		"ret(ursp) 0x%lx\n",
		__func__, regs->ip, regs->ax);
	
	return 0;
}

static struct kretprobe krp = {
	.handler		= kp_ret,
	.entry_handler		= kp_entry,
	.data_size		= 0,
	/* Probe up to 20 instances concurrently. */
	.maxactive		= 20,
	.kp.symbol_name		= "get_sigframe.isra.13.constprop.14",
};

static int __init ksig_init(void)
{
	int ret;

	pr_info("ksig: Entering: %s\n", __func__);

	ret = register_kretprobe(&krp);
	if (ret < 0) {
		pr_err("kp: register_kretprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("kp: kretprobe at %p\n", krp.kp.addr);

	return 0;
}

static void __exit ksig_exit(void)
{
	pr_info("exiting ksig module\n");
	unregister_kretprobe(&krp);
}

module_init(ksig_init);
module_exit(ksig_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ksig module");
MODULE_AUTHOR("daveti");
