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

static int krp_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pt_regs *uregs;
	size_t frame_size;

	if (not_target())
		return 0;

	pr_info("krp: %s: rip [0x%lx]\n",
		__func__, regs->ip);
	dump_stack();

	/* NOTE: because get_sigframe get GCC SRA optimized,
	 * and the parameter passing does not follow the original
	 * signature of the function, RSI and RDX do NOT necessarily
	 * point to the pt_reg and frame... Thus the output here
	 * are useless for us.
	 */
	uregs = (void *)regs->si;
	frame_size = (size_t)regs->dx;

	pr_info("krp: %s: urges [%p], frame_size [%lu]\n"
		"urbp 0x%lx, ursp 0x%lx, urip 0x%lx\n",
		__func__, uregs, frame_size,
		uregs->ip, uregs->bp, uregs->sp);

	return 0;
}

static int krp_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (not_target())
		return 0;

	/* Good news: even though get_sigframe is optimized out,
	 * the return value at RAX still makes sense.
	 */
	pr_info("krp: %s: ip [0x%lx]\n"
		"ret(ursp) 0x%lx\n",
		__func__, regs->ip, regs->ax);
	
	return 0;
}

static struct kretprobe krp = {
	.handler		= krp_ret,
	.entry_handler		= krp_entry,
	.data_size		= 0,
	/* Probe up to 20 instances concurrently. */
	.maxactive		= 20,
	.kp.symbol_name		= "get_sigframe.isra.13.constprop.14",
	//.krp.symbol_name		= "get_sigframe.isra.4.constprop.5",
	//.krp.symbol_name		= "get_sigframe",
};


static int kp_entry(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *uregs;

	if (not_target())
		return 0;

	pr_info("kp: %s: ip [0x%lx], rdi [0x%lx]\n",
		__func__, regs->ip, regs->di);
	dump_stack();

	uregs = (void *)regs->di;
	pr_info("kp: %s: urip [0x%lx], urbp [0x%lx], ursp [0x%lx]\n",
		__func__, uregs->ip, uregs->bp, uregs->sp);

	return 0;
}

static void kp_ret(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	if (not_target())
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


/* Like we mentioned, get_sigframe is fucked by GCC SRA,
 * as well as its caller (__setup_rt_frame),
 * its caller's caller (setup_rt_frame),
 * its caller's caller's caller (handle_signal).
 * To get a stable and trusted view of the pt_reg when the
 * excpetion happens, we need to probe "do_signal".
 */
static struct kprobe kp = {
	.pre_handler = kp_entry,
	.post_handler = kp_ret,
	.fault_handler = kp_fault,
	.symbol_name = "do_signal",
};


static int __init ksig_init(void)
{
	int ret;

	pr_info("ksig: Entering: %s\n", __func__);

	ret = register_kretprobe(&krp);
	if (ret < 0) {
		pr_err("krp: register_kretprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("krp: kretprobe at %p\n", krp.kp.addr);

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
	unregister_kretprobe(&krp);
	unregister_kprobe(&kp);
}

module_init(ksig_init);
module_exit(ksig_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ksig module");
MODULE_AUTHOR("daveti");
