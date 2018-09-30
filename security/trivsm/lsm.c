/*
 * Trivial security module
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/sysctl.h>
#include <linux/lsm_hooks.h>

/*
 * TrivSM is disabled by default.  Please do
 *	echo 1 > /proc/sys/kernel/trivsm_enabled
 * to enable.
 */
int trivsm_enabled = 0;

int zero = 0;
int one = 1;

static struct ctl_table trivsm_kern_table[] = {
	{
		.procname	= "trivsm_enabled",
		.data		= &trivsm_enabled,
		.maxlen		= sizeof(trivsm_enabled),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{}
};

static struct ctl_table ctl_kern_table[] = {
	{
		.procname	= "kernel",
		.mode		= 0555,
		.child		= trivsm_kern_table,
	},
	{}
};

/**
 * trivsm_task_kill - trivsm check on signal delivery
 * @p: the task object
 * @info: unused
 * @sig: unused
 * @secid: unused
 *
 * Return 0 if write access is permitted
 */
static int trivsm_task_kill(struct task_struct *p, struct siginfo *info,
			   int sig, u32 secid)
{
	int pid_src = task_pid_nr(current);
	int ppid_src = task_ppid_nr(current);
	int pid_dst = task_pid_nr(p);

	pr_debug("TrivSM: src %i:%i sends sig[%i] to dst %i\n",
		ppid_src, pid_src, sig, pid_dst);

	/*
	 * Permit killing if both are odd or both are even.
	 */
	return ((pid_src & 1) ^ (pid_dst & 1)) & trivsm_enabled;
}

static struct security_hook_list trivsm_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_kill, trivsm_task_kill),
};

/**
 * trivsm_init - initialize the triv sm
 *
 * Returns 0
 */
static __init int trivsm_init(void)
{
	struct ctl_table_header *hdr;

	if (!security_module_enable("trivsm"))
		return 0;

	pr_info("TrivSM: initializing\n");

	hdr = register_sysctl_table(ctl_kern_table);
	if (!hdr) {
		pr_info("TrivSM: cannot fill in sysctl table");
	}
	kmemleak_not_leak(hdr);

	/*
	 * Register with LSM
	 */
	security_add_hooks(trivsm_hooks, ARRAY_SIZE(trivsm_hooks), "trivsm");

	return 0;
}

security_initcall(trivsm_init);
