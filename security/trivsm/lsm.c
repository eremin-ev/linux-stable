/*
 * Trivial security module
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/lsm_hooks.h>

int trivsm_enabled = 0;

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
	return (pid_src & 1) ^ (pid_dst & 1);
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
	if (!security_module_enable("trivsm"))
		return 0;

	trivsm_enabled = 1;

	pr_info("TrivSM: initializing\n");

	/*
	 * Register with LSM
	 */
	security_add_hooks(trivsm_hooks, ARRAY_SIZE(trivsm_hooks), "trivsm");

	return 0;
}

security_initcall(trivsm_init);
