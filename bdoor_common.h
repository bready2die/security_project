#ifndef BDOOR_COMMON_LIB
#define BDOOR_COMMON_LIB 1

#define BDOOR_DEV_MINOR 42
#define BDOOR_DEV_NAME "backdoor"
#define BDOOR_DEV_PATH "/dev/backdoor"

//ioctls for our interface
#define ROOT_IOCTL        1
#define URAND_IOCTL       2
#define HIDE_IOCTL        3
#define SHOW_IOCTL        4
#define LIST_HIDDEN_IOCTL 5
#define INJECT_IOCTL      6
#define REPLACE_IOCTL     7

#endif
