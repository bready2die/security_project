#ifndef WHITELIST_LIB
#define WHITELIST_LIB 1

#ifdef CONFIG_X86_64
#include <linux/sched.h>

struct procname {
        char name[TASK_COMM_LEN];
};

struct procname_entry {
        struct procname id;
        struct rhash_head node;
};

extern struct rhashtable_params procname_whitelist_params;
extern atomic_t procname_whitelist_users;
extern struct rhashtable procname_whitelist;
extern spinlock_t procname_whitelist_lock;

void procname_whitelist_free_entry(void *ptr, void *arg);


struct pid_entry {
        unsigned int id;
        struct rhash_head node;
};

extern struct rhashtable_params pid_whitelist_params;
extern atomic_t pid_whitelist_users;
extern struct rhashtable pid_whitelist;
extern spinlock_t pid_whitelist_lock;

void pid_whitelist_free_entry(void *ptr, void *arg);


struct uid_entry {
        unsigned int id;
        struct rhash_head node;
};

extern struct rhashtable_params uid_whitelist_params;
extern atomic_t uid_whitelist_users;
extern struct rhashtable uid_whitelist;
extern spinlock_t uid_whitelist_lock;

void uid_whitelist_free_entry(void *ptr, void *arg);


struct gid_entry {
        unsigned int id;
        struct rhash_head node;
};

extern struct rhashtable_params gid_whitelist_params;
extern atomic_t gid_whitelist_users;
extern struct rhashtable gid_whitelist;
extern spinlock_t gid_whitelist_lock;

void gid_whitelist_free_entry(void *ptr, void *arg);


int process_wadd_request(struct white_request *request);
int process_wrem_request(struct white_request *request);

int check_whitelist(void);

extern struct proc_dir_entry *whitelist_viewer;
extern const struct proc_ops whitelist_ops;

#endif //CONFIG_X86_64
#endif //WHITELIST_LIB
