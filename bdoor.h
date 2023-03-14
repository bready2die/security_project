#ifndef BDOOR_LIB
#define BDOOR_LIB 1
#include "bdoor_common.h"

struct dentry_table
{
	struct qstr *name
}

struct _hidden_list
{
	struct qstr *dentry_id;
        pid_t pid;
        struct dentry_table *dentry_table;
        //struct rhashtable dirent_hashtable;
        spinlock_t lock;
        struct rhash_head node;
        atomic_t users;
};

#endif
