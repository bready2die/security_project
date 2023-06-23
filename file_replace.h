#ifndef FILE_REPLACE_LIB
#define FILE_REPLACE_LIB 1

extern atomic_t replace_table_users;
extern struct rhashtable replace_table;
extern spinlock_t replace_table_lock;
extern struct rhashtable_params replace_table_params;

struct replace_entry {
        struct dentry_identifier id;
	struct dentry_identifier rep;
        struct rhash_head node;
};

void replace_table_free_entry(void *ptr, void *arg);

int process_replace_request(struct replace_request *request);

int process_unreplace_request(struct replace_request *request);


extern struct proc_dir_entry *replaced_file_viewer;
extern const struct proc_ops replace_ops;
#endif
