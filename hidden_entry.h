#ifndef HIDDEN_ENTRY_LIB
#define HIDDEN_ENTRY_LIB 1

extern atomic_t hidden_table_users;
extern struct rhashtable hidden_table;
extern spinlock_t hidden_table_lock;
extern struct rhashtable_params hidden_table_params;

struct hidden_entry {
        struct dentry_identifier id;
        spinlock_t lock;
        struct rhash_head node;
        atomic_t users;
};
/*
int cmp_dentry_identifier(struct dentry_identifier *d_id1,
			struct dentry_identifier *d_id2);
*/
//struct hidden_entry *req_to_entry(struct dentry_identifier *orig_id);

void hidden_table_free_entry(void *ptr, void *arg);

//void add_hidden_entry_to_table(struct dentry_identifier *identifier);

int process_hide_request(struct hide_request *request);

//void rem_hidden_entry_from_table(struct dentry_identifier *old_id);

int process_show_request(struct hide_request *request);


extern struct proc_dir_entry *hidden_file_viewer;
extern const struct proc_ops hidden_ops;
#endif
