#include <linux/kernel.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rhashtable.h>
#include "bdoor_common.h"
#include "whitelist.h"
#include "util.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#ifdef CONFIG_X86_64
/*
const char *white_type_names[] = {
        "PROCNAME",
        "PID",
        "UID",
        "GID",
};
*/
struct rhashtable_params procname_whitelist_params = {
        .key_len = sizeof(struct procname),
        .key_offset = offsetof(struct procname_entry,id),
        .head_offset = offsetof(struct procname_entry,node)
};

atomic_t procname_whitelist_users;
struct rhashtable procname_whitelist;
spinlock_t procname_whitelist_lock;

void procname_whitelist_free_entry(void *ptr, void *arg)
{
        struct procname_entry *entry = (struct procname_entry*)ptr;
        kfree(entry);
}

static void add_procname_to_whitelist(struct procname *pname)
{
	int err;
	struct procname_entry *new_entry = kmalloc(sizeof(struct procname_entry),GFP_ATOMIC);
	memcpy(&new_entry->id,pname,sizeof(struct procname));

	atomic_inc(&procname_whitelist_users);
	err = rhashtable_lookup_insert_fast(&procname_whitelist,
					&new_entry->node,
					procname_whitelist_params);

	if (err)
		kfree(new_entry);

	atomic_dec(&procname_whitelist_users);
}

static void rem_procname_from_whitelist(struct procname *pname)
{
	struct procname_entry *old_entry;
	atomic_inc(&procname_whitelist_users);
	old_entry = rhashtable_lookup_fast(&procname_whitelist,
					pname,
					procname_whitelist_params);
	if (!old_entry)
		goto out;

	rhashtable_remove_fast(&procname_whitelist,
			&old_entry->node,
			procname_whitelist_params);
	kfree(old_entry);
out:
	atomic_dec(&procname_whitelist_users);
}


struct rhashtable_params pid_whitelist_params = {
        .key_len = sizeof(unsigned int),
        .key_offset = offsetof(struct pid_entry,id),
        .head_offset = offsetof(struct pid_entry,node)
};

atomic_t pid_whitelist_users;
struct rhashtable pid_whitelist;
spinlock_t pid_whitelist_lock;

void pid_whitelist_free_entry(void *ptr, void *arg)
{
        struct pid_entry *entry = (struct pid_entry*)ptr;
        kfree(entry);
}

static void add_pid_to_whitelist(unsigned int id)
{
	int err;
	struct pid_entry *new_entry = kmalloc(sizeof(struct pid_entry),GFP_ATOMIC);
	new_entry->id = id;
	atomic_inc(&pid_whitelist_users);
	err = rhashtable_lookup_insert_fast(&pid_whitelist,
					&new_entry->node,
					pid_whitelist_params);

	if (err)
		kfree(new_entry);

	atomic_dec(&pid_whitelist_users);
}

static void rem_pid_from_whitelist(unsigned int id)
{
	struct pid_entry *old_entry;
	atomic_inc(&pid_whitelist_users);
	old_entry = rhashtable_lookup_fast(&pid_whitelist,
					&id,
					pid_whitelist_params);
	if (!old_entry)
		goto out;

	rhashtable_remove_fast(&pid_whitelist,
			&old_entry->node,
			pid_whitelist_params);
	kfree(old_entry);
out:
	atomic_dec(&pid_whitelist_users);
}


struct rhashtable_params uid_whitelist_params = {
        .key_len = sizeof(unsigned int),
        .key_offset = offsetof(struct uid_entry,id),
        .head_offset = offsetof(struct uid_entry,node)
};

atomic_t uid_whitelist_users;
struct rhashtable uid_whitelist;
spinlock_t uid_whitelist_lock;

void uid_whitelist_free_entry(void *ptr, void *arg)
{
        struct uid_entry *entry = (struct uid_entry*)ptr;
        kfree(entry);
}

static void add_uid_to_whitelist(unsigned int id)
{
	int err;
	struct uid_entry *new_entry = kmalloc(sizeof(struct uid_entry),GFP_ATOMIC);
	new_entry->id = id;
	atomic_inc(&uid_whitelist_users);
	err = rhashtable_lookup_insert_fast(&uid_whitelist,
					&new_entry->node,
					uid_whitelist_params);

	if (err)
		kfree(new_entry);

	atomic_dec(&uid_whitelist_users);
}

static void rem_uid_from_whitelist(unsigned int id)
{
	struct uid_entry *old_entry;
	atomic_inc(&uid_whitelist_users);
	old_entry = rhashtable_lookup_fast(&uid_whitelist,
					&id,
					uid_whitelist_params);
	if (!old_entry)
		goto out;

	rhashtable_remove_fast(&uid_whitelist,
			&old_entry->node,
			uid_whitelist_params);
	kfree(old_entry);
out:
	atomic_dec(&uid_whitelist_users);
}


struct rhashtable_params gid_whitelist_params = {
        .key_len = sizeof(unsigned int),
        .key_offset = offsetof(struct gid_entry,id),
        .head_offset = offsetof(struct gid_entry,node)
};

atomic_t gid_whitelist_users;
struct rhashtable gid_whitelist;
spinlock_t gid_whitelist_lock;

void gid_whitelist_free_entry(void *ptr, void *arg)
{
        struct gid_entry *entry = (struct gid_entry*)ptr;
        kfree(entry);
}

static void add_gid_to_whitelist(unsigned int id)
{
	int err;
	struct gid_entry *new_entry = kmalloc(sizeof(struct gid_entry),GFP_ATOMIC);
	new_entry->id = id;
	atomic_inc(&gid_whitelist_users);
	err = rhashtable_lookup_insert_fast(&gid_whitelist,
					&new_entry->node,
					gid_whitelist_params);

	if (err)
		kfree(new_entry);

	atomic_dec(&gid_whitelist_users);
}

static void rem_gid_from_whitelist(unsigned int id)
{
	struct gid_entry *old_entry;
	atomic_inc(&gid_whitelist_users);
	old_entry = rhashtable_lookup_fast(&gid_whitelist,
					&id,
					gid_whitelist_params);
	if (!old_entry)
		goto out;

	rhashtable_remove_fast(&gid_whitelist,
			&old_entry->node,
			gid_whitelist_params);
	kfree(old_entry);
out:
	atomic_dec(&gid_whitelist_users);
}

int process_wadd_request(struct white_request *request)
{
	int i;
	int ret = 0;
	struct procname pname;
	struct whitelist_entry *entries = kmalloc(request->count *
						sizeof(struct whitelist_entry),
						GFP_ATOMIC);
	if (copy_from_user(entries,(struct whitelist_entry*)request->entries,
				request->count * sizeof(struct whitelist_entry))) {
		ret = 1;
		goto out;
	}
	for (i = 0; i < request->count; i++) {
		switch (entries[i].wtype) {
		case PROCNAME:
			//hexdump("procname",entries[i].name,16);
			memcpy(pname.name,entries[i].name,sizeof(char)*TASK_COMM_LEN);
			add_procname_to_whitelist(&pname);
			break;
		case PID:
			add_pid_to_whitelist(entries[i].id);
			break;
		case UID:
			add_uid_to_whitelist(entries[i].id);
			break;
		case GID:
			add_gid_to_whitelist(entries[i].id);
			break;
		case INVALID:
			//do nothing
		}
	}
out:
	kfree(entries);
	return ret;
}

int process_wrem_request(struct white_request *request)
{
	int i;
	int ret = 0;
	struct procname pname;
	struct whitelist_entry *entries = kmalloc(request->count *
						sizeof(struct whitelist_entry),
						GFP_ATOMIC);
	if (copy_from_user(entries,(struct whitelist_entry*)request->entries,
				request->count * sizeof(struct whitelist_entry))) {
		ret = 1;
		goto out;
	}
	for (i = 0; i < request->count; i++) {
		switch (entries[i].wtype) {
		case PROCNAME:
			memcpy(pname.name,entries[i].name,sizeof(char)*TASK_COMM_LEN);
			rem_procname_from_whitelist(&pname);
			break;
		case PID:
			rem_pid_from_whitelist(entries[i].id);
			break;
		case UID:
			rem_uid_from_whitelist(entries[i].id);
			break;
		case GID:
			rem_gid_from_whitelist(entries[i].id);
			break;
		case INVALID:
			//do nothing
		}
	}
out:
	kfree(entries);
	return ret;
}

static int check_procname(void)
{
	int ret = 0;
	unsigned long flags;
	struct procname curname;
	memset(curname.name,0,sizeof(char) * TASK_COMM_LEN);
	memcpy(curname.name,current->comm,
		sizeof(char) * MIN(TASK_COMM_LEN,strlen(current->comm)));
	spin_lock_irqsave(&procname_whitelist_lock,flags);
	atomic_inc(&procname_whitelist_users);
	if (rhashtable_lookup_fast(&procname_whitelist,&curname,
					procname_whitelist_params))
	        ret = 1;
	atomic_dec(&procname_whitelist_users);
	spin_unlock_irqrestore(&procname_whitelist_lock,flags);
	return ret;
}

static int check_pid(void)
{
	int ret = 0;
	unsigned long flags;
	spin_lock_irqsave(&pid_whitelist_lock,flags);
	atomic_inc(&pid_whitelist_users);
	if (rhashtable_lookup_fast(&pid_whitelist,&current->pid,
					pid_whitelist_params))
	        ret = 1;
	atomic_dec(&pid_whitelist_users);
	spin_unlock_irqrestore(&pid_whitelist_lock,flags);
	return ret;
}

static int check_uid(const struct cred *cur_creds)
{
	int ret = 0;
	unsigned long flags;
	spin_lock_irqsave(&uid_whitelist_lock,flags);
	atomic_inc(&uid_whitelist_users);
	if (rhashtable_lookup_fast(&uid_whitelist,&cur_creds->uid,
					uid_whitelist_params))
	        ret = 1;
	atomic_dec(&uid_whitelist_users);
	spin_unlock_irqrestore(&uid_whitelist_lock,flags);
	return ret;
}

static int check_gid(const struct cred *cur_creds)
{
	int ret = 0;
	unsigned long flags;
	spin_lock_irqsave(&gid_whitelist_lock,flags);
	atomic_inc(&gid_whitelist_users);
	if (rhashtable_lookup_fast(&gid_whitelist,&cur_creds->gid,
					gid_whitelist_params))
	        ret = 1;
	atomic_dec(&gid_whitelist_users);
	spin_unlock_irqrestore(&gid_whitelist_lock,flags);
	return ret;
}

int check_whitelist()
{
	const struct cred *cur_creds = current_cred();
	if (check_procname())
		return 1;
	else if (check_pid())
		return 1;
	else if (check_uid(cur_creds))
		return 1;
	else if (check_gid(cur_creds))
		return 1;
	else
		return 0;
}


static void procname_whitelist_show(struct seq_file *p, void *v)
{
	struct rhashtable_iter iter;
	struct procname *procname_id;
        unsigned long flags;

        spin_lock_irqsave(&procname_whitelist_lock,flags);
        atomic_inc(&procname_whitelist_users);
        rhashtable_walk_enter(&procname_whitelist,&iter);
        rhashtable_walk_start(&iter);

        while ((procname_id = rhashtable_walk_next(&iter)) != NULL) {
                rhashtable_walk_stop(&iter);
                seq_printf(p,"%-*s%.*s\n",
                        11,"PROCNAME",
                        16,procname_id->name);
                rhashtable_walk_start(&iter);
        }

        rhashtable_walk_stop(&iter);
        rhashtable_walk_exit(&iter);
        atomic_dec(&procname_whitelist_users);
        spin_unlock_irqrestore(&procname_whitelist_lock,flags);
}

static void pid_whitelist_show(struct seq_file *p, void *v)
{
	struct rhashtable_iter iter;
	unsigned int *cur_id;
        unsigned long flags;

        spin_lock_irqsave(&pid_whitelist_lock,flags);
        atomic_inc(&pid_whitelist_users);
        rhashtable_walk_enter(&pid_whitelist,&iter);
        rhashtable_walk_start(&iter);

        while ((cur_id = rhashtable_walk_next(&iter)) != NULL) {
                rhashtable_walk_stop(&iter);
                seq_printf(p,"%-*s%u\n",
                        11,"PID",
                        *cur_id);
                rhashtable_walk_start(&iter);
        }

        rhashtable_walk_stop(&iter);
        rhashtable_walk_exit(&iter);
        atomic_dec(&pid_whitelist_users);
        spin_unlock_irqrestore(&pid_whitelist_lock,flags);
}

static void uid_whitelist_show(struct seq_file *p, void *v)
{
	struct rhashtable_iter iter;
	unsigned int *cur_id;
        unsigned long flags;

        spin_lock_irqsave(&uid_whitelist_lock,flags);
        atomic_inc(&uid_whitelist_users);
        rhashtable_walk_enter(&uid_whitelist,&iter);
        rhashtable_walk_start(&iter);

        while ((cur_id = rhashtable_walk_next(&iter)) != NULL) {
                rhashtable_walk_stop(&iter);
                seq_printf(p,"%-*s%u\n",
                        11,"UID",
                        *cur_id);
                rhashtable_walk_start(&iter);
        }

        rhashtable_walk_stop(&iter);
        rhashtable_walk_exit(&iter);
        atomic_dec(&uid_whitelist_users);
        spin_unlock_irqrestore(&uid_whitelist_lock,flags);
}

static void gid_whitelist_show(struct seq_file *p, void *v)
{
	struct rhashtable_iter iter;
	unsigned int *cur_id;
        unsigned long flags;

        spin_lock_irqsave(&gid_whitelist_lock,flags);
        atomic_inc(&gid_whitelist_users);
        rhashtable_walk_enter(&gid_whitelist,&iter);
        rhashtable_walk_start(&iter);

        while ((cur_id = rhashtable_walk_next(&iter)) != NULL) {
                rhashtable_walk_stop(&iter);
                seq_printf(p,"%-*s%u\n",
                        11,"GID",
                        *cur_id);
                rhashtable_walk_start(&iter);
        }

        rhashtable_walk_stop(&iter);
        rhashtable_walk_exit(&iter);
        atomic_dec(&gid_whitelist_users);
        spin_unlock_irqrestore(&gid_whitelist_lock,flags);
}

static int whitelist_show(struct seq_file *p, void *v)
{
	seq_printf(p,"%-*s%-*s\n",
                11,"TYPE",
                21,"ID");
	procname_whitelist_show(p,v);
	pid_whitelist_show(p,v);
	uid_whitelist_show(p,v);
	gid_whitelist_show(p,v);
        return 0;
}

static int whitelist_open(struct inode *inode,struct file *file)
{
        return single_open(file,whitelist_show,NULL);
}

const struct proc_ops whitelist_ops = {
        .proc_open = whitelist_open,
        .proc_read=seq_read,
        .proc_release=single_release,
};

struct proc_dir_entry *whitelist_viewer;
#endif
