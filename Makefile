KDIR = ~/learning/linux #replace with appropriate path
CC = gcc
CFLAGS = -Wall -O3

all: kbuild

kbuild:
	make -C $(KDIR) M=`pwd`


clean:
	make -C $(KDIR) M=`pwd` clean

