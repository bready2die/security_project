KDIR = ~/learning/linux #replace with appropriate path
CC = gcc
CFLAGS = -Wall -O3

all: kbuild frontend

kbuild:
	make -C $(KDIR) M=`pwd`

frontend:
	$(CC) $(CFLAGS) -m32 rkit_frontend.c -o rkit_frontend

clean:
	make -C $(KDIR) M=`pwd` clean
	rm rkit_frontend
