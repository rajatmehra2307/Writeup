### Sandboxing ###

These are the notes for solving the Sandboxing module of pwn.college. This includes some description of the sandboxing techniques that are described in the module - chroot, seccomp and using namespaces

#### chroot ####
This is an old way of creating a sandbox. It is a command that is used to create a different root directory for a process. 

```
chroot("/tmp/jail")
 ```
will disallow process from getting out of the jail. You need special privileges to run as root.

chroot is a system call has two effects
<li> For the process, it changes the meaning of root
<li> If you try to do ../../, you still can't escape the jail

It does not close any file descriptors that are pointing to files outside the jail
It doesn't change directory into the jail.

One of the ways to bypass chroot is, if there is any file descriptor for a resource outside the chroot jail you can use ```openat``` or ```execveat``` that takes the open fd and a relative path w.r.t the open fd.

Current working directory is an implicitly opened resource. The ```AT_FDCWD``` value represents the current working directory.

chroot overrides the previous chroot. So one can chroot again to bypass the sandboxing

chroot does not provide isolation like pid isolation, network isolation etc.


#### Seccomp ####
allows/disallows certain system calls. This is inherited by child process as well
The way seccomp works is it uses kernel functionality called extended Berkeley Packet filters, eBPF. BPF is an architecture, inside the kernel there is a virtual machine for BPF that executes these filters.

Escaping seccomp

- Permissive policies. Allowing ptrace can escape sandbox by attaching to a different process. ```sendmsg``` system call can transfer file descriptor between processes.
- syscall confusion - Many x64 arch are bkwd compatible. Linux has different syscall numbers for x86 and amd64. By default configuration if any syscall is attempted using 32 bit mode but there are non default configurations for seccomp filters that are not like that
- kernel vuln in syscall handlers


#### Namespaces ####
This is the modern way of creating sandboxes, providing processes isolation in terms of userspace, pid, networks etc. Namespacing is the underlying mechanism used to run containers

- unshare - is a command used to unshare a namespace. For ins. ```unshare -m ``` unshares the mount namespace. It creates a new namespace. Changes to a mount namespace are only reflected in the same namespace. If the parent mounts a new filesystem inside the directory from where the child namespace was created then this new mount is not seen by the child. Basically 2 processes can have different views of the same file system. If we create a new namespace using ```unshare -n```, and open a nc port on listen mode and try to connect to it from a different namespace's process it won't work. For instance, lets say in the first terminal you run

```
unshare -n bash
nc -l 1337
```
and in the new terminal you try to connect to localhost:1337 using nc, it won't work since the network namespace is different for these two processes. You can kill processes running in child namespace from the parent namespace.

- pivot_root is a new way of creating a new root 

For more info: https://www.youtube.com/watch?v=-Xd22KjZwJk&t=2261s&ab_channel=pwn.college 
