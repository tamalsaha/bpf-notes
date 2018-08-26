# perf-tools

## Kprobe

- [https://lwn.net/Articles/132196/](https://lwn.net/Articles/132196/) 

KProbes is a debugging mechanism for the Linux kernel which can also be used for monitoring events inside a production system.

JProbes are used to get access to a kernel function's arguments at runtime.

Uprobe:

[http://www.brendangregg.com/blog/2015-06-28/linux-ftrace-uprobe.html](http://www.brendangregg.com/blog/2015-06-28/linux-ftrace-uprobe.html) 


Kernel Auditing as Scale

Falco - Kernel Module

BPF - 
http://www.brendangregg.com/Slides/BSidesSF2017_BPF_security_monitoring.pdf 

Auditd - 
https://news.ycombinator.com/item?id=13010544 

https://slack.engineering/syscall-auditing-at-scale-e6a3ca8ac1b8

As the kind-of-sort-of maintainer of Linux's syscall infrastructure on x86, I have a public service announcement: the syscall auditing infrastructure is awful.
It is inherently buggy in numerous ways. It hardcodes the number of arguments a syscall has incorrectly. It screws up compat handling. It doesn't robustly match entries to returns. It has an utterly broken approach to handling x32 syscalls. It has terrifying code that does bizarre things involving path names (!). It doesn't handle containerization sensibly at all. I wouldn't be at all surprised if it contains major root holes. And last, but certainly not least, it's eminently clear that no one stress tests it.
If you really want to use it for production, invest the effort to fix it, please. (And cc me.) Otherwise do yourself a favor and stay away from it. Use the syscall tracing infrastructure instead.

Yes, more or less. There are bunch of different "tracing" mechanisms in the kernel, and perf trace is the common way to use it. Syscalls trigger tracepoints, and anything that can see tracepoints can see them. Using eBPF to trace syscalls is probably quite useful.


Why Falco is unsafe? It loads kernel module.

https://stackoverflow.com/questions/1565323/linux-kernel-modules-security-risk



```
What is XDP

https://www.iovisor.org/technology/xdp


http://prototype-kernel.readthedocs.io/en/latest/networking/XDP/introduction.html


XDP LB ebpf
https://gist.github.com/summerwind/080750455a396a1b1ba78938b3178f6b 

Xdp_ drop using ebpf
https://github.com/iovisor/gobpf/blob/master/examples/bcc/xdp/xdp_drop.go


FB xdp - LB
https://drive.google.com/open?id=1EAUsfpMOWfisllfsz6CTXV1j6jJ5qnie 

```



```
Examples of ebpf

http://cilium.readthedocs.io/en/latest/bpf/#projects-using-bpf 
```



```
L7 in Kernel
https://lwn.net/Articles/719850/

Kproxy : https://www.youtube.com/watch?v=CcGtDMm1SJA&feature=youtu.be&t=30m15s

Perf ring buffer: https://lwn.net/Articles/388978/ 

Kproxy
https://lwn.net/Articles/726811/


kTLS
https://lwn.net/Articles/666509/

https://lwn.net/Articles/665602/

https://blog.filippo.io/playing-with-kernel-tls-in-linux-4-13-and-go/

```



```
BPF + Kubernetes
https://kubernetes.io/blog/2017/12/using-ebpf-in-kubernetes/
```
