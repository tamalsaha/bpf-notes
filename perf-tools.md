# perf-tools

## Kprobe

- [An introduction to KProbes](https://lwn.net/Articles/132196/): KProbes is a debugging mechanism for the Linux kernel which can also be used for monitoring events inside a production system.
- **JProbes** are used to get access to a kernel function's arguments at runtime.
- **Uprobe**: [http://www.brendangregg.com/blog/2015-06-28/linux-ftrace-uprobe.html](http://www.brendangregg.com/blog/2015-06-28/linux-ftrace-uprobe.html) 
- [Security Monitoring with eBPF](https://github.com/tamalsaha/bpf-notes/blob/master/papers/BSidesSF2017_BPF_security_monitoring.pdf)
- [Tracing syscalls using eBPF using tracepoints](https://github.com/pmem/vltrace)
- [Syscall Auditing at Scale](https://slack.engineering/syscall-auditing-at-scale-e6a3ca8ac1b8)
- [Linux kernel modules - security risk?](https://stackoverflow.com/questions/1565323/linux-kernel-modules-security-risk)
- Auditd: https://news.ycombinator.com/item?id=13010544 
As the kind-of-sort-of maintainer of Linux's syscall infrastructure on x86, I have a public service announcement: the syscall auditing infrastructure is awful.
It is inherently buggy in numerous ways. It hardcodes the number of arguments a syscall has incorrectly. It screws up compat handling. It doesn't robustly match entries to returns. It has an utterly broken approach to handling x32 syscalls. It has terrifying code that does bizarre things involving path names (!). It doesn't handle containerization sensibly at all. I wouldn't be at all surprised if it contains major root holes. And last, but certainly not least, it's eminently clear that no one stress tests it.
If you really want to use it for production, invest the effort to fix it, please. (And cc me.) Otherwise do yourself a favor and stay away from it. Use the syscall tracing infrastructure instead.
Yes, more or less. There are bunch of different "tracing" mechanisms in the kernel, and perf trace is the common way to use it. Syscalls trigger tracepoints, and anything that can see tracepoints can see them. Using eBPF to trace syscalls is probably quite useful.



## perf_events
- http://web.eece.maine.edu/~vweaver/projects/perf_events/
- http://www.brendangregg.com/perf.html

- Tracepoints (stable): https://www.kernel.org/doc/Documentation/trace/tracepoints.txt
- kprobe (unstable): bpf  
