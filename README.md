# bpf-notes

Traditionally, BPF could only be attached to sockets for socket filtering. BPF's first use case was in `tcpdump`. When you run `tcpdump` the filter is compiled into a BPF program and attached to a raw `AF_PACKET` socket in order to print out filtered packets.

But over the years, eBPF added the ability to attach to [other kernel objects](https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h#L117-L133). In addition to socket filtering, some supported attach points are:

*   Kprobes (and userspace equivalents uprobes)
*   Tracepoints
*   Network schedulers or qdiscs for classification or action (tc)
*   XDP (eXpress Data Path) This and other, newer features like in-kernel helper functions and shared data-structures (maps) that can be used to communicate with user space, extend BPF's capabilities.

<img src="images/bpf-prog-types.png" width="65%" height="65%">

- [A thorough introduction to eBPF](https://lwn.net/Articles/740157/) 
- [BPF and XDP Reference Guide](https://github.com/cilium/cilium/blob/master/Documentation/bpf.rst)
- eBPF maps: Using eBPF maps is a method to keep state between invocations of the eBPF program, and allows sharing data between eBPF kernel programs, and also between kernel and user-space applications.
  - [eBPF maps](https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html)
  - [Types of eBPF maps](https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps_types.html)
  - [`bpf_map_get_next_key` pitfalls](https://www.bouncybouncy.net/blog/bpf_map_get_next_key-pitfalls/)
- [Persistent BPF objects](https://lwn.net/Articles/664688/)
- [Using eBPF in Kubernetes](https://kubernetes.io/blog/2017/12/using-ebpf-in-kubernetes/)
- Kernel docs
  - [BPF(2) man page](http://man7.org/linux/man-pages/man2/bpf.2.html)
  - [Linux Socket Filtering aka Berkeley Packet Filter (BPF)](https://github.com/torvalds/linux/blob/master/Documentation/networking/filter.txt)

## Go + eBPF
- https://github.com/iovisor/gobpf
- https://github.com/andrewkroh/go-ebpf
- https://github.com/newtools/ebpf
- comparison: https://github.com/newtools/ebpf/issues/54
- projects on Github: https://github.com/topics/ebpf

## Testing eBPF in CI

- [Video: High-performance Linux monitoring with eBPF](https://www.youtube.com/watch?v=uTTFUpT0Sfw)

<img src="images/bpf-ci.png" width="50%" height="50%">







---
















---


- [Dive into BPF: a list of reading material](https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/)
- [How to filter packets super fast: XDP & eBPF!](https://jvns.ca/blog/2017/04/07/xdp-bpf-tutorial/)
- [http://brendangregg.com/perf.html#eBPF](http://brendangregg.com/perf.html#eBPF)



**Notes**
- This also implies that API users must clear/zero sizeof(bpf_attr), as compiler can size-align the struct differently, to avoid garbage data to be interpreted as parameters by future kernels.

## eBPF + Prometheus exporter
- https://github.com/cloudflare/ebpf_exporter
- https://github.com/dswarbrick/ebpf_exporter

## eBPF VM in userspace
- https://github.com/iovisor/ubpf/

**Tracing syscalls using eBPF using tracepoints**
- https://github.com/pmem/vltrace

**eBPF with autocomplete**
- https://ops.tips/blog/developing-ebpf-with-autocompletion-support/

**GRO Engine**
- https://lwn.net/Articles/358910/

## BPF: sockmap and sk redirect support
- John Fastabend: https://lwn.net/Articles/731133/
- Sample problem: https://github.com/linus5/linux-kernel-xdp/commit/f0c18713b4e6d5398fc9cb8b24a61c566ecbd166

This series implements a sockmap and socket redirect helper for BPF
using a model similar to XDP netdev redirect. A sockmap is a BPF map
type that holds references to sock structs. Then with a new sk
redirect bpf helper BPF programs can use the map to redirect skbs
between sockets,

      bpf_sk_redirect_map(map, key, flags)

Finally, we need a call site to attach our BPF logic to do socket
redirects. We added hooks to recv_sock using the existing strparser
infrastructure to do this. The call site is added via the BPF attach
map call. To enable users to use this infrastructure a new BPF program
BPF_PROG_TYPE_SK_SKB is created that allows users to reference sock
details, such as port and ip address fields, to build useful socket
layer program. The sockmap datapath is as follows,

     recv -> strparser -> verdict/action

where this series implements the drop and redirect actions.
Additional, actions can be added as needed.

A sample program is provided to illustrate how a sockmap can
be integrated with cgroups and used to add/delete sockets in
a sockmap. The program is simple but should show many of the
key ideas.

To test this work test_maps in selftests/bpf was leveraged.
We added a set of tests to add sockets and do send/recv ops
on the sockets to ensure correct behavior. Additionally, the
selftests tests a series of negative test cases. We can expand
on this in the future.

I also have a basic test program I use with iperf/netperf
clients that could be sent as an additional sample if folks
want this. It needs a bit of cleanup to send to the list and
wasn't included in this series.

For people who prefer git over pulling patches out of their mail
editor I've posted the code here,

https://github.com/jrfastab/linux-kernel-xdp/tree/sockmap

For some background information on the genesis of this work
it might be helpful to review these slides from netconf 2017
by Thomas Graf,

http://vger.kernel.org/netconf2017.html
https://docs.google.com/a/covalent.io/presentation/d/1dwS...


**XDP support for veth driver**
- https://twitter.com/davem_dokebi/status/1021082455086792704
- https://marc.info/?l=linux-netdev&m=153227240330693&w=2

**Accelerating Linux security with eBPF iptables**
https://twitter.com/sebymiano/status/1027164445448069120?s=19

## perf_events
- http://web.eece.maine.edu/~vweaver/projects/perf_events/
- http://www.brendangregg.com/perf.html

- Tracepoints (stable): https://www.kernel.org/doc/Documentation/trace/tracepoints.txt
- kprobe (unstable): bpf  


## Kernel Auditing as Scale

BPF - 
http://www.brendangregg.com/Slides/BSidesSF2017_BPF_security_monitoring.pdf 

Auditd - 
https://news.ycombinator.com/item?id=13010544 

https://slack.engineering/syscall-auditing-at-scale-e6a3ca8ac1b8

As the kind-of-sort-of maintainer of Linux's syscall infrastructure on x86, I have a public service announcement: the syscall auditing infrastructure is awful.
It is inherently buggy in numerous ways. It hardcodes the number of arguments a syscall has incorrectly. It screws up compat handling. It doesn't robustly match entries to returns. It has an utterly broken approach to handling x32 syscalls. It has terrifying code that does bizarre things involving path names (!). It doesn't handle containerization sensibly at all. I wouldn't be at all surprised if it contains major root holes. And last, but certainly not least, it's eminently clear that no one stress tests it.
If you really want to use it for production, invest the effort to fix it, please. (And cc me.) Otherwise do yourself a favor and stay away from it. Use the syscall tracing infrastructure instead.

Yes, more or less. There are bunch of different "tracing" mechanisms in the kernel, and perf trace is the common way to use it. Syscalls trigger tracepoints, and anything that can see tracepoints can see them. Using eBPF to trace syscalls is probably quite useful.

Falco - Kernel Module. Why Falco is unsafe? It loads kernel module.

https://stackoverflow.com/questions/1565323/linux-kernel-modules-security-risk

