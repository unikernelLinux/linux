SPDX-License-Identifier: GPL-2.0

Unikernel Linux (UKL)
=====================

Unikernel Linux (UKL) is a research project aimed at integrating
application specific optimizations to the Linux kernel. This RFC aims to
introduce this research to the community. Any feedback regarding the idea,
goals, implementation and research is highly appreciated.

Unikernels are specialized operating systems where an application is linked
directly with the kernel and runs in supervisor mode. This allows the
developers to implement application specific optimizations to the kernel,
which can be directly invoked by the application (without going through the
syscall path). An application can control scheduling and resource
management and directly access the hardware. Application and the kernel can
be co-optimized, e.g., through LTO, PGO, etc. All of these optimizations,
and others, provide applications with huge performance benefits over
general purpose operating systems.

Linux is the de-facto operating system of today. Applications depend on its
battle tested code base, large developer community, support for legacy
code, a huge ecosystem of tools and utilities, and a wide range of
compatible hardware and device drivers. Linux also allows some degree of
application specific optimizations through build time config options,
runtime configuration, and recently through eBPF. But still, there is a
need for even more fine-grained application specific optimizations, and
some developers resort to kernel bypass techniques.

Unikernel Linux (UKL) aims to get the best of both worlds by bringing
application specific optimizations to the Linux ecosystem. This way,
unmodified applications can keep getting the benefits of Linux while taking
advantage of the unikernel-style optimizations. Optionally, applications
can be modified to invoke deeper optimizations.

There are two steps to unikernel-izing Linux, i.e., first, equip Linux with
a unikernel model, and second, actually use that model to implement
application specific optimizations. This patch focuses on the first part.
Through this patch, unmodified applications can be built as Linux
unikernels, albeit with only modest performance advantages. Like
unikernels, UKL would allow an application to be statically linked into the
kernel and executed in supervisor mode. However, UKL preserves most of the
invariants and design of Linux, including a separate page-able application
portion of the address space and a pinned kernel portion, the ability to
run multiple processes, and distinct execution modes for application and
kernel code. Kernel execution mode and application execution mode are
different, e.g., the application execution mode allows application threads
to be scheduled, handle signals, etc., which do not apply to kernel
threads. Application built as a Linux unikernel will have its text and data
loaded with the kernel at boot time, while the rest of the address space
would remain unchanged. These applications invoke the system call
functionality through a function call into the kernel system call entry
point instead of through the syscall assembly instruction. UKL would
support a normal userspace so the UKL application can be started, managed,
profiled, etc., using normal command line utilities.

Once Linux has a unikernel model, different application specific
optimizations are possible. We have tried a few, e.g., fast system call
transitions, shared stacks to allow LTO, invoking kernel functions
directly, etc. We have seen huge performance benefits, details of which are
not relevant to this patch and can be found in our paper.
(https://arxiv.org/pdf/2206.00789.pdf)

UKL differs significantly from previous projects, e.g., UML, KML and LKL.
User Mode Linux (UML) is a virtual machine monitor implemented on syscall
interface, a very different goal from UKL. Kernel Mode Linux (KML) allows
applications to run in kernel mode and replaces syscalls with function
calls. While KML stops there, UKL goes further. UKL links applications and
kernel together which allows further optimizations e.g., fast system call
transitions, shared stacks to allow LTO, invoking kernel functions directly
etc. Details can be found in the paper linked above. Linux Kernel Library
(LKL) harvests arch independent code from Linux, takes it to userspace as a
library to be linked with applications. A host needs to provide arch
dependent functionality. This model is very different from UKL. A detailed
discussion of related work is present in the paper linked above.

See samples/ukl for a simple TCP echo server example which can be built as
a normal user space application and also as a UKL application. In the Linux
config options, a path to the compiled and partially linked application
binary can be specified. Kernel built with UKL enabled will search this
location for the binary and link with the kernel. Applications and required
libraries need to be compiled with -mno-red-zone -mcmodel=kernel flags
because kernel mode execution can trample on application red zones and in
order to link with the kernel and be loaded in the high end of the address
space, application should have the correct memory model. Examples of other
applications like Redis, Memcached etc along with glibc and libgcc etc.,
can be found at https://github.com/unikernelLinux/ukl

List of authors and contributors:
=================================

Ali Raza - aliraza@bu.edu
Thomas Unger - tommyu@bu.edu
Matthew Boyd - mboydmcse@gmail.com
Eric Munson - munsoner@bu.edu
Parul Sohal - psohal@bu.edu
Ulrich Drepper - drepper@redhat.com
Richard Jones - rjones@redhat.com
Daniel Bristot de Oliveira - bristot@kernel.org
Larry Woodman - lwoodman@redhat.com
Renato Mancuso - rmancuso@bu.edu
Jonathan Appavoo - jappavoo@bu.edu
Orran Krieger - okrieg@bu.edu

