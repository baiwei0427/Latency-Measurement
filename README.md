## 1. Description
A network latency measurement tool. The implementation is based on Linux kernel 3.18.11. 

## 2. How to use

Our implementation consits of a kernel patch and a kernel module. To use this tool, you need to patch Linux kernel (3.18.11) first, then install the kernel module.

The kernel patch provides two functions: (1) set skb timestamp when a TCP packet is generated (`tcp_transmit_skb`) or received by NIC driver (current implementation supports `Broadcom tg3` and `Intel ixgbe` drivers) (2) dynamically adjust TCP RTO min in user space (using sysctl). 

The kernel module adds hooks to several network functions, including
<ol>
<li>TX: <code>ip_queue_xmit</code>, <code>ip_output</code>, <code>dev_queue_xmit</code> and <code>qdisc dequeue</code></li>
<li>RX: <code>ip_rcv</code>, <code>ip_local_deliver</code>, <code>tcp_v4_rcv</code> and <code>tcp_rcv_established</code></li> 
</ol>

### 2.1 How to apply the kernel patch 
(1) Download the Linux Kernel 3.18.11
<pre><code>$ wget https://cdn.kernel.org/pub/linux/kernel/v3.x/linux-3.18.11.tar.gz<br/>
$ tar zxvf linux-3.18.11.tar.gz
</code></pre>

(2) Install the patch
<pre><code>$ cp kernel_measurement3.patch linux-3.18.11<br/>
$ cd linux-3.18.11<br/>
$ patch -p1 < kernel_measurement3.patch
</code></pre>

(3) Compile the kernel

### 2.2 How to install the kernel module
To compile the kernel module (`latency_probe`), you need kernel header files. 
<pre><code>$ cd latency_probe<br/>
$ make<br/>
</code></pre>

Then you can install the kernel module as follows (assuming our module works on `eth0`):
<pre><code>$ insmod latency_probe.ko
& tc qdisc add dev eth0 root multiq
</code></pre>

The kernel module writes results using `printk`. So you can get measurement results in `syslog` (or using `dmesg`). You can configure the kernel module using sysctl interfaces. For more details, you can read `params.h`.

To remove the kernel module
<pre><code>$ tc qdisc del dev eth0 root 
$ rmmod latency_probe
</code></pre>
