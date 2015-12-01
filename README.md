## 1. Description
A network latency measurement tool. The implementation is based on Linux kernel 3.18.11. 

## 2. How to use

Our implementation consits of a kernel patch and a kernel module. To use this tool, you need to patch Linux kernel (3.18.11) first, then install the kernel module.

### 2.1 How to apply the kernel patch 

The kernel patch implements two functions: (1) set skb timestamp when a TCP packet is generated or received by NIC driver (tg3 and ixgbe) (2) dynamically adjust TCP RTO min in user space (using sysctl). 

### 2.2 How to install the kernel module

