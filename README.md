# Linux Security Hardening Scanning Tool
## Introduction ##
**securityscan.py** is a tool writen in Python and checks the followig Linux security hardening options:
* checks the Linux kernel config options (according to the list given by [Kernel Self Protection Project](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)). The black list and other configuration options are configurable in policy.json
* checks loaded kernel modules
  * shows the number of dynamically loaded modules
  * alerts if blacklisted modules are loaded
* checks dmesg messages
* checks running processes
  * alerts if there are processes listening ports (including root processes)
  * checks if processes have executable heap and stack
* scans executables
  * alerts if they are built without PIE, relro, stack protectors,..
* scans the file system and finds X509 certificates that will expire in a year or use weak keys
* checks vulnerabilities (*/sys/devices/system/cpu/vulnerabilities/*)
* Does system security hardening checks
  * "*/dev/kmem*" and "*/proc/kcore*" are disabled
  * ASLR (Address Space Layout Randomization) settings ("*/proc/sys/kernel/randomize_va_space*")
  * kptr_restrict setting for kernel pointer leak mitigation ("*/proc/sys/kernel/kptr_restrict*")
  * entropy in the primary entropy pool ("*/proc/sys/kernel/random/entropy_avail*")
* Network security hardening checks
    
    IPv4 ICMP redirect acceptance is disabled
    
      net.ipv4.conf.default.accept_redirects = 0
      net.ipv4.conf.all.accept_redirects = 0
    
    IPv6 ICMP redirect acceptance is disabled
      
      net.ipv6.conf.default.accept_redirects = 0
      net.ipv6.conf.all.accept_redirects = 0
    
    don't send IPv4 ICMP redirects
        
      net.ipv4.conf.all.send_redirects = 0    
    
    IP spoofing protection is enabled  
        
      net.ipv4.conf.all.rp_filter (enable strict more '1' if possible)      

    Disables the acceptance of packets with the SSR option set in the IPv4 packet header

      net.ipv4.conf.default.accept_source_route = 0
      net.ipv4.conf.all.accept_source_route = 0

    IP forwarding is disabled
      
      net.ipv4.ip_forward = 0
      net.ipv6.conf.all.forwarding = 0
      net.ipv6.conf.default.forwarding = 0

    TCP Syn cookie protection is enabled

      net.ipv4.tcp_syncookies = 1

## Setup
---
$ sudo pip3 install unicorn psutil pyopenssl python-dateutil pwntools rich 

## Usage
      usage: securityscan.py [-h] --arch ARCH --config CONFIG --policy POLICY
                             [--kernel] [--dmesg] [--proc] [--exec] [--vuln]
                             [--cert] [--sys]
      optional arguments:
    
      -h, --help       show this help message and exit
      --arch ARCH      Architecture, x86, arm64 or arm
      --config CONFIG  Kernel config file
      --policy POLICY  Policy file
      --kernel         Run kernel checks
      --dmesg          Run dmesg checks
      --proc           Run process checks
      --exec           Run excecutable checks
      --vuln           Run vulnerability checks
      --cert           Run X.509 certificate checks
      --sys            Run system checks

## Sample usage ##
    $ sudo ./securityscan.py  --arch x86 --config /boot/config-5.11.0-43-generic --policy policy.json  --kernel --dmesg --proc --exec --vuln --cert --sys

## Sample usage screenshot

![Screenshot from 2022-01-03 19-01-54](https://user-images.githubusercontent.com/5366714/147958858-7b9328e8-ca4e-42e8-9ebb-59e29f9ed29d.png)
)

## The relevant links ##
* [Kernel Self Protection Project](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)
* [Google Online Security Blog: Linux Kernel Security Done Right - Kees Cook](https://security.googleblog.com/2021/08/linux-kernel-security-done-right.html)
* [Linux Kernel Modules in Rust](https://static.sched.com/hosted_files/lssna19/d6/kernel-modules-in-rust-lssna2019.pdf)
* [LKRG - Linux Kernel Runtime Guard](https://www.openwall.com/lkrg/)
* [Project Zero: How a simple Linux kernel memory corruption bug can lead to complete system compromise](https://googleprojectzero.blogspot.com/2021/10/how-simple-linux-kernel-memory.html)
* [GitHub - a13xp0p0v/Linux Kernel Defense Map](https://github.com/a13xp0p0v/linux-kernel-defence-map)
* [GitHub - a13xp0p0v/kconfig-hardened-check: A tool for checking the security hardening options of the Linux kernel](https://github.com/a13xp0p0v/kconfig-hardened-check)
