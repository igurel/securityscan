#!/usr/bin/python3
###############################################################################
#
# usage: securityscan.py [-h] --arch ARCH --config CONFIG --policy POLICY
#                        [--kernel] [--dmesg] [--proc] [--exec] [--vuln]
#                        [--cert] [--sys]
#
# optional arguments:
#   -h, --help       show this help message and exit
#   --arch ARCH      Architecture, x86, arm64 or arm
#   --config CONFIG  Kernel config file
#   --policy POLICY  Policy file
#   --kernel         Run kernel checks
#   --dmesg          Run dmesg checks
#   --proc           Run process checks
#   --exec           Run excecutable checks
#   --vuln           Run vulnerability checks
#   --cert           Run X.509 certificate checks
#   --sys            Run system checks
#
# Sample usage:
# sudo ./securityscan.py  --arch x86 \
#                         --config /boot/config-5.11.0-43-generic \
#                         --policy policy.json   
#                         --kernel \
#                         --dmesg \
#                         --proc \
#                         --exec \
#                         --vuln \
#                         --cert \
#                         --sys
#
################################################################################

import os
import sys
import re
import argparse
import tempfile
import psutil
import json
import OpenSSL
import datetime
import subprocess
from pwn import *
from dateutil import parser
from pathlib import Path
from rich.table import Table
from rich.console import Console
from rich import print, style
from rich.panel import Panel

# See http://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings
# for the recommended and black listed kernel config options

def exists(file):
    if not os.path.exists(file):
        print("ERROR: %s doesn't exist" % file)
        sys.exit()


class SecurityChecker():

        def __init__(self, arch, config, policy):
            self.arch = arch
            self.config = config
            self.policy = policy
            self.console = Console()


        def error(self, msg):
            self.grid.add_row("[red]ERROR", msg)


        def info(self, msg):
            self.grid.add_row("[green]INFO", msg)


        def print_row(self, msg):
            self.grid.add_row("", msg)


        def warning(self, msg):
            self.grid.add_row("[yellow]WARNING", msg)


        def title(self, msg):
            self.grid = Table.grid(expand=True)
            self.grid.add_column(width=10)
            self.grid.add_column()
            self.grid.add_row("", msg.upper(), style="bold")


        def print_grid(self):
            self.console.print(self.grid)
            self.console.print("\n")


        def error_if_int_val_not_equal(self, file, val):
            if not os.path.exists(file):
                self.error("%s doesn't exist" % file)
                return

            with open(file) as f:
                fval = int(f.read())
                if fval != val:
                    self.error("%s is %d, expected %d" % (file, fval, val))
                else:
                    self.info("%s is %d" % (file, fval))


        def read_policy(self):
            with open(self.policy) as f:
                try:
                    policy = json.load(f)
                except:
                    error("Parsing policy file failed..")
                    sys.exit()
            return policy


        def print_certificate(self, file):
            try:
                cert_parser = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(file).read())
                cert_issuer  = cert_parser.get_issuer()
                cert_subject = cert_parser.get_subject()
                notbefore = parser.parse(cert_parser.get_notBefore().decode("UTF-8"))
                notafter  = parser.parse(cert_parser.get_notAfter().decode("UTF-8"))

                notbefore_fmt = notbefore.strftime('%Y-%m-%d %H:%M:%S')
                notafter_fmt  = notafter.strftime('%Y-%m-%d %H:%M:%S')

                self.grid.add_row("", "")
                self.grid.add_row("File", "%s" % file)
                self.grid.add_row("Issuer", "%s" % cert_issuer.commonName)
                self.grid.add_row("Subject", "%s" % cert_subject.commonName)

                key_type = ""
                if cert_parser.get_pubkey().type() == OpenSSL.crypto.TYPE_RSA:
                    key_type = "RSA"
                elif cert_parser.get_pubkey().type() == OpenSSL.crypto.TYPE_EC:
                    key_type = "ECC"
                elif cert_parser.get_pubkey().type() == OpenSSL.crypto.TYPE_DSA:
                    key_type = "DSA"
                elif cert_parser.get_pubkey().type() == OpenSSL.crypto.TYPE_DH:
                    key_type = "DH"
                else:
                    key_type = "unknown"

                self.grid.add_row("Key type", "%s" % key_type)
                self.grid.add_row("Key size", "%s" % cert_parser.get_pubkey().bits())
                self.grid.add_row("Validity", "%s - %s" % (notbefore_fmt, notafter_fmt))
            except:
                pass


        def check_kernel(self):
            self.title("Scanning kernel config options")
            mod_count = 0
            mod_list = []
            lines = []

            policy = self.read_policy()

            with open(self.config, 'r') as fhandle:
                for line in fhandle.readlines():
                    line = line.rstrip()
                    if not line.startswith("#"):
                        lines.append(line)

            if 'blacklist' in policy['kernel']['config']['all']:
                for line in policy['kernel']['config']['all']['blacklist']:
                    if  line in lines:
                        self.error(line  + " is defined")

            if 'blacklist' in policy['kernel']['config'][self.arch]:
                for line in policy['kernel']['config'][self.arch]['blacklist']:
                    if  line in lines:
                        self.error(line  + " is defined")

            if 'recommended' in policy['kernel']['config']['all']:
                for line in policy['kernel']['config']['all']['recommended']:
                    if  not line in lines:
                        self.warning(line  + " is recommended but not defined")

            if 'recommended' in policy['kernel']['config'][self.arch]:
                for line in policy['kernel']['config'][self.arch]['recommended']:
                    if  not line in lines:
                        self.warning(line  + " is recommended but not defined")


            modtmp = tempfile.NamedTemporaryFile(prefix="mod.log.").name
            cmd = "lsmod > " + str(modtmp)
            os.system(cmd)
            with open(modtmp, 'r') as fhandle:
                for line in fhandle.readlines():
                    line = line.rstrip()
                    match = re.match( r'(.*?)\s+[0-9]+\s+(.*)', line, re.M|re.I)
                    if match:
                        mod_list.append(match.group(1))
                        mod_count += 1

            self.info("Detected %d dynamically loaded modules" % mod_count)
            for mod in mod_list:
                for bl_mod in policy['kernel']['module']['blacklist']:
                    m = re.search(bl_mod, mod)
                    if m: self.error("Detected dynamically loaded blacklisted module = %s " % bl_mod)

            os.remove(modtmp)
            self.print_grid()


        def check_dmesg(self):
            self.title("Scanning dmesg messages")
            dmtmp = tempfile.NamedTemporaryFile(prefix="dmesg.log.").name
            cmd = "dmesg > " + str(dmtmp)
            os.system(cmd)
            with open(dmtmp, 'r') as fhandle:
                for line in fhandle.readlines():
                    line = line.rstrip()

                    match = re.match( r'(.*?) Linux version (.*)', line)
                    if match: self.info("%s" % match.group(2))

                    match = re.match( r'(.*?) Secure boot disabled', line)
                    if match: self.warning("Secure boot disabled")

                    match = re.match( r'(.*?) AppArmor: (.*)', line)
                    if match: self.info("AppArmor: %s" % match.group(2))

                    match = re.match( r'(.*?) SELinux: (.*)', line)
                    if match: self.info("SELinux: %s" % match.group(2))

                    match = re.match( r'(.*?) Yama: (.*)', line)
                    if match: self.info("Yama is enabled")

                    match = re.match( r'(.*?) Spectre V1 : (.*)', line)
                    if match: self.info("Spectre V1 " + match.group(2))

                    match = re.match( r'(.*?) Spectre V2 : (.*)', line)
                    if match: self.info("Spectre V2 " + match.group(2))

                    match = re.match( r'(.*?) process (.*) started with executable stack', line)
                    if match: self.error ("Detected process " + match.group(2) + " with executable stack")

            os.remove(dmtmp)
            self.print_grid()


        def check_processes(self):
            self.title("Scanning processes")
            # root processes
            proc_count = 0
            root_proc_list = []
            root_pids = []

            policy = self.read_policy()

            for proc in psutil.process_iter():
                if proc.username() == 'root':
                    if not proc.pid in root_pids:
                        root_pids.append(proc.pid)
                    root_proc_list.append(proc.name())
                    proc_count += 1

            self.info("Detected %s root processes (inc. kernel threads and user space root processes)" % (proc_count))

            for root_proc in root_proc_list:
                for bl_proc  in policy['process']['root']['blacklist']:
                    m = re.search(bl_proc, root_proc)
                    if m: self.error("Detected blacklisted \"%s\" in the root process list" % bl_proc)

            # list the processes and check of they have executable heap and stack
            heap_x_cnt = 0
            stack_x_cnt = 0
            for pid in psutil.pids():
                p = psutil.Process(pid)
                for map in p.memory_maps(grouped=False):
                    # check if heap is marked as executable
                    if '[heap]' in map.path and 'x' in map.perms:
                        self.error("%s has executable heap" % (p.name()))
                        heap_x_cnt += 1
                    # check if stack is marked as executable
                    if '[stack]' in map.path and 'x' in map.perms:
                        self.error("%s has executable stack" % (p.name()))
                        stack_x_cnt += 1

            if heap_x_cnt == 0:  self.info("No runninng process with executable heap")
            if stack_x_cnt == 0: self.info("No runninng process with executable stack")

            # List of the ports and root processes listening them
            connections = psutil.net_connections()
            root_proc_ports = []
            self.warning("List of the ports being listened:")
            for con in connections:
                if con.status == 'LISTEN':
                    self.print_row("%s(%s)" % (psutil.Process(con.pid).name(), con.laddr.port))

            self.warning("Root processes listening ports")
            for con in connections:
                if con.pid in root_pids:
                    if con.status == 'LISTEN':
                        root_proc_port = "%s(%s)" % (psutil.Process(con.pid).name(), con.laddr.port)
                        if not root_proc_port in root_proc_ports:
                            root_proc_ports.append(root_proc_port)

            for root_proc_port in root_proc_ports:
                self.print_row("%s" % root_proc_port)
                
            self.print_grid()


        def check_executables(self):
            self.title("Scanning binaries")

            nonpie = []
            noncanary = []
            nonrelro = []
            execstack = []
            nonfortify = []
            exec_list = []

            policy = self.read_policy()

            for folder in policy['exec']['folders']:
                result = subprocess.run(['find', folder, '-type', 'f', '-executable'], stdout=subprocess.PIPE)
                execs = result.stdout.decode("ascii").splitlines()
                if len(execs) != 0:
                    exec_list.append(execs)

            for exec in exec_list[0]:
                try:
                    elf = ELF(exec, checksec=False)
                    if not elf.canary:    noncanary.append(exec)
                    if not elf.fortify:   nonfortify.append(exec)
                    if not elf.pie:       nonpie.append(exec)
                    if not elf.relro:     nonrelro.append(exec)
                    if elf.execstack:     execstack.append(exec)
                except:
                    pass

            if len(nonpie) != 0:
                self.warning("[yellow]Non-PIE binaries:")
                for binary in nonpie: self.print_row("%s" % binary)

            if len(noncanary) != 0:
                self.warning("[yellow]Non-stack canary binaries:")
                for binary in noncanary: self.print_row("%s" % binary)

            if len(nonrelro) != 0:
                self.warning("[yellow]Non-relro binaries")
                for binary in nonrelro: self.print_row("%s" % binary)

            if len(nonfortify) != 0:
                self.warning("[yellow]Non-fortify binaries")
                for binary in nonfortify: self.print_row("%s" % binary)

            if len(execstack) != 0:
                self.warning("[yellow]Binaries with executable stack")
                for binary in execstack: self.print_row("%s" % binary)

            self.print_grid()


        def check_vulnerabilities(self):
            self.title("Scanning microarchitectural vulnerabilities")
            folder = "/sys/devices/system/cpu/vulnerabilities/"
            vultmp = tempfile.NamedTemporaryFile(prefix="vul.log.").name

            if os.path.exists(folder):
                cmd = "grep . " + folder + "* > " + str(vultmp)
                os.system(cmd)
                with open(vultmp,'r') as fhandle:
                    lines = fhandle.read().splitlines()
                os.remove(vultmp)
                for line in lines:
                    line = line.replace(folder, "")
                    self.info(line)
            else:
                self.warning("Cannot locate %s" % folder)

            self.print_grid()


        def check_certificates(self):
            self.title("Scanning X.509 certificates")
            cert_list = []
            certs_to_expire = []
            certs_expired = []
            certs_with_weak_keys = []

            policy = self.read_policy()

            for folder in policy['certificate']['folders']:
                for cert in Path(folder).rglob('*.pem'):
                    cert_list.append(cert)

            for folder in policy['certificate']['folders']:
                for cert in Path(folder).rglob('*.crt'):
                    cert_list.append(cert)

            now = datetime.datetime.now()

            for cert in cert_list:
                try:
                    cert_parser = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(cert).read())
                    expiry = cert_parser.get_notAfter()
                    date_fmt = r'%Y%m%d%H%M%SZ'
                    expires = datetime.datetime.strptime(str(expiry)[2:-1], date_fmt)
                    remaining = (expires - datetime.datetime.utcnow()).days

                    # Find certificates that will expire in 1 year
                    if remaining <= 365 and not cert_parser.has_expired():
                        certs_to_expire.append(cert)

                    # Expired certificates
                    if cert_parser.has_expired():
                        certs_expired.append(cert)

                    # Certificates with weak keys
                    if cert_parser.get_pubkey().type() == OpenSSL.crypto.TYPE_RSA and cert_parser.get_pubkey().bits() < 2048:
                        certs_with_weak_keys.append(cert)

                    if cert_parser.get_pubkey().type() == OpenSSL.crypto.TYPE_EC and cert_parser.get_pubkey().bits() < 256:
                        certs_with_weak_keys.append(cert)
                except:
                    pass

            if len(certs_to_expire) == 0:
                self.info("No certificates found")

            if len(certs_to_expire) > 0:
                self.warning("[yellow]X.509 certificates to expire within 1 year")
                for cert in certs_to_expire: self.print_certificate(cert)

            if len(certs_expired) > 0:
                self.error("[red]Expired X.509 certificates")
                for cert in certs_expired: self.print_certificate(cert)

            if len(certs_with_weak_keys) > 0:
                self.error("[red]X.509 certificates with weak keys")
                for cert in certs_with_weak_keys: self.print_certificate(cert)
            self.print_grid()


        def check_system(self):
            # The checks are done based on the information given on
            # https://documentation.suse.com/sles/15-SP2/pdf/book-security_color_en.pdf
            self.title("Scanning system hardening")

            result = subprocess.run(['uname', '-a'], stdout=subprocess.PIPE)
            self.info("%s" % result.stdout.decode("ascii").rstrip())

            if os.path.exists("/dev/kmem"): self.error("/dev/kmem is available (allows direct kernel memory writing)")
            if os.path.exists("/proc/kcore"): self.error("/proc/kcore is available (exposes kernel text image layout)")

            result = subprocess.run(['cat', '/proc/sys/kernel/random/entropy_avail'], stdout=subprocess.PIPE)
            self.info("Available entropy in the primary entropy pool: %s" % result.stdout.decode("ascii").rstrip())

            self.error_if_int_val_not_equal("/proc/sys/kernel/randomize_va_space", 2)
            self.error_if_int_val_not_equal("/proc/sys/kernel/kptr_restrict", 1)
            self.error_if_int_val_not_equal("/proc/sys/fs/protected_hardlinks", 1)
            self.error_if_int_val_not_equal("/proc/sys/fs/protected_symlinks", 1)

            # Network management
            # IPv4 ICMP redirect acceptance is disabled
            self.error_if_int_val_not_equal("/proc/sys/net/ipv4/conf/default/accept_redirects", 0)
            self.error_if_int_val_not_equal("/proc/sys/net/ipv4/conf/all/accept_redirects", 0)
            # IPv6 ICMP redirect acceptance is disabled
            self.error_if_int_val_not_equal("/proc/sys/net/ipv6/conf/default/accept_redirects", 0)
            self.error_if_int_val_not_equal("/proc/sys/net/ipv6/conf/all/accept_redirects", 0)
            # Don't send IPv4 ICMP redirects (unless a router)
            self.error_if_int_val_not_equal("/proc/sys/net/ipv4/conf/all/send_redirects", 0)
            # IP spoofing protection is enabled
            self.error_if_int_val_not_equal("/proc/sys/net/ipv4/conf/all/rp_filter", 1)
            # Disables the acceptance of packets with the SSR option set in the IPv4 packet header
            self.error_if_int_val_not_equal("/proc/sys/net/ipv4/conf/default/accept_source_route", 0)
            self.error_if_int_val_not_equal("/proc/sys/net/ipv4/conf/all/accept_source_route", 0)
            # Disable IP forwarding
            self.error_if_int_val_not_equal("/proc/sys/net/ipv4/ip_forward", 0)
            self.error_if_int_val_not_equal("/proc/sys/net/ipv6/conf/default/forwarding", 0)
            self.error_if_int_val_not_equal("/proc/sys/net/ipv6/conf/all/forwarding", 0)
            # Enable TCP synccookies
            self.error_if_int_val_not_equal("/proc/sys/net/ipv4/tcp_syncookies", 1)
            # Ignore ICMP echo (ping) requests
            self.error_if_int_val_not_equal("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", 1)

            # User management
            result = subprocess. Popen(['grep', "-v", ':x:', "/etc/passwd"], stdout=subprocess.PIPE)
            if result.communicate()[0].decode("ascii").rstrip() != "":
                self.error("User accounts without password: %s" %  result.communicate()[0].decode("ascii").rstrip())

            # ssh hardening
            ssh_config = "/etc/ssh/sshd_config"
            rootlogin = re.compile("^PermitRootLogin\s+yes")
            default_port = re.compile("^Port\s+22$")
            pwd_auth = re.compile("^PasswordAuthentication\s+yes$")
            if  os.path.exists(ssh_config):
                with open(ssh_config, 'r') as fhandle:
                    for line in fhandle.readlines():
                        line = line.rstrip()
                        if rootlogin.match(line):  self.warning("SSH root login enabled")
                        if default_port.match(line):  self.warning("SSH default port is 22")
                        if pwd_auth.match(line):  self.warning("SSH password based authentication enabled")

            self.print_grid()


def main():

    # Handle commandline arguments
    parser = argparse.ArgumentParser(description='')
    parser.add_argument("--arch",   dest='arch',   required=True, help="Architecture, x86, arm64 or arm")
    parser.add_argument("--config", dest='config', required=True, help="Kernel config file")
    parser.add_argument("--policy", dest='policy', required=True, help="Policy file")
    parser.add_argument("--kernel", dest='kernel', help="Run kernel checks", action='store_true')
    parser.add_argument("--dmesg",  dest='dmesg',  help="Run dmesg checks", action='store_true')
    parser.add_argument("--proc",   dest='proc',   help="Run process checks", action='store_true')
    parser.add_argument("--exec",   dest='exec',   help="Run excecutable checks", action='store_true')
    parser.add_argument("--vuln",   dest='vuln',   help="Run vulnerability checks", action='store_true')
    parser.add_argument("--cert",   dest='cert',   help="Run X.509 certificate checks", action='store_true')
    parser.add_argument("--sys",    dest='sys',    help="Run system checks", action='store_true')
    args = parser.parse_args()

    # Check if input file exists
    exists(args.config)
    exists(args.policy)
    # Validate architecture
    if args.arch != "x86" and args.arch != "arm64" and args.arch != "arm":
        print("ERROR: invalid architecrure. Select x86, arm64 or arm")
        sys.exit()

    sec = SecurityChecker(args.arch, args.config, args.policy)

    if args.kernel: sec.check_kernel()
    if args.dmesg:  sec.check_dmesg()
    if args.proc:   sec.check_processes()
    if args.exec:   sec.check_executables()
    if args.vuln:   sec.check_vulnerabilities()
    if args.cert:   sec.check_certificates()
    if args.sys:    sec.check_system()


if __name__ == "__main__":
    main()
