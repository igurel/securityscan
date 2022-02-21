#!/usr/bin/python3
###############################################################################
#
# usage: securityscan.py [-h] --arch ARCH --config CONFIG --policy POLICY --output OUTPUT [--kernel] [--dmesg]
#                        [--proc] [--exec] [--vuln] [--cert] [--sys]
#
# optional arguments:
#   -h, --help       show this help message and exit
#   --arch ARCH      Architecture, x86, arm64 or arm
#   --config CONFIG  Kernel config file
#   --policy POLICY  Policy file
#   --output OUTPUT  Outpuf file (JSON format)
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
#                         --policy policy.json \
#                         --output test.json \
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


def exists(file):
    if not os.path.exists(file):
        print("ERROR: %s doesn't exist" % file)
        sys.exit()


class SecurityChecker():

        def __init__(self, arch, config, policy):
            self.arch = arch
            self.config = config
            self.policy = policy
            self.output = {}


        def error(self, msg):
            print("ERROR:   %s" % msg)
            if not 'error' in self.output[self.group]:
                self.output[self.group]['error'] = []
            self.output[self.group]['error'].append(msg)


        def info(self, msg):
            print("INFO:    %s" % msg)
            if not 'info' in self.output[self.group]:
                self.output[self.group]['info'] = []
            self.output[self.group]['info'].append(msg)


        def warning(self, msg):
            print("WARNING: %s" % msg)
            if not 'warning' in self.output[self.group]:
                self.output[self.group]['warning'] = []
            self.output[self.group]['warning'].append(msg)


        def title(self, group, msg):
            if group != None:
                self.group = group
                if not self.group in self.output:
                    self.output[self.group] = {}
            print("\n------------o %s o------------" % msg)


        def error_if_int_val_not_eq(self, file, val):
            if not os.path.exists(file):
                self.error("%s doesn't exist" % file)
                return
            with open(file) as f:
                fval = int(f.read())
                if fval != val:
                    self.error("%s is %d, expected %d" % (file, fval, val))
                else:
                    self.info("%s is %d" % (file, fval))


        def error_if_int_val_lt(self, file, val):
            if not os.path.exists(file):
                self.error("%s doesn't exist" % file)
                return
            with open(file) as f:
                fval = int(f.read())
                if fval < val:
                    self.error("%s is %d, expected > %d" % (file, fval, val))
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

                print("   File: %s" % file)
                print("   Issuer: %s" % cert_issuer.commonName)
                print("   Subject: %s" % cert_subject.commonName)

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

                print("   Key type: %s" % key_type)
                print("   Key size: %s" % cert_parser.get_pubkey().bits())
                print("   Validity: %s - %s\n" % (notbefore_fmt, notafter_fmt))
            except:
                pass


        def check_kernel(self):
            self.title("kernel", "Scanning kernel config options")
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


        def check_dmesg(self):
            self.title("dmesg", "Scanning dmesg messages")
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


        def check_processes(self):
            self.title("process", "Scanning processes")
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
                    print("   %s(%s)" % (psutil.Process(con.pid).name(), con.laddr.port))

            self.warning("Root processes listening ports")
            for con in connections:
                if con.pid in root_pids:
                    if con.status == 'LISTEN':
                        root_proc_port = "%s(%s)" % (psutil.Process(con.pid).name(), con.laddr.port)
                        if not root_proc_port in root_proc_ports:
                            root_proc_ports.append(root_proc_port)

            for root_proc_port in root_proc_ports:
                print("   %s" % root_proc_port)


        def check_executables(self):
            self.title("executables", "Scanning executables")

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
                self.warning("%d non-PIE binaries" % len(nonpie))
                self.output['executables']['nonpie'] = []
                for binary in nonpie:
                    self.output['executables']['nonpie'].append(binary)
                    print("   %s" % binary)

            if len(noncanary) != 0:
                self.output['executables']['noncanary'] = []
                self.warning("%d non-stack canary binaries" % len(noncanary))
                for binary in noncanary:
                    self.output['executables']['noncanary'].append(binary)
                    print("   %s" % binary)

            if len(nonrelro) != 0:
                self.output['executables']['nonrelro'] = []
                self.warning("%d non-relro binaries" % len(nonrelro))
                for binary in nonrelro:
                    self.output['executables']['nonrelro'].append(binary)
                    print("   %s" % binary)

            if len(nonfortify) != 0:
                self.output['executables']['nonfortify'] = []
                self.warning("%d non-fortify binaries" % len(nonfortify))
                for binary in nonfortify:
                    self.output['executables']['nonfortify'].append(binary)
                    print("   %s" % binary)

            if len(execstack) != 0:
                self.output['executables']['execstack'] = []
                self.warning("%d binaries with executable stack" % len(execstack))
                for binary in execstack:
                    self.output['executables']['execstack'].append(binary)
                    print("   %s" % binary)


        def check_vulnerabilities(self):
            self.title("vulnerabilities", "Scanning microarchitectural vulnerabilities")
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


        def check_certificates(self):
            self.title("certificates", "Scanning X.509 certificates")
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
                self.warning("%d X.509 certificates to expire within 1 year" % len(certs_to_expire))
                self.output['certificates']['to_expire'] = []
                for cert in certs_to_expire:
                    self.output['certificates']['to_expire'].append(str(cert))
                    self.print_certificate(cert)

            if len(certs_expired) > 0:
                self.error("%d expired X.509 certificates" % len(certs_expired))
                self.output['certificates']['expired'] = []
                for cert in certs_expired:
                    self.output['certificates']['expired'].append(str(cert))
                    self.print_certificate(cert)

            if len(certs_with_weak_keys) > 0:
                self.error("%d X.509 certificates with weak keys" % len(certs_with_weak_keys))
                self.output['certificates']['with_weak_key'] = []
                for cert in certs_with_weak_keys:
                    self.output['certificates']['with_weak_key'].append(str(cert))
                    self.print_certificate(cert)


        def check_system(self):
            self.title("system", "Scanning system hardening")

            result = subprocess.run(['uname', '-a'], stdout=subprocess.PIPE)
            self.info("%s" % result.stdout.decode("ascii").rstrip())

            if os.path.exists("/dev/kmem"): self.error("/dev/kmem is available (allows direct kernel memory writing)")
            if os.path.exists("/proc/kcore"): self.error("/proc/kcore is available (exposes kernel text image layout)")

            # Make sure that entropy level in the primary entropy pool is greater than 3000
            self.error_if_int_val_lt("/proc/sys/kernel/random/entropy_avail", 3000)
            # Make sure that ASLR is fully enabled
            self.error_if_int_val_not_eq("/proc/sys/kernel/randomize_va_space", 2)
            self.error_if_int_val_not_eq("/proc/sys/kernel/kptr_restrict", 1)
            self.error_if_int_val_not_eq("/proc/sys/kernel/dmesg_restrict", 1)
            self.error_if_int_val_not_eq("/proc/sys/kernel/unprivileged_bpf_disabled", 1)
            self.error_if_int_val_not_eq("/proc/sys/net/core/bpf_jit_harden", 2)
            self.error_if_int_val_not_eq("/proc/sys/fs/protected_hardlinks", 1)
            self.error_if_int_val_not_eq("/proc/sys/fs/protected_symlinks", 1)
            # Disable Magic SysRq key completely
            self.error_if_int_val_not_eq("/proc/sys/kernel/sysrq", 0)

            # Network management
            # IPv4 ICMP redirect acceptance is disabled
            self.error_if_int_val_not_eq("/proc/sys/net/ipv4/conf/default/accept_redirects", 0)
            self.error_if_int_val_not_eq("/proc/sys/net/ipv4/conf/all/accept_redirects", 0)
            # IPv6 ICMP redirect acceptance is disabled
            self.error_if_int_val_not_eq("/proc/sys/net/ipv6/conf/default/accept_redirects", 0)
            self.error_if_int_val_not_eq("/proc/sys/net/ipv6/conf/all/accept_redirects", 0)
            # Don't send IPv4 ICMP redirects (unless a router)
            self.error_if_int_val_not_eq("/proc/sys/net/ipv4/conf/all/send_redirects", 0)
            # IP spoofing protection is enabled
            self.error_if_int_val_not_eq("/proc/sys/net/ipv4/conf/all/rp_filter", 1)
            # Disables the acceptance of packets with the SSR option set in the IPv4 packet header
            self.error_if_int_val_not_eq("/proc/sys/net/ipv4/conf/default/accept_source_route", 0)
            self.error_if_int_val_not_eq("/proc/sys/net/ipv4/conf/all/accept_source_route", 0)
            # Log Martian packets
            self.error_if_int_val_not_eq("/proc/sys/net/ipv4/conf/all/log_martians", 1)
            # Disable IP forwarding
            self.error_if_int_val_not_eq("/proc/sys/net/ipv4/ip_forward", 0)
            self.error_if_int_val_not_eq("/proc/sys/net/ipv6/conf/default/forwarding", 0)
            self.error_if_int_val_not_eq("/proc/sys/net/ipv6/conf/all/forwarding", 0)
            # Enable TCP synccookies
            self.error_if_int_val_not_eq("/proc/sys/net/ipv4/tcp_syncookies", 1)
            # Ignore ICMP echo (ping) requests
            self.error_if_int_val_not_eq("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", 1)

            # User management
            result = subprocess. Popen(['grep', "-v", ':x:', "/etc/passwd"], stdout=subprocess.PIPE)
            value = result.communicate()[0].decode("ascii").rstrip()
            if value != "":
                self.error("User accounts without password: %s" %  value)

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


        def generate_output_file(self, fname):
            self.title(None, "Generating outputfile in JSON format")
            try:
                with open(fname, 'w') as fh:
                    json_data = json.dumps(self.output)
                    fh.write(json_data)
                    print("INFO:    Generated output file \"%s\"" % fname)
            except:
                print("ERROR:   Cannot create output file \"%s\"" % fname)


        def check_selinux(self):
            self.title("system", "Scanning SELinux setup")
            selinux_enabled  = False
            with open(self.config, 'r') as fhandle:
                for line in fhandle.readlines():
                    line = line.rstrip()
                    if not line.startswith("#"):
                        if line == "CONFIG_SECURITY_SELINUX=y":
                            selinux_enabled  = True
                            self.info("CONFIG_SECURITY_SELINUX is enabled")
                        if line == "CONFIG_DEFAULT_SECURITY_SELINUX=y":
                            self.info("CONFIG_DEFAULT_SECURITY_SELINUX is enabled")
                        if line == "CONFIG_DEFAULT_SECURITY_SELINUX=y":
                            self.warning("CONFIG_SECURITY_SELINUX_DEVELOP is enabled")

            if selinux_enabled == False:
                self.warning("SELINUX notenabled is enabled")
                return

            result = subprocess. Popen(['/usr/bin/sestatus'], stdout=subprocess.PIPE)
            info_list = result.communicate()[0].decode("ascii").splitlines()
            for info in info_list:
                self.info(info)


def main():

    # Handle commandline arguments
    parser = argparse.ArgumentParser(description='')
    parser.add_argument("--arch",   dest='arch',   required=True, help="Architecture, x86, arm64 or arm")
    parser.add_argument("--config", dest='config', required=True, help="Kernel config file")
    parser.add_argument("--policy", dest='policy', required=True, help="Policy file")
    parser.add_argument("--output", dest='output', help="Outpuf file (JSON format)")
    parser.add_argument("--kernel", dest='kernel', help="Run kernel checks", action='store_true')
    parser.add_argument("--dmesg",  dest='dmesg',  help="Run dmesg checks", action='store_true')
    parser.add_argument("--proc",   dest='proc',   help="Run process checks", action='store_true')
    parser.add_argument("--exec",   dest='exec',   help="Run excecutable checks", action='store_true')
    parser.add_argument("--vuln",   dest='vuln',   help="Run vulnerability checks", action='store_true')
    parser.add_argument("--cert",   dest='cert',   help="Run X.509 certificate checks", action='store_true')
    parser.add_argument("--sys",    dest='sys',    help="Run system checks", action='store_true')
    parser.add_argument("--selinux",dest='selinux',  help="Run SELinux checks", action='store_true')
    args = parser.parse_args()

    # Check if input file exists
    exists(args.config)
    exists(args.policy)
    # Validate architecture
    if args.arch != "x86" and args.arch != "arm64" and args.arch != "arm":
        print("ERROR: invalid architecture. Select x86, arm64 or arm")
        sys.exit()

    sec = SecurityChecker(args.arch, args.config, args.policy)

    if args.kernel: sec.check_kernel()
    if args.dmesg:  sec.check_dmesg()
    if args.proc:   sec.check_processes()
    if args.exec:   sec.check_executables()
    if args.vuln:   sec.check_vulnerabilities()
    if args.cert:   sec.check_certificates()
    if args.sys:    sec.check_system()
    if args.selinux: sec.check_selinux()

    if args.output: sec.generate_output_file(args.output)

if __name__ == "__main__":
    main()