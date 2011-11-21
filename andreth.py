#!/usr/bin/env python
# coding=utf-8

#
# Copyright (c) dtk <dtk@gmx.de>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#


import sys
import os
import re
import signal
import argparse
import subprocess


# hardcoded values
dns_resolver = '/etc/resolv.conf'

# shell commands
## IP forwarding
get_ip_forward_cmd = ['cat', '/proc/sys/net/ipv4/ip_forward']
set_ip_forward_template = ['sysctl', 'net.ipv4.ip_forward={value}']
## iptables
iptables_masquerade_template = ['iptables',
                                '-I', 'POSTROUTING',
                                '-t', 'nat',
                                '-s', 
                                '-j', 'MASQUERADE',
                                '-o'
                               ]
iptables_revert_template = ['iptables',
                            '-D', 'POSTROUTING',
                            '-t', 'nat',
                            '-s',
                            '-j', 'MASQUERADE',
                            '-o'
                           ]
## PPP tunnel
establish_tunnel_template = ['adb',
                             'ppp',
                             'shell:pppd nodetach noauth noipdefault defaultroute /dev/tty',
                             'nodetach',
                             'noauth',
                             'noipdefault',
                             'notty',
                             '{local}:{remote}'
                            ]
close_tunnel_cmd = ['ifconfig', 'ppp0', 'down']
## DNS on device
set_dns_template = ['adb', 'shell', 'setprop', 'net.dns{num}']


def enable_ip_forwarding():
    ipforwarding_was_enabled = int(subprocess.check_output(get_ip_forward_cmd))

    if not ipforwarding_was_enabled:
        print "enabling IPv4 forwarding"
        set_ip_forwarding(1)

    return ipforwarding_was_enabled


def set_ip_forwarding(value):
    assert value in range(2)
    set_ip_forward_cmd = list(set_ip_forward_template)
    set_ip_forward_cmd[1] = set_ip_forward_cmd[1].format(value=value)
    subprocess.check_call(set_ip_forward_cmd)


def configure_firewall(device_ip, network_interface):
    print 'configuring firewall'
    masquerade_cmd = list(iptables_masquerade_template)
    masquerade_cmd.insert(6, device_ip)
    masquerade_cmd.insert(10, network_interface)
    subprocess.check_call(masquerade_cmd)


def establish_tunnel(local_ip, remote_ip):
    print 'setting up PPP tunnel'
    tunnel_cmd = list(establish_tunnel_template)
    tunnel_cmd[7] = tunnel_cmd[7].format(local=local_ip, remote=remote_ip)
    subprocess.check_call(tunnel_cmd)


def configure_android_device():
    print 'setting the DNS servers'
    dns_num = 1
    for dns_server in get_dns_servers():
        print ' * {}'.format(dns_server)
        dns_cmd = list(set_dns_template)
        dns_cmd[3] = dns_cmd[3].format(num=dns_num)
        dns_cmd.append(dns_server)
        subprocess.check_call(dns_cmd)
        dns_num += 1


def get_dns_servers():
    dns_file = open(dns_resolver, 'r')

    for entry in dns_file.readlines():
        nameserver = re.match(r'nameserver (\d+\.\d+\.\d+\.\d+)', entry)
        if nameserver:
            yield nameserver.group(1)

    dns_file.close()


def clean_up(signal_number, stack_frame):
    """
    Clean up before terminating the script.
    Called by a signal interrupt.
    """
    print '\n'
    print 'closing tunnel'
    subprocess.check_call(close_tunnel_cmd)

    if not ipforwarding_was_enabled:
        print "disabling IPv4 forwarding"
        set_ip_forwarding(0)

    print 'reverting firewall rules'
    iptables_revert_cmd = list(iptables_revert_template)
    iptables_revert_cmd.insert(6, args.remote_ip)
    iptables_revert_cmd.insert(10, args.interface)
    subprocess.check_call(iptables_revert_cmd)


#
# main
#
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Reverse tethering over USB '\
                                                 'for your Android device')

    parser.add_argument('-l', '--local-ip',
                        default='192.168.55.51', metavar='IP',
                        help='the IP on the host side of the PPP tunnel '\
                             '[default: %(default)s]')

    parser.add_argument('-r', '--remote-ip',
                        default='192.168.55.52', metavar='IP',
                        help='the IP on the device side of the PPP tunnel '\
                             '[default: %(default)s]')

    parser.add_argument('-i', '--interface',
                        default='eth0', metavar='IFACE',
                        help='the interface that provides the internet connection '\
                             '[default: %(default)s]')

    args = parser.parse_args() 


    # preliminary checks
    ## we are root
    if os.geteuid() != 0:
        print 'Sorry, you have to be root to run this script.'
        sys.exit(1)

    # handle signals
    signal.signal(signal.SIGINT, clean_up)

    # IP forwarding
    ipforwarding_was_enabled = enable_ip_forwarding()

    # firewall rules
    configure_firewall(args.remote_ip, args.interface)

    # establish PPP tunnel
    establish_tunnel(args.local_ip, args.remote_ip)

    # configure device
    configure_android_device()

    print 'Your device can now access the internet via the established tunnel.\n' \
          'Press <Ctrl+c> to terminate the connection.'

    # wait for interrupt
    signal.pause()
