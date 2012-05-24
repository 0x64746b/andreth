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
import atexit
import argparse
import subprocess


# hardcoded values
ip_forwarder = '/proc/sys/net/ipv4/ip_forward'
dns_resolver = '/etc/resolv.conf'

placeholder = '%PLACEHOLDER%'
target_device_flag = '-d'
serial_number_flag = '-s'

# shell commands
## iptables
iptables_masquerade_template = ['iptables',
                                '-I', 'POSTROUTING',
                                '-t', 'nat',
                                '-s', placeholder,
                                '-j', 'MASQUERADE',
                                '-o', placeholder
                               ]
iptables_revert_template = ['iptables',
                            '-D', 'POSTROUTING',
                            '-t', 'nat',
                            '-s', placeholder,
                            '-j', 'MASQUERADE',
                            '-o', placeholder
                           ]
## PPP tunnel
establish_tunnel_template = [placeholder,
                             'ppp',
                             'shell:pppd nodetach noauth noipdefault defaultroute /dev/tty',
                             'nodetach',
                             'noauth',
                             'noipdefault',
                             'notty',
                             '{local}:{remote}'
                            ]
close_tunnel_template = ['pkill', '-f', 'pppd.+{local}:{remote}']
## DNS on device
set_dns_template = [placeholder, 'shell', 'setprop',
                    'net.dns{num}', placeholder]


def _inject_target(command, serial_number):
    if not serial_number:
        command.insert(1, target_device_flag)
    else:
        command.insert(1, serial_number_flag)
        command.insert(2, serial_number)

def enable_ip_forwarding():
    forward_file = open(ip_forwarder, 'r')
    ipforwarding_was_enabled = int(forward_file.readline())
    forward_file.close()

    if not ipforwarding_was_enabled:
        print "enabling IPv4 forwarding"
        set_ip_forwarding(1)

    return ipforwarding_was_enabled


def set_ip_forwarding(value):
    assert value in range(2)
    forward_file = open(ip_forwarder, 'w')
    forward_file.write(str(value))
    forward_file.close()


def configure_firewall(device_ip, network_interface):
    print 'configuring firewall'
    masquerade_cmd = list(iptables_masquerade_template)
    masquerade_cmd[6] = device_ip
    masquerade_cmd[10] = network_interface
    subprocess.check_call(masquerade_cmd)


def revert_firewall(remote_ip, network_interface):
    print 'reverting firewall rules'
    iptables_revert_cmd = list(iptables_revert_template)
    iptables_revert_cmd[6] = remote_ip
    iptables_revert_cmd[10] = network_interface
    try:
        subprocess.check_call(iptables_revert_cmd)
    except subprocess.CalledProcessError:
        print 'ERROR: Could not revert firewall rules'


def establish_tunnel(adb_bin, serial_number, local_ip, remote_ip):
    print 'setting up PPP tunnel'
    tunnel_cmd = list(establish_tunnel_template)
    tunnel_cmd[0] = adb_bin
    tunnel_cmd[7] = tunnel_cmd[7].format(local=local_ip, remote=remote_ip)
    _inject_target(tunnel_cmd, serial_number)
    try:
        subprocess.check_call(tunnel_cmd)
    except (subprocess.CalledProcessError, OSError) as err:
        print 'ERROR: Could not establish tunnel: {}'.format(err)
        sys.exit(1)


def destroy_tunnel(local_ip, remote_ip):
    print 'closing tunnel'
    close_tunnel_cmd = list(close_tunnel_template)
    close_tunnel_cmd[2] = close_tunnel_cmd[2].format(
                                               local=re.escape(local_ip),
                                               remote=re.escape(remote_ip)
                                                    )
    try:
        subprocess.check_call(close_tunnel_cmd)
    except subprocess.CalledProcessError:
        print 'ERROR: Could not destroy tunnel device'


def configure_android_device(adb_bin, serial_number):
    print 'setting the DNS servers'
    dns_num = 1
    for dns_server in get_dns_servers():
        print ' * {}'.format(dns_server)
        dns_cmd = list(set_dns_template)
        dns_cmd[0] = adb_bin
        dns_cmd[3] = dns_cmd[3].format(num=dns_num)
        dns_cmd[4] = dns_server
        _inject_target(dns_cmd, serial_number)
        subprocess.check_call(dns_cmd)
        dns_num += 1


def get_dns_servers():
    dns_file = open(dns_resolver, 'r')

    for entry in dns_file.readlines():
        nameserver = re.match(r'nameserver (\d+\.\d+\.\d+\.\d+)', entry)
        if nameserver:
            yield nameserver.group(1)

    dns_file.close()


def clean_up():
    """
    Clean up before terminating the script.
    Called by a signal interrupt.
    """
    print '\n'
    destroy_tunnel(args.local_ip, args.remote_ip)

    if not ipforwarding_was_enabled:
        print "disabling IPv4 forwarding"
        set_ip_forwarding(0)

    revert_firewall(args.remote_ip, args.interface)


def main(args):
    """
    The main control flow
    """
    # preliminary checks
    ## we are root
    if os.geteuid() != 0:
        print 'Sorry, you have to be root to run this script.'
        sys.exit(1)

    # clean up before leaving
    atexit.register(clean_up)

    # IP forwarding
    global ipforwarding_was_enabled
    ipforwarding_was_enabled = enable_ip_forwarding()

    # firewall rules
    configure_firewall(args.remote_ip, args.interface)

    # establish PPP tunnel
    establish_tunnel(args.adb, args.serial_number,
                     args.local_ip, args.remote_ip)

    # configure device
    configure_android_device(args.adb, args.serial_number)

    print 'Your device can now access the internet via the established tunnel.\n' \
          'Press <Ctrl+d> to terminate the connection.'

    # wait for EOF, cope with SIGINT
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass


#
# Command line parsing
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
                        help='the interface that provides the internet '\
                             'connection [default: %(default)s]')
    parser.add_argument('-a', '--adb',
                        default='adb', metavar='/path/to/adb',
                        help='the path to the adb binary [default: %(default)s]')
    parser.add_argument('-s', '--serial-number',
                        default=None, metavar='SN',
                        help='the serial number of the device you want to '\
                             'connect to if there is more than one real device')

    args = parser.parse_args()

    ipforwarding_was_enabled = 0

    main(args)
