#!/usr/bin/env python3
from urllib.parse import urlparse
from socket import getaddrinfo, AF_INET, SOL_TCP
from functools import lru_cache
import argparse
import sys


def _bencode_read_string(f):
    """Read a Bencoded byte string from current position of f."""
    length = 0
    s = f.read(1)
    while s != b':':
        if not s.isdigit():
            raise ValueError('Length of string expected but %s found.' % s)
        length = length * 10 + int(s.decode())
        s = f.read(1)
    if length == 0:
        raise ValueError("Length of string expected but ':' found.")
    return f.read(length).decode()


def parse_torrent(f):
    """Parse a torrent file, return a list of all trackers on it."""
    trackers = []
    if f.read(1) != b'd':
        raise ValueError('Torrent not start with a dictionary.')
        
    key = _bencode_read_string(f)
    if key == 'announce':
        trackers.append(_bencode_read_string(f))
        key = _bencode_read_string(f)
     
    if key == 'announce-list':
        if f.read(1) != b'l':
            raise ValueError('"announce-list" not contain a list.')
        
        while f.read(1) == b'l':
            trackers.append(_bencode_read_string(f))
            if f.read(1) != b'e':
                raise ValueError('Item of "announce-list" contain '
                                 'multiple value.')
    return trackers


def _tracker_conn_info(url):
    """Given a URL of trackers, return a list of 
    tuples [IP address, protocol (tcp or udp), port].
    """
    url = urlparse(url)
    addrs = nslookup(url.hostname)
    proto = url.scheme
    if proto == 'http':
        proto = 'tcp'
    elif proto != 'udp':
        raise ValueError('Unknown tracker protocol: %s' % proto)
    port = url.port
    if url.port is None:
        port = 6881

    return [(addr, proto, port) for addr in addrs]


@lru_cache()
def nslookup(domain):
    """Look up DNS for the domain name, return a list of IPv4 addresses."""
    infos = getaddrinfo(domain, 1, AF_INET, proto=SOL_TCP)
    return [info[4][0] for info in infos]


def generate_rules(f, func_print):
    """Read tracker URLs from f, print firewall rules 
    via func_print(addr, proto, port).
    """
    trackers = set()
    for url in f:
        url = url.strip()
        if url[0] in '#;"':
            continue
        try:
            new_trackers = set(_tracker_conn_info(url)) - trackers
        except (ValueError, OSError) as e:
            print('Failed to resolve ', url, ':', e, file=sys.stderr)
            continue

        for tracker in new_trackers:
            func_print(*tracker)
            
        trackers |= new_trackers


def action_torrent(args):
    trackers = set()
    for f in args.files:
        try:
            new_trackers = set(parse_torrent(f)) - trackers
            f.close()
            for tracker in new_trackers:
                print(tracker)
            trackers |= new_trackers
        except (ValueError, UnicodeDecodeError, IOError) as e:
            print('Failed to parse file', f.name, ':', e, file=sys.stderr)


def action_ipset(args):
    print('create -exist %s hash:ip,port family inet' % args.setname)
    def print_command(addr, proto, port):
        print('add -exist %s %s,%s:%s' % (args.setname, addr, proto, port))
    generate_rules(args.trackers, print_command)


def action_iptables(args):
    table = ''
    if args.table is not None:
        table = ' -t %s' % args.table
    def print_command(addr, proto, port):
        print('iptables%s -A %s -d %s -p %s --dport %s -j %s' % \
              (table, args.chain, addr, proto, port, args.target))
    generate_rules(args.trackers, print_command)


def action_raw(args):
    generate_rules(args.trackers, print)


def parse_args():
    parser = argparse.ArgumentParser(description='BitTorrent Trackers '
                                                 'firewall helper.')
    subparsers = parser.add_subparsers(dest='action')
    
    tor = subparsers.add_parser('torrent',
                                help='parse tracker URLs from torrent files.')
    tor.add_argument('files', nargs='+', metavar='FILE',
                     type=argparse.FileType('rb'),
                     help='a torrent file.')
                     
    TRACKERS_KWARGS = dict(metavar='TRACKER-LIST',
                           type=argparse.FileType('r'),
                           help='a file contains tracert URLs line by line, '
                                'or "-" for stdin.')

    ips = subparsers.add_parser('ipset', help='generate ipset restore file.')
    ips.add_argument('setname', metavar='SETNAME',
                     help='the setname of ipset.')
    ips.add_argument('trackers', **TRACKERS_KWARGS)

    ipt = subparsers.add_parser('iptables', help='generate iptables commands.')
    ipt.add_argument('-t', '--table', metavar='TABLE',
                     help='which iptables tables add rules to.')
    ipt.add_argument('chain', metavar='CHAIN',
                     help='which iptables chain add rules to.')
    ipt.add_argument('target', metavar='TARGET',
                     help='which iptables target rules jump to.')
    ipt.add_argument('trackers', **TRACKERS_KWARGS)

    raw = subparsers.add_parser('raw', help='print plain server connection info.')
    raw.add_argument('trackers', **TRACKERS_KWARGS)

    return parser.parse_args()


def main():
    args = parse_args()

    if args.action == 'torrent':
        action_torrent(args)
    if args.action == 'ipset':
        action_ipset(args)
    if args.action == 'iptables':
        action_iptables(args)
    if args.action == 'raw':
        action_raw(args)


if __name__ == '__main__':
    main()
