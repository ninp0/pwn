#!/usr/bin/python3 -I
"""Local network capability broker. Install root-owned; never setcap Python."""
import argparse
import base64
import ctypes
import ipaddress
import json
import os
import pathlib
import socket
import stat
import struct
import subprocess
import time


class Broker:
    def __init__(self, uid, interfaces):
        self.uid = uid
        self.interfaces = interfaces

    def dispatch(self, request, peer_uid):
        try:
            if peer_uid != self.uid:
                raise ValueError('peer UID denied')
            if not isinstance(request, dict):
                raise ValueError('object required')
            operation = request.get('operation')
            if operation not in ('status', 'raw_send', 'capture', 'arp', 'nd'):
                raise ValueError('operation denied')
            if operation == 'status':
                caps = int(next(x.split()[1] for x in pathlib.Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')), 16)
                missing = [name for bit, name in ((13, 'CAP_NET_RAW'), (12, 'CAP_NET_ADMIN')) if not caps & (1 << bit)]
                return {'ok': True, 'backend': 'pwn-capd', 'missing': missing, 'interfaces': self.interfaces}
            iface = request.get('iface')
            if iface not in self.interfaces:
                raise ValueError('interface denied')
            if operation == 'raw_send':
                frame = base64.b64decode(request['frame'], validate=True)
                if not 14 <= len(frame) <= 65535:
                    raise ValueError('frame size must be 14..65535')
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as raw:
                    raw.bind((iface, 0))
                    sent = raw.send(frame)
                return {'ok': True, 'backend': 'pwn-capd', 'bytes': sent}
            if operation in ('arp', 'nd'):
                address = ipaddress.ip_address(request['address'])
                if address.version != (4 if operation == 'arp' else 6):
                    raise ValueError('address family mismatch')
                # Read the kernel neighbour cache, not a general netlink/command proxy.
                result = subprocess.run(['/usr/sbin/ip', '-j', '-4' if operation == 'arp' else '-6', 'neigh', 'show', 'to', str(address), 'dev', iface], capture_output=True, timeout=5, env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C'}, check=True)
                return {'ok': True, 'backend': 'pwn-capd', 'neighbors': json.loads(result.stdout)}
            count = int(request.get('count', 8))
            seconds = float(request.get('timeout', 5))
            if not 1 <= count <= 128 or not 0 < seconds <= 30:
                raise ValueError('capture budget out of range')
            # Build pcap in memory; no client-controlled privileged file write.
            data = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 4096, 1))
            captured = 0
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as raw:
                raw.bind((iface, 0))
                deadline = time.monotonic() + seconds
                while captured < count and time.monotonic() < deadline:
                    raw.settimeout(max(.001, deadline - time.monotonic()))
                    try:
                        frame = raw.recv(4096)
                    except socket.timeout:
                        break
                    now = time.time()
                    data.extend(struct.pack('<IIII', int(now), int((now % 1) * 1000000), len(frame), len(frame)))
                    data.extend(frame)
                    captured += 1
            return {'ok': True, 'backend': 'pwn-capd', 'count': captured, 'pcap': base64.b64encode(data).decode()}
        except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
            return {'ok': False, 'degraded': True, 'error': str(error)}

    def serve_client(self, client):
        client.settimeout(35)
        _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        with client.makefile('rwb') as stream:
            line = stream.readline(100001)
            try:
                if len(line) > 100000 or not line.endswith(b'\n'):
                    raise ValueError('request too large or incomplete')
                response = self.dispatch(json.loads(line), uid)
            except (ValueError, TypeError) as error:
                response = {'ok': False, 'error': str(error)}
            stream.write(json.dumps(response).encode() + b'\n')
            stream.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--interface', action='append', required=True)
    parser.add_argument('--socket', default='/run/pwn-capd/control.sock')
    args = parser.parse_args()
    # Keep only the network capabilities already possessed. Never acquire any.
    # NO_NEW_PRIVS prevents child exec (ip) from recovering root/setid caps.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        parser.error('cannot set no_new_privs')
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
    header = Header(0x20080522, 0)
    caps = (Data * 2)()
    if libc.capget(ctypes.byref(header), caps) != 0:
        parser.error('cannot read capabilities')
    mask = (1 << 12) | (1 << 13)
    caps[0].effective &= mask
    caps[0].permitted &= mask
    caps[0].inheritable = 0
    caps[1] = Data(0, 0, 0)
    parent = pathlib.Path(args.socket).parent
    parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    info = parent.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        parser.error('socket directory must be owned by daemon and not group/world writable')
    broker = Broker(args.uid, args.interface)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        old_umask = os.umask(0o177)
        try:
            server.bind(args.socket)  # Refuse existing paths, including symlinks.
        finally:
            os.umask(old_umask)
        os.chown(args.socket, args.uid, -1)
        if libc.capset(ctypes.byref(header), caps) != 0:
            parser.error('cannot drop excess capabilities')
        server.listen(8)
        try:
            while True:
                client, _ = server.accept()
                with client:
                    try:
                        broker.serve_client(client)
                    except (OSError, ValueError):
                        pass
        finally:
            os.unlink(args.socket)


if __name__ == '__main__':
    main()
