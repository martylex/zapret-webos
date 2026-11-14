"""Return packets through TUN on kernels enforcing strict reverse-path checks.

No sysctl or firewall writes. Only local unicast replies whose reverse route
was captured by this engine are eligible; LAN/native-route traffic stays on
its original path. The nonpersistent TUN owns the whole runtime lifetime.
"""
import os
import socket
import struct


def reverse_path_mode(interface):
    values=[]
    for name in ['all',interface]:
        try:
            with open('/proc/sys/net/ipv4/conf/'+name+'/rp_filter') as source: values.append(int(source.read()))
        except IOError: values.append(0)
    return max(values)


def prefix(value):
    parts=value.split('/')
    bits=int(parts[1]) if len(parts)==2 else 32
    if not 0<=bits<=32: raise ValueError('Invalid IPv4 prefix')
    mask=(0xffffffff<<(32-bits))&0xffffffff if bits else 0
    return struct.unpack('!I',socket.inet_aton(parts[0]))[0]&mask,mask,bits


class ReturnPolicy(object):
    def __init__(self,source,targets,global_capture,original_routes):
        self.local=socket.inet_aton(source)
        self.targets=set(socket.inet_aton(value) for value in targets)
        self.global_capture=global_capture
        self.native=[]
        if isinstance(original_routes,bytes): original_routes=original_routes.decode('ascii')
        for line in original_routes.splitlines():
            tokens=line.split()
            if not tokens: continue
            value=tokens[1] if tokens[0] in ('unreachable','blackhole','prohibit','throw') and len(tokens)>1 else tokens[0]
            if value=='default' or ':' in value: continue
            try: network,mask,bits=prefix(value)
            except (ValueError,socket.error): continue
            if bits>1: self.native.append((network,mask))
        self.reserved=[prefix(value)[:2] for value in ['0.0.0.0/8','127.0.0.0/8','224.0.0.0/4','240.0.0.0/4']]

    def packet(self,data,packet_type):
        if packet_type!=0 or len(data)<20 or bytearray(data[:1])[0]>>4!=4 or data[16:20]!=self.local: return None
        length=struct.unpack('!H',data[2:4])[0]
        ihl=(bytearray(data[:1])[0]&15)*4
        if ihl<20 or length<ihl or length>len(data): return None
        source=data[12:16]
        if source==self.local: return None
        value=struct.unpack('!I',source)[0]
        if any(value&mask==network for network,mask in self.reserved): return None
        if self.global_capture:
            if any(value&mask==network for network,mask in self.native): return None
        elif source not in self.targets: return None
        return data[:length]


class ReturnBridge(object):
    def __init__(self,interface,fd,policy):
        self.fd=fd; self.policy=policy
        self.socket=socket.socket(17,socket.SOCK_DGRAM,socket.htons(0x0800))
        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,512*1024)
        self.socket.bind((interface,0))

    def receive(self):
        data,address=self.socket.recvfrom(65535)
        packet=self.policy.packet(data,address[2])
        if packet is None: return False
        if os.write(self.fd,packet)!=len(packet): raise RuntimeError('Short TUN return-packet write')
        return True

    def close(self): self.socket.close()
