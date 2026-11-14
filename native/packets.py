"""Original Linux packet transformations referencing the supplied Flowseal ALT3.

No upstream engine is bundled. Python 2.7/3 standard library only.
"""
from __future__ import print_function
import os
import re
import socket
import struct


def checksum(data):
    if len(data) & 1: data += b'\x00'
    value = sum(struct.unpack('!%dH' % (len(data)//2),data))
    while value >> 16: value = (value & 65535)+(value >> 16)
    return (~value) & 65535


class Packet(object):
    def __init__(self,data):
        self.data = data
        b = bytearray(data)
        if len(b)<20 or b[0]>>4 != 4: raise ValueError('not IPv4')
        self.ihl = (b[0]&15)*4
        length = struct.unpack('!H',data[2:4])[0]
        if self.ihl<20 or len(b)<length or length<self.ihl: raise ValueError('truncated IPv4')
        self.data = data[:length]
        self.protocol = b[9]
        self.fragment = bool(struct.unpack('!H',data[6:8])[0]&0x3fff)
        self.src = socket.inet_ntoa(data[12:16])
        self.dst = socket.inet_ntoa(data[16:20])
        self.sport = self.dport = self.seq = self.flags = 0
        self.thl = 0
        self.payload = b''
        if not self.fragment and self.protocol in (6,17):
            minimum = 20 if self.protocol==6 else 8
            if length<self.ihl+minimum: raise ValueError('short transport')
            self.sport,self.dport = struct.unpack('!HH',data[self.ihl:self.ihl+4])
            self.thl = (b[self.ihl+12]>>4)*4 if self.protocol==6 else 8
            if self.thl<minimum or self.ihl+self.thl>length: raise ValueError('invalid transport header')
            self.payload = self.data[self.ihl+self.thl:]
            if self.protocol==6:
                self.seq = struct.unpack('!I',data[self.ihl+4:self.ihl+8])[0]
                self.flags = b[self.ihl+13]
        self.key = (self.src,self.dst,self.sport,self.dport,self.protocol)

    def timestamp_offset(self):
        if self.protocol!=6: return None
        p = self.ihl+20
        end = self.ihl+self.thl
        b = bytearray(self.data)
        while p<end:
            kind = b[p]
            if kind==0: break
            if kind==1: p+=1; continue
            if p+2>end or b[p+1]<2 or p+b[p+1]>end: break
            if kind==8 and b[p+1]==10: return p-self.ihl+2
            p+=b[p+1]
        return None

    def rebuild(self,payload,seq=None,ts_delta=0,zero_id=False,first=False,ack_delta=0,extra_options=b'',ip_id=None):
        ip = bytearray(self.data[:self.ihl])
        transport = bytearray(self.data[self.ihl:self.ihl+self.thl])
        if self.protocol==6:
            if seq is not None: transport[4:8] = struct.pack('!I',seq & 0xffffffff)
            if ack_delta:
                ack=struct.unpack('!I',bytes(transport[8:12]))[0]
                transport[8:12]=struct.pack('!I',(ack+ack_delta)&0xffffffff)
            if first: transport[13] &= ~9  # FIN and PSH belong to the final real part.
            offset = self.timestamp_offset()
            if ts_delta and offset is not None:
                val = struct.unpack('!I',bytes(transport[offset:offset+4]))[0]
                transport[offset:offset+4] = struct.pack('!I',(val+ts_delta)&0xffffffff)
            if extra_options:
                transport.extend(extra_options)
                while len(transport)%4: transport.extend(b'\x01')
                if len(transport)>60: raise ValueError('TCP options exceed header limit')
                transport[12]=(len(transport)//4)<<4 | (transport[12]&15)
            checkoffset = 16
        elif self.protocol==17:
            transport[4:6] = struct.pack('!H',len(transport)+len(payload))
            checkoffset = 6
        else: raise ValueError('unsupported rebuild')
        transport[checkoffset:checkoffset+2] = b'\0\0'
        body = bytes(transport)+payload
        pseudo = self.data[12:20]+struct.pack('!BBH',0,self.protocol,len(body))
        value = checksum(pseudo+body)
        transport[checkoffset:checkoffset+2] = struct.pack('!H',value or (65535 if self.protocol==17 else 0))
        ip[2:4] = struct.pack('!H',len(ip)+len(transport)+len(payload))
        if zero_id: ip[4:6] = b'\0\0'
        elif ip_id is not None: ip[4:6] = struct.pack('!H',ip_id&65535)
        ip[10:12] = b'\0\0'
        ip[10:12] = struct.pack('!H',checksum(bytes(ip)))
        return bytes(ip)+bytes(transport)+payload


def hello_info(data,record=True):
    """Return host/session for a complete ClientHello, or None for partial/unknown."""
    b = bytearray(data)
    try:
        offset = 5 if record else 0
        if record and (len(b)<5 or b[0]!=22): return None
        if len(b)<offset+38 or b[offset]!=1: return None
        size = (b[offset+1]<<16)+(b[offset+2]<<8)+b[offset+3]
        if size>32768 or len(b)<offset+4+size: return None
        sidpos=offset+38
        sidlen=b[sidpos]
        sid=data[sidpos+1:sidpos+1+sidlen]
        p=sidpos+1+sidlen
        n=struct.unpack('!H',data[p:p+2])[0]; p+=n+2
        n=b[p]; p+=n+1
        n=struct.unpack('!H',data[p:p+2])[0]; p+=2
        end=min(p+n,offset+4+size)
        while p+4<=end:
            kind,n=struct.unpack('!HH',data[p:p+4]); p+=4
            if p+n>end: return None
            if kind==0:
                q=p+2
                while q+3<=p+n:
                    t,length=struct.unpack('!BH',data[q:q+3]); q+=3
                    if q+length>p+n: return None
                    if t==0: return {'host':data[q:q+length].decode('ascii').lower(),'sid':sid,
                                    'host_offset':q,'host_length':length,'sniext_offset':p}
                    q+=length
            p+=n
    except (ValueError,IndexError,struct.error,UnicodeError): return None
    return None


def http_host(data):
    if not re.match(br'^(GET|POST|HEAD|PUT|OPTIONS|DELETE|PATCH|CONNECT) ',data): return None
    match=re.search(br'\r\nHost:\s*([^\r\n: ]+)',data,re.I)
    return match.group(1).decode('ascii','ignore').lower() if match else None


def domains(path):
    if not os.path.isfile(path): return []
    with open(path,'rb') as f:
        return [x.strip().decode('ascii').lower() for x in f if x.strip() and not x.lstrip().startswith((b'#',b';'))]


def domain_match(host,entries):
    for entry in entries:
        if entry.startswith('^'):
            if host==entry[1:]: return True
        elif host==entry or host.endswith('.'+entry): return True
    return False


def fake_tls(seed,sid):
    b=bytearray(seed)
    b[11:43]=os.urandom(32)
    old=b[43]
    b[43:44+old]=bytes(bytearray([len(sid)]))+sid
    size=len(b)
    b[3:5]=struct.pack('!H',size-5)
    b[6:9]=struct.pack('!I',size-9)[1:]
    return bytes(b)


class Alt3(object):
    def __init__(self,root):
        self.general=domains(root+'/lists/list-general.txt')+domains(root+'/lists/list-general-user.txt')
        self.google=domains(root+'/lists/list-google.txt')
        self.exclude=domains(root+'/lists/list-exclude.txt')+domains(root+'/lists/list-exclude-user.txt')
        self.seed=open(root+'/bin/tls_clienthello_www_google_com.bin','rb').read()
        self.httpfake=open(root+'/bin/tls_clienthello_www_sferum_ru.bin','rb').read()
        self.quicfake=open(root+'/bin/quic_initial_www_google_com.bin','rb').read()
        self.discordfake=open(root+'/bin/ACTIVE_DISCORD_UDP.bin','rb').read()
        self.ip_exclude=networks(root+'/lists/ipset-exclude.txt')+networks(root+'/lists/ipset-exclude-user.txt')
        self.ip_include=networks(root+'/lists/ipset-all.txt')
        self.ip_any=not domains(root+'/lists/ipset-all.txt')

    def tcp_profile(self,packet,host):
        if packet.dport in (2053,2083,2087,2096,8443) and domain_match(host,['discord.media']): return 'discord-media'
        if packet.dport==443 and domain_match(host,self.google): return 'google'
        if ip_match(packet.dst,self.ip_exclude): return None
        if packet.dport in (80,443) and domain_match(host,self.general) and not domain_match(host,self.exclude): return 'general'
        if packet.dport in (80,443,8443) and (self.ip_any or ip_match(packet.dst,self.ip_include)) and not domain_match(host,self.exclude): return 'ipset'
        return None

    def transform_tcp(self,packet,hello,profile,variant='alt3'):
        zero=profile=='google'
        payload=packet.payload
        generated=[]
        # Fake packets require negotiated timestamps; otherwise send only the safe split.
        if packet.timestamp_offset() is not None or variant=='alt2':
            fake=fake_tls(self.seed,hello['sid']) if hello is not None else self.httpfake
            item=packet.rebuild(fake,ts_delta=-600000 if variant=='alt3' else 0,
                seq=packet.seq+10000000 if variant=='alt2' else None,
                ack_delta=-66000 if variant=='alt2' else 0,zero_id=zero)
            generated.extend([item]*8)
        # The overlap is entirely before the receive window; only one original byte is in-window.
        if len(payload)>1:
            generated.append(packet.rebuild(self.seed+payload[:1],seq=packet.seq-len(self.seed),zero_id=zero,first=True))
            generated.append(packet.rebuild(payload[1:],seq=packet.seq+1,zero_id=zero))
        else:
            generated.append(packet.rebuild(payload,zero_id=zero))
        return generated

    def udp_profile(self,packet,host=None):
        if packet.dport==443:
            if ip_match(packet.dst,self.ip_exclude) or (host and domain_match(host,self.exclude)): return None
            if host and domain_match(host,self.general): return ('quic-hostlist',self.quicfake,11)
            if self.ip_any or ip_match(packet.dst,self.ip_include): return ('quic-ipset',self.quicfake,11)
        if 19294<=packet.dport<=19344 or 50000<=packet.dport<=50100:
            b=bytearray(packet.payload)
            stun=len(b)>=20 and b[0]&0xc0==0 and packet.payload[4:8]==b'\x21\x12\xa4\x42'
            discord=(len(b)==74 and packet.payload[:4]==b'\x00\x01\x00\x46') or (len(b)==70)
            if stun or discord: return ('stun' if stun else 'discord',self.discordfake,6)
        return None


def networks(path):
    result=[]
    for item in domains(path):
        if ':' in item: continue  # IPv6 is deliberately outside this IPv4 transport.
        parts=item.split('/')
        bits=int(parts[1]) if len(parts)==2 else 32
        if bits<0 or bits>32: raise ValueError('invalid IPv4 prefix')
        value=struct.unpack('!I',socket.inet_aton(parts[0]))[0]
        mask=(0xffffffff<<(32-bits))&0xffffffff if bits else 0
        result.append((value&mask,mask))
    return result


def ip_match(ip,entries):
    value=struct.unpack('!I',socket.inet_aton(ip))[0]
    return any((value&mask)==network for network,mask in entries)
