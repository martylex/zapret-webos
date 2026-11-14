"""Check packet integrity and server-visible data for all supplied strategies."""
import hashlib
import socket
import struct
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'native'))
from packets import Packet, checksum, hello_info
from strategies import Strategy, catalog, tls_mod


def packet(payload, timestamps=True, dport=443):
    opts=b'\x01\x01\x08\x0a'+struct.pack('!II',1000000,1000) if timestamps else b''
    tcp=struct.pack('!HHIIBBHHH',12345,dport,10000,50000,((20+len(opts))//4)<<4,24,65535,0,0)+opts
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp)+len(payload),77,0x4000,64,6,0,
                   socket.inet_aton('192.0.2.10'),socket.inet_aton('1.1.1.1'))
    value=Packet(ip+tcp+payload)
    return Packet(value.rebuild(payload))


def check_output(original, output):
    buffer=bytearray(len(original.payload)); covered=set()
    for raw in output:
        p=Packet(raw)
        assert len(raw)<=1500
        assert checksum(raw[:p.ihl])==0
        assert checksum(raw[12:20]+struct.pack('!BBH',0,6,len(raw)-p.ihl)+raw[p.ihl:])==0
        ts=p.timestamp_offset(); origts=original.timestamp_offset()
        if ts is not None and origts is not None:
            if raw[p.ihl+ts:p.ihl+ts+4]!=original.data[original.ihl+origts:original.ihl+origts+4]: continue
        if raw[p.ihl+8:p.ihl+12]!=original.data[original.ihl+8:original.ihl+12]: continue
        if b'\x13\x12' in raw[p.ihl+20:p.ihl+p.thl]: continue
        start=((p.seq-original.seq+0x80000000)&0xffffffff)-0x80000000
        for n,value in enumerate(p.payload):
            offset=start+n
            if 0<=offset<len(buffer): buffer[offset]=value; covered.add(offset)
    assert len(covered)==len(buffer),'Missing real TCP bytes'
    assert bytes(buffer)==original.payload,'Strategy corrupts server-visible TCP data'


entries=catalog(); assert len(entries)==22 and len(set(x['id'] for x in entries))==22
seed=(ROOT/'source/flowseal-1.10.4/bin/tls_clienthello_www_google_com.bin').read_bytes()
variants=set()
for item in entries:
    strategy=Strategy(str(ROOT/'source/flowseal-1.10.4'),item['id'])
    assert hashlib.sha256((ROOT/'source/flowseal-1.10.4'/item['source']).read_bytes()).hexdigest()==item['source_sha256']
    for host in ['rr1---example.googlevideo.com','discord.com']:
        payload=tls_mod(seed,'sni='+host,hello_info(seed))
        assert hello_info(payload)['host']==host
        for ts in [True,False]:
            original=packet(payload,ts)
            profile=strategy.tcp_profile(original,host)
            assert profile, item['id']+' does not match '+host
            generated,fakes=strategy.transform_tcp(original,hello_info(payload),profile)
            assert generated
            check_output(original,generated)
            if ts: variants.add(tuple((Packet(p).seq-original.seq,len(Packet(p).payload)) for p in generated))
        large=packet(payload+b'X'*3000)
        generated,_=strategy.transform_tcp(large,hello_info(payload),profile)
        check_output(large,generated)
    http=packet(b'GET / HTTP/1.1\r\nHost: discord.com\r\n\r\n',dport=80)
    profile=strategy.tcp_profile(http,'discord.com')
    generated,_=strategy.transform_tcp(http,None,profile)
    check_output(http,generated)
    print('PASS '+str(item['number']).zfill(2)+' '+item['label']+': checksums, real data, no-timestamp path, reassembly, HTTP')
assert len(variants)>=10,'Strategies unexpectedly collapse to the same packet behavior'
print('PASS all 22 strategy sources; %d distinct packet layouts'%len(variants))
