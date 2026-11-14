"""Check that the return path never duplicates native/LAN or unrelated traffic."""
import socket
import struct
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'native'))
from receive import ReturnPolicy

def packet(source,destination='192.0.2.10'):
    return struct.pack('!BBHHHBBH4s4s',0x45,0,24,1,0,64,17,0,socket.inet_aton(source),socket.inet_aton(destination))+b'data'

routes=b'default via 192.0.2.1 dev wlan0\n192.0.2.0/24 dev wlan0\n192.0.2.1 dev wlan0\n172.16.0.0/12 dev eth0\n'
policy=ReturnPolicy('192.0.2.10',set(),True,routes)
valid=packet('198.51.100.20')
assert policy.packet(valid,0)==valid
for source in ['192.0.2.30','192.0.2.1','172.18.0.3','127.0.0.1','0.0.0.0','224.0.0.1','255.255.255.255','192.0.2.10']:
    assert policy.packet(packet(source),0) is None,source
assert policy.packet(valid,4) is None,'Outgoing capture must never be reinjected'
assert policy.packet(packet('198.51.100.20','192.0.2.20'),0) is None
assert policy.packet(valid[:22],0) is None
assert policy.packet(valid+b'padding',0)==valid
specific=ReturnPolicy('192.0.2.10',{'198.51.100.20'},False,routes)
assert specific.packet(valid,0)==valid
assert specific.packet(packet('203.0.113.20'),0) is None
print('PASS: exact target/local-destination checks, native routes and SSH exclusion, reserved sources, direction and IP bounds')
