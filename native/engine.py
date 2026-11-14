#!/usr/bin/env python
"""Nonpersistent TUN -> bound raw IPv4 transport, without NFQUEUE.

Experimental native Linux implementation. Nothing changes the default route,
firewall, DNS, sysctls or Homebrew startup configuration.
"""
from __future__ import print_function
import json
import errno
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import time
from packets import Packet, hello_info, http_host
from strategies import Strategy, catalog
from receive import ReturnBridge, ReturnPolicy, reverse_path_mode


def emit(event,**fields):
    fields['event']=event
    print(json.dumps(fields,sort_keys=True)); sys.stdout.flush()


def write_state(path,value):
    if not path: return
    temp=path+'.tmp.'+str(os.getpid())
    with open(temp,'w') as f: json.dump(value,f,sort_keys=True)
    os.rename(temp,path)


def main():
    import fcntl
    # LG ships a reduced Python 2.7 standard library without argparse.
    options={'--root':os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'flowseal'),
             '--targets':'','--seconds':'30','--strategy':'alt3','--status':'','--parent':'0'}
    argv=sys.argv[1:]
    if len(argv)%2: raise SystemExit('Expected --option value pairs')
    for index in range(0,len(argv),2):
        if argv[index] not in options: raise SystemExit('Unknown option '+argv[index])
        options[argv[index]]=argv[index+1]
    if not options['--targets']: raise SystemExit('--targets is required')
    class Options: pass
    args=Options()
    args.root=options['--root']; args.targets=options['--targets']
    args.seconds=int(options['--seconds']); args.strategy=options['--strategy']
    args.status=options['--status']; args.parent=int(options['--parent'])
    if args.strategy not in ['passthrough']+[item['id'] for item in catalog()]: raise SystemExit('Unsupported strategy')
    if os.geteuid()!=0: raise SystemExit('root required')
    global_capture=args.targets=='all'
    targets=set() if global_capture else set(args.targets.split(','))
    for ip in targets: socket.inet_aton(ip)
    if len(targets)>32: raise SystemExit('Test limited to 32 addresses')
    strategy=Strategy(args.root,args.strategy if args.strategy!='passthrough' else 'alt3')
    quic=None
    try:
        from quic import Initial
        quic=Initial()
    except Exception as e: emit('quic_unavailable',reason=str(e))
    route=subprocess.check_output(['ip','route','get','1.1.1.1' if global_capture else sorted(targets)[0]]).decode().split()
    interface=route[route.index('dev')+1]
    source=route[route.index('src')+1]
    if interface not in ('wlan0','eth0'): raise SystemExit('Refusing VPN or unexpected egress '+interface)
    name='fszdev'
    if os.path.exists('/sys/class/net/'+name): raise SystemExit('fszdev already exists')
    original_routes=subprocess.check_output(['ip','route','show'])
    if global_capture and (b'0.0.0.0/1 ' in original_routes or b'128.0.0.0/1 ' in original_routes):
        raise SystemExit('Existing split-default route found; stop VPN before starting')
    running=[True]
    def stop(signum,frame): running[0]=False
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    fd=None; raw=None; receiver=None
    flows={}
    udpflows={}
    counters={'read':0,'sent':0,'transformed':0,'udp_transformed':0,'fake_packets':0,'parse_errors':0,'reassembly_timeout':0,'received':0}
    started=time.time(); last_state=0; last_gc=0
    state={'running':True,'pid':os.getpid(),'strategy':args.strategy,'interface':interface,'source':source,
           'quic_initial_v1':quic is not None,'ipv6':False,'started':started,'counters':counters}
    def send(data):
        raw.sendto(data,(socket.inet_ntoa(data[16:20]),0)); counters['sent']+=1
    def flush(flow):
        for p in flow.get('held',[]): send(p.data)
        flow['held']=[]; flow['buffer']=b''
    try:
        fd=os.open('/dev/net/tun',os.O_RDWR)
        # IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL; deliberately never TUNSETPERSIST.
        fcntl.ioctl(fd,0x400454ca,struct.pack('16sH',name.encode(),0x9001))
        raw=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
        raw.setsockopt(socket.SOL_SOCKET,25,interface.encode()+b'\0')
        raw.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        subprocess.check_call(['ip','link','set','dev',name,'mtu','1500','up'])
        capture_routes=['0.0.0.0/1','128.0.0.0/1'] if global_capture else [target+'/32' for target in sorted(targets)]
        for target in capture_routes:
            subprocess.check_call(['ip','route','add',target,'dev',name,'src',source])
        state['reverse_path_mode']=reverse_path_mode(interface)
        state['receive_bridge']=state['reverse_path_mode']==1
        if state['receive_bridge']:
            receiver=ReturnBridge(interface,fd,ReturnPolicy(source,targets,global_capture,original_routes))
        emit('ready',pid=os.getpid(),interface=interface,source=source,targets=sorted(targets),strategy=args.strategy)
        state['heartbeat']=time.time(); write_state(args.status,state)
        deadline=time.time()+args.seconds if args.seconds>0 else float('inf')
        while running[0] and time.time()<deadline:
            now=time.time()
            if args.parent and os.getppid()!=args.parent: break
            if now-last_state>=1:
                state['heartbeat']=now; state['flows']=len(flows); write_state(args.status,state); last_state=now
            if now-last_gc>=0.25:
                for key,flow in list(flows.items()):
                    if flow.get('held') and now-flow['started']>0.4:
                        flush(flow); flow['done']=True; counters['reassembly_timeout']+=1
                    if now-flow['seen']>30: flush(flow); del flows[key]
                for key,flow in list(udpflows.items()):
                    if now-flow['seen']>10: del udpflows[key]
                last_gc=now
            try:
                readable=select.select([fd]+([receiver.socket] if receiver is not None else []),[],[],0.1)[0]
            except select.error as error:
                if error.args[0]==errno.EINTR: continue
                raise
            if not readable: continue
            if receiver is not None and receiver.socket in readable:
                if receiver.receive(): counters['received']+=1
            if fd not in readable: continue
            data=os.read(fd,65535)
            counters['read']+=1
            try: p=Packet(data)
            except ValueError:
                counters['parse_errors']+=1
                send(data); continue
            if not global_capture and p.dst not in targets: raise RuntimeError('unexpected routed destination '+p.dst)
            if p.src!=source: raise RuntimeError('source address changed; stopping for safe recovery')
            if args.strategy=='passthrough' or p.fragment:
                send(data); continue
            if p.protocol==17:
                previous=udpflows.get(p.key,{})
                count=previous.get('count',0)+1
                previous.update(count=count,seen=now)
                if len(udpflows)<1024 or p.key in udpflows: udpflows[p.key]=previous
                profile=strategy.udp_profile(p,previous.get('host'),count)
                host=None
                if p.dport==443 and quic is not None and len(p.payload)>=1200:
                    try:
                        decoded=quic.decode(p.payload)
                        if decoded:
                            flow=udpflows.get(p.key)
                            if flow is None or flow.get('dcid')!=decoded['dcid']:
                                flow={'dcid':decoded['dcid'],'chunks':{},'seen':now,'count':count}
                                if len(udpflows)<1024: udpflows[p.key]=flow
                            flow['seen']=now
                            for offset,chunk in decoded['chunks']: flow['chunks'][offset]=chunk
                            assembled=b''
                            for offset,chunk in sorted(flow['chunks'].items()):
                                if offset>len(assembled): break
                                assembled+=chunk[max(0,len(assembled)-offset):]
                            info=hello_info(assembled,False)
                            if info:
                                host=info['host']; flow['host']=host
                                profile=strategy.udp_profile(p,host,count)
                    except (ValueError,IndexError,struct.error): pass
                if profile:
                    label,fakes,repeats=profile
                    for fake in fakes:
                        item=p.rebuild(fake)
                        for _ in range(repeats): send(item)
                    counters['fake_packets']+=repeats*len(fakes); counters['udp_transformed']+=1
                    if counters['udp_transformed']<=40: emit('udp_desync',profile=label,host=host,repeats=repeats)
                send(data); continue
            if p.protocol!=6:
                send(data); continue
            if p.flags&2:
                old=flows.pop(p.key,None)
                if old: flush(old)
                if not p.flags&16:
                    syn=strategy.transform_syn(p)
                    if syn is not None: send(syn); continue
            if not p.payload:
                send(data); continue
            flow=flows.get(p.key)
            if flow is None:
                if len(flows)>=2048 or sum(1 for value in flows.values() if value.get('held'))>=32:
                    send(data); continue
                flow={'held':[],'buffer':b'','started':now,'seen':now,'seq':p.seq,'done':False}
                flows[p.key]=flow
            flow['seen']=now
            if flow['done']:
                if flow.get('profile') and p.seq==flow['seq'] and p.payload.startswith((b'\x16\x03',b'GET ',b'POST ',b'HEAD ')):
                    generated,fakes=strategy.transform_tcp(p,flow.get('hello'),flow['profile'])
                    for item in generated: send(item)
                    counters['fake_packets']+=fakes
                    continue
                send(data); continue
            expected=(flow['seq']+len(flow['buffer']))&0xffffffff
            if p.seq!=expected:
                flush(flow); flow['done']=True; send(data); continue
            flow['held'].append(p); flow['buffer']+=p.payload
            buffer=flow['buffer']
            hello=hello_info(buffer)
            host=hello['host'] if hello else http_host(buffer)
            if host is None:
                b=bytearray(buffer)
                pending_tls=len(b)>=5 and b[0]==22 and len(b)<5+struct.unpack('!H',buffer[3:5])[0]
                pending_http=len(buffer)<8192 and buffer.startswith((b'GET ',b'POST ',b'HEAD ',b'OPTIONS ')) and b'\r\n\r\n' not in buffer
                if len(buffer)<32768 and (pending_tls or pending_http): continue
                flush(flow); flow['done']=True; continue
            profile=strategy.tcp_profile(p,host)
            flow['done']=True
            if profile:
                first=flow['held'][0]
                generated,fakes=strategy.transform_tcp(first,hello,profile,buffer)
                for item in generated: send(item)
                counters['transformed']+=1
                counters['fake_packets']+=fakes
                if counters['transformed']<=120: emit('tcp_desync',host=host,profile=profile['label'],original_bytes=len(buffer),packets=len(generated),timestamp=first.timestamp_offset() is not None)
                flow['profile']=profile; flow['hello']=hello
                flow['held']=[]; flow['buffer']=b''
            else: flush(flow)
    finally:
        if receiver is not None: receiver.close()
        if raw is not None: raw.close()
        if fd is not None: os.close(fd)
        restored=subprocess.check_output(['ip','route','show'])==original_routes
        state.update(running=False,heartbeat=time.time(),route_snapshot_restored=restored)
        write_state(args.status,state)
        emit('stopped',counters=counters,route_snapshot_restored=restored,tun_exists=os.path.exists('/sys/class/net/'+name))


if __name__=='__main__': main()
