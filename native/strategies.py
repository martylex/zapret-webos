"""Original Linux implementations of the modes used by the supplied Flowseal files."""
from __future__ import print_function
import binascii
import json
import os
import re
import struct
from packets import domains, domain_match, networks, ip_match, hello_info

HERE = os.path.dirname(os.path.abspath(__file__))


def catalog():
    with open(HERE + '/strategy_catalog.json') as source:
        return json.load(source)['strategies']


def port_match(port, value):
    for entry in value.split(','):
        if '%' in entry: continue  # GameFilter is disabled in the supplied source.
        parts = entry.split('-')
        if parts[0] and int(parts[0]) <= port <= int(parts[-1]): return True
    return False


def pattern(data, size, offset=0):
    if not data: raise ValueError('Empty payload pattern')
    return (data * ((size + offset) // len(data) + 1))[offset:offset + size]


def fake_hostname(template, size):
    template = template.encode('ascii')
    if len(template) >= size: return template[-size:]
    length = size - len(template)
    return binascii.hexlify(os.urandom(length))[:max(0,length-1)] + b'.' + template


def tls_mod(data, mods, original):
    info = hello_info(data)
    if not info or mods == 'none': return data
    values = mods.split(',')
    target = next((v[4:] for v in values if v.startswith('sni=')), None)
    if target or 'rndsni' in values:
        host = target.encode('ascii') if target else fake_hostname('com', info['host_length'])
        b = bytearray(data)
        delta = len(host) - info['host_length']
        start = info['host_offset']; ext = info['sniext_offset']
        b[start:start + info['host_length']] = host
        b[start-2:start] = struct.pack('!H', len(host))
        for offset in [ext-2, ext]:
            b[offset:offset+2] = struct.pack('!H', struct.unpack('!H',bytes(b[offset:offset+2]))[0]+delta)
        data = bytes(b)
    b = bytearray(data)
    if 'rnd' in values: b[11:43] = os.urandom(32)
    if 'dupsid' in values and original:
        old = b[43]; sid = original['sid']
        b[43:44+old] = bytes(bytearray([len(sid)])) + sid
    b[3:5] = struct.pack('!H',len(b)-5)
    b[6:9] = struct.pack('!I',len(b)-9)[1:]
    return bytes(b)


def markers(data, info=None):
    host = info['host'].encode('ascii') if info else b''
    start = info.get('host_offset', -1) if info else -1
    if start < 0 or start + len(host) > len(data):
        match = re.search(br'\r\nHost:\s*([^\r\n: ]+)',data,re.I)
        if match: start = match.start(1); host = match.group(1)
    result = {'method':0}
    if start >= 0 and host:
        result.update(host=start, endhost=start+len(host))
        parts = host.split(b'.')
        if len(parts)>1:
            sld = start + len(host) - len(parts[-1]) - len(parts[-2]) - 1
            result.update(sld=sld, endsld=sld+len(parts[-2]), midsld=sld+len(parts[-2])//2)
    if info and 'sniext_offset' in info: result['sniext'] = info['sniext_offset']
    return result


def split_positions(value, data, info):
    positions = []; relative = markers(data,info)
    for item in value.split(','):
        if re.match(r'^-?\d+$',item):
            offset = int(item); offset = len(data)+offset if offset<0 else offset
        else:
            match = re.match(r'^([a-z]+)([+-]\d+)?$',item)
            if not match or match.group(1) not in relative: continue
            offset = relative[match.group(1)] + int(match.group(2) or 0)
        if 0<offset<len(data): positions.append(offset)
    return sorted(set(positions))


class Strategy(object):
    def __init__(self, root, key='alt3'):
        self.root = root
        choices = dict((item['id'],item) for item in catalog())
        if key not in choices: raise ValueError('Unsupported strategy '+key)
        self.definition = choices[key]
        self.extra = domains(os.path.dirname(HERE)+'/config/user-domains.txt')
        self.seed = self.resource('"%BIN%tls_clienthello_www_google_com.bin"')
        self.profiles = []
        for index, tokens in enumerate(self.definition['profiles']):
            opts = {}; tls = []; default_mod = None
            for token in tokens:
                name, _, value = token.partition('=')
                name = name[2:]
                opts.setdefault(name,[]).append(value)
                if name == 'dpi-desync-fake-tls':
                    tls.append({'data':self.resource(value), 'mods':'rnd,rndsni,dupsid' if value=='!' else 'none'})
                elif name == 'dpi-desync-fake-tls-mod':
                    if tls: tls[-1]['mods']=value
                    else: default_mod=value
            opts['index'] = index
            opts['tls_fakes'] = tls or [{'data':self.seed,'mods':default_mod or 'rnd,rndsni,dupsid'}]
            opts['include_hosts'] = self.hosts(opts.get('hostlist',[]))
            opts['exclude_hosts'] = self.hosts(opts.get('hostlist-exclude',[]))
            opts['include_hosts'] += self.inline(opts.get('hostlist-domains',[]))
            opts['exclude_hosts'] += self.inline(opts.get('hostlist-exclude-domains',[]))
            if opts.get('hostlist'): opts['include_hosts'] += self.extra
            opts['include_ips'],opts['ip_any'] = self.ips(opts.get('ipset',[]))
            opts['exclude_ips'],_ = self.ips(opts.get('ipset-exclude',[]))
            opts['label'] = 'google' if any('list-google' in p for p in opts.get('hostlist',[])) else 'profile-'+str(index+1)
            self.profiles.append(opts)

    @staticmethod
    def inline(values):
        return [entry for value in values for entry in value.split(',')]

    @staticmethod
    def value(profile, name, default=''):
        values = profile.get(name)
        return values[-1] if values else default

    def filename(self, value, kind):
        name = value.strip('"').replace('%'+kind+'%', '')
        if name != os.path.basename(name) or '..' in name: raise ValueError('Invalid resource '+value)
        return self.root + ('/bin/' if kind=='BIN' else '/lists/') + name

    def resource(self, value):
        if value == '!': return open(self.root+'/bin/tls_clienthello_www_google_com.bin','rb').read()
        if value.startswith('0x'): return binascii.unhexlify(value[2:])
        return open(self.filename(value,'BIN'),'rb').read()

    def hosts(self, values):
        return [entry for value in values for entry in domains(self.filename(value,'LISTS'))]

    def ips(self, values):
        entries=[]; any_ip=False
        for value in values:
            path=self.filename(value,'LISTS')
            entries+=networks(path)
            if os.path.isfile(path) and not domains(path): any_ip=True
        return entries, any_ip

    def match(self, packet, host, protocol, l7=None, syn=False):
        for profile in self.profiles:
            ports=self.value(profile,'filter-'+protocol)
            if not ports and self.value(profile,'filter-l7')=='quic' and protocol=='udp': ports='443'
            if not ports or not port_match(packet.dport, ports): continue
            if ip_match(packet.dst,profile['exclude_ips']): continue
            if profile.get('ipset') and not (profile['ip_any'] or ip_match(packet.dst,profile['include_ips'])): continue
            if host and domain_match(host,profile['exclude_hosts']): continue
            if profile['include_hosts']:
                if syn or not host or not domain_match(host,profile['include_hosts']): continue
            wanted=self.value(profile,'filter-l7')
            if wanted and not syn and l7 not in wanted.split(','): continue
            return profile
        return None

    def tcp_profile(self, packet, host): return self.match(packet,host,'tcp')

    def transform_syn(self, packet):
        # SYN data is permitted only by an unconditionally matching profile.
        profile=self.match(packet,None,'tcp',syn=True)
        if not profile or 'syndata' not in self.value(profile,'dpi-desync').split(',') or packet.payload: return None
        # Never interfere with TCP Fast Open options.
        options=bytearray(packet.data[packet.ihl+20:packet.ihl+packet.thl]); offset=0
        while offset<len(options):
            kind=options[offset]
            if kind in (34,254): return None
            if kind==0: break
            if kind==1: offset+=1; continue
            if offset+1>=len(options) or options[offset+1]<2: break
            offset+=options[offset+1]
        return packet.rebuild(b'\x00'*16)

    def udp_profile(self, packet, host=None, count=1):
        b=bytearray(packet.payload)
        stun=len(b)>=20 and b[0]&0xc0==0 and packet.payload[4:8]==b'\x21\x12\xa4\x42'
        discord=(len(b)==74 and packet.payload[:4]==b'\x00\x01\x00\x46') or len(b)==70
        kind='quic' if packet.dport==443 and len(b)>5 and b[0]&0xc0==0xc0 else 'stun' if stun else 'discord' if discord else 'unknown'
        profile=self.match(packet,host,'udp',kind)
        if not profile: return None
        cutoff=self.value(profile,'dpi-desync-cutoff')
        if cutoff and count>int(cutoff[1:]): return None
        values=profile.get('dpi-desync-fake-'+kind,[])
        if not values: return None
        return profile['label']+'-'+kind,[self.resource(value) for value in values],int(self.value(profile,'dpi-desync-repeats','1'))

    def transform_tcp(self, packet, hello, profile, data=None):
        data=packet.payload if data is None else data
        modes=self.value(profile,'dpi-desync').split(',')
        fooling=self.value(profile,'dpi-desync-fooling').split(',')
        repeats=int(self.value(profile,'dpi-desync-repeats','1'))
        zero=self.value(profile,'ip-id')=='zero'
        ident=[struct.unpack('!H',packet.data[4:6])[0]]
        output=[]; fakes=[0]
        max_payload=1500-packet.ihl-packet.thl

        def make(payload, offset=0, fake=False, first=False):
            kwargs={'seq':packet.seq+offset,'zero_id':zero,'first':first,'ip_id':ident[0]}
            ident[0]=(ident[0]+1)&65535
            if fake:
                if 'badseq' in fooling:
                    kwargs.update(seq=packet.seq+offset+int(self.value(profile,'dpi-desync-badseq-increment','-10000')),
                                  ack_delta=int(self.value(profile,'dpi-desync-badack-increment','-66000')))
                if 'ts' in fooling: kwargs['ts_delta']=int(self.value(profile,'dpi-desync-ts-increment','-600000'))
                if 'md5sig' in fooling: kwargs['extra_options']=b'\x13\x12'+os.urandom(16)
            return packet.rebuild(payload,**kwargs)

        can_fake=('badseq' in fooling or 'md5sig' in fooling or ('ts' in fooling and packet.timestamp_offset() is not None))

        def emit(payload, offset=0, fake=False, repeat=1):
            if fake and not can_fake: return
            # Segment even large reassembled hellos rather than fragmenting IPv4.
            limit=max_payload-(20 if fake and 'md5sig' in fooling else 0)
            for start in range(0,len(payload),limit):
                value=make(payload[start:start+limit],offset+start,fake,start+limit<len(payload) or offset+len(payload)<len(data))
                output.extend([value]*repeat)
                if fake: fakes[0]+=repeat

        if 'fake' in modes:
            values=profile['tls_fakes'] if hello else [{'data':self.resource(value),'mods':'none'} for value in profile.get('dpi-desync-fake-http',[])]
            for value in values: emit(tls_mod(value['data'],value['mods'],hello),fake=True,repeat=repeats)

        if 'hostfakesplit' in modes:
            points=markers(data,hello)
            start=points.get('host'); end=points.get('endhost')
            if start is None or not 0<=start<end<=len(data): emit(data)
            else:
                mod=self.value(profile,'dpi-desync-hostfakesplit-mod')
                template=next((v[5:] for v in mod.split(',') if v.startswith('host=')),'com')
                fake=fake_hostname(template,end-start)
                emit(data[:start]); emit(fake,start,True,repeats)
                if 'altorder=1' in mod: emit(data[end:],end); emit(data[start:end],start)
                else: emit(data[start:end],start); emit(fake,start,True,repeats); emit(data[end:],end)
        elif 'fakedsplit' in modes:
            positions=split_positions(self.value(profile,'dpi-desync-split-pos','2'),data,hello)
            split=positions[0] if positions else min(1,len(data))
            fake=self.resource(self.value(profile,'dpi-desync-fakedsplit-pattern','0x00'))
            for start,end in [(0,split),(split,len(data))]:
                if end<=start: continue
                value=pattern(fake,end-start,start)
                emit(value,start,True,repeats); emit(data[start:end],start); emit(value,start,True,repeats)
        elif 'multisplit' in modes or 'multidisorder' in modes:
            positions=split_positions(self.value(profile,'dpi-desync-split-pos','2'),data,hello)
            spans=list(zip([0]+positions,positions+[len(data)]))
            reverse='multidisorder' in modes
            if reverse: spans.reverse()
            overlap=int(self.value(profile,'dpi-desync-split-seqovl','0'))
            seed=self.resource(self.value(profile,'dpi-desync-split-seqovl-pattern','0x00'))
            for start,end in spans:
                prefix=b''
                if overlap and ((not reverse and start==0) or (reverse and positions and start==positions[0] and overlap<start)):
                    prefix=pattern(seed,overlap)
                # Keep overlap+first real byte in one packet, within the interface MTU.
                emit(prefix+data[start:end],start-len(prefix))
        else: emit(data)
        return output,fakes[0]
