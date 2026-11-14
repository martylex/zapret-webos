"""Build a webOS IPK with Python stdlib; no SDK downloads or substituted resources."""
import binascii
import gzip
import hashlib
import io
import json
import struct
import tarfile
import zlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
APP_ID='org.flowseal.webos'
VERSION=json.loads((ROOT/'app/appinfo.json').read_text(encoding='utf8'))['version']


def icon():
    width=height=128
    rows=[]
    for y in range(height):
        row=bytearray()
        for x in range(width):
            inside=(25<=x<=102 and 19<=y<=75) or (75<y<=111 and abs(x-63.5)<(112-y)*1.1)
            color=(29,63,101) if inside else (17,28,42)
            if (44<=x<=52 and 36<=y<=83) or (44<=x<=85 and 36<=y<=44) or (44<=x<=77 and 56<=y<=64): color=(150,200,255)
            row.extend(color)
        rows.append(b'\x00'+row)
    def chunk(kind,data): return struct.pack('!I',len(data))+kind+data+struct.pack('!I',binascii.crc32(kind+data)&0xffffffff)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!IIBBBBB',width,height,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b''.join(rows),9))+chunk(b'IEND',b'')


def archive(files):
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as out:
        directories=set()
        for name,_,_ in files:
            parts=name.split('/')
            for i in range(1,len(parts)): directories.add('/'.join(parts[:i]))
        for name in sorted(directories,key=lambda n:(n.count('/'),n)):
            info=tarfile.TarInfo('./'+name); info.type=tarfile.DIRTYPE; info.mode=0o755; info.mtime=1735689600
            out.addfile(info)
        for name,data,mode in sorted(files):
            info=tarfile.TarInfo('./'+name); info.size=len(data); info.mode=mode; info.mtime=1735689600
            out.addfile(info,io.BytesIO(data))
    compressed=io.BytesIO()
    with gzip.GzipFile(filename='',fileobj=compressed,mode='wb',mtime=0) as out:
        out.write(buf.getvalue())
    return compressed.getvalue()


def ar_member(name,data):
    header=(name+'/').ljust(16)+'0'.ljust(12)+'0'.ljust(6)+'0'.ljust(6)+'100644'.ljust(8)+str(len(data)).ljust(10)+'`\n'
    return header.encode('ascii')+data+(b'\n' if len(data)%2 else b'')


def build():
    from build_strategies import build as build_strategies
    build_strategies()
    output=ROOT/'dist'; output.mkdir(exist_ok=True)
    (ROOT/'app/icon.png').write_bytes(icon())
    prefix='usr/palm/applications/'+APP_ID+'/'
    files=[]
    for path in (ROOT/'app').rglob('*'):
        if path.is_file(): files.append((prefix+path.relative_to(ROOT/'app').as_posix(),path.read_bytes(),0o644))
    for name in ['engine.py','packets.py','quic.py','control.py','startup.sh','strategies.py','strategy_catalog.json','receive.py']:
        path=ROOT/'native'/name
        files.append((prefix+'native/'+name,path.read_bytes(),0o755 if name.endswith('.sh') else 0o644))
    source=ROOT/'source/flowseal-1.10.4'
    for path in sorted((source/'lists').glob('*.txt')):
        if path.is_file(): files.append((prefix+'flowseal/lists/'+path.name,path.read_bytes(),0o644))
    for path in (source/'bin').glob('*.bin'):
        files.append((prefix+'flowseal/bin/'+path.name,path.read_bytes(),0o644))
    for path in (ROOT/'config').glob('*.txt'):
        files.append((prefix+'config/'+path.name,path.read_bytes(),0o644))
    for name in ['LICENSE.txt']+[p.name for p in sorted(source.glob('general*.bat'))]:
        files.append((prefix+'flowseal/'+name,(source/name).read_bytes(),0o644))
    resources=[{'path':name[len(prefix+'flowseal/'):],'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
               for name,data,_ in sorted(files) if name.startswith(prefix+'flowseal/')]
    tree=''.join(item['path']+'\0'+item['sha256']+'\n' for item in resources).encode('utf8')
    provenance={'source_type':'Bundled subset of Flowseal 1.10.4 resources and strategy definitions',
                'upstream_url':'https://github.com/Flowseal/zapret-discord-youtube',
                'upstream_version':'1.10.4','file_count':len(resources),
                'total_bytes':sum(item['bytes'] for item in resources),
                'tree_sha256':hashlib.sha256(tree).hexdigest(),'files':resources}
    provenance.update(native_engine='Original Python Linux TUN/raw implementation; not winws or nfqws',default_strategy='alt3',version=VERSION)
    files.append((prefix+'provenance.json',(json.dumps(provenance,indent=2)+'\n').encode(),0o644))
    for name in ['LICENSE','NOTICE.md']:
        files.append((prefix+name,(ROOT/name).read_bytes(),0o644))
    package={'id':APP_ID,'app':APP_ID,'version':VERSION,'vendor':'Local webOS adaptation','loc_name':'Flowseal Zapret','package_format_version':2,'services':[]}
    files.append(('usr/palm/packages/'+APP_ID+'/packageinfo.json',(json.dumps(package,indent=2)+'\n').encode(),0o644))
    installed_size=(sum(len(data) for _,data,_ in files)+1023)//1024
    control=('Package: '+APP_ID+'\nVersion: '+VERSION+'\nSection: misc\nPriority: optional\nArchitecture: all\nMaintainer: Local webOS adaptation\nDescription: Flowseal 1.10.4 DPI bypass for rooted webOS\nInstalled-Size: '+str(installed_size)+'\nwebOS-Package-Format-Version: 2\n').encode()
    prerm='''#!/bin/sh
set -e
for base in /media/developer/apps /media/cryptofs/apps /media/system/apps; do
    controller="$base/usr/palm/applications/org.flowseal.webos/native/control.py"
    if [ -f "$controller" ]; then
        /usr/bin/python -B "$controller" stop >/dev/null
        /usr/bin/python -B "$controller" autostart-off >/dev/null
    fi
done
exit 0
'''.encode()
    ipk=b'!<arch>\n'+ar_member('debian-binary',b'2.0\n')+ar_member('control.tar.gz',archive([('control',control,0o644),('prerm',prerm,0o755)]))+ar_member('data.tar.gz',archive(files))
    target=output/(APP_ID+'_'+VERSION+'_all.ipk'); target.write_bytes(ipk)
    (output/(target.name+'.sha256')).write_text(hashlib.sha256(ipk).hexdigest()+'  '+target.name+'\n',encoding='ascii')
    (output/'package-contents.json').write_text(json.dumps([{'path':n,'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()} for n,d,_ in files],indent=2)+'\n',encoding='utf8')
    print(str(target)+' (%d bytes, %d files)'%(len(ipk),len(files)))


if __name__=='__main__': build()
