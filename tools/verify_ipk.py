"""Inspect the IPK and compare embedded assets with the supplied source."""
import hashlib, io, json, tarfile
from build_ipk import ROOT, APP_ID, VERSION

path=ROOT/'dist'/(APP_ID+'_'+VERSION+'_all.ipk')
data=path.read_bytes(); assert data[:8]==b'!<arch>\n'
p=8; members={}
while p<len(data):
    header=data[p:p+60]; assert header[58:60]==b'`\n'
    name=header[:16].decode().strip().rstrip('/'); length=int(header[48:58])
    members[name]=data[p+60:p+60+length]; p+=60+length+(length%2)
assert set(members)=={'debian-binary','control.tar.gz','data.tar.gz'}
assert members['debian-binary']==b'2.0\n'
archive=tarfile.open(fileobj=io.BytesIO(members['data.tar.gz']),mode='r:gz')
files={entry.name.lstrip('./'):archive.extractfile(entry).read() for entry in archive.getmembers() if entry.isfile()}
prefix='usr/palm/applications/'+APP_ID+'/'
info=json.loads(files[prefix+'appinfo.json'])
assert info['id']==APP_ID and info['version']==VERSION
source=ROOT/'source/flowseal-1.10.4'
for item,content in files.items():
    assert '..' not in item.split('/') and not item.startswith('/')
    assert not item.lower().endswith(('.exe','.dll','.sys','.pyc'))
    if item.startswith(prefix+'flowseal/'):
        rel=item[len(prefix+'flowseal/'):]
        assert content==(source/rel).read_bytes(), 'Changed source resource '+rel
for name in ['engine.py','packets.py','quic.py','control.py','startup.sh','strategies.py','strategy_catalog.json','receive.py']:
    assert files[prefix+'native/'+name]==(ROOT/'native'/name).read_bytes()
for name in ['index.html','app.js','style.css','icon.png','strategies.js']:
    assert files[prefix+name]==(ROOT/'app'/name).read_bytes()
assert json.loads(files[prefix+'provenance.json'])['default_strategy']=='alt3'
provenance=json.loads(files[prefix+'provenance.json'])
resources={name[len(prefix+'flowseal/'):]:content for name,content in files.items() if name.startswith(prefix+'flowseal/')}
assert provenance['file_count']==len(resources)
assert provenance['total_bytes']==sum(map(len,resources.values()))
assert {item['path'] for item in provenance['files']}==set(resources)
for item in provenance['files']:
    assert item['bytes']==len(resources[item['path']])
    assert item['sha256']==hashlib.sha256(resources[item['path']]).hexdigest()
tree=''.join(item['path']+'\0'+item['sha256']+'\n' for item in provenance['files']).encode('utf8')
assert provenance['tree_sha256']==hashlib.sha256(tree).hexdigest()
for name in ['LICENSE','NOTICE.md']:
    assert files[prefix+name]==(ROOT/name).read_bytes()
strategies=json.loads(files[prefix+'native/strategy_catalog.json'])['strategies']
assert len(strategies)==22
for item in strategies:
    assert item['source_sha256']==hashlib.sha256((source/item['source']).read_bytes()).hexdigest()
    assert files[prefix+'flowseal/'+item['source']]==(source/item['source']).read_bytes()
assert files[prefix+'config/user-domains.txt']==(ROOT/'config/user-domains.txt').read_bytes()
control=tarfile.open(fileobj=io.BytesIO(members['control.tar.gz']),mode='r:gz')
assert any(x.name.lstrip('./')=='prerm' and x.mode&0o111 for x in control.getmembers())
manifest=json.loads((ROOT/'dist/package-contents.json').read_text(encoding='utf8'))
assert {item['path'] for item in manifest}==set(files)
for item in manifest:
    assert item['bytes']==len(files[item['path']])
    assert item['sha256']==hashlib.sha256(files[item['path']]).hexdigest()
assert path.with_name(path.name+'.sha256').read_text(encoding='ascii').split()[0]==hashlib.sha256(data).hexdigest()
print('PASS: IPK/ar/tar structure, metadata, unchanged Flowseal resources, ALT3 default, removal hook')
print('PASS: source provenance, bundled licenses, installed-file manifest and SHA256 sidecar')
print('SHA256 '+hashlib.sha256(data).hexdigest())
print('Packaged files: '+str(len(files)))
