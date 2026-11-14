"""Prepare a hash-checked, offline TV installation script. Does not connect."""
import base64
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = '/tmp/flowseal-webos-install'


def build():
    version = json.loads((ROOT / 'app/appinfo.json').read_text(encoding='utf8'))['version']
    ipk = ROOT / 'dist' / ('org.flowseal.webos_' + version + '_all.ipk')
    paths = [ipk, ROOT / 'native/install_tv.py', ROOT / 'dist/package-contents.json']
    script = ["#!/bin/sh", "set -e", "umask 077", "python - <<'FLOWSEAL_UPLOAD'",
              'import base64, hashlib, os', 'dest=' + repr(STAGE),
              "if os.path.islink(dest): raise RuntimeError('Refusing symlink staging directory')",
              'if not os.path.isdir(dest): os.mkdir(dest, 0700)',
              "if os.stat(dest).st_uid != 0: raise RuntimeError('Staging directory not owned by root')"]
    for path in paths:
        data = path.read_bytes()
        script += ['data=base64.b64decode(' + repr(base64.b64encode(data).decode('ascii')) + ')',
                   'assert hashlib.sha256(data).hexdigest() == ' + repr(hashlib.sha256(data).hexdigest()),
                   'open(dest+' + repr('/' + path.name) + ", 'wb').write(data)"]
    script += ["print('Verified offline IPK and installer upload')", 'FLOWSEAL_UPLOAD',
               'python -B ' + STAGE + '/install_tv.py ' + STAGE + '/' + ipk.name +
               ' ' + STAGE + '/package-contents.json']
    target = ROOT / 'diagnostics/install-tv.sh'
    target.parent.mkdir(exist_ok=True)
    target.write_text('\n'.join(script) + '\n', encoding='ascii')
    print(str(target))


if __name__ == '__main__':
    build()
