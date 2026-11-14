"""Install the locally built IPK through webOS, verify its files, and open it.

Run on the TV using tools/build_install_script.py and tools/Invoke-TV.ps1.
This installs only org.flowseal.webos; it does not enable the engine or autostart.
"""
from __future__ import print_function
import hashlib
import json
import os
import select
import subprocess
import sys
import time

APP_ID = 'org.flowseal.webos'
BASES = ['/media/developer/apps', '/media/cryptofs/apps', '/media/system/apps']


def luna(uri, payload, complete=None, timeout=20):
    process = subprocess.Popen(['luna-send', '-i', uri, json.dumps(payload)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, close_fds=True)
    pending = ''
    decoder = json.JSONDecoder()
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            if not select.select([process.stdout], [], [], 0.2)[0]:
                continue
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                raise RuntimeError('Luna call ended: ' + process.stderr.read().decode('utf8', 'replace'))
            pending += chunk.decode('utf8')
            while pending.strip():
                pending = pending.lstrip()
                try:
                    value, end = decoder.raw_decode(pending)
                except ValueError:
                    break
                pending = pending[end:]
                logged = value if 'stdoutString' not in value else {
                    'returnValue': value.get('returnValue'), 'errorText': value.get('errorText'),
                    'stdoutCharacters': len(value.get('stdoutString', ''))}
                print(json.dumps({'uri': uri, 'response': logged}, sort_keys=True))
                sys.stdout.flush()
                if value.get('returnValue') is False:
                    raise RuntimeError(value.get('errorText', repr(value)))
                details = value.get('details', {})
                if isinstance(details, dict) and 'errorCode' in details:
                    raise RuntimeError(repr(details))
                if complete(value) if complete else value.get('returnValue') is True:
                    return value
        raise RuntimeError('Timed out waiting for ' + uri)
    finally:
        if process.poll() is None:
            process.terminate()
        process.communicate()


def installed_root():
    for base in BASES:
        path = base + '/usr/palm/applications/' + APP_ID
        if os.path.isfile(path + '/appinfo.json'):
            return path
    raise RuntimeError('Installed application directory not found')


def install(path, manifest):
    if os.geteuid() != 0:
        raise RuntimeError('Root required')
    if os.path.exists('/sys/class/net/fszdev'):
        raise RuntimeError('Stop the existing Flowseal engine before installation')
    previous=None
    try:
        previous_root=installed_root()
        previous=json.loads(subprocess.check_output(['/usr/bin/python','-B',previous_root+'/native/control.py','status']))
    except (RuntimeError, ValueError, subprocess.CalledProcessError):
        pass
    prefix = 'usr/palm/applications/' + APP_ID + '/'
    expected = [item for item in json.load(open(manifest)) if item['path'].startswith(prefix)]
    if not expected:
        raise RuntimeError('No application files in installation manifest')
    luna('luna://com.webos.appInstallService/dev/install',
         {'id': APP_ID, 'ipkUrl': os.path.abspath(path), 'subscribe': True},
         complete=lambda value: value.get('statusValue') == 30, timeout=90)
    root = installed_root()
    for item in expected:
        relative = item['path'][len(prefix):]
        if '..' in relative.split('/') or relative.startswith('/'):
            raise RuntimeError('Invalid manifest path')
        installed = open(root + '/' + relative, 'rb').read()
        if hashlib.sha256(installed).hexdigest() != item['sha256']:
            raise RuntimeError('Installed file differs: ' + relative)
    print('PASS: %d installed application files match the IPK byte for byte' % len(expected))
    command = ['/usr/bin/python', '-B', root + '/native/control.py', 'status']
    state = json.loads(subprocess.check_output(command))
    if not state.get('returnValue'):
        raise RuntimeError(repr(state))
    # Some package installers run prerm during an update. Preserve the user's
    # existing startup choice rather than silently disabling it on upgrade.
    if previous and previous.get('autostart') and not state.get('autostart'):
        state=json.loads(subprocess.check_output(command[:-1]+['autostart-on']))
        if not state.get('returnValue'): raise RuntimeError(repr(state))
    print(json.dumps({'installedRoot': root, 'state': state}, sort_keys=True))
    luna('luna://com.webos.applicationManager/launch', {'id': APP_ID})
    print('PASS: installed and launched ' + APP_ID)


if __name__ == '__main__':
    install(sys.argv[1], sys.argv[2])
