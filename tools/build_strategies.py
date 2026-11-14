"""Compile every supplied batch strategy into data, never execute a batch file."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'source/flowseal-1.10.4'
ORDER = [('alt3', 'FAKE TLS AUTO ALT3'), ('alt2', 'FAKE TLS AUTO ALT2'),
         ('auto-alt', 'FAKE TLS AUTO ALT'), ('auto', 'FAKE TLS AUTO'),
         ('simple', 'SIMPLE FAKE'), ('simple-alt', 'SIMPLE FAKE ALT'),
         ('simple-alt2', 'SIMPLE FAKE ALT2'), ('general', None)]
ORDER += [('general-alt' + (str(n) if n > 1 else ''), 'ALT' + (str(n) if n > 1 else '')) for n in range(1,14)]
ORDER += [('exp', 'EXP')]


def build():
    items = []
    for index, (key, title) in enumerate(ORDER, 1):
        name = 'general' + (' (' + title + ')' if title else '') + '.bat'
        path = SOURCE / name
        data = path.read_bytes()
        text = re.sub(r'\^\s*\r?\n', ' ', data.decode('utf-8-sig'))
        command = text[text.index('--wf-tcp='):].strip()
        profiles = []
        for section in re.split(r'\s+--new\s+', command):
            options = re.findall(r'--[a-zA-Z0-9-]+(?:=(?:"[^"]*"|[^\s]+))?', section)
            # cmd's caret before ! is an escape, not part of winws's argument.
            profiles.append([value.replace('=^!', '=!') for value in options if not value.startswith('--wf-')])
        items.append({'id': key, 'number': index, 'label': title or 'GENERAL', 'source': name,
                      'source_sha256': hashlib.sha256(data).hexdigest(), 'profiles': profiles})
    assert len(items) == len(list(SOURCE.glob('general*.bat'))) == 22
    document = {'default': 'alt3', 'strategies': items,
                'native_limits': ['IPv4 only', 'Game filter disabled as supplied',
                                 'Implicit winws fake uses supplied Google TLS payload',
                                 'SYN-data uses the documented 16 zero-byte default']}
    (ROOT / 'native/strategy_catalog.json').write_text(json.dumps(document, indent=2) + '\n', encoding='utf8')
    public = [{k: item[k] for k in ['id', 'number', 'label', 'source']} for item in items]
    (ROOT / 'app/strategies.js').write_text('window.FlowsealStrategies = ' + json.dumps(public, indent=2) + ';\n', encoding='utf8')
    print('Compiled all 22 supplied strategies; preserved ordered options and payload references')


if __name__ == '__main__':
    build()
