import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import get_game_dir

_GAME = get_game_dir()
md = os.path.join(_GAME, 'Endfield_Data', 'il2cpp_data', 'Metadata', 'global-metadata.dat')
with open(md, 'rb') as f:
    data = f.read()

out = os.path.join(_SCRIPT_DIR, '..', 'DecryptOutput', 'masterkey_search.txt')
lines = []

for kw in [b'DynamicAssets', b'Assets/Beyond', b'Padding', b'CHACHA_KEYS', b'chachaKey', b'_chachaKey', b'masterKey']:
    idx = data.find(kw)
    if idx >= 0:
        end = idx
        while end < len(data) and data[end:end+1] != b'\x00':
            end += 1
        s = data[idx:end].decode('utf-8', errors='replace')
        lines.append(f'0x{idx:06x}: {s}')
    else:
        lines.append(f'NOT FOUND: {kw}')

with open(out, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
print(f'Wrote to {out}', flush=True)
