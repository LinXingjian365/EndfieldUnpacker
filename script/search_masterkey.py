import os, sys

md = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\il2cpp_data\Metadata\global-metadata.dat'
with open(md, 'rb') as f:
    data = f.read()

out = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\unity\zmdobj\masterkey_search.txt'
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
