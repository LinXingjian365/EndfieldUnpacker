import struct, os, sys

md = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\il2cpp_data\Metadata\global-metadata.dat'
with open(md, 'rb') as f:
    data = f.read()

out = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\unity\zmdobj\metadata_strings.txt'

# Find all string references to ChaCha/VFS decryption
keywords = [b'ChaCha', b'VFS', b'VFBlock', b'BlockInfo', b'Decrypt', b'Crypto']
lines = []
for kw in keywords:
    start = 0
    count = 0
    while True:
        idx = data.find(kw, start)
        if idx == -1 or count >= 50:
            break
        # Read until null
        end = idx
        while end < len(data) and data[end] != 0:
            end += 1
        s = data[idx:end].decode('utf-8', errors='backslashreplace')
        lines.append(f'0x{idx:06x}: "{s}"')
        count += 1
        start = idx + 1

with open(out, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
print(f'Wrote {len(lines)} lines to {out}', flush=True)
