import struct, os, sys

md = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\il2cpp_data\Metadata\global-metadata.dat'
with open(md, 'rb') as f:
    data = f.read()

# Find all string references to ChaCha/VFS decryption
keywords = [b'ChaCha', b'VFS', b'Decrypt', b'VFBlock', b'BlockInfo', b'Crypto']
for kw in keywords:
    start = 0
    count = 0
    while True:
        idx = data.find(kw, start)
        if idx == -1 or count >= 20:
            break
        # Read until null
        end = idx
        while end < len(data) and data[end] != 0:
            end += 1
        # Back up to find start (string may have length prefix before it)
        # Just grab a reasonable prefix
        begin = idx
        while begin > idx - 10 and data[begin-1:begin+2] not in [b'\x00', b'\x01', b'\x02']:
            begin -= 1
        s = data[idx:end].decode('utf-8', errors='backslashreplace')
        print(f'0x{idx:06x}: "{s}"', flush=True)
        count += 1
        start = idx + 1
