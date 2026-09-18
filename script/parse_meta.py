import struct, os, sys

md = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\il2cpp_data\Metadata\global-metadata.dat'
with open(md, 'rb') as f:
    data = f.read()

# Il2CPP Metadata v29
idx = 0x1358dd  # known location of 'ChaCha'
print(f'Context around 0x{idx:x}:', flush=True)
print(f'  {data[idx-16:idx+64].hex()}', flush=True)
print(f'  repr: {data[idx-16:idx+64]}', flush=True)

# Let's search for all 'ChaCha' references and their context
for start in range(len(data)):
    if data[start:start+6] == b'ChaCha':
        # Read forward until null
        end = start
        while end < len(data) and data[end] != 0:
            end += 1
        s = data[start:end].decode('utf-8', errors='replace')
        print(f'\nString at 0x{start:x}: "{s}"', flush=True)
        
        # Look backwards for the string length encoded with variable-length encoding
        # The string pool stores strings with a length prefix using a variable-length scheme
        for back in range(1, 10):
            pos = start - back
            if pos < 0:
                break
            # Try to decode the length
            # Il2CPP uses a fairly standard variable-length encoding
            # where bytes have MSB=1 for continuation
            val = 0
            for i in range(back):
                b = data[pos + i]
                val |= (b & 0x7F) << (i * 7)
                if not (b & 0x80):
                    break
            else:
                continue
            if val == len(s):
                print(f'  Length prefix at 0x{pos:x}, {back} bytes, val={val}', flush=True)
                break
