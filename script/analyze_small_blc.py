import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct

key = vfs_key()
vfs = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

# Small BLC: 07A1BB91 (375 bytes)
for d in ['07A1BB91', '1CDDBF1F', '3C9D9D2D', 'D6E622F7']:
    fp = f'{vfs}/{d}/{d}.blc'
    with open(fp, 'rb') as f:
        data = f.read()
    
    nonce = data[:12]
    enc = data[12:]
    c = ChaCha20.new(key=key, nonce=nonce)
    c.decrypt(b'\x00' * 64)
    plain = c.decrypt(enc)
    
    print(f'===== {d} ({len(plain)} bytes) =====', flush=True)
    for i in range(0, len(plain), 16):
        chunk = plain[i:i+16]
        h = ' '.join(f'{b:02x}' for b in chunk)
        a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  {i:04x}: {h:48s} {a}', flush=True)
    print()
