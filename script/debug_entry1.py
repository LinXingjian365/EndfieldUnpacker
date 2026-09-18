import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct, os

KEY = vfs_key()
VFS = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

d = '0CE8FA57'
dp = os.path.join(VFS, d)
blc_path = os.path.join(dp, f'{d}.blc')

with open(blc_path, 'rb') as f:
    data = f.read()
nonce = data[:12]
enc = data[12:]
c = ChaCha20.new(key=KEY, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(enc)

off = 0
ver = struct.unpack('<I', plain[off:off+4])[0]; off += 4
unk1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
name_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
name = plain[off:off+name_len].decode('ascii')
off += name_len
dir_hash = struct.unpack('<I', plain[off:off+4])[0]; off += 4
flag = struct.unpack('<i', plain[off:off+4])[0]; off += 4
file_cnt = struct.unpack('<I', plain[off:off+4])[0]; off += 4
block_size = struct.unpack('<Q', plain[off:off+8])[0]; off += 8

# Entry 0 at chunk_start + 45 = 40 + 45 = 85
e0 = 85

# Dump bytes 85 to 219 (before the error)
print("Entry 0 raw bytes (85-219):")
for i in range(85, min(220, len(plain))):
    b = plain[i]
    c = chr(b) if 32 <= b < 127 else '.'
    print(f"  {i:3d} (0x{i:02x}): 0x{b:02x} ({b:3d}) '{c}'")
