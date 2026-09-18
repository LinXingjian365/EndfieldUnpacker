import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct, os

KEY = vfs_key()
vfs = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

d = '42A8FCA6'  # Table
dp = os.path.join(vfs, d)
blc = os.path.join(dp, f'{d}.blc')
with open(blc, 'rb') as f:
    data = f.read()
nonce = data[:12]
c = ChaCha20.new(key=KEY, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(data[12:])

# Parse block
o = 0
o += 4+4+2
name_len = struct.unpack('<H', plain[o-2:o])[0]
name = plain[o:o+name_len].decode('ascii'); o += name_len
o += 4+4+4+8
print(f'Block: {name}, chunk header at off {o}')

# First chunk
chk_sizes = {}
for fname in os.listdir(dp):
    if fname.endswith('.chk'):
        chk_sizes[fname[:-4].upper()] = os.path.getsize(os.path.join(dp, fname))

print(f'Total CHK files: {len(chk_sizes)}')

# Find ALL chunk headers by scanning the entire plain data
print(f'\nScanning ALL chunk headers in plain data (size={len(plain)}):')
found_count = 0
for scan_off in range(0, len(plain) - 45, 1):
    bt = plain[scan_off]
    if not (1 <= bt <= 30):
        continue
    for md5_off in [3, 4, 5, 6, 7, 8]:
        cand_md5 = plain[scan_off+md5_off:scan_off+md5_off+16].hex().upper()
        if cand_md5 in chk_sizes:
            ver_val = struct.unpack('<I', plain[scan_off+1:scan_off+5])[0]
            chunk_len = struct.unpack('<Q', plain[scan_off+37:scan_off+45])[0]
            print(f'  off={scan_off}: type={bt} ver={ver_val} MD5_at=+{md5_off} MD5={cand_md5} chk_len={chunk_len} size={chk_sizes[cand_md5]}')
            found_count += 1
            break  # only report one match per position
    if found_count > 54:  # should have 54 chunks
        break

print(f'Total found: {found_count}')
