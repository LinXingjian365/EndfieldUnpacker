import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct

KEY = vfs_key()
vfs = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'
dp = vfs + '/0CE8FA57'

with open(dp + '/0CE8FA57.blc', 'rb') as f:
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
name = plain[off:off+name_len].decode('ascii'); off += name_len
dir_hash = struct.unpack('<I', plain[off:off+4])[0]; off += 4
flag = struct.unpack('<i', plain[off:off+4])[0]; off += 4
file_cnt = struct.unpack('<I', plain[off:off+4])[0]; off += 4
block_size = struct.unpack('<Q', plain[off:off+8])[0]; off += 8

print(f'Block: {name}, {file_cnt} files, header_off=0x{off:x}', flush=True)

block_type = plain[off]; off += 1
chunk_ver = struct.unpack('<I', plain[off:off+4])[0]; off += 4
chunk_md5 = plain[off:off+16]; off += 16
content_md5 = plain[off:off+16]; off += 16
chunk_len = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
print(f'Chunk: type={block_type} ver={chunk_ver} len={chunk_len}', flush=True)

for i in range(5):
    start = off
    file_type = plain[off]; off += 1
    f1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    f2 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    fn_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
    fn = plain[off:off+fn_len]
    off += fn_len
    
    fn_clean = fn.replace(b'\x00', b'').decode('ascii', errors='backslashreplace')
    after_fn = off
    
    pos = after_fn
    results = []
    for skip in range(0, 64, 8):
        if pos + skip + 16 <= len(plain):
            o = struct.unpack('<Q', plain[pos+skip:pos+skip+8])[0]
            l = struct.unpack('<Q', plain[pos+skip+8:pos+skip+16])[0]
            results.append((skip, o, l))
    
    u32s = []
    for skip in range(0, 16, 4):
        if pos + skip + 8 <= len(plain):
            o = struct.unpack('<I', plain[pos+skip:pos+skip+4])[0]
            l = struct.unpack('<I', plain[pos+skip+4:pos+skip+8])[0]
            u32s.append((skip, o, l))
    
    print(f'File[{i}] @0x{start:x}: type={file_type} f1={f1} f2={f2} fnLen={fn_len}', flush=True)
    print(f'  fn="{fn_clean}"', flush=True)
    for skip, o, l in results:
        print(f'  u64 skip+{skip}: off={o} ({o:#x}) len={l} ({l:#x})', flush=True)
    for skip, o, l in u32s:
        print(f'  u32 skip+{skip}: off={o} ({o:#x}) len={l} ({l:#x})', flush=True)
    hex_str = ' '.join(f'{plain[pos+j]:02x}' for j in range(64))
    print(f'  hex: {hex_str}', flush=True)
