import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct

KEY = vfs_key()
VFS = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

def decrypt_blc(blc_path):
    with open(blc_path, 'rb') as f:
        data = f.read()
    nonce = data[:12]
    enc = data[12:]
    c = ChaCha20.new(key=KEY, nonce=nonce)
    c.decrypt(b'\x00' * 64)
    return c.decrypt(enc)

for d in sorted(os.listdir(VFS)):
    dp = os.path.join(VFS, d)
    if not os.path.isdir(dp):
        continue
    blc_path = os.path.join(dp, f'{d}.blc')
    if not os.path.exists(blc_path):
        continue
    
    plain = decrypt_blc(blc_path)
    
    ver = struct.unpack('<I', plain[0:4])[0]
    unk1 = struct.unpack('<I', plain[4:8])[0]
    name_len = struct.unpack('<H', plain[8:10])[0]
    name = plain[10:10+name_len].decode('ascii')
    off = 10 + name_len
    dir_hash = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    flag = struct.unpack('<i', plain[off:off+4])[0]; off += 4
    file_cnt = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    block_size = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
    
    print(f'[{d}] {name}: ver={ver} unk1={unk1} flag={flag} files={file_cnt} size={block_size}')
    print(f'  Header ends at offset {off}')
    print(f'  Next 128 bytes hex:')
    hex_str = plain[off:off+128].hex()
    for i in range(0, len(hex_str), 64):
        line = hex_str[i:i+64]
        ascii_str = ''
        for j in range(i//2, min(i//2+32, (off+128))):
            b = plain[off+j-(i//2)]
            ascii_str += chr(b) if 32 <= b < 127 else '.'
        print(f'    {line}')
    print()
