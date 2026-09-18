import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct, os

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
    
    print(f'[{d}] {name}: header_off={off} files={file_cnt}')
    
    # Check first chunk at off
    if off + 45 > len(plain):
        print(f'  Not enough data for chunk header')
        continue
    
    bt = plain[off]
    ver_val = struct.unpack('<I', plain[off+1:off+5])[0]
    md5_bytes = plain[off+5:off+37]
    ascii_cnt = sum(1 for b in md5_bytes if 32 <= b < 127)
    chunk_len_val = struct.unpack('<Q', plain[off+37:off+45])[0]
    
    print(f'  Chunk candidate at {off}:')
    print(f'    block_type={bt} ({"1-30 OK" if 1<=bt<=30 else "OUT OF RANGE"})')
    print(f'    version={ver_val} ({"1-23 OK" if 1<=ver_val<=23 else "OUT OF RANGE"})')
    print(f'    ascii_in_md5={ascii_cnt} ({"<=8 OK" if ascii_cnt<=8 else "TOO MANY"})')
    print(f'    chunk_len={chunk_len_val}')
    
    # First file entry at off+45
    fe = off + 45
    if fe + 12 > len(plain):
        continue
    
    print(f'  First file entry at {fe}:')
    print(f'    hex={plain[fe:fe+24].hex()}')
    
    ft = plain[fe]
    f1v = struct.unpack('<I', plain[fe+1:fe+5])[0]
    fxv = struct.unpack('<I', plain[fe+5:fe+9])[0]
    padv = plain[fe+9]
    fnlv = struct.unpack('<H', plain[fe+10:fe+12])[0]
    
    print(f'    file_type={ft} f1={f1v} fieldX={fxv} pad={padv} fnLen={fnlv}')
    
    try:
        fn = plain[fe+12:fe+12+fnlv].decode('ascii').rstrip('\x00')
        print(f'    fn="{fn}"')
    except:
        print(f'    fn=[not ascii] {plain[fe+12:fe+12+min(fnlv,40)].hex()}')
    
    print()
