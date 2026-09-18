import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct, os

KEY = vfs_key()
VFS = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

for blk in ['0CE8FA57', '19E3AE45', '23D53F5D']:
    d = blk
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
    name = plain[off:off+name_len].decode('ascii'); off += name_len
    off += 4 + 4 + 4 + 8  # skip remaining header

    e0 = off + 45
    fn_len = struct.unpack('<H', plain[e0+9:e0+11])[0]
    fn_end = e0 + 11 + fn_len

    print(f'[{d}] {name}')
    print(f'  entry[0] fn ends at {fn_end}')
    print(f'  Bytes {fn_end} to {fn_end+72}:')
    for i in range(fn_end, min(fn_end+72, len(plain))):
        b = plain[i]
        c = chr(b) if 32 <= b < 127 else '.'
        mark = ''
        if i == fn_end + 56:
            mark = '  <-- +56 (my fixed end)'
        elif i == fn_end + 60:
            mark = '  <-- +60'
        elif i == fn_end + 64:
            mark = '  <-- +64 (with ivSeed)'
        print(f'    {i:3d}: 0x{b:02x} \'{c}\'{mark}')
    
    # Check what's at fn_end + 64 (including ivSeed 4 bytes)
    e1_64 = fn_end + 64
    t = plain[e1_64]
    f1v = struct.unpack('<I', plain[e1_64+1:e1_64+5])[0]
    padv = plain[e1_64+5]
    fnlv = struct.unpack('<H', plain[e1_64+6:e1_64+8])[0]
    valid = 1 <= t <= 30 and padv == 0 and 10 <= fnlv <= 400
    print(f'  Entry[1] at +64 (type+f1+pad+fnLen): type={t} f1={f1v} pad={padv} fnLen={fnlv} valid={valid}')
    if valid and e1_64+8+fnlv <= len(plain):
        try:
            fn = plain[e1_64+8:e1_64+8+fnlv].decode('ascii').rstrip('\x00')
            print(f'    fn = "{fn}"')
        except:
            pass
    
    # Also check +56
    e1_56 = fn_end + 56
    t = plain[e1_56]
    f1v = struct.unpack('<I', plain[e1_56+1:e1_56+5])[0]
    fnlv = struct.unpack('<H', plain[e1_56+5:e1_56+7])[0]
    valid_no_pad = (1 <= t <= 30) and (10 <= fnlv <= 400)
    print(f'  Entry[1] at +56 (type+f1+fnLen no pad): type={t} f1={f1v} fnLen={fnlv} valid={valid_no_pad}')
    
    # Check +58 (maybe 2 pad bytes)
    e1_58 = fn_end + 58
    t = plain[e1_58]
    f1v = struct.unpack('<I', plain[e1_58+1:e1_58+5])[0]
    fnlv = struct.unpack('<H', plain[e1_58+5:e1_58+7])[0]
    valid_check = (1 <= t <= 30) and (10 <= fnlv <= 400)
    print(f'  Entry[1] at +58: type={t} f1={f1v} fnLen={fnlv} valid={valid_check}')

    print()
