import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct

KEY = vfs_key()
blc = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS\19E3AE45\19E3AE45.blc'

with open(blc, 'rb') as f:
    data = f.read()
nonce = data[:12]
c = ChaCha20.new(key=KEY, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(data[12:])

# Parse block header properly
o = 0
ver = struct.unpack('<I', plain[o:o+4])[0]; o += 4
unk1 = struct.unpack('<I', plain[o:o+4])[0]; o += 4
name_len = struct.unpack('<H', plain[o:o+2])[0]; o += 2
name = plain[o:o+name_len].decode('ascii'); o += name_len
dir_hash = struct.unpack('<I', plain[o:o+4])[0]; o += 4
flag = struct.unpack('<i', plain[o:o+4])[0]; o += 4
file_cnt = struct.unpack('<I', plain[o:o+4])[0]; o += 4
block_size = struct.unpack('<Q', plain[o:o+8])[0]; o += 8

print(f'Block header: ver={ver} unk1={unk1} nameLen={name_len} name="{name}"'
      f' dirHash=0x{dir_hash:08x} flag={flag} fileCnt={file_cnt} blockSize={block_size}')
print(f'Block header ends at off {o}')

# Chunk header
chunk_start = o
bt = plain[o]; ver_chk = struct.unpack('<I', plain[o+1:o+5])[0]
chunk_len = struct.unpack('<Q', plain[o+37:o+45])[0]
print(f'Chunk header at off {o}: type={bt} ver={ver_chk} chunkLen={chunk_len}')
o += 45

print(f'\nEntry[0] at off {o}')
print('  raw: ' + ' '.join(f'{b:02x}' for b in plain[o:o+30]))

# Read with current format: type+f1+fieldX+fnLen
typ = plain[o]; f1 = struct.unpack('<I', plain[o+1:o+5])[0]
fX = struct.unpack('<I', plain[o+5:o+9])[0]
fnl = struct.unpack('<H', plain[o+9:o+11])[0]
fn = plain[o+11:o+11+fnl].decode('ascii').rstrip('\x00')
print(f'  type={typ} f1=0x{f1:08x} fieldX={fX} fnLen={fnl} fn="{fn}"')
e0_end = o + 11 + fnl + 56
print(f'  Entry[0] ends at off {e0_end}')

# entry[1]
e1 = e0_end
print(f'\nEntry[1] at off {e1}:')
print('  raw: ' + ' '.join(f'{b:02x}' for b in plain[e1:e1+80]))

print('\n  Scanning for valid fnLen positions:')
for fnlen_off in range(3, 22):
    if e1 + fnlen_off + 2 > len(plain):
        continue
    fnl = struct.unpack('<H', plain[e1+fnlen_off:e1+fnlen_off+2])[0]
    if fnl <= 0 or fnl > 200:
        continue
    fn_start = e1 + fnlen_off + 2
    if fn_start + fnl + 56 > len(plain):
        continue
    fn = plain[fn_start:fn_start+fnl]
    try:
        fn_str = fn.decode('ascii').rstrip('\x00')
        if len(fn_str) >= 8:
            file_off = struct.unpack('<Q', plain[fn_start+fnl+40:fn_start+fnl+48])[0]
            file_len = struct.unpack('<Q', plain[fn_start+fnl+48:fn_start+fnl+56])[0]
            overhead = fnlen_off + 2
            entry_size = overhead + fnl + 56
            next_off = fn_start + fnl + 56
            print(f'    fnLen at +{fnlen_off}: ovh={overhead}B fn="{fn_str}" off={file_off} len={file_len} next={next_off}')
    except:
        pass

# Show hex with annotations
print('\n  Hex breakdown at entry[1]:')
for i in range(0, min(113, len(plain)-e1), 16):
    hex_part = ' '.join(f'{b:02x}' for b in plain[e1+i:e1+min(i+16, len(plain)-e1)])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in plain[e1+i:e1+min(i+16, len(plain)-e1)])
    print(f'    {i:3d}: {hex_part:48s}  {ascii_part}')

# Check f1 pattern for first 5 entries  
print(f'\n  Quick f1 scan for first 5 entries:')
o2 = o  # start of entry[0]
for ei in range(5):
    if o2 >= len(plain):
        break
    typ = plain[o2]
    f1v = struct.unpack('<I', plain[o2+1:o2+5])[0]
    
    # Try to find the fn with any overhead
    found = False
    for ovh in range(3, 22):
        if o2 + ovh + 2 > len(plain):
            continue
        fnl = struct.unpack('<H', plain[o2+ovh:o2+ovh+2])[0]
        fn_start = o2 + ovh + 2
        if fn_start + fnl + 56 > len(plain) or fnl <= 0 or fnl > 200:
            continue
        try:
            fn_str = plain[fn_start:fn_start+fnl].decode('ascii').rstrip('\x00')
            if len(fn_str) >= 8:
                file_off = struct.unpack('<Q', plain[fn_start+fnl+40:fn_start+fnl+48])[0]
                file_len = struct.unpack('<Q', plain[fn_start+fnl+48:fn_start+fnl+56])[0]
                print(f'    [{ei}] ovh={ovh}: type={typ} f1=0x{f1v:08x} fn="{fn_str}" off={file_off} len={file_len}')
                o2 = fn_start + fnl + 56
                found = True
                break
        except:
            pass
    if not found:
        print(f'    [{ei}] type={typ} f1=0x{f1v:08x} - NO valid parse')
        o2 += 20
