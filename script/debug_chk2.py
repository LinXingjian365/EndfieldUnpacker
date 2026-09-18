import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct, os

KEY = vfs_key()
vfs = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

d = '7064D8E2'  # Bundle (has more than 1 chunk)
dp = os.path.join(vfs, d)
blc = os.path.join(dp, f'{d}.blc')
with open(blc, 'rb') as f:
    data = f.read()
nonce = data[:12]
c = ChaCha20.new(key=KEY, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(data[12:])

# Parse block header
o = 0
ver = struct.unpack('<I', plain[o:o+4])[0]; o += 4
unk1 = struct.unpack('<I', plain[o:o+4])[0]; o += 4
name_len = struct.unpack('<H', plain[o:o+2])[0]; o += 2
name = plain[o:o+name_len].decode('ascii'); o += name_len
dir_hash = struct.unpack('<I', plain[o:o+4])[0]; o += 4
flag = struct.unpack('<i', plain[o:o+4])[0]; o += 4
file_cnt = struct.unpack('<I', plain[o:o+4])[0]; o += 4
block_size = struct.unpack('<Q', plain[o:o+8])[0]; o += 8
print(f'Block name="{name}" file_cnt={file_cnt}')

# First chunk header
bt = plain[o]
ver_chk = struct.unpack('<I', plain[o+1:o+5])[0]
chk_md5 = plain[o+5:o+21].hex().upper()
chk_len0 = struct.unpack('<Q', plain[o+37:o+45])[0]
print(f'Chunk[0] at off {o}: type={bt} ver={ver_chk} MD5={chk_md5} len={chk_len0}')

# The fieldX is at entry[0], after reading entry[0] with standard format
o += 45  # skip chunk header
# Read entry[0] 
typ = plain[o]; o += 1
f1 = struct.unpack('<I', plain[o:o+4])[0]; o += 4
fieldX = struct.unpack('<I', plain[o:o+4])[0]; o += 4
fnl = struct.unpack('<H', plain[o:o+2])[0]; o += 2
fn0 = plain[o:o+fnl].decode('ascii', errors='replace').rstrip('\x00'); o += fnl
o += 56
print(f'Entry[0]: f1=0x{f1:08x} fieldX={fieldX} fn="{fn0}"')
print(f'Reading {fieldX} entries from chunk[0]...')

# Read remaining fieldX-1 entries
for ei in range(1, fieldX):
    typ = plain[o]; o += 1
    f1 = struct.unpack('<I', plain[o:o+4])[0]; o += 4
    # subsequent entry: pad(1)+fnLen(2) = 3 bytes before fn
    pad = plain[o]; o += 1
    fnl = struct.unpack('<H', plain[o:o+2])[0]; o += 2
    try:
        fn = plain[o:o+fnl].decode('ascii', errors='replace').rstrip('\x00')
    except:
        fn = '?'
    o += fnl
    o += 56

print(f'After {fieldX} entries: off={o}')

# Now scan for the next chunk header
# Get CHK files
chk_files = {}
for fname in os.listdir(dp):
    if fname.endswith('.chk'):
        chk_files[fname[:-4].upper()] = os.path.getsize(os.path.join(dp, fname))

print(f'Total CHK files: {len(chk_files)}')

# Scan for next chunk header by trying different chunkMD5 offsets
print(f'\nScanning for next chunk header from off {o}:')
for scan_start in range(max(0, o-5), min(o+200, len(plain))):
    if scan_start + 45 > len(plain):
        break
    for md5_off in [5, 6, 4, 3]:
        cand_md5 = plain[scan_start+md5_off:scan_start+md5_off+16].hex().upper()
        if cand_md5 in chk_files and cand_md5 != chk_md5:
            bt_cand = plain[scan_start]
            ver_cand = struct.unpack('<I', plain[scan_start+1:scan_start+5])[0]
            print(f'  FOUND at off {scan_start} (MD5 at +{md5_off}): MD5={cand_md5}')
            print(f'    type={bt_cand} ver={ver_cand} chk_size={chk_files[cand_md5]}')
            print(f'    raw: {" ".join(f"{b:02x}" for b in plain[scan_start:scan_start+45])}')
            
            # Also check if the bytes BEFORE the found header form a complete entry
            # (verify we're at the right position)
            # The first chunk header was at off 46+45, and after fieldX entries we're at o
            # The distance o - scan_start should be the number of bytes consumed by the last entry
            print(f'    Distance from after-last-entry: {scan_start - o} bytes')
            break
    else:
        continue
    break
else:
    print('  No next chunk header found')
    # Show what is_chunk_header finds
    print(f'\n  Data at off {o}:')
    print(f'    {" ".join(f"{b:02x}" for b in plain[o:min(o+45, len(plain))])}')
    print(f'    First 5 bytes as possible chunk header: type={plain[o] if o < len(plain) else "?"} ver={struct.unpack("<I", plain[o+1:o+5])[0] if o+5 <= len(plain) else "?"}')
