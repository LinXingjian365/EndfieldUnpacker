import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
"""Probe file entry format at entry boundaries for Table, JsonData, Lua."""
from Crypto.Cipher import ChaCha20
import struct, os

KEY = vfs_key()
VFS = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

def decrypt_blc(blc_path):
    with open(blc_path, 'rb') as f:
        data = f.read()
    nonce = data[:12]
    c = ChaCha20.new(key=KEY, nonce=nonce)
    c.decrypt(b'\x00' * 64)
    return c.decrypt(data[12:])

# === Table (type 18) ===
dp = os.path.join(VFS, '42A8FCA6')
plain = decrypt_blc(os.path.join(dp, '42A8FCA6.blc'))
print(f"=== Table (42A8FCA6) === plain len={len(plain)}")
print(f"Header: {plain[:40].hex()}")

# Find chunk header
off = 0
# skip version, unk, name...
off += 4  # ver
off += 4  # unk1
name_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
off += name_len  # name
off += 4  # dir_hash
off += 4  # flag
file_cnt = struct.unpack('<I', plain[off:off+4])[0]; off += 4
off += 8  # block_size
print(f"After block header: off={off}, file_cnt={file_cnt}")

# First chunk header at off=35
hdr_off = off
print(f"\nFirst chunk header at off={hdr_off}:")
print(f"  Raw: {plain[hdr_off:hdr_off+50].hex()}")
print(f"  type={plain[hdr_off]}")
print(f"  f1/ver={struct.unpack('<I', plain[hdr_off+1:hdr_off+5])[0]}")
print(f"  MD5 at +5: {plain[hdr_off+5:hdr_off+21].hex().upper()}")
print(f"  MD5 at +6: {plain[hdr_off+6:hdr_off+22].hex().upper()}")

off = hdr_off + 5 + 16  # skip to after chunkMD5
off += 16  # contentMD5
off += 8   # chunkLen
print(f"\nAfter chunk header: off={off}")

# Entry[0]
e0_off = off
print(f"\nEntry[0] at off={e0_off}:")
print(f"  Raw: {plain[e0_off:e0_off+80].hex()}")
print(f"  type={plain[e0_off]}")
print(f"  f1={struct.unpack('<I', plain[e0_off+1:e0_off+5])[0]}")
print(f"  fieldX={struct.unpack('<I', plain[e0_off+5:e0_off+9])[0]}")

fn_len = struct.unpack('<H', plain[e0_off+9:e0_off+11])[0]
print(f"  fnLen={fn_len}")
fn = plain[e0_off+11:e0_off+11+fn_len].decode('ascii').rstrip('\x00')
print(f"  fn='{fn}'")

e0_end = e0_off + 11 + fn_len + 56
print(f"  Entry[0] ends at off={e0_end}")

# Entry[1] starts at e0_end
e1_off = e0_end
print(f"\nEntry[1] at off={e1_off}:")
print(f"  Raw: {plain[e1_off:e1_off+40].hex()}")
print(f"  type={plain[e1_off]}")
print(f"  f1={struct.unpack('<I', plain[e1_off+1:e1_off+5])[0]}")
print(f"  byte +5: {plain[e1_off+5]}")
print(f"  byte +6: {plain[e1_off+6]}")
print(f"  byte +7: {plain[e1_off+7]}")
print(f"  byte +8: {plain[e1_off+8]}")

# Try different offsets for fnLen
print(f"\n  Trying different entry formats:")
for pad in range(0, 15):
    try_fn_len_off = 5 + pad
    if e1_off + try_fn_len_off + 2 > len(plain):
        break
    tfn_len = struct.unpack('<H', plain[e1_off+try_fn_len_off:e1_off+try_fn_len_off+2])[0]
    if 5 <= tfn_len <= 300:
        try:
            tfn = plain[e1_off+try_fn_len_off+2:e1_off+try_fn_len_off+2+tfn_len].decode('ascii').rstrip('\x00')
            print(f"    pad={pad} (total_ovh={5+pad+2}): fnLen={tfn_len} fn='{tfn}'")
        except:
            if tfn_len <= 200:
                print(f"    pad={pad} (total_ovh={5+pad+2}): fnLen={tfn_len} (not ascii)")

# === Lua (type 17) - check entries around 240-245 ===
print("\n\n=== Lua (19E3AE45) ===")
dp2 = os.path.join(VFS, '19E3AE45')
plain2 = decrypt_blc(os.path.join(dp2, '19E3AE45.blc'))
print(f"plain len={len(plain2)}")

off2 = 0
off2 += 4; off2 += 4
name_len2 = struct.unpack('<H', plain2[off2:off2+2])[0]; off2 += 2
off2 += name_len2
off2 += 4; off2 += 4
file_cnt2 = struct.unpack('<I', plain2[off2:off2+4])[0]; off2 += 4
off2 += 8
print(f"After block header: off={off2}, file_cnt={file_cnt2}")

# First chunk header
hdr_off2 = off2
print(f"\nFirst chunk header at off={hdr_off2}:")
print(f"  type={plain2[hdr_off2]}")
print(f"  f1/ver={struct.unpack('<I', plain2[hdr_off2+1:hdr_off2+5])[0]}")
off2 = hdr_off2 + 5 + 16 + 16 + 8  # type+f1+chunkMD5+contentMD5+chunkLen
print(f"After chunk header: off={off2}")

# Read entries until ~245
entry_offsets = []
e_idx = 0
while off2 < len(plain2) and e_idx < 250:
    entry_offsets.append((e_idx, off2))
    t = plain2[off2]; off2 += 1
    f1 = struct.unpack('<I', plain2[off2:off2+4])[0]; off2 += 4
    if e_idx == 0:
        # First entry: fieldX
        fieldX = struct.unpack('<I', plain2[off2:off2+4])[0]; off2 += 4
        ovh = 16  # Lua overhead
    else:
        off2 += (ovh - 7)
    fn_len = struct.unpack('<H', plain2[off2:off2+2])[0]; off2 += 2
    if off2 + fn_len + 56 > len(plain2):
        break
    try:
        fn = plain2[off2:off2+fn_len].decode('ascii').rstrip('\x00')
    except:
        fn = f'binary_{fn_len}b'
    off2 += fn_len
    off2 += 8 + 16 + 16 + 8 + 8  # hash + chunkRef + dataMD5 + fileOff + fileLen
    if e_idx >= 238 and e_idx <= 246:
        print(f"  Entry[{e_idx}] off={entry_offsets[-1][1]}: fn='{fn}'")
    e_idx += 1

# Now dump raw data around entry 240-245
for idx, off_pos in entry_offsets:
    if idx >= 240 and idx <= 246:
        print(f"\n  RAW Entry[{idx}] at {off_pos}:")
        print(f"    {plain2[off_pos:off_pos+40].hex()}")
