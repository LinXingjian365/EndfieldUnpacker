import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
"""Dump suffix bytes for first vs subsequent entries in Table and Lua."""
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

def load_chk_map(dp):
    chk_map = {}
    for f in os.listdir(dp):
        if f.endswith('.chk'):
            chk_map[bytes.fromhex(f[:-4].upper())] = True
    return chk_map

def list_chks(dp):
    return {f[:-4].upper() for f in os.listdir(dp) if f.endswith('.chk')}

# === Table ===
dp = os.path.join(VFS, '42A8FCA6')
chks = list_chks(dp)
plain = decrypt_blc(os.path.join(dp, '42A8FCA6.blc'))
print(f"=== Table (42A8FCA6) === {len(chks)} CHKs, {len(plain)} bytes")

# Skip block header to reach chunk[0]
off = 0; off += 4; off += 4
name_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
off += name_len; off += 4; off += 4
file_cnt = struct.unpack('<I', plain[off:off+4])[0]; off += 4
off += 8
hdr_off = off  # off=35

# Skip chunk header
off = hdr_off + 5 + 16 + 16 + 8  # = hdr_off + 45
print(f"Entry[0] at off={off}")

# Read entry[0]
file_type = plain[off]; off += 1
f1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
fieldX = struct.unpack('<I', plain[off:off+4])[0]; off += 4
fn_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
fn = plain[off:off+fn_len].decode('ascii').rstrip('\x00')
print(f"  fn='{fn}' fieldX={fieldX} fn_len={fn_len}")
off += fn_len
print(f"  After fn: off={off}")
# Dump 56 bytes of suffix
suffix = plain[off:off+56]
print(f"  Suffix hex: {suffix.hex()}")
print(f"  chunkRef @+0: {suffix[0:16].hex().upper()} {'IN CHKS' if suffix[0:16].hex().upper() in chks else 'NOT IN CHKS'}")
print(f"  chunkRef @+8: {suffix[8:24].hex().upper()} {'IN CHKS' if suffix[8:24].hex().upper() in chks else 'NOT IN CHKS'}")
file_off = struct.unpack('<Q', suffix[40:48])[0]
file_len = struct.unpack('<Q', suffix[48:56])[0]
print(f"  fileOff={file_off} fileLen={file_len}")

# Try different ovh values for entry[1]
e1_off = off + 56  # = past entry[0]
print(f"\nEntry[1] raw hex (first 60 bytes at {e1_off}): {plain[e1_off:e1_off+60].hex()}")
for ovh in [7, 8, 6, 9, 10, 11, 12, 13, 14, 15, 16]:
    off = e1_off
    file_type = plain[off]; off += 1
    f1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    fn_len_off = off + (ovh - 7)
    if fn_len_off + 2 + 56 > len(plain):
        continue
    fn_len = struct.unpack('<H', plain[fn_len_off:fn_len_off+2])[0]
    if fn_len < 4 or fn_len > 300:
        continue
    fn_start = fn_len_off + 2
    if fn_start + fn_len + 56 > len(plain):
        continue
    try:
        raw_fn = plain[fn_start:fn_start+fn_len]
        fn = raw_fn.decode('ascii').rstrip('\x00')
    except:
        continue
    if not fn.startswith('Data/') and not fn.startswith('Assets/'):
        continue
    # Found a valid entry!
    data_start = fn_start + fn_len
    suffix = plain[data_start:data_start+56]
    cr0 = suffix[0:16].hex().upper()
    cr8 = suffix[8:24].hex().upper()
    cr0_match = 'IN_CHKS' if cr0 in chks else ''
    cr8_match = 'IN_CHKS' if cr8 in chks else ''
    file_off40 = struct.unpack('<Q', suffix[40:48])[0]
    file_len48 = struct.unpack('<Q', suffix[48:56])[0]
    file_off32 = struct.unpack('<Q', suffix[32:40])[0]
    file_len40 = struct.unpack('<Q', suffix[40:48])[0]
    print(f"\nEntry[1] ovh={ovh}: fn='{fn}' fn_len={fn_len}")
    print(f"  suffix[:16]={cr0} {cr0_match}")
    print(f"  suffix[8:24]={cr8} {cr8_match}")
    print(f"  fileOff@s[40:48]={file_off40} fileLen@s[48:56]={file_len48}")
    print(f"  fileOff@s[32:40]={file_off32} fileLen@s[40:48]={file_len40}")
    if cr0_match:
        print(f"  *** chunkRef at +0 matches! Use this layout for subsequent entries (no hash)")
    if cr8_match:
        print(f"  *** chunkRef at +8 matches! Use hash(8)+chunkRef layout")

print("\nFor reference, check raw fn bytes:")
off = e1_off + 7
raw_fn = plain[off:off+60]
print(f"  At off+7 (= {e1_off+7}): {raw_fn.hex()}")
print(f"  First 36 bytes as ascii: {raw_fn[:36]}")
print(f"  First 36 decoded: {raw_fn[:36].decode('ascii', errors='replace')}")
