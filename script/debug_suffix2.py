import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
"""Find actual Table entry format by locating the filename."""
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

dp = os.path.join(VFS, '42A8FCA6')
chks = {f[:-4].upper() for f in os.listdir(dp) if f.endswith('.chk')}
plain = decrypt_blc(os.path.join(dp, '42A8FCA6.blc'))

# Skip block header
off = 0; off += 4; off += 4
name_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
off += name_len; off += 4; off += 4
file_cnt = struct.unpack('<I', plain[off:off+4])[0]; off += 4
off += 8

# Skip chunk header (type+f1+5+chunkMD5+contentMD5+chunkLen)
off += 5 + 16 + 16 + 8  # off=80

# Read entry[0]
t = plain[off]; off += 1
f1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
fieldX = struct.unpack('<I', plain[off:off+4])[0]; off += 4
fn_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
fn0 = plain[off:off+fn_len].decode('ascii').rstrip('\x00')
print(f"Entry[0]: fn='{fn0}' fieldX={fieldX} fn_len={fn_len} end_off={off+fn_len+56}")

# Now locate entry[1] by searching for known filename
# Known filenames from the directory - search for "SkillLevelUpTable.bytes"
target = b'SkillLevelUpTable.bytes'
pos = plain.find(target, off)
print(f"\n'SkillLevelUpTable.bytes' found at BLC offset {pos}")

# The filename is null-terminated, find the start
# Go back from the target to find the full path "Data/TableCfg/SkillLevelUpTable.bytes"
fn_end = pos + len(target)
# Find null at end
while fn_end < len(plain) and plain[fn_end] != 0:
    fn_end += 1
# fn is null-terminated at fn_end
print(f"  fn ends at {fn_end} (byte value: {plain[fn_end]})")

# Find start of fn by going back to before 'Data/'
fn_start = pos
print(f"  Bytes before target: {plain[fn_start-20:fn_start].hex()}")

# Go back further to find 'Data/'
data_pos = plain.find(b'Data/', max(0, fn_start - 100), fn_start)
if data_pos >= 0:
    fn_start = data_pos
    fn_bytes = plain[fn_start:fn_end]
    print(f"  Full fn ({len(fn_bytes)} bytes, includes null): {fn_bytes}")
    print(f"  fn without null: '{fn_bytes.decode('ascii').rstrip('\x00')}'")

    # Now we know: entry starts at some offset before fn_start
    # The entry type byte should be at a position where byte = 18 (0x12)
    # Search backwards for 0x12 within a reasonable range
    for entry_start in range(fn_start - 1, max(0, fn_start - 100), -1):
        if plain[entry_start] == 18:  # type 18 for Table
            print(f"\nCandidate entry at {entry_start}:")
            print(f"  type={plain[entry_start]} f1={struct.unpack('<I', plain[entry_start+1:entry_start+5])[0]}")
            # Check bytes between entry_start and fn_start
            gap = fn_start - entry_start
            print(f"  gap (entry->fn) = {gap} bytes")
            print(f"  Raw bytes [{entry_start}:{entry_start+gap+len(fn_bytes)+10}]: {plain[entry_start:entry_start+gap+len(fn_bytes)+10].hex()}")
            if gap >= 45:
                # Check if bytes [+5:+21] = chunkRef + [+21:+37] = dataMD5 + [+37:+45] = fileOff
                cr = plain[entry_start+5:entry_start+21].hex().upper()
                md5 = plain[entry_start+21:entry_start+37].hex().upper()
                fo = struct.unpack('<Q', plain[entry_start+37:entry_start+45])[0]
                print(f"    bytes[5:21] as chunkRef: {cr} {'IN_CHKS' if cr in chks else ''}")
                print(f"    bytes[21:37] as dataMD5: {md5}")
                print(f"    bytes[37:45] as fileOff: {fo}")
            break
    else:
        print("  No entry start (type=18) found within -100 bytes of fn")
    
    # What comes after fn?
    after_fn = plain[fn_end+1:fn_end+1+56]
    print(f"\n  After fn: {after_fn.hex()}")
    # Check if after_fn[0:8] looks like fileLen (small int)
    fl = struct.unpack('<Q', after_fn[0:8])[0]
    print(f"    bytes[0:8] as fileLen: {fl}")
    # Check if bytes[8:24] is a valid chunkRef
    cr2 = after_fn[8:24].hex().upper()
    print(f"    bytes[8:24] as chunkRef: {cr2} {'IN_CHKS' if cr2 in chks else ''}")
    # Check if bytes[32:40] is fileOff
    fo2 = struct.unpack('<Q', after_fn[32:40])[0]
    print(f"    bytes[32:40] as fileOff: {fo2}")
    # Check if bytes[40:48] is fileLen
    fl2 = struct.unpack('<Q', after_fn[40:48])[0]
    print(f"    bytes[40:48] as fileLen: {fl2}")
else:
    print("  'Data/' not found before target")
