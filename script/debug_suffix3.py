import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
"""Find ALL valid filenames in the Table BLC."""
from Crypto.Cipher import ChaCha20
import struct, os, re

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
plain = decrypt_blc(os.path.join(dp, '42A8FCA6.blc'))
chks = {f[:-4].upper() for f in os.listdir(dp) if f.endswith('.chk')}

# Find all ASCII filenames starting with "Data/TableCfg/"
pattern = re.compile(rb'Data/TableCfg/[A-Za-z0-9_./]+\.bytes\x00')
matches = list(pattern.finditer(plain))
print(f"Found {len(matches)} filenames matching 'Data/TableCfg/*.bytes'")
for m in matches[:10]:
    fn = m.group().decode('ascii').rstrip('\x00')
    off = m.start()
    print(f"  off={off}: '{fn}'")
if len(matches) > 10:
    print(f"  ... and {len(matches)-10} more")

# Now for each match, find the entry start by going backward to type=18
print("\nEntry analysis for each filename:")
for m in matches[:5]:
    fn_off = m.start()
    fn_bytes = m.group()
    fn_str = fn_bytes.decode('ascii').rstrip('\x00')
    print(f"\nFilename at {fn_off}: '{fn_str}' ({len(fn_bytes)} bytes total, fn_len={len(fn_bytes)})")
    
    # Search backward for entry start
    found = False
    for entry_off in range(fn_off - 1, max(0, fn_off - 100), -1):
        if plain[entry_off] == 18:
            gap = fn_off - entry_off
            # Try different entry layouts
            if gap == 11:  # standard: type+f1+fieldX+fnLen
                print(f"  Entry at {entry_off}: type=18, gap={gap} (standard format)")
                print(f"    Raw entry start: {plain[entry_off:entry_off+gap+len(fn_bytes)+20].hex()}")
            elif gap == 7:  # no fieldX, no pad
                print(f"  Entry at {entry_off}: type=18, gap={gap} (no fieldX, no pad)")
            elif gap == 8:  # has pad byte
                print(f"  Entry at {entry_off}: type=18, gap={gap} (has pad)")
            elif gap > 20 and gap < 60:
                print(f"  Entry at {entry_off}: type=18, gap={gap} (large gap -> maybe chunkRef before fn)")
                raw = plain[entry_off:entry_off+gap+len(fn_bytes)+8]
                print(f"    Raw: {raw.hex()}")
            else:
                print(f"  Entry at {entry_off}: type=18, gap={gap}")
            found = True
            break
    if not found:
        print(f"  No entry start (type=18) found nearby")
    
    # What comes after the fn?
    after_fn = plain[fn_off+len(fn_bytes):fn_off+len(fn_bytes)+60]
    print(f"  After fn (60 bytes): {after_fn.hex()}")
    # Check if bytes[0:8] is fileLen (small)
    fl = struct.unpack('<Q', after_fn[0:8])[0]
    print(f"    bytes[0:8] as fileLen: {fl}")
    if fl > 0 and fl < 50000000:
        print(f"    -> Looks like valid fileLen!")
    # Check if bytes[8:24] is chunkRef in chks
    cr = after_fn[8:24].hex().upper()
    print(f"    bytes[8:24] as chunkRef: {cr} {'IN_CHKS' if cr in chks else ''}")

# Also print total BLC size and search for "Data/" pattern
print(f"\n\nBLC size: {len(plain)}")
print(f"Total CHKs: {len(chks)}")
all_fn = [m.group().decode('ascii').rstrip('\x00') for m in matches]
print(f"Sample filenames: {all_fn[:10]}")
