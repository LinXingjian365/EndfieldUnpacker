import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct, os, sys

KEY = vfs_key()
VFS = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

def dump_region(plain, start, length, label):
    hex_part = plain[start:start+length].hex()
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in plain[start:start+length])
    print(f'{label} @ {start}:')
    for i in range(0, len(hex_part), 64):
        line_off = start + i//2
        print(f'  {line_off:04x}: {hex_part[i:i+64]:64s} {ascii_part[i//2:i//2+32]}')

def verify_entry(plain, off, block_type, ovh, cr_off, chk_map):
    """Check if entry at 'off' parsers with given ovh/cr_off and returns valid chunk_ref + offsets."""
    fn_len_off = off + ovh - 2
    if fn_len_off + 2 > len(plain):
        return None
    fn_len = struct.unpack('<H', plain[fn_len_off:fn_len_off+2])[0]
    if fn_len < 2 or fn_len > 500:
        return None
    fn_start = fn_len_off + 2
    if fn_start + fn_len + cr_off + 48 > len(plain):
        return None
    fn = plain[fn_start:fn_start+fn_len]
    if b'/' not in fn or not (fn.startswith(b'Data/') or fn.startswith(b'Assets/') or fn.startswith(b'RawEncrypted/')):
        return None
    
    suffix_start = fn_start + fn_len
    chunk_ref = plain[suffix_start+cr_off:suffix_start+cr_off+16]
    if chunk_ref not in chk_map:
        return None
    file_off = struct.unpack('<Q', plain[suffix_start+cr_off+32:suffix_start+cr_off+40])[0]
    file_len = struct.unpack('<Q', plain[suffix_start+cr_off+40:suffix_start+cr_off+48])[0]
    chk_size = chk_map[chunk_ref][0]
    if file_len <= 0 or file_len > chk_size or file_off < 0 or file_off + file_len > chk_size:
        return None
    return (fn[:80].decode('ascii', errors='replace'), suffix_start + cr_off + 48)


def find_best_ovh(plain, entries_offsets, block_type, chk_map):
    """For a set of entry offsets, find the ovh that consistently produces valid parses."""
    for cr_off_try in [8, 7, 9, 0, 4]:
        for ovh_try in range(8, 30):
            ok = 0
            for e_off in entries_offsets[:20]:
                result = verify_entry(plain, e_off, block_type, ovh_try, cr_off_try, chk_map)
                if result:
                    ok += 1
            if ok >= len(entries_offsets[:20]) * 0.8:
                return (ovh_try, cr_off_try, ok)
    return (None, None, 0)


def scan_entries(plain, start_off, block_type, chk_map, max_entries=30):
    """Scan for type bytes and find entry offsets, then determine ovh/cr_off."""
    # Find all type byte positions
    type_offsets = []
    scan = start_off
    while scan < len(plain) and len(type_offsets) < max_entries:
        if plain[scan] == block_type:
            type_offsets.append(scan)
        scan += 1
    
    # Find best ovh/cr_off
    ovh, cr_off, count = find_best_ovh(plain, type_offsets, block_type, chk_map)
    print(f'  Best: ovh={ovh} cr_off={cr_off} ({count}/{len(type_offsets)} entries valid)')
    
    # Parse and display entries
    entries = []
    off = start_off
    found = 0
    while off < len(plain) - 20 and found < max_entries:
        if plain[off] != block_type:
            off += 1
            continue
        result = verify_entry(plain, off, block_type, ovh, cr_off, chk_map)
        if result:
            fn, next_off = result
            entries.append((off, fn))
            off = next_off
            found += 1
        else:
            off += 1
    
    return entries, ovh, cr_off

blc_name = sys.argv[1] if len(sys.argv) > 1 else '42A8FCA6'
blc_path = os.path.join(VFS, blc_name, f'{blc_name}.blc')
with open(blc_path, 'rb') as f:
    data = f.read()
nonce = data[:12]
c = ChaCha20.new(key=KEY, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(data[12:])

# Parse header
off = 0
ver = struct.unpack('<I', plain[off:off+4])[0]; off += 4
unk1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
name_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
name = plain[off:off+name_len].decode('ascii'); off += name_len
dir_hash = struct.unpack('<I', plain[off:off+4])[0]; off += 4
flag = struct.unpack('<i', plain[off:off+4])[0]; off += 4
file_cnt = struct.unpack('<I', plain[off:off+4])[0]; off += 4
block_size = struct.unpack('<Q', plain[off:off+8])[0]; off += 8

print(f'{blc_name} ({name}): {file_cnt} files, header ends at off={off}, plain={len(plain)}B')

# Build chk_map
chk_dir = os.path.join(VFS, blc_name)
chk_map = {}
for f in os.listdir(chk_dir):
    if f.endswith('.chk'):
        md5 = bytes.fromhex(f[:-4])
        chk_map[md5] = (os.path.getsize(os.path.join(chk_dir, f)), os.path.join(chk_dir, f))
print(f'CHK files: {len(chk_map)}')

# First chunk header
bt = plain[off]
ver_chk = struct.unpack('<I', plain[off+1:off+5])[0]
print(f'First chunk header at {off}: type={bt} ver={ver_chk}')
dump_region(plain, off, 45, 'chunk_header')
dump_region(plain, off+45, 200, 'post_header')

# Try multiple ovh/cr_off combos systematically
print(f'\n--- Systematic ovh/cr_off search (type={bt}) ---')
best_ovh = None
best_cr = None
best_count = 0
found_any = False
for cr_try in [8, 7, 0, 4, 9]:
    for ovh_try in range(8, 30):
        count = 0
        first_fns = []
        scan_off = off + 45
        while scan_off < len(plain) - 20 and count < 30:
            if plain[scan_off] != bt:
                scan_off += 1
                continue
            fn_len_off = scan_off + ovh_try - 2
            if fn_len_off + 2 > len(plain):
                scan_off += 1
                continue
            fn_len = struct.unpack('<H', plain[fn_len_off:fn_len_off+2])[0]
            if fn_len < 2 or fn_len > 500:
                scan_off += 1
                continue
            fn_start = fn_len_off + 2
            if fn_start + fn_len + cr_try + 48 > len(plain):
                scan_off += 1
                continue
            fn = plain[fn_start:fn_start+fn_len]
            if b'/' not in fn or not (fn.startswith(b'Data/') or fn.startswith(b'Assets/')):
                scan_off += 1
                continue
            
            suffix_start = fn_start + fn_len
            chunk_ref = plain[suffix_start+cr_try:suffix_start+cr_try+16]
            if chunk_ref not in chk_map:
                scan_off += 1
                continue
            file_off = struct.unpack('<Q', plain[suffix_start+cr_try+32:suffix_start+cr_try+40])[0]
            file_len = struct.unpack('<Q', plain[suffix_start+cr_try+40:suffix_start+cr_try+48])[0]
            chk_size = chk_map[chunk_ref][0]
            if file_len <= 0 or file_len > chk_size or file_off < 0 or file_off + file_len > chk_size:
                scan_off += 1
                continue
            
            # Valid entry found!
            count += 1
            if len(first_fns) < 5:
                first_fns.append(fn[:60].decode('ascii', errors='replace'))
            scan_off = suffix_start + cr_try + 48
        
        if count > best_count:
            best_count = count
            best_ovh = ovh_try
            best_cr = cr_try
            found_fns = first_fns
            found_any = True
    
    if best_count >= 10:
        break

if found_any:
    print(f'  Best: ovh={best_ovh} cr_off={best_cr} ({best_count} valid entries)')
    for fn in found_fns:
        print(f'    {fn}')
else:
    print(f'  Could not find any valid ovh/cr_off combination')
    # Try also with first-entry format (ovh=11)
    print(f'  Checking first-entry format (ovh=11, cr_off=8)...')
    cnt = 0
    scan_off = off + 45
    while scan_off < len(plain) - 20 and cnt < 10:
        if plain[scan_off] != bt:
            scan_off += 1
            continue
        # Try first-entry format: type+f1+fieldX+fnLen = 11 bytes
        for fn_len_pos in [9, 10, 11, 12, 13, 14]:
            fn_len_off = scan_off + fn_len_pos
            if fn_len_off + 2 > len(plain):
                continue
            fn_len = struct.unpack('<H', plain[fn_len_off:fn_len_off+2])[0]
            if fn_len < 2 or fn_len > 500:
                continue
            fn_start = fn_len_off + 2
            if fn_start + fn_len > len(plain):
                continue
            fn = plain[fn_start:fn_start+fn_len]
            if b'/' not in fn or not fn.startswith(b'Data/'):
                continue
            print(f'  Found possible entry at {scan_off}: fnLenOff={fn_len_pos} fnLen={fn_len} fn={fn[:60]}')
            scan_off = fn_start + fn_len + 56  # skip suffix
            cnt += 1
            break
