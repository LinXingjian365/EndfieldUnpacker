"""Extract only the Table (42A8FCA6) and JsonData (775A31D1) directories."""
import sys, os
from config import get_game_dir
from keys import vfs_key

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_SCRIPT_DIR, '..', 'opencode'))

# Replicate decrypt_vfs.py logic with the fixed ENTRY_OVH/ENTRY_CR_OFF
from Crypto.Cipher import ChaCha20
import struct, re

KEY = vfs_key()
_GAME = get_game_dir()
VFS = os.path.join(_GAME, 'Endfield_Data', 'StreamingAssets', 'VFS')
OUT = os.path.join(_SCRIPT_DIR, 'DecryptOutput')

ENTRY_OVH = {17: [16, 8], 18: [11, 16], 19: [11, 16]}
ENTRY_CR_OFF = {18: 8, 19: 8}

def get_chk_sizes(dp):
    sizes = {}
    for f in os.listdir(dp):
        if f.endswith('.chk'):
            sizes[f[:-4].upper()] = os.path.getsize(os.path.join(dp, f))
    return sizes

def decrypt_blc(blc_path):
    with open(blc_path, 'rb') as f:
        data = f.read()
    nonce = data[:12]
    c = ChaCha20.new(key=KEY, nonce=nonce)
    c.decrypt(b'\x00' * 64)
    return c.decrypt(data[12:])

def chunk_header_matches(plain, scan_off, chk_sizes, expected_type=None):
    if scan_off + 45 > len(plain):
        return None
    bt = plain[scan_off]
    if not (1 <= bt <= 30):
        return None
    if expected_type is not None and bt != expected_type:
        return None
    ver = struct.unpack('<I', plain[scan_off+1:scan_off+5])[0]
    if ver > 2048:
        return None
    for md5_off in [5, 6]:
        md5_hex = plain[scan_off+md5_off:scan_off+md5_off+16].hex().upper()
        if md5_hex in chk_sizes:
            return (bt, md5_hex, chk_sizes[md5_hex], md5_off)
    return None

def find_chunk_header(plain, off, chk_sizes, expected_type=None):
    for try_off in range(off, min(off+2, len(plain))):
        result = chunk_header_matches(plain, try_off, chk_sizes, expected_type)
        if result:
            bt, md5_hex, chk_size, md5_off = result
            return (try_off, bt, md5_hex, chk_size)
    scan_limit = min(off + 2000, len(plain))
    scan_off = off
    while scan_off < scan_limit:
        result = chunk_header_matches(plain, scan_off, chk_sizes, expected_type)
        if result:
            bt, md5_hex, chk_size, md5_off = result
            return (scan_off, bt, md5_hex, chk_size)
        scan_off += 1
    return None

def try_read_entry(plain, off, block_type, chk_map, cr_off):
    candidates = ENTRY_OVH.get(block_type, [8])
    if isinstance(candidates, int):
        candidates = [candidates]
    suffix_size = cr_off + 48
    for ovh in candidates:
        if off + ovh + 4 > len(plain):
            continue
        file_type = plain[off]
        if file_type != block_type:
            continue
        fn_len_off = off + ovh - 2
        if fn_len_off + 2 > len(plain):
            continue
        fn_len = struct.unpack('<H', plain[fn_len_off:fn_len_off+2])[0]
        if fn_len < 2 or fn_len > 500:
            continue
        fn_start = fn_len_off + 2
        if fn_start + fn_len + suffix_size > len(plain):
            continue
        try:
            raw_fn = plain[fn_start:fn_start+fn_len]
            null_pos = raw_fn.find(b'\x00')
            if null_pos >= 0:
                raw_fn = raw_fn[:null_pos]
            fn = raw_fn.decode('ascii', errors='replace')
        except:
            continue
        fn_clean = re.sub(r'[^\x20-\x7e/]', '', fn)
        m = re.search(r'(Data/|Assets/)[A-Za-z0-9_./-]+', fn_clean)
        if m:
            fn_clean = m.group(0)
        else:
            continue
        suffix_start = fn_start + fn_len
        chunk_ref = plain[suffix_start + cr_off:suffix_start + cr_off + 16]
        if chunk_ref not in chk_map:
            continue
        file_off = struct.unpack('<Q', plain[suffix_start+cr_off+32:suffix_start+cr_off+40])[0]
        file_len = struct.unpack('<Q', plain[suffix_start+cr_off+40:suffix_start+cr_off+48])[0]
        chk_size = chk_map[chunk_ref][0]
        if file_len <= 0 or file_len > chk_size or file_off < 0 or file_off + file_len > chk_size:
            continue
        return (fn_clean, chunk_ref, suffix_start, ovh, True)
    return (None, None, None, None, False)

def write_file(fn_rel, fn_display, file_off, file_len, chk_size, chk_path, dp):
    fn_rel = re.sub(r'[^\x20-\x7e/\\]', '', fn_rel)
    m = re.search(r'(Data/|Assets/)[A-Za-z0-9_./-]+', fn_rel)
    if m:
        fn_rel = m.group(0)
    if fn_rel.startswith('Assets/StreamingAssets/'):
        fn_rel = fn_rel[len('Assets/StreamingAssets/'):]
    elif fn_rel.startswith('Assets/'):
        fn_rel = fn_rel[len('Assets/'):]
    elif fn_rel.startswith('Data/'):
        fn_rel = fn_rel[len('Data/'):]
    out_path = os.path.join(OUT, fn_rel)
    valid = file_off + file_len <= chk_size
    if valid and file_len > 0:
        dl = min(file_len, max(0, chk_size - file_off))
        if dl > 0:
            with open(chk_path, 'rb') as f:
                f.seek(file_off)
                file_data = f.read(dl)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'wb') as f:
                f.write(file_data)
            print(f'  {fn_display} ({file_len} B)')

def extract_vfs_dir(d):
    dp = os.path.join(VFS, d)
    if not os.path.isdir(dp):
        return
    blc_path = os.path.join(dp, f'{d}.blc')
    if not os.path.exists(blc_path):
        return
    chk_sizes = get_chk_sizes(dp)
    if not chk_sizes:
        return
    print(f'\n[{d}] Processing...')
    
    try:
        plain = decrypt_blc(blc_path)
    except:
        print(f'  BLC decrypt failed')
        return
    
    off = 0
    ver = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    unk1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    name_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
    name = plain[off:off+name_len].decode('ascii'); off += name_len
    dir_hash = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    flag = struct.unpack('<i', plain[off:off+4])[0]; off += 4
    file_cnt = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    block_size = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
    
    if file_cnt == 0:
        return
    
    files_found = 0
    chunk_idx = -1
    processed_chks = set()
    expected_type = None
    
    chk_map = {}
    for chk_md5_hex, chk_size in chk_sizes.items():
        chk_map[bytes.fromhex(chk_md5_hex)] = (chk_size, os.path.join(dp, f'{chk_md5_hex}.chk'))
    
    while off < len(plain) and files_found < file_cnt:
        result = find_chunk_header(plain, off, chk_sizes, expected_type)
        if result is not None:
            chk_off, block_type, chunk_md5_hex, chk_size = result
            if chunk_md5_hex in processed_chks:
                off = chk_off + 1
                continue
            processed_chks.add(chunk_md5_hex)
            off = chk_off
            actual_md5_off = None
            for md5_off in [5, 6]:
                md5_hex = plain[off+md5_off:off+md5_off+16].hex().upper()
                if md5_hex == chunk_md5_hex:
                    actual_md5_off = md5_off
                    break
            if actual_md5_off is None:
                break
            off += actual_md5_off + 16 + 16 + 8  # skip md5 + content_md5 + chunk_len
            expected_type = block_type
            chunk_idx += 1
            cr_off = ENTRY_CR_OFF.get(block_type, 8)
            suffix_size = cr_off + 48
            
            # First entry
            if off + 11 + suffix_size > len(plain):
                break
            file_type = plain[off]
            if file_type != block_type:
                off += 1; continue
            fn_len = struct.unpack('<H', plain[off+9:off+11])[0]
            if off + 11 + fn_len + suffix_size <= len(plain):
                raw_fn = plain[off+11:off+11+fn_len]
                null_pos = raw_fn.find(b'\x00')
                if null_pos >= 0:
                    raw_fn = raw_fn[:null_pos]
                try:
                    fn = raw_fn.decode('ascii', errors='replace')
                except:
                    off += 1; continue
                fn = re.sub(r'[^\x20-\x7e/]', '', fn)
                m = re.search(r'(Data/|Assets/)[A-Za-z0-9_./-]+', fn)
                if m:
                    fn = m.group(0)
                else:
                    off += 1; continue
                if len(fn) < 3 or '/' not in fn:
                    off += 1; continue
                fn_display = fn
                suffix_start = off + 11 + fn_len
                chunk_ref = plain[suffix_start+8:suffix_start+24]
                file_off_val = struct.unpack('<Q', plain[suffix_start+40:suffix_start+48])[0]
                file_len_val = struct.unpack('<Q', plain[suffix_start+48:suffix_start+56])[0]
                chk_info = chk_map.get(chunk_ref, (0, None))
                chk_size_entry, chk_path_entry = chk_info if chk_info[1] else (chk_size, os.path.join(dp, f'{chunk_md5_hex}.chk'))
                files_found += 1
                write_file(fn, fn_display, file_off_val, file_len_val, chk_size_entry, chk_path_entry, dp)
                off = suffix_start + suffix_size
                
                # Remaining entries use entry format
                for _ in range(file_cnt - 1):
                    if off >= len(plain) or files_found >= file_cnt:
                        break
                    fn2, cr2, suffix_start2, ovh_used, ok = try_read_entry(plain, off, block_type, chk_map, cr_off)
                    if not ok:
                        off += 1
                        continue
                    chk_entry = chk_map.get(cr2)
                    if chk_entry is None:
                        off += 1
                        continue
                    chk_size2, chk_path2 = chk_entry
                    file_off2 = struct.unpack('<Q', plain[suffix_start2+cr_off+32:suffix_start2+cr_off+40])[0]
                    file_len2 = struct.unpack('<Q', plain[suffix_start2+cr_off+40:suffix_start2+cr_off+48])[0]
                    fn_display2 = re.sub(r'[^\x20-\x7e/]', '', fn2)
                    m = re.search(r'(Data/|Assets/)[A-Za-z0-9_./-]+', fn_display2)
                    if m:
                        fn_display2 = m.group(0)
                    files_found += 1
                    write_file(fn2, fn_display2, file_off2, file_len2, chk_size2, chk_path2, dp)
                    off = suffix_start2 + suffix_size
            else:
                off += 1
        else:
            # No more chunks — read remaining entries
            if files_found >= file_cnt or expected_type is None:
                break
            cr_off = ENTRY_CR_OFF.get(expected_type, 8)
            suffix_size = cr_off + 48
            while off < len(plain) and files_found < file_cnt:
                fn, chunk_ref, suffix_start, ovh_used, ok = try_read_entry(plain, off, expected_type, chk_map, cr_off)
                if not ok:
                    off += 1
                    continue
                chk_entry = chk_map.get(chunk_ref)
                if chk_entry is None:
                    off += 1
                    continue
                chk_size_entry, chk_path_entry = chk_entry
                file_off_val = struct.unpack('<Q', plain[suffix_start+cr_off+32:suffix_start+cr_off+40])[0]
                file_len_val = struct.unpack('<Q', plain[suffix_start+cr_off+40:suffix_start+cr_off+48])[0]
                fn_display = re.sub(r'[^\x20-\x7e/]', '', fn)
                m = re.search(r'(Data/|Assets/)[A-Za-z0-9_./-]+', fn_display)
                if m:
                    fn_display = m.group(0)
                files_found += 1
                write_file(fn, fn_display, file_off_val, file_len_val, chk_size_entry, chk_path_entry, dp)
                off = suffix_start + suffix_size
    
    print(f'  Written: {files_found}/{file_cnt} files')

if __name__ == '__main__':
    for d in ['42A8FCA6', '775A31D1']:
        extract_vfs_dir(d)
