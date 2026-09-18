"""
VFS extractor for Arknights: Endfield.
Proper BLC parser (matching fluffy-dumper parser.rs) + per-file ChaCha20 decryption.

Usage: python decrypt_vfs.py [dry|extract]
"""
from Crypto.Cipher import ChaCha20
import struct, os, sys, re
from config import get_game_dir
from keys import vfs_key

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEY = vfs_key()
_GAME = get_game_dir()
VFS = os.path.join(_GAME, 'Endfield_Data', 'StreamingAssets', 'VFS')
OUT = os.path.join(_SCRIPT_DIR, 'DecryptOutput')
VFS_PROTO_VERSION = 3
BLOCK_HEAD_LEN = 12

def decrypt_blc(blc_path):
    with open(blc_path, 'rb') as f:
        data = f.read()
    nonce = data[:BLOCK_HEAD_LEN]
    c = ChaCha20.new(key=KEY, nonce=nonce)
    c.decrypt(b'\x00' * 64)
    plain = c.decrypt(data[BLOCK_HEAD_LEN:])
    # CRC32 verify (last 4 bytes are CRC of everything before them)
    if len(plain) >= 4:
        expected_crc = struct.unpack('<i', plain[-4:])[0]
        actual_crc = crc32(plain[:-4])
        if expected_crc != actual_crc:
            print(f'  WARNING: CRC mismatch: expected {expected_crc:#x}, got {actual_crc:#x}', flush=True)
        plain = plain[:-4]
    return plain

def crc32(data):
    # Simple CRC32 (matches crc32fast)
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF

def read_i32(plain, off):
    return struct.unpack('<i', plain[off:off+4])[0], off + 4

def read_i64(plain, off):
    return struct.unpack('<q', plain[off:off+8])[0], off + 8

def read_u16(plain, off):
    return struct.unpack('<H', plain[off:off+2])[0], off + 2

def read_u128(plain, off):
    return plain[off:off+16], off + 16

def read_u8(plain, off):
    return plain[off], off + 1

def read_string(plain, off, length):
    return plain[off:off+length].decode('ascii', errors='replace'), off + length

def per_file_decrypt(data, iv_seed):
    """Per-file ChaCha20 decryption (same as fluffy-dumper VfsLoader)."""
    nonce = struct.pack('<i', VFS_PROTO_VERSION) + struct.pack('<q', iv_seed)
    c = ChaCha20.new(key=KEY, nonce=nonce)
    c.decrypt(b'\x00' * 64)
    return c.decrypt(data)

def process_blc(blc_path, dp, chk_map, dry_run):
    """Process one BLC file, extracting all files with per-file decryption."""
    try:
        plain = decrypt_blc(blc_path)
    except Exception as e:
        if dry_run:
            print(f'  BLC decrypt failed: {e}', flush=True)
        return 0

    off = 0
    raw_version, off = read_i32(plain, off)
    if raw_version < 11:
        code_version = raw_version
        version, off = read_i32(plain, off)
    else:
        code_version = 3
        version = raw_version

    name_len, off = read_u16(plain, off)
    name, off = read_string(plain, off, name_len)
    dir_hash, off = read_i64(plain, off)
    file_cnt, off = read_i32(plain, off)
    chunks_len, off = read_i64(plain, off)
    block_type_val, off = read_u8(plain, off)
    chunk_count, off = read_i32(plain, off)

    block_name_map = {1: 'Bundle', 2: 'Audio', 3: 'Video', 4: 'Streaming',
                      5: 'DynamicStreaming', 6: 'Lua', 7: 'Table', 8: 'JsonData',
                      9: 'ExtendData', 10: 'IV', 11: 'InitialAudio',
                      12: 'InitialBundle', 13: 'InitialExtendData',
                      14: 'BundleManifest', 15: 'IFixPatch',
                      16: 'AuditStreaming', 17: 'AuditDynamicStreaming',
                      18: 'AuditIV', 19: 'AuditAudio', 20: 'AuditVideo'}
    block_name = block_name_map.get(block_type_val, f'Unknown({block_type_val})')

    if dry_run:
        print(f'  [{block_name}] {name}: {file_cnt} files, {chunk_count} chunks, code_ver={code_version}', flush=True)

    total = 0
    for ci in range(chunk_count):
        chunk_md5, off = read_u128(plain, off)
        content_md5, off = read_u128(plain, off)
        length, off = read_i64(plain, off)
        chunk_bt_val, off = read_u8(plain, off)
        if code_version > 3:
            main_tag, off = read_i32(plain, off)
        file_count, off = read_i32(plain, off)

        chunk_md5_hex = chunk_md5.hex().upper()
        chk_path = os.path.join(dp, f'{chunk_md5_hex}.chk')
        chk_size = chk_map.get(chunk_md5_hex, 0)

        for fi in range(file_count):
            fn_len, off = read_u16(plain, off)
            raw_fn, off = read_string(plain, off, fn_len)
            fn_hash, off = read_i64(plain, off)
            file_chunk_md5, off = read_u128(plain, off)
            file_data_md5, off = read_u128(plain, off)
            file_off, off = read_i64(plain, off)
            file_len, off = read_i64(plain, off)
            file_bt_val, off = read_u8(plain, off)
            use_encrypt_val, off = read_u8(plain, off)
            use_encrypt = use_encrypt_val != 0
            iv_seed = 0
            if use_encrypt:
                iv_seed, off = read_i64(plain, off)
            if code_version > 3:
                file_tag, off = read_i32(plain, off)

            # Normalize filename
            fn_rel = re.sub(r'[^\x20-\x7e/\\]', '', raw_fn)
            m = re.search(r'(Data/|Assets/)[A-Za-z0-9_./-]+', fn_rel)
            if m:
                fn_rel = m.group(0)
            if fn_rel.startswith('Assets/StreamingAssets/'):
                fn_rel = fn_rel[len('Assets/StreamingAssets/'):]
            elif fn_rel.startswith('Assets/'):
                fn_rel = fn_rel[len('Assets/'):]
            elif fn_rel.startswith('Data/'):
                fn_rel = fn_rel[len('Data/'):]
            if not fn_rel or len(fn_rel) < 2:
                continue

            out_path = os.path.join(OUT, fn_rel)
            valid = file_off + file_len <= chk_size if chk_size > 0 else True

            if dry_run:
                status = 'OK' if valid else 'INVALID'
                enc_flag = ' [ENC]' if use_encrypt else ''
                print(f'    off={file_off} len={file_len} -> "{fn_rel}" {status}{enc_flag}', flush=True)
                total += 1
            elif valid and file_len > 0 and os.path.exists(chk_path):
                dl = min(file_len, max(0, chk_size - file_off))
                if dl > 0:
                    with open(chk_path, 'rb') as f:
                        f.seek(file_off)
                        file_data = f.read(dl)
                    if use_encrypt:
                        file_data = per_file_decrypt(file_data, iv_seed)
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, 'wb') as f:
                        f.write(file_data)
                    total += 1

    if dry_run:
        print(f'    Total: {total}/{file_cnt}', flush=True)
    return total

def extract_vfs(dry_run=True):
    total_files = 0
    dirs = sorted(os.listdir(VFS))

    for d in dirs:
        dp = os.path.join(VFS, d)
        if not os.path.isdir(dp):
            continue
        blc_path = os.path.join(dp, f'{d}.blc')
        if not os.path.exists(blc_path):
            continue

        # Build CHK size map
        chk_map = {}
        for f in os.listdir(dp):
            if f.endswith('.chk'):
                md5 = f[:-4].upper()
                chk_map[md5] = os.path.getsize(os.path.join(dp, f))

        if not chk_map:
            if dry_run:
                print(f'  [{d}] no CHK files', flush=True)
            continue

        total_files += process_blc(blc_path, dp, chk_map, dry_run)

    return total_files

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'dry'
    if mode == 'dry':
        print('=== DRY RUN ===', flush=True)
        total = extract_vfs(dry_run=True)
        print(f'\nTotal files: {total}', flush=True)
    elif mode == 'extract':
        print('=== EXTRACTING FILES ===', flush=True)
        os.makedirs(OUT, exist_ok=True)
        total = extract_vfs(dry_run=False)
        print(f'\nTotal files extracted: {total}', flush=True)
    elif mode == 'test':
        # Test per-file decryption on a specific file
        dp = os.path.join(VFS, '775A31D1')
        blc_path = os.path.join(dp, '775A31D1.blc')
        plain = decrypt_blc(blc_path)
        off = 0
        raw_version, off = read_i32(plain, off)
        code_version = 3 if raw_version >= 11 else raw_version
        if raw_version < 11:
            version, off = read_i32(plain, off)
        else:
            version = raw_version
        name_len, off = read_u16(plain, off)
        name, off = read_string(plain, off, name_len)
        dir_hash, off = read_i64(plain, off)
        file_cnt, off = read_i32(plain, off)
        chunks_len, off = read_i64(plain, off)
        block_type_val, off = read_u8(plain, off)
        chunk_count, off = read_i32(plain, off)
        found = 0
        for ci in range(chunk_count):
            chunk_md5, off = read_u128(plain, off)
            content_md5, off = read_u128(plain, off)
            length, off = read_i64(plain, off)
            chunk_bt_val, off = read_u8(plain, off)
            if code_version > 3:
                main_tag, off = read_i32(plain, off)
            file_count, off = read_i32(plain, off)
            for fi in range(file_count):
                fn_len, off = read_u16(plain, off)
                raw_fn, off = read_string(plain, off, fn_len)
                fn_hash, off = read_i64(plain, off)
                file_chunk_md5, off = read_u128(plain, off)
                file_data_md5, off = read_u128(plain, off)
                file_off, off = read_i64(plain, off)
                file_len, off = read_i64(plain, off)
                file_bt_val, off = read_u8(plain, off)
                use_encrypt_val, off = read_u8(plain, off)
                use_encrypt = use_encrypt_val != 0
                iv_seed = 0
                if use_encrypt:
                    iv_seed, off = read_i64(plain, off)
                if code_version > 3:
                    file_tag, off = read_i32(plain, off)
                if use_encrypt and file_len > 0 and found < 3:
                    chunk_md5_hex = chunk_md5.hex().upper()
                    chk_path = os.path.join(dp, f'{chunk_md5_hex}.chk')
                    if os.path.exists(chk_path):
                        with open(chk_path, 'rb') as f:
                            f.seek(file_off)
                            raw = f.read(file_len)
                        dec = per_file_decrypt(raw, iv_seed)
                        print(f'\n--- File: {raw_fn} ---')
                        print(f'  Encrypted: {use_encrypt}, IV seed: {iv_seed}')
                        print(f'  Raw ({len(raw)}B): {raw[:32].hex()}')
                        print(f'  Dec ({len(dec)}B): {dec[:32].hex()}')
                        try:
                            print(f'  Text: {dec[:200].decode("utf-8")}')
                        except:
                            print(f'  Not UTF-8, first 64: {dec[:64].hex()}')
                        found += 1
        print(f'\nTested {found} encrypted files')
    else:
        print(f'Usage: {sys.argv[0]} [dry|extract|test]', flush=True)
