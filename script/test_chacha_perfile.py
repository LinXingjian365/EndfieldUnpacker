import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
"""
Test per-file ChaCha20 decryption for JsonData VFS entries.
Based on fluffy-dumper's parser.rs + loader.rs logic.
"""
from Crypto.Cipher import ChaCha20
import struct, os, re

KEY = vfs_key()
VFS = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'
VFS_PROTO_VERSION = 3

def decrypt_blc(blc_path):
    with open(blc_path, 'rb') as f:
        data = f.read()
    nonce = data[:12]
    c = ChaCha20.new(key=KEY, nonce=nonce)
    c.decrypt(b'\x00' * 64)
    return c.decrypt(data[12:])

def parse_blc_entries(plain):
    """Parse BLC entries following fluffy-dumper parser.rs logic."""
    off = 0
    raw_version = struct.unpack('<i', plain[off:off+4])[0]; off += 4
    if raw_version < 11:
        code_version = raw_version
        version = struct.unpack('<i', plain[off:off+4])[0]; off += 4
    else:
        code_version = 3
        version = raw_version
    name_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
    name = plain[off:off+name_len].decode('ascii'); off += name_len
    dir_hash = struct.unpack('<q', plain[off:off+8])[0]; off += 8  # group_cfg_hash_name (i64)
    file_cnt = struct.unpack('<i', plain[off:off+4])[0]; off += 4   # group_file_info_num
    chunks_len = struct.unpack('<q', plain[off:off+8])[0]; off += 8
    block_type = plain[off]; off += 1
    chunk_count = struct.unpack('<i', plain[off:off+4])[0]; off += 4
    chunks = []
    for ci in range(chunk_count):
        chunk_md5 = plain[off:off+16]; off += 16
        content_md5 = plain[off:off+16]; off += 16
        length = struct.unpack('<q', plain[off:off+8])[0]; off += 8
        chunk_bt = plain[off]; off += 1
        if code_version > 3:
            main_tag = plain[off]; off += 4  # actually i32 but we only need low byte
        file_count = struct.unpack('<i', plain[off:off+4])[0]; off += 4
        files = []
        for fi in range(file_count):
            fn_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
            raw_fn = plain[off:off+fn_len]; off += fn_len
            fn = raw_fn.decode('ascii', errors='replace')
            fn_hash = struct.unpack('<q', plain[off:off+8])[0]; off += 8
            file_chunk_md5 = plain[off:off+16]; off += 16
            file_data_md5 = plain[off:off+16]; off += 16
            file_off = struct.unpack('<q', plain[off:off+8])[0]; off += 8
            file_len = struct.unpack('<q', plain[off:off+8])[0]; off += 8
            file_bt = plain[off]; off += 1
            use_encrypt = plain[off] != 0; off += 1
            iv_seed = 0
            if use_encrypt:
                iv_seed = struct.unpack('<q', plain[off:off+8])[0]; off += 8
            if code_version > 3:
                file_tag = plain[off]; off += 4
            files.append({
                'name': fn,
                'chunk_md5': file_chunk_md5,
                'data_md5': file_data_md5,
                'offset': file_off,
                'length': file_len,
                'use_encrypt': use_encrypt,
                'iv_seed': iv_seed,
            })
        chunks.append({
            'md5': chunk_md5,
            'length': length,
            'files': files,
        })
    return {'name': name, 'version': version, 'block_type': block_type, 'code_version': code_version,
            'chunks': chunks}

def decrypt_chunk_data(data, iv_seed):
    """Per-file ChaCha20 decryption matching fluffy-dumper."""
    nonce = struct.pack('<i', VFS_PROTO_VERSION) + struct.pack('<q', iv_seed)
    c = ChaCha20.new(key=KEY, nonce=nonce)
    c.decrypt(b'\x00' * 64)  # skip first 64 bytes
    return c.decrypt(data)

# Find JsonData block dir (775A31D1)
json_dir = None
for d in os.listdir(VFS):
    dp = os.path.join(VFS, d)
    if os.path.isdir(dp) and os.path.exists(os.path.join(dp, f'{d}.blc')):
        blc_path = os.path.join(dp, f'{d}.blc')
        with open(blc_path, 'rb') as f:
            hdr = f.read(4)
        if hdr == b'\x03\x00\x00\x00':  # version 3
            pass  # continue checking
        # Read first 20+ bytes to get name
        with open(blc_path, 'rb') as f:
            data = f.read(200)
        if b'Json' in data or b'json' in data:
            json_dir = d
            print(f"Found JsonData block dir: {d}")
            break

if not json_dir:
    print("JsonData dir not found by name scan, checking all...")
    # Just use 775A31D1
    json_dir = "775A31D1"

dp = os.path.join(VFS, json_dir)
blc_path = os.path.join(dp, f'{json_dir}.blc')

print(f"\nParsing BLC: {blc_path}")
plain = decrypt_blc(blc_path)
parsed = parse_blc_entries(plain)
print(f"Block: {parsed['name']}, chunks: {len(parsed['chunks'])}")

# Find first encrypted JSON file
for ci, chunk in enumerate(parsed['chunks']):
    for fi, file in enumerate(chunk['files']):
        if file['use_encrypt'] and file['length'] > 0:
            print(f"\nFirst encrypted file: chunk[{ci}] file[{fi}]")
            print(f"  Name: {file['name']}")
            print(f"  Offset: {file['offset']}, Length: {file['length']}")
            print(f"  IV seed: {file['iv_seed']}")
            print(f"  Chunk MD5: {file['chunk_md5'].hex().upper()}")
            
            # Read raw data from CHK
            chunk_md5_hex = file['chunk_md5'].hex().upper()
            chk_path = os.path.join(dp, f'{chunk_md5_hex}.chk')
            if os.path.exists(chk_path):
                with open(chk_path, 'rb') as f:
                    f.seek(file['offset'])
                    raw_data = f.read(file['length'])
                print(f"  Raw data ({len(raw_data)} bytes): first 32 hex = {raw_data[:32].hex()}")
                
                # Decrypt
                decrypted = decrypt_chunk_data(raw_data, file['iv_seed'])
                print(f"  Decrypted ({len(decrypted)} bytes): first 32 hex = {decrypted[:32].hex()}")
                
                # Check if JSON
                try:
                    text = decrypted.decode('utf-8')
                    print(f"  Decrypted text ({len(text)} chars):")
                    print(f"  {text[:300]}")
                except:
                    print(f"  Not UTF-8, first 64 hex: {decrypted[:64].hex()}")
            else:
                print(f"  CHK file not found: {chk_path}")
            break
    else:
        continue
    break
