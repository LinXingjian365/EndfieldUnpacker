import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct, os, json

key = vfs_key()
vfs = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

def decrypt_blc(blc_path):
    with open(blc_path, 'rb') as f:
        data = f.read()
    nonce = data[:12]
    enc = data[12:]
    c = ChaCha20.new(key=key, nonce=nonce)
    c.decrypt(b'\x00' * 64)
    return c.decrypt(enc)

# Test accurate parsing on multiple BLCs
for blc_name in ['1CDDBF1F', '07A1BB91', '0CE8FA57']:
    plain = decrypt_blc(os.path.join(vfs, blc_name, f'{blc_name}.blc'))
print(f'Size: {len(plain)}', flush=True)

# ---- Block header ----
ver = struct.unpack('<I', plain[0:4])[0]
unk1 = struct.unpack('<I', plain[4:8])[0]
name_len = struct.unpack('<H', plain[8:10])[0]
name = plain[10:10+name_len].decode('ascii')
print(f'Block: ver={ver} unk1=0x{unk1:08x} name="{name}"', flush=True)

off = 10 + name_len
dir_hash = struct.unpack('<I', plain[off:off+4])[0]
off += 4
flag = struct.unpack('<i', plain[off:off+4])[0]
off += 4
chunk_cnt = struct.unpack('<I', plain[off:off+4])[0]
off += 4
total_val = struct.unpack('<Q', plain[off:off+8])[0]
off += 8
print(f'  dirHash=0x{dir_hash:08X} flag={flag} chunkCnt={chunk_cnt} totalVal={total_val}', flush=True)

# ---- Process each chunk ----
for ci in range(chunk_cnt):
    block_type = plain[off]; off += 1
    chunk_ver = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    chunk_md5 = plain[off:off+16]; off += 16
    content_md5 = plain[off:off+16]; off += 16
    chunk_len = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
    print(f'\nChunk {ci}: type={block_type} ver={chunk_ver} md5={chunk_md5.hex().upper()} len={chunk_len}', flush=True)
    
    # Now we're at the file entry. Let me try to build entries based on what we see
    while off < len(plain):
        # Check if this looks like a new chunk (blockType + valid version)
        if off + 5 <= len(plain):
            pot_type = plain[off]
            pot_ver = struct.unpack('<I', plain[off+1:off+5])[0]
            # A new chunk has blockType (usually <= 30) and version (1-10)
            if ci < chunk_cnt - 1 and pot_type <= 30 and 0 < pot_ver < 100:
                print(f'  (next chunk detected at offset {off})', flush=True)
                break
        
        # Check if remaining data is too small for a file entry
        if off + 10 > len(plain):
            break
        
        # File entry: blockType(u8) + ??? + ??? + fnLen(u16) + fn + trailer
        file_type = plain[off]; off += 1
        file_flag1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
        file_flag2 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
        fn_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
        
        try:
            fn = plain[off:off+fn_len].decode('ascii')
        except:
            fn = f'<binary: {plain[off:off+min(fn_len,40)].hex()}>'
        off += fn_len
        
        if off >= len(plain):
            print(f'  File: type={file_type} flag1={file_flag1} flag2={file_flag2} fn="{fn}" (truncated after fn)', flush=True)
            break
        
        # After filename: fileNameHash(u64) + chunkRef(16) + fileDataMD5(16) + offset(u64) + len(u64)
        fn_hash = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
        
        chunk_ref = plain[off:off+16] if off+16 <= len(plain) else b''; off += min(16, len(plain)-off)
        data_md5 = plain[off:off+16] if off+16 <= len(plain) else b''; off += min(16, len(plain)-off)
        
        file_off = 0
        file_len = 0
        if off + 8 <= len(plain):
            file_off = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
        if off + 8 <= len(plain):
            file_len = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
        
        # Remaining: might be bUseEncrypt(u32) + ivSeed(u32) + ...
        remaining = plain[off:]
        
        print(f'  File: type={file_type} fn="{fn}"', flush=True)
        print(f'    hash=0x{fn_hash:016x} chunkRef={chunk_ref.hex().upper()} dataMD5={data_md5.hex().upper()}', flush=True)
        print(f'    offset={file_off} len={file_len}', flush=True)
        if remaining:
            print(f'    trailer ({len(remaining)} bytes): {remaining.hex()}', flush=True)
        
        # Check if there's another file right after this one
        # trailer might contain bUseEncrypt(u32), ivSeed(u32), and/or next entry

# Remaining data
if off < len(plain):
    rem = plain[off:]
    print(f'\nRemaining ({len(rem)} bytes): {rem.hex()}', flush=True)
