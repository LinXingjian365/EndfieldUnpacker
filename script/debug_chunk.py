import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct

KEY = vfs_key()
vfs = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'
dp = vfs + '/F84BF5E6'

with open(dp + '/F84BF5E6.blc', 'rb') as f:
    data = f.read()
nonce = data[:12]
enc = data[12:]
c = ChaCha20.new(key=KEY, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(enc)

off = 0
ver = struct.unpack('<I', plain[off:off+4])[0]; off += 4
unk1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
name_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
name = plain[off:off+name_len].decode('ascii'); off += name_len
dir_hash = struct.unpack('<I', plain[off:off+4])[0]; off += 4
flag = struct.unpack('<i', plain[off:off+4])[0]; off += 4
file_cnt = struct.unpack('<I', plain[off:off+4])[0]; off += 4
block_size = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
print(f'Block: {name}, {file_cnt} files, block_size={block_size}', flush=True)
print(f'Plain size: {len(plain)}', flush=True)

# Parse chunks and find where things go wrong
files_found = 0
chunk_idx = 0
chunk_detected_count = 0

while off < len(plain) and files_found < file_cnt:
    if off + 5 > len(plain):
        break
    
    block_type = plain[off]; off += 1
    chunk_ver = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    chunk_md5 = plain[off:off+16]; off += 16
    content_md5 = plain[off:off+16]; off += 16
    chunk_len = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
    
    chunk_md5_hex = chunk_md5.hex().upper()
    
    print(f'\nChunk {chunk_idx} at 0x{off-45:x}: type={block_type} ver={chunk_ver} md5={chunk_md5_hex[:16]}... len={chunk_len}', flush=True)
    
    files_in_chunk = 0
    while off < len(plain) and files_found < file_cnt:
        if off + 10 > len(plain):
            break
        
        if off + 5 <= len(plain):
            pt = plain[off]
            pv = struct.unpack('<I', plain[off+1:off+5])[0]
            if chunk_idx > 0 or files_in_chunk > 0:
                if pt <= 30 and 0 < pv < 10:
                    if off + 21 <= len(plain):
                        after = plain[off+5:off+21]
                        ascii_cnt = sum(1 for b in after if 32 <= b < 127)
                        if ascii_cnt < 10:
                            chunk_detected_count += 1
                            break
        
        entry_start = off
        file_type = plain[off]; off += 1
        f1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
        
        if files_in_chunk == 0:
            f2_val = struct.unpack('<I', plain[off:off+4])[0]; off += 4
        else:
            f2_val = -1
        
        pad = plain[off]; off += 1
        fn_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
        
        if off + fn_len > len(plain):
            files_found = file_cnt
            break
        
        fn = plain[off:off+fn_len].decode('ascii', errors='replace').rstrip('\x00')
        off += fn_len
        
        if off + 56 > len(plain):
            files_found = file_cnt
            break
        
        fn_hash = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
        chunk_ref = plain[off:off+16]; off += 16
        data_md5 = plain[off:off+16]; off += 16
        file_off = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
        file_len = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
        
        files_found += 1
        files_in_chunk += 1
        
        if files_found <= 5 or files_found % 5000 < 3 or files_found > 18440:
            if files_found > 18440:
                out_rel = fn
                if out_rel.startswith('Data/'):
                    out_rel = out_rel[5:]
                print(f'  [{files_found-1}] @0x{entry_start:x} type={file_type} f1={f1} f2={f2_val} fnLen={fn_len} off={file_off} len={file_len} fn="{out_rel[:60]}"', flush=True)
    
    chunk_idx += 1

print(f'\nTotal files: {files_found}, chunks: {chunk_idx}, chunk detections: {chunk_detected_count}', flush=True)
