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

files_found = 0
chunk_idx = 0
files_remaining_in_chunk = 0

while off < len(plain) and files_found < file_cnt:
    if off + 5 > len(plain):
        break
    
    # Read chunk header
    block_type = plain[off]; off += 1
    chunk_ver = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    chunk_md5 = plain[off:off+16]; off += 16
    content_md5 = plain[off:off+16]; off += 16
    chunk_len = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
    
    chunk_md5_hex = chunk_md5.hex().upper()
    
    # process all files for this chunk
    while off < len(plain) and files_found < file_cnt:
        # Check if we've hit the next chunk header (before exhausting files)
        # Only check if we've consumed at least some files
        if files_remaining_in_chunk == 0 and files_found > 0:
            break
        
        entry_start = off
        file_type = plain[off]; off += 1
        f1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
        
        if files_remaining_in_chunk == 0:
            # First file in chunk - read f2 (file count for this chunk)
            f2 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
            files_remaining_in_chunk = f2
        else:
            f2 = -1
        
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
        files_remaining_in_chunk -= 1
        
        if files_found <= 3 or files_found > file_cnt - 3 or (f2 > 0 and (files_remaining_in_chunk == files_remaining_in_chunk)):
            if f2 > 0:
                print(f'Chunk[{chunk_idx}] first file f2={f2} type={file_type}', flush=True)
    
    chunk_idx += 1
    if chunk_idx > 3:
        break

print(f'\nParsed {chunk_idx} chunks, {files_found} files', flush=True)
print(f'Would need {file_cnt} total', flush=True)
