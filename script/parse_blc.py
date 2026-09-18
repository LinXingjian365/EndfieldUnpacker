import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct, os

key = vfs_key()
vfs = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

d = '07A1BB91'
dp = os.path.join(vfs, d)
blc_file = os.path.join(dp, f'{d}.blc')
chk_files = sorted(f for f in os.listdir(dp) if f.endswith('.chk'))
print(f'Dir {d}: {len(chk_files)} CHK files', flush=True)
for cf in chk_files:
    sz = os.path.getsize(os.path.join(dp, cf))
    print(f'  {cf}: {sz} bytes', flush=True)

# Decrypt BLC
with open(blc_file, 'rb') as f:
    data = f.read()
nonce = data[:12]
enc = data[12:]
c = ChaCha20.new(key=key, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(enc)

print(f'\nBLC decrypted size: {len(plain)}', flush=True)

# Try to parse the binary VFBlockMainInfo
# Based on CBT3 JSON format, the binary structure likely has:
# version (u32) = 4
# groupCfgName (string)
# allChunks (array), each with md5Name, files[], each with offset, len, bUseEncrypt, fileName

off = 0
ver = struct.unpack('<I', plain[off:off+4])[0]
off += 4
print(f'version = {ver}', flush=True)

# Next field: looks like const 0x01512E5F
const_val = struct.unpack('<I', plain[off:off+4])[0]
off += 4

# groupCfgName: length-prefixed string
name_len = struct.unpack('<H', plain[off:off+2])[0]
off += 2
name = plain[off:off+name_len].decode('ascii')
off += name_len
print(f'groupCfgName = "{name}"', flush=True)
print(f'  const = 0x{const_val:08X}', flush=True)

# dirHash
dir_hash = struct.unpack('<I', plain[off:off+4])[0]
off += 4
print(f'  dirHash = 0x{dir_hash:08X}', flush=True)

# flag
flag = struct.unpack('<i', plain[off:off+4])[0]
off += 4
print(f'  flag = {flag}', flush=True)

# chunkCount
chunk_cnt = struct.unpack('<I', plain[off:off+4])[0]
off += 4
print(f'  chunkCount = {chunk_cnt}', flush=True)

# totalValue?
total_val = struct.unpack('<Q', plain[off:off+8])[0]
off += 8
print(f'  totalValue = {total_val}', flush=True)

# per-chunk data
for ci in range(chunk_cnt):
    if off >= len(plain):
        print(f'  Chunk {ci}: ran out of data!', flush=True)
        break
    
    # blockType (u8?)
    block_type = plain[off]
    off += 1
    # version (u32?)
    chunk_ver = struct.unpack('<I', plain[off:off+4])[0]
    off += 4
    
    # chunk md5Name (16 bytes)
    if off + 16 > len(plain):
        break
    chunk_md5 = plain[off:off+16].hex().upper()
    off += 16
    print(f'\n  Chunk {ci}: blockType={block_type} chunkVer={chunk_ver} md5={chunk_md5}', flush=True)
    
    # files in chunk
    file_cnt = 0
    while off < len(plain):
        if off + 16 > len(plain):
            break
        file_md5 = plain[off:off+16].hex().upper()
        off += 16
        if off + 4 > len(plain):
            break
        
        file_offset = struct.unpack('<I', plain[off:off+4])[0]
        off += 4
        if off + 4 > len(plain):
            break
        
        # ??? padding?
        # Might be just advancing until we find a usable field
        
        # Let's try reading 4 bytes as some field
        unknown1 = struct.unpack('<I', plain[off:off+4])[0]
        off += 4
        
        if off + 4 > len(plain):
            break
        file_len = struct.unpack('<I', plain[off:off+4])[0]
        off += 4
        
        if off + 4 > len(plain):
            break
        # bUseEncrypt or ivSeed
        b_encrypt = struct.unpack('<I', plain[off:off+4])[0]
        off += 4
        
        if off + 2 > len(plain):
            break
        fn_len = struct.unpack('<H', plain[off:off+2])[0]
        off += 2
        
        if off + fn_len > len(plain):
            break
        fn = plain[off:off+fn_len].decode('ascii')
        off += fn_len
        
        file_cnt += 1
        print(f'    File {file_cnt}: md5={file_md5} offset={file_offset} unknown1={unknown1} len={file_len} encrypt={b_encrypt} fn="{fn}"', flush=True)
        
        # Check if next file entry starts with a blockType (u8) or directly with chunk/ file md5
        # We need to detect the boundary - maybe there's an 8-byte re-chunk marker?
        if off + 1 <= len(plain):
            next_byte = plain[off]
            if next_byte <= 30:  # likely blockType
                # Check if it looks like a valid blockType by looking ahead
                if off + 5 <= len(plain):
                    pot_type = plain[off]
                    pot_ver = struct.unpack('<I', plain[off+1:off+5])[0]
                    # If pot_ver looks like a version (0-100 or so), it might be next chunk
                    # Otherwise it could be next file in same chunk
                    if pot_ver >= 0 and pot_ver < 100:
                        print(f'      -> Next chunk detected at offset {off} (type={pot_type} ver={pot_ver})', flush=True)
                        break
                    elif off + 16 <= len(plain) and all(b >= 0x20 for b in plain[off:off+16]) == False:
                        # Might be continuing same chunk
                        pass
        
        # After filename, what's the next offset?
        if off < len(plain):
            remaining = min(32, len(plain) - off)
            next_bytes = ' '.join(f'{b:02x}' for b in plain[off:off+remaining])
            print(f'      Next bytes @ {off}: {next_bytes}', flush=True)
    
    print(f'    Total {file_cnt} files in chunk', flush=True)

# Break early after first block
print(f'\nHeader parsing done, remaining {len(plain)-off} bytes', flush=True)
