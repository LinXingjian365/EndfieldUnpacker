import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct

key = vfs_key()
vfs = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

# Check CHK content structure for 1CDDBF1F (BundleManifest)
dp = os.path.join(vfs, '1CDDBF1F')
chk_path = os.path.join(dp, 'C145B7B3250353118F269EA800D8208E.chk')
chk_size = os.path.getsize(chk_path)
print(f'CHK file size: {chk_size}', flush=True)

with open(chk_path, 'rb') as f:
    chk_data = f.read()

# Check first and last bytes
print(f'First 64 bytes:', flush=True)
for i in range(0, min(64, len(chk_data)), 16):
    chunk = chk_data[i:i+16]
    h = ' '.join(f'{b:02x}' for b in chunk)
    a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f'  {i:04x}: {h:48s} {a}', flush=True)

# Try to see if the bundle manifest hgmmap data is directly readable
# The hgmmap format typically starts with a header
# Check if there's a known pattern at the start
if chk_size > 4:
    u32_1 = struct.unpack('<I', chk_data[0:4])[0]
    print(f'\nFirst u32: {u32_1} (0x{u32_1:08x})', flush=True)
    print(f'Size matches CHK file: {chk_size == u32_1}', flush=True)

# Check BLC decrypted for 1CDDBF1F  
blc_path = os.path.join(dp, '1CDDBF1F.blc')
with open(blc_path, 'rb') as f:
    blc_raw = f.read()
nonce = blc_raw[:12]
enc = blc_raw[12:]
c = ChaCha20.new(key=key, nonce=nonce)
c.decrypt(b'\x00' * 64)
blc_data = c.decrypt(enc)

# The BLC has: header(44) + chunk(45) = 89 bytes before file data
# Then file data starts at 0x59
header_size = 0x2C  # 44 bytes to end of totalValue
chunk_info_size = 45  # blockType(1)+ver(4)+chunkMd5(16)+contentMD5(16)+chunkLength(8)
file_start = header_size + chunk_info_size
print(f'\nFile data starts at offset 0x{file_start:04x} in BLC', flush=True)
print(f'BLC data at offset 0x{file_start:04x}: {blc_data[file_start:file_start+16].hex()}', flush=True)

# After chunk header in BLC, the first bytes should tell us about the file entry structure
# Fields we know from CBT3: bUseEncrypt, ivSeed, offset, len, fileChunkMD5Name, fileDataMD5, fileNameHash, fileName

# The BLC is 220 bytes total. After header(44) + chunk header(45) = 89 bytes, we have 131 bytes
# Filename "Data/Bundles/Windows/manifest.hgmmap" = 36 bytes
# So the file entry header (before filename) is 131-36 = 95 bytes
# Or 131 = fileEntryHeader(unknown) + 36 or more structure

# Let me look at what comes after the chunk header
remaining = blc_data[0x59:]
print(f'\nRemaining BLC data ({len(remaining)} bytes):', flush=True)
for i in range(0, len(remaining), 16):
    chunk = remaining[i:i+16]
    h = ' '.join(f'{b:02x}' for b in chunk)
    a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f'  {i:04x}: {h:48s} {a}', flush=True)

# Check if the BLC stores "offset" within CHK somewhere
# For BundleManifest, there's only 1 chunk with 1 CHK file, and 1 file in it
# The file offset should be 0 (start of CHK)
# Looking for a u32 field = 0 followed by u32 field = chunk_length or file_length

# Try: u8 blockType(u8=4), u32(1), u32(1), u16 fnLen(36=0x24), fn(36),
# Then 8 bytes hash, then 16 bytes chunkMd5, 16 bytes contentMD5, 8 bytes chunkLen
# Then more data

if len(remaining) > 0x59:
    print(f'\nDetailed analysis of remaining data:', flush=True)
    print(f'  0x00: blockType(u8) = {remaining[0]}', flush=True)
    print(f'  0x01-0x04: u32 = {struct.unpack("<I", remaining[1:5])[0]}', flush=True)
    print(f'  0x05-0x08: u32 = {struct.unpack("<I", remaining[5:9])[0]}', flush=True)
    print(f'  0x09-0x0A: u16 fnLen = {struct.unpack("<H", remaining[9:11])[0]}', flush=True)
    fn_len = struct.unpack('<H', remaining[9:11])[0]
    fn_end = 11 + fn_len
    fn = remaining[11:fn_end].decode('ascii')
    print(f'  0x0B-0x{fn_end-1:04x}: fn = "{fn}"', flush=True)
    
    # After filename
    after_fn = remaining[fn_end:]
    print(f'\n  After filename ({len(after_fn)} bytes):', flush=True)
    for i in range(0, len(after_fn), 16):
        chunk = after_fn[i:i+16]
        h = ' '.join(f'{b:02x}' for b in chunk)
        a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'    {i:04x}: {h:48s} {a}', flush=True)
