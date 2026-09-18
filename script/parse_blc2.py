import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct, os

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

def parse_vf_block(plain):
    off = 0
    ver = struct.unpack('<I', plain[off:off+4])[0]
    off += 4
    unk1 = struct.unpack('<I', plain[off:off+4])[0]
    off += 4
    name_len = struct.unpack('<H', plain[off:off+2])[0]
    off += 2
    name = plain[off:off+name_len].decode('ascii')
    off += name_len
    dir_hash = struct.unpack('<I', plain[off:off+4])[0]
    off += 4
    flag = struct.unpack('<i', plain[off:off+4])[0]
    off += 4
    chunk_cnt = struct.unpack('<I', plain[off:off+4])[0]
    off += 4
    total_val = struct.unpack('<Q', plain[off:off+8])[0]
    off += 8
    
    chunks = []
    
    for ci in range(chunk_cnt):
        if off + 1 > len(plain):
            break
        
        block_type = plain[off]
        off += 1
        chunk_ver = struct.unpack('<I', plain[off:off+4])[0]
        off += 4
        
        if off + 32 > len(plain):
            break
        chunk_md5 = plain[off:off+16]
        off += 16
        content_md5 = plain[off:off+16]
        off += 16
        
        chunk_len = struct.unpack('<Q', plain[off:off+8])[0]
        off += 8
        
        files = []
        while off < len(plain):
            # Check if next byte starts a new chunk
            if off + 5 <= len(plain):
                next_byte = plain[off]
                pot_ver = struct.unpack('<I', plain[off+1:off+5])[0]
                # Heuristic: a new chunk starts with blockType (usually <= 30) and version (usually 1 or 2)
                if ci < chunk_cnt - 1 and next_byte <= 30 and (pot_ver == 1 or pot_ver == 2):
                    break
            
            # Try to parse a file entry
            if off + 16 > len(plain):
                break
            
            # Check if what follows looks like a fileDataMD5 or a new chunk header
            # A fileDataMD5 is 16 bytes with high entropy (not pattern like small ints)
            first_bytes = plain[off:off+4]
            fv = struct.unpack('<I', first_bytes)[0]
            
            # If next chunk pattern detected
            if ci < chunk_cnt - 1:
                # Check if this is blockType+version (blockType <= 30, version 1-10)
                if plain[off] <= 30:
                    nv = struct.unpack('<I', plain[off+1:off+5])[0]
                    if 0 < nv < 50:
                        break
            
            # If we reach here, assume it's part of the same chunk (repeated chunk header + file)
            # Check for repeated chunk md5 or content md5
            if off + 16 <= len(plain) and ci < chunk_cnt - 1:
                # Maybe this is continuation of same chunk
                pass
            
            # Read file entry
            # fileDataMD5 (16 bytes) 
            file_data_md5 = plain[off:off+16]
            off += 16
            
            # fileChunkMD5Name (16 bytes) - or skip if same as chunk md5
            file_chunk_md5 = plain[off:off+16]
            off += 16
            
            # offset (u64)
            file_off = struct.unpack('<Q', plain[off:off+8])[0]
            off += 8
            
            # len (u32?)
            file_len = struct.unpack('<I', plain[off:off+4])[0]
            off += 4
            
            # bUseEncrypt (u32)
            b_enc = struct.unpack('<I', plain[off:off+4])[0]
            off += 4
            
            # ivSeed (u32 or skipped?)
            # Unknown field
            unk2 = struct.unpack('<I', plain[off:off+4])[0]
            off += 4
            
            # fileNameHash (u64?)
            fn_hash = struct.unpack('<Q', plain[off:off+8])[0]
            off += 8
            
            # fileNameLen (u16)
            fn_len = struct.unpack('<H', plain[off:off+2])[0]
            off += 2
            
            # fileName
            try:
                fn = plain[off:off+fn_len].decode('ascii')
            except:
                fn = f'<binary_{fn_len}bytes>'
            off += fn_len
            
            files.append({
                'fileDataMD5': file_data_md5.hex().upper(),
                'fileChunkMD5': file_chunk_md5.hex().upper(),
                'offset': file_off,
                'len': file_len,
                'bUseEncrypt': b_enc,
                'unk2': unk2,
                'fileNameHash': fn_hash,
                'fileName': fn,
            })
            
            if off >= len(plain):
                break
        
        chunks.append({
            'blockType': block_type,
            'chunkVer': chunk_ver,
            'md5Name': chunk_md5.hex().upper(),
            'contentMD5': content_md5.hex().upper(),
            'length': chunk_len,
            'files': files,
        })
    
    return {
        'version': ver,
        'groupCfgName': name,
        'dirHash': f'{dir_hash:08X}',
        'chunkCount': chunk_cnt,
        'chunks': chunks,
    }

# Test on a few BLCs
test_dirs = ['07A1BB91', '1CDDBF1F', 'D6E622F7']
for d in test_dirs:
    dp = os.path.join(vfs, d)
    if not os.path.isdir(dp):
        continue
    blc_path = os.path.join(dp, f'{d}.blc')
    if not os.path.exists(blc_path):
        continue
    plain = decrypt_blc(blc_path)
    result = parse_vf_block(plain)
    print(f'\n===== {d} =====', flush=True)
    print(f'groupCfgName: {result["groupCfgName"]}', flush=True)
    print(f'chunks: {result["chunkCount"]}', flush=True)
    for ci, c in enumerate(result['chunks']):
        print(f'  Chunk {ci}: type={c["blockType"]} ver={c["chunkVer"]} md5={c["md5Name"]} len={c["length"]}', flush=True)
        print(f'    contentMD5={c["contentMD5"]}', flush=True)
        print(f'    files: {len(c["files"])}', flush=True)
        for fi, f in enumerate(c['files']):
            print(f'      File {fi}: offset={f["offset"]} len={f["len"]} encrypt={f["bUseEncrypt"]} fn="{f["fileName"]}"', flush=True)
