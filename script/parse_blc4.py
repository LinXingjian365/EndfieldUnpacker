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

for blc_name in ['1CDDBF1F', '07A1BB91']:
    plain = decrypt_blc(os.path.join(vfs, blc_name, f'{blc_name}.blc'))
    print(f'===== {blc_name} ({len(plain)} bytes) =====', flush=True)
    
    ver = struct.unpack('<I', plain[0:4])[0]
    unk1 = struct.unpack('<I', plain[4:8])[0]
    name_len = struct.unpack('<H', plain[8:10])[0]
    name = plain[10:10+name_len].decode('ascii')
    print(f'Block: ver={ver} name="{name}"', flush=True)
    
    off = 10 + name_len
    dir_hash = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    flag = struct.unpack('<i', plain[off:off+4])[0]; off += 4
    chunk_cnt = struct.unpack('<I', plain[off:off+4])[0]; off += 4
    total_val = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
    
    for ci in range(chunk_cnt):
        block_type = plain[off]; off += 1
        chunk_ver = struct.unpack('<I', plain[off:off+4])[0]; off += 4
        chunk_md5 = plain[off:off+16]; off += 16
        content_md5 = plain[off:off+16]; off += 16
        chunk_len = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
        print(f'  Chunk {ci}: type={block_type} md5={chunk_md5.hex().upper()} len={chunk_len}', flush=True)
        
        while off < len(plain):
            if off + 5 <= len(plain):
                pt = plain[off]; pv = struct.unpack('<I', plain[off+1:off+5])[0]
                if ci < chunk_cnt - 1 and pt <= 30 and 0 < pv < 100:
                    print(f'    (next chunk at 0x{off:x})', flush=True)
                    break
            if off + 10 > len(plain):
                break
            
            file_type = plain[off]; off += 1
            f1 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
            f2 = struct.unpack('<I', plain[off:off+4])[0]; off += 4
            fn_len = struct.unpack('<H', plain[off:off+2])[0]; off += 2
            fn = plain[off:off+fn_len].decode('ascii', errors='backslashreplace')
            off += fn_len
            
            if off >= len(plain):
                print(f'    File: type={file_type} f1={f1} f2={f2} fn="{fn}" TRUNCATED', flush=True)
                break
            
            fn_hash = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
            
            chunk_ref = b''
            if off + 16 <= len(plain):
                chunk_ref = plain[off:off+16]; off += 16
            
            data_md5 = b''
            if off + 16 <= len(plain):
                data_md5 = plain[off:off+16]; off += 16
            
            file_off = 0
            if off + 8 <= len(plain):
                file_off = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
            
            file_len = 0
            if off + 8 <= len(plain):
                file_len = struct.unpack('<Q', plain[off:off+8])[0]; off += 8
            
            trailer = plain[off:] if off < len(plain) else b''
            
            print(f'    File: type={file_type} f1={f1} f2={f2} fn="{fn}"', flush=True)
            print(f'      hash=0x{fn_hash:016x} chunkRef={chunk_ref.hex().upper()} dataMD5={data_md5.hex().upper()}', flush=True)
            print(f'      offset={file_off} len={file_len}', flush=True)
            if trailer:
                # Try to interpret trailer as bUseEncrypt(u32) + maybe ivSeed(u32)
                if len(trailer) >= 4:
                    b_enc = struct.unpack('<I', trailer[0:4])[0]
                    print(f'      trailer[0:4] as bUseEncrypt = {b_enc}', flush=True)
                if len(trailer) >= 8:
                    v_seed = struct.unpack('<I', trailer[4:8])[0]
                    print(f'      trailer[4:8] as ivSeed = {v_seed}', flush=True)
    print()
