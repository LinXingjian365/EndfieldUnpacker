import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct, os

KEY = vfs_key()
vfs = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'

for d in sorted(os.listdir(vfs)):
    dp = os.path.join(vfs, d)
    blc = os.path.join(dp, f'{d}.blc')
    if not os.path.exists(blc):
        continue
    with open(blc, 'rb') as f:
        data = f.read()
    if len(data) <= 12:
        continue
    nonce = data[:12]
    c = ChaCha20.new(key=KEY, nonce=nonce)
    c.decrypt(b'\x00' * 64)
    plain = c.decrypt(data[12:])
    
    o = 0
    ver = struct.unpack('<I', plain[o:o+4])[0]; o += 4
    unk1 = struct.unpack('<I', plain[o:o+4])[0]; o += 4
    name_len = struct.unpack('<H', plain[o:o+2])[0]; o += 2
    name = plain[o:o+name_len].decode('ascii', errors='replace'); o += name_len
    dir_hash = struct.unpack('<I', plain[o:o+4])[0]; o += 4
    flag = struct.unpack('<i', plain[o:o+4])[0]; o += 4
    file_cnt = struct.unpack('<I', plain[o:o+4])[0]; o += 4
    block_size = struct.unpack('<Q', plain[o:o+8])[0]; o += 8
    
    if file_cnt == 0:
        continue
    
    bt = plain[o]; ver_chk = struct.unpack('<I', plain[o+1:o+5])[0]
    o += 45  # skip chunk header
    
    typ = plain[o]; f1 = struct.unpack('<I', plain[o+1:o+5])[0]
    fieldX = struct.unpack('<I', plain[o+5:o+9])[0]
    fnl = struct.unpack('<H', plain[o+9:o+11])[0]
    fn0 = plain[o+11:o+11+fnl].decode('ascii', errors='replace').rstrip('\x00')
    e0_end = o + 11 + fnl + 56
    
    # Deeper scan for entry[1] format - try ALL fnLen offsets
    results = []
    for fnlen_off in range(3, 24):
        try:
            if e0_end + fnlen_off + 2 > len(plain):
                continue
            fnl = struct.unpack('<H', plain[e0_end+fnlen_off:e0_end+fnlen_off+2])[0]
            if fnl <= 0 or fnl > 200:
                continue
            fn_start = e0_end + fnlen_off + 2
            if fn_start + fnl + 56 > len(plain):
                continue
            fn = plain[fn_start:fn_start+fnl]
            fn_str = fn.decode('ascii').rstrip('\x00')
            if len(fn_str) >= 8:
                file_off = struct.unpack('<Q', plain[fn_start+fnl+40:fn_start+fnl+48])[0]
                file_len = struct.unpack('<Q', plain[fn_start+fnl+48:fn_start+fnl+56])[0]
                results.append((fnlen_off, fnlen_off+2, fn_str, file_off, file_len))
        except:
            pass
    
    if results:
        best = results[0]
        extra = ''
        if len(results) > 1:
            # check if there's a clear best (most matches at same offset for next entry too)
            # For now, just note there are options
            extra = f' [{len(results)} options]'
        
        e1_next = e0_end + best[1] + fnl + 56
        # verify with entry[2]
        e2_check = ''
        for fnlen_off in range(3, 24):
            try:
                if e1_next + fnlen_off + 2 > len(plain):
                    continue
                fnl2 = struct.unpack('<H', plain[e1_next+fnlen_off:e1_next+fnlen_off+2])[0]
                if fnl2 <= 0 or fnl2 > 200:
                    continue
                fn_start2 = e1_next + fnlen_off + 2
                if fn_start2 + fnl2 + 56 > len(plain):
                    continue
                fn2 = plain[fn_start2:fn_start2+fnl2]
                fn_str2 = fn2.decode('ascii').rstrip('\x00')
                if len(fn_str2) >= 8 and fnlen_off == best[0]:
                    s2 = fn_str2[:40]
                    e2_check = f' [e2 same ovh: OK "{s2}"]'
                    break
            except:
                pass
        
        print(f'{d} {name:20s} bt={bt:2d} ver={ver_chk:4d} fX={fieldX:6d} cnt={file_cnt:6d} | best ovh={best[0]+2:2d}B fn="{best[2]}" off={best[3]} len={best[4]}{extra}{e2_check}')
    else:
        print(f'{d} {name:20s} bt={bt:2d} ver={ver_chk:4d} fX={fieldX:6d} cnt={file_cnt:6d} | NO valid next entry')
