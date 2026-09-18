import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keys import vfs_key
from Crypto.Cipher import ChaCha20
import struct

key = vfs_key()

blc_path = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS\0CE8FA57\0CE8FA57.blc'
with open(blc_path, 'rb') as f:
    data = f.read()

nonce = data[:12]
enc = data[12:]

c = ChaCha20.new(key=key, nonce=nonce)
c.decrypt(b'\x00' * 64)
plain = c.decrypt(enc)

# Let's also look at other BLC files
vfs_dir = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS'
for d in sorted(os.listdir(vfs_dir)):
    dp = os.path.join(vfs_dir, d)
    if not os.path.isdir(dp):
        continue
    for f in os.listdir(dp):
        if f.endswith('.blc'):
            fp = os.path.join(dp, f)
            with open(fp, 'rb') as fh:
                filedata = fh.read()
            n = filedata[:12]
            e = filedata[12:]
            ci = ChaCha20.new(key=key, nonce=n)
            ci.decrypt(b'\x00' * 64)
            p = ci.decrypt(e)
            
            # Parse header
            ver = struct.unpack('<I', p[0:4])[0]
            # Try to get groupCfgName
            # Offset 0x08 might be a string length for the group name
            if len(p) > 128:
                # Look for readable path strings
                readable = []
                for i in range(0x08, min(0x200, len(p))):
                    if p[i] < 0x80 and i + p[i] + 1 < len(p):
                        slen = p[i]
                        if slen > 5 and all(32 <= b < 127 for b in p[i+1:i+1+slen]):
                            s = p[i+1:i+1+slen].decode('ascii', errors='replace')
                            if '/' in s or 'Bundle' in s:
                                readable.append(s)
                print(f'{d}: ver={ver} size={len(p)} groupCfgName={readable[0] if readable else "?"} numEntries={readable[1] if len(readable)>1 else "?"}', flush=True)
            break
