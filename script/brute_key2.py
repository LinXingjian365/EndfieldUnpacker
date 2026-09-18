"""
Brute-force search with better validation - check first 12 bytes of decrypted JSON.
"""

import struct, os, sys
from Crypto.Cipher import ChaCha20

ga = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\GameAssembly.dll'
eb = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\EndfieldBase.dll'
blc_path = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\Endfield_Data\StreamingAssets\VFS\0CE8FA57\0CE8FA57.blc'

with open(blc_path, 'rb') as f:
    blc_data = f.read()

nonce = blc_data[:12]
enc_data = blc_data[12:]
print(f'BLC: {len(blc_data)} bytes, nonce={nonce.hex()}', flush=True)

# Expected JSON prefix: { " v e r s i o n "
expected_prefix = b'{"version":'
target_ks = bytes([enc_data[i] ^ expected_prefix[i] for i in range(len(expected_prefix))])
print(f'Need keystream = {target_ks.hex()}', flush=True)

# Search both binaries
for binary_name, binary_path in [('GameAssembly.dll', ga), ('EndfieldBase.dll', eb)]:
    print(f'\nSearching {binary_name}...', flush=True)
    with open(binary_path, 'rb') as f:
        binary = f.read()
    
    scan_limit = min(len(binary) - 32, 200 * 1024 * 1024)
    found_count = 0
    
    for offset in range(0, scan_limit, 32):
        if offset % 500000 == 0:
            print(f'  Progress: {offset/1024/1024:.0f}/{scan_limit/1024/1024:.0f} MB', flush=True)
        
        key = binary[offset:offset+32]
        
        # Quick filter: skip if too many repeated bytes or null bytes
        if b'\x00' in key:
            continue
        
        try:
            c = ChaCha20.new(key=key, nonce=nonce)
            c.decrypt(b'\x00' * 64)  # counter=1
            ks = c.decrypt(bytes(len(expected_prefix)))
        except:
            continue
        
        if ks == target_ks:
            found_count += 1
            print(f'\n*** MATCH #{found_count} at 0x{offset:x} ***', flush=True)
            print(f'  Key: {key.hex().upper()}', flush=True)
            
            # Full decrypt of first 128 bytes
            c2 = ChaCha20.new(key=key, nonce=nonce)
            c2.decrypt(b'\x00' * 64)
            dec = c2.decrypt(enc_data[:128])
            # Check if it's valid JSON
            try:
                text = dec.decode('utf-8')
                print(f'  Decoded: {text[:128]}', flush=True)
            except:
                print(f'  Raw: {dec[:64].hex()}', flush=True)
            
            if found_count >= 10:
                break

print(f'\nDone. Total matches found: {found_count}', flush=True)
