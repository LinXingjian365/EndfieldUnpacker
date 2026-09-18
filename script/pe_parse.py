import struct, os, sys

ga = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\GameAssembly.dll'
with open(ga, 'rb') as f:
    data = f.read()

if data[:2] != b'MZ':
    print('Not a PE file', flush=True)
    sys.exit(1)

e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
print(f'PE at 0x{e_lfanew:x}', flush=True)
assert data[e_lfanew:e_lfanew+4] == b'PE\x00\x00'

file_hdr = data[e_lfanew+4:e_lfanew+24]
machine = struct.unpack('<H', file_hdr[0:2])[0]
num_sections = struct.unpack('<H', file_hdr[2:4])[0]
print(f'Machine=0x{machine:x} Sections={num_sections}', flush=True)

opt_start = e_lfanew + 24
magic = struct.unpack('<H', data[opt_start:opt_start+2])[0]
print(f'PE32+={magic==0x20b}', flush=True)

if magic == 0x20b:
    dd_start = opt_start + 112
else:
    dd_start = opt_start + 96

# Section headers
sec_size = magic == 0x20b and 112 or 96
sec_start = e_lfanew + 24 + sec_size + 4

sections = []
for i in range(num_sections):
    ss = sec_start + i * 40
    sname = data[ss:ss+8]
    svsize = struct.unpack('<I', data[ss+8:ss+12])[0]
    srva = struct.unpack('<I', data[ss+12:ss+16])[0]
    srsize = struct.unpack('<I', data[ss+16:ss+20])[0]
    srptr = struct.unpack('<I', data[ss+20:ss+24])[0]
    sname_str = sname.rstrip(b'\x00').decode('latin-1')
    sections.append((sname_str, srva, svsize, srptr, srsize))
    print(f'  {sname_str}: RVA=0x{srva:08x} VSize=0x{svsize:x} RPtr=0x{srptr:x} RSize=0x{srsize:x}', flush=True)

def rva2off(rva):
    for name, srva, svsize, srptr, srsize in sections:
        if srva <= rva < srva + max(svsize, srsize):
            return rva - srva + srptr
    return None

# Import directory
num_dirs = struct.unpack('<I', data[dd_start-4:dd_start])[0]
print(f'\nData directories: {num_dirs}', flush=True)
for i in range(num_dirs):
    drva = struct.unpack('<I', data[dd_start+i*8:dd_start+i*8+4])[0]
    dsz = struct.unpack('<I', data[dd_start+i*8+4:dd_start+i*8+8])[0]
    if drva:
        print(f'  [{i}] RVA=0x{drva:x} Size=0x{dsz:x}', flush=True)

# Import: index 1
import_rva = struct.unpack('<I', data[dd_start+1*8:dd_start+1*8+4])[0]
import_sz = struct.unpack('<I', data[dd_start+1*8+4:dd_start+1*8+8])[0]
print(f'\nImport directory at RVA=0x{import_rva:x}, size={import_sz}', flush=True)

import_off = rva2off(import_rva)
if import_off:
    print(f'Import at file offset 0x{import_off:x}', flush=True)
    off = import_off
    while True:
        ilt = struct.unpack('<I', data[off:off+4])[0]
        ts = struct.unpack('<I', data[off+4:off+8])[0]
        fc = struct.unpack('<I', data[off+8:off+12])[0]
        nrva = struct.unpack('<I', data[off+12:off+16])[0]
        iat = struct.unpack('<I', data[off+16:off+20])[0]
        
        if nrva == 0 and ilt == 0:
            break
        
        noff = rva2off(nrva)
        if noff:
            dll_name = data[noff:data.index(b'\x00', noff)].decode('latin-1')
            print(f'  DLL: "{dll_name}"', flush=True)
            
            # Parse ILT
            ilt_off = rva2off(ilt)
            if ilt_off:
                func_count = 0
                while True:
                    entry = struct.unpack('<Q', data[ilt_off:ilt_off+8])[0]
                    if entry == 0:
                        break
                    if entry & 0x8000000000000000:  # Ordinal
                        ord = entry & 0xFFFF
                        func_count += 1
                        if func_count <= 5:
                            print(f'    [ordinal {ord}]', flush=True)
                    else:
                        # Import by name
                        hint_off = rva2off(entry & 0x7FFFFFFF)
                        if hint_off:
                            hint = struct.unpack('<H', data[hint_off:hint_off+2])[0]
                            func_name = data[hint_off+2:data.index(b'\x00', hint_off+2)].decode('latin-1')
                            func_count += 1
                            if func_count <= 5:
                                print(f'    [{func_count}] {func_name}', flush=True)
                            # Check for ChaCha
                            if 'cha' in func_name.lower() or 'Cha' in func_name:
                                print(f'    *** ARK FOUND: {func_name}', flush=True)
                print(f'    Total: {func_count} imports', flush=True)
        
        off += 20
