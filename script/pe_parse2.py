import struct, os, sys

ga = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\GameAssembly.dll'
with open(ga, 'rb') as f:
    data = f.read()

out_lines = []

def log(s):
    out_lines.append(s)

if data[:2] != b'MZ':
    log('Not a PE file')
    sys.exit(1)

e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
log(f'PE at 0x{e_lfanew:x}')
assert data[e_lfanew:e_lfanew+4] == b'PE\x00\x00'

file_hdr = data[e_lfanew+4:e_lfanew+24]
machine = struct.unpack('<H', file_hdr[0:2])[0]
num_sections = struct.unpack('<H', file_hdr[2:4])[0]
log(f'Machine=0x{machine:x} Sections={num_sections}')

opt_start = e_lfanew + 24
magic = struct.unpack('<H', data[opt_start:opt_start+2])[0]
log(f'PE32+={magic==0x20b}')

if magic == 0x20b:
    dd_start = opt_start + 112
else:
    dd_start = opt_start + 96

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
    sname_hex = sname.hex()
    sections.append((sname, srva, svsize, srptr, srsize))
    log(f'  Sec[{i}] name={sname_hex} RVA=0x{srva:08x} VSize=0x{svsize:x} RPtr=0x{srptr:x} RSize=0x{srsize:x}')

def rva2off(rva):
    for sname, srva, svsize, srptr, srsize in sections:
        if srva <= rva < srva + max(svsize, srsize):
            return rva - srva + srptr
    return None

num_dirs = struct.unpack('<I', data[dd_start-4:dd_start])[0]
log(f'\nData directories: {num_dirs}')
for i in range(num_dirs):
    drva = struct.unpack('<I', data[dd_start+i*8:dd_start+i*8+4])[0]
    dsz = struct.unpack('<I', data[dd_start+i*8+4:dd_start+i*8+8])[0]
    if drva:
        log(f'  [{i}] RVA=0x{drva:x} Size=0x{dsz:x}')

import_rva = struct.unpack('<I', data[dd_start+1*8:dd_start+1*8+4])[0]
import_sz = struct.unpack('<I', data[dd_start+1*8+4:dd_start+1*8+8])[0]
log(f'\nImport directory at RVA=0x{import_rva:x}, size={import_sz}')

import_off = rva2off(import_rva)
if import_off:
    log(f'Import at file offset 0x{import_off:x}')
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
            log(f'  DLL: "{dll_name}"')
            
            ilt_rva = ilt
            if ilt == 0:
                ilt_rva = iat
            ilt_off = rva2off(ilt_rva)
            if ilt_off:
                func_count = 0
                while True:
                    entry = struct.unpack('<Q', data[ilt_off:ilt_off+8])[0]
                    if entry == 0:
                        break
                    func_count += 1
                    if entry & 0x8000000000000000:
                        ord = entry & 0xFFFF
                        if func_count <= 3 or True:
                            log(f'    [{func_count}] ordinal={ord}')
                    else:
                        hint_off = rva2off(entry & 0x7FFFFFFF)
                        if hint_off:
                            hint = struct.unpack('<H', data[hint_off:hint_off+2])[0]
                            fname = data[hint_off+2:data.index(b'\x00', hint_off+2)].decode('latin-1')
                            log(f'    [{func_count}] {fname}')
                log(f'    Total: {func_count} imports')
        
        off += 20

# Write output
out_path = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\unity\zmdobj\pe_info.txt'
with open(out_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(out_lines))
print(f'Wrote to {out_path}', flush=True)
