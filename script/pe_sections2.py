import struct, sys

ga = r'D:\Upan\Hypergryph\Hypergryph Launcher\games\EndField Game\GameAssembly.dll'
with open(ga, 'rb') as f:
    d = f.read()

e_lfanew = struct.unpack('<I', d[0x3C:0x40])[0]
opt_start = e_lfanew + 24
magic = struct.unpack('<H', d[opt_start:opt_start+2])[0]
sec_size = 112 if magic == 0x20b else 96
sec_start = e_lfanew + 24 + sec_size + 4
num_sections = struct.unpack('<H', d[e_lfanew+4+2:e_lfanew+4+4])[0]

lines = []
for i in range(num_sections):
    ss = sec_start + i * 40
    sname_raw = d[ss:ss+8]
    sname_hex = sname_raw.hex()
    svsize = struct.unpack('<I', d[ss+8:ss+12])[0]
    srva = struct.unpack('<I', d[ss+12:ss+16])[0]
    srsize = struct.unpack('<I', d[ss+16:ss+20])[0]
    srptr = struct.unpack('<I', d[ss+20:ss+24])[0]
    sflags = struct.unpack('<I', d[ss+24:ss+28])[0]
    
    is_code = bool(sflags & 0x20)
    is_data = bool(sflags & 0x40)
    is_exec = bool(sflags & 0x20000000)
    is_read = bool(sflags & 0x40000000)
    is_write = bool(sflags & 0x80000000)
    
    flags_parts = []
    if is_code: flags_parts.append('CODE')
    if is_data: flags_parts.append('INIT_DATA')
    if is_exec: flags_parts.append('EXEC')
    if is_read: flags_parts.append('READ')
    if is_write: flags_parts.append('WRITE')
    
    lines.append(f'Sec[{i}] name_hex={sname_hex} RVA=0x{srva:08x} VSize=0x{svsize:x} RPtr=0x{srptr:x} RSize=0x{srsize:x} flags={"|".join(flags_parts)}')

sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)
print('\n'.join(lines))
