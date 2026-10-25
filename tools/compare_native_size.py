"""Compare public native translation units without linking or deploying firmware."""
from pathlib import Path
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
CC = os.environ.get('LLVM_CLANG') or shutil.which('clang')
if not CC:
    raise SystemExit('Set LLVM_CLANG to an ARM-target-capable clang')
P = Path('work/uv310-wireguard')
flags = ['--target=arm-none-eabi', '-mcpu=cortex-m3', '-mthumb', '-Oz',
         '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
         '-ffunction-sections', '-fdata-sections', '-DBYTE_ORDER=1234',
         '-DLITTLE_ENDIAN=1234', '-DBOUNDED_REKEY_LAB']
rows = {}
with tempfile.TemporaryDirectory(prefix='uv310-native-size-') as tmp:
    for branch in ('rekey-memory', 'rekey-pressure'):
        n = P / branch
        fixture = ROOT / n / 'native-config.h'
        assert '203,0,113,7' in fixture.read_text(), 'Public fixture required'
        includes = [n, P/'rng-provider', P/'wg-port/build', P/'wg-port/include',
                    P/'wg-port', P/'wg-port/upstream/src']
        out = Path(tmp) / (branch + '.o')
        subprocess.run([CC, *flags, *['-I'+str(p) for p in includes], '-c',
                        str(n/'native.c'), '-o', str(out)], cwd=ROOT, check=True)
        elf = ELFFile(io.BytesIO(out.read_bytes()))
        sections = {s.name: s['sh_size'] for s in elf.iter_sections() if s['sh_flags'] & 2}
        rows[branch] = {
            'source_sha256': hashlib.sha256((ROOT/n/'native.c').read_bytes()).hexdigest(),
            'fixture_sha256': hashlib.sha256(fixture.read_bytes()).hexdigest(),
            'executable_bytes': sum(s['sh_size'] for s in elf.iter_sections() if s['sh_flags'] & 4),
            'writable_allocated_bytes': sum(s['sh_size'] for s in elf.iter_sections() if s['sh_flags'] & 3 == 3),
            'readonly_allocated_bytes': sum(s['sh_size'] for s in elf.iter_sections() if s['sh_flags'] & 2 and not s['sh_flags'] & 5),
            'sections': sections,
        }
metrics = ('executable_bytes', 'writable_allocated_bytes', 'readonly_allocated_bytes')
result = {'scope': 'Public native.c object files, BOUNDED_REKEY_LAB; not linked images or runtime RAM',
          'compiler': subprocess.check_output([CC, '--version'], text=True).splitlines()[0],
          'flags': flags, 'branches': rows,
          'delta_pressure_minus_memory': {k: rows['rekey-pressure'][k]-rows['rekey-memory'][k] for k in metrics},
          'limitations': ['No linker garbage collection, alignment or total firmware/heap estimate',
                          'No ROM allocator, stack high-water or hardware execution',
                          'Synthetic public key material, not a historical deployed binary']}
dest = ROOT/'.test-results'
dest.mkdir(exist_ok=True)
(dest/'native-size-pressure.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({'bytes': {b: {k: v[k] for k in metrics} for b, v in rows.items()},
                  'delta': result['delta_pressure_minus_memory']}, indent=2))
