"""Build and extract position-independent ARM code; never accesses USB."""
from pathlib import Path
import hashlib,subprocess
from elftools.elf.elffile import ELFFile
root=Path('outputs/new-dongle-hello')
obj=Path('work/new-dongle-hello/hello-ram.o');obj.parent.mkdir(parents=True,exist_ok=True)
subprocess.run(['clang','--target=arm-none-eabi','-march=armv5te','-marm','-c',str(root/'hello-ram.S'),'-o',str(obj)],check=True)
with obj.open('rb') as f:
    elf=ELFFile(f)
    assert elf['e_machine']=='EM_ARM'
    assert not any(s['sh_type'] in ('SHT_REL','SHT_RELA') and s.num_relocations() for s in elf.iter_sections())
    code=elf.get_section_by_name('.text').data()
assert len(code)==68
assert hashlib.sha256(code).hexdigest()=='5f03e8cc08877b82919123b3a94126967a9c415f43b8cab9a270fae7d8d14b58'
(root/'hello-ram.bin').write_bytes(code)
print('ARM applet rebuilt: 68 bytes, pinned hash matched. This is not a device-execution test.')
