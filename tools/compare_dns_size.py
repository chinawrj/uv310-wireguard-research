"""Compare pressure vs DNS candidate, including the added DHCP translation unit."""
from pathlib import Path
import hashlib,io,json,os,shutil,subprocess,tempfile
from elftools.elf.elffile import ELFFile
ROOT=Path(__file__).resolve().parents[1];P=Path('work/uv310-wireguard')
cc=os.environ.get('LLVM_CLANG') or shutil.which('clang');assert cc
flags=['--target=arm-none-eabi','-mcpu=cortex-m3','-mthumb','-Oz','-ffreestanding','-fno-builtin','-fno-stack-protector','-ffunction-sections','-fdata-sections','-DBYTE_ORDER=1234','-DLITTLE_ENDIAN=1234','-DBOUNDED_REKEY_LAB']
rows={}
with tempfile.TemporaryDirectory(prefix='uv310-dns-size-') as temp:
 for branch in ['rekey-pressure','rekey-dns','rekey-dns-grow']:
  n=P/branch;includes=[n,P/'rng-provider',P/'wg-port/build',P/'wg-port/include',P/'wg-port',P/'wg-port/upstream/src']
  assert '203,0,113,7' in (ROOT/n/'native-config.h').read_text()
  sources=[n/'native.c']+([P/'dhcp-dns/dhcp_dns.c'] if branch in ('rekey-dns','rekey-dns-grow') else [])
  if branch=='rekey-dns-grow':sources.append(P/'dhcp-dns/dhcp_dns_grow.c')
  row={'executable_bytes':0,'writable_allocated_bytes':0,'readonly_allocated_bytes':0,'source_sha256':{}}
  for i,src in enumerate(sources):
   out=Path(temp)/f'{branch}-{i}.o';subprocess.run([cc,*flags,*['-I'+str(x) for x in includes],'-c',str(src),'-o',str(out)],cwd=ROOT,check=True)
   elf=ELFFile(io.BytesIO(out.read_bytes()));row['source_sha256'][str(src)]=hashlib.sha256((ROOT/src).read_bytes()).hexdigest()
   for section in elf.iter_sections():
    size=section['sh_size'];f=section['sh_flags']
    if f&2:row['executable_bytes' if f&4 else ('writable_allocated_bytes' if f&1 else 'readonly_allocated_bytes')]+=size
  rows[branch]=row
keys=['executable_bytes','writable_allocated_bytes','readonly_allocated_bytes'];delta={k:rows['rekey-dns'][k]-rows['rekey-pressure'][k] for k in keys}
result={'scope':'Object-file sums, includes DHCP module for DNS candidate; not linked firmware or runtime memory','branches':rows,'delta_dns_minus_pressure':delta,'delta_growth_minus_dns':{k:rows['rekey-dns-grow'][k]-rows['rekey-dns'][k] for k in keys},'compiler':subprocess.check_output([cc,'--version'],text=True).splitlines()[0],'limitations':['No stock firmware link, alignment/GC or image-capacity validation','No runtime memory/stack high-water or throughput','Hardware not available; native candidate remains undeployed']}
out=ROOT/'.test-results';out.mkdir(exist_ok=True);(out/'native-size-dns.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'delta':delta,'totals':{b:{k:v[k] for k in keys} for b,v in rows.items()}},indent=2))
