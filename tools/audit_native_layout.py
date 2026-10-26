"""Link public synthetic candidates at original native addresses, never emit firmware.
Temporary ELF files are deleted. Reports the historical deployment ceiling as a
constraint, not a measured heap capacity or proof of device compatibility.
"""
from pathlib import Path
import argparse,hashlib,io,json,os,re,shutil,struct,subprocess,tempfile
from elftools.elf.elffile import ELFFile
ROOT=Path(__file__).resolve().parents[1];P=Path('work/uv310-wireguard');W=P/'wg-port';R=P/'rng-provider';H=P/'control-hardening';S=W/'upstream/src';LAYOUT=P/'rekey-layout/layout.ld'
STOCK_SHA='4b86d71b92529034b2b46da7b93402f67c8aef98d2fc1efa91fc67ff7e5fb85a'
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--stock',type=Path);parser.add_argument('--lto',action='store_true');parser.add_argument('--pool-bytes',type=int,choices=[256,1024],default=1024);parser.add_argument('--out',type=Path,default=ROOT/'.test-results/native-layout.json');args=parser.parse_args()
 cc=os.environ.get('LLVM_CLANG') or shutil.which('clang');ld=os.environ.get('LLVM_LD') or shutil.which('ld.lld');assert cc and ld
 stock_info={'provided':False}
 if args.stock:
  stock=args.stock.read_bytes();assert hashlib.sha256(stock).hexdigest()==STOCK_SHA,'Wrong stock image'
  stock_info={'provided':True,'sha256':STOCK_SHA,'bytes':len(stock),'probe_start_after_file':0x2f340>=len(stock),'original_heap_start_word':hex(struct.unpack_from('<I',stock,0x1e840)[0]),'original_version_pointer':hex(struct.unpack_from('<I',stock,0x9e18)[0])}
 flags=['--target=arm-none-eabi','-mcpu=cortex-m3','-mthumb','-Oz','-ffreestanding','-fno-builtin','-fno-stack-protector','-ffunction-sections','-fdata-sections','-DBYTE_ORDER=1234','-DLITTLE_ENDIAN=1234','-DBOUNDED_REKEY_LAB']
 if args.lto:flags.append('-flto')
 rows=[]
 with tempfile.TemporaryDirectory(prefix='uv310-layout-') as temp:
  t=Path(temp)
  for branch in ['rekey-memory','rekey-pressure','rekey-dns','rekey-dns-grow']:
   n=P/branch;assert '203,0,113,7' in (ROOT/n/'native-config.h').read_text(),'Only public synthetic fixture permitted'
   local=t/branch;local.mkdir();header=(ROOT/n/'native-config.h').read_text()
   match=re.search(r'(RANDOM_POOL\[\]=\{)([^}]+)(\})',header);assert match
   pool=match.group(2).split(',');assert len(pool)==1024
   header=header[:match.start(2)]+','.join(pool[:args.pool_bytes])+header[match.end(2):]
   (local/'native-config.h').write_text('/* SYNTHETIC LAYOUT ONLY; NEVER DEPLOY. */\n'+header)
   (local/'native.c').write_bytes((ROOT/n/'native.c').read_bytes())
   sources=[n/'native.c',R/'wireguard.c',S/'crypto.c',*sorted((ROOT/S/'crypto/refc').glob('*.c')),W/'runtime.c',H/'entry.S']
   sources=[x.relative_to(ROOT) if x.is_absolute() else x for x in sources]
   if branch in ('rekey-dns','rekey-dns-grow'):sources.append(P/'dhcp-dns/dhcp_dns.c')
   if branch=='rekey-dns-grow':sources.append(P/'dhcp-dns/dhcp_dns_grow.c')
   includes=[local,n,R,W/'build',W/'include',W,S];objects=[]
   for i,src in enumerate(sources):
    out=t/(branch+'-'+str(i)+'.o');subprocess.run([cc,*flags,*(['-fno-lto'] if args.lto and src==W/'runtime.c' else []),*['-I'+str(x) for x in includes],'-c',str(local/'native.c' if src==n/'native.c' else src),'-o',str(out)],cwd=ROOT,check=True,capture_output=True);objects.append(str(out))
   elf_path=t/(branch+'.elf');linked=subprocess.run([ld,'--gc-sections','--no-undefined','-T',str(LAYOUT),*objects,'-o',str(elf_path)],cwd=ROOT,capture_output=True,text=True)
   if linked.returncode:raise SystemExit(linked.stderr)
   elf=ELFFile(io.BytesIO(elf_path.read_bytes()));symbols={s.name:s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()}
   assert not any(x.startswith('fixture_') or x.startswith('fake_') for x in symbols),'Test stubs in native link'
   sections=[{'name':s.name,'address':s['sh_addr'],'bytes':s['sh_size'],'end':s['sh_addr']+s['sh_size'],'nobits':s['sh_type']=='SHT_NOBITS'} for s in elf.iter_sections() if s['sh_flags']&2 and s['sh_size']]
   assert {s['name'] for s in sections}=={'.hook','.probe','.state','.version'},'Unexpected allocated section'
   ordered=sorted(sections,key=lambda s:s['address']);assert all(a['end']<=b['address'] for a,b in zip(ordered,ordered[1:])), 'Overlap'
   assert ordered[0]['address']==0x9df8 and ordered[0]['bytes']==4 and ordered[1]['address']==0x2f340
   end=symbols['__image_end'];heap=(end+255)&~255
   rows.append({'branch':branch,'synthetic_pool_bytes':args.pool_bytes,'effective_config_sha256':hashlib.sha256((local/'native-config.h').read_bytes()).hexdigest(),'sections':sections,'image_end':hex(end),'rounded_heap_start':hex(heap),'historical_heap_ceiling':hex(0x33c00),'fits_historical_ceiling':heap<=0x33c00,'ceiling_margin_bytes':0x33c00-heap,'reserved_from_0x2f290_bytes':heap-0x2f290,'no_test_stub_symbols':True,'source_sha256':{str(x):hashlib.sha256((ROOT/x).read_bytes()).hexdigest() for x in [*sources,n/'native-config.h',LAYOUT]}})
 result={'synthetic_pool_bytes':args.pool_bytes,'lto_enabled':args.lto,'runtime_lto_disabled':args.lto,'scope':'Final native address layout with public synthetic configuration; no stock overlay, no candidate firmware output, no device access','compiler':subprocess.check_output([cc,'--version'],text=True).splitlines()[0],'linker':subprocess.check_output([ld,'--version'],text=True).strip(),'stock':stock_info,'branches':rows,'layout_script_sha256':hashlib.sha256((ROOT/LAYOUT).read_bytes()).hexdigest(),'source_sha256':{str(Path(__file__).relative_to(ROOT)):hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},'hardware_access':False,'real_configuration_used':False,'goal_complete':False,'limitations':['Synthetic constants can alter final compiler/linker output; real fresh one-boot configuration needs independent audit','0x33c00 is historical packaging policy, not a measured current safe heap boundary','No runtime stack/IRQ/heap peak, fragmentation, DMA or firmware boot verified','No CRC-patched combined image emitted or deployed','Fitting address layout is not standalone readiness or stability']}
 args.out.parent.mkdir(exist_ok=True,parents=True);args.out.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps([{'branch':x['branch'],'heap_start':x['rounded_heap_start'],'fits_ceiling':x['fits_historical_ceiling'],'margin_bytes':x['ceiling_margin_bytes']} for x in rows],indent=2))
if __name__=='__main__':main()
