"""Read-only owned ROM/stock prefix replay; no firmware output or device access.
Requires private owner-provided images and optional Unicorn/Capstone dependencies.
Only executes selected ordinary Wi-Fi path to Ethernet prefix, NOT full transmit.
"""
from pathlib import Path
import argparse,hashlib,json,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_MODE_MCLASS,UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R5,UC_ARM_REG_R10,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
import capstone,unicorn
ROM_SHA='f96f3e5f1dd2352a71b777ce4fc586cefdc2c62977eae3cef0a82461a8ae5bb4'
STOCK_SHA='4b86d71b92529034b2b46da7b93402f67c8aef98d2fc1efa91fc67ff7e5fb85a'
BASE=0x800000;STOP=0x8281c6;PKT=0x33000;DATA=0x33100
DEST=0x31000;PRIV=0x31200;PUB=0x31400;WLC=0x31600;INFO=0x31800;OSH=0x31a00

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rom',type=Path,required=True);p.add_argument('--stock',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('Output exists; choose a new path')
 rom=a.rom.read_bytes();stock=a.stock.read_bytes()
 assert hashlib.sha256(rom).hexdigest()==ROM_SHA,'Wrong ROM'
 assert hashlib.sha256(stock).hexdigest()==STOCK_SHA,'Wrong stock image'
 cs=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB|capstone.CS_MODE_MCLASS)
 anchors=[(0x80fc34,'mov.w','ip, #0x800'),(0x80fc38,'ldr.w','pc, [ip, #0x90]'),(0x806d7c,'mov','r0, r1'),(0x80fcc8,'bl','#0x8281a4'),(0x8281b2,'ldrh','r0, [r1, #0x14]'),(0x8281c2,'ldr','r5, [r1, #0x10]')]
 for addr,mn,ops in anchors:
  ins=next(cs.disasm(rom[addr-BASE:addr-BASE+4],addr));assert (ins.mnemonic,ins.op_str)==(mn,ops),hex(addr)
 slots={0x890:0x80fc3d,0x618:0x806d65,0x88c:0x80f7a9,0x11f4:0x8281ad}
 for address,value in slots.items():assert struct.unpack_from('<I',stock,address)[0]==value,hex(address)
 def replay(length,mark_flag=0,accounted_flag=0,stored_length=None,data_offset=0):
  u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS);u.mem_map(0,0x40000);u.mem_map(BASE,0x70000);u.mem_write(0,stock);u.mem_write(BASE,rom)
  def put(addr,value):u.mem_write(addr,struct.pack('<I',value))
  def get(addr):return struct.unpack('<I',u.mem_read(addr,4))[0]
  # All contexts synthetic. Disable optional filter/accelerator/QoS paths.
  u.mem_write(DEST,bytes(0xc00));u.mem_write(PKT,bytes(0x900))
  put(DEST+0x18,PRIV);put(PRIV+0x10,DEST);put(PRIV+4,PUB);put(PRIV+8,WLC);put(PUB+0xc,OSH);put(WLC,INFO)
  u.mem_write(INFO+0x95,bytes([mark_flag]));put(OSH,7)
  put(PKT+8,DATA);put(PKT+12,DATA+2048);put(PKT+16,DATA+data_offset)
  u.mem_write(PKT+20,struct.pack('<HH',length if stored_length is None else stored_length,0x200 if accounted_flag else 0));u.mem_write(PKT+29,b'\x01')
  # Deliberately patterned synthetic payload; prefix stops before EtherType parse.
  frame=bytes((i*29+3)&255 for i in range(length));u.mem_write(DATA,frame)
  before=bytes(u.mem_read(PKT,0x44));visited=[]
  def code(uc,address,size,user):
   if address in [0x80fc3c,0x806d64,0x80f7a8,0x8281ac,0x8281b2,0x8281c2]:visited.append(hex(address))
  u.hook_add(UC_HOOK_CODE,code)
  for reg,value in [(UC_ARM_REG_R0,0),(UC_ARM_REG_R1,DEST),(UC_ARM_REG_R2,PKT),(UC_ARM_REG_SP,0x3bd60),(UC_ARM_REG_LR,0x3fff1)]:u.reg_write(reg,value)
  u.emu_start(0x80fc35,STOP,count=1000)
  assert u.reg_read(UC_ARM_REG_PC)==STOP,'Prefix did not reach length/data consumer'
  observed={'length':u.reg_read(UC_ARM_REG_R0),'data':u.reg_read(UC_ARM_REG_R5),'packet':u.reg_read(UC_ARM_REG_R10)}
  expected=bytearray(before);struct.pack_into('<H',expected,22,(0x200 if accounted_flag else 0)|(0x80 if mark_flag else 0))
  assert bytes(u.mem_read(PKT,0x44))==bytes(expected),'Unexpected packet metadata mutation'
  assert bytes(u.mem_read(DATA,length))==frame,'Unexpected payload mutation'
  assert get(OSH)==7+(0 if accounted_flag else 1),'Unexpected packet accounting'
  assert visited==['0x80fc3c','0x806d64','0x80f7a8','0x8281ac','0x8281b2','0x8281c2']
  return observed,visited
 def validates(observed,length):return observed=={'length':length,'data':DATA,'packet':PKT}
 rows=[]
 for length in [286,287,288,289,290,291,292,2048]:
  for mark in [0,1]:
   for accounted in [0,1]:
    observed,visited=replay(length,mark,accounted);assert validates(observed,length)
    rows.append({'frame_length':length,'mark_flag':mark,'already_accounted_flag':accounted,'consumer_length':observed['length'],'passed':True})
 negative=[]
 for name,length,stored,offset in [('stale_packet_length',292,286,0),('off_by_one_length',292,291,0),('wrong_data_pointer',292,292,1)]:
  observed,_=replay(length,stored_length=stored,data_offset=offset);assert not validates(observed,length)
  negative.append({'mutation':name,'kind':'synthetic input fixture corruption, original ROM unchanged','detected':True})
 result={'source_sha256':{str(Path(__file__).resolve().relative_to(Path(__file__).resolve().parents[1])):hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},'emulator_version':unicorn.__version__,'disassembler_version':capstone.__version__,'scope':'Exact owned stock ROM ordinary Wi-Fi transmit prefix; synthetic contexts and payload, stop before deeper Ethernet processing','rom_sha256':ROM_SHA,'stock_sha256':STOCK_SHA,'static_anchors':[{'address':hex(addr),'instruction':mn+' '+ops} for addr,mn,ops in anchors],'stock_dispatch_slots':{hex(k):hex(v) for k,v in slots.items()},'visited_entries':visited,'positive_scenarios':rows,'negative_controls':negative,'entry':'0x80fc34','stop_before':'0x8281c6','native_candidate_executed':False,'dhcp_payload_parsed_by_rom':False,'firmware_written':False,'hardware_access':False,'full_transmit_verified':False,'conclusion':'Selected unpatched stock path preserves packet and rereads +0x14 length/+0x10 data; no duplicate length fixup observed before stop','limitations':['Contexts, feature flags and packet memory are synthetic; real active flags unknown','No radio, DMA, IRQ, queueing, encapsulation, headroom or full lifetime model','Optional filtering/accelerator branches disabled; not all callers/consumers audited','Native growth and ROM prefix tested separately, not a linked firmware deployment','This does not prove DHCP is visible at hook or all stock length metadata is covered']}
 a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n');print('PASS',len(rows),'stock-prefix cases;',len(negative),'fixture corruption controls; no device access')
if __name__=='__main__':main()
