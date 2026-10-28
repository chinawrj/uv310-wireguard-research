#!/usr/bin/env python3
"""Offline UV310 image audit. Reads named files only; no USB/network dependencies.

Run against the owner's private NAND collection and historical capture evidence.
Outputs only structural metadata, hashes and aggregate read statuses, never bytes,
strings, identifiers, configuration, or disassembly from proprietary images.
"""
import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

EXPECTED_AMSS = '388dda0d44c9ed391306c8dbd5851a612b0e68c3dc7faec189234dd7a525c9f5'
EXPECTED_BYTES = 1880064

def sha(b):
    return hashlib.sha256(b).hexdigest()

def require(ok, message):
    if not ok:
        raise ValueError(message)

def read_json(directory, name):
    b = (directory / name).read_bytes()
    return json.loads(b), {'file': name, 'sha256': sha(b), 'bytes': len(b)}

def read_status_ok(r):
    return (r['timeout'] == 0 and r['bytes'] == 512
            and not int(r['status'], 0) & 0x110
            and not int(r['buffer_status'], 0) & 0x100)

def capture_summary(log):
    reads = log['reads']
    status = Counter((r['status'], r['buffer_status'], r['bytes'], r['timeout']) for r in reads)
    return {
        'reads': len(reads),
        'first': {k: reads[0][k] for k in ('row', 'sector')},
        'last': {k: reads[-1][k] for k in ('row', 'sector')},
        'reader_rejection_masks': {'status': '0x110', 'buffer_status': '0x100'},
        'reads_passing_original_reader_checks': sum(read_status_ok(r) for r in reads),
        'reported_error': log.get('error'),
        'flash_program_or_erase_sent': log['flash_program_or_erase_sent'],
        'status_counts': [dict(status=s, buffer_status=b, bytes=n, timeout=t, count=count)
                          for (s,b,n,t),count in sorted(status.items())],
    }

def parse_elf(blob):
    require(len(blob) >= 52 and blob[:7] == b'\x7fELF\x01\x01\x01', 'Not ELF32 little-endian v1')
    fields = struct.unpack_from('<HHIIIIIHHHHHH', blob, 16)
    names = ('type','machine','version','entry','phoff','shoff','flags','ehsize','phentsize','phnum','shentsize','shnum','shstrndx')
    h = dict(zip(names,fields))
    require(h['machine'] == 40 and h['type'] == 2, 'Expected ARM ET_EXEC')
    require(h['ehsize'] == 52 and h['phentsize'] == 32, 'Unexpected ELF structure size')
    require(h['phoff'] + h['phnum'] * h['phentsize'] <= len(blob), 'Truncated program headers')
    segments=[]
    for i in range(h['phnum']):
        typ,off,va,pa,fs,ms,flags,align=struct.unpack_from('<8I',blob,h['phoff']+i*32)
        require(off + fs <= len(blob), f'Segment {i}: truncated file-backed extent')
        require(typ != 1 or fs <= ms, f'Segment {i}: filesz exceeds memsz')
        segments.append({
            'index':i, 'type':{0:'PT_NULL',1:'PT_LOAD'}.get(typ,hex(typ)),
            'file_offset':hex(off), 'file_end_exclusive':hex(off+fs),
            'vaddr':hex(va), 'vaddr_end_exclusive':hex(va+ms),
            'paddr':hex(pa), 'paddr_end_exclusive':hex(pa+ms),
            'filesz':fs,'memsz':ms,'memsz_minus_filesz':ms-fs,
            'flags':hex(flags),'elf_rwx_bits':('r' if flags&4 else '-')+('w' if flags&2 else '-')+('x' if flags&1 else '-'),
            'non_rwx_flags':hex(flags & ~7),'alignment':align,
            'file_extent_present':True,
            'file_extent_sha256':sha(blob[off:off+fs]) if fs else None,
        })
    load=[s for s in segments if s['type']=='PT_LOAD']
    return {
        'class':'ELF32','endianness':'little','osabi_byte':hex(blob[7]),
        'type':'ET_EXEC','machine':'EM_ARM','entry':hex(h['entry']),
        'elf_flags':hex(h['flags']),'program_header_offset':h['phoff'],
        'program_header_count':h['phnum'],'section_header_offset':h['shoff'],
        'section_header_count':h['shnum'],'section_headers_present':bool(h['shnum']),
        'max_declared_file_end':max(int(s['file_end_exclusive'],0) for s in segments),
        'entry_in_load_virtual_ranges':[s['index'] for s in load if int(s['vaddr'],0)<=h['entry']<int(s['vaddr_end_exclusive'],0)],
        'entry_in_load_physical_ranges':[s['index'] for s in load if int(s['paddr'],0)<=h['entry']<int(s['paddr_end_exclusive'],0)],
        'segments':segments,
        'interpretation_limits':[
            'PT_LOAD and low R/W/X bits are reported structurally; vendor high flags are not decoded here.',
            'memsz minus filesz is not proven to be entirely BSS; packed/pageable content requires loader analysis.',
            'VA/PA are ELF-declared addresses; MMU setup and live mappings are not verified.',
            'ELF completeness does not imply a complete boot chain, ROM, NAND clone, or runtime RAM image.',
        ],
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--nand',type=Path,required=True,help='Owner-private NAND directory')
    p.add_argument('--capture-evidence',type=Path,required=True,help='Historical JSON capture logs directory')
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    blob=(a.nand/'amss.elf').read_bytes()
    require(len(blob)==EXPECTED_BYTES and sha(blob)==EXPECTED_AMSS,'AMSS identity mismatch')
    elf=parse_elf(blob)
    require(elf['max_declared_file_end']==len(blob),'ELF final declared extent mismatch')
    prefix=(a.nand/'amss-first64k.bin').read_bytes()
    require(len(prefix)==65536 and prefix==blob[:65536],'Independent prefix mismatch')
    full,full_source=read_json(a.capture_evidence,'amss-elf-read.json')
    head,head_source=read_json(a.capture_evidence,'amss-header-read.json')
    failed,failed_source=read_json(a.capture_evidence,'amss-code-read.json')
    partlog,part_source=read_json(a.capture_evidence,'nand-partitions.json')
    for log, data, start, rows in ((full,blob,1536,918),(head,prefix,1536,32)):
        require(not log.get('error'),'Successful capture contains an error')
        require(log['image']['bytes']==len(data) and log['image']['sha256']==sha(data),'Capture image metadata mismatch')
        require(log['page_bytes']==2048 and log['block_bytes']==131072,'Unexpected NAND geometry')
        require(log['flash_program_or_erase_sent'] is False,'Unexpected capture write flag')
        require([(r['row'],r['sector']) for r in log['reads']]==[(r,s) for r in range(start,start+rows) for s in range(4)],'Sector coverage mismatch')
        require(all(read_status_ok(r) for r in log['reads']),'Capture controller check failed')
    # The earlier full-partition attempt failed immediately beyond the saved extent.
    require(failed.get('error')=='Controller reports read error','Unexpected earlier attempt outcome')
    require(len(failed['reads'])==3673 and all(read_status_ok(r) for r in failed['reads'][:-1]),'Unexpected earlier capture coverage')
    require([(r['row'],r['sector']) for r in failed['reads'][:-1]]==[(r['row'],r['sector']) for r in full['reads']], 'Earlier capture prefix coverage mismatch')
    last=failed['reads'][-1]
    require((last['row'],last['sector'])==(2454,0) and not read_status_ok(last),'Expected boundary failure absent')
    table=(a.nand/'block-2-partition-table.bin').read_bytes()
    require(struct.unpack_from('<4I',table)==(0x55ee73aa,0xe35ebddb,3,10),'Unexpected partition table')
    partitions=[]
    for i in range(10):
        name,start,count,attrs=struct.unpack_from('<16sII4s',table,16+i*28)
        name=name.split(b'\0')[0].decode('ascii')
        part=dict(name=name,start_block=start,blocks=count,attributes_hex=attrs.hex(),size_bytes=None if count==0xffffffff else count*131072)
        require(part==partlog['partitions'][i],f'Partition log mismatch at {i}')
        partitions.append(part)
    amsspart=next(x for x in partitions if x['name']=='0:AMSS')
    observed=[]
    for name in ('amss.elf','amss-first64k.bin','dsp1-first64k.bin','dsp2-first64k.bin','block-0-header.bin','block-1-header.bin','block-2-header.bin','block-2-partition-table.bin'):
        b=(a.nand/name).read_bytes()
        observed.append(dict(file=name,bytes=len(b),sha256=sha(b)))
    out={
        'schema':'uv310-arm926-inventory-v1','audit_date':'2026-10-28',
        'audit_mode':'offline structural analysis of existing owner captures',
        'network_or_device_access':False,'firmware_or_raw_bytes_published':False,
        'image':dict(file='amss.elf',bytes=len(blob),sha256=sha(blob)),
        'elf':elf,'capture_sources':[full_source,head_source,failed_source,part_source],
        'capture':capture_summary(full),'independent_prefix_capture':capture_summary(head),
        'independent_prefix_matches':True,'independent_full_image_repeat_available':False,
        'earlier_full_partition_attempt':capture_summary(failed),
        'partition_table':dict(file='block-2-partition-table.bin',sha256=sha(table),partitions=partitions),
        'amss_partition_coverage':dict(partition_bytes=amsspart['size_bytes'],saved_bytes=len(blob),remaining_bytes_not_saved=amsspart['size_bytes']-len(blob),read_strategy='contiguous physical rows; no bad-block remapping in historical capture script',raw_oob_captured=False),
        'observed_named_files':observed,
        'completeness':{
            'all_amss_elf_declared_file_extents_present':True,
            'whole_amss_partition_saved':False,
            'whole_arm_boot_chain_available':False,
            'known_missing_from_examined_nand_collection':['FSBL full image','OSBL full image','PBL/BootROM dump','normal-runtime ARM RAM snapshot'],
            'dsp1_full_image_available':False,
            'compression_or_paging_semantics_proven':False,
            'runtime_arm_custom_code_execution_proven_by_this_audit':False,
        },
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'passed':True,'output':str(a.out),'amss_bytes':len(blob),'segments':len(elf['segments']),'sector_reads':len(full['reads']),'independent_prefix_match':True}))

if __name__=='__main__':
    main()
