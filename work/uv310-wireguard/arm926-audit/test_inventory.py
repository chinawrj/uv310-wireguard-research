#!/usr/bin/env python3
"""Repeat six negative controls for inventory.py; never copy firmware into repo.

Only capture-log copies and report JSON are written into a TemporaryDirectory.
The proprietary AMSS input is read in place by inventory.py, never executed.
"""
import argparse
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
LOG_NAMES=('amss-elf-read.json','amss-header-read.json','amss-code-read.json','nand-partitions.json')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--nand',type=Path,required=True)
    p.add_argument('--capture-evidence',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    script=Path(__file__).with_name('inventory.py')
    spec=importlib.util.spec_from_file_location('arm926_inventory_under_test',script)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    results=[]
    # A tiny synthetic ELF contains no actual firmware or executable instructions.
    fixture=bytearray(84)
    fixture[:7]=b'\x7fELF\x01\x01\x01'
    struct.pack_into('<HHIIIIIHHHHHH',fixture,16,2,40,1,0,52,0,0,52,32,1,0,0,0)
    struct.pack_into('<8I',fixture,52,1,84,0,0,0,0,5,4)
    parsed=module.parse_elf(bytes(fixture))
    assert len(parsed['segments'])==1
    results.append({'case':'synthetic_valid_header','expected':'accepted','passed':True})
    for name,expected in (
        ('truncated_program_header','Truncated program headers'),
        ('file_extent_out_of_bounds','Segment 0: truncated file-backed extent'),
        ('filesz_exceeds_memsz','Segment 0: filesz exceeds memsz'),
    ):
        b=bytearray(fixture)
        if name=='truncated_program_header':
            b=b[:60]
        elif name=='file_extent_out_of_bounds':
            struct.pack_into('<I',b,52+16,4)
            struct.pack_into('<I',b,52+20,4)
        else:
            struct.pack_into('<I',b,52+4,80)
            struct.pack_into('<I',b,52+16,4)
        try:
            module.parse_elf(bytes(b))
        except ValueError as error:
            assert str(error)==expected,(name,str(error))
        else:
            raise AssertionError(f'{name}: invalid ELF was accepted')
        results.append({'case':name,'expected':'rejected','diagnostic':expected,'passed':True})
    source_logs={name:json.loads((a.capture_evidence/name).read_text()) for name in LOG_NAMES}
    with tempfile.TemporaryDirectory(prefix='arm926-inventory-guards-') as temp:
        temp=Path(temp)
        def run(logdir):
            return subprocess.run([sys.executable,str(script),'--nand',str(a.nand),
                '--capture-evidence',str(logdir),'--out',str(temp/'inventory-result.json')],
                capture_output=True,text=True,timeout=30)
        baseline=run(a.capture_evidence)
        assert baseline.returncode==0,'Real-input baseline failed; inspect inventory.py directly'
        baseline_result=json.loads((temp/'inventory-result.json').read_text())
        results.append({'case':'real_owner_capture_baseline','expected':'accepted','passed':True})
        for name,expected in (
            ('missing_sector','Sector coverage mismatch'),
            ('wrong_capture_hash','Capture image metadata mismatch'),
            ('controller_error_bit','Capture controller check failed'),
        ):
            for logname,original in source_logs.items():
                log=json.loads(json.dumps(original))
                if logname=='amss-elf-read.json':
                    if name=='missing_sector':
                        log['reads'].pop(100)
                    elif name=='wrong_capture_hash':
                        log['image']['sha256']='0'*64
                    else:
                        log['reads'][100]['status']='0x110'
                (temp/logname).write_text(json.dumps(log))
            run_result=run(temp)
            assert run_result.returncode!=0 and f'ValueError: {expected}' in run_result.stderr, f'{name}: wrong outcome'
            results.append({'case':name,'expected':'rejected','diagnostic':expected,'passed':True})
    report={
        'schema':'uv310-arm926-inventory-guards-v1','audit_date':'2026-10-28',
        'offline':True,'network_or_device_access':False,'firmware_copied_or_executed':False,
        'inventory_script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
        'test_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'owner_image_identity':baseline_result['image'],
        'positive_controls':2,'negative_controls':6,'all_passed':True,
        'results':results,
        'scope':'Auditor guard behavior only; no execution, decompression, boot or live Wi-Fi/WireGuard claim',
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'positive_controls':2,'negative_controls':6,'output':str(a.out)}))

if __name__=='__main__':
    main()
