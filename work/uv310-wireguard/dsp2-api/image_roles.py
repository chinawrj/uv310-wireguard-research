#!/usr/bin/env python3
"""Read-only role clues; string presence does not prove runtime task placement."""
import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile

SOURCES = {
    'dsp1-first64k.bin': '28b41392936142b4148dc94c4a1c1df583b10b114998fd1d6472a7ae5d9592ae',
    'dsp2-rodata.bin': '588fd80ade91170e5a11431f8d21f78f72e62fd5b189f174863f9b21c018b98f',
    'amss.elf': '388dda0d44c9ed391306c8dbd5851a612b0e68c3dc7faec189234dd7a525c9f5',
}
MARKERS = [b'lte\\RRC\\src\\lte_rrc_config.c', b'lte\\L2\\mac\\src\\lte_mac_dl.c',
           b'lte\\L2\\pdcp\\src\\lte_pdcp_dl.c', b'lte_ml1_gps_mrl.c',
           b'lte_ml1_gps_timetag_stm.c', b'geran\\gcommon\\src\\gprs_pdu.c',
           b'geran\\gl1\\src\\gpl1_gprs_shared_transfer.c']

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--nand',required=True,type=Path)
    p.add_argument('--out',required=True,type=Path)
    a=p.parse_args(); blobs={}
    for n,h in SOURCES.items():
        b=(a.nand/n).read_bytes()
        if hashlib.sha256(b).hexdigest()!=h:
            raise ValueError('source hash mismatch: '+n)
        blobs[n]=b
    with (a.nand/'dsp1-first64k.bin').open('rb') as f:
        e=ELFFile(f)
        segments=[s for s in e.iter_segments() if s['p_type']=='PT_LOAD']
        extent=max(s['p_offset']+s['p_filesz'] for s in segments)
        dsp1={'machine':e['e_machine'],'entry':hex(e['e_entry']),
              'available_file_bytes':len(blobs['dsp1-first64k.bin']),
              'declared_load_file_extent':extent,'complete_image_available':False,
              'runtime_role_identified':False}
    assert dsp1['machine']=='EM_QDSP6' and extent>len(blobs['dsp1-first64k.bin'])
    markers=[]
    for m in MARKERS:
        offset=blobs['dsp2-rodata.bin'].find(m+b'\0')
        assert offset>=0, 'missing selected marker'
        markers.append({'text':m.decode(),'rodata_va':hex(0x183e000+offset)})
    marker=b'clkrgm_mpss_q6ss.c:Invalid QDSP6 type: %d'
    assert marker in blobs['amss.elf']
    result={'scope':'Static image roles, not runtime task/cycle attribution',
            'source_sha256':SOURCES,'dsp1':dsp1,'dsp2_selected_markers':markers,
            'amss_selected_marker':marker.decode(),
            'conclusions':['DSP2 includes cellular protocol/ML1-related clues as well as WLAN/IPnet',
                           'These clues do not prove which core executes every PHY operation',
                           'DSP1 is not established as idle, exclusive modem core or available offload CPU'],
            'hardware_access':False,'runtime_mapping_verified':False}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'markers_checked':len(markers)+1,'dsp1_available':dsp1['available_file_bytes'],
                      'dsp1_declared_extent':extent,'runtime_mapping_verified':False}))
if __name__=='__main__': main()
