"""Offline, hash-pinned UV310 ALKU 7.3.2 driver table analysis.
No device access. All ABI labels are static hypotheses, not callable exports.
"""
from pathlib import Path
import hashlib, json, struct

p = Path('work/uv310-wireguard/private/nand')
ro = (p/'dsp2-rodata.bin').read_bytes()
data = (p/'dsp2-data.bin').read_bytes()
paged = (p/'dsp2-paged-code.bin').read_bytes()
small = (p/'dsp2-small-data.bin').read_bytes()
assert hashlib.sha256(ro).hexdigest() == '588fd80ade91170e5a11431f8d21f78f72e62fd5b189f174863f9b21c018b98f'
assert hashlib.sha256(data).hexdigest() == 'b31d062ece0b896b98c33d8359dfad23cb660e17605059afc239eab13f9919c3'
assert hashlib.sha256(paged).hexdigest() == 'a9880ae5b3476beca54136d98f2be87bcae2273867f0cfb317b308a339a74460'
assert hashlib.sha256(small).hexdigest() == '366ff74c956a4897f124072f967de5ab76f6ec728c6e85aeb7281a5c527a32f4'
assert paged[0x1c1800:0x1c1804] == b'+WL\0'
assert struct.unpack_from('<I',paged,0x1c182c)[0] == 0xd380fc
assert struct.unpack_from('<I',small,0x12c58)[0] == 0x1887328
assert struct.unpack_from('<I',small,0x1f37c)[0] == 0x444944

def string(addr):
    assert 0x183e000 <= addr < 0x183e000 + len(ro)
    return ro[addr-0x183e000:].split(b'\0', 1)[0].decode('ascii')

iovars = []
for a in range(0x18878ac, 0x18879f0, 12):
    ptr, ident, flags, typ, minimum = struct.unpack_from('<IHHHH', ro, a-0x183e000)
    iovars.append(dict(table_va=hex(a), name=string(ptr), varid=ident,
                       flags=flags, type=typ, minlen=minimum))
cli = []
for a in range(0x1a8f304, 0x1a8f304+12*20, 20):
    ptr, fn, get, set_, help_ = struct.unpack_from('<IIIII', data, a-0x1a1e000)
    cli.append(dict(table_va=hex(a), name=string(ptr), handler=hex(fn),
                    get_command=hex(get), set_command=hex(set_)))
cases = struct.unpack_from('<41I', ro, 0x1887328-0x183e000)
result = {
    'firmware_scope': 'MDM9K-ALKU-7.3.2; extracted DSP2 segments only',
    'execution_performed': False,
    'driver_banner': string(0x18873e0),
    'iovar_table': iovars,
    'cli_table_first_12_entries': cli,
    'config_operation_jump_table': [dict(operation=i+1, target=hex(a),
        default_return_only=a==0xcf5358) for i,a in enumerate(cases)],
    'config_dispatch': {
        'function':'0xcf4e8c', 'input_layout':'8-byte operation/value-pointer pair',
        'bounds':'unsigned (operation - 1) <= 40',
        'list_wrapper':'0xcf5754', 'cli_trampoline':'0xcf56c8',
        'cli_dispatch':'0x17f449c', 'cli_name_lookup':'0x17f445c',
        'handler_call_instruction':'0x17f4528',
        'default':'0xcf5358 returns 1; does not dispatch arbitrary command text'},
    'text_command_candidate': {
        'function':'0xcf475c','caller':'0xd380fc',
        'call_instruction':'0xd38128','special_prefix':string(0x19a9362),
        'normal_path':'split mutable command string on spaces, call CLI via 0xcf47fc',
        'external_entry':'+WL at 0xf01c1800, handler pointer at +44 -> 0xd380fc',
        'live_verified_command':'AT+WL=wl ver',
        'live_firmware_version':'5.90.153.52.1',
        'live_chipnum':'0xa962 (43362)', 'live_chiprev':'0x1',
        'live_evidence':['wl-version-probe.json','wl-runtime-info.json','wl-memory-info.json']},
    'host_vs_firmware_ioctl':{
        'gp_candidate':'0x3400000, cross-checked using jump-table pointer and magic',
        'dhd_magic_address':'0x341f37c','dhd_magic':'0x00444944',
        'selector':'0xcf5824 reads ioctl structure +24; match goes to 0xd015e4; otherwise firmware path 0xcffd68',
        'wl_wrapper':'0x17f4610 clears 28 bytes and fills command, buffer, length, set; leaves +24 zero',
        'consequence':'Verified +WL CLI reaches Wi-Fi firmware IOCTL; it does not by itself expose host DHD membytes/memsize IOVARs',
        'writes_performed':False},
    'task_record':{
        'table_va':'0x1a92250','name':string(struct.unpack_from('<I',data,0x1a92250-0x1a1e000)[0]),
        'entry':'0xcf6014','queue':'0x243c4d0','command_signal':'0x8',
        'request_offsets':{'8':'operation-pairs pointer','12':'pair count',
            '16':'completion task pointer','20':'completion signal','24':'one-byte result'},
        'status':'static interpretation; synchronization and request ownership unverified'},
    'rx_candidate':{
        'function':'0xcf4b38','name_evidence':string(0x1887460),
        'arguments':'r0 driver context, r1 interface index, r2 packet chain, r3 packet count (inferred)',
        'packet_offsets':{'0':'next pointer','16':'Ethernet data pointer','24':'length'},
        'event_ethertype':'0x886c; separate event handling path',
        'ordinary_frame_call':'0xcf4c68 -> 0xf74428 (r0 frame pointer, r1 length)',
        'ipnet_evidence':['ath1 log strings', '../../ipnet/task/ipnet_if.c'],
        'ownership':'original packet chain passed to 0x141593c at 0xcf4c90; retaining pointers requires a verified copy/refcount scheme'},
    'tx_candidate':{
        'function':'0xcf49f0','caller_instruction':'0xf7435c',
        'path':['0x14159c8 packet allocation/copy candidate','0xcfef88 protocol-header candidate','0xcfd50c bus transmit candidate'],
        'status':'not invoked; exact ownership, headroom and return semantics unverified'},
    'limitations':[
        'These are internal addresses tied to one firmware, not public AT commands or a stable ABI.',
        'Verified +WL entry is the Wi-Fi firmware path; host DHD IOVAR access and arbitrary execution remain unproven.',
        'No live hook, packet injection, WireGuard deployment or throughput claim.',
        'Modern LLVM disassembly is an analysis aid, not a fully validated Hexagon v3 model.']
}
out=Path('outputs/uv310-wireguard/evidence/dsp2-driver-abi.json')
out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'output':str(out),'iovar_count':len(iovars),'operation_count':len(cases),'driver':result['driver_banner']}))
