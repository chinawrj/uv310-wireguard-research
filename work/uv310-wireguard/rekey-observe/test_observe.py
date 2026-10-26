"""Fault injection: real USB is always mocked; never touches a device."""
import unittest,tempfile,sys
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import observe as o

class Fake:
 def __init__(self):self.writes=[];self.queue=[];self.drain=True;self.mode='ok';self.page=0;self.pages='AERM'
 def get_active_configuration(self):
  top=o.NORMAL if self.mode!='topology' else {0:[1,129]}
  return [Interface(k,v) for k,v in top.items()]
 def write(self,ep,payload,timeout):
  self.writes.append(payload)
  if self.mode=='short':return 0
  if payload==b'AT^PROJECTNAME?\r':
   self.queue=[b'\r\n^PROJECTNAME:MDM9600\tUV310\r\n\r\nOK\r\n' if self.mode!='identity' else b'PRIVATE_OTHER_DEVICE\r\nOK\r\n']
  else:
   if self.mode=='missing':self.queue=[b'5.90.153.52.1\r\nOK\r\n']
   else:
    name=self.pages[self.page%len(self.pages)];self.page+=1;v=[0]*16
    if name=='N':v[:4]=[0x01020304,0xffffffff,0x87654321,0x12345678]
    if name=='M':v[8]=1;v[12]=int(self.mode!='memory')
    v[13 if name=='M' else 15]=([0xfffffffe,0xffffffff,0,1][self.page-1] if self.mode=='wrap' else (100 if self.page==1 else 50) if self.mode=='rollback' else 0)
    self.queue=[(name+'='+','.join(f'{x:08x}' for x in v)+'\r\nOK\r\n').encode()]
  return len(payload)
 def read(self,ep,n,timeout):
  if self.mode=='stale':return b'stale'
  if self.drain:self.drain=False;raise o.usb.core.USBTimeoutError('timeout')
  if self.mode=='gone':raise o.usb.core.USBError('private backend detail',errno=19)
  if self.mode=='timeout':raise o.usb.core.USBTimeoutError('timeout')
  if self.mode=='aterror':return b'\r\nERROR\r\n'
  if self.mode=='large':return b'x'*8193
  if self.queue:return self.queue.pop(0)
  raise o.usb.core.USBTimeoutError('timeout')
class Interface(list):
 def __init__(self,k,eps):super().__init__(SimpleNamespace(bEndpointAddress=e) for e in eps);self.bInterfaceNumber=k
class Cases(unittest.TestCase):
 def setUp(self):
  self.d=Fake();self.find=patch.object(o.usb.core,'find',return_value=self.d).start()
  self.claim=patch.object(o.usb.util,'claim_interface').start();self.release=patch.object(o.usb.util,'release_interface').start();self.dispose=patch.object(o.usb.util,'dispose_resources').start()
  self.addCleanup(patch.stopall)
 def failcode(self,mode,code):
  self.d.mode=mode
  with self.assertRaises(o.ObservationError) as got:o.status(pause=lambda _:None)
  self.assertEqual(got.exception.code,code);return got.exception
 def test_success_pages_and_cleanup(self):
  x=o.status(pause=lambda _:None);self.assertEqual(set(x['pages']),set('AERM'));self.assertEqual(x['queries']['status_queries'],4);self.release.assert_called_once();self.dispose.assert_called_once()
 def test_n1_collects_fifth_page(self):
  self.d.pages='AERMN';x=o.status(pause=lambda _:None,protocol='n1')
  self.assertEqual(x['queries']['status_queries'],5);self.assertEqual(set(x['pages']),set('AERMN'));self.assertFalse(x['dns_path_verified'])
  n=x['pages']['N'];self.assertEqual(n['dhcp_rewrites'],0x01020304);self.assertEqual(n['gateway_udp_rejects'],0xffffffff);self.assertEqual(n['lan_dns_guard_drops'],0x87654321);self.assertEqual(n['rx_count'],0x12345678)
 def test_n1_old_firmware_is_missing_n_not_success(self):
  with self.assertRaises(o.ObservationError) as got:o.status(pause=lambda _:None,protocol='n1')
  self.assertEqual(got.exception.code,'MISSING_STATUS_PAGES');self.assertEqual(got.exception.details['missing'],['N']);self.assertEqual(got.exception.details['status_queries'],12);self.release.assert_called_once()
 def test_n1_rotation_starts_at_n(self):
  self.d.pages='NAERM';x=o.status(pause=lambda _:None,protocol='n1');self.assertEqual(x['queries']['status_queries'],5)
 def test_legacy_ignores_extra_n_and_completes(self):
  self.d.pages='NAERM';x=o.status(pause=lambda _:None);self.assertEqual(set(x['pages']),set('AERM'));self.assertEqual(x['queries']['unrecognized_replies'],1)
 def test_unknown_protocol_no_usb_access(self):
  with self.assertRaises(ValueError):o.status(protocol='unknown')
  self.find.assert_not_called()
 def test_strict_page_formats(self):
  good=b'N='+b','.join([b'00000000']*16)
  for bad in [good+b',00000000',good[:-1],good.replace(b'00000000',b'0000000g',1),good+b'x',good.replace(b',',b';',1)]:
   with self.subTest(bad=bad),self.assertRaises(o.ObservationError) as got:o.parse_page(bad)
   self.assertEqual(got.exception.code,'INVALID_STATUS_PAGE')
 def test_full_prefixed_page_and_embedded_text(self):
  good=b'N='+b','.join([b'00000000']*16)
  self.assertEqual(o.parse_page(b'5.90.153.52.1 '+good+b'\r\nOK\r\n')[0],'N')
  self.assertIsNone(o.parse_page(b'PRIVATE_PREFIX_'+good))
 def test_ambiguous_pages_rejected(self):
  good=b'N='+b','.join([b'00000000']*16)
  with self.assertRaises(o.ObservationError) as got:o.parse_page(good+b'\r\n'+good)
  self.assertEqual(got.exception.code,'AMBIGUOUS_STATUS_REPLY')
 def test_n_clock_rollback_is_not_ignored(self):
  self.d.pages='NAERM';self.d.mode='rollback'
  with self.assertRaises(o.ObservationError) as got:o.status(pause=lambda _:None,protocol='n1')
  self.assertEqual(got.exception.code,'CLOCK_DISCONTINUITY')
 def test_malformed_n_preserves_cleanup_and_hides_reply(self):
  self.d.pages='N';write=self.d.write
  def malformed(*args,**kwargs):
   n=write(*args,**kwargs)
   if args[1]==b'AT+WL=wl ver\r':self.d.queue=[b'N=PRIVATE_CONTENT\r\nOK\r\n']
   return n
  self.d.write=malformed
  with self.assertRaises(o.ObservationError) as got:o.status(pause=lambda _:None,protocol='n1')
  self.assertEqual(got.exception.code,'INVALID_STATUS_PAGE');self.assertNotIn('PRIVATE_CONTENT',str(got.exception.record()));self.release.assert_called_once();self.dispose.assert_called_once()
 def test_n1_clock_wrap(self):
  self.d.pages='AERMN';write=self.d.write
  def wrapped(*args,**kwargs):
   n=write(*args,**kwargs)
   if args[1]==b'AT+WL=wl ver\r':
    name,page=o.parse_page(self.d.queue[0]);page['clock']=(0xfffffffc+self.d.page)&0xffffffff
    self.d.queue=[(name+'='+','.join(f'{page[k]:08x}' for k in o.FIELDS[name])+'\r\nOK\r\n').encode()]
   return n
  self.d.write=wrapped;self.assertEqual(o.status(pause=lambda _:None,protocol='n1')['pages']['N']['clock'],1)
 def test_duplicate_n_never_counts_as_other_pages(self):
  self.d.pages='N'
  with self.assertRaises(o.ObservationError) as got:o.status(pause=lambda _:None,protocol='n1')
  self.assertEqual(got.exception.code,'MISSING_STATUS_PAGES');self.assertEqual(got.exception.details['missing'],list('AEMR'));self.assertEqual(got.exception.details['status_queries'],12)
 def test_collect_propagates_protocol(self):
  with patch.object(o,'host_state',return_value={}),patch.object(o,'status',return_value={}) as status:
   self.assertTrue(o.collect(protocol='n1')['status_read_ok']);status.assert_called_once_with(protocol='n1')
 def test_device_absent_no_writes(self):
  self.find.return_value=None;self.failcode('ok','DEVICE_ABSENT');self.assertFalse(self.d.writes);self.claim.assert_not_called()
 def test_wrong_topology_no_claim_no_write(self):
  self.failcode('topology','TOPOLOGY_MISMATCH');self.assertFalse(self.d.writes);self.claim.assert_not_called();self.dispose.assert_called_once()
 def test_claim_failure_still_disposes(self):
  self.claim.side_effect=o.usb.core.USBError('busy',errno=16);self.failcode('ok','USB_IO_ERROR');self.release.assert_not_called();self.dispose.assert_called_once()
 def test_identity_mismatch_no_status_queries_no_raw_response(self):
  ex=self.failcode('identity','IDENTITY_MISMATCH');self.assertEqual(len(self.d.writes),1);self.assertNotIn('PRIVATE',str(ex.record()))
 def test_at_error(self):self.failcode('aterror','AT_ERROR')
 def test_missing_pages_query_bound(self):
  ex=self.failcode('missing','MISSING_STATUS_PAGES');self.assertEqual(ex.details['status_queries'],12);self.assertEqual(len(self.d.writes),13)
 def test_timeout_bounded(self):self.failcode('timeout','AT_TIMEOUT')
 def test_stale_input_bound(self):
  self.failcode('stale','STALE_INPUT_LIMIT');self.assertFalse(self.d.writes)
 def test_short_write(self):self.failcode('short','SHORT_WRITE')
 def test_oversize_reply(self):self.failcode('large','REPLY_LIMIT')
 def test_usb_detach_errno_not_message(self):
  ex=self.failcode('gone','USB_IO_ERROR');self.assertEqual(ex.details['errno'],19);self.assertNotIn('private',str(ex.record()));self.dispose.assert_called_once()
 def test_invalid_memory(self):self.failcode('memory','MEMORY_SNAPSHOT_INVALID')
 def test_cleanup_does_not_hide_primary_failure(self):
  self.release.side_effect=o.usb.core.USBError('gone',errno=19);ex=self.failcode('aterror','AT_ERROR');self.assertEqual(ex.details['cleanup_errors'][0]['stage'],'release');self.dispose.assert_called_once()
 def test_cleanup_failure_is_not_success(self):
  self.release.side_effect=o.usb.core.USBError('gone',errno=19);self.failcode('ok','CLEANUP_ERROR')
 def test_fragmented_reply(self):
  self.d.drain=False
  def write(*a,**kw):self.d.queue=[b'\r\n^PROJECTNAME:MDM',b'9600\tUV310\r\n',b'\r\nOK\r\n'];return len(a[1])
  self.d.write=write;self.assertIn(b'MDM9600',o.query(self.d,'AT^PROJECTNAME?'))
 def test_nonallowlisted_query_never_written(self):
  with self.assertRaises(ValueError):o.query(self.d,'AT+RESET')
  self.assertFalse(self.d.writes)
 def test_clock_rollback_rejected(self):self.failcode('rollback','CLOCK_DISCONTINUITY')
 def test_clock_wrap_accepted(self):
  self.d.mode='wrap';self.assertEqual(len(o.status(pause=lambda _:None)['pages']),4)
 def test_host_change_separate_from_status(self):
  before={'source_ip':'192.168.100.100','matches_lab_client':True,'gateway_route_interface':'en0'}
  after={'source_ip':'192.168.1.195','matches_lab_client':False,'gateway_route_interface':'en8'}
  with patch.object(o,'host_state',side_effect=[before,after]),patch.object(o,'status',return_value={'pages':{}}):x=o.collect()
  self.assertTrue(x['status_read_ok']);self.assertTrue(x['host_network_changed']);self.assertFalse(x['lab_client_ready']);self.assertFalse(x['vpn_or_rekey_verified_by_this_tool'])
 def test_host_errors_do_not_hide_usb_error(self):
  with patch.object(o,'host_state',return_value={}),patch.object(o,'status',side_effect=o.ObservationError('DEVICE_ABSENT')):x=o.collect()
  self.assertFalse(x['status_read_ok']);self.assertEqual(x['error']['code'],'DEVICE_ABSENT');self.assertFalse(x['lab_client_ready'])
 def test_bad_host_ip_and_route_failure(self):
  result=[SimpleNamespace(returncode=0,stdout='999.1.2.3'),SimpleNamespace(returncode=1,stdout='interface: en0')]
  with patch.object(o.subprocess,'run',side_effect=result):x=o.host_state()
  self.assertIsNone(x['source_ip']);self.assertIsNone(x['gateway_route_interface'])
 def test_no_existing_evidence_overwrite_or_device_access(self):
  with tempfile.TemporaryDirectory() as tmp:
   f=Path(tmp)/'result.json';f.write_text('ORIGINAL')
   with patch.object(sys,'argv',['observe','--out',str(f)]),patch.object(o,'collect') as collect:
    with self.assertRaises(FileExistsError):o.main()
    collect.assert_not_called()
   self.assertEqual(f.read_text(),'ORIGINAL')
if __name__=='__main__':unittest.main(verbosity=2)
