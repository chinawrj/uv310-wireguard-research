"""Fault injection: real USB is always mocked; never touches a device."""
import unittest,tempfile,sys
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import observe as o

class Fake:
 def __init__(self):self.writes=[];self.queue=[];self.drain=True;self.mode='ok';self.page=0
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
    name='AERM'[self.page%4];self.page+=1;v=[0]*16
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
