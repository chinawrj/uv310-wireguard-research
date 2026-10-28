"""Synthetic material and stock only; temp directories removed after tests."""
import hashlib,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as m
from test_check import CONFIG
NOW=1800000000*10**9
class Cases(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.root=self.base/'private';self.root.mkdir(mode=0o700)
  self.config=self.base/'fixture.conf';self.config.write_text(CONFIG);self.config.chmod(0o600);self.stock=self.base/'stock';self.stock.write_bytes(b'synthetic')
  patch.object(m,'STOCK_BYTES',9).start();patch.object(m,'STOCK_SHA',hashlib.sha256(b'synthetic').hexdigest()).start();self.clock=patch.object(m.time,'time_ns',return_value=NOW).start();patch.object(m.secrets,'token_bytes',side_effect=lambda n:bytes((i%251)+1 for i in range(n))).start();self.addCleanup(patch.stopall)
 def run_prepare(self):return m.prepare(self.config,self.stock,self.root)
 def test_permissions_and_no_boot_claim(self):
  result=self.run_prepare();d=self.root/result['directory_name'];self.assertFalse(result['boot_authorized']);self.assertFalse(result['seed_integrated'])
  for p in d.iterdir():self.assertEqual(p.stat().st_mode&0o777,0o600)
  self.assertEqual(d.stat().st_mode&0o777,0o700);self.assertEqual((d/'generator-seed.bin').stat().st_size,32)
  header=(d/'native-config.h').read_text();self.assertIn('RANDOM_POOL',header);self.assertNotIn('SERVER_PRIVATE',header)
  self.assertEqual(json.loads((d/'material.json').read_text())['phase'],'prepared-only')
 def test_same_time_and_rollback_refused(self):
  self.run_prepare()
  for stamp in [NOW,NOW-1,NOW+10**9]:
   self.clock.return_value=stamp
   with self.assertRaisesRegex(m.CheckError,'HOST_CLOCK_NOT_FRESH'):self.run_prepare()
 def test_new_attempt_does_not_overwrite(self):
  first=self.run_prepare();self.clock.return_value=NOW+2*10**9;second=self.run_prepare();self.assertNotEqual(first['attempt_id'],second['attempt_id']);self.assertTrue((self.root/first['directory_name']/'material.json').exists())
 def test_corrupt_ledger_refused(self):
  p=self.root/'prepare-clock.json';p.write_text('{}');p.chmod(0o600)
  with self.assertRaisesRegex(m.CheckError,'INVALID_CLOCK_LEDGER'):self.run_prepare()
 def test_symlink_ledger_refused(self):
  (self.root/'prepare-clock.json').symlink_to(self.config)
  with self.assertRaisesRegex(m.CheckError,'INPUT_UNREADABLE'):self.run_prepare()
 def test_insecure_output_refused(self):
  self.root.chmod(0o755)
  with self.assertRaisesRegex(m.CheckError,'PRIVATE_DIRECTORY_REQUIRED'):self.run_prepare()
 def test_bad_stock_creates_no_material(self):
  self.stock.write_bytes(b'bad')
  with self.assertRaisesRegex(m.CheckError,'STOCK_MISMATCH'):self.run_prepare()
  self.assertEqual(list(self.root.iterdir()),[])
 def test_random_failure_no_material(self):
  m.secrets.token_bytes.side_effect=lambda n:b''
  with self.assertRaisesRegex(m.CheckError,'RANDOM_SOURCE_FAILURE'):self.run_prepare()
  self.assertEqual(list(self.root.glob('bootstrap-*')),[])
 def test_incomplete_write_does_not_publish_ready_metadata(self):
  original=m.write_new
  def fail(path,data):
   if path.name=='native-config.h':raise OSError('synthetic failure')
   return original(path,data)
  with patch.object(m,'write_new',side_effect=fail),self.assertRaises(OSError):self.run_prepare()
  self.assertEqual(list(self.root.glob('bootstrap-*/material.json')),[])
  with self.assertRaisesRegex(m.CheckError,'HOST_CLOCK_NOT_FRESH'):self.run_prepare()
 def test_concurrent_same_clock_only_one_prepared(self):
  from concurrent.futures import ThreadPoolExecutor
  def attempt():
   try:self.run_prepare();return 'prepared'
   except m.CheckError as e:return str(e)
  with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:attempt(),range(2)))
  self.assertEqual(sorted(results),['HOST_CLOCK_NOT_FRESH','prepared'])
  self.assertEqual(len(list(self.root.glob('bootstrap-*/material.json'))),1)
 def test_invalid_clock_refused(self):
  self.clock.return_value=0
  with self.assertRaisesRegex(m.CheckError,'HOST_CLOCK_NOT_FRESH'):self.run_prepare()
if __name__=='__main__':unittest.main(verbosity=2)
