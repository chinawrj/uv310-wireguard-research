"""All credentials and firmware are synthetic; no device or network."""
import base64,contextlib,hashlib,importlib.util,io,json,os,socket,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('bootstrap_check',Path(__file__).with_name('check.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
KEY=base64.b64encode(bytes(range(1,33))).decode()
CONFIG=f'[Interface]\nPrivateKey={KEY}\nAddress=10.77.0.2/24\nDNS=1.1.1.1\n[Peer]\nPublicKey={KEY}\nEndpoint=203.0.113.7:51820\nAllowedIPs=0.0.0.0/0\n'
class Cases(unittest.TestCase):
 def error(self,text,code):
  with self.assertRaises(m.CheckError) as e:m.parse_config(text.encode())
  self.assertEqual(str(e.exception),code)
 def test_supported_shape(self):self.assertTrue(m.parse_config(CONFIG.encode())['configuration_shape_supported'])
 def test_psk_optional_and_valid(self):self.assertTrue(m.parse_config((CONFIG+'PresharedKey='+KEY+'\n').encode())['preshared_key_present'])
 def test_zero_psk_permitted(self):self.assertTrue(m.parse_config((CONFIG+'PresharedKey='+base64.b64encode(bytes(32)).decode()).encode())['preshared_key_present'])
 def test_bad_and_zero_identity_keys(self):
  for key in ['INVALID',base64.b64encode(bytes(31)).decode(),base64.b64encode(bytes(32)).decode()]:self.error(CONFIG.replace(KEY,key),'INVALID_KEY')
 def test_duplicate_peer(self):self.error(CONFIG+'[Peer]\n','CONFIG_SYNTAX')
 def test_defaults_rejected(self):self.error('[DEFAULT]\nDNS=1.1.1.1\n'+CONFIG,'ONE_INTERFACE_ONE_PEER_REQUIRED')
 def test_unknown_options_not_ignored(self):
  for option in ['PersistentKeepalive=25','PostUp=echo SECRET','Table=off']:self.error(CONFIG+option,'UNSUPPORTED_OPTION')
 def test_ipv6_and_multiple_addresses(self):
  for value in ['fd00::2/64','10.77.0.2/24,10.77.0.3/24']:self.error(CONFIG.replace('10.77.0.2/24',value),'SINGLE_IPV4_ADDRESS_REQUIRED')
 def test_dns_local_or_multiple_rejected(self):
  for value in ['192.168.100.1','1.1.1.1,8.8.8.8','::1']:self.error(CONFIG.replace('DNS=1.1.1.1','DNS='+value),'SINGLE_TUNNEL_DNS_REQUIRED')
 def test_hostname_endpoint_no_resolution(self):
  with patch.object(socket,'getaddrinfo',side_effect=AssertionError('No DNS')):self.error(CONFIG.replace('203.0.113.7','example.invalid'),'IPV4_LITERAL_ENDPOINT_REQUIRED')
 def test_ports(self):
  for port in ['0','65536','abc']:self.error(CONFIG.replace(':51820',':'+port),'INVALID_ENDPOINT_PORT')
 def test_split_tunnel_rejected(self):self.error(CONFIG.replace('0.0.0.0/0','10.0.0.0/8'),'IPV4_DEFAULT_ROUTE_REQUIRED')
 def test_mtu_and_missing_fields(self):
  self.error(CONFIG.replace('DNS=1.1.1.1','DNS=1.1.1.1\nMTU=1500'),'UNSUPPORTED_MTU');self.error(CONFIG.replace('DNS=1.1.1.1\n',''),'MISSING_OPTION')
 def test_file_permissions_symlink_and_size(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'config';p.write_text(CONFIG);p.chmod(0o644)
   with self.assertRaisesRegex(m.CheckError,'CONFIG_PERMISSIONS'):m.read_regular(p,65536,True)
   p.chmod(0o600);self.assertEqual(m.read_regular(p,65536,True),CONFIG.encode())
   link=Path(td)/'link';link.symlink_to(p)
   with self.assertRaisesRegex(m.CheckError,'INPUT_UNREADABLE'):m.read_regular(link,65536,True)
   with self.assertRaisesRegex(m.CheckError,'INPUT_TOO_LARGE'):m.read_regular(p,1,True)
 def test_wrong_stock_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'config';p.write_text(CONFIG);p.chmod(0o600);s=Path(td)/'stock';s.write_bytes(b'bad')
   with self.assertRaisesRegex(m.CheckError,'STOCK_MISMATCH'):m.check(p,s)
 def test_success_redacted_and_explicitly_not_deployable(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'config';p.write_text(CONFIG);p.chmod(0o600);s=Path(td)/'stock';data=b'synthetic';s.write_bytes(data)
   with patch.object(m,'STOCK_BYTES',len(data)),patch.object(m,'STOCK_SHA',hashlib.sha256(data).hexdigest()):result=m.check(p,s)
   encoded=json.dumps(result);self.assertNotIn(KEY,encoded);self.assertNotIn('203.0.113.7',encoded);self.assertFalse(result['deployable']);self.assertFalse(result['network_access'])
 def test_cli_errors_do_not_echo_secret(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'config';p.write_text(CONFIG.replace('[Peer]','[PRIVATE_SECRET'));p.chmod(0o600);out=io.StringIO()
   with patch('sys.argv',['check','--config',str(p),'--stock',str(Path(td)/'missing')]),contextlib.redirect_stdout(out):self.assertEqual(m.main(),2)
   self.assertEqual(json.loads(out.getvalue())['error'],'CONFIG_SYNTAX');self.assertNotIn('PRIVATE_SECRET',out.getvalue())
if __name__=='__main__':unittest.main(verbosity=2)
