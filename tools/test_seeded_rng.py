"""Host oracle and bounded-state tests. No native candidate integration."""
from pathlib import Path
import ctypes as C,hashlib,json,os,subprocess,tempfile
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms
ROOT=Path(__file__).resolve().parents[1];N=ROOT/'work/uv310-wireguard/seeded-rng';S=ROOT/'work/uv310-wireguard/wg-port/upstream/src';R=S/'crypto/refc'
class State(C.Structure):_fields_=[('cipher',C.c_uint32*16),('state',C.c_uint32)]
checks=[]
def verify(name,condition):
 assert condition,name
 checks.append(name)
with tempfile.TemporaryDirectory() as tmp:
 lib=Path(tmp)/'rng.dylib';cc=os.environ.get('HOST_CC','clang')
 subprocess.run([cc,'-shared','-fPIC','-O2','-I'+str(R),str(N/'seeded_rng.c'),str(R/'chacha20.c'),'-o',str(lib)],check=True)
 dll=C.CDLL(str(lib));dll.seeded_rng_init.argtypes=[C.POINTER(State),C.c_void_p];dll.seeded_rng_init.restype=C.c_bool;dll.seeded_rng_read.argtypes=[C.POINTER(State),C.c_void_p,C.c_size_t];dll.seeded_rng_read.restype=C.c_bool;dll.seeded_rng_close.argtypes=[C.POINTER(State)]
 def init(seed):
  r=State();assert dll.seeded_rng_init(C.byref(r),C.create_string_buffer(seed));return r
 def draw(r,n):
  out=C.create_string_buffer(b'\xa5'*max(n,1));ok=dll.seeded_rng_read(C.byref(r),out,n);return ok,out.raw[:n]
 for case,seed in enumerate([bytes(32),bytes(range(32)),bytes([255])*32]):
  r=init(seed);stream=Cipher(algorithms.ChaCha20(seed,bytes(16)),mode=None).encryptor().update(bytes(64*10))
  for block,n in enumerate([1,32,64,4,63,16,8,33,2,64]):
   ok,out=draw(r,n);verify(f'oracle-{case}-{block}',ok and out==stream[block*64:block*64+n] and r.cipher[12]==block+1)
 r=init(bytes(range(32)));before=bytes(r);ok,_=draw(r,0);verify('zero-length-does-not-advance',ok and bytes(r)==before)
 verify('reinit-refused-without-rewind',not dll.seeded_rng_init(C.byref(r),C.create_string_buffer(bytes(32))) and bytes(r)==before)
 verify('oversized-request-refused',not draw(r,65)[0] and bytes(r)==before)
 verify('null-output-refused',not dll.seeded_rng_read(C.byref(r),None,1) and bytes(r)==before)
 r.cipher[12]=65535;ok,out=draw(r,32)
 oracle=Cipher(algorithms.ChaCha20(bytes(range(32)),(65535).to_bytes(4,'little')+bytes(12)),mode=None).encryptor().update(bytes(32))
 verify('last-budget-block',ok and out==oracle and r.cipher[12]==65536)
 ok,out=draw(r,32);verify('budget-exhaustion-zeroes-output-and-state',not ok and out==bytes(32) and bytes(r.cipher)==bytes(64) and r.state==2)
 verify('closed-state-cannot-reinitialize',not dll.seeded_rng_init(C.byref(r),C.create_string_buffer(bytes(32))))
 r=State();ok,out=draw(r,32);verify('unseeded-fails-closed',not ok and out==bytes(32) and r.state==2)
 r=init(bytes(range(32)));dll.seeded_rng_close(C.byref(r));verify('explicit-close-wipes',bytes(r.cipher)==bytes(64) and r.state==2)
 # Genuine negative control: resetting counter is detected against the independent stream.
 r=init(bytes(range(32)));draw(r,32);r.cipher[12]=0;ok,bad=draw(r,32)
 expected=Cipher(algorithms.ChaCha20(bytes(range(32)),bytes(16)),mode=None).encryptor().update(bytes(128))[64:96]
 verify('counter-rewind-negative-control',ok and bad!=expected)
 result={'scope':'Host-only ChaCha20 oracle and wrapper lifecycle; not device or WG integration','checks':checks,'checks_passed':len(checks),'state_bytes':C.sizeof(State),'block_budget':65536,'max_request_bytes':64,'dedicated_fresh_seed_bytes':32,'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [N/'seeded_rng.c',N/'seeded_rng.h',R/'chacha20.c',R/'chacha20.h',Path(__file__)]},'oracle':'cryptography ChaCha20, counter<2^32 and zero nonce (compatible state layout in this range)','hardware_verified':False,'integrated':False,'limitations':['No reseed or backtracking protection','Fresh dedicated seed required each boot; snapshot/seed reuse repeats output','Caller must serialize; no interrupt/concurrency guarantee','Raw state corruption or rollback is not detected by wrapper','No final linked layout or ARM execution tested']}
 out=ROOT/'.test-results';out.mkdir(exist_ok=True);(out/'seeded-rng-tests.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS',len(checks),'host checks; state',C.sizeof(State),'bytes')
