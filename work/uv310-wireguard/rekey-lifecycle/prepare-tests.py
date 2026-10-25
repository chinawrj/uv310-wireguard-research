from pathlib import Path
import random,re
P=Path('work/uv310-wireguard');N=P/'rekey-lifecycle';H=P/'control-hardening'
h=(H/'native-config.h').read_text();assert '203,0,113,7' in h
# Published deterministic fixture, no user config or device material.
r=random.Random(310);pool=','.join(str(r.randrange(256)) for _ in range(1024))
h=re.sub(r'(RANDOM_POOL\s*\[)[^\]]*(\]\s*=\s*\{)[^}]*(\})',lambda m:m[1]+m[2]+pool+m[3],h)
(N/'native-config.h').write_text(h)
s=(H/'test.c').read_text();a=s.index('int tests(void){');b=s.index('static u32 frees;',a)
s=s[:a]+(N/'cases.inc').read_text()+'\n'+s[b:]
s=s.replace('volatile u32 fixture_clock,fixture_step=10;','volatile u32 fixture_clock=1000,fixture_step=0;')
s=s.replace('if(expiry_alloc)fixture_clock+=60000;','if(expiry_alloc)fixture_clock+=180000;')
s=s.replace('fixture_clock+=60000;emit_control();','fixture_clock+=180000;emit_control();')
s=s.replace('#define CHECK(x) do{if(!(x))return __LINE__;}while(0)','#define CHECK(x) do{if(!(x)){if(!failure_line)failure_line=__LINE__;return failure_line;}}while(0)')
s=s.replace('static struct wireguard_device server;','static struct wireguard_device server;\nstatic struct wireguard_keypair *active_server_key;\nvolatile unsigned failure_line;\nextern struct wireguard_device *fixture_device(void);\nextern u32 renewals,handshake_failures,rng_failed;')
s=s.replace('&server.peers[0].next_keypair','active_server_key') if False else s
# Only existing forwarding helpers use this substitution; lifecycle cases choose keys explicitly.
a=s.index('static int one_forward(')
s=s[:a]+s[a:].replace('&server.peers[0].next_keypair','active_server_key').replace('server.peers[0].next_keypair.','active_server_key->')
s=s.replace('session_start=wireguard_sys_now()-60001;','fixture_device()->peers[0].curr_keypair.keypair_millis=wireguard_sys_now()-180001;')
s+='''\nvoid print_fail(unsigned ignored){(void)ignored;unsigned n=failure_line;char msg[]="FAIL line=00000000\\n";for(unsigned i=0;i<8;i++)msg[10+i]="0123456789abcdef"[(n>>(28-4*i))&15];register unsigned r0 __asm__("r0")=4;register char*r1 __asm__("r1")=msg;__asm__ volatile("bkpt #0xab" : "+r"(r0):"r"(r1):"memory");}\n'''
(N/'tests.c').write_text(s)
