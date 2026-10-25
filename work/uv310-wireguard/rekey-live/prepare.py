"""Prepare a bounded one-boot interoperability experiment; no USB/private inputs."""
from pathlib import Path
import hashlib,json
P=Path('work/uv310-wireguard');N=P/'rekey-live';L=P/'rekey-lifecycle'
N.mkdir(exist_ok=True)
s=(L/'native.c').read_text()
s=s.replace('#ifndef SYNTHETIC_TEST\n#error This branch is a synthetic integration test, not a deployable image', '#if !defined(SYNTHETIC_TEST) && !defined(BOUNDED_REKEY_LAB)\n#error Explicit bounded one-boot lab build required')
s=s.replace('extern void fixture_before_claim(u32 expected);','#ifdef SYNTHETIC_TEST\nextern void fixture_before_claim(u32 expected);\n#endif')
s=s.replace(' fixture_before_claim(expected);','#ifdef SYNTHETIC_TEST\n fixture_before_claim(expected);\n#endif')
s=s.replace('static u32 status_page;', 'static u32 status_page;\nu32 lab_started,lab_origin;\n#define LAB_MAX_TICKS 360000u\nstatic int lab_expired(void);')
s=s.replace(' if(stopped){phase=255;control_ready=0;}else phase=next;', ' if(lab_expired()||stopped){phase=255;control_ready=0;}else phase=next;')
needle='static int control_expired(u32 kind,u32 now){'
s=s.replace(needle, '''/* Bounds a single fresh provisioned experiment, NOT restart-safe entropy. */
static int lab_expired(void){
 if(lab_started&&(u32)(wireguard_sys_now()-lab_origin)>=LAB_MAX_TICKS){fail(0xe9);return 1;}
 return 0;
}
'''+needle+'\n if(lab_expired())return 1;')
s=s.replace(' if(stopped||!control_ready||control_packet)return;', ' if(lab_expired()||stopped||!control_ready||control_packet)return;')
s=s.replace('  if(!stopped&&phase==0){', '  if(lab_expired())return drop(0x25);\n  if(!stopped&&phase==0){')
s=s.replace('   source_context=src;', '   lab_origin=wireguard_sys_now();lab_started=1;\n   source_context=src;')
s=s.replace(' if(phase==0||memcmp(ip+16,client_ip,4))return 0;', ' if(phase==0||memcmp(ip+16,client_ip,4))return 0;\n if(lab_expired()&&memcmp(ip+12,LAN_GATEWAY,3))return drop(0x25);')
s=s.replace(' if(stopped||ipsr||primask||!pending)return;', ' if(lab_expired()||stopped||ipsr||primask||!pending)return;')
s=s.replace(' if(status_page){u32 e[16]', ' if(status_page==1){u32 e[16]')
s=s.replace(' char*p=version;', ''' if(status_page==2){
  struct wireguard_peer*p=&dev.peers[0];u32 now=wireguard_sys_now();
  u32 r[16]={renewals,handshake_failures,rng_failed,sizeof(RANDOM_POOL),session_start,now-session_start,
    p->curr_keypair.local_index,p->prev_keypair.local_index,p->curr_keypair.valid,p->prev_keypair.valid,
    lab_started,lab_started?now-lab_origin:0,LAB_MAX_TICKS,stopped,W(0x2690),now};memcpy(v,r,sizeof(v));
 }
 char*p=version;''')
s=s.replace("*p++=status_page?'E':'A';*p++='=';status_page^=1;", "*p++=\"AER\"[status_page];*p++='=';status_page=(status_page+1)%3;")
(N/'native.c').write_text(s)
t=(L/'tests.c').read_text().replace('extern u32 renewals,handshake_failures,rng_failed;', 'extern u32 renewals,handshake_failures,rng_failed,lab_origin;')
t=t.replace('first_start=0xffff0000u;p->curr_keypair.keypair_millis=first_start;', 'first_start=0xffff0000u;p->curr_keypair.keypair_millis=first_start;lab_origin=first_start;')
needle=' struct wireguard_peer*p=&fixture_device()->peers[0];'
t=t.replace(needle,needle+'''
#if defined(TEST_LAB_PACKET) || defined(TEST_LAB_TIMER) || defined(TEST_LAB_WORKER) || defined(TEST_LAB_WRAP)
#ifdef TEST_LAB_WRAP
 lab_origin=0xffff0000u;
#endif
 fixture_clock=lab_origin+359999;u32 submits=submitted;
 /* Packet hook must close at the boundary even without a timer/worker. */
#if defined(TEST_LAB_PACKET) || defined(TEST_LAB_WRAP)
 fixture_clock++;ordinary(17,9);CHECK(intercept(0,0x35000)==1);
#elif defined(TEST_LAB_TIMER)
 fixture_clock++;signal_timer(0);
#else
 fixture_clock++;worker();
#endif
 CHECK(stopped&&phase==255&&err==0xe9&&!control_ready&&submitted==submits);
 signal_timer(0);worker();CHECK(submitted==submits);return 0;
#endif
''')
(N/'tests.c').write_text(t)
(N/'native-config.h').write_text((L/'native-config.h').read_text())
build=(L/'build.py').read_text().replace("N=P/'rekey-lifecycle'", "N=P/'rekey-live'")
build=build.replace("'PUBLISH_EXPIRY']:", "'PUBLISH_EXPIRY','LAB_PACKET','LAB_TIMER','LAB_WORKER','LAB_WRAP']:")
build=build.replace("N/'worker.inc',", '')
build=build.replace('rekey-lifecycle-tests.json','rekey-live-tests.json')
(N/'test-build.py').write_text(build)
e={'derived_from_sha256':hashlib.sha256((L/'native.c').read_bytes()).hexdigest(),'candidate_source_sha256':hashlib.sha256(s.encode()).hexdigest(),'lab_lifetime_cached_ticks':360000,'hardware_written':False,'fresh_per_build_material_required':True,'persistent_startup_supported':False}
(N/'prepare.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e))
