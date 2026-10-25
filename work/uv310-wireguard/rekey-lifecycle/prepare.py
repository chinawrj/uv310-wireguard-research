"""Offline renewal adapter. Never produce a live image."""
from pathlib import Path
import json,hashlib
P=Path('work/uv310-wireguard');N=P/'rekey-lifecycle';base=P/'rng-provider/native.c';s=base.read_text()
def rep(a,b):
 global s
 assert s.count(a)==1,(a[:70],s.count(a));s=s.replace(a,b)
rep('/* Automatic first-client handshake, one provisioned session only. NOT reboot-safe production firmware. */','''/* Offline renewal integration: RNG/time/persistence remain unresolved. */
#ifndef SYNTHETIC_TEST
#error This branch is a synthetic integration test, not a deployable image
#endif''')
rep('static struct wireguard_device dev;','''extern volatile u32 phase;
static struct wireguard_device dev;
struct wireguard_device *fixture_device(void){return &dev;}
#define KEY_RENEW_MS (REKEY_AFTER_TIME*1000u)
#define KEY_REJECT_MS (REJECT_AFTER_TIME*1000u)
#define RETRY_MS (REKEY_TIMEOUT*1000u)
#define MAX_TRIES 18u
static u32 initialized,cycle_tries,retry_paused,demand,try_started,retry_wait;
u32 renewals,handshake_failures;
static u32 control_key_index;
static int key_live(struct wireguard_keypair*k,u32 now){return k->valid&&(u32)(now-k->keypair_millis)<KEY_REJECT_MS;}
static int can_send(u32 now){struct wireguard_keypair*k=&dev.peers[0].curr_keypair;return key_live(k,now)&&k->sending_valid&&k->sending_counter<REJECT_AFTER_MESSAGES;}
static int data_phase(void){return phase==2||phase==3||phase==4||phase==9;}''')
a=s.index('static int control_expired(');b=s.index('/* Single-client',a)
s=s[:a]+'''static int control_expired(u32 kind,u32 now){
 if(kind==1)return (u32)(now-control_queued_at)>=RETRY_MS;
 if(kind==2)return !can_send(now)||control_key_index!=dev.peers[0].curr_keypair.local_index;
 return 1;
}
static void discard_control(u32 kind){
 control_ready=0;control_errors++;
 if(kind==1){last_send=control_queued_at;publish_phase(3);}
}
/* Claim under PRIMASK: a just-arrived response cannot be replaced by retry. */
extern void fixture_before_claim(u32 expected);
static int claim_phase(u32 expected,u32 busy){
 fixture_before_claim(expected);
 u32 mask;__asm__ volatile("mrs %0,primask\\n cpsid i":"=r"(mask)::"memory");
 int ok=!stopped&&phase==expected;if(ok)phase=busy;
 __asm__ volatile("msr primask,%0"::"r"(mask):"memory");return ok;
}
static void expire_keys(u32 now){
 struct wireguard_peer*p=&dev.peers[0];
 struct wireguard_keypair*k[3]={&p->curr_keypair,&p->prev_keypair,&p->next_keypair};
 for(u32 i=0;i<3;i++)if(k[i]->valid&&!key_live(k[i],now))keypair_destroy(k[i]);
}
''' +s[b:]
rep('if(!dev.peers[0].curr_keypair.valid||wireguard_sys_now()-session_start>=60000)return drop(0x25);','u32 now=wireguard_sys_now();\n if(!dir&&!can_send(now))return drop(0x25);')
rep('wireguard_encrypt_packet(inner,inner,padded,&dev.peers[0].curr_keypair);','wireguard_encrypt_packet(inner,inner,padded,&dev.peers[0].curr_keypair);\n  dev.peers[0].curr_keypair.last_tx=now;')
a=s.index(' if(plen<32||U8TO32_LITTLE(wg)!=4');b=s.index(' if(!padded)',a)
s=s[:a]+''' if(plen<32||U8TO32_LITTLE(wg)!=4)return drop(0x2a);
 struct wireguard_keypair*k=get_peer_keypair_for_idx(&dev.peers[0],U8TO32_LITTLE(wg+4));
 uint64_t count=U8TO64_LITTLE(wg+8);u32 padded=plen-32;u8*inner=wg+16;
 if(!k||!key_live(k,now)||!k->receiving_valid||count>=REJECT_AFTER_MESSAGES)return drop(0x2a);
 if(!wireguard_decrypt_packet(inner,inner,plen-16,count,k)||!wireguard_check_replay(k,count))return drop(0x2b);
 k->last_rx=now;
''' +s[b:]
rep('if(stopped)return;control_queued_at=wireguard_sys_now();','if(stopped)return;control_queued_at=wireguard_sys_now();\n control_key_index=dev.peers[0].curr_keypair.local_index;')
rep('static void prepare_keepalive(void){\n u8 message[32];','static void prepare_keepalive(void){\n if(!can_send(wireguard_sys_now()))return;\n u8 message[32];')
rep('if(control_expired(kind,wireguard_sys_now())){fail(0xe7);return;}','if((kind==1&&phase!=2)||(kind==2&&phase!=9))return;\n if(control_expired(kind,wireguard_sys_now())){discard_control(kind);return;}')
rep('if(stopped||control_expired(kind,wireguard_sys_now())){raw_packet_free(p);fail(0xe7);return;}','if(stopped||control_expired(kind,wireguard_sys_now())){raw_packet_free(p);discard_control(kind);return;}')
rep('if(!stopped&&phase==9)return forward(dir,pkt);\n  return drop(0x37);','if(!stopped&&data_phase()){demand=1;return forward(dir,pkt);}\n  return drop(0x37);')
rep('if(!stopped&&phase==9)return forward(dir,pkt);\n if(!memcmp(ip+12,LAN_GATEWAY,3))return 0;','if(!memcmp(ip+12,LAN_GATEWAY,3))return 0;')
rep('return drop(0x38); /* Never deliver handshake/control UDP to client stack. */','if(!stopped&&data_phase())return forward(dir,pkt);\n return drop(0x38); /* Never deliver handshake/control UDP to client stack. */')
a=s.index('void wireguard_tai64n_now(');b=s.index('bool wireguard_is_under_load(',a)
s=s[:a]+'''void wireguard_tai64n_now(u8*v){
 memcpy(v,TAI64N,12);
 u32 nano=((u32)v[8]<<24)|((u32)v[9]<<16)|((u32)v[10]<<8)|v[11];
 u32 carry=attempts/1000000000u;nano+=attempts%1000000000u;
 if(nano>=1000000000u){nano-=1000000000u;carry++;}
 for(int i=7;i>=0&&carry;i--){u32 sum=v[i]+carry;v[i]=(u8)sum;carry=sum>>8;}
 v[8]=nano>>24;v[9]=nano>>16;v[10]=nano>>8;v[11]=nano;
}
''' +s[b:]
a=s.index('void worker(void){');b=s.index('void snapshot(void){',a)
s=s[:a]+(N/'worker.inc').read_text()+s[b:]
(N/'native.c').write_text(s)
(N/'source-provenance.json').write_text(json.dumps({'base_native_sha256':hashlib.sha256(base.read_bytes()).hexdigest(),'new_native_sha256':hashlib.sha256(s.encode()).hexdigest(),'offline_only_compile_guard':True,'live_image_generated':False},indent=2)+'\n')
