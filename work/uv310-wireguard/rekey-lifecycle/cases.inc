static struct message_handshake_response response,old_response;
static struct wireguard_keypair old_server;
static u32 inject_claim;
void fixture_before_claim(u32 expected){
 if(expected==3&&inject_claim){inject_claim=0;frame(1,&response,92);intercept(1,0x35000);}
}
static int make_response(void){
 struct message_handshake_initiation init;memcpy(&init,sent+42,148);
 CHECK(sent_bytes==190&&wireguard_check_mac1(&server,(u8*)&init,116,init.mac1));
 CHECK(wireguard_process_initiation_message(&server,&init)==&server.peers[0]);
 CHECK(wireguard_create_handshake_response(&server,&server.peers[0],&response));
 wireguard_start_session(&server.peers[0],false);return 0;
}
static int complete_response(void){
 frame(1,&response,92);CHECK(intercept(1,0x35000)==1&&phase==4);
 signal_timer(0);worker();CHECK(phase==9&&!stopped&&control_ready==2);
 signal_timer(0);CHECK(!control_ready&&!control_packet&&submitted==freed);
 struct wireguard_keypair*k=&server.peers[0].next_keypair;
 CHECK(sent_bytes==74&&U8TO32_LITTLE(sent+46)==k->local_index);
 CHECK(wireguard_decrypt_packet(decoded,sent+58,16,U8TO64_LITTLE(sent+50),k));
 CHECK(wireguard_check_replay(k,U8TO64_LITTLE(sent+50)));
 keypair_update(&server.peers[0],k);active_server_key=&server.peers[0].curr_keypair;return 0;
}
static int one_forward(u32,u32);
static int late_packet(struct wireguard_keypair*k,int accepted){
 /* Valid inner echo reply under explicitly selected old/new transport key. */
 memset(decoded,0,32);decoded[0]=0x45;put16(decoded+2,28);decoded[8]=64;decoded[9]=1;
 memcpy(decoded+12,INNER_DEST,4);memcpy(decoded+16,INNER_SOURCE,4);
 memset(reply,0,16);reply[0]=4;U32TO8_LITTLE(reply+4,k->remote_index);U64TO8_LITTLE(reply+8,k->sending_counter);
 wireguard_encrypt_packet(reply+16,decoded,32,k);u32 before=f_rx;
 frame(1,reply,64);CHECK(intercept(1,0x35000)==(accepted?0:1));CHECK(f_rx==before+(accepted?1:0));
 if(accepted){frame(1,reply,64);CHECK(intercept(1,0x35000)==1&&f_rx==before+1);}return 0;
}
int tests(void){
#ifdef TEST_TAI_CARRY
 u8 last[12],now[12];u32 serials[]={0,1,999999999u,1000000000u,2000000000u,4294967294u};
 for(u32 i=0;i<6;i++){
  attempts=serials[i];wireguard_tai64n_now(now);
  u32 n=((u32)now[8]<<24)|((u32)now[9]<<16)|((u32)now[10]<<8)|now[11];CHECK(n<1000000000u);
  if(i)CHECK(memcmp(last,now,12)<0);memcpy(last,now,12);
 }
 return 0;
#endif
 W(0x33d18)=0x33e00;W(0x33e18)=0x33f00;W(0x33f04)=0x34000;W(0x33f0c)=0x34100;W(0x34148)=64;W(0x33f3c)=0x33c00;
 ordinary(1,0);CHECK(intercept(0,0x35000)==1&&phase==1);
 signal_timer(0);worker();CHECK(phase==2&&attempts==1);signal_timer(0);CHECK(phase==3&&submitted==freed);
 CHECK(wireguard_device_init(&server,SERVER_PRIVATE));CHECK(wireguard_peer_init(&server,&server.peers[0],CLIENT_PUBLIC,PRESHARED_KEY));
 CHECK(make_response()==0);CHECK(complete_response()==0);old_response=response;
 struct wireguard_peer*p=&fixture_device()->peers[0];
#ifdef TEST_BASELINE
 CHECK(forward_tests()==0);return 0;
#endif
 CHECK(one_forward(17,31)==0);CHECK(one_forward(6,0)==0);CHECK(one_forward(1,11)==0);
 u32 first_index=p->curr_keypair.local_index,first_start=p->curr_keypair.keypair_millis;
#ifdef TEST_WRAP
 first_start=0xffff0000u;p->curr_keypair.keypair_millis=first_start;
#endif
 fixture_clock=first_start+119999;last_keepalive=fixture_clock;signal_timer(0);worker();CHECK(phase==9&&attempts==1&&!control_ready);
#ifdef TEST_COUNT_REKEY
 p->curr_keypair.sending_counter=REKEY_AFTER_MESSAGES;
#else
 fixture_clock=first_start+120000;
#endif
#ifdef TEST_RNG_FAIL
 rng_pos=sizeof(RANDOM_POOL);
#endif
 signal_timer(0);worker();
#ifdef TEST_RNG_FAIL
 CHECK(!stopped&&phase==9&&err==2&&handshake_failures==1&&!control_ready);
 CHECK(p->curr_keypair.valid&&p->curr_keypair.local_index==first_index);CHECK(one_forward(17,13)==0);
 u32 tries=attempts;signal_timer(0);worker();CHECK(attempts==tries);
 fixture_clock=first_start+180000;ordinary(17,13);CHECK(intercept(0,0x35000)==1);signal_timer(0);worker();CHECK(!p->curr_keypair.valid&&!stopped);return 0;
#endif
 CHECK(phase==2&&attempts==2&&p->curr_keypair.valid&&p->curr_keypair.local_index==first_index);
 CHECK(one_forward(17,19)==0); /* forwarding while initiation is queued */
#ifdef TEST_QUEUE_EXPIRE
 fixture_clock+=5000;u32 submits=submitted;signal_timer(0);CHECK(submitted==submits&&phase==3&&!control_ready&&!stopped);
 CHECK(one_forward(17,20)==0);worker();CHECK(phase==2&&attempts==3);return 0;
#endif
 signal_timer(0);CHECK(phase==3&&submitted==freed);
 CHECK(make_response()==0);old_server=server.peers[0].curr_keypair;
 CHECK(one_forward(17,21)==0); /* forwarding while waiting for response */
#ifdef TEST_BAD_MAC
 response.mac1[0]^=1;
#elif defined(TEST_BAD_AEAD)
 ((u8*)&response)[44]^=1;wireguard_blake2s(response.mac1,16,server.peers[0].label_mac1_key,32,&response,60);
#elif defined(TEST_STALE_RESPONSE)
 response=old_response;
#endif
#if defined(TEST_BAD_MAC)||defined(TEST_BAD_AEAD)||defined(TEST_STALE_RESPONSE)
 frame(1,&response,92);CHECK(intercept(1,0x35000)==1&&phase==4);signal_timer(0);worker();
 CHECK(phase==3&&!stopped&&handshake_failures==1&&p->curr_keypair.local_index==first_index);CHECK(one_forward(17,23)==0);
 fixture_clock=last_send+5000;signal_timer(0);worker();CHECK(phase==2&&attempts==3);signal_timer(0);CHECK(make_response()==0);CHECK(complete_response()==0);CHECK(renewals==1);CHECK(one_forward(17,25)==0);return 0;
#endif
#ifdef TEST_CLAIM_RACE
 fixture_clock=last_send+5000;inject_claim=1;signal_timer(0);worker();
 CHECK(phase==4&&attempts==2&&inject_claim==0);
 CHECK(complete_response()==0&&renewals==1);CHECK(one_forward(17,23)==0);return 0;
#endif
#ifdef TEST_RETRY
 fixture_clock=last_send+4999;signal_timer(0);worker();CHECK(phase==3&&attempts==2);
 fixture_clock++;signal_timer(0);worker();CHECK(phase==2&&attempts==3);CHECK(one_forward(17,23)==0);
 signal_timer(0);CHECK(make_response()==0);
#endif
#ifdef TEST_RETRY_LIMIT
 for(u32 i=0;i<18;i++){
  fixture_clock=last_send+5000;signal_timer(0);worker();
  if(i<17){CHECK(phase==2&&!stopped);signal_timer(0);}else CHECK(phase==9&&!stopped&&!p->handshake.valid);
 }
 u32 tries=attempts;fixture_clock+=10000;signal_timer(0);worker();CHECK(attempts==tries&&phase==9);
 ordinary(17,13);CHECK(intercept(0,0x35000)==1);signal_timer(0);worker();CHECK(phase==2&&attempts==tries+1);
 signal_timer(0);CHECK(make_response()==0);CHECK(complete_response()==0);CHECK(one_forward(17,27)==0);return 0;
#endif
 frame(1,&response,92);CHECK(intercept(1,0x35000)==1&&phase==4);CHECK(one_forward(17,23)==0);old_server=server.peers[0].curr_keypair;
#ifdef TEST_PUBLISH_EXPIRY
 inject_publish=1;signal_timer(0);worker();CHECK(!stopped&&phase==9&&control_ready==2);
 u32 before_publish=submitted;signal_timer(0);CHECK(!control_ready&&submitted==before_publish&&!stopped);return 0;
#endif
#ifdef TEST_ALLOC_EXPIRE
 signal_timer(0);worker();CHECK(phase==9&&control_ready==2);u32 submits=submitted,bytes=W(0x2688),headers=W(0x26a4);expiry_alloc=1;
 signal_timer(0);CHECK(!stopped&&submitted==submits&&!control_ready&&!control_packet&&W(0x2688)==bytes&&W(0x26a4)==headers);return 0;
#endif
 /* Worker has not processed buffered response; complete_response replays frame,
  * which is ignored while phase4, then processes the already-buffered response. */
 CHECK(complete_response()==0);CHECK(renewals==1&&p->prev_keypair.local_index==first_index&&p->curr_keypair.local_index!=first_index);
 CHECK(one_forward(17,25)==0);CHECK(one_forward(6,0)==0);CHECK(one_forward(1,11)==0);
#ifdef TEST_COUNT_REJECT
 p->curr_keypair.sending_counter=REJECT_AFTER_MESSAGES;u32 limit_tx=f_tx;ordinary(17,9);CHECK(intercept(0,0x35000)==1&&f_tx==limit_tx);
 old_server.sending_counter=REJECT_AFTER_MESSAGES;CHECK(late_packet(&old_server,0)==0);return 0;
#endif
 CHECK(late_packet(&old_server,1)==0);
 fixture_clock=first_start+179999;CHECK(late_packet(&old_server,1)==0);
 fixture_clock++;CHECK(late_packet(&old_server,0)==0);CHECK(one_forward(17,29)==0);
 last_keepalive=fixture_clock;signal_timer(0);worker();CHECK(!p->prev_keypair.valid);
 /* Delay every timer/worker past new-key expiry: the packet hook itself must reject. */
 fixture_clock=p->curr_keypair.keypair_millis+180000;u32 tx=f_tx;ordinary(17,9);CHECK(intercept(0,0x35000)==1&&f_tx==tx);
 CHECK(late_packet(active_server_key,0)==0);signal_timer(0);worker();CHECK(!p->curr_keypair.valid&&phase==2&&!stopped);
 signal_timer(0);CHECK(make_response()==0);CHECK(complete_response()==0);CHECK(one_forward(17,31)==0);
 CHECK(submitted==freed&&!control_packet);return 0;
}
