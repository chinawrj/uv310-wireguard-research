/* Crypto remains in the idle worker. While phase10/11/12 owns mutable state,
 * interrupt packet hooks drop external traffic instead of racing crypto. */
void worker(void){
 u32 ipsr,primask;__asm__ volatile("mrs %0,ipsr":"=r"(ipsr));__asm__ volatile("mrs %0,primask":"=r"(primask));
 if(stopped||ipsr||primask||!pending)return;pending=0;worker_count++;
 u32 current=phase,now=wireguard_sys_now();
 if(current==3){
  if((u32)(now-last_send)<RETRY_MS||control_packet)return;
  if(!claim_phase(3,10))return;
  if(cycle_tries>=MAX_TRIES){
   crypto_zero(&dev.peers[0].handshake,sizeof(dev.peers[0].handshake));
   retry_paused=1;demand=0;retry_wait=1;try_started=now;publish_phase(9);return;
  }
  current=1;
 }else if(current==9){
  if(!claim_phase(9,12))return;
  expire_keys(now);
  if(!control_ready&&!control_packet&&
    (!retry_wait||(u32)(now-try_started)>=RETRY_MS)&&(!retry_paused||demand)&&
    (!can_send(now)||(u32)(now-dev.peers[0].curr_keypair.keypair_millis)>=KEY_RENEW_MS||dev.peers[0].curr_keypair.sending_counter>=REKEY_AFTER_MESSAGES)){
   retry_paused=0;demand=0;cycle_tries=0;current=1;publish_phase(10);
  }else{
   if(can_send(now)&&(u32)(now-last_keepalive)>=20000&&!control_ready&&!control_packet)prepare_keepalive();
   publish_phase(9);return;
  }
 }else if(current==1){if(!claim_phase(1,10))return;}
 else if(current==4){if(!claim_phase(4,11))return;}
 else return;
 u32 begin=wireguard_sys_now();
 expire_keys(begin);
 if(current==1){
  try_started=begin;retry_wait=1;cycle_tries++;
  /* Never reset this serial at rekey. Fixed synthetic TAI+serial is monotonic
   * within a run, but is NOT reboot-safe freshness. */
  if(attempts==0xffffffffu){fail(0xe8);return;}attempts++;
  if(!initialized){
   wireguard_init();
   if(!wireguard_device_init(&dev,PRIVATE_KEY)||!wireguard_peer_init(&dev,&dev.peers[0],PEER_KEY,PRESHARED_KEY)){fail(1);return;}
   initialized=1;
  }
  if(!wireguard_create_handshake_initiation(&dev,&dev.peers[0],(struct message_handshake_initiation*)initiation)||rng_failed){
   handshake_failures++;err=2;retry_paused=1;demand=0;publish_phase(9);
  }else{make_control(initiation,148,1);publish_phase(2);}
  init_time=wireguard_sys_now()-begin;
 }else{
  struct message_handshake_response*r=(void*)received;
  if((u32)(begin-try_started)>=KEY_REJECT_MS||r->receiver!=dev.peers[0].handshake.local_index||!wireguard_check_mac1(&dev,received,60,r->mac1)||!wireguard_process_handshake_response(&dev,&dev.peers[0],r)){
   handshake_failures++;err=3;crypto_zero(received,sizeof(received));publish_phase(3);
  }else{
   if(dev.peers[0].curr_keypair.valid)renewals++;
   wireguard_start_session(&dev.peers[0],true);session_start=dev.peers[0].curr_keypair.keypair_millis;
   retry_paused=0;retry_wait=0;cycle_tries=0;demand=0;err=0;
   crypto_zero(received,sizeof(received));prepare_keepalive();publish_phase(9);
  }
  response_time=wireguard_sys_now()-begin;
 }
}
