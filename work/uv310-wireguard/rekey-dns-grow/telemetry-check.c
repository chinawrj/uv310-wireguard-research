/* Included only by the isolated proposed telemetry test, never production. */
static int telemetry_check(void){
 extern u32 dhcp_rewrites,dhcp_rejects,lan_dns_drops,rx_count;
 u32 saved_rx=rx_count,saved_rng=rng_pos,alloc_before=alloc_calls,free_before=raw_frees;
 u32 a[16]={0};const char *prefix="5.90.153.52.1 ";u32 off=14;
 CHECK(strlen(prefix)==off);
 for(u32 round=0;round<3;round++){
  dhcp_rewrites=round==0?0x01020304u:round==1?0xffffffffu:0;
  dhcp_rejects=round==0?0x87654321u:round==1?0:0xffffffffu;
  lan_dns_drops=round==0?0xdeadbeefu:round==1?0xffffffffu:1;
  rx_count=0x12345678u;
  for(u32 page=0;page<5;page++){
   memset(version,0x5a,192);snapshot();
   CHECK(!memcmp(version,prefix,off)&&version[off]=="AERMN"[page]&&version[off+1]=='=');
   u32 words[16];
   for(u32 i=0;i<16;i++){
    u32 value=0;
    for(u32 k=0;k<8;k++){
     char ch=version[off+2+i*9+k];CHECK((ch>='0'&&ch<='9')||(ch>='a'&&ch<='f'));
     value=(value<<4)|(ch<='9'?ch-'0':ch-'a'+10);
    }
    words[i]=value;CHECK(version[off+2+i*9+8]==(i==15?0:','));
   }
   for(u32 i=off+2+143+1;i<192;i++)CHECK(version[i]==0x5a);
   if(page==0)memcpy(a,words,sizeof(a));
   if(page==4){
    CHECK(words[0]==dhcp_rewrites&&words[1]==dhcp_rejects&&words[2]==lan_dns_drops);
    for(u32 i=3;i<16;i++)CHECK(words[i]==a[i]);
   }
  }
  CHECK(dhcp_rewrites==(round==0?0x01020304u:round==1?0xffffffffu:0));
  CHECK(dhcp_rejects==(round==0?0x87654321u:round==1?0:0xffffffffu));
  CHECK(lan_dns_drops==(round==0?0xdeadbeefu:round==1?0xffffffffu:1));
 }
 CHECK(phase==0&&rng_pos==saved_rng&&alloc_calls==alloc_before&&raw_frees==free_before);
 rx_count=saved_rx;dhcp_rewrites=dhcp_rejects=lan_dns_drops=0;
 return 0;
}
