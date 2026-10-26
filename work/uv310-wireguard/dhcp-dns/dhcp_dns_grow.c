#include "dhcp_dns_grow.h"
static unsigned get16(const uint8_t *p) { return (unsigned)p[0]*256u+p[1]; }
static void put16(uint8_t *p,unsigned x) { p[0]=(uint8_t)(x>>8);p[1]=(uint8_t)x; }
static unsigned addsum(const uint8_t *p,size_t n,unsigned s) {
    while(n>=2){s+=get16(p);p+=2;n-=2;}if(n)s+=(unsigned)p[0]<<8;return s;
}
static unsigned finish(unsigned s) { while(s>>16)s=(s&65535u)+(s>>16);return (~s)&65535u; }
int dhcp_dns_rewrite_grow(uint8_t *b,size_t *size,size_t capacity,
                          const uint8_t server[4],const uint8_t dns[4]) {
    if(!size||!b||capacity<*size) return DHCP_DNS_REJECT;
    size_t n=*size;
    int result=dhcp_dns_rewrite(b,n,server,dns);
    if(result!=DHCP_DNS_NO_SPACE) return result;
    /* NO_SPACE guarantees a validated OFFER/ACK, no DNS anywhere, valid
     * checksum and a main END, without any mutation by the base transformer. */
    unsigned h=(b[14]&15u)*4u;
    size_t udp_start=14+h,udp_len=get16(b+udp_start+4);
    size_t end=udp_start+8+240,udp_end=udp_start+udp_len;
    while(b[end]!=255) {
        if(b[end]==0)end++;else end+=2u+b[end+1];
    }
    size_t pad=0;
    while(pad<6&&end+1+pad<udp_end&&b[end+1+pad]==0)pad++;
    size_t growth=6-pad;
    if(growth>capacity-n||growth>2048u-n) return DHCP_DNS_NO_SPACE;
    /* No further failing operation after this point. Copy backward for overlap;
     * retain all DHCP bytes after consumed padding and all Ethernet tail bytes. */
    for(size_t i=n;i>end+1+pad;i--)b[i-1+growth]=b[i-1];
    b[end]=6;b[end+1]=4;
    for(unsigned i=0;i<4;i++)b[end+2+i]=dns[i];
    b[end+6]=255;
    uint8_t *ip=b+14,*udp=b+udp_start;
    put16(ip+2,get16(ip+2)+growth);put16(udp+4,udp_len+growth);
    ip[10]=ip[11]=0;put16(ip+10,finish(addsum(ip,h,0)));
    udp[6]=udp[7]=0;
    unsigned checksum=finish(addsum(udp,udp_len+growth,addsum(ip+12,8,17u+udp_len+growth)));
    put16(udp+6,checksum?checksum:65535u);
    *size=n+growth;
    return DHCP_DNS_REWRITTEN;
}
