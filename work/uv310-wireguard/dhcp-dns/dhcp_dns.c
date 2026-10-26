#include "dhcp_dns.h"
#define FRAME_LIMIT 2048u
#define BOOTP_FIXED 240u
struct options {
    unsigned dns_bytes, dns_seen, type, type_seen, overload, overload_seen;
    size_t main_end;
};
static unsigned get16(const uint8_t *p) { return (unsigned)p[0]*256u+p[1]; }
static void put16(uint8_t *p, unsigned x) { p[0]=(uint8_t)(x>>8); p[1]=(uint8_t)x; }
static int equal4(const uint8_t *a,const uint8_t *b) {
    return a[0]==b[0]&&a[1]==b[1]&&a[2]==b[2]&&a[3]==b[3];
}
static unsigned addsum(const uint8_t *p,size_t n,unsigned sum) {
    while(n>=2) { sum+=get16(p); p+=2; n-=2; }
    if(n) sum+=(unsigned)p[0]<<8;
    return sum;
}
static unsigned finish(unsigned sum) {
    while(sum>>16) sum=(sum&65535u)+(sum>>16);
    return (~sum)&65535u;
}
/* Parse first, write later. RFC3396 ordering: options, file, then sname.
 * DNS chunks need not be four-byte aligned individually; their aggregate must.
 */
static int scan(const uint8_t *p,size_t n,int main,struct options *s) {
    size_t i=0;
    while(i<n) {
        unsigned code=p[i++];
        if(code==0) continue;
        if(code==255) { if(main)s->main_end=i-1; return 1; }
        if(i==n) return 0;
        unsigned len=p[i++];
        if(len>n-i) return 0;
        if(code==6) { s->dns_seen++; s->dns_bytes+=len; }
        if(code==53) {
            if(!main||s->type_seen++||len!=1) return 0;
            s->type=p[i];
        }
        if(code==52) {
            if(!main||s->overload_seen++||len!=1||p[i]<1||p[i]>3) return 0;
            s->overload=p[i];
        }
        i+=len;
    }
    return 0; /* Every examined option field must have END. */
}
static void rewrite_options(uint8_t *p,size_t n,const uint8_t dns[4],unsigned *offset) {
    size_t i=0;
    while(i<n) {
        unsigned code=p[i++];
        if(code==0) continue;
        if(code==255) return;
        unsigned len=p[i++];
        if(code==6) for(unsigned j=0;j<len;j++) p[i+j]=dns[((*offset)++)&3u];
        i+=len;
    }
}
int dhcp_dns_rewrite(uint8_t *b,size_t n,const uint8_t server[4],const uint8_t dns[4]) {
    if(!b||!server||!dns) return DHCP_DNS_BAD_CONFIG;
    if(!dns[0]||dns[0]==127||dns[0]>=224||
       (dns[0]==server[0]&&dns[1]==server[1]&&dns[2]==server[2]))
        return DHCP_DNS_BAD_CONFIG; /* Existing native route bypasses server /24. */
    if(n<34||get16(b+12)!=0x0800) return DHCP_DNS_UNCHANGED;
    uint8_t *ip=b+14;
    if((ip[0]>>4)!=4||ip[9]!=17||!equal4(ip+12,server)) return DHCP_DNS_UNCHANGED;
    if(n>FRAME_LIMIT) return DHCP_DNS_REJECT;
    unsigned h=(ip[0]&15u)*4u,total=get16(ip+2);
    if(h<20||h>n-14||total<h+8||total>n-14) return DHCP_DNS_REJECT;
    if(get16(ip+6)&0xbfffu) return DHCP_DNS_REJECT; /* RF/MF/offset; DF is allowed. */
    uint8_t *udp=ip+h;
    if(get16(udp)!=67||get16(udp+2)!=68) return DHCP_DNS_UNCHANGED;
    unsigned len=get16(udp+4);
    if(len!=total-h||len<8+BOOTP_FIXED+1) return DHCP_DNS_REJECT;
    if(finish(addsum(ip,h,0))) return DHCP_DNS_REJECT;
    unsigned pseudo=addsum(ip+12,8,17u+len);
    if(get16(udp+6)&&finish(addsum(udp,len,pseudo))) return DHCP_DNS_REJECT;
    uint8_t *boot=udp+8;
    if(boot[0]!=2||boot[1]!=1||boot[2]!=6||
       boot[236]!=99||boot[237]!=130||boot[238]!=83||boot[239]!=99)
        return DHCP_DNS_REJECT;
    size_t option_len=len-8-BOOTP_FIXED;
    struct options s={0};
    if(!scan(boot+240,option_len,1,&s)||
       ((s.overload&1)&&!scan(boot+108,128,0,&s))||
       ((s.overload&2)&&!scan(boot+44,64,0,&s))) return DHCP_DNS_REJECT;
    if(s.type_seen!=1) return DHCP_DNS_REJECT;
    if(s.type!=2&&s.type!=5) return DHCP_DNS_UNCHANGED; /* OFFER and ACK only. */
    if(s.dns_seen) {
        if(!s.dns_bytes||(s.dns_bytes&3u)) return DHCP_DNS_REJECT;
    } else {
        /* Append without growing the packet, only into explicit zero padding. */
        if(option_len-s.main_end<7) return DHCP_DNS_NO_SPACE;
        for(size_t i=s.main_end+1;i<=s.main_end+6;i++)
            if(boot[240+i]!=0) return DHCP_DNS_NO_SPACE;
    }
    /* All rejection paths precede this point: byte-for-byte atomic on failure. */
    if(s.dns_seen) {
        unsigned offset=0;
        rewrite_options(boot+240,option_len,dns,&offset);
        if(s.overload&1) rewrite_options(boot+108,128,dns,&offset);
        if(s.overload&2) rewrite_options(boot+44,64,dns,&offset);
    } else {
        uint8_t *p=boot+240+s.main_end;p[0]=6;p[1]=4;
        for(unsigned i=0;i<4;i++)p[2+i]=dns[i];p[6]=255;
    }
    udp[6]=udp[7]=0;
    unsigned checksum=finish(addsum(udp,len,pseudo));
    put16(udp+6,checksum?checksum:65535u);
    return DHCP_DNS_REWRITTEN;
}
