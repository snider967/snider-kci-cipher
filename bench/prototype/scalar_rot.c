/* Prototype scalar benchmark from Session 02 (2026-11-27): fixed vs key-selected rotations.
   Throwaway measurement code for vault/Refactor/KCI-Primitive-Design.md section 11; not KCI-20 itself
   (rotation table and round constants here are placeholders). Build: see vault/Refactor/Performance-Notes.md */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
static inline uint32_t rotl(uint32_t x, unsigned n){ return (x<<(n&31))|(x>>((32-n)&31)); }
/* step-interleaved round: all 4 quarter-rounds do step k together, so each rotation count is used 4x in a row */
#define STEP(A,B,D,R) A##0+=B##0;D##0^=A##0;D##0=rotl(D##0,R); A##1+=B##1;D##1^=A##1;D##1=rotl(D##1,R); \
                      A##2+=B##2;D##2^=A##2;D##2=rotl(D##2,R); A##3+=B##3;D##3^=A##3;D##3=rotl(D##3,R);
#define ROUND(R0,R1,R2,R3) STEP(a,b,d,R0) STEP(c,d,b,R1) STEP(a,b,d,R2) STEP(c,d,b,R3)
#define DIAG_IN  { uint32_t t; t=b0;b0=b1;b1=b2;b2=b3;b3=t; t=c0;c0=c2;c2=t;t=c1;c1=c3;c3=t; t=d3;d3=d2;d2=d1;d1=d0;d0=t; }
#define DIAG_OUT { uint32_t t; t=b3;b3=b2;b2=b1;b1=b0;b0=t; t=c0;c0=c2;c2=t;t=c1;c1=c3;c3=t; t=d0;d0=d1;d1=d2;d2=d3;d3=t; }
#define LOAD uint32_t a0=in[0],a1=in[1],a2=in[2],a3=in[3],b0=in[4],b1=in[5],b2=in[6],b3=in[7],c0=in[8],c1=in[9],c2=in[10],c3=in[11],d0=in[12],d1=in[13],d2=in[14],d3=in[15];
#define STORE { uint32_t t[16]={a0,a1,a2,a3,b0,b1,b2,b3,c0,c1,c2,c3,d0,d1,d2,d3}; for(int i=0;i<16;i++) o[i]^=t[i]+in[i]; }
__attribute__((noinline)) static void fixed_block(uint32_t o[16], const uint32_t in[16]){ LOAD
  for(int r=0;r<20;r+=2){ ROUND(16,12,8,7) DIAG_IN ROUND(16,12,8,7) DIAG_OUT } STORE }
typedef struct { uint8_t rot[20][4]; uint32_t rc[20]; } sched;
__attribute__((noinline)) static void kci_block(uint32_t o[16], const uint32_t in[16], const sched *S){ LOAD
  for(int r=0;r<20;r+=2){ const uint8_t *p=S->rot[r],*q=S->rot[r+1];
    a0^=S->rc[r]; ROUND(p[0],p[1],p[2],p[3]) DIAG_IN a1^=S->rc[r+1]; ROUND(q[0],q[1],q[2],q[3]) DIAG_OUT } STORE }
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
int main(void){
  static const uint8_t R[8][4]={{19,16,26,24},{24,5,11,13},{7,5,11,10},{9,17,25,24},{11,10,15,12},{20,25,11,18},{17,23,15,22},{23,28,18,25}};
  sched S; volatile uint32_t keybits=0x5a3c96e1u;
  for(int r=0;r<20;r++){ unsigned s=(keybits>>(r%10*3))&7;
    for(int i=0;i<4;i++){uint8_t v=0; for(unsigned j=0;j<8;j++){uint8_t m=(uint8_t)-(uint8_t)(j==s); v|=R[j][i]&m;} S.rot[r][i]=v;}
    S.rc[r]=0x9E3779B9u*(r+1); }
  static uint32_t buf[1<<18]; /* 1 MiB */ uint32_t in[16]; for(int i=0;i<16;i++) in[i]=0x01234567u*i;
  const int REPS=200; double best_a=1e9,best_b=1e9;
  for(int k=0;k<3;k++){
    double t=now(); for(int r=0;r<REPS;r++) for(int i=0;i<(1<<18);i+=16){in[12]++;fixed_block(buf+i,in);} double a=now()-t;
    t=now(); for(int r=0;r<REPS;r++) for(int i=0;i<(1<<18);i+=16){in[12]++;kci_block(buf+i,in,&S);} double b=now()-t;
    if(a<best_a)best_a=a; if(b<best_b)best_b=b; }
  double mb=REPS*1.048576;
  printf("fixed rotations: %6.0f MB/s | key-selected rotations: %6.0f MB/s | slowdown %.2fx  (chk %u)\n", mb/best_a, mb/best_b, best_b/best_a, buf[5]);
  return 0;
}
