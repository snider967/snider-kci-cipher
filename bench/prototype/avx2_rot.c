/* Prototype AVX2 8-way benchmark from Session 02 (2026-11-27): fixed vs key-selected rotations.
   Throwaway measurement code for vault/Refactor/KCI-Primitive-Design.md section 11; not KCI-20 itself
   (rotation table and round constants here are placeholders). Build: see vault/Refactor/Performance-Notes.md */
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
/* 8 blocks in parallel, one register per state word (the standard fast layout) */
static inline __m256i rot_imm16(__m256i x){ const __m256i m=_mm256_setr_epi8(2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13,2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13); return _mm256_shuffle_epi8(x,m); }
static inline __m256i rot_imm8(__m256i x){ const __m256i m=_mm256_setr_epi8(3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14,3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14); return _mm256_shuffle_epi8(x,m); }
#define ROTI(x,n) _mm256_or_si256(_mm256_slli_epi32(x,n),_mm256_srli_epi32(x,32-(n)))
static inline __m256i rotv(__m256i x, __m256i l, __m256i r){ return _mm256_or_si256(_mm256_sllv_epi32(x,l),_mm256_srlv_epi32(x,r)); }
static inline __m256i rotb(__m256i x, __m256i m){ return _mm256_shuffle_epi8(x,m); }
#define ADD _mm256_add_epi32
#define XOR _mm256_xor_si256
#define QF(a,b,c,d) a=ADD(a,b);d=rot_imm16(XOR(d,a));c=ADD(c,d);b=ROTI(XOR(b,c),12);a=ADD(a,b);d=rot_imm8(XOR(d,a));c=ADD(c,d);b=ROTI(XOR(b,c),7);
#define QV(a,b,c,d,L,R) a=ADD(a,b);d=rotv(XOR(d,a),L[0],R[0]);c=ADD(c,d);b=rotv(XOR(b,c),L[1],R[1]);a=ADD(a,b);d=rotv(XOR(d,a),L[2],R[2]);c=ADD(c,d);b=rotv(XOR(b,c),L[3],R[3]);
#define BODY_IN __m256i x[16]; for(int i=0;i<16;i++) x[i]=in[i];
#define BODY_OUT for(int i=0;i<16;i++) out[i]=XOR(out[i],ADD(x[i],in[i]));
__attribute__((noinline)) static void fixed8(__m256i out[16], const __m256i in[16]){ BODY_IN
  for(int r=0;r<20;r+=2){ QF(x[0],x[4],x[8],x[12])QF(x[1],x[5],x[9],x[13])QF(x[2],x[6],x[10],x[14])QF(x[3],x[7],x[11],x[15])
    QF(x[0],x[5],x[10],x[15])QF(x[1],x[6],x[11],x[12])QF(x[2],x[7],x[8],x[13])QF(x[3],x[4],x[9],x[14]) } BODY_OUT }
typedef struct { __m256i L[20][4], R[20][4], B[20][2]; __m256i rc[20]; } sched;
__attribute__((noinline)) static void kci8(__m256i out[16], const __m256i in[16], const sched *S){ BODY_IN
  for(int r=0;r<20;r+=2){ const __m256i *L=S->L[r],*R=S->R[r],*L2=S->L[r+1],*R2=S->R[r+1],*B=S->B[r],*B2=S->B[r+1];
    x[0]=XOR(x[0],S->rc[r]); QV(x[0],x[4],x[8],x[12],L,R)QV(x[1],x[5],x[9],x[13],L,R)QV(x[2],x[6],x[10],x[14],L,R)QV(x[3],x[7],x[11],x[15],L,R)
    x[1]=XOR(x[1],S->rc[r+1]); QV(x[0],x[5],x[10],x[15],L2,R2)QV(x[1],x[6],x[11],x[12],L2,R2)QV(x[2],x[7],x[8],x[13],L2,R2)QV(x[3],x[4],x[9],x[14],L2,R2) } BODY_OUT }
#define QB(a,b,c,d,L,R,B) a=ADD(a,b);d=rotb(XOR(d,a),B[0]);c=ADD(c,d);b=rotv(XOR(b,c),L[1],R[1]);a=ADD(a,b);d=rotb(XOR(d,a),B[1]);c=ADD(c,d);b=rotv(XOR(b,c),L[3],R[3]);
__attribute__((noinline)) static void kciB(__m256i out[16], const __m256i in[16], const sched *S){ BODY_IN
  for(int r=0;r<20;r+=2){ const __m256i *L=S->L[r],*R=S->R[r],*L2=S->L[r+1],*R2=S->R[r+1],*B=S->B[r],*B2=S->B[r+1];
    x[0]=XOR(x[0],S->rc[r]); QB(x[0],x[4],x[8],x[12],L,R,B)QB(x[1],x[5],x[9],x[13],L,R,B)QB(x[2],x[6],x[10],x[14],L,R,B)QB(x[3],x[7],x[11],x[15],L,R,B)
    x[1]=XOR(x[1],S->rc[r+1]); QB(x[0],x[5],x[10],x[15],L2,R2,B2)QB(x[1],x[6],x[11],x[12],L2,R2,B2)QB(x[2],x[7],x[8],x[13],L2,R2,B2)QB(x[3],x[4],x[9],x[14],L2,R2,B2) } BODY_OUT }
static __m256i bytemask(unsigned k){ uint8_t m[32]; for(int i=0;i<32;i++){ int w=i&~3, j=i&3; m[i]=(uint8_t)(w+((j-(int)k/8)&3)); } return _mm256_loadu_si256((const __m256i*)m); }
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
int main(void){
  static const uint8_t RT[8][4]={{19,16,26,24},{24,5,11,13},{7,5,11,10},{9,17,25,24},{11,10,15,12},{20,25,11,18},{17,23,15,22},{23,28,18,25}};
  static sched S; volatile uint32_t kb=0x5a3c96e1u;
  for(int r=0;r<20;r++){ unsigned s=(kb>>(r%10*3))&7; for(int i=0;i<4;i++){ unsigned v=RT[s][i];
      S.L[r][i]=_mm256_set1_epi32(v); S.R[r][i]=_mm256_set1_epi32(32-v);} S.B[r][0]=bytemask(16);S.B[r][1]=bytemask(8+8*(r&1)); S.rc[r]=_mm256_set1_epi32(0x9E3779B9u*(r+1)); }
  static __m256i buf[1<<15][16]; __m256i in[16]; for(int i=0;i<16;i++) in[i]=_mm256_set1_epi32(0x01234567*i);
  const int N=1<<15, REPS=40; double ba=1e9,bb=1e9,bc=1e9; /* 32768 * 512 B = 16 MiB per rep; use 2 MiB slices */
  for(int k=0;k<3;k++){
    double t=now(); for(int r=0;r<REPS;r++) for(int i=0;i<4096;i++){ in[12]=ADD(in[12],_mm256_set1_epi32(8)); fixed8(buf[i],in);} double a=now()-t;
    t=now(); for(int r=0;r<REPS;r++) for(int i=0;i<4096;i++){ in[12]=ADD(in[12],_mm256_set1_epi32(8)); kci8(buf[i],in,&S);} double b=now()-t;
    double c0=now(); for(int r=0;r<REPS;r++) for(int i=0;i<4096;i++){ in[12]=ADD(in[12],_mm256_set1_epi32(8)); kciB(buf[i],in,&S);} double c=now()-c0;
    if(a<ba)ba=a; if(b<bb)bb=b; if(c<bc)bc=c; }
  double mb=REPS*4096*512/1e6; (void)N;
  printf("AVX2 8-way: fixed %5.0f MB/s | A all-variable(vpsllvd) %5.0f MB/s (%.2fx) | B byte-shuffle+variable %5.0f MB/s (%.2fx) chk %d\n", mb/ba, mb/bb, bb/ba, mb/bc, bc/ba, _mm256_extract_epi32(buf[7][3],2));
}
