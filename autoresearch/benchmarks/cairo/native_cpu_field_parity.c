#include "prelude.h"
#include <stdio.h>
static uint64_t state=0x124f5839abc8;
static uint32_t rnd(void){state^=state<<13;state^=state>>7;state^=state<<17;return state%P;}
int main(void){
 for(unsigned t=0;t<100000;t++){
  V a,b;for(int k=0;k<4;k++){a[k]=t<5?(uint32_t[]){0,1,2,P-2,P-1}[t]:rnd();b[k]=rnd();}
  V add=va(a,b),sub=vb(a,b),mul=vm(a,b),neg=vn(a);
  for(int k=0;k<4;k++)if(add[k]!=(uint64_t)(a[k]+(uint64_t)b[k])%P || sub[k]!=((uint64_t)a[k]+P-b[k])%P || mul[k]!=((uint64_t)a[k]*b[k])%P || neg[k]!=((uint64_t)P-a[k])%P)return 1;
 }
 puts("100000 packed M31 trials: 1.6 million native/scalar comparisons passed");return 0;
}
