#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <CommonCrypto/CommonCrypto.h>
static long long modmult(long long a,long long b,long long c,long long m,long long s){long long q=s/a;s=b*(s-a*q)-c*q;if(s<0)s+=m;return s;}
static void gen_iv(int page_no,uint8_t*out){long long z=page_no+1;uint8_t ik[16];for(int i=0;i<4;i++){z=modmult(52774,40692,3791,2147483399,z);uint32_t v=(uint32_t)(z&0xFFFFFFFF);ik[i*4]=v&0xff;ik[i*4+1]=(v>>8)&0xff;ik[i*4+2]=(v>>16)&0xff;ik[i*4+3]=(v>>24)&0xff;}CC_MD5(ik,16,out);}
int main(void){
  uint8_t iv[16];gen_iv(1,iv);
  printf("iv1 = ");for(int i=0;i<16;i++)printf("%02x",iv[i]);printf("\n");
  uint8_t key[16]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  uint8_t mat[24];memcpy(mat,key,16);mat[16]=1;mat[17]=0;mat[18]=0;mat[19]=0;memcpy(mat+20,"sAlT",4);
  uint8_t pk[16];CC_MD5(mat,24,pk);
  printf("pk1 = ");for(int i=0;i<16;i++)printf("%02x",pk[i]);printf("\n");
  const uint8_t H[16]="SQLite format 3";
  uint8_t in[16],out[16];for(int i=0;i<16;i++)in[i]=H[i]^iv[i];
  size_t mv=0;
  CCCryptorStatus st=CCCrypt(kCCEncrypt,kCCAlgorithmAES,kCCOptionECBMode,pk,16,NULL,in,16,out,16,&mv);
  printf("status=%d moved=%zu kcv=",st,mv);
  for(int i=0;i<8;i++)printf("%02x",out[i]);
  printf("\n");
  return 0;
}
