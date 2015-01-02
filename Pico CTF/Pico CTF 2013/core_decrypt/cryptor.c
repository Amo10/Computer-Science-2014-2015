#include <stdio.h>
#include <stdlib.h>

void swap(unsigned char* sbox, int i, int j) {
  unsigned char tmp;
  tmp = sbox[i];
  sbox[i] = sbox[j];
  sbox[j] = tmp;
}

void init_rc4(unsigned char* sbox, char* key, int keylen) {
  int i;
  for (i = 0; i < 256; i++) {
    sbox[i] = i;
  }
  unsigned char j,tmp;
  for (i = 0; i < 256; i++) {
    j = j + sbox[i] + key[i % keylen];
    swap(sbox,i,j);
  }
}

unsigned char next_prg(unsigned char* sbox, int *i, int *j) {
  i[0] = (i[0] + 1)&0xff;
  j[0] = (j[0] + sbox[i[0]])&0xff;
  swap(sbox,i[0],j[0]);
  return sbox[(sbox[i[0]] + sbox[j[0]])&0xff];
}

void crypt(FILE *inf, FILE *keyf, FILE *outf) {
  int uhoh;
  unsigned char sbox[256];
  int i,j;
  i = j = 0;
  char key[16];

  fread(key,1,16,keyf);
  init_rc4(sbox,key,16);

  unsigned char tmp;
  while (fread(&tmp,1,1,inf) > 0) {
    tmp ^= next_prg(sbox,&i,&j);
    fwrite(&tmp,1,1,outf);
  }
}

int usage(char* this) {
  printf("Usage: %s [input file] [outfile] [key file]\n",this);
  return -1;
}

int main(int argc, char** argv) {
  if (argc != 4) {
    return usage(argv[0]);
  }
  FILE *inf = fopen(argv[1],"r");
  FILE *outf = fopen(argv[2],"w");
  FILE *keyf = fopen(argv[3],"r");

  if (!(inf && outf && keyf)) {
    printf("Sorry, could not open all files for reading/writing\n");
    return -1;
  }
  crypt(inf,keyf,outf);
  fclose(inf);
  fclose(outf);
  fclose(keyf);
  return 0;
}
