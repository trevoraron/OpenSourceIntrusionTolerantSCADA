#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include "TC.h"
//void TC_write_shares(TC_DEALER* dealer, char* directory);
//BIGNUM* TC_read_share(char* filename);
int main(int argc, char** argv)
{

  /*
  RSA* rsa = RSA_new();
  RSA* rsa2 = RSA_new();
  FILE* out = fopen("test", "w");
  BIGNUM* num = BN_new();
  BN_set_word(num, 5);
  RSA* rsa3 = RSA_new();
  rsa3->e = num;
  rsa3->n = num;

  rsa = RSA_generate_key(1024, 3, NULL, NULL);
  PEM_write_RSAPublicKey(out, rsa);
  PEM_write_RSAPublicKey(out, rsa3);
  fclose(out);
  out = fopen("test", "r");
  PEM_read_RSAPublicKey(out, &rsa2, NULL, NULL);
  PEM_read_RSAPublicKey(out, &rsa2, NULL, NULL); 
  
  BN_print_fp(stdout, rsa2->e);
  printf("\n");
  BN_print_fp(stdout, rsa2->n);
  printf("\n");
  */

  TC_DEALER* test = (TC_DEALER*)malloc(sizeof(TC_DEALER));
  printf("dealer allocated\n");
  BIGNUM* n = BN_new();
  int l = 5;
  int k = 3;
  int i=0;
  BIGNUM** si = (BIGNUM**)malloc(sizeof(BIGNUM*)*l);
  BIGNUM* e = BN_new();
  BN_set_word(n, 10);
  BN_set_word(e, 30);

  for (i=0; i<l; i++)
    {
      si[i] = BN_new();
      BN_set_word(si[i], i);
    }

  test->e = e;
  test->n = n;
  test->si= si;
  test->l = l;
  test->k = k;
  //TC_write_shares(test, "shares");
  BIGNUM* share0 = TC_read_share("shares/share0.pem");
  BN_print_fp(stdout, share0);
  BIGNUM* share1 = TC_read_share("shares/share1.pem");
  BN_print_fp(stdout, share1);

  
  
  free(test);

  for (i=0; i<l; i++)
    BN_free(si[i]);

  free(si);
  BN_free(e);
  BN_free(n);
  BN_free(share0);
  
}

#if 0
BIGNUM* TC_read_share(char* file)
{
  RSA* share = RSA_new();
  FILE* read = fopen(file, "r");
  BIGNUM* ret;

  if (!read)
    fprintf(stderr, "TC_read_share: Error opening file");

  PEM_read_RSAPublicKey(read, &share, NULL, NULL);
  ret = BN_dup(share->e);
  RSA_free(share);
  fclose(read);
  return ret;

}


RSA* TC_read_public_key(char* file)
{
  RSA* ret = RSA_new();
  FILE* read = fopen(file, "r");

  if (!read)
    fprintf(stderr, "TC_read_public_key: Error opening file");

  PEM_read_RSAPublicKey(read, &ret, NULL, NULL);

  fclose(read);

  return ret;
}

void TC_write_shares(TC_DEALER* dealer, char* directory)
{
  FILE* out;
  RSA* current = RSA_new();
  char buf[512];
  int i;

  mkdir(directory, 0777);

  for (i=0; i<dealer->l; i++)
    {
      sprintf(buf, "%s/share%d.pem", directory, i);
      printf("Writing to %s\n", buf);
      out = fopen(buf, "w");
      
      current->e = dealer->si[i];
      current->n = dealer->n;

      PEM_write_RSAPublicKey(out,current); 
      fclose(out);
    }

  sprintf(buf, "%s/pubkey.pem", directory);
  fopen(buf, "w");
  current->e = dealer->e;
  current->n = dealer->n;

  PEM_write_RSAPublicKey(out, current);
  fclose(out);
}
#endif

