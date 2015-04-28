/**
 * file: marshal.c - Implements all marshal-demarshla functions
 *
 * OpenTC.
 *
 * The contents of this file are subject to the OpenTC Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 *
 * The Creators of OpenTC are:
 *         Abhilasha Bhargav, <bhargav@cs.purdue.edu>
 *         Rahim Sewani, <sewani@cs.purdue.edu>
 *         Sarvjeet Singh, <sarvjeet_s@yahoo.com, sarvjeet@purdue.edu>
 *         Cristina Nita-Rotaru, <crisn@cs.purdue.edu>
 *
 * Contributors:
 *         Chi-Bun Chan, <cbchan@cs.purdue.edu>
 *
 * Copyright (c) 2004 Purdue University.
 * All rights reserved.
 *
 */


#include "TC.h"

static int marshal_int(int what, unsigned char *buf) {
  unsigned char *pt=buf;
  
  while (what>0) {
    *pt = what % 256;
    what = what / 256;
    pt++;
  }
  
  return (pt-buf);
}

static int demarshal_int(int len, unsigned char *buf) {
  int i;
  int ans=0;

  for(i=len-1;i>=0;i--)
    ans=ans*256 + buf[i];

  return ans;
}
  

static int size_int(int i) {
  int count=0;

  while (i > 0) {
    count++;
    i /= 256;
  }
  return count;
}

static int write_len(BIGNUM *a, unsigned char *buf) {
  int size = BN_num_bytes(a);
  
  buf[0] = size %256;
  size= size/256;

  buf[1]=size%256;
  
  if ((size/256)!=0) return 0;
  
  return 1;
}
  
/********************/

int TC_PK_size(TC_PK *a) {
  return(4 + BN_num_bytes(a->e) + BN_num_bytes(a->n));
}

int TC_PK_marshal(TC_PK *a, unsigned char *buf) {
  unsigned char *pt=buf;
  
  if (!write_len(a->e,pt)) return -1;
  pt=pt+2;
  BN_bn2bin(a->e,pt);
  pt=pt+BN_num_bytes(a->e);

  if (!write_len(a->n,pt)) return -1;
  pt=pt+2;
  BN_bn2bin(a->n,pt);
  pt=pt+BN_num_bytes(a->n);
  
  return (pt-buf);
}

TC_PK *TC_PK_demarshal(unsigned char *buf) {
  unsigned char *pk=buf;
  TC_PK *ans;
  int size;

  if ((ans=(TC_PK *)OPENSSL_malloc(sizeof(TC_PK))) == NULL) {
    return NULL;
  }

  ans->e=ans->n=NULL;
  
  size = demarshal_int(2,pk);
  ans->e = BN_bin2bn(pk+2, size, NULL);
  pk += 2 + size;

  size = demarshal_int(2,pk);
  ans->n = BN_bin2bn(pk+2, size, NULL);
  pk += 2 + size;
  
  if ((ans->e==NULL) || (ans->n == NULL)) {
    if (ans->e!=NULL) BN_clear_free(ans->e);
    if (ans->n!=NULL) BN_clear_free(ans->n);
    OPENSSL_free(ans);
    return (NULL);
  }
  return(ans);
}


/**************************/

/* First bytes tells if this struct has secret key(=1) or not(=0) (in case of combiner struct) */

int TC_IND_size(TC_IND *a) {
  int size_vki=0,i;

  for(i=0;i<(a->l);i++)
    size_vki += BN_num_bytes(a->vki[i]);

  if (a->si==NULL)
    return (1 + 1*2 + 2*4 + 2*(a->l)+ 1 + size_int(a->l)+ size_int(a->k)+ BN_num_bytes( a->v) 
	    + BN_num_bytes(a->u) + BN_num_bytes(a->e) + BN_num_bytes(a->n)+ size_vki);
  else
    return (1 + 1*3 + 2*5 + 2*(a->l)+ 1 + size_int(a->l)+ size_int(a->k)+ size_int(a->mynum) + 
	    BN_num_bytes(a->v) + BN_num_bytes(a->u) + BN_num_bytes(a->e)+ BN_num_bytes(a->n)+ 
	    + BN_num_bytes(a->si) + size_vki);
}

int TC_IND_marshal(TC_IND *a, unsigned char *buf) {
  unsigned char *pt=buf;
  int i;

  if (a->si == NULL)
    *pt = 0;
  else
    *pt = 1;
  
  pt++;

  *pt=marshal_int(a->l, pt+1);
  pt= pt+1+(*pt);

  *pt=marshal_int(a->k, pt+1);
  pt= pt+1+(*pt);

  if (a->si != NULL) {
    *pt=marshal_int(a->mynum, pt+1);
    pt= pt+1+(*pt);
  }

  if (!write_len(a->v,pt)) return -1;
  pt=pt+2;
  BN_bn2bin(a->v,pt);
  pt=pt+BN_num_bytes(a->v);

  if (!write_len(a->u,pt)) return -1;
  pt=pt+2;
  BN_bn2bin(a->u,pt);
  pt=pt+BN_num_bytes(a->u);

  if (!write_len(a->e,pt)) return -1;
  pt=pt+2;
  BN_bn2bin(a->e,pt);
  pt=pt+BN_num_bytes(a->e);
 
  if (!write_len(a->n,pt)) return -1;
  pt=pt+2;
  BN_bn2bin(a->n,pt);
  pt=pt+BN_num_bytes(a->n);

  for(i=0; i< (a->l); i++) {
    if (!write_len(a->vki[i],pt)) return -1;
    pt=pt+2;
    BN_bn2bin(a->vki[i],pt);
    pt=pt+BN_num_bytes(a->vki[i]);
  }

  if (a->si != NULL) { 
    if (!write_len(a->si,pt)) return -1;
    pt=pt+2;
    BN_bn2bin(a->si,pt);
    pt=pt+BN_num_bytes(a->si);
  }
  
  *pt = 0; /* UPDATE THIS **********************/
  pt++;
  
  return (pt-buf);
}

TC_IND *TC_IND_demarshal(unsigned char *buf) {
  unsigned char *pk=buf;
  TC_IND *ans;
  int size,i;
  int flag=0;
  int private=0;

  if ((ans=OPENSSL_malloc(sizeof(TC_IND))) == NULL) {
    return NULL;

  }

  ans->v=ans->u=ans->e=ans->n=ans->si=NULL;
  ans->Hp=NULL;
  ans->vki=NULL;
  ans->mynum=-1;

  private=demarshal_int(1,pk);
  pk++;
  
  size=demarshal_int(1,pk);
  ans->l=demarshal_int(size,pk+1);
  pk += 1+size;

  /* Got l, now we can allocate vki */

  if ((ans->vki = (BIGNUM **)OPENSSL_malloc((ans->l)*sizeof(BIGNUM *)))==NULL) {
    OPENSSL_free(ans);
    return NULL;
  }

  for(i=0;i<(ans->l);i++)
    flag = flag || ((ans->vki[i]=BN_new())==NULL);
  
  if (flag) {
    for (i=0;i<(ans->l);i++)
      if (ans->vki[i] != NULL) BN_clear_free(ans->vki[i]);
    OPENSSL_free(ans->vki);
    OPENSSL_free(ans);
    return NULL;
  }

  size=demarshal_int(1,pk);
  ans->k=demarshal_int(size,pk+1);
  pk += 1+size;

  if (private) {
    size=demarshal_int(1,pk);
    ans->mynum=demarshal_int(size,pk+1);
    pk += 1+size;
  }

  size = demarshal_int(2,pk);
  ans->v = BN_bin2bn(pk+2, size, NULL);
  pk += 2 + size;

  size = demarshal_int(2,pk);
  ans->u = BN_bin2bn(pk+2, size, NULL);
  pk += 2 + size;
  
  size = demarshal_int(2,pk);
  ans->e = BN_bin2bn(pk+2, size, NULL);
  pk += 2 + size;

  size = demarshal_int(2,pk);
  ans->n = BN_bin2bn(pk+2, size, NULL);
  pk += 2 + size;

  for (i=0;i<(ans->l);i++) {
    size = demarshal_int(2,pk);
    ans->vki[i] = BN_bin2bn(pk+2, size, NULL);
    pk += 2 + size;
  }

  if (private) {
    size = demarshal_int(2,pk);
    ans->si = BN_bin2bn(pk+2, size, NULL);
    pk += 2 + size;
  }

  flag=demarshal_int(1,pk);
  pk++;

  switch (flag){
  case 0: ans->Hp =EVP_md5(); break;
  }

  /**************** HASH *****************/

  
  if ( (ans->v == NULL) || (ans->u == NULL) || (ans->e==NULL) || (ans->n == NULL) || (private && (ans->si ==NULL))) {
    if (ans->v!=NULL) BN_clear_free(ans->v);
    if (ans->u!=NULL) BN_clear_free(ans->u);
    if (ans->e!=NULL) BN_clear_free(ans->e);
    if (ans->n!=NULL) BN_clear_free(ans->n);

    for (i=0;i<(ans->l);i++)
      if (ans->vki[i] != NULL) BN_clear_free(ans->vki[i]);
    OPENSSL_free(ans->vki);
    
    if (ans->si!=NULL) BN_clear_free(ans->si);
    OPENSSL_free(ans);
    return (NULL);
  }
  
  return(ans);
}

int TC_IND_SIG_size(TC_IND_SIG *a) {
  return( 6 + BN_num_bytes( a->sig) + BN_num_bytes(a->proof_z) + BN_num_bytes(a->proof_c));
}

int TC_IND_SIG_marshal(TC_IND_SIG *a, unsigned char *buf) {
  unsigned char *pt=buf;
  
  if (!write_len(a->sig,pt)) return -1;
  pt=pt+2;
  BN_bn2bin(a->sig,pt);
  pt=pt+BN_num_bytes(a->sig);

  if (!write_len(a->proof_z,pt)) return -1;
  pt=pt+2;
  BN_bn2bin(a->proof_z,pt);
  pt=pt+BN_num_bytes(a->proof_z);

  if (!write_len(a->proof_c,pt)) return -1;
  pt=pt+2;
  BN_bn2bin(a->proof_c,pt);
  pt=pt+BN_num_bytes(a->proof_c);
  
  return (pt-buf);
}

TC_IND_SIG *TC_IND_SIG_demarshal(unsigned char *buf) {
  unsigned char *pk=buf;
  TC_IND_SIG *ans;
  int size;

  if ((ans=OPENSSL_malloc(sizeof(TC_IND_SIG))) == NULL) {
    return NULL;
  }

  ans->sig=ans->proof_z=ans->proof_c=NULL;
  
  size = demarshal_int(2,pk);
  ans->sig = BN_bin2bn(pk+2, size, NULL);
  pk += 2 + size;
  
  size = demarshal_int(2,pk);
  ans->proof_z = BN_bin2bn(pk+2, size, NULL);
  pk += 2 + size;

  size = demarshal_int(2,pk);
  ans->proof_c = BN_bin2bn(pk+2, size, NULL);
  pk += 2 + size;
  
  if ( (ans->sig == NULL) || (ans->proof_z==NULL) || (ans->proof_c == NULL)) {
    if (ans->sig!=NULL) BN_clear_free(ans->sig);
    if (ans->proof_z!=NULL) BN_clear_free(ans->proof_z);
    if (ans->proof_c!=NULL) BN_clear_free(ans->proof_c);
    OPENSSL_free(ans);
    return (NULL);
  }
  return(ans);
}


/********************************/

int TC_SIG_size(TC_SIG sig) {
  return (2 + BN_num_bytes(sig));
}

int TC_SIG_marshal(TC_SIG sig, unsigned char *buf) {
  unsigned char *pt=buf;
  
  if (!write_len(sig,pt)) return -1;
  pt=pt+2;
  BN_bn2bin(sig,pt);
  pt=pt+BN_num_bytes(sig);
  
  return (pt-buf);
}

TC_SIG TC_SIG_demarshal(unsigned char *buf) {
  unsigned char *pk=buf;
  TC_SIG ans=NULL;
  int size;


  size = demarshal_int(2,pk);
  ans = BN_bin2bn(pk+2, size, NULL);
  pk += 2 + size;

  return ans;
}
