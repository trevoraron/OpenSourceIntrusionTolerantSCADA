/**
 * file: combineSig.c - Implements TC_Combine_Sigs()
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

static int lambda(BIGNUM *answer, int i, int j, int *Set_S, BIGNUM *delta, BIGNUM *temp, BIGNUM *temp2, BIGNUM *temp3,BN_CTX *ctx) {
  int count;
  if (BN_copy(answer,delta)==NULL) return 0;

  count=0;
  while (Set_S[count]!=-1) {
    if (Set_S[count]!=j) {
      if (!BN_set_word(temp2, i)) return 0;
      if (!BN_set_word(temp3,Set_S[count])) return 0;
      if (!BN_sub(temp, temp2, temp3)) return 0;
      if (!BN_mul(answer, answer, temp, ctx)) return 0;
    }
    count++;
  }

  count=0;
  while (Set_S[count]!=-1) {
    if (Set_S[count]!=j) {
      if (!BN_set_word(temp2, j)) return 0;
      if (!BN_set_word(temp3,Set_S[count])) return 0;

      if (!BN_sub(temp, temp2, temp3)) return 0;

      if (!BN_div(temp2, NULL, answer, temp, ctx)) return 0;
      if (!BN_zero(answer)) return 0;
      if (!BN_add(answer, answer, temp2)) return 0;
    }
    count++;
  }

  return 1;
}

static int modified_BN_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m, BN_CTX *ctx, BIGNUM *temp) {
  BN_zero(r);

  if (BN_cmp(b,r) < 0) { // r < 0
    if (!BN_mod_inverse(temp, a, m,ctx)) return 0;
    return (BN_mod_exp(r,temp,b,m,ctx));
  } else
    return (BN_mod_exp(r,a,b,m,ctx));
}

static int ret_error(TC_SIG *sig, int *Set_S, BN_CTX *ctx, int errno) {
  if( *sig !=  NULL)
    BN_clear_free(*sig);
  if (Set_S != NULL)
    OPENSSL_free(Set_S);
  
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  
  return errno;
}

int TC_Combine_Sigs(TC_IND_SIG **ind_sigs, TC_IND *key,  BIGNUM *hM, TC_SIG *sig, int checkproof) {
  BIGNUM *w=NULL, *delta=NULL;
  BN_CTX *ctx=NULL;
  BIGNUM *temp=NULL,*temp2=NULL,*temp3=NULL, *temp4=NULL;
  BIGNUM *a=NULL, *b=NULL, *p=NULL, *q=NULL, *r=NULL, *s=NULL, *c=NULL, *quot=NULL, *new_r=NULL, *new_s=NULL;  
  int *Set_S=NULL;
  int j,j1;
  int retJac;

  *sig=NULL;
  
  /* Allocate everything */
  if ((ctx=BN_CTX_new()) == NULL) return(TC_ALLOC_ERROR);
  BN_CTX_start(ctx);
  
  w = BN_CTX_get(ctx);
  delta = BN_CTX_get(ctx);
  temp = BN_CTX_get(ctx);
  temp2 = BN_CTX_get(ctx);
  temp3 = BN_CTX_get(ctx);
  temp4 = BN_CTX_get(ctx);
  a = BN_CTX_get(ctx);
  b = BN_CTX_get(ctx);
  p = BN_CTX_get(ctx);
  q = BN_CTX_get(ctx);
  r = BN_CTX_get(ctx);
  s = BN_CTX_get(ctx);
  c = BN_CTX_get(ctx);
  quot = BN_CTX_get(ctx);
  new_r = BN_CTX_get(ctx);
  if ((new_s = BN_CTX_get(ctx))== NULL) return(ret_error(sig, Set_S, ctx, TC_ALLOC_ERROR));
  if ((*sig = BN_new())==NULL) return (ret_error(sig, Set_S, ctx, TC_ALLOC_ERROR)); /* Users responsiblity to free this */
  if ((Set_S=(int *)OPENSSL_malloc(((key->k)+1)*sizeof(int)))==NULL) return(ret_error(sig, Set_S, ctx, TC_ALLOC_ERROR));


  /* Compute delta */
  if (!BN_one(delta)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));

  for(j=2;j<=(key->l);j++) {
    if (!BN_set_word(temp, j)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_mul(delta, delta, temp, ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  }
  /* Delta computed */

  /* Compute the Set_S */
  j=0;

  if (checkproof == 0) {
    for(j1=0; (j1 < (key->l)) && (j< (key->k)); j1++) {
      if (ind_sigs[j1] != NULL) /* Ind_sig exists for this person */
        Set_S[j++] = j1+1;
    }
  } else {
    for(j1=0; (j1 < (key->l)) && (j< (key->k)); j1++) {
      if (ind_sigs[j1] != NULL) /* Ind_sig exists for this person */
        if (TC_Check_Proof(key, hM,ind_sigs[j1],j1+1) == 1) /* Signature verified */
          Set_S[j++] = j1+1;
    }
  }

  if (j == key->k)  /* got enough signatures */
    Set_S[j]=-1; /* end of array marker */
  else
    return(ret_error(sig, Set_S, ctx, TC_NOT_ENOUGH_SIGS));

  /* Compute w */
  if (!BN_one(w)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  for (j=0;j<key->k;j++) {
    if (!lambda(temp, 0, Set_S[j], Set_S, delta, temp2, temp3, temp4, ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_lshift1(temp, temp)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); // temp= temp*2
    if (!modified_BN_mod_exp(temp2,ind_sigs[Set_S[j]-1]->sig,temp,key->n,ctx, temp3)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_mod_mul(w,w,temp2,key->n,ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  }

  /* Use extended Euclidean Algorithm */
  /* Initialisations */
  if (!BN_set_word(a,4)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); /* a=e' */
  if (!BN_copy(b,key->e)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); /* b = e */


  if (!BN_one(p)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  if (!BN_zero(q)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  if (!BN_zero(r)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  if (!BN_one(s)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));

  while (!BN_is_zero(b)) {
    if (!BN_div(quot, c, a, b, ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    
    if (!BN_copy(a,b)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_copy(b,c)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));

    if (!BN_mul(temp,quot,r,ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); /* new_r = p - quot*r */
    if (!BN_sub(new_r, p, temp)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));

    if (!BN_mul(temp,quot,s,ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); /* new_s = q - quot*s */
    if (!BN_sub(new_s, q, temp)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));

    if (!BN_copy(p,r)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); 
    if (!BN_copy(q,s)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_copy(r,new_r)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); 
    if (!BN_copy(s,new_s)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  }

  /* p*e'+ q*e = a = gcd(e,e') = 1 */
  /* y = w^p x^q ; this gives (y/u)^e = x */
  if (!modified_BN_mod_exp(temp, w, p, key->n,ctx,temp3)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
 
  retJac = jacobi(hM,key->n);
  
  if (retJac == -1 ) {
    if (!BN_mod_exp(temp4, key->u, key->e, key->n, ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_mod_mul(temp4, temp4, hM,key->n,ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  } else 
    BN_copy(temp4,hM);

  if (!modified_BN_mod_exp(temp2, temp4, q, key->n, ctx, temp3)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  if (!BN_mod_mul(temp, temp, temp2,key->n, ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  
  /* sig = y/u */
  if (retJac == -1) {
    if (!BN_mod_inverse(temp2, key->u, key->n, ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_mod_mul(*sig, temp, temp2, key->n,ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  } else {
    BN_copy(*sig,temp);
  }

  OPENSSL_free(Set_S);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  
  return TC_NOERROR;
}

int TC_Combine_Sigs_P1(TC_IND_SIG **ind_sigs, TC_IND *key, BIGNUM *hM, int checkproof, int idx, BIGNUM *wexp, int **pSet_S) {
  BIGNUM *w=NULL, *delta=NULL;
  BN_CTX *ctx=NULL;
  BIGNUM *temp=NULL,*temp2=NULL,*temp3=NULL, *temp4=NULL;
  int *Set_S=NULL;
  int j,j1;
  
  /* Allocate everything */
  if ((ctx=BN_CTX_new()) == NULL) return(TC_ALLOC_ERROR);
  BN_CTX_start(ctx);
  
  w = BN_CTX_get(ctx);
  delta = BN_CTX_get(ctx);
  temp = BN_CTX_get(ctx);
  temp2 = BN_CTX_get(ctx);
  temp3 = BN_CTX_get(ctx);
  temp4 = BN_CTX_get(ctx);
  if ((Set_S=(int *)OPENSSL_malloc(((key->k)+1)*sizeof(int)))==NULL) return(ret_error(NULL, Set_S, ctx, TC_ALLOC_ERROR));

  /* Compute delta */
  if (!BN_one(delta)) return (ret_error(NULL,Set_S, ctx, TC_BN_ARTH_ERROR));

  for(j=2;j<=(key->l);j++) {
    if (!BN_set_word(temp, j)) return (ret_error(NULL,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_mul(delta, delta, temp, ctx)) return (ret_error(NULL,Set_S, ctx, TC_BN_ARTH_ERROR));
  }
  /* Delta computed */

  /* Compute the Set_S */
  j=0;

  if (checkproof == 0) {
    for(j1=0; (j1 < (key->l)) && (j< (key->k)); j1++) {
      if (ind_sigs[j1] != NULL) /* Ind_sig exists for this person */
        Set_S[j++] = j1+1;
    }
  } else {
    for(j1=0; (j1 < (key->l)) && (j< (key->k)); j1++) {
      if (ind_sigs[j1] != NULL) /* Ind_sig exists for this person */
        if (TC_Check_Proof(key, hM,ind_sigs[j1],j1+1) == 1) /* Signature verified */
          Set_S[j++] = j1+1;
    }
  }

  if (j == key->k)  /* got enough signatures */
    Set_S[j]=-1; /* end of array marker */
  else
    return(ret_error(NULL, Set_S, ctx, TC_NOT_ENOUGH_SIGS));

  /* Compute w (partial) */
  j = idx;
  if (!BN_one(w)) return (ret_error(NULL,Set_S, ctx, TC_BN_ARTH_ERROR));
  if (!lambda(temp, 0, Set_S[j], Set_S, delta, temp2, temp3, temp4, ctx)) return (ret_error(NULL,Set_S, ctx, TC_BN_ARTH_ERROR));
  if (!BN_lshift1(temp, temp)) return (ret_error(NULL,Set_S, ctx, TC_BN_ARTH_ERROR)); // temp= temp*2
  if (!modified_BN_mod_exp(temp2,ind_sigs[Set_S[j]-1]->sig,temp,key->n,ctx, temp3)) return (ret_error(NULL,Set_S, ctx, TC_BN_ARTH_ERROR));

  *pSet_S = Set_S;
  BN_copy(wexp,temp2);

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  
  return TC_NOERROR;
}

int TC_Combine_Sigs_P2(TC_IND *key, BIGNUM *hM, TC_SIG *sig, BIGNUM *wexps, int *Set_S) {
  BN_CTX *ctx=NULL;
  BIGNUM *w=NULL; 
  BIGNUM *temp=NULL,*temp2=NULL,*temp3=NULL, *temp4=NULL;
  BIGNUM *a=NULL, *b=NULL, *p=NULL, *q=NULL, *r=NULL, *s=NULL, *c=NULL, *quot=NULL, *new_r=NULL, *new_s=NULL;  
  int j;
  int retJac;

  /* Allocate everything */
  if ((ctx=BN_CTX_new()) == NULL) return(TC_ALLOC_ERROR);
  BN_CTX_start(ctx);
  
  w = BN_CTX_get(ctx);
  temp = BN_CTX_get(ctx);
  temp2 = BN_CTX_get(ctx);
  temp3 = BN_CTX_get(ctx);
  temp4 = BN_CTX_get(ctx);
  a = BN_CTX_get(ctx);
  b = BN_CTX_get(ctx);
  p = BN_CTX_get(ctx);
  q = BN_CTX_get(ctx);
  r = BN_CTX_get(ctx);
  s = BN_CTX_get(ctx);
  c = BN_CTX_get(ctx);
  quot = BN_CTX_get(ctx);
  new_r = BN_CTX_get(ctx);
  if ((new_s = BN_CTX_get(ctx))== NULL) return(ret_error(sig, Set_S, ctx, TC_ALLOC_ERROR));
  if ((*sig = BN_new())==NULL) return (ret_error(sig, Set_S, ctx, TC_ALLOC_ERROR)); /* Users responsiblity to free this */

  /* Compute w */
  if (!BN_one(w)) return (ret_error(NULL,Set_S, ctx, TC_BN_ARTH_ERROR));
  for (j=0;j<key->k;j++) {
    if (!BN_mod_mul(w,w,&(wexps[j]),key->n,ctx)) return (ret_error(NULL,Set_S, ctx, TC_BN_ARTH_ERROR));
  }
  
  /* Use extended Euclidean Algorithm */
  /* Initialisations */
  if (!BN_set_word(a,4)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); /* a=e' */
  if (!BN_copy(b,key->e)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); /* b = e */

  if (!BN_one(p)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  if (!BN_zero(q)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  if (!BN_zero(r)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  if (!BN_one(s)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));

  while (!BN_is_zero(b)) {
    if (!BN_div(quot, c, a, b, ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    
    if (!BN_copy(a,b)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_copy(b,c)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));

    if (!BN_mul(temp,quot,r,ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); /* new_r = p - quot*r */
    if (!BN_sub(new_r, p, temp)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));

    if (!BN_mul(temp,quot,s,ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); /* new_s = q - quot*s */
    if (!BN_sub(new_s, q, temp)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));

    if (!BN_copy(p,r)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); 
    if (!BN_copy(q,s)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_copy(r,new_r)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR)); 
    if (!BN_copy(s,new_s)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  }

  /* p*e'+ q*e = a = gcd(e,e') = 1 */
  /* y = w^p x^q ; this gives (y/u)^e = x */
  if (!modified_BN_mod_exp(temp, w, p, key->n,ctx,temp3)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
 
  retJac = jacobi(hM,key->n);
  
  if (retJac == -1 ) {
    if (!BN_mod_exp(temp4, key->u, key->e, key->n, ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_mod_mul(temp4, temp4, hM,key->n,ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  } else 
    BN_copy(temp4,hM);

  if (!modified_BN_mod_exp(temp2, temp4, q, key->n, ctx, temp3)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  if (!BN_mod_mul(temp, temp, temp2,key->n, ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  
  /* sig = y/u */
  if (retJac == -1) {
    if (!BN_mod_inverse(temp2, key->u, key->n, ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
    if (!BN_mod_mul(*sig, temp, temp2, key->n,ctx)) return (ret_error(sig,Set_S, ctx, TC_BN_ARTH_ERROR));
  } else {
    BN_copy(*sig,temp);
  }

  OPENSSL_free(Set_S);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  
  return TC_NOERROR;
}

