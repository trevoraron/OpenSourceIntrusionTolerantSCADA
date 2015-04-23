/**
 * file: struct_func.c - Implements all the functions listed in TC.h under
 *                  the section "Helper functions"
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

#if HAVE_STDIO_H
#include <stdio.h>
#endif

TC_DEALER *TC_DEALER_new(void)
{
	TC_DEALER *tc;
	tc = (TC_DEALER *)OPENSSL_malloc(sizeof(TC_DEALER));
	if(tc == NULL)
	{
	/* malloc failure */
	return NULL;
	}

	tc->u = NULL;
	tc->e = NULL;
	tc->n = NULL;
	tc->vki = NULL;
	tc->v = NULL;
	tc->si = NULL;
	tc->l = 0;
	tc->k = 0;
	tc->Hp=EVP_md5();

	return (tc);
}

void TC_DEALER_free(TC_DEALER *tc)
{
        int i;
	if (tc == NULL) return;
	if (tc->n != NULL) BN_clear_free(tc->n);
	if (tc->u != NULL) BN_clear_free(tc->u);
	if (tc->e != NULL) BN_clear_free(tc->e);
	if (tc->v != NULL) BN_clear_free(tc->v);
	
	if (tc->vki != NULL) {
	  for (i=0; i<tc->l; i++) {
	    if (tc->vki[i] != NULL) BN_clear_free(tc->vki[i]);
	  }
	  OPENSSL_free(tc->vki);
	}

	if (tc->si != NULL) {
	  for (i=0; i<tc->l; i++) {
	    if (tc->si[i] != NULL) BN_clear_free(tc->si[i]);
	  }
	  OPENSSL_free(tc->si);
	}

	OPENSSL_free(tc);
}

void TC_DEALER_print(TC_DEALER *tc)
{
	int i = 0;
	char *temp,*temp1,*temp2, *temp3;
	
	
	if(tc == NULL) return;
	printf("Total number of people = %d\nThreshold = %d\n", tc->l, tc->k);
	printf("Public key n = %s\nPublic Key e = %s\nVerfication key = %s\nJacobi Norm = %s\n", 
		temp=BN_bn2dec(tc->n),temp1=BN_bn2dec(tc->e),temp2=BN_bn2dec(tc->v), temp3=BN_bn2dec(tc->u));

	OPENSSL_free(temp);
	OPENSSL_free(temp1);
	OPENSSL_free(temp2);
	OPENSSL_free(temp3);

	for( i = 0; i < tc->l; i++) {
	  printf("Secret key#%d %s\nVerification key#%d %s\n", 
		 i + 1 ,temp=BN_bn2dec(tc->si[i]),i + 1 ,temp1=BN_bn2dec(tc->vki[i]));
	  OPENSSL_free(temp);
	  OPENSSL_free(temp1);
	}

	printf("Hash Function pointer = %p\n", tc->Hp);
}

int TC_Dealer_setHash (TC_DEALER *tcd,unsigned short hashpointer){
  if(tcd == NULL) return TC_ERROR;
  switch (hashpointer){
  case 0: tcd->Hp =EVP_md5(); break;
  default: return TC_ERROR;
  }
  return TC_NOERROR;
}

TC_IND *TC_get_ind(int index,TC_DEALER *tcd){
  int i,error=0;
  TC_IND *tcind = (TC_IND *)OPENSSL_malloc(sizeof(TC_IND));
  if (tcind == NULL) return NULL;

  if (index<1) return NULL;

  /* First assign the verification keys, so we can easily bail out on error */
  if ((tcind->vki = (BIGNUM **)OPENSSL_malloc((tcd->l)*sizeof(BIGNUM *)))==NULL) {
    OPENSSL_free(tcind);
    return NULL;
  }

  for(i=0;i<(tcd->l);i++)
    error = error || ((tcind->vki[i]=BN_dup(tcd->vki[i]))==NULL);
  
  if (error) {
    for (i=0;i<(tcd->l);i++)
      if (tcind->vki[i] != NULL) BN_clear_free(tcind->vki[i]);
    OPENSSL_free(tcind->vki);
    OPENSSL_free(tcind);
    return NULL;
  }

  tcind->l = tcd->l;
  tcind->k = tcd->k;
  tcind->mynum = index-1;

  tcind->v = BN_dup(tcd->v);
  tcind->u = BN_dup(tcd->u);
  tcind->e = BN_dup(tcd->e);
  tcind->n = BN_dup(tcd->n);

  tcind->si = BN_dup(tcd->si[index-1]);
  tcind->Hp = tcd->Hp;
  
  if ((tcind->v == NULL) ||
      (tcind->u == NULL) ||
      (tcind->e == NULL) ||
      (tcind->n == NULL) ||
      (tcind->si == NULL)) {
    if (tcind->v!=NULL) BN_clear_free(tcind->v);
    if (tcind->u!=NULL) BN_clear_free(tcind->u);
    if (tcind->e!=NULL) BN_clear_free(tcind->e);
    if (tcind->n!=NULL) BN_clear_free(tcind->n);
    if (tcind->si!=NULL) BN_clear_free(tcind->si);
    
    for (i=0;i<(tcd->l);i++)
      if (tcind->vki[i] != NULL) BN_clear_free(tcind->vki[i]);

    OPENSSL_free(tcind->vki);
    OPENSSL_free(tcind);
    return (NULL);
  }

  return tcind;
}

TC_PK *TC_get_pub (TC_DEALER *tcd){
  TC_PK *tcpk = (TC_PK *)OPENSSL_malloc(sizeof(TC_PK));
  if (tcpk==NULL)
    return NULL;

  tcpk->e = BN_dup(tcd->e);
  tcpk->n = BN_dup(tcd->n);

  if ((tcpk->e==NULL) || (tcpk->n == NULL)) {
    if (tcpk->e!=NULL) BN_clear_free(tcpk->e);
    if (tcpk->n!=NULL) BN_clear_free(tcpk->n);
    OPENSSL_free(tcpk);
    return (NULL);
  }
  return(tcpk);
}

TC_IND *TC_get_combine(TC_DEALER *tcd){
  int i, error=0;
  TC_IND *tcind = (TC_IND *)OPENSSL_malloc(sizeof(TC_IND));
  if (tcind == NULL) return NULL;

  if ((tcind->vki = (BIGNUM **)OPENSSL_malloc((tcd->l)*sizeof(BIGNUM *)))==NULL) {
    OPENSSL_free(tcind);
    return NULL;
  }

  for(i=0;i<(tcd->l);i++)
    error = error || ((tcind->vki[i]=BN_dup(tcd->vki[i]))==NULL);
  
  if (error) {
    for (i=0;i<(tcd->l);i++)
      if (tcind->vki[i] != NULL) BN_clear_free(tcind->vki[i]);
    OPENSSL_free(tcind->vki);
    OPENSSL_free(tcind);
    return NULL;
  }

  tcind->l = tcd->l;
  tcind->k = tcd->k;
  tcind->mynum = -1;

  tcind->v = BN_dup(tcd->v);
  tcind->u = BN_dup(tcd->u);
  tcind->e = BN_dup(tcd->e);
  tcind->n = BN_dup(tcd->n);
  tcind->si = NULL;
  tcind->Hp = tcd->Hp;
  
  if ((tcind->v == NULL) ||
      (tcind->u == NULL) ||
      (tcind->e == NULL) ||
      (tcind->n == NULL)) {
    if (tcind->v!=NULL) BN_clear_free(tcind->v);
    if (tcind->u!=NULL) BN_clear_free(tcind->u);
    if (tcind->e!=NULL) BN_clear_free(tcind->e);
    if (tcind->n!=NULL) BN_clear_free(tcind->n);
    
    for (i=0;i<(tcd->l);i++)
      if (tcind->vki[i] != NULL) BN_clear_free(tcind->vki[i]);
    
    OPENSSL_free(tcind->vki);
    OPENSSL_free(tcind);
    return (NULL);
  }

  return tcind;
}

void TC_PK_free(TC_PK *tcpk){
  if (tcpk == NULL) return;
  if (tcpk->n != NULL) BN_clear_free(tcpk->n);
  if (tcpk->e != NULL) BN_clear_free(tcpk->e);

  OPENSSL_free(tcpk);
}

void TC_IND_free(TC_IND *tcind){
  int i;

  if (tcind == NULL) return;
  if (tcind->n != NULL) BN_clear_free(tcind->n);
  if (tcind->u != NULL) BN_clear_free(tcind->u);
  if (tcind->e != NULL) BN_clear_free(tcind->e);
  if (tcind->v != NULL) BN_clear_free(tcind->v);
  if (tcind->si != NULL) BN_clear_free(tcind->si);
  if (tcind->vki != NULL) {
    for (i=0;i<(tcind->l);i++)
      if (tcind->vki[i] != NULL) BN_clear_free(tcind->vki[i]);
    OPENSSL_free(tcind->vki);
  }
  OPENSSL_free(tcind);
}

TC_IND_SIG *TC_IND_SIG_new() {
  TC_IND_SIG *tcind = (TC_IND_SIG *)OPENSSL_malloc(sizeof(TC_IND_SIG));
  if (tcind ==NULL)
    return NULL;
  
  if ((tcind->sig = BN_new())==NULL) goto err;
  if ((tcind->proof_c = BN_new())==NULL) goto err;
  if ((tcind->proof_z = BN_new())==NULL) goto err;

  return (tcind);

 err:
  if (tcind->sig!=NULL) BN_clear_free(tcind->sig);
  if (tcind->proof_c!=NULL) BN_clear_free(tcind->proof_c);
  if (tcind->proof_z!=NULL) BN_clear_free(tcind->proof_z);
  OPENSSL_free(tcind);
  return NULL;
}

void TC_PK_Print(TC_PK *pk)
{
  char *temp,*temp1;
  if(pk == NULL) return;

  printf("n %s\ne %s\n",
	 temp=BN_bn2dec(pk->n),temp1=BN_bn2dec(pk->e));
  OPENSSL_free(temp);
  OPENSSL_free(temp1);
}

void TC_IND_Print(TC_IND *ind)
{
  int i = 0;
  char *temp,*temp1,*temp2, *temp3, *temp4;
  
  if(ind == NULL) return;
  printf("Total number of people = %d\nThreshold = %d\nMy Number = %d\n", ind->l, ind->k, ind->mynum+1);
  printf("Public key n = %s\nPublic Key e = %s\nVerfication key = %s\nMy Secret Key = %s\nJac Norm = %s\n", 
	 temp=BN_bn2dec(ind->n),temp1=BN_bn2dec(ind->e),temp2=BN_bn2dec(ind->v), ((ind->si==NULL)?"NONE":(temp3=BN_bn2dec(ind->si))),
	 temp4=BN_bn2dec(ind->u));
  
  OPENSSL_free(temp);
  OPENSSL_free(temp1);
  OPENSSL_free(temp2);
  OPENSSL_free(temp4);
  if (ind->si !=NULL) OPENSSL_free(temp3);
  
  for( i = 0; i < ind->l; i++) {
    printf("Verification key#%d %s\n", 
	   i + 1,temp=BN_bn2dec(ind->vki[i]));
    OPENSSL_free(temp);
  }
  
  printf("Hash Function pointer = %p\n", ind->Hp);
}

void TC_IND_SIG_Print(TC_IND_SIG *sig)
{
  char *temp,*temp1,*temp2;
  if(sig == NULL) return;

  printf("sig %s\nproof_z %s\nproof_c %s\n",
	 temp=BN_bn2dec(sig->sig),temp1=BN_bn2dec(sig->proof_z),temp2=BN_bn2dec(sig->proof_c));
  
  OPENSSL_free(temp);
  OPENSSL_free(temp1);
  OPENSSL_free(temp2);
}


TC_IND_SIG **TC_SIG_Array_new(int l) {
  int i;
  TC_IND_SIG **ret = (TC_IND_SIG **) OPENSSL_malloc(l * sizeof(TC_IND_SIG *));
  
  if (ret==NULL)
    return NULL;

  for (i=0; i<l; i++)
    ret[i]=NULL;

  return ret;
}

void set_TC_SIG(int index, TC_IND_SIG* si,TC_IND_SIG** sigs) {
  if ((si==NULL) || (sigs==NULL))
    return;

  if ((sigs[index-1] = TC_IND_SIG_new())==NULL) return;

  BN_copy(sigs[index-1]->sig, si->sig);
  BN_copy(sigs[index-1]->proof_z, si->proof_z);
  BN_copy(sigs[index-1]->proof_c, si->proof_c);
}


void TC_IND_SIG_free(TC_IND_SIG *a) {
  if (a == NULL) return;

  if (a->sig != NULL) BN_clear_free(a->sig);
  if (a->proof_c != NULL) BN_clear_free(a->proof_z);
  if (a->proof_z != NULL) BN_clear_free(a->proof_c);
  
  OPENSSL_free(a);
}


void TC_SIG_Array_free(TC_IND_SIG **a,int l) {
  int i;
 
  for(i=0;i<l;i++)
    if (a[i]!=NULL)
      TC_IND_SIG_free(a[i]);
  
  OPENSSL_free(a);
}
