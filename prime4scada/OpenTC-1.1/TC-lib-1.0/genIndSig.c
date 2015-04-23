/**
 * file: genIndSig.c - Implements TC_Check_Proof() and genIndSig()
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

/* Proof of correctness:
   c = H'(v,xt,vi,xi^2,v^z*vi^-c,xt^z*xi^-2c)*/

static int ret_error_veri(BN_CTX *ctx, int errno) {
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return errno;
}

int TC_Check_Proof(TC_IND *tcind, BIGNUM*_x,TC_IND_SIG* sign, int signum) {
  EVP_MD_CTX ctx;
  int hLength;
  unsigned char *tempc;
  int retJacobi;

  BN_CTX *temp=NULL;
  BIGNUM* x =NULL;  
  BIGNUM* xt =NULL;  
  BIGNUM* xiSq =NULL;  
  BIGNUM *four =NULL;
  BIGNUM *two =NULL;
  BIGNUM *zero =NULL;
  BIGNUM* calcTemp =NULL;
  BIGNUM* calcTemp2 =NULL;
  BIGNUM* calcTemp3 =NULL;
  BIGNUM* calcTemp4 =NULL;
  BIGNUM* calcTemp5 =NULL;
  BIGNUM* calcTemp6 =NULL;

  signum--;

  if ((temp=BN_CTX_new()) == NULL) return(TC_ALLOC_ERROR);
  BN_CTX_start(temp);
  x = BN_CTX_get(temp);  
  xt = BN_CTX_get(temp);  
  xiSq = BN_CTX_get(temp);  
  four = BN_CTX_get(temp);
  two = BN_CTX_get(temp);
  zero = BN_CTX_get(temp);
  calcTemp = BN_CTX_get(temp);
  calcTemp2 = BN_CTX_get(temp);
  calcTemp3 = BN_CTX_get(temp);
  calcTemp4 = BN_CTX_get(temp);
  calcTemp5 = BN_CTX_get(temp);
  calcTemp6 = BN_CTX_get(temp);
  
  if(calcTemp6 == NULL) return (ret_error_veri(temp, TC_ALLOC_ERROR));

  /*0) x = _x if jacobi(_x,n) =1 
    x = _x*u^e if jacobi(_x,n) = -1*/
  
  retJacobi = jacobi(_x,tcind->n);

  switch (retJacobi){
  case 1: if (!BN_copy(x,_x)) return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    break;
  case -1: 
    if (!(BN_mod_exp(calcTemp,tcind->u,tcind->e,tcind->n,temp)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    if (!(BN_mod_mul(x,_x,calcTemp,tcind->n,temp)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    break;
    
  default: return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  }
  
  if (!(BN_set_word(four,4))){
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  }
  if (!(BN_set_word(two,2))){
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  }
  if (!(BN_set_word(zero,0))){
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  }
  
  /*to get xt*/
  if (!(BN_mod_exp(xt,x,four,tcind->n,temp))){
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  }
  
  if(!(BN_mod_exp(xiSq,sign->sig,two,tcind->n,temp))){
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));     
  }
  
  /*v^z*/
  if(!(BN_mod_exp(calcTemp,tcind->v,sign->proof_z,tcind->n,temp))){
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));     
  }

  /*vi^-c*/
  if (!(BN_mod_inverse(calcTemp2, tcind->vki[signum], tcind->n, temp)))
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));

  if(!(BN_mod_exp(calcTemp3,calcTemp2,sign->proof_c,tcind->n,temp))){
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));     
  }
  
  /*v^z*vi^-c****/
  if(!(BN_mod_mul(calcTemp4,calcTemp,calcTemp3,tcind->n,temp)))
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  
  /*xt^z*/
  if(!(BN_mod_exp(calcTemp,xt,sign->proof_z,tcind->n,temp))){
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));     
  }
  
  /*2c*/
  if(!(BN_mul(calcTemp2,sign->proof_c,two,temp))) {
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  }
  
  /*xi^-2c*/

  if (!(BN_mod_inverse(calcTemp3 ,sign->sig, tcind->n, temp)))
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));

  if(!(BN_mod_exp(calcTemp5,calcTemp3,calcTemp2,tcind->n,temp))){
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));     
  }
  
  /*xt^z*xi^-2c)****/
  if(!(BN_mod_mul(calcTemp6,calcTemp,calcTemp5,tcind->n,temp))) {
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  }
  
  if ((tempc = (unsigned char*)OPENSSL_malloc(EVP_MAX_MD_SIZE))==NULL) {
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  }

  EVP_DigestInit(&ctx,tcind->Hp);
  EVP_DigestUpdate(&ctx,tcind->v->d,(tcind->v->top)*sizeof(BN_ULONG));
  EVP_DigestUpdate(&ctx,xt->d,(xt->top)*sizeof(BN_ULONG));
  EVP_DigestUpdate(&ctx,tcind->vki[signum]->d,(tcind->vki[signum]->top)*sizeof(BN_ULONG));
  EVP_DigestUpdate(&ctx,xiSq->d,(xiSq->top)*sizeof(BN_ULONG));
  EVP_DigestUpdate(&ctx,calcTemp4->d,(calcTemp4->top)*sizeof(BN_ULONG));
  EVP_DigestUpdate(&ctx,calcTemp6->d,(calcTemp6->top)*sizeof(BN_ULONG));
  EVP_DigestFinal(&ctx,tempc,&hLength);
  
  BN_bin2bn(tempc,hLength,calcTemp);

  OPENSSL_free(tempc);

  if (BN_cmp(calcTemp,sign->proof_c)==0) {
    BN_CTX_end(temp);
    BN_CTX_free(temp);
    return 1;
  }

  BN_CTX_end(temp);
  BN_CTX_free(temp);
  
  return 0;
}


/************************************************************
  genIndSig: 
  input    :Tc_Ind individual signature struct,H(m) = _x,
            Tc_Ind_Sig signature share of player i
  output   :err code or TC_NOERROR
*************************************************************/

int genIndSig(TC_IND *tcind,BIGNUM *_x,TC_IND_SIG* sign, int genproof) {
  int iL1 = 128; /*secondary security parameter passed or just default val??*/

/*signature share of the player i*/
  BN_CTX *temp;
  BIGNUM* x ;
  BIGNUM* calcTemp ;
  BIGNUM *one ;
  BIGNUM *two ;
  BIGNUM *four ;
  int iLn;
  BIGNUM *Range ;
  BIGNUM *tempRange1 ;
  BIGNUM *tempRange2 ;
  BIGNUM *L1 ;
  BIGNUM *Ln ;
  BIGNUM *vp ;
  BIGNUM *xp ;
  BIGNUM *xt ;
  BIGNUM *xiSq ;
  BIGNUM *tempz ;
  EVP_MD_CTX ctx;
  unsigned char *tempc;
  int hLength;
  int retJacobi;

  if (tcind->mynum == -1)
    return (TC_ERROR);

  if ((temp=BN_CTX_new()) == NULL) return(TC_ALLOC_ERROR);
  BN_CTX_start(temp);
  x = BN_CTX_get(temp);
  calcTemp = BN_CTX_get(temp);
  one = BN_CTX_get(temp);
  two = BN_CTX_get(temp);
  four = BN_CTX_get(temp);
  Range = BN_CTX_get(temp);
  tempRange1 = BN_CTX_get(temp);
  tempRange2 = BN_CTX_get(temp);
  L1 = BN_CTX_get(temp);
  Ln = BN_CTX_get(temp);
  vp = BN_CTX_get(temp);
  xp = BN_CTX_get(temp);
  xt = BN_CTX_get(temp);
  xiSq = BN_CTX_get(temp);
  tempz = BN_CTX_get(temp);
  if(tempz == NULL) return (ret_error_veri(temp, TC_ALLOC_ERROR));

  /*set secondary security parameter*/
  if (!BN_set_word(L1,iL1))  return(ret_error_veri(temp,TC_BN_ARTH_ERROR));

  retJacobi = jacobi(_x,tcind->n);

  /*0) x = _x if jacobi(_x,n) =1 
    x = _x*u^e if jacobi(_x,n) = -1*/
  switch (retJacobi){
  case 1: if (!BN_copy(x,_x)) return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    break;
  case -1: 
    if (!(BN_mod_exp(calcTemp,tcind->u,tcind->e,tcind->n,temp)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    if (!(BN_mod_mul(x,_x,calcTemp,tcind->n,temp)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    break;
  default: return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  }
  
  if (!(BN_set_word(one,1))) 
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  
  if (!(BN_set_word(four,4)))
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  
  /*1) xi = x^(2*si) */
  if (!(BN_set_word(two,2)))
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  if (!(BN_mod_mul(calcTemp,two,tcind->si,tcind->n,temp)))
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
  if (!(BN_mod_exp(sign->sig,x,calcTemp,tcind->n,temp)))
    return(ret_error_veri(temp,TC_BN_ARTH_ERROR));

  /*verification*/

  /*choose random number r from range :
    let L(n) = bit length of n;
    L1   = bit length of the out of the hash function H' == Hp
    (this is the secondary security parameter)
    compute vp = v^r
    xp = xt^r 
    c = Hp(v,xp,vi,xi^2,vp,xp)
    z = si*c + r
    proof of correctness = (z,c)
  */


  if (genproof != 0) {
    iLn = BN_num_bits(tcind->n);
    if (!(BN_set_word(Ln,iLn)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    
    /*Range = 2^(Ln +2*L1) -1*/
    if(!(BN_mul(tempRange1,two,L1,temp)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    if(!(BN_add(tempRange2,Ln,tempRange1)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    if (!(BN_sub(Range,tempRange2,one)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    if (!(BN_rand_range(calcTemp,Range)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    if(!(BN_mod_exp(vp,tcind->v,calcTemp,tcind->n,temp)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    if (!(BN_mod_exp(xt,x,four,tcind->n,temp)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    if(!(BN_mod_exp(xp,xt,calcTemp,tcind->n,temp)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));
    if(!(BN_mod_exp(xiSq,sign->sig,two,tcind->n,temp)))
      return(ret_error_veri(temp,TC_BN_ARTH_ERROR));

    if ((tempc = (unsigned char*)OPENSSL_malloc(EVP_MAX_MD_SIZE))==NULL)
      return(ret_error_veri(temp,TC_ALLOC_ERROR));


    EVP_DigestInit(&ctx,tcind->Hp);
    EVP_DigestUpdate(&ctx,tcind->v->d,(tcind->v->top)*sizeof(BN_ULONG));
    EVP_DigestUpdate(&ctx,xt->d,(xt->top)*sizeof(BN_ULONG));
    EVP_DigestUpdate(&ctx,tcind->vki[tcind->mynum]->d,(tcind->vki[tcind->mynum]->top)*sizeof(BN_ULONG));
    EVP_DigestUpdate(&ctx,xiSq->d,(xiSq->top)*sizeof(BN_ULONG));
    EVP_DigestUpdate(&ctx,vp->d,(vp->top)*sizeof(BN_ULONG));
    EVP_DigestUpdate(&ctx,xp->d,(xp->top)*sizeof(BN_ULONG));
    EVP_DigestFinal(&ctx,tempc,&hLength); 

    BN_bin2bn(tempc,hLength,sign->proof_c);

    OPENSSL_free(tempc);

    if(!(BN_mul(tempz,tcind->si,sign->proof_c,temp)))
      return(ret_error_veri(temp,TC_ALLOC_ERROR));

    /*set z*/
    if(!(BN_add(sign->proof_z,tempz,calcTemp)))
      return(ret_error_veri(temp,TC_ALLOC_ERROR));
  }
  
  BN_CTX_end(temp);
  BN_CTX_free(temp);

  return TC_NOERROR;
}
