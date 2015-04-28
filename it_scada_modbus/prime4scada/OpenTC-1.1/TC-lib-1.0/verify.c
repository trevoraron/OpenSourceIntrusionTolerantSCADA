/**
 * file: verify.c - Implements TC_verify
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

int TC_verify(BIGNUM *hM, TC_SIG sig, TC_PK *tcpk) {
  BN_CTX *ctx=NULL;
  BIGNUM *temp=NULL;

  if ((ctx=BN_CTX_new()) == NULL) return(TC_ALLOC_ERROR);
  BN_CTX_start(ctx);
  temp = BN_CTX_get(ctx);
  if ((temp = BN_CTX_get(ctx))== NULL) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return(TC_ALLOC_ERROR);
  }
  
  if (!BN_mod_exp(temp,sig,tcpk->e,tcpk->n,ctx)) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return TC_BN_ARTH_ERROR;    
  };
 
  if (BN_cmp(temp,hM)==0) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 1;
  } else {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 0;
  }
}
