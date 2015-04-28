/**
 * file: jacobi.c - Implements jacobi function, used internally
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

int jacobi(BIGNUM* paramp,BIGNUM* paramq) 
{
	int j, result;
  	BN_CTX *temp=BN_CTX_new();

	BIGNUM* p ;
        BIGNUM* q ;
        BIGNUM* ptemp ;
        BIGNUM *z ;
        BIGNUM *o ;
        BIGNUM *m ;

  	BN_ULONG r;
  	BN_ULONG u;

	if( temp == NULL ) return TC_ALLOC_ERROR;

        BN_CTX_start(temp);

        p = BN_CTX_get(temp);
        q = BN_CTX_get(temp);
        ptemp = BN_CTX_get(temp);
        z = BN_CTX_get(temp);
        o = BN_CTX_get(temp);
        m = BN_CTX_get(temp);

        /* check if either of these variables failed to initialize */
        if( m == NULL ) goto null_err;

  	BN_zero(z); /*used for zero everywhere*/
  	BN_one(o); /*used for one everywhere*/

	/* copy the variable, if its fails return error */
  	if ( BN_copy(p,paramp) == NULL ) goto null_err;
  	if ( BN_copy(q,paramq) == NULL ) goto null_err;
	
	/* error if q <= 0 or q  is even */
 	if ( (BN_cmp(q,z) <= 0) || (BN_is_odd(q) == 0) ) 
		return (-2);

  	/*if (p < 0) {p = p%q; if (p < 0) p += q;}*/
  	if( BN_cmp(p,z) < 0 ) 
	{
    		result =  BN_mod(ptemp,p,q,temp);
		if( result == 0 ) goto arth_err;

    		if( BN_copy(p,ptemp) == NULL ) goto null_err;

    		if ( BN_cmp(p,z) < 0 ) 
		{
     			result = BN_add(p,p,q);
			if( result == 0 ) goto null_err;
    		}
  	}

   	/*if (p == 1 || q == 1) return(1);*/
   	if ( (BN_cmp(p,o) == 0) || (BN_cmp(q,o) == 0) ) 
		return(1);

   	/*if (q <= p) p = p%q;*/
   	if ( BN_cmp(p,q) <= 0 )
	{
     		result = BN_mod(ptemp,p,q,temp);
		if( result == 0 ) goto arth_err;

     		if( BN_copy(p,ptemp) == NULL ) goto null_err;
   	}

  	/*if (p == 0) return(0);*/
  	if( BN_cmp(p,z) == 0) 
		return(0);

     	j = 1;
     	while ( BN_cmp(p,o) != 0 )
	{
       		u = BN_mod_word(p,4);
       		switch (u) 
		{
         		/* break into four cases of p mod 4 */
       			case 0: 
				result = BN_rshift(ptemp,p,2); 
				if( result == 0 ) goto arth_err;

				if( BN_copy(p,ptemp) == NULL ) goto null_err; 
			break; 
			
			/* divide by 4 */
       			case 2: 
				result = BN_rshift(ptemp,p,1); 
				if( result == 0 ) goto arth_err;

				if( BN_copy(p,ptemp) == NULL ) goto null_err;
         		
				r = BN_mod_word(q,8);
         			if (r == 3 || r == 5) 
					j = -j; 
			break;

       			case 3: 
				if ( BN_mod_word(q,4) == 3 ) 
				{
					j = -j; 
				}

         		/* fall through into case  1 */
       			case 1:
         			result = BN_mod(m,q,p,temp);
				if( result == 0 ) goto arth_err;

         			if( BN_cmp(m,z) == 0 ) 
					return(0);
         			else
           			{
             				if( BN_copy(q,p) == NULL ) goto null_err;
             				if( BN_copy(p,m) == NULL ) goto null_err;
           			}
         		break;
       		}/* end of switch */
     	}/* end of while */
     
	/* free the memory */
	BN_CTX_end(temp);
     	BN_CTX_free(temp);

     	return(j);

null_err:
	BN_CTX_end(temp);
        BN_CTX_free(temp);
	return TC_ALLOC_ERROR;

arth_err:
	BN_CTX_end(temp);
        BN_CTX_free(temp);
	return TC_BN_ARTH_ERROR;
}
