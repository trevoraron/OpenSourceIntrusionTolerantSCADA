/**
 * file: generate.c - Implements the TC_generate API call
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

#include <openssl/rsa.h>

int jacobi(BIGNUM* p,BIGNUM* q);

TC_DEALER *TC_generate(int bits, int l, int k,unsigned long val_e)
{
	TC_DEALER *tc = NULL;
	
	/* variables needed to perform calculations */
	BIGNUM *p,*q,*p_prime,*q_prime,*m,*d,*fX[k]; 
	BIGNUM *a, *b, *c, *f, *sum,*inv_delta, *bndelta;	
	BN_CTX *temp, *ctx;
	int result = 0, i = 0, j = 0;

	/* variablle to be used for calcualtion */
	temp = BN_CTX_new();
	
	/* variable to be used for initialization */
	ctx = BN_CTX_new();
        if (ctx == NULL) goto null_err;
        BN_CTX_start(ctx);	

	/* initialize the variables */
	p = BN_CTX_get(ctx);
	q = BN_CTX_get(ctx);
	p_prime = BN_CTX_get(ctx);
	q_prime = BN_CTX_get(ctx);
	m = BN_CTX_get(ctx);
	d = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
        b = BN_CTX_get(ctx);
        c = BN_CTX_get(ctx);
        f = BN_CTX_get(ctx);
        bndelta = BN_CTX_get(ctx);
        inv_delta = BN_CTX_get(ctx);
        sum = BN_CTX_get(ctx);
	
	/* check if either of these variable failed to initialize */
	if( sum == NULL) goto null_err;
	
	if( l <= k || l == 0 || k == 0 ) goto null_err;

	/* initialize tc */
	tc = TC_DEALER_new();
	if( tc == NULL) goto null_err;

	/* set l and k */
	tc->l = l;
	tc->k = k;	

	/* set n */
	tc->n = BN_new();
	if( tc->n == NULL) goto null_err;

	/*generate p and q */
        /* p and q are generated as strong prime such that
        *  p = 2p' + 1 and q = 2q'+1*/
        /*setting the safe to true will generate a strong prime*/

        p = BN_generate_prime(NULL,bits,1,NULL,NULL,NULL,NULL);
        if (p == NULL) goto null_err;

        q = BN_generate_prime(NULL,bits,1,NULL,NULL,NULL,NULL);
        if (q == NULL) goto null_err;

	/*calculate n = p*q */
        result = BN_mul(tc->n,p,q,temp);
	if( result == 0 ) goto null_err;

	/* calculating p' by subtract p by 1 and then divide by 2*/
        result = BN_sub(p_prime, p, BN_value_one());
	if( result == 0 ) goto null_err;
        result = BN_rshift1(p_prime,p_prime);
	if( result == 0 ) goto null_err;

        /* calculating q' by subtract q by 1 and then divide by 2*/
        result = BN_sub(q_prime, q, BN_value_one());
	if( result == 0 ) goto null_err;
        result = BN_rshift1(q_prime,q_prime);
	if( result == 0 ) goto null_err;

	/*calculate m = p' * q'*/
        result = BN_mul(m,p_prime,q_prime,temp);
	if( result == 0 ) goto null_err;
	
	if (val_e == 0) {
	  tc->e = BN_generate_prime(NULL,bits,0,NULL,NULL,NULL,NULL);
	  if( tc->e == NULL) goto null_err;
	} else {
	  tc->e=BN_new();
	  if( tc->e == NULL) goto null_err;
	  BN_set_word(tc->e, val_e);
	}

	 /* generate d by de = 1 mod m*/
        d = BN_mod_inverse(NULL,tc->e,m,temp);
        if( d == NULL) goto null_err;

	/*define the polynomial */
        /*allocate memory for the array to store the polynomial coefficient*/
        for( i = 0; i < k ; i++)
        {
		fX[i] = BN_new();	
        }
	BN_copy(fX[0], d); /* a0 = d */ /* a0 * X^0 */
	 /* store the rest of the coefficient */
        for( i = 1; i < k; i++)
        {
                /*random a starting from a1 till ak-1*/
                result = BN_rand(fX[i], bits, 0,0);
		if( result == 0 ) goto null_err;
        }

	/*computes si using si = f(i) * delta^-1 mod m */

        /* compute delta which is factorial of l */
	
	result = BN_one(bndelta);
	if( result == 0 ) goto null_err;
	for( i = 1; i <= l; i++)
	{
		result = BN_set_word(c, i);
		if( result == 0 ) goto null_err;
		result = BN_mul(bndelta,bndelta,c,temp);
		if( result == 0 ) goto null_err;		
	}

        /*we need inverse delta for the equation */        
	inv_delta = BN_mod_inverse(NULL,bndelta,m, temp);
	if( inv_delta == NULL) goto null_err;

        tc->si = (BIGNUM **) OPENSSL_malloc (l*sizeof(BIGNUM *));
	if( tc->si == NULL) goto null_err;
	
	for (i=0; i<l;i++)
	  tc->si[i]=NULL;

        /*alocate memory for the secret key shares*/
        for( i = 0; i < l; i++)
        {
                tc->si[i] = BN_new();
		if( tc->si[i] == NULL) goto null_err;
        }

	/*compute the secret key shares */
        for( i = 1; i <= l; i++)
        {
                result = BN_set_word(sum,0);
		if( result == 0 ) goto null_err;

                /* fX[i]= aj * i^j */
                for( j = 0; j < k ; j++ )
                {
                        /* a = fX[j] * i^j(b) */
                        result = BN_set_word(c,i);
			if( result == 0 ) goto null_err;

                        result = BN_set_word(f,j);
                        if( result == 0 ) goto null_err;

			result = BN_exp(b,c,f,temp);
			if( result == 0 ) goto null_err;

                        result = BN_mul(a,fX[j],b,temp);
			if( result == 0 ) goto null_err;

                        result = BN_add(sum,sum,a);
			if( result == 0 ) goto null_err;

                }
                /*sk[i] = a * inv_delta(inv_delta) */
                result = BN_mod_mul(tc->si[i-1], sum, inv_delta, m, temp);
		if( result == 0 ) goto null_err;

        }

	/* compute VK */
        tc->v = BN_new();
	if( tc->v == NULL) goto null_err;

        for(;;)
        {

                result = BN_rand_range(a, tc->n);
		if( result == 0 ) goto null_err;

                result = BN_mod_sqr(b,a,tc->n,temp);
		if( result == 0 ) goto null_err;

                result = BN_is_zero(b);
                if( result == 0 )
                        break;
        }

        BN_copy(tc->v,b);
	if( tc->v == NULL) goto null_err;

	/* generate shares of verification key */
        /*alocate memory for the verify key shares*/

        tc->vki = (BIGNUM **) OPENSSL_malloc (l*sizeof(BIGNUM *));
	if( tc->vki == NULL) goto null_err;

	for( i = 0; i < l; i++)
                tc->vki[i] = NULL;
	
        for( i = 0; i < l; i++)
        {
                tc->vki[i] = BN_new();
		if( tc->vki[i] == NULL) goto null_err;
        }
        for( i = 0; i < l; i++)
        {
                BN_mod_exp(tc->vki[i],tc->v,tc->si[i],tc->n,temp);
        }

	
	for(;;)
        {
                result = BN_rand_range(a,tc->n);
		if( result == 0 ) goto null_err;

                if ((result = jacobi(tc->n,a))==TC_BN_ARTH_ERROR) goto null_err;
                if( result == -1)
                {
			tc->u = BN_new();
			BN_copy(tc->u,a);
		        break;
		}
        }
	

	BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        BN_CTX_free(temp);
	return (tc);

null_err:
	/* free the allocate memory and exit */
	if( tc !=  NULL)
		TC_DEALER_free(tc);
	BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        BN_CTX_free(temp);
	return NULL;
}	

TC_IND * TC_read_share(char* file)
{
	TC_IND * tci;
	int j;
	RSA* current;
	FILE * read;

	printf("Reading %s", file);
	read = fopen(file, "r");
	if (!read)
		fprintf(stderr, "TC_read_share: Error opening file");

	tci = (TC_IND *)OPENSSL_malloc(sizeof(TC_IND));
	current = RSA_new();
	
	PEM_read_RSAPublicKey(read, &current, NULL, NULL);
	tci->l = atoi(BN_bn2dec(current->e));
	tci->k = atoi(BN_bn2dec(current->n));

	PEM_read_RSAPublicKey(read, &current, NULL, NULL);
	tci->mynum = atoi(BN_bn2dec(current->e));
	tci->v = BN_dup(current->n);

	PEM_read_RSAPublicKey(read, &current, NULL, NULL);
	tci->u = BN_dup(current->e);
	tci->e = BN_dup(current->n);
	
	PEM_read_RSAPublicKey(read, &current, NULL, NULL);
	tci->n = BN_dup(current->e);
	tci->si = BN_dup(current->n);

	tci->vki = (BIGNUM**)(OPENSSL_malloc(tci->l * sizeof(BIGNUM*)));	
	for(j=0; j<tci->l; j+=2)
	{
		PEM_read_RSAPublicKey(read, &current, NULL, NULL);
		(tci->vki)[j] = BN_dup(current->e);
		if(j+1 != tci->l)
			(tci->vki)[j+1] = BN_dup(current->n);
	}
	tci->Hp= EVP_md5();

	RSA_free(current);
	fclose(read);
	printf(" ... Done Reading\n");

#ifdef DEBUG
printf("---User---\n");
printf("l=%d k=%d mynum=%d", tci->l, tci->k, tci->mynum);
printf("\n-----v----\n");
BN_print_fp(stdout, tci->v);
printf("\n-----u----\n");
BN_print_fp(stdout, tci->u);
printf("\n-----e----\n");
BN_print_fp(stdout, tci->e);
printf("\n-----n----\n");
BN_print_fp(stdout, tci->n);
printf("\n-----si----\n");
BN_print_fp(stdout, tci->si);
printf("\n-----End user-----\n");
#endif

	return tci;
}

TC_PK * TC_read_public_key(char* file)
{
	RSA* ret = RSA_new();
	FILE* read = fopen(file, "r");
	TC_PK * tcpk;

	if (!read)
		fprintf(stderr, "TC_read_public_key: Error opening file");

	PEM_read_RSAPublicKey(read, &ret, NULL, NULL);
	fclose(read);

	tcpk = (TC_PK*)(malloc(sizeof(TC_PK)));
	tcpk->e = BN_dup(ret->e);
	tcpk->n = BN_dup(ret->n);
	RSA_free(ret);

	return tcpk;
}

#include <sys/stat.h>
void TC_write_shares(TC_DEALER* dealer, char* directory, int site_number )
{
	FILE* out;
	RSA* current;
	TC_IND * tci;
	char buf[512];
	int i, j;
	unsigned long fInfo;

	struct stat statbuf;
	if(stat(directory, &statbuf) != 0) 
	{
		if(mkdir(directory, 0777) != 0)
		{
			fprintf(stderr, "Error creating dir %s", directory);
			return;
		}
	
	}

	current = RSA_new();

	for (i=0; i<dealer->l; i++)
	{

		sprintf(buf, "%s/share%d_%d.pem", directory, i, site_number);
		printf("Writing to %s\n", buf);
		out = fopen(buf, "w");

		tci = TC_get_ind(i+1, dealer);
#ifdef DEBUG
printf("---User %d---\n", i);
printf("l=%d k=%d mynum=%d", tci->l, tci->k, tci->mynum);
printf("\n-----v----\n");
BN_print_fp(stdout, tci->v);
printf("\n-----u----\n");
BN_print_fp(stdout, tci->u);
printf("\n-----e----\n");
BN_print_fp(stdout, tci->e);
printf("\n-----n----\n");
BN_print_fp(stdout, tci->n);
printf("\n-----si----\n");
BN_print_fp(stdout, tci->si);
printf("\n-----End user %d-----\n", i);
#endif DEBUG

		current->e = BN_new();
		current->n = BN_new();

		BN_set_word((current->e), tci->l);
		BN_set_word(current->n, tci->k);
		PEM_write_RSAPublicKey(out,current);

		BN_set_word(current->e, tci->mynum);
		BN_free(current->n);
		current->n = tci->v;
		PEM_write_RSAPublicKey(out,current);
		BN_free(current->e);

		current->e = tci->u;
		current->n = tci->e;
		PEM_write_RSAPublicKey(out,current);

		current->e = tci->n;
		current->n = tci->si;
		PEM_write_RSAPublicKey(out,current);
		
		for(j=0; j<dealer->l; j+=2)
		{
			current->e = (tci->vki)[j];
			if(j+1 != dealer->l)
				current->n = (tci->vki)[j+1];
			PEM_write_RSAPublicKey(out,current);
		}
		TC_IND_free(tci);
		fclose(out);
	}

	sprintf(buf, "%s/pubkey_%d.pem", directory,site_number);
	out = fopen(buf, "w");
	current->e = dealer->e;
	current->n = dealer->n;
	PEM_write_RSAPublicKey(out, current);
	current->e = NULL;
	current->n = NULL;
	RSA_free(current);
	fclose(out);

	printf("Done Writing\n");
}
