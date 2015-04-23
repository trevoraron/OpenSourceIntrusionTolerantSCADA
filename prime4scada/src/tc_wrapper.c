/*
 * Steward.
 *     
 * The contents of this file are subject to the Steward Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/byzrep/steward/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * The Creators of Steward are:
 *  Yair Amir, Claudiu Danilov, Danny Dolev, Jonathan Kirsch, John Lane,
 *  Cristina Nita-Rotaru, Josh Olsen, and David Zage.
 *
 * Copyright (c) 2005 - 2010 
 * The Johns Hopkins University, Purdue University, The Hebrew University.
 * All rights reserved.
 *
 */

#include "../OpenTC-1.1/TC-lib-1.0/TC.h" 
#include "openssl_rsa.h"
#include "data_structs.h"
#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_data_link.h"
#include "spu_memory.h"

extern server_variables VAR;

#define TIME_GENERATE_SIG_SHARE 0
#define NUM_SITES 1 //JCS: don't want to modify whole thing, so just defined this here...

TC_IND *tc_partial_key; /* My Partial Key */
TC_PK *tc_public_key[NUM_SITES+1];   /* Public Key of Site */
TC_IND_SIG **tc_partial_signatures; /* A list of Partial Signatures */

void assert(int ret, int expect, char *s) {
  if (ret != expect) {
    fprintf(stderr, "ERROR: %s (%d)\n", s, ret);
    exit(1);
  } else {
    /*fprintf(stdout, "%s ... OK\n", s);*/
  }
}

void assert_except(int ret, int except, char *s) {
  if (ret == except) {
    fprintf(stderr, "ERROR: %s (%d)\n", s, ret);
    exit(1);
  } else {
    /*fprintf(stdout, "%s ... OK\n", s);*/
  }
}

void TC_Read_Partial_Key( int32u server_no, int32u site_id ) {

    char buf[100];
    char dir[100] = "./keys";
 
    sprintf(buf, "%s/share%d_%d.pem", dir, server_no - 1, site_id );
    tc_partial_key = (TC_IND *)TC_read_share(buf);
 
}

void TC_Read_Public_Key() {

    int32u nsite;
    
    char buf[100];
    char dir[100] = "./keys";

    for ( nsite = 1; nsite <= NUM_SITES; nsite++ ) {
	sprintf(buf,"%s/pubkey_%d.pem", dir, nsite);
	tc_public_key[nsite] = (TC_PK *)TC_read_public_key(buf);
    }
}

int32u TC_Generate_Sig_Share( byte* destination, byte* hash  ) { 

    /* Generate a signature share without the proof. */
    
    TC_IND_SIG *signature;
    int32u length;
    BIGNUM *hash_bn;
    int32u ret;
    /*BIGNUM *bn;*/
    int32u pad;
 #if TIME_GENERATE_SIG_SHARE
    sp_time start, end, diff;

    start = E_get_time();
#endif

    hash_bn = BN_bin2bn( hash, DIGEST_SIZE, NULL );

    signature = TC_IND_SIG_new();
    ret = genIndSig( tc_partial_key, hash_bn, signature, 0);
    //assert(ret, TC_NOERROR, "genIndSig");

  
    BN_free( hash_bn );
    
    /* Made the signature share. Now take the bn sig and store it in the
     * destination in OPENSSL mpi format. */

    //length = BN_bn2bin( signature->sig, (destination + 4) );

    //*((int32u*)destination) = length;
    
    //bn = BN_bin2bn( destination + 4, *((int32u*)destination), NULL );

    length = BN_num_bytes( signature->sig );
	
    BN_bn2bin( signature->sig, destination + (128 - length) );

    /* The length should be around 128 bytes if it is not 128 then we need to
     * pad with zeroes */
    for ( pad = 0; pad < (128 - length); pad++ ) {
	destination[pad] = 0;
    }
      
#if 0
    printf("Sig Share: %s\n", BN_bn2hex( signature->sig ));
    printf("Sig Share Read Back: %s\n", BN_bn2hex( bn ));
#endif

    TC_IND_SIG_free( signature );
    
#if TIME_GENERATE_SIG_SHARE
    end = E_get_time();

    diff = E_sub_time(end, start);
    Alarm(PRINT, "Gen sig share: %d sec; %d microsec\n", diff.sec, diff.usec);
#endif

    return length;

}

void TC_Initialize_Combine_Phase( int32u number ) {

    tc_partial_signatures = TC_SIG_Array_new( number );

}

void TC_Add_Share_To_Be_Combined( int server_no, byte *share ) {

    /* Convert share to bignum. */

    TC_IND_SIG *signature;

    signature = TC_IND_SIG_new();

    //BN_bin2bn( share + 4, *((int32u*)share), signature->sig );

    BN_bin2bn( share, 128, signature->sig );

#if 0    
    printf("ADD: %d; %s\n", server_no, BN_bn2hex( signature->sig ));
#endif

    set_TC_SIG(server_no, signature, tc_partial_signatures );

}

void TC_Destruct_Combine_Phase( int32u number ) {
    
    TC_SIG_Array_free( tc_partial_signatures, number );
    
}
    
void TC_Combine_Shares( byte *signature_dest, byte *digest ) {
 
    TC_SIG combined_signature;
    BIGNUM *hash_bn;
    int32u ret;
    int32u length;
    BIGNUM *bn;
    int32u pad;
    
    hash_bn = BN_bin2bn( digest, DIGEST_SIZE, NULL );

    ret = TC_Combine_Sigs( tc_partial_signatures, tc_partial_key, 
	    hash_bn, &combined_signature, 0);

    /* There is a probable security error here. We need to make sure
     * that we don't exit if there is an arithmetic error in the
     * combining, and then enter the proof phase, during which we
     * identify the malicious server that sent a message which caused
     * the arithmetic error. This is related to the blacklisting code,
     * which is not currently coded.*/

    ret = TC_verify(hash_bn, combined_signature, 
		tc_public_key[1]);    
		//tc_public_key[VAR.My_Site_ID]); //XXX: if want to use for multi-site, will need to change this

    length = BN_num_bytes( combined_signature );
	
    BN_bn2bin( combined_signature, signature_dest + (128 - length) );

    /* The length should be approx 128 bytes if it is not 128 then we need to
     * pad with zeroes */
    for ( pad = 0; pad < (128 - length); pad++ ) {
	signature_dest[pad] = 0;
    }
    
    bn = BN_bin2bn( signature_dest, 128, NULL );

#if 0 
    if ( length < 128 ) {
	printf("Combined Sig: %s\n", BN_bn2hex( combined_signature ));
	printf("Read Back: %s\n", BN_bn2hex( bn ));
	printf("Size: %d\n", length );
	ret = TC_verify(hash_bn, bn, tc_public_key);
	assert(ret, 1, "TC_verify");
	exit(0);
    }
#endif

    BN_free( combined_signature );
    BN_free( bn );
    BN_free( hash_bn );

}

int32u TC_Verify_Signature( int32u site, byte *signature, byte *digest ) {

    BIGNUM *hash_bn;
    int32u ret;
    BIGNUM *sig_bn;
   
#if REMOVE_CRYPTO
    return 1;
#endif

    hash_bn = BN_bin2bn( digest, DIGEST_SIZE, NULL );
    sig_bn = BN_bin2bn( signature, SIGNATURE_SIZE, NULL );

    if ( site == 0 || site > NUM_SITES ) {
	ret = 0;
    } else {
	ret = TC_verify(hash_bn, sig_bn, tc_public_key[site]);
    }

    BN_free( sig_bn );
    BN_free( hash_bn );

    return ret;
}

/* The following function generate the threshold shares and store them on disk. */

void TC_Generate()
{
	TC_DEALER *dealer; //[NUM_SITES+1];
	int nsite;

	int faults, n, k, keysize, num_sites;

	keysize = 1024;
	faults = NUM_FAULTS;
	n = 3*faults+1;
	k = 2*faults+1;
	num_sites = NUM_SITES;

	for ( nsite = 1; nsite <= num_sites; nsite++ ) {
		printf("Generating threshold crypto keys for site %d\n",nsite);
		dealer = NULL;
		/* while ( dealer == NULL ) */
		dealer = TC_generate(keysize/2, n, k, 17);

		TC_write_shares(dealer, "./keys", nsite);
		TC_DEALER_free(dealer);
	}

}



