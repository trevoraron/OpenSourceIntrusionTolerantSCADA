/*
 * Prime.
 *     
 * The contents of this file are subject to the Prime Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/byzrep/prime/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * The Creators of Prime are:
 *  Yair Amir, Jonathan Kirsch, and John Lane.
 *
 * Special thanks to Brian Coan for major contributions to the design of
 * the Prime algorithm. 
 *  	
 * Copyright (c) 2008 - 2010 
 * The Johns Hopkins University.
 * All rights reserved.
 *
 */

/* Openssl RSA signing and verifying functionality. The openssl_rsa.h header
 * file lists the public functions that can be used to sign messages and verify
 * that signatures are valid. */

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include "openssl_rsa.h"
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include "data_structs.h"
#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_data_link.h"
#include "spu_memory.h"

/* Defined Types */
// "ripemd160"
#define RSA_TYPE_PUBLIC          1
#define RSA_TYPE_PRIVATE         2
#define RSA_TYPE_CLIENT_PUBLIC   3 
#define RSA_TYPE_CLIENT_PRIVATE  4 
#define DIGEST_ALGORITHM         "sha1" 
#define NUMBER_OF_SERVERS        NUM_SERVERS
#define NUMBER_OF_CLIENTS        NUM_CLIENTS


/* Global variables */
RSA *private_rsa; /* My Private Key */
RSA *public_rsa_by_server[NUMBER_OF_SERVERS + 1];
RSA *public_rsa_by_client[NUMBER_OF_CLIENTS + 1];
const EVP_MD *message_digest;
void *pt;
int32 verify_count;

void Gen_Key_Callback(int32 stage, int32 n, void *unused) 
{
}

void Write_BN(FILE *f, BIGNUM *bn) 
{
  char *bn_buf;
  
  bn_buf = BN_bn2hex( bn );
  
  fprintf( f, "%s\n", bn_buf );

  /* Note: The memory for the BIGNUM should be freed if the bignum will not
   * be used again. TODO */ 
}

void Write_RSA( int32u rsa_type, int32u server_number, RSA *rsa) 
{
  FILE *f;
  char fileName[50];
  char dir[100] = "./keys";
  
  /* Write an RSA structure to a file */
  if(rsa_type == RSA_TYPE_PUBLIC)
    sprintf(fileName,"%s/public_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_PRIVATE)
    sprintf(fileName,"%s/private_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PUBLIC)
    sprintf(fileName,"%s/public_client_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PRIVATE)
    sprintf(fileName,"%s/private_client_%02d.key", dir, server_number);
     
  f = fopen(fileName, "w");

  Write_BN(f, rsa->n);
  Write_BN(f, rsa->e);

  if(rsa_type == RSA_TYPE_PRIVATE || rsa_type == RSA_TYPE_CLIENT_PRIVATE) {
    Write_BN( f, rsa->d );
    Write_BN( f, rsa->p );
    Write_BN( f, rsa->q );
    Write_BN( f, rsa->dmp1 );
    Write_BN( f, rsa->dmq1 );
    Write_BN( f, rsa->iqmp );
  }
  fprintf( f, "\n" );
  fclose(f);
}

void Read_BN( FILE *f, BIGNUM **bn ) 
{
  char bn_buf[1000];

  (*bn) = BN_new();
  fgets(bn_buf, 1000, f);
  BN_hex2bn( bn, bn_buf );
}

void Read_RSA( int32u rsa_type, int32u server_number, RSA *rsa) 
{
  FILE *f;
  char fileName[50];
  char dir[100] = "./keys";
  
  /* Read an RSA structure to a file */
  
  if(rsa_type == RSA_TYPE_PUBLIC)
    sprintf(fileName,"%s/public_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_PRIVATE)
    sprintf(fileName,"%s/private_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PUBLIC)
    sprintf(fileName,"%s/public_client_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PRIVATE)
    sprintf(fileName,"%s/private_client_%02d.key", dir, server_number);
  
  if((f = fopen( fileName, "r")) == NULL)
    Alarm(EXIT,"   ERROR: Could not open the key file: %s\n", fileName );
  
  Read_BN( f, &rsa->n );
  Read_BN( f, &rsa->e );
  if ( rsa_type == RSA_TYPE_PRIVATE || rsa_type == RSA_TYPE_CLIENT_PRIVATE ) {
    Read_BN( f, &rsa->d );
    Read_BN( f, &rsa->p );
    Read_BN( f, &rsa->q );
    Read_BN( f, &rsa->dmp1 );
    Read_BN( f, &rsa->dmq1 );
    Read_BN( f, &rsa->iqmp );
  }

  fclose(f);
}


/* This function generates keys based on the current configuration as specified
 * in data_structs.h */
void OPENSSL_RSA_Generate_Keys() {

    RSA *rsa;
    int32u s;

    /* Prompt user for a secret key value. */

    /* Generate Keys For Servers */
    for ( s = 1; s <= NUMBER_OF_SERVERS; s++ ) {
      rsa = RSA_generate_key( 1024, 3, Gen_Key_Callback, NULL );
      /*RSA_print_fp( stdout, rsa, 4 );*/
      Write_RSA( RSA_TYPE_PUBLIC,  s, rsa ); 
      Write_RSA( RSA_TYPE_PRIVATE, s, rsa ); 
    } 

    /* Generate Keys For Clients */
    for ( s = 1; s <= NUMBER_OF_CLIENTS; s++ ) {
      rsa = RSA_generate_key( 1024, 3, Gen_Key_Callback, NULL );
      /*RSA_print_fp( stdout, rsa, 4 );*/
      Write_RSA( RSA_TYPE_CLIENT_PUBLIC,  s, rsa ); 
      Write_RSA( RSA_TYPE_CLIENT_PRIVATE, s, rsa ); 
    } 
}

/* Read all of the keys for servers or clients. All of the public keys
 * should be read and the private key for this server should be read. */
 void OPENSSL_RSA_Read_Keys(int32u my_number, int32u type)
{

  int32u s; 
  int32u rt;
  
  /* Read all public keys for servers. */
  for(s = 1; s <= NUMBER_OF_SERVERS; s++) {
    public_rsa_by_server[s] = RSA_new();
    Read_RSA(RSA_TYPE_PUBLIC, s, public_rsa_by_server[s] );
  } 

  /* Read all public keys for clients. */
  for ( s = 1; s <= NUMBER_OF_CLIENTS; s++ ) {
    public_rsa_by_client[s] = RSA_new();
    Read_RSA( RSA_TYPE_CLIENT_PUBLIC, s, public_rsa_by_client[s] );
  } 
    
  if ( type == RSA_SERVER ) {
    rt = RSA_TYPE_PRIVATE;
  } else if ( type == RSA_CLIENT ) {
    rt = RSA_TYPE_CLIENT_PRIVATE;
  } else {
    printf("OPENSSL_RSA_Read_Keys: Called with invalid type.\n");
    exit(0);
  }

  /* Read my private key. */
  private_rsa = RSA_new();
  Read_RSA( rt, my_number, private_rsa );
}

void OPENSSL_RSA_Init() 
{
  /* Load a table containing names and digest algorithms. */
  OpenSSL_add_all_digests();
  
  /* Use sha1 as the digest algorithm. */
  message_digest = EVP_get_digestbyname( DIGEST_ALGORITHM );
  verify_count = 0;
}

int32u OPENSSL_RSA_Digests_Equal( unsigned char *digest1, 
				  unsigned char *digest2 ) {

    int32u i;

#if REMOVE_CRYPTO    
    //return 1;
#endif    
    
    for ( i = 0; i < DIGEST_SIZE; i++ ) {
	if ( digest1[i] != digest2[i] ) return 0;
    }
    return 1;
}

void OPENSSL_RSA_Make_Digest( const void *buffer, size_t buffer_size, 
	unsigned char *digest_value ) {

    /* EVP functions are a higher level abstraction that encapsulate many
     * different digest algorithms. We currently use sha1. The returned digest
     * is for sha1 and therefore we currently assume that functions which use
     * this type of digest. It would be best to extend the encapsulation
     * through our code. TODO Note that there may be an increase in
     * computational cost because these high-level functions are used. We might
     * want to test this and see if we take a performance hit. */
    
    EVP_MD_CTX mdctx;
    int32u md_len;
    
#if REMOVE_CRYPTO 
    //return;
#endif
    
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, message_digest, NULL);
    EVP_DigestUpdate(&mdctx, buffer, buffer_size);
    EVP_DigestFinal_ex(&mdctx, digest_value, &md_len);
    EVP_MD_CTX_cleanup(&mdctx);

    /* Check to determine if the digest length is expected for sha1. It should
     * be 20 bytes. */
   
    if ( md_len != 20 ) {
	printf("An error occurred while generating a message digest.\n"
		"The length of the digest was set to %d. It should be 20.\n"
		, md_len);
	exit(0);
    }

#if 0 
    printf("Digest is, size %d: ",md_len);
#endif
    
}

void OPENSSL_RSA_Print_Digest( unsigned char *digest_value ) {

    int32u i;
    
    for(i = 0; i < DIGEST_SIZE; i++) printf("%02x", digest_value[i]);
    printf("\n");

}

void OPENSSL_RSA_Make_Signature( const byte *digest_value, byte *signature ) 
{
  sp_time start, end, diff;
  int32u signature_size = 0;
  
  /* Make a signature for the specified digest value. The digest value is
   * assumed to be 20 bytes. */

#if REMOVE_CRYPTO
  //UTIL_Busy_Wait(0.000005);
  return;
#endif
  
  /*int32u rsa_size;*/ 
  
  if(private_rsa == NULL) {
    printf("Error: In Make_Signature, private_rsa key is NULL.\n");
    exit(0);
  }

  /*RSA_print_fp( stdout, private_rsa, 4 );*/
  /*rsa_size = RSA_size( private_rsa ); */
    
  /*printf("Signature size: %d\n", rsa_size);*/
  //private_rsa = RSA_generate_key( 1024, 3, Gen_Key_Callback, NULL );
 
  start = E_get_time();

  RSA_sign(NID_sha1, digest_value, 20, signature, &signature_size,private_rsa);

  end = E_get_time();
  
  diff = E_sub_time(end, start);
  Alarm(DEBUG, "Signing: %d sec; %d microsec\n", diff.sec, diff.usec);
}


int32u OPENSSL_RSA_Verify_Signature( const byte *digest_value, 
	unsigned char *signature,  int32u number,  int32u type ) {

    /* Verify a signature for the specified digest value. The digest value is
     * assumed to be 20 bytes. */
   
    int32 ret;
    RSA *rsa; 

#if REMOVE_CRYPTO 
    //UTIL_Busy_Wait(0.000005);
    return 1;
#endif
    
    /*unsigned int32u rsa_size = RSA_size( private_rsa );*/
    /*printf("Signature size: %d\n", rsa_size);*/
   
    if ( type == RSA_CLIENT ) {
	if (number < 1 || number > NUMBER_OF_CLIENTS ) {
	    return 0;
	}
	rsa = public_rsa_by_client[number];
    } else {
	if (number < 1 || number > NUMBER_OF_SERVERS ) {
	    return 0;
	}
        rsa = public_rsa_by_server[number];
    }
    
    ret = RSA_verify(NID_sha1, digest_value, 20, signature, SIGNATURE_SIZE,
	    rsa );
    
    verify_count++;
   
    if ( verify_count % 1000 == 0 ) {
	//Alarm(PRINT,"Verify Count %d\n",verify_count);
    }
    
#if 1 
    if ( !ret ) {
	printf("RSA_OPENSSL_Verify: Verification Failed. "
		"Machine number = %d. \n",
		number);
    }
#endif

    return ret; 
}

void OPENSSL_RSA_Sign( const unsigned char *message, size_t message_length,
       unsigned char *signature ) {

  unsigned char md_value[EVP_MAX_MD_SIZE];

#if REMOVE_CRYPTO
    //UTIL_Busy_Wait(0.000005);
    return;
#endif

    memset(md_value, 0, sizeof(md_value));
    OPENSSL_RSA_Make_Digest( message, message_length, md_value );

    OPENSSL_RSA_Make_Signature( md_value, signature );

#if 0    
    Alarm( PRINT," verify 1 %d\n",
	   OPENSSL_RSA_Verify_Signature( md_value, signature, 1, 
	   RSA_SERVER ));

    Alarm( PRINT," verify 2 %d\n",
	   OPENSSL_RSA_Verify( message, message_length, signature, 1, 
	   RSA_SERVER ));
#endif

}

int OPENSSL_RSA_Verify( const unsigned char *message, size_t message_length,
	unsigned char *signature, int32u number, int32u type ) {
 
    int32 ret;
     
    unsigned char md_value[EVP_MAX_MD_SIZE];

#if REMOVE_CRYPTO
    //UTIL_Busy_Wait(0.000005);
    return 1;
#endif    

    OPENSSL_RSA_Make_Digest( message, message_length, md_value );
    ret =  OPENSSL_RSA_Verify_Signature( md_value, signature, number, type );

   
    return ret;
}

