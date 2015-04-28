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

#include <string.h>
#include <assert.h>
#include "merkle.h"
#include "openssl_rsa.h"
#include "spu_alarm.h"

byte dt[DIGEST_SIZE * (512) + 1];
byte verify_dt[DIGEST_SIZE * (512) + 1];
int32 mt_num;

int32 MT_Parent( int32 n ); 
int32 MT_C1( int32 n ); 
int32 MT_C2( int32 n );
int32 MT_L( int32 n ); 
int32 MT_S( int32 n ); 

int32 MT_Parent( int32 n ) 
{
  return n / 2; 
}

int32 MT_Digests_( int32 n ) 
{
  if ( n <= 1 ) return 0;
  if ( n <= 2 ) return 1;
  if ( n <= 4 ) return 2;
  if ( n <= 8 ) return 3;
  if ( n <= 16 ) return 4;
  if ( n <= 32 ) return 5;
  if ( n <= 64 ) return 6;
  if ( n <= 128) return 7; 
  if ( n <= 256) return 8;

  Alarm(EXIT, "Probable bug: Should probably never happen? %d\n", n);
  return -1;
}

int32 MT_Digests() 
{
  return MT_Digests_( mt_num );
}

int32 MT_C1( int32 n ) 
{
  return (2*n);
}

int32 MT_C2( int32 n ) 
{
  return (2*n+1);
}

int32 MT_L( int32 n ) 
{
  return (mt_num-1+n);
}

int32 MT_S( int32 n ) 
{
  if (n % 2 == 0) 
    return n + 1;
  return n - 1;
}

int32 MT_Set_Num(int32 n) 
{
  if (n == 1) mt_num = 1;
  else if (n <= 2) mt_num = 2;
  else if (n <= 4) mt_num = 4;
  else if (n <= 8) mt_num = 8;
  else if (n <= 16) mt_num = 16;
  else if (n <= 32) mt_num = 32;
  else if (n <= 64) mt_num = 64;
  else if (n <= 128) mt_num = 128;
  else if (n <= 256) mt_num = 256;
  else Alarm(EXIT, "MT_Set_Num: %d too high (> 256)\n", n);
  
  return mt_num;
}

void MT_Put_Mess_Digest( int32 n, byte *digest ) 
{
  byte *p;

  p = dt + (DIGEST_SIZE * MT_L(n));
  
  memcpy( p, digest, DIGEST_SIZE );
}

byte* MT_Make_Digest_From_All() 
{
  int32 n;
  int32 c;
  
  /* We assume that all of the digests in the leaf nodes are filled in. */
  
  for ( n = mt_num-1; n >= 1; n--) {
	c = MT_C1(n);
	/* Make a digest for node n */
	OPENSSL_RSA_Make_Digest( dt + (c*DIGEST_SIZE), 2 * DIGEST_SIZE, 
				 dt + (n*DIGEST_SIZE) );
	//Alarm(PRINT,"Node = %d\n",n);
	//OPENSSL_RSA_Print_Digest( dt + (n*DIGEST_SIZE) );
  }
  
  //OPENSSL_RSA_Print_Digest( dt + DIGEST_SIZE );
  
  return dt + DIGEST_SIZE;
}

void MT_Extract_Set( int32 mess_num, signed_message *mess ) 
{
  int32 sib;
  int32 n;
  int32 di;
  byte *digests;
  
  /* Get a set of digests that can be used to recreate the original */
  mess->mt_index = mess_num;
  mess->mt_num   = mt_num;
  
  digests = ((byte*)(mess+1)) + mess->len;
  
  n = mess_num + mt_num - 1;
  di = 0;
  while ( n > 1 ) {
    sib = MT_S(n);
    if ( sib > 1 ) {
      memcpy( digests + di * DIGEST_SIZE, dt + sib * DIGEST_SIZE, DIGEST_SIZE);
      di++;
      //Alarm(PRINT," Set di %d\n",di);
    }
    n = MT_Parent(n);
  }
}

byte* MT_Make_Digest_From_Set( int32 mess_num, byte *digests, 
			       byte *mess_digest, int32u mtnum ) 
{

  int32 sib;
  int32 n;
  int32 di;

  n = mess_num + mtnum - 1;
  memcpy(verify_dt + n * DIGEST_SIZE, mess_digest, DIGEST_SIZE);

  /* The first digest should be placed in the sibling of n */
  di = 0;
  while ( n > 1 ) {
    sib = MT_S(n);
    if ( sib > 1 ) {
      memcpy(verify_dt + sib * DIGEST_SIZE, 
	     digests + di * DIGEST_SIZE, DIGEST_SIZE);
      di++;
    }
    /* Make the digest of the parent */
    n = MT_Parent(n);
    OPENSSL_RSA_Make_Digest(verify_dt + MT_C1(n) * DIGEST_SIZE, 
			    2 * DIGEST_SIZE,
			    verify_dt + n * DIGEST_SIZE );
  }
  
  return verify_dt + DIGEST_SIZE;
}

void MT_Clear() 
{
  memset( dt, 0, sizeof(dt));//DIGEST_SIZE * 256 );   
}

void MT_Clear_Verify()
{
  memset(verify_dt, 0, sizeof(verify_dt));
}

int32 MT_Verify( signed_message *mess ) 
{
  byte digest[DIGEST_SIZE];
  /*byte *mtopt;*/
  byte *proot = NULL;
  int32 ret;
  byte *digests;
  
  //MT_Set_Num( mess->mt_num );

  if(mess->type == UPDATE) {
    OPENSSL_RSA_Make_Digest((char*)mess + SIGNATURE_SIZE, 
			    mess->len + sizeof(signed_message) - 
			    SIGNATURE_SIZE,
			    digest );

    ret = OPENSSL_RSA_Verify_Signature(digest, (byte *)mess,
				       mess->machine_id, RSA_CLIENT);
  }
  else {
    digests = ((byte*)(mess+1)) + mess->len;

    MT_Clear_Verify();

    OPENSSL_RSA_Make_Digest((char*)mess + SIGNATURE_SIZE + (2*sizeof(int16u)), 
			    mess->len + sizeof(signed_message) - 
			    SIGNATURE_SIZE - (2*sizeof(int16u)),
			    digest );
    
    proot = MT_Make_Digest_From_Set(mess->mt_index, digests, digest, 
				    mess->mt_num);
    
#if 0
    Alarm(PRINT, "Digest in MT_Verify: ");
    OPENSSL_RSA_Print_Digest(proot);
#endif

    ret = OPENSSL_RSA_Verify_Signature(proot, (byte *)mess,
				       mess->machine_id, RSA_SERVER);
  }
  
  if ( ret == 0 ) {
    Alarm(PRINT,"MT Verify bad RSA Sig n=%d mtn=%d type=%d sid=%d di=%d\n",
	  mess->mt_index, mess->mt_num, mess->type, mess->site_id, 
	  MT_Digests_(mess->mt_num));
    Alarm(PRINT,"YY->"); OPENSSL_RSA_Print_Digest(proot);
    OPENSSL_RSA_Print_Digest(digest); 
  }
  
  return ret; 
}

byte* MT_Make_Digest_From_List(dll_struct *list)
{
  byte digest[DIGEST_SIZE];
  int32 i, ret;
  signed_message *mess;
  int32u threshold;

  ret = MT_Set_Num(list->length);

  threshold = 2 << (MAX_MERKLE_DIGESTS-1);
  
  /* We've exceeded the maximum number of digests for this context */
  if(ret > threshold) {
    Alarm(PRINT, "ret = %d, threshold = %d, length = %d\n", 
	  ret, threshold, list->length);
    assert(0);
  }

  MT_Clear();

  UTIL_DLL_Set_Begin(list);
  i = 1;

  memset(digest, 0, sizeof(digest));
  while((mess = (signed_message *)UTIL_DLL_Get_Signed_Message(list)) != NULL) {
    OPENSSL_RSA_Make_Digest((char*)mess + SIGNATURE_SIZE + (2*sizeof(int16u)),
       mess->len + sizeof(signed_message) - SIGNATURE_SIZE -(2*sizeof(int16u)),
			    digest);
      
    MT_Put_Mess_Digest(i, digest);
    UTIL_DLL_Next(list);
    i++;
  }
  
  return MT_Make_Digest_From_All();
}

#if 0
void MT_Test() {
 
    /* Test the Merkel Hash Optimization */

    int32 i;
    byte d[DIGEST_SIZE];
    byte dset[DIGEST_SIZE * 3];
    int t;
    
    for ( i = 1; i <= 8; i++ ) {
	((int*)d)[0] = i;
	MT_Put_Mess_Digest( i, d );
	//OPENSSL_RSA_Print_Digest( d );
    }

    t = 6;
 
    d[5] = 15;
    MT_Put_Mess_Digest( t, d );
 
    MT_Make_Digest_From_All();

    MT_Extract_Set( t, (signed_message *)dset );

    for ( i = 0; i < 3; i ++ ) {

	//OPENSSL_RSA_Print_Digest( dset + DIGEST_SIZE * i );

    }
 
    MT_Clear();

    d[5] = 1;
    d[5] = 15;
 
    MT_Make_Digest_From_Set( t, dset, d ); 
 
    //Alarm(EXIT,"");
 
}
#endif
