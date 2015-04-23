/* Copyright (c) 2000, The Johns Hopkins University
 * All rights reserved.
 *
 * The contents of this file are subject to a license (the ``License'')
 * that is the exact equivalent of the BSD license as of July 23, 1999. 
 * You may not use this file except in compliance with the License. The
 * specific language governing the rights and limitations of the License
 * can be found in the file ``STDUTIL_LICENSE'' found in this 
 * distribution.
 *
 * Software distributed under the License is distributed on an AS IS 
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. 
 *
 * The Original Software is:
 *     The Stdutil Library
 * 
 * Contributors:
 *     Creator - John Lane Schultz (jschultz@cnds.jhu.edu)
 *     The Center for Networking and Distributed Systems
 *         (CNDS - http://www.cnds.jhu.edu)
 */ 

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdutil/stdhash.h>

#define DEBUG(x)
/* #define DEBUG(x) x */

#define NUM_STRINGS 15000
#define STRING_SIZE 20

char strings[NUM_STRINGS][STRING_SIZE], (*str_ptr)[STRING_SIZE];

int main(void) {
  stdhash my_hash = STDHASH_STATIC_CONSTRUCT(sizeof(int), sizeof(char*),
					     stdhash_int_cmp, stdhash_int_hcode, NULL); 
  stdhash_it hit;
  int i, j, k;

  /*
  stdhash_construct(&my_hash, sizeof(int), sizeof(char*), 
		    stdhash_int_equals, stdhash_int_hashcode); 
  */

  for (i = 0, str_ptr = strings; i < NUM_STRINGS; ++i, ++str_ptr)
    sprintf((char*) str_ptr, "%d", i);

  DEBUG(printf("begin insertions: time %ld\n", time(0)));
  for (i = 0, str_ptr = strings; i < NUM_STRINGS; ++i, ++str_ptr)
    stdhash_insert(&my_hash, 0, &i, &str_ptr);
 
  DEBUG(printf("done insertions: time %ld\n", time(0)));
  stdhash_begin(&my_hash, &hit); /* make the iterator valid */

  DEBUG(printf("start loop overhead: time %ld\n", time(0)));
  for (i = 0, j = 0, k = 0; i < 10000000; ++i) {
    j = rand() % NUM_STRINGS;
    if (stdhash_it_is_end(&hit) || *(int*) stdhash_it_key(&hit) == j)
      ++k;
  }
  DEBUG(printf("end loop overhead: time %ld: j %d, k %d\n", time(0), j, k));

  DEBUG(printf("start lookups: time %ld\n", time(0)));
  for (i = 0; i < 10000000; ++i) {
    j = rand() % NUM_STRINGS;
    stdhash_find(&my_hash, &hit, &j);
    if (stdhash_it_is_end(&hit) || *(int*) stdhash_it_key(&hit) != j)
      exit(printf("got an end on it %d: %d != %d\n", i, *(int*) stdhash_it_key(&hit), j));
  }
  DEBUG(printf("done lookups: time %ld\n", time(0)));

  printf("\nstdhash_test run successful!\n\n");

  return 0;
}
