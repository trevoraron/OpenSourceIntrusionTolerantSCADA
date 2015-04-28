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
#include <stdarg.h>
#include <errno.h>
#include <string.h>

#ifdef USE_DMALLOC
# include <dmalloc.h>
#endif

#include <stdutil/stddll.h>
#include <stdutil/stderror.h>

// keep NUM_PUSH a multiple of 2
#define NUM_PUSH   ((size_t) 1024)
#define NUM_END    ((size_t) 6)
#define NUM_INSERT ((size_t) 5)

int main(int argc, char **argv) {
  stddll list, list2;
  stddll_it list_it, list_it2;
  size_t i, j, k;

  if (NUM_PUSH % 4)
    stderr_pabort(__FILE__, __LINE__, "NUM_PUSH must be at least a multiple of 4, is %u, NUM_PUSH %% 4 = %u\n", 
	   NUM_PUSH, NUM_PUSH % 4);

  if (NUM_PUSH/4 < NUM_END)
    stderr_pabort(__FILE__, __LINE__, "NUM_END (%u) is greater than NUM_PUSH/4 (%u)\n", NUM_END, NUM_PUSH/4);

  if (stddll_construct(&list, sizeof(size_t))) /* list will contain size_t's */
    stderr_pabort(__FILE__, __LINE__, "stddll_construct failed!");

  if (stddll_val_size(&list) != sizeof(size_t))
    stderr_pabort(__FILE__, __LINE__, "stddll_copy_construct failed, wrong type size!");

  for (i = 0; i < NUM_PUSH; ++i) {
    if (stddll_size(&list) != i)
      stderr_pabort(__FILE__, __LINE__, "stddll_size not %u! is %u\n", i, stddll_size(&list));

    if (stddll_push_back(&list, &i))
      stderr_pabort(__FILE__, __LINE__, "stddll_push_back failed on i = %d"
	     ", size = %u", i, stddll_size(&list));
  }

  if (i != stddll_size(&list))
    stderr_pabort(__FILE__, __LINE__, "i is %u! not %u\n", i, stddll_size(&list));

  stddll_last(&list, &list_it);
  /* you can modify stddll while iterating through it: not all DS's support this */
  do {
    --i;
    j = *(size_t*) stddll_it_val(&list_it);

    if (j != i)
      stderr_pabort(__FILE__, __LINE__, "unexpected value! last was %u, should be %u!", j, i);

    if (i != 0) /* get previous unless it is begin */
      stddll_it_prev(&list_it);
    else if (!stddll_it_is_begin(&list_it)) /* check and be sure is begin */
      stderr_pabort(__FILE__, __LINE__, "isn't begin but should be i % u, j %u!", i, j);

    if (stddll_pop_back(&list))
      stderr_pabort(__FILE__, __LINE__, "stddll_pop_back failed on i = %u, size = %u", i, stddll_size(&list));

    if (stddll_size(&list) != i)
      stderr_pabort(__FILE__, __LINE__, "stddll_size not %u! is %u\n", i, stddll_size(&list));
    
  } while (i != 0);

  /* make sequence: 0, 2, 4, ..., NUM_PUSH - 3, NUM_PUSH - 1, NUMPUSH - 2, NUM_PUSH - 4, ..., 3, 1 */
  stddll_end(&list, &list_it); 
  for (i = 0; i < NUM_PUSH; ++i) {
    if (stddll_size(&list) != i)
      stderr_pabort(__FILE__, __LINE__, "stddll_size not %u! is %u\n", i, stddll_size(&list));

    if (!stddll_insert(&list_it, &i))
      stderr_pabort(__FILE__, __LINE__, "stddll_insert failed on i = %u, size = %u\n", i, stddll_size(&list));

    if (i % 2 == 0)
      stddll_it_next(&list_it);
  }

  /* make a copy (by value clone) of it */
  if (stddll_copy_construct(&list2, &list))
    stderr_pabort(__FILE__, __LINE__, "stddll_copy_construct failed!");

  if (stddll_val_size(&list2) != sizeof(size_t))
    stderr_pabort(__FILE__, __LINE__, "stddll_copy_construct failed, wrong type size!");

  /* clearing list doesn't affect list2 */
  if (stddll_clear(&list))
    stderr_pabort(__FILE__, __LINE__, "stddll_clear failed!");

  if (stddll_size(&list) != 0 || !stddll_it_is_end(stddll_begin(&list, &list_it)))
    stderr_pabort(__FILE__, __LINE__, "stddll_clear succeeded incorrectly!");

  /* check and be sure list2 has an exact copy of the above sequence */
  stddll_begin(&list2, &list_it);
  stddll_last(&list2, &list_it2);
  for (i = 0; i < NUM_PUSH; ++i) {
    j = *(size_t*) stddll_it_val(&list_it);  /* iterate through evens */
    k = *(size_t*) stddll_it_val(&list_it2); /* iterate through odds  */

    if (j != i)
      stderr_pabort(__FILE__, __LINE__, "j is %u! not %u!", j, i);

    if (k != ++i)
      stderr_pabort(__FILE__, __LINE__, "k is %u! not %u!", k, i);

    stddll_it_next(&list_it);
    stddll_it_prev(&list_it2);
  }

  /* erase the odds -- list_it should be pointing at first odd and list_it2 at last even */
  if (!stddll_multi_erase(&list_it, NUM_PUSH / 2))
    stderr_pabort(__FILE__, __LINE__, "multi-erase of odds failed!");

  if (!stddll_it_is_end(&list_it))
    stderr_pabort(__FILE__, __LINE__, "list_it should be end but it isn't?!");

  stddll_get(&list2, &list_it, NUM_PUSH / 4); 

  if ((i = *(size_t*) stddll_it_val(&list_it)) != NUM_PUSH / 2) /* should be twice the seq # */
    stderr_pabort(__FILE__, __LINE__, "wrong value for seq num %u is %u! not %u\n", 
	   NUM_PUSH / 4, i, NUM_PUSH / 2);

  if (!stddll_multi_erase(&list_it, NUM_PUSH / 4 - NUM_END))
    stderr_pabort(__FILE__, __LINE__, "multi-erase of sequence range [NUM_PUSH/4, NUM_PUSH/2 - NUM_END)!");

  if (stddll_size(&list2) != NUM_PUSH/4 + NUM_END)
    stderr_pabort(__FILE__, __LINE__, "size is %u! not %u!\n", stddll_size(&list2), NUM_PUSH/4 + NUM_END);
  
  if (NUM_END)
    if ((i = *(size_t*) stddll_it_val(&list_it)) != NUM_PUSH - NUM_END * 2)
      stderr_pabort(__FILE__, __LINE__, "wrong value for seq num %u is %u! not %u\n", 
	     NUM_PUSH/2 - NUM_END, i, NUM_PUSH - NUM_END * 2);

  j = 20000;
  if (!stddll_repeat_insert(&list_it, &j, NUM_INSERT))
    stderr_pabort(__FILE__, __LINE__, "repeat insert failed");

  /* pop off the front of the list */
  if (stddll_multi_pop_front(&list2, NUM_PUSH/4))
    stderr_pabort(__FILE__, __LINE__, "multi_pop_front failed!");

  i = 0;
  for (stddll_begin(&list2, &list_it); !stddll_it_is_end(&list_it); stddll_it_next(&list_it), ++i) {
    if (i < NUM_INSERT) {
      if ((k = *(size_t*) stddll_it_val(&list_it)) != j)
	stderr_pabort(__FILE__, __LINE__, "position %u: value %u incorrect should be %u!", i, k, j);
    } else {
      if (i == 5)
	j = NUM_PUSH - NUM_END * 2;

      if ((k = *(size_t*) stddll_it_val(&list_it)) != j)
	stderr_pabort(__FILE__, __LINE__, "position %u: value %u incorrect should be %u!", i, k, j);

      j += 2;
    }
    /* printf("list[%u] = %u\n", i, k); */
  }
  if (i != stddll_size(&list2) || i != NUM_INSERT + NUM_END)
    stderr_pabort(__FILE__, __LINE__, "size %u! i %u! should be %u\n", stddll_size(&list2), i, NUM_INSERT + NUM_END);

  stddll_destruct(&list);
  stddll_destruct(&list2);

  printf("\nstddll_test run successful!\n\n");

  return 0;
}
