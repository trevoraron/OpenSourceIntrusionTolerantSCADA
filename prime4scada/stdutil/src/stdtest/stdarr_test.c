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
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdutil/stdarr.h>
#include <stdutil/stddll.h>
#include <stdutil/stderror.h>

/* This program runs a probabilistic test of the stdarr data
   structure. It picks a stdarr operation to perform randomly (see
   probabilities of operations below) and then performs the same
   operation on a stdarr and also on a stddll. A stddll has almost the
   exact same interface as a stdarr, but has been tested elsewhere and
   is considered to be correctly implemented. As different operations
   change the stdarr it is compared, occasionally, against the stddll
   to see that they are still exactly the same. The most obvious of
   these equality checks is performed in the TOTAL_CHECK_OP operation.  
*/

/* TODO: don't use rand() use stdrand32() and report what the seed
   was. This should help with reproducibility on different systems, where
   rand() may be implemented differently.
*/

/* uncomment and comment other line to turn debug printfs on or off */
/* # define DEBUG(x) x */
# define DEBUG(x)

/* parameters for running tests: 
     Num_ops - how many operations should be run
     Max_size - maximum size to which the sequences should grow
     Max_delta - maximum number of values added or removed in one operation
     Rand_seed - seed used for random number generator (see usage())
*/
static long Num_ops, Max_size, Max_delta, Rand_seed;

/* defaults for running test if command line parameters aren't passed */
#define DEFAULT_NUM_OPS   100000L
#define DEFAULT_MAX_SIZE   10000L
#define DEFAULT_MAX_DELTA   2000L
#define DEFAULT_RAND_SEED     -1L

/* global used for multi-inserts and repeat-inserts, Tmp_array is
   allocated to contain Max_delta values by usage(). Tmp_array[0] is
   used for repeat inserts (see handle_structural_op()). 
*/
static int *Tmp_array = 0;

/* types of basic operations to perform - also offset into base_ops_probs probability array */
typedef enum {
  STRUCTURAL_OP = 0, TOTAL_CHECK_OP, ITERATOR_OP, CONSTRUCT_OP, NUM_BASE_OPS
} base_op_type;

/* probabilites of basic operations being performed */
static float base_ops_probs[NUM_BASE_OPS] = { .7, .05, .248, .002 };
/* for debugging */
/* static float base_ops_probs[NUM_BASE_OPS] = { 1.0 }; */

/* pre-declarations of handler fcns for each of the base operations */
static void handle_structural_op(stdarr *arr, stdarr_it *arr_it, stddll *list, 
				 stddll_it *list_it, int *it_index, stdbool *it_good);

static void handle_total_op(const stdarr *arr, const stddll *list);

static void handle_iterator_op(stdarr *arr, stdarr_it *arr_it, stddll *list, 
			       stddll_it *list_it, int *it_index, stdbool *it_good);

static void handle_construct_op(stdarr *arr_dst, const stdarr *arr_src, stdarr_it *arr_it,
				stddll *list_dst, const stddll *list_src, stddll_it *list_it,
				int *it_index, stdbool *it_good);

/* types of structural operations to perform - also offset into structural_ops_probs probability array */
/* based on assumption that non-multi operations are performed by calling multi operations or vice-versa */
typedef enum { 
  MERASE = 0, MINSERT, RINSERT, MPUSH_FRONT, MPOP_FRONT, 
  MPUSH_BACK, MPOP_BACK, RESIZE, CLEAR, NUM_STRUCTURAL_OPS
} structural_op_type;

/* probabilites of structural ops being performed */
static float structural_ops_probs[NUM_STRUCTURAL_OPS] = { .3, .15, .15, .095, .095,
							  .063, .063, .064, .02 };

/* types of iterator operations to perform - also offset into iterator_ops_probs probability array */
typedef enum {
  IT_ADVANCE = 0, IT_RETREAT, IT_NEXT, IT_PREV, IT_BEGIN,
  IT_END, IT_LAST, IT_SEEK_BEGIN, IT_SEEK_END, NUM_ITERATOR_OPS
} iterator_op_type;

/* probabilites of iterator operations being performed */
static float iterator_ops_probs[NUM_ITERATOR_OPS] = { .3, .3, .175, .175, .01, .01, .01, .01, .01 };

/* types of construct operations to perform - also offset into construct_ops_probs probability array */
typedef enum {
  CONSTRUCT = 0, COPY_CONSTRUCT, NUM_CONSTRUCT_OPS
} construct_op_type;

/* probabilites of constructor operations being performed */
static float construct_ops_probs[NUM_CONSTRUCT_OPS] = { .5, .5 };

/* get_event - based on the probabilties in a probability array and the random number prob, this fcn 
      will return a number in the range [0, probs_size) signifying which event was chosen to occur
   probs_array - a float array of probs_size independent probabilites for events to occur 
      - the sum of probabilities of the first (probs_size - 1) events should sum to <= 1.0, if not exit() 
      - the probability of the last event in the array occurring is defined to be 1.0 - (sum of prev 
        events), meaning that the probability of the last event in the array is ignored 
   probs_size - positive integer (zero is illegal) of how many events can occur 
   prob - a uniform random float in range [0.0, 1.0] 
*/
static inline int get_event(float *probs_array, int probs_size, float prob) {
  float run_tot = 0.0;
  int i;

  if (probs_size <= 0)
    exit(fprintf(stderr, "get_event: probability array size must be a positive integer, probs_size: %d\n", 
		 probs_size));

  if (prob < 0.0 || prob > 1.0)
    exit(fprintf(stderr, "get_event: passed probability not in range [0.0, 1.0] was %f\n", prob));

  probs_size -= 1;
  for (i = 0; i < probs_size; ++i) {
    if ((run_tot += probs_array[i]) > 1.0)
      exit(fprintf(stderr, "get_event: illegal probability array!\n"
		   "\tSum of probs of first %d events greather than 1.0! Sum prob was %f\n", i, run_tot));

    if (run_tot >= prob)
      return i;
  }
  return i;
}

/* same as get_event except it generates a random number (rand()) for the event probability */
static inline int get_rand_event(float *probs_array, int probs_size) {
  return get_event(probs_array, probs_size, (float) rand() / RAND_MAX);
}

/* return a random base_op_type based off of probabilties in base_ops_probs */
static inline base_op_type get_rand_base_op() {
  return (base_op_type) get_rand_event(base_ops_probs, NUM_BASE_OPS);
}

/* return a random structural_op_type based off of probabilties in structural_ops_probs */
static inline structural_op_type get_rand_structural_op() { 
  return (structural_op_type) get_rand_event(structural_ops_probs, NUM_STRUCTURAL_OPS);
}

/* return a random iterator_op_type based off of probabilties in iterator_ops_probs */
static inline iterator_op_type get_rand_iterator_op() {
  return (iterator_op_type) get_rand_event(iterator_ops_probs, NUM_ITERATOR_OPS);
}

/* return a random construct_op_type based off of probabilties in construct_ops_probs */
static inline construct_op_type get_rand_construct_op() {
  return (construct_op_type) get_rand_event(construct_ops_probs, NUM_CONSTRUCT_OPS);
}

/* simply print how to run the program to stderr and then exit */
static void usage_and_exit(const char *exe) {
  exit(fprintf(stderr, 
	       "\nUsage: %s [NUM_OPS=%ld] [MAX_SIZE=%ld] [MAX_DELTA=%ld] [RAND_SEED=%ld]\n"
	       "\tTo set later parameters you must set all previous parameters.\n\n"
	       "\tNUM_OPS - how many random operations should be performed.\n"
	       "\tMAX_SIZE - the maximum number of values the sequences should ever contain.\n"
	       "\tMAX_DELTA - the maximum number of values ever inserted or deleted at once.\n"
	       "\tRAND_SEED - seed for random number generator; -1 means use time(0).\n\n", 
	       exe, DEFAULT_NUM_OPS, DEFAULT_MAX_SIZE, DEFAULT_MAX_DELTA, DEFAULT_RAND_SEED));
}

/* given the command line parameters, check the input for legality: if illegal, print 
   usage and exit; if legal, initialize the global running parameters (top of file) */
static void usage(int argc, char **argv) {
  char *convert;

  if (argc > 1) {
    Num_ops = strtol(argv[1], &convert, 0);
    if (errno == ERANGE || convert != argv[1] + strlen(argv[1])) {
      fprintf(stderr, "Error converting NUM_OPS: `%s' %s\n", argv[1],
	      errno == ERANGE ? strerror(errno) : "");
      usage_and_exit(argv[0]);
    }
  } else 
    Num_ops = DEFAULT_NUM_OPS;

  if (Num_ops < 0) {
    fprintf(stderr, "Illegal NUM_OPS: %ld < 0!\n", Num_ops);
    usage_and_exit(argv[0]);
  }

  if (argc > 2) {
    Max_size = strtol(argv[2], &convert, 0);
    if (errno == ERANGE || convert != argv[2] + strlen(argv[2])) {
      fprintf(stderr, "Error converting MAX_SIZE: `%s' %s\n", argv[2],
	      errno == ERANGE ? strerror(errno) : "");
      usage_and_exit(argv[0]);
    }
  } else
    Max_size = DEFAULT_MAX_SIZE;

  if (Max_size <= 0) {
    fprintf(stderr, "Illegal MAX_SIZE: %ld <= 0!\n", Max_size);
    usage_and_exit(argv[0]);
  }

  if (argc > 3) {
    Max_delta = strtol(argv[3], &convert, 0);
    if (errno == ERANGE || convert != argv[3] + strlen(argv[3])) {
      fprintf(stderr, "Error converting MAX_DELTA: `%s' %s\n", argv[3], 
	      errno == ERANGE ? strerror(errno) : "");
      usage_and_exit(argv[0]);
    }
  } else
    Max_delta = DEFAULT_MAX_DELTA;

  if (Max_delta <= 0) {
    fprintf(stderr, "Illegal MAX_DELTA: %ld <= 0!\n", Max_delta);
    usage_and_exit(argv[0]);
  }

  if (!(Tmp_array = (int*) malloc(Max_delta * sizeof(int))))
    stderr_pabort(__FILE__, __LINE__, "couldn't malloc(%d) Tmp_array!\n", Max_delta * sizeof(int));

  if (argc > 4) {
    Rand_seed = strtol(argv[4], &convert, 0);
    if (convert != argv[4] + strlen(argv[4])) {
      fprintf(stderr, "Error converting RAND_SEED: `%s'\n", argv[4]);
      usage_and_exit(argv[0]);
    }
  } else
    Rand_seed = DEFAULT_RAND_SEED;

  /* seed random number generator: convert to unsigned int which srand() takes */
  if (Rand_seed != -1)
    srand((Rand_seed = (unsigned int) Rand_seed));
  else
    srand((Rand_seed = (unsigned int) time(0)));

  if (argc > 5)
    fprintf(stderr, "WARNING: all parameters beyond the fourth were ignored!");
}

int main(int argc, char **argv) {
  stdarr arr1, arr2, *arr;
  stdarr_it arr_it1, arr_it2, *arr_it;

  stddll list1, list2, *list;
  stddll_it list_it1, list_it2, *list_it;
  
  int it1_index, it2_index, *it_index;
  stdbool it1_good, it2_good, *it_good;

  int i, tmp, twentieth_num_ops;

  /* initialize globals from command line parameters */
  usage(argc, argv); 
  twentieth_num_ops = Num_ops / 20; /* used for printing progress notifications */

  /* initialize data structures and iterators */
  if (stdarr_construct(&arr1, sizeof(int)) ||
      stdarr_construct(&arr2, sizeof(int)) ||
      stddll_construct(&list1, sizeof(int)) ||
      stddll_construct(&list2, sizeof(int)))
    stderr_pabort(__FILE__, __LINE__, "constructor failure!");

  stdarr_begin(&arr1, &arr_it1);
  stdarr_begin(&arr2, &arr_it2);
  stddll_begin(&list1, &list_it1);
  stddll_begin(&list2, &list_it2);
  it1_good = it2_good = stdtrue;
  it1_index = it2_index = 0;

  printf("Begining run: Num_ops: %ld, Max_size: %ld, Max_delta: %ld, Rand_seed: %ld\n\n",
	 Num_ops, Max_size, Max_delta, Rand_seed);

  /* perform Num_ops random operations on the two sets of sequences */
  for (i = 1; i <= Num_ops; ++i) {
    if ((float) rand() / RAND_MAX <= .5) { /* choose to work with arr1 or arr2 */
      arr      = &arr1;
      arr_it   = &arr_it1;
      list     = &list1;
      list_it  = &list_it1;
      it_index = &it1_index;
      it_good  = &it1_good;
    } else {
      arr      = &arr2;
      arr_it   = &arr_it2;
      list     = &list2;
      list_it  = &list_it2;
      it_index = &it2_index;
      it_good  = &it2_good;
    }

    /* choose a basic operation at random to perform */
    switch ((tmp = get_rand_base_op())) {
      case STRUCTURAL_OP:
	DEBUG(printf("executing STRUCTURAL_OP\n"));
	handle_structural_op(arr, arr_it, list, list_it, it_index, it_good);
	break;
      case TOTAL_CHECK_OP:
 	DEBUG(printf("executing TOTAL_CHECK_OP 1\n"));
	handle_total_op(arr, list);
	break;
      case ITERATOR_OP:
	DEBUG(printf("executing ITERATOR_OP\n"));
	handle_iterator_op(arr, arr_it, list, list_it, it_index, it_good);
	break;
      case CONSTRUCT_OP:
	DEBUG(printf("executing CONSTRUCT_OP\n"));
	if (arr == &arr1)
	  handle_construct_op(arr, &arr2, arr_it, list, &list2, list_it, it_index, it_good);
	else 
	  handle_construct_op(arr, &arr1, arr_it, list, &list1, list_it, it_index, it_good);
	break;
      default: 
	stderr_pabort(__FILE__, __LINE__, "base op switch failed, returned %d, unknown op\n", tmp);
	break;
    }
    DEBUG(printf("executing TOTAL_CHECK_OP 2\n"));
    DEBUG(handle_total_op(carr, list));
    /* print progress notification */
    if (i % twentieth_num_ops == 0)
      printf("Run %.1f%% complete...\n", (float) i / Num_ops * 100);
  }

  /* free all resources (memory) */
  stdarr_destruct(&arr1);
  stdarr_destruct(&arr2);
  stddll_destruct(&list1);
  stddll_destruct(&list2);

  if (Tmp_array != 0)
    free(Tmp_array);

  printf("\nstdarr_test run successful!\n\n");

  return 0;
}

/* this fcn chooses a structural operation at random (based on the structural ops probabilities)
   and performs it on the passed sequences */
static void handle_structural_op(stdarr *arr, stdarr_it *arr_it, stddll *list, 
				 stddll_it *list_it, int *it_index, stdbool *it_good) {
  int tmp, i;

  switch ((tmp = get_rand_structural_op())) {
    case MERASE: 
      if (!*it_good) { /* if iterator is no good, pick a random position */
	*it_index = rand() % (stddll_size(list) + 1);
	DEBUG(printf("%p: it wasn't good: %d, choose new index of %d, it_good: %d\n", 
		     arr, *it_good, *it_index, stdtrue));
	*it_good  = stdtrue;
	stddll_get(list, list_it, *it_index);
	stdarr_get(arr, arr_it, *it_index);
      }
      tmp = rand() % (Max_delta + 1);                   /* pick how many to erase */
      tmp = STDMIN(tmp, stddll_size(list) - *it_index); /* limit the size of the erase */

      DEBUG(printf("%p: executing multi-erase at index %d of size %d, old_size %d\n", 
		   arr, *it_index, tmp, stddll_size(list)));

      if (!stddll_multi_erase(list_it, tmp))
	stderr_pabort(__FILE__, __LINE__, "list multi-erase failure!");

      if (!stdarr_multi_erase(arr_it, tmp))
	stderr_pabort(__FILE__, __LINE__, "array multi-erase failure!");
      break;
 
    case MINSERT:
      if (!*it_good) { /* if iterator is no good, pick a random position */
	*it_index = rand() % (stddll_size(list) + 1);
	DEBUG(printf("%p: it wasn't good: %d, choose new index of %d, it_good: %d\n", 
		     arr, *it_good, *it_index, stdtrue));
	*it_good  = stdtrue;
	stddll_get(list, list_it, *it_index);
	stdarr_get(arr, arr_it, *it_index);
      }
      tmp = rand() % (Max_delta + 1);         /* pick how many to insert */
      if (stddll_size(list) + tmp > Max_size) /* limit the size of the insert */
	tmp = Max_size - stddll_size(list);

      for (i = 0; i < tmp; ++i)               /* use random data to insert */
	Tmp_array[i] = rand();

      DEBUG(printf("%p: executing multi-insert at index %d of size %d, old_size %d\n", 
		   arr, *it_index, tmp, stddll_size(list)));

      if (!stddll_multi_insert(list_it, Tmp_array, tmp))
	stderr_pabort(__FILE__, __LINE__, "list multi-insert failure!");

      if (!stdarr_multi_insert(arr_it, Tmp_array, tmp))
	stderr_pabort(__FILE__, __LINE__, "array multi-insert failure!");
      break; 

    case RINSERT:
      if (!*it_good) { /* if iterator is no good, pick a random position */
	*it_index = rand() % (stddll_size(list) + 1);
	DEBUG(printf("%p: it wasn't good: %d, choose new index of %d, it_good: %d\n", 
		     arr, *it_good, *it_index, stdtrue));
	*it_good  = stdtrue;
	stddll_get(list, list_it, *it_index);
	stdarr_get(arr, arr_it, *it_index);
      }
      tmp = rand() % (Max_delta + 1);         /* pick how many to insert */
      if (stddll_size(list) + tmp > Max_size) /* limit the size of the insert */
	tmp = Max_size - stddll_size(list);

      Tmp_array[0] = rand();                  /* use random data to insert */

      DEBUG(printf("%p: executing repeat_insert at index %d of size %d, old_size %d\n", 
		   arr, *it_index, tmp, stddll_size(list)));

      if (!stddll_repeat_insert(list_it, Tmp_array, tmp))
	stderr_pabort(__FILE__, __LINE__, "list multi-insert failure!");

      if (!stdarr_repeat_insert(arr_it, Tmp_array, tmp))
	stderr_pabort(__FILE__, __LINE__, "array multi-insert failure!");
      break; 

    case MPUSH_FRONT: 
      /* structural operations usually only _guarantee_ iterators' validness after the 
	 operation if the iterator is used (i.e. - passed to the fcn) in that operation */
      *it_index = -1;       
      *it_good  = stdfalse;

      tmp = rand() % (Max_delta + 1);         /* pick how many to insert */
      if (stddll_size(list) + tmp > Max_size) /* limit the size of the push */
	tmp = Max_size - stddll_size(list);

      for (i = 0; i < tmp; ++i)               /* use random data to push */
	Tmp_array[i] = rand();

      DEBUG(printf("%p: executing multi-push front of size %d, old_size %d\n", 
		   arr, tmp, stddll_size(list)));

      if (stddll_multi_push_front(list, Tmp_array, tmp))
	stderr_pabort(__FILE__, __LINE__, "list multi-push front failure!");

      /* stdarr doesn't have a push front, so we simulate by inserting at begin */
      stdarr_begin(arr, arr_it);
      if (!stdarr_multi_insert(arr_it, Tmp_array, tmp))
	stderr_pabort(__FILE__, __LINE__, "array multi-\"push front\" failure!");
      break; 

    case MPOP_FRONT:
      /* structural operations usually only _guarantee_ iterators' validness after the 
	 operation if the iterator is used (i.e. - passed to the fcn) in that operation */
      *it_index = -1;
      *it_good  = stdfalse;

      tmp = rand() % (Max_delta + 1);         /* pick how many to pop */
      tmp = STDMIN(tmp, stddll_size(list));   /* limit the size of the pop */

      DEBUG(printf("%p: executing multi-pop front of size %d, old_size %d\n", 
		   arr, tmp, stddll_size(list)));

      if (stddll_multi_pop_front(list, tmp))
	stderr_pabort(__FILE__, __LINE__, "list multi-pop front failure!");

      /* stdarr doesn't have a pop front, so we simulate by erasing at begin */
      stdarr_begin(arr, arr_it);
      if (!stdarr_multi_erase(arr_it, tmp))
	stderr_pabort(__FILE__, __LINE__, "array multi-\"pop front\" failure!");
      break; 

    case MPUSH_BACK: 
      /* structural operations usually only _guarantee_ iterators' validness after the 
	 operation if the iterator is used (i.e. - passed to the fcn) in that operation */
      *it_index = -1;
      *it_good  = stdfalse;

      tmp = rand() % (Max_delta + 1);         /* pick how many to push */
      if (stddll_size(list) + tmp > Max_size) /* limit the size of the push */
	tmp = Max_size - stddll_size(list);

      for (i = 0; i < tmp; ++i)               /* use random data to push */
	Tmp_array[i] = rand();

      DEBUG(printf("%p: executing multi-push back of size %d, old_size %d\n", 
		   arr, tmp, stddll_size(list)));

      if (stddll_multi_push_back(list, Tmp_array, tmp))
	stderr_pabort(__FILE__, __LINE__, "list multi-push back failure!");

      if (stdarr_multi_push_back(arr, Tmp_array, tmp))
	stderr_pabort(__FILE__, __LINE__, "array multi-push back failure!");
      break;

    case MPOP_BACK: 
      /* structural operations usually only _guarantee_ iterators' validness after the 
	 operation if the iterator is used (i.e. - passed to the fcn) in that operation */
      *it_index = -1;
      *it_good  = stdfalse;

      tmp = rand() % (Max_delta + 1);         /* pick how many to pop */
      tmp = STDMIN(tmp, stddll_size(list));   /* limit the size of the pop */

      DEBUG(printf("%p: executing multi-pop back of size %d: old_size %d\n", 
		   arr, tmp, stddll_size(list)));

      if (stddll_multi_pop_back(list, tmp))
	stderr_pabort(__FILE__, __LINE__, "list multi-pop back failure!");

      if (stdarr_multi_pop_back(arr, tmp))
	stderr_pabort(__FILE__, __LINE__, "array multi-pop back failure!");
      break;

    case RESIZE: 
      /* structural operations usually only _guarantee_ iterators' validness after the 
	 operation if the iterator is used (i.e. - passed to the fcn) in that operation */
      *it_index = -1;
      *it_good  = stdfalse;

      /* pick randomly uniformly in range [-Max_delta, Max_delta] */
      tmp = 2 * (rand() % (Max_delta + 1)) - Max_delta; /* pick a delta in size */

      if (tmp >= 0) { /* tmp is non-negative -> grow or stay the same */
	int delta = tmp;                                  /* how many elements are being added? */

	/* set tmp to reflect absolute size of sequence after growth */
	if ((tmp = stddll_size(list) + tmp) > Max_size) { /* if growth is too big, set to max */
	  tmp = Max_size;
	  delta = Max_size - stddll_size(list); 
	}

	DEBUG(printf("%p: executing grow resize %d -> %d\n", 
		     arr, stddll_size(list), tmp));

	if (stddll_resize(list, tmp))
	  stderr_pabort(__FILE__, __LINE__, "list grow resize(%d -> %d) failure!", 
			stddll_size(list), tmp);

	if (stdarr_resize(arr, tmp))
	  stderr_pabort(__FILE__, __LINE__, "array grow resize(%d -> %d) failure!", 
			stdarr_size(arr), tmp);

	/* not done yet: need to fill in uninited values appended (if any)
	   to end so that arr and list match in the values they contain */
	if (delta > 0) {
	  stddll_end(list, list_it); /* start from last value setting uninited values */
	  stdarr_end(arr, arr_it);   /* moving backwards */

	  for (i = 0; i < delta; ++i) {
	    tmp = rand();                         /* use random data */
	    stddll_it_prev(list_it); 
	    stdarr_it_prev(arr_it);
	    *(int*) stddll_it_val(list_it) = tmp; /* set both to use random data */
	    *(int*) stdarr_it_val(arr_it) = tmp;
	  }
	}
      } else { /* tmp is negative -> shrink */
	/* set tmp to reflect absolute size of sequence after shrinking */
	if ((tmp = stddll_size(list) + tmp) < 0) /* if shrink is too big set to zero */
	  tmp = 0;

	DEBUG(printf("%p: executing shrink resize %d -> %d\n", 
		     arr, stddll_size(list), tmp));

	if (stddll_resize(list, tmp))
	  stderr_pabort(__FILE__, __LINE__, "list shrink resize(%d -> %d) failure!", 
			stddll_size(list), tmp);

	if (stdarr_resize(arr, tmp))
	  stderr_pabort(__FILE__, __LINE__, "array shrink resize(%d -> %d) failure!", 
			stdarr_size(arr), tmp);
      }
      break; 

    case CLEAR:
      /* structural operations usually only _guarantee_ iterators' validness after the 
	 operation if the iterator is used (i.e. - passed to the fcn) in that operation */
      *it_index = -1;
      *it_good  = stdfalse;

      DEBUG(printf("%p: executing clear, old_size %d\n", arr, stddll_size(list)));
	
      if (stddll_clear(list))
	stderr_pabort(__FILE__, __LINE__, "list clear failure!");

      if (stdarr_clear(arr))
	stderr_pabort(__FILE__, __LINE__, "array clear failure!");
      break;

    default:
      stderr_pabort(__FILE__, __LINE__, "structural op switch failed, returned %d, unknown op\n", tmp); 
      break;
  }
}

/* do a check from begin to end to see that the contained sequences match exactly */
static void handle_total_op(const stdarr *arr, const stddll *list) { 
  stdarr_it ait, *aitp = &ait;
  stddll_it lit, *litp = &lit;
  int i;

  if (stdarr_size(arr) != stddll_size(list) || stdarr_empty(arr) != stddll_empty(list))
    stderr_pabort(__FILE__, __LINE__, "size() or empty() disagreed!\n");

  stdarr_begin(arr, aitp);
  stddll_begin(list, litp);

  for (i = 0; !stddll_it_is_end(litp); stdarr_it_next(aitp), stddll_it_next(litp), ++i) {
    if (*(int*) stddll_it_val(litp) != *(int*) stdarr_it_val(aitp))
      stderr_pabort(__FILE__, __LINE__, "array and list differed at index %d: list(%d) != array(%d)!\n",
		    i, *(int*) stddll_it_val(litp), *(int*) stdarr_it_val(aitp));
  }
  if (!stdarr_it_is_end(aitp))
    stderr_pabort(__FILE__, __LINE__, "array wasn't at end and list was!\n");
}

static void handle_iterator_op(stdarr *arr, stdarr_it *arr_it, stddll *list, 
			       stddll_it *list_it, int *it_index, stdbool *it_good) {
  int tmp = get_rand_iterator_op();
  
  /* if iterator is no good and doing a relative offset, then choose an iterator at random */
  if (!*it_good && (tmp == IT_ADVANCE || tmp == IT_RETREAT || tmp == IT_PREV || tmp == IT_NEXT)) {
    *it_index = rand() % (stddll_size(list) + 1);
    *it_good  = stdtrue;
    stddll_get(list, list_it, *it_index);
    stdarr_get(arr, arr_it, *it_index);
  }

  switch (tmp) {
    case IT_ADVANCE:
      tmp = rand() % (Max_delta + 1);          /* pick random # to advance */
      if (*it_index + tmp > stddll_size(list)) /* limit advance to end */
	tmp = stddll_size(list) - *it_index;

      stddll_it_advance(list_it, tmp);
      stdarr_it_advance(arr_it, tmp);

      *it_index += tmp;
      break; 

    case IT_RETREAT: 
      tmp = rand() % (Max_delta + 1);          /* pick random # to retreat */
      if (tmp > *it_index)                     /* limit retreat to begin */
	tmp = *it_index;

      stddll_it_retreat(list_it, tmp);
      stdarr_it_retreat(arr_it, tmp);

      *it_index -= tmp;
      break; 

    case IT_NEXT:
      if (!stddll_it_is_end(list_it)) {        /* don't do op if at end */
	stddll_it_next(list_it);
	stdarr_it_next(arr_it);
	*it_index += 1;
      }
      break; 

    case IT_PREV:
      if (!stddll_it_is_begin(list_it)) {      /* don't do op if at begin */
	stddll_it_prev(list_it);
	stdarr_it_prev(arr_it);
	*it_index -= 1;
      }
      break; 

    case IT_BEGIN: 
      stddll_begin(list, list_it);
      stdarr_begin(arr, arr_it);
      *it_index = 0;
      break; 

    case IT_LAST: 
      if (!stddll_empty(list)) {               /* if there are values contained */
	stddll_last(list, list_it);
	stdarr_last(arr, arr_it);
	*it_index = stddll_size(list) - 1;
	break; 
      } 
      /* else fall through to case END:!!!! */

    case IT_END:
      stddll_end(list, list_it);
      stdarr_end(arr, arr_it);
      *it_index = stddll_size(list);
      break; 

    case IT_SEEK_BEGIN: 
      stddll_it_seek_begin(list_it);
      stdarr_it_seek_begin(arr_it);
      *it_index = 0;
      break; 

    case IT_SEEK_END: 
      stddll_it_seek_end(list_it);
      stdarr_it_seek_end(arr_it);
      *it_index = stddll_size(list);
      break;

    default:
      stderr_pabort(__FILE__, __LINE__, "iterator op switch failed, returned %d, unknown op\n", tmp); 
      break;
  }
  *it_good = stdtrue;

  /* check that list and arr agree on that position's value (if it isn't end) */
  if (!stddll_it_is_end(list_it) &&
      *(int*) stddll_it_val(list_it) != *(int*) stdarr_it_val(arr_it))
    stderr_pabort(__FILE__, __LINE__, "array and list differed at index %d: list(%d) != array(%d)!\n",
		  *it_index, *(int*) stddll_it_val(list_it), *(int*) stdarr_it_val(arr_it));
}

static void handle_construct_op(stdarr *arr_dst, const stdarr *arr_src, stdarr_it *arr_it,
				stddll *list_dst, const stddll *list_src, stddll_it *list_it,
				int *it_index, stdbool *it_good) {
  int tmp;

  *it_index = -1;
  *it_good  = stdfalse;

  stddll_destruct(list_dst);
  stdarr_destruct(arr_dst);

  switch ((tmp = get_rand_construct_op())) {
    case CONSTRUCT:
      if (stddll_construct(list_dst, sizeof(int)))
	stderr_pabort(__FILE__, __LINE__, "list construct failed!");

      if (stdarr_construct(arr_dst, sizeof(int)))
	stderr_pabort(__FILE__, __LINE__, "array construct failed!");
      break;

    case COPY_CONSTRUCT:
      if (stddll_copy_construct(list_dst, list_src))
	stderr_pabort(__FILE__, __LINE__, "list copy construct failed!");

      if (stdarr_copy_construct(arr_dst, arr_src))
	stderr_pabort(__FILE__, __LINE__, "array copy construct failed!");
      break;

    default:
      stderr_pabort(__FILE__, __LINE__, "construct op switch failed, returned %d, unknown op\n", tmp);   
      break;
  }
}
