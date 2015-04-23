#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <map>
#include <string>
#include <iterator>

using namespace std;

#include <stdutil/stderror.h>
#include <stdutil/stdutil.h>
#include <stdutil/stdskl.h>

#define MY_STR_MAX_CHARS 15

typedef struct 
{
  char str[MY_STR_MAX_CHARS + 1];

} my_str;

typedef map<string, long> map_type;
typedef multimap<string, long> multi_type;

map_type map_test, map_base;
stdskl sklmap_test, sklmap_base;

multi_type multi_test, multi_base;
stdskl sklmulti_test, sklmulti_base;

/************************************************************************************************
 ***********************************************************************************************/

size_t my_read_line(char * buf, size_t buf_size, FILE * stream)
{
  size_t ret = 0;
  size_t slen;

  /* read in a line */

  if (fgets(buf, buf_size, stream) == NULL) {
    goto my_read_line_end;
  }

  slen = strlen(buf);
  assert(slen > 0);

  /* remove any trailing end-of-line sequence */

  if (buf[slen - 1] == '\n') {
    buf[--slen] = '\0';

    if (slen == 0) {
      goto my_read_line_end;
    }

    if (buf[slen - 1] == '\r') {
      buf[--slen] = '\0';
    }

    if (slen == 0) {
      goto my_read_line_end;
    }
  }

  ret = slen;

 my_read_line_end:
  return ret;
}

/************************************************************************************************
 ***********************************************************************************************/

void full_map_check(stdskl &skl, map_type &m)
{
  map_type::iterator  map_it;
  stdit               it;
  const char *        prev;
  stdsize             i;

  /* check that skl and m match forwards */

  stdskl_begin(&skl, &it);
  map_it = m.begin();
  prev   = NULL;

  for (i = 0; map_it != m.end() && !stdskl_is_end(&skl, &it); ++map_it, stdskl_it_next(&it), ++i) {

    if (strcmp(map_it->first.c_str(), (char*) stdskl_it_key(&it)) != 0) {
      fprintf(stdout, "key mistmatch!\r\n");
      abort();
    }

    if (map_it->second != *(long*) stdskl_it_val(&it)) {
      fprintf(stdout, "val mismatch!\r\n");
      abort();
    }

    if (prev != NULL && strcmp(prev, (char*) stdskl_it_key(&it)) >= 0) {
      fprintf(stdout, "order incorrect!\r\n");
      abort();
    }		 

    //fprintf(stdout, "%s\n", (char*) stdskl_it_key(&it), *(long*) stdskl_it_val(&it));

    prev = (char*) stdskl_it_key(&it);
  } 

  if (map_it != m.end() || !stdskl_is_end(&skl, &it) || i != m.size() || i != stdskl_size(&skl)) {      
    fprintf(stdout, "iterator mismatch!\r\n");
    abort();
  }

  /* check that skl and m match backwards */

  stdskl_end(&skl, &it);
  map_it = m.end();
  prev   = NULL;

  for (i = 0; map_it != m.begin() && !stdskl_is_begin(&skl, &it); ++i) {
    --map_it;
    stdskl_it_prev(&it);

    if (strcmp(map_it->first.c_str(), (char*) stdskl_it_key(&it)) != 0) {
      fprintf(stdout, "key mistmatch!\r\n");
      abort();
    }

    if (map_it->second != *(long*) stdskl_it_val(&it)) {
      fprintf(stdout, "val mismatch!\r\n");
      abort();
    }

    if (prev != NULL && strcmp(prev, (char*) stdskl_it_key(&it)) <= 0) {
      fprintf(stdout, "order incorrect!\r\n");
      abort();
    }		 

    //fprintf(stdout, "%s\n", (char*) stdskl_it_key(&it), *(long*) stdskl_it_val(&it));

    prev = (char*) stdskl_it_key(&it);
  } 

  if (map_it != m.begin() || !stdskl_is_begin(&skl, &it) || i != m.size() || i != stdskl_size(&skl)) {      
    fprintf(stdout, "iterator mismatch!\r\n");
    abort();
  }
}

/************************************************************************************************
 ***********************************************************************************************/

void full_multi_check(stdskl &skl, multi_type &m)
{
  multi_type::iterator multi_it;
  stdit                it;
  const char *         prev;
  stdsize              i;

  /* check that m and skl match forwards */

  stdskl_begin(&skl, &it);
  multi_it = m.begin();
  prev     = NULL;

  for (i = 0; multi_it != m.end() && !stdskl_is_end(&skl, &it); ++multi_it, stdskl_it_next(&it), ++i) {

    if (strcmp(multi_it->first.c_str(), (char*) stdskl_it_key(&it)) != 0) {
      fprintf(stdout, "key mistmatch!\r\n");
      abort();
    }

    if (multi_it->second != *(long*) stdskl_it_val(&it)) {
      fprintf(stdout, "val mismatch!\r\n");
      abort();
    }

    if (prev != NULL && strcmp(prev, (char*) stdskl_it_key(&it)) > 0) {
      fprintf(stdout, "order incorrect!\r\n");
      abort();
    }		 

    //fprintf(stdout, "%s\n", (char*) stdskl_it_key(&it), *(long*) stdskl_it_val(&it));

    prev = (char*) stdskl_it_key(&it);
  } 

  if (multi_it != m.end() || !stdskl_is_end(&skl, &it) || i != m.size() || i != stdskl_size(&skl)) {      
    fprintf(stdout, "iterator mismatch!\r\n");
    abort();
  }

  /* check that m and skl match backwards */

  stdskl_end(&skl, &it);
  multi_it = m.end();
  prev     = NULL;

  for (i = 0; multi_it != m.begin() && !stdskl_is_begin(&skl, &it); ++i) {
    --multi_it;
    stdskl_it_prev(&it);

    if (strcmp(multi_it->first.c_str(), (char*) stdskl_it_key(&it)) != 0) {
      fprintf(stdout, "key mistmatch!\r\n");
      abort();
    }

    if (multi_it->second != *(long*) stdskl_it_val(&it)) {
      fprintf(stdout, "val mismatch!\r\n");
      abort();
    }

    if (prev != NULL && strcmp(prev, (char*) stdskl_it_key(&it)) < 0) {
      fprintf(stdout, "order incorrect!\r\n");
      abort();
    }		 

    //fprintf(stdout, "%s\n", (char*) stdskl_it_key(&it), *(long*) stdskl_it_val(&it));

    prev = (char*) stdskl_it_key(&it);
  } 

  if (multi_it != m.begin() || !stdskl_is_begin(&skl, &it) || i != m.size() || i != stdskl_size(&skl)) {      
    fprintf(stdout, "iterator mismatch!\r\n");
    abort();
  }
}

/************************************************************************************************
 ***********************************************************************************************/

int main(int argc, char **argv)
{
  stdcode              ret = STDESUCCESS;
  char                 buf[1024];
  size_t               slen;
  long                 num_lines;
  map_type::iterator   map_it;
  multi_type::iterator multi_it;
  stdit                it;
  stdsize              i;

  srand(0);

  try {
    if ((ret = stdskl_construct(&sklmap_test, sizeof(my_str), sizeof(long), NULL)) != STDESUCCESS) {
      goto main_end0;
    }
  } catch (...) {
    goto main_end0;
  }

  try {
    if ((ret = stdskl_construct(&sklmulti_test, sizeof(my_str), sizeof(long), NULL)) != STDESUCCESS) {
      goto main_end1;
    }
  } catch (...) {
    goto main_end1;
  }
  
  try {
    /* read in stdin line by line and insert into maps */

    for (num_lines = 0; (slen = my_read_line(buf, sizeof(buf), stdin)) != 0;) {
      my_str s = { { 0 } };  /* NOTE: ensure zeroed out so that memcmp will work properly */

      if (slen > MY_STR_MAX_CHARS) {
	continue;
      }
    
      strcpy(s.str, buf);

      /* insert into maps */

      map_test[buf] = num_lines;

      if ((ret = stdskl_put(&sklmap_test, &it, &s, &num_lines, STDFALSE)) != STDESUCCESS) {
	goto main_end2;
      }

      /* insert into multi-maps */

      multi_test.insert(multi_test.upper_bound(buf), pair<string, long>(buf, num_lines));

      if ((ret = stdskl_insert(&sklmulti_test, stdskl_upperb(&sklmulti_test, &it, &s), &s, &num_lines, STDTRUE)) != STDESUCCESS) {
	goto main_end2;
      }

      ++num_lines;
    }

    fprintf(stdout, "map_test size %lu; sklmap_test size %lu, multi_test size %lu; sklmulti_test size %lu\r\n",
            map_test.size(), stdskl_size(&sklmap_test), multi_test.size(), stdskl_size(&sklmulti_test));

    full_map_check(sklmap_test, map_test);
    full_multi_check(sklmulti_test, multi_test);

    /* make copies and check that they worked */

    map_base   = map_test;
    multi_base = multi_test;

    if ((ret = stdskl_copy_construct(&sklmap_base, &sklmap_test)) != STDESUCCESS) {
      goto main_end2;
    }

  } catch (...) {
    goto main_end2;
  }

  try {

    if ((ret = stdskl_copy_construct(&sklmulti_base, &sklmulti_test)) != STDESUCCESS) {
      goto main_end3;
    }

  } catch (...) {
    goto main_end3;
  }

  try {
    full_map_check(sklmap_base, map_base);
    full_multi_check(sklmulti_base, multi_base);

    /* perform some random deletes (this idiom has horrible performance btw) */

    for (i = 0; !map_test.empty(); ++i) {
      int r = rand() % STDMIN(1000, map_test.size());

      map_it = map_test.begin();
      advance(map_it, r);
      map_test.erase(map_it);

      stdskl_erase(&sklmap_test, stdskl_get(&sklmap_test, &it, r));

      multi_it = multi_test.begin();
      advance(multi_it, r);
      multi_test.erase(multi_it);

      stdskl_erase(&sklmulti_test, stdskl_get(&sklmulti_test, &it, r));
    }

    fprintf(stdout, "map_test size %lu; sklmap_test size %lu, multi_test size %lu; sklmulti_test size %lu\r\n",
            map_test.size(), stdskl_size(&sklmap_test), multi_test.size(), stdskl_size(&sklmulti_test));

    full_map_check(sklmap_test, map_test);
    full_multi_check(sklmulti_test, multi_test);

    /* test setting one map equal to another */

    map_test   = map_base;
    multi_test = multi_base;

    if ((ret = stdskl_set_eq(&sklmap_test, &sklmap_base)) != STDESUCCESS) {
      goto main_end4;
    }

    if ((ret = stdskl_set_eq(&sklmulti_test, &sklmulti_base)) != STDESUCCESS) {
      goto main_end4;
    }

    fprintf(stdout, "map_test size %lu; sklmap_test size %lu, multi_test size %lu; sklmulti_test size %lu\r\n",
            map_test.size(), stdskl_size(&sklmap_test), multi_test.size(), stdskl_size(&sklmulti_test));

    full_map_check(sklmap_test, map_test);
    full_multi_check(sklmulti_test, multi_test);

    fprintf(stdout, "Success!\r\n");
    fflush(stdout);

  } catch (...) {
    goto main_end4;
  }

 main_end4:
  stdskl_destruct(&sklmulti_base);

 main_end3:
  stdskl_destruct(&sklmap_base);

 main_end2:
  stdskl_destruct(&sklmulti_test);

 main_end1:
  stdskl_destruct(&sklmap_test);

 main_end0:
  if (ret != 0) {
    stderr_abort("something failed with error code %d: %s\r\n", ret, stderr_strerr(ret));
  }

  return ret;
}
