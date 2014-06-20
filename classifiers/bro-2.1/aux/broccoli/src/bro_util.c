/*
       B R O C C O L I  --  The Bro Client Communications Library

Copyright (C) 2004-2008 Christian Kreibich <christian (at) icir.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>

#ifdef __EMX__
#include <strings.h>
#endif

#include <bro_util.h>

#ifdef __MINGW32__

/* MinGW does not define a gettimeofday so we need to roll our own.
 * This one is largely following
 * http://lists.gnu.org/archive/html/bug-gnu-chess/2004-01/msg00020.html
 */

static int
gettimeofday(struct timeval* p, void* tz /* IGNORED */){
  union {
    long long ns100; /*time since 1 Jan 1601 in 100ns units */
    FILETIME ft;
  } _now;

  GetSystemTimeAsFileTime( &(_now.ft) );
  p->tv_usec=(long)((_now.ns100 / 10LL) % 1000000LL );
  p->tv_sec= (long)((_now.ns100-(116444736000000000LL))/10000000LL);
  return 0;
}
#endif


int
__bro_util_snprintf(char *str, size_t size, const char *format, ...)
{
  int result;
  va_list al;
  va_start(al, format);
  result = vsnprintf(str, size, format, al);
  va_end(al);
  str[size-1] = '\0';

  return result;
}

void
__bro_util_fill_v4_addr(BroAddr *a, uint32 addr)
{
  if ( ! a )
    return;

  memcpy(a->addr, BRO_IPV4_MAPPED_PREFIX, sizeof(BRO_IPV4_MAPPED_PREFIX));
  a->addr[3] = addr;
}

void
__bro_util_fill_subnet(BroSubnet *sn, uint32 net, uint32 width)
{
  if (! sn)
    return;

  __bro_util_fill_v4_addr(&sn->sn_net, net);
  sn->sn_width = width;
}


double
__bro_util_get_time(void)
{
  struct timeval tv;

  if (gettimeofday(&tv, 0) < 0)
    return 0.0;

  return __bro_util_timeval_to_double(&tv);
}


double
__bro_util_timeval_to_double(const struct timeval *tv)
{
  if (! tv)
    return 0.0;

  return ((double) tv->tv_sec) + ((double) tv->tv_usec) / 1000000;
}


int
__bro_util_is_v4_addr(const BroAddr *a)
{
  return memcmp(a->addr, BRO_IPV4_MAPPED_PREFIX,
                sizeof(BRO_IPV4_MAPPED_PREFIX)) == 0;
}

#ifndef WORDS_BIGENDIAN
double
__bro_util_htond(double d)
{
  /* Should work as long as doubles have an even length */
  int i, dsize;
  double tmp;
  char* src = (char*) &d;
  char* dst = (char*) &tmp;

  dsize = sizeof(d) - 1;

  for (i = 0; i <= dsize; i++)
    dst[i] = src[dsize - i];

  return tmp;
}

double
__bro_util_ntohd(double d)
{
  return __bro_util_htond(d);
}

uint64
__bro_util_htonll(uint64 i)
{
  uchar c;
  union {
    uint64 i;
    uchar c[8];
  } x;

  x.i = i;
  c = x.c[0]; x.c[0] = x.c[7]; x.c[7] = c;
  c = x.c[1]; x.c[1] = x.c[6]; x.c[6] = c;
  c = x.c[2]; x.c[2] = x.c[5]; x.c[5] = c;
  c = x.c[3]; x.c[3] = x.c[4]; x.c[4] = c;
  return x.i;
}

uint64
__bro_util_ntohll(uint64 i)
{
  return __bro_util_htonll(i);
}
#endif
