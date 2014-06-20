/*
 * appid_hexdump.c
 *
 * Simple function to display packet in hex/ascii.
 *
 * Copyright (c) 2001-2007 Arbor Networks, Inc.
 *
 * $Id: appid_hexdump.c 2 2007-06-04 18:16:24Z dugsong $
 */

static const char rcsid[] = "@(#)$Id: appid_hexdump.c 2 2007-06-04 18:16:24Z dugsong $";

#include <sys/types.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "appid.h"

/*
 * n - offset. (what the left side column prints)
 * a - address in memory.
 * l - length.
 */

void
appid_hexdump(int n, const void *v, int l)
{
	const unsigned char *buffer = v;
	int i;
	for(i=0;i<l;i+=16) {
		int j;
		/* print address/offset: */
		printf("%04x:  ", n+i);

		/* print hex bytes */
		for(j=0;j<16;j++) {
			if(i+j<l)
				printf("%02x",buffer[i+j]);
			else
				printf("  ");
			if((j&0x03) == 3) printf(" ");
		}

		printf("   ");
		/* print char bytes */
		for(j=0;j<16;j++) {
			char ch = '.';
			if(isprint(buffer[i+j])) ch = buffer[i+j];
			if(i+j<l)
				printf("%c",ch);
			else
				printf("  ");
		}
		printf("\n");
	}
}
