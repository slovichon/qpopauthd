/* $Id$ */

#ifndef QPOPAUTHD_H
#define QPOPAUTHD_H
#include <stdio.h>
#include <time.h>

#define MAX_CONNS 50				/* Max # of simultaneous connections */

#define TRUE  1
#define FALSE 0

void usage(int status);
int addrec(char *ip);
int rmrec(int index);

void carp(char *msg, ...);
void bark(char *msg, ...);

struct authrec {
	char	ip[15];				/* IP address (xxx.xxx.xxx.xxx) */
	time_t	time;				/* Time to keep track of record */
};

extern int *auth_ips_count;
extern char *authfile;
extern struct authrec *auth_ips[MAX_CONNS];

#endif /* QPOPAUTHD_H */
