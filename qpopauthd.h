/* $Id */

#ifndef QPOPAUTHD_H
#define QPOPAUTHD_H
#include <stdio.h>
#include <time.h>

#define MAX_CONNS	50			/* Max # of simultaneous connections */

#define DEF_F_AUTH	"/etc/mail/access"	/* Default file for access perms */
#define DEF_DELAY	5			/* Default delay for auth record timeouts */

void usage(int status);
int addrec(char *ip);
int rmrec(int index);

void carp(char *msg, ...);
void report(char *msg, ...);

struct authrec
{
	char	ip[15];				/* IP address (xxx.xxx.xxx.xxx) */
	time_t	time;				/* Time to keep track of record */
};


extern int		*auth_ips_count;
extern char		f_auth[BUFSIZ];
extern struct authrec	*auth_ips[MAX_CONNS];

#ifndef HAVE_STRLCPY
size_t strlcpy(char *s, const char *t, size_t n);
#endif

#endif /* QPOPAUTHD_H */
