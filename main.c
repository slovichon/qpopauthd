/* $Id$ */

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <regex.h>
#include <errno.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include "qpopauthd.h"

int *auth_ips_count;
char authfile[BUFSIZ];
struct authrec *auth_ips[MAX_CONNS];

#define NUM_MATCHES 3

int main(int argc,char *argv[])
{
	pid_t pid;
	int arg, delay, i;
	extern char *optarg;
	extern int errno;

	/* Map shared data */
	for (i = 0; i < MAX_CONNS; i++)
		auth_ips[i] = mmap((void *)0,sizeof(struct authrec),
				PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED,
				-1, 0);

	auth_ips_count = mmap((void *)0,sizeof(int), PROT_READ | PROT_WRITE,
				MAP_ANON | MAP_SHARED, -1, 0);

	/* Set defaults */
	delay = DEF_DELAY;
	strlcpy(authfile, DEF_AUTHFILE, sizeof(authfile));

	/* Parse arguments */
	while ((arg = getopt(argc, argv, "a:d:h")) != -1) {
		switch (arg) {
			case 'a':
				/* auth file */
				strlcpy(authfile, optarg, sizeof(authfile));
				break;
			case 'h':
				/* Help */
				usage(0);
				break;
			case 'd':
				delay = atoi(optarg);
				break;
			default:
				/* snprintf(tmp, sizeof(tmp), "Unknown option -%s\n", arg); */
				usage(1);
		}
	}

	/* Delay should be in minutes and sleep() wants seconds */
	delay *= 60;

	/* We'll have the child feed authenticated IPs to the parent */
	pid = fork();

	if (pid == EAGAIN || pid == ENOMEM)
		carp("Unable to fork()");
	else if (pid) {
		/* Parent */
		int i;

		/* Die on child exit */
		signal(SIGCHLD, exit);

		/* Loop through the records and remove old ones */
		while (TRUE) {
bark("[PARENT] Scoping %d IP records", *auth_ips_count);

			for (i = 0; i < *auth_ips_count; i++) {
bark("[PARENT] Examining %s:%d time:%d (%d of %d)",
	auth_ips[i]->ip, auth_ips[i]->time, time(NULL), i + 1, *auth_ips_count);

				if (auth_ips[i]->time + delay < time(NULL)) {
bark("[PARENT] Removing IP ``%s''", auth_ips[i]->ip);
					rmrec(i);
				}
			}
			sleep(1);
		}
	} else {		/* Child */
		int ret;
		char in[BUFSIZ], ip[15];
		regex_t authreg;
		regmatch_t matches[NUM_MATCHES];	/* We're only expecting 2 matches */

bark("[CHILD] Compiling regex");

		/*
			Expect entries in the following format:

			Aug 24 09:38:19 netzdamon sendmail[25661]: g7OEcIPq025661:
				from=<firerunner@pa2600.org>,
				size=1306,
				class=0,
				nrcpts=1,
				msgid=<20020822041803.5fd58444.firerunner@pa2600.org>,
				proto=SMTP,
				daemon=MTA,
				relay=dorms-pppoe-2-85-128.pittsburgh.resnet.pitt.edu [130.49.85.128]
		 */
		ret = regcomp(&authreg,
			"^[A-Za-z]+ [0-9]+ "			/* date */
			"[0-9][0-9]:[0-9][0-9]:[0-9][0-9] "	/* time */
			"[a-z0-9]+ "				/* hostname */
			"sendmail[[][0-9]+[]]: "		/* program/line */
			"[a-zA-Z0-9]+: "			/* id */
			"from="
			"<[a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+>, "	/* from */
			"size=[0-9]+, "				/* size */
			"class=[0-9]+, "			/* class */
			"nrcpts=[0-9]+,"			/* number of recipients */
			"( msgid=<[0-9]+[.][a-z0-9]+[.]"	/* msgid */
			"[a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+>, | )"	/* email */
			"proto=SMTP, "				/* protocol */
			"daemon=MTA, "				/* mail transfer agent */
			"relay=[a-zA-Z0-9_.-]+ "		/* hostname */
			"[[]([0-9.]+)[]]$",			/* ip */
			REG_EXTENDED | REG_ICASE | REG_NEWLINE);

		if (ret)
			carp("[CHILD] ***WARNING***: Regex compile failed: %d",ret);
		else {
			while (fgets(in, sizeof(in), stdin) != NULL) {
bark("[CHILD] Received >>>%s<<<",in);

				if ((ret = regexec(&authreg, in, NUM_MATCHES, matches, 0)) == 0)
				{
					/* Make sure string is empty */
					int len = 1 + matches[2].rm_eo - matches[2].rm_so;

					if (len > sizeof(ip))
						len = sizeof(ip);

					bzero(ip,sizeof(ip));

					strlcpy(ip,in + matches[2].rm_so,len);

bark("[child] Matched IP ``%s'' (start:%d end:%d subs:%d)",
	ip, matches[2].rm_so, matches[2].rm_eo, authreg.re_nsub);

					addrec(ip);
				}
			}
		}

		carp("[child] ***WARNING***: Main loop ended");
	}
	return 0;
}

/* Show usage information */
void usage(int status)
{
	carp(	"Usage: qpopauthd [options]\n\n"
		"Consult the manual for more help.\n");

	exit(status);
}
