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
#include <err.h>
#include "qpopauthd.h"

int *auth_ips_count;
char *authfile;
struct authrec *auth_ips[MAX_CONNS];

#define NUM_MATCHES 3				/* Data matched in regular expression below */
#define DEF_AUTHFILE "/etc/mail/access"		/* Default file for access perms */
#define DEF_DELAY 5				/* Default delay for auth record timeouts */

int main(int argc, char *argv[])
{
	pid_t pid;
	int c, delay, i;
	extern char *optarg;
	extern int errno;

	/* Map shared data */
	for (i = 0; i < MAX_CONNS; i++)
		if ((auth_ips[i] = mmap(0, sizeof(struct authrec), PROT_READ | PROT_WRITE,
					MAP_ANON | MAP_SHARED, -1, 0)) == MAP_FAILED)
			err(1, "Unable to mmap()");

	if ((auth_ips_count = mmap(0, sizeof(int), PROT_READ | PROT_WRITE,
				   MAP_ANON | MAP_SHARED, -1, 0)) == MAP_FAILED)
		err(1, "Unable to mmap()");

	/* Set defaults */
	delay = DEF_DELAY;
	authfile = DEF_AUTHFILE;

	/* Parse arguments */
	while ((c = getopt(argc, argv, "a:d:h")) != -1) {
		switch (c) {
			case 'a': /* Auth file */
				authfile = optarg;
				break;

			case 'h': /* Help */
				usage(0);
				break;

			case 'd': /* Delay interval for purging sessions */
				delay = atoi(optarg);
				break;

			default:
				warn("Unknown option: %c", c);
				usage(1);
		}
	}

	/* Delay should be in minutes and sleep() wants seconds */
	delay *= 60;

	/* We'll have the child feed authenticated IPs to the parent */
	pid = fork();

	if (pid == EAGAIN || pid == ENOMEM)
		err(1, "Unable to fork()");

	else if (pid) {
		/* Parent */
		int i;

		/* Die on child exit */
		signal(SIGCHLD, exit);

		/* Loop through the records and remove old ones */
		while (TRUE) {
			for (i = 0; i < *auth_ips_count; i++)
				if (auth_ips[i]->time + delay < time(NULL))
					rmrec(i);
			sleep(1);
		}
	} else {
		/* Child */
		int ret;
		char in[BUFSIZ], ip[15];
		regex_t authreg;
		regmatch_t matches[NUM_MATCHES];

		/*
			Expect entries in the following format:

			Aug 24 09:38:19 hostname sendmail[25661]: g7OEcIPq025661:
				from=<foo@bar.com>,
				size=1306,
				class=0,
				nrcpts=1,
				msgid=<20020822041803.5fd58444.foo@bar.com>,
				proto=SMTP,
				daemon=MTA,
				relay=client-hostname.attbi.com [130.49.85.128]
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

		if (ret) {
			char errbuf[BUFSIZ];
			regerror(ret, &authreg, errbuf, BUFSIZ);
			errx(1, "Regex compile failed: %s", errbuf);
		} else {
			while (fgets(in, sizeof(in), stdin) != NULL) {
				if ((ret = regexec(&authreg, in, NUM_MATCHES, matches, 0)) == 0) {
					/* Make sure string is empty */
					int len = 1 + matches[2].rm_eo - matches[2].rm_so;

					if (len > sizeof(ip))
						len = sizeof(ip);

					bzero(ip, sizeof(ip));

					strncpy(ip, in + matches[2].rm_so, len - 1);
					ip[len - 1] = '\0';

					addrec(ip);
				}
			}
		}
	}
	return 0;
}

/* Show usage information */
void usage(int status)
{
	fprintf(stderr, "Usage: qpopauthd [options]\n");

	exit(status);
}
