/* $Id$ */

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <regex.h>
#include <errno.h>
#include <sys/mman.h>
#include <signal.h>
#include "qpopauthd.h"

int		*auth_ips_count;
char		f_auth[BUFSIZ];
struct authrec	*auth_ips[MAX_CONNS];

int main(int argc,char *argv[])
{
	char		tmp[BUFSIZ];
	pid_t		pid;
	int		arg,
			delay,
			i;
	extern char	*optarg;
	extern int	errno;

	/* Map shared data */
	for (i = 0; i < MAX_CONNS; i++)
		auth_ips[i] = mmap((void *)0,sizeof(struct authrec),
				PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED,
				-1, 0);

	auth_ips_count = mmap((void *)0,sizeof(int), PROT_READ | PROT_WRITE,
				MAP_ANON | MAP_SHARED, -1, 0);

	/* Set defaults */
	delay = DEF_DELAY;
	strlcpy(f_auth, DEF_F_AUTH, sizeof(f_auth));

	/* Parse arguments */
	while ((arg = getopt(argc,argv, "a:d:h")) != -1)
	{
		switch (arg)
		{
			case 'a':	/* Override default auth file */
				strlcpy(f_auth,optarg,sizeof(f_auth));
				break;
			case 'h':	/* Help */
				usage(0);
				break;
			case 'd':
				delay = atoi(optarg);
				break;
			default:
				/*snprintf(tmp,sizeof(tmp),"Unknown option -%s",arg);*/
				usage(1);
		}
	}

	/* Delay is in minutes and sleep() wants seconds */
	delay *= 60;

	/* We'll have the child feed authenticated IPs to the parent */
	pid = fork();

	if (pid == EAGAIN || pid == ENOMEM)
	{
		snprintf(tmp,sizeof(tmp),"Unable to fork(): %s",strerror(errno));
		perror(tmp);

	} else if (pid) {	/* Parent */

		int i;

		/* Die on child exit */
		signal(SIGCHLD,exit);

		/* Loop through the records and remove old ones */
		while (1)
		{
#ifdef DEBUG
snprintf(tmp,sizeof(tmp),"[parent] Scoping IP records (%d)",*auth_ips_count);
report(tmp);
#endif

			for (i = 0; i < *auth_ips_count; i++)
			{
#ifdef DEBUG
snprintf(tmp,sizeof(tmp),"Index: %d, count: %d\nTime: %d\nIP: %s",i,*auth_ips_count,auth_ips[i]->time,auth_ips[i]->ip);
report(tmp);

snprintf(tmp,sizeof(tmp),"[parent] Examining %s:%d time:%d (%d of %d)",auth_ips[i]->ip,auth_ips[i]->time,time(NULL),i + 1,*auth_ips_count);
report(tmp);
#endif

				if (auth_ips[i]->time + delay < time(NULL))
				{
#ifdef DEBUG
snprintf(tmp,sizeof(tmp),"Removing IP ``%s''",auth_ips[i]->ip);
report(tmp);
#endif

					rmrec(i);
				}
			}

			sleep(1);
		}
	} else {		/* Child */
		int		i,
				ret;
		char		in[BUFSIZ],
				ip[15];
		regex_t		authreg;
		size_t		num_matches = 3;
		regmatch_t	matches[3];	/* We're only expecting 2 match */

#ifdef DEBUG
report("[child] Compiling regex");
#endif

		/*
We need to grab (ip) from the following:

Aug 24 09:38:19 netzdamon sendmail[25661]: g7OEcIPq025661:	from=<firerunner@pa2600.org>,
								size=1306,
								class=0,
								nrcpts=1,
								msgid=<20020822041803.5fd58444.firerunner@pa2600.org>,
								proto=SMTP,
								daemon=MTA,
								relay=dorms-pppoe-2-85-128.pittsburgh.resnet.pitt.edu [130.49.85.128]


		 */
		ret = regcomp
		(
			&authreg,
			"^[A-Za-z]+ [0-9]+ [0-9][0-9]:[0-9][0-9]:[0-9][0-9] "			/* date */
			"[a-z0-9]+ "								/* hostname */
			"sendmail[[][0-9]+[]]: "						/* program/line */
			"[a-zA-Z0-9]+: "							/* ? */
			"from=<[a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+>, "				/* from */
			"size=[0-9]+, "								/* message size */
			"class=[0-9]+, "							/* class */
			"nrcpts=[0-9]+,"							/* number of recipients */
			"( msgid=<[0-9]+[.][a-z0-9]+[.][a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+>, | )"	/* id */
			"proto=SMTP, "								/* protocol */
			"daemon=MTA, "								/* mail transfer agent */
			"relay=[a-zA-Z0-9_.-]+ [[]([0-9.]+)[]]$"				/* ip */
			,
/*
"^[A-Za-z]+ +[0-9]+ [0-9]+:[0-9]+:[0-9]+ [A-Za-z]+ spop3d[[][0-9]+[]]: user [a-z_]+ "
"authenticated - ([0-9]+[.][0-9]+[.][0-9]+[.][0-9]+)$",
*/			REG_EXTENDED | REG_ICASE | REG_NEWLINE

		);

		if (ret)
		{
#ifdef DEBUG
snprintf(tmp,sizeof(tmp),"[child] ***WARNING***: Regex compile failed: %d",ret);
report(tmp);
#endif
		}

		while (fgets(in,sizeof(in),stdin))
		{
#ifdef DEBUG
snprintf(tmp,sizeof(tmp),"[child] Received >>>%s<<<",in);
report(tmp);
#endif

			if ((ret = regexec(&authreg,in,num_matches,matches,0)) == 0)
			{
				/* Make sure string is empty */
				int len = 1 + matches[2].rm_eo - matches[2].rm_so;

				if (len > sizeof(ip))
					len = sizeof(ip);

				bzero(ip,sizeof(ip));

				strlcpy(ip,in + matches[2].rm_so,len);

#ifdef DEBUG
snprintf(tmp,sizeof(tmp),"[child] Matched IP ``%s'' (start:%d end:%d subs:%d)",ip,matches[2].rm_so,matches[2].rm_eo,authreg.re_nsub);
report(tmp);
#endif

				addrec(ip);
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
