/*
	QPopAuthD
	Daemon which listens for QPOP connections
	after successful user authentication

	By Jared Yanovich <jaredy@closeedge.net>

	Thursday, August 22, 2002 04:04:59 AM
*/

/* Includes */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <regex.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <string.h>

/* Defines */
#define MAX_CONNS	50		/* Maximum number of simultaneous connections */

/* Default values */
#define DEF_F_AUTH	"/etc/mail/access"
#define DEF_DELAY	5

/* Function prototypes */
void usage(int status);
int addrec(char *ip);
int rmrec(int index);
void carp(char *msg);
#ifdef DEBUG
void report(char *msg);
#endif

/* Datatypes */
struct authrec
{
	char	ip[15];		/* IP address; Too big a pain in the ass to make a different type */
	time_t	time;		/* Time to keep track of record */
};

/* Globals */
int		*auth_ips_count;
char		f_auth[BUFSIZ];

struct authrec	*auth_ips[MAX_CONNS];

/* Main */
int main(int argc,char *argv[])
{
	char		tmp[BUFSIZ];
	int		arg,
			pid,
			delay,
			i;
	extern char	*optarg;
	extern int	errno;

	/* Set up shared data */
	for (i = 0; i < MAX_CONNS; i++)
		auth_ips[i] =	mmap
				(
					(void *)0,
					sizeof(struct authrec),
					PROT_READ | PROT_WRITE,
					MAP_ANON | MAP_SHARED,
					-1,
					0
				);

	auth_ips_count =	mmap
				(
					(void *)0,
					sizeof(int),
					PROT_READ | PROT_WRITE,
					MAP_ANON | MAP_SHARED,
					-1,
					0
				);

	/* Set up default values */
	delay = DEF_DELAY;
	strlcpy(f_auth,DEF_F_AUTH,sizeof(f_auth));

	/* Parse arguments */
	while ((arg = getopt(argc,argv,"a:d:h")) != -1)
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

	/* Delay is in minutes */
	delay *= 60;

	/* We'll have the child feed authenticated IPs to the parent */
	pid = fork();

	if (pid == -1)
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

/* Function definitions */

/* Show usage information */

void usage(int status)
{
	carp
	(
		"Usage: qpopauthd [options]\n\n"
		"Consult the manual for more help.\n"
	);

	exit(status);
}

/* Output some information */

void carp(char *msg)
{
	(void)fprintf(stderr,"%s\n",msg);

	return;
}

/* Output some debugging infomation */
#ifdef DEBUG
void report(char *msg)
{
	char newmsg[BUFSIZ];

	snprintf(newmsg,sizeof(newmsg),"[DEBUG] %s",msg);

	carp(newmsg);

	return;
}
#endif

/* Adds IP record of user session */

int addrec(char *ip)
{
	FILE		*fp;
	char		tmp[BUFSIZ];
	int		i;
	extern int	errno;


#ifdef DEBUG
snprintf(tmp,sizeof(tmp),"Adding IP\nExamining records %d",*auth_ips_count);
report(tmp);
#endif

	/* Make sure we don't surpass out connection bounds */
	if (*auth_ips_count >= MAX_CONNS)
		return 0;

#ifdef DEBUG
report("Within max num of connections");
#endif

	/* Make sure it doesn't already exist -- if it does, we have to update*/
	for (i = 0; i < *auth_ips_count; i++)
		if (strcmp(ip,auth_ips[i]->ip) == 0)
		{
			/* Update timeout */
			auth_ips[i]->time = time(NULL);
			return 0;
		}

#ifdef DEBUG
report("Unique IP");
#endif

	/* Update latest structure */
	auth_ips[*auth_ips_count]->time = time(NULL);
	strlcpy(auth_ips[*auth_ips_count]->ip,ip,sizeof(auth_ips[*auth_ips_count]->ip));

#ifdef DEBUG
report("Memory updated");
#endif

	/* Now append it to the auth file */
	fp = fopen(f_auth,"a");

	if (!fp)
	{
		snprintf(tmp,sizeof(tmp),"Cannot open file ``%s'': %s",f_auth,strerror(errno));
		perror(tmp);
	}

	/* Put line into format the auth system is expecting */
	snprintf(tmp,sizeof(tmp),"%s\tRELAY\n",ip);

	flock((int)fp,LOCK_SH);
	fputs(tmp,fp);
	flock((int)fp,LOCK_UN);
	fclose(fp);

#ifdef DEBUG
report("File updated");
#endif

	system("/usr/sbin/makemap hash /etc/mail/access.db < /etc/mail/access");

	(*auth_ips_count)++;

#ifdef DEBUG
snprintf(tmp,sizeof(tmp),"Pointer updated, num records: %d",*auth_ips_count);
report(tmp);
#endif

	return 1;
}

/* Remove an IP record */

int rmrec(int index)
{
	FILE	/**tmp_fp,*/	/* Temporary file for copying */
		*auth_fp;	/* Auth file */
	char	tmp[BUFSIZ],
		line[BUFSIZ],
		f_temp[BUFSIZ];
	int	tmp_fp;

	extern int errno;

	/* Remove it from the file */
	strlcpy(f_temp,"/tmp/qpopauth.XXXXXX",sizeof(f_temp));

	tmp_fp = mkstemp(f_temp);

	if (tmp_fp == -1)
	{
		snprintf(tmp,sizeof(tmp),"Cannot get mkstemp() handle (%d)",errno);
		perror(tmp);
	}

	auth_fp = fopen(f_auth,"r");

	if (!auth_fp)
	{
		snprintf(tmp,sizeof(tmp),"Cannot fopen() file ``%s''",auth_fp);
		perror(tmp);
	}

	/* Fill up what the line should look like and compare */
	snprintf(tmp,sizeof(tmp),"%s\tRELAY\n",auth_ips[index]->ip);

#ifdef DEBUG
{char t[BUFSIZ];
snprintf(t,sizeof(t),"Searching for line >>>%s<<<",tmp);
report(t);}
#endif

	while (fgets(line,sizeof(line),auth_fp))
		if (strcmp(line,tmp) != 0)
			write(tmp_fp,line,sizeof(line));

	fclose(auth_fp);

	lseek(tmp_fp,0,SEEK_SET);

	auth_fp = fopen(f_auth,"w");

	while (read(tmp_fp,line,sizeof(line)))
		fputs(line,auth_fp);

	fclose(auth_fp);

	close(tmp_fp);

	unlink(f_temp);

#ifdef DEBUG
report("Files updated, updating memory");
#endif

	/* We're done with this entry */
	(*auth_ips_count)--;

	auth_ips[index] = auth_ips[*auth_ips_count];

/*	auth_ips[*auth_ips_count] = NULL;
*/

#ifdef DEBUG
report("Memory updated");
#endif

	return 1;
}
