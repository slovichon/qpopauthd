/* $Id */

#include <stdio.h>
#include <fcntl.h>
#include "qpopauthd.h"

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
