/* $Id$ */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <err.h>
#include "qpopauthd.h"

/* Creates and adds new session record */
int addrec(char *ip)
{
	FILE *fp;
	char tmp[BUFSIZ];
	int i;

	/* Make sure we don't surpass out connection bounds */
	if (*auth_ips_count >= MAX_CONNS)
		return 0;

	/*
	 * Make sure it doesn't already exist.
	 * If it does, update the timeout.
	 */
	for (i = 0; i < *auth_ips_count; i++)
		if (strcmp(ip, auth_ips[i]->ip) == 0) {
			/* Update timeout */
			auth_ips[i]->time = time(NULL);
			return 0;
		}

	/* Update latest structure */
	auth_ips[*auth_ips_count]->time = time(NULL);
	strncpy(auth_ips[*auth_ips_count]->ip, ip, sizeof(auth_ips[*auth_ips_count]->ip) - 1);
	auth_ips[sizeof(auth_ips[*auth_ips_count]->ip) - 1] = '\0';

	/* Now append it to the auth file */
	if ((fp = fopen(authfile, "a")) == NULL)
		err(1, "Cannot open \"%s\"", authfile);

	/* Put line into format the auth system is expecting */
	snprintf(tmp, sizeof(tmp), "%s\tRELAY\n", ip);

	flock(fileno(fp), LOCK_SH);
	fputs(tmp, fp);
	flock(fileno(fp), LOCK_UN);
	fclose(fp);

	system("/usr/sbin/makemap hash /etc/mail/access.db < /etc/mail/access");

	++*auth_ips_count;

	return 1;
}

/* Remove an IP record */
int rmrec(int index)
{
	FILE *auth_fp;
	char tmp[BUFSIZ], line[BUFSIZ], tempfile[BUFSIZ];
	int temp_fp;

	/* Remove it from the file */
	strncpy(tempfile, "/tmp/qpopauth.XXXXXX", sizeof(tempfile) - 1);
	tempfile[sizeof(tempfile) - 1] = '\0';

	if ((temp_fp = mkstemp(tempfile)) == -1)
		err(1, "Unable to mkstemp()");

	if ((auth_fp = fopen(authfile, "r")) == NULL)
		err(1, "Cannot open file \"%s\"", authfile);

	/* Fill up what the line should look like and compare */
	snprintf(tmp, sizeof(tmp), "%s\tRELAY\n", auth_ips[index]->ip);

	/*
	 * Only copy back lines that don't
	 * match (i.e., all other records).
	 */
	while (fgets(line, sizeof(line), auth_fp) != NULL)
		if (strcmp(line, tmp) != 0)
			write(temp_fp, line, sizeof(line));

	fclose(auth_fp);
	auth_fp = fopen(authfile, "w");

	lseek(temp_fp, 0, SEEK_SET);

	while (read(temp_fp, line, sizeof(line)) > 0)
		fputs(line, auth_fp);

	fclose(auth_fp);
	close(temp_fp);
	unlink(tempfile);

	/* We're done with this entry */
	--*auth_ips_count;
	auth_ips[index] = auth_ips[*auth_ips_count];
	/* auth_ips[*auth_ips_count] = NULL; */

	return 1;
}
