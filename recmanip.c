/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include "qpopauthd.h"

/* Adds IP record of user session */
int addrec(char *ip)
{
	FILE *fp;
	char tmp[BUFSIZ];
	int i;

bark("[ADD] Examining records %d", *auth_ips_count);

	/* Make sure we don't surpass out connection bounds */
	if (*auth_ips_count >= MAX_CONNS)
		return 0;

bark("Within max num of connections");

	/*
	 * Make sure it doesn't already exist.
	 * If it does, update the timeout.
	 */
	for (i = 0; i < *auth_ips_count; i++)
		if (strcmp(ip, auth_ips[i]->ip) == 0)
		{
			/* Update timeout */
			auth_ips[i]->time = time(NULL);
			return 0;
		}

bark("Unique IP");

	/* Update latest structure */
	auth_ips[*auth_ips_count]->time = time(NULL);
	strlcpy(auth_ips[*auth_ips_count]->ip, ip, sizeof(auth_ips[*auth_ips_count]->ip));

bark("Memory updated");

	/* Now append it to the auth file */
	fp = fopen(authfile, "a");

	if (!fp)
		carp("Cannot open file ``%s''", authfile);

	/* Put line into format the auth system is expecting */
	snprintf(tmp, sizeof(tmp), "%s\tRELAY\n", ip);

	flock((int)fp, LOCK_SH);
	fputs(tmp, fp);
	flock((int)fp, LOCK_UN);
	fclose(fp);

bark("File updated");

	system("/usr/sbin/makemap hash /etc/mail/access.db < /etc/mail/access");

	++*auth_ips_count;

bark("Pointer updated, num records: %d", *auth_ips_count);

	return 1;
}

/* Remove an IP record */
int rmrec(int index)
{
	FILE *auth_fp;
	char tmp[BUFSIZ], line[BUFSIZ],
	     tempfile[BUFSIZ];
	int temp_fp;

	/* Remove it from the file */
	strlcpy(tempfile, "/tmp/qpopauth.XXXXXX", sizeof(tempfile));
	temp_fp = mkstemp(tempfile);
	if (temp_fp == -1)
		carp("Cannot get mkstemp() handle");

	auth_fp = fopen(authfile, "r");
	if (auth_fp == NULL)
		carp("Cannot fopen() file ``%s''", auth_fp);

	/* Fill up what the line should look like and compare */
	snprintf(tmp, sizeof(tmp), "%s\tRELAY\n", auth_ips[index]->ip);

bark("Searching for line >>>%s<<<", tmp);

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

	while (read(temp_fp, line, sizeof(line)))
		fputs(line, auth_fp);

	fclose(auth_fp);
	close(temp_fp);
	unlink(tempfile);

bark("Files updated, updating memory");

	/* We're done with this entry */
	--*auth_ips_count;
	auth_ips[index] = auth_ips[*auth_ips_count];
	/* auth_ips[*auth_ips_count] = NULL; */

bark("Memory updated");

	return 1;
}
