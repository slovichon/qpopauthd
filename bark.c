/* $Id$ */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include "qpopauthd.h"

void carp(char *fmt, ...)
{
	va_list ap;
	extern int errno;

	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	(void)fprintf(stderr, "\n");

	if (errno)
		perror(NULL);

	exit(1);
}

void bark(char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "[DEBUG] ");

	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);

	(void)fprintf(stderr, "\n");
}
