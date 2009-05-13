/* $diskrescue$ */
/*
 * Copyright (c) 2009 Marco Peereboom <marco@peereboom.us>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

static const char	*cvstag = "$diskrescue$";

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/param.h>
#include <sys/disklabel.h>
#include <sys/dkio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define	VERSION		"0.1"
/*
 * todo:
 *	rewrite whole disk
 *	add blocks to GLIST
 *	add more scsi/sata magic to "heal" a disk
 *	add skip offset
 *	add continue option in case of bombed kernel
 */

/*
 * verify:	Verify entire media on disk to allow the drive to reallocate any
 *		failed blocks.
 *
 * recover:	Read entire media and write it to another disk or a file
 *
 */
struct operations {
	char		*op;
	int		opcode;
#define OPC_VERIFY	(0)
#define OPC_RECOVER	(1)
#define OPC_INVALID	(255) /* must be last */
} ops[] = {
	{ "verify", OPC_VERIFY },
	{ "recover", OPC_RECOVER },
	{ NULL, OPC_INVALID }
};

FILE			*resfd = stderr;
int			quiet = 0;

int
rawsize(int fd, daddr64_t *size)
{
#if defined(__OpenBSD__)
	struct disklabel        dl;

	if (ioctl(fd, DIOCGPDINFO, &dl) < 0)
		return (-1);

	*size = DL_SECTOBLK(&dl, DL_GETDSIZE(&dl)) * DEV_BSIZE;
	return (0);
#else
	return (-1);
#endif
}

daddr64_t
getbs(char *val)
{
	daddr64_t		num, t;
	char			*expr;

	num = strtoul(val, &expr, 0);
	if (num == SIZE_T_MAX) /* Overflow. */
		err(1, "too big");
	if (expr == val) /* No digits. */
		errx(1, "%s: illegal numeric value", val);

	switch(*expr) {
	case 'b':
		t = num;
		num *= 512;
		if (t > num)
			goto erange;
		++expr;
		break;
	case 'k':
		t = num;
		num *= 1024;
		if (t > num)
			goto erange;
		++expr;
		break;
	case 'm':
		t = num;
		num *= 1048576;
		if (t > num)
			goto erange;
		++expr;
		break;
	case 'g':
		t = num;
		num *= 1073741824;
		if (t > num)
			goto erange;
		++expr;
		break;
	}

	switch(*expr) {
	case '\0':
		break;
	case 'x':
	case '*':
		t = num;
		num *= getbs(expr + 1);
		if (t > num)
erange:			errx(1, "illegal block size: %s", strerror(ERANGE));
		break;
	default:
		errx(1, "%s: illegal numeric value", val);
	}
	return (num);
}

int
readoffset(daddr64_t offs, int fd, char *buf, daddr64_t bs)
{
	int			rv;

	if (lseek(fd, offs, SEEK_SET) == -1)
		err(1, "lseek");

	rv = read(fd, buf, bs);
	if (rv == -1)
		bzero(buf, bs);

	return (rv);
}

int
recover(daddr64_t offs, int fd, char *buf, daddr64_t bs)
{
	int			rv = -1, sz;
	daddr64_t		blocks, b;

	blocks = bs / DEV_BSIZE;
	if (bs % DEV_BSIZE)
		errx(1, "invalid blocksize");

	for (b = 0, sz = 0; b < blocks; b++, sz += DEV_BSIZE) {
		rv = readoffset(offs + b * DEV_BSIZE, fd, &buf[b * DEV_BSIZE],
		    DEV_BSIZE);
		if (rv == 0)
			errx(1, "recover unexpected eof");
		else if (rv == -1) {
			fprintf(resfd, "unrecoverable error at offset: %llu\n",
			    offs + b * DEV_BSIZE);
			bzero(&buf[b * DEV_BSIZE], DEV_BSIZE);
		} else if (rv != DEV_BSIZE)
			errx(1, "invalid size recovered");
	}

	return (sz);
}

void
usage(void)
{
	extern char		*__progname;

	fprintf(stderr,
		"usage: %s [-qv] [-R results file] [-b block size] "
		"[-o out file] [-r raw device] operation\n",
		__progname);
	
	exit(1);
}
int
main(int argc, char *argv[])
{
	FILE			*ofd = NULL;
	char			*rawdev = NULL, *outfile = NULL, *resfile = NULL;
	daddr64_t		size, bs = 512;
	daddr64_t		offs, sz;
	int			fd, c, rv, i, operation = OPC_INVALID;
	char			*inbuf, *error = "no error";
	struct stat		sb;
	double			p = 0;

	while ((c = getopt(argc, argv, "R:b:r:qo:v")) != -1) {
		switch (c) {
		case 'R':
			/* result file */
			resfile = optarg;
			break;
		case 'b':
			/* read/write block size */
			bs = getbs(optarg);
			break;
		case 'o':
			/* out file or disk */
			outfile = optarg;
			break;
		case 'q':
			/* quiet */
			quiet = 1;
			break;
		case 'r':
			/* raw disk to read */
			rawdev = optarg;
			break;
		case 'v':
			/* version */
			fprintf(stderr, "version %s, cvs %s\n",
			    VERSION, cvstag);
			exit(1);
			break;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage();

	for (i = 0; ops[i].op != NULL; i++)
		if (!strcmp(argv[0], ops[i].op))
			operation = ops[i].opcode;
	if (operation == OPC_INVALID)
		errx(1, "invalid operation %s", argv[0]);

	/* verify args */
	if (bs % DEV_BSIZE)
		errx(1, "block size must be divisible by 512");

	switch (operation) {
	case OPC_VERIFY:
		if (rawdev == NULL) {
			error = "must supply raw device";
			goto iargs;
		}
		if (outfile != NULL) {
			error = "must not supply an out file";
			goto iargs;
		}
		break;
	case OPC_RECOVER:
		if (rawdev == NULL) {
			error = "must supply raw device";
			goto iargs;
		}
		if (outfile == NULL) {
			error = "must supply an out file";
			goto iargs;
		}
		break;

	case OPC_INVALID:
	default:
iargs:
		errx(1, "invalid arguments to %s: %s",
		    ops[operation].op, error);
	}

	/* here we go */
	inbuf = malloc(bs);
	if (inbuf == NULL)
		err(1, "inbuf");

	/* are we the full raw device? */
	if (rawdev == NULL)
		errx(1, "must supply raw device");
	if (lstat(rawdev, &sb))
		err(1, "lstat");
	if (!S_ISCHR(sb.st_mode))
		errx(1, "not a raw device");
	if (rawdev[strlen(rawdev) - 1] != 'c')
		errx(1, "must use c partition");

	/* open out file */
	if (outfile)
		if ((ofd = fopen(outfile, "w+")) == NULL)
			err(1, "fopen outfile");

	/* open disk */
	if ((fd = open(rawdev, O_RDWR, 0)) == -1)
		err(1, "can't open %s", rawdev);
	if (rawsize(fd, &size))
		errx(1, "can't obtain raw size");

	/* open resulys file */
	if (resfile != NULL) {
		/*
		 * XXX interpret results file instead to continue where we
		 * left of
		 */
		if (!lstat(resfile, &sb))
			errx(1, "results file exists");
		if ((resfd = fopen(resfile, "w+")) == NULL)
			err(1, "results file");
	}

	fprintf(resfd, "disk size : %llu\n", size);
	fprintf(resfd, "block size: %llu\n", bs);
	fflush(resfd);

	for (offs = 0; offs < size; offs += sz) {
		sz = MIN(size - offs, bs);

		rv = readoffset(offs, fd, inbuf, sz);
		if (rv == 0)
			errx(1, "unexpected eof");
		else if (rv == -1) {
			rv = recover(offs, fd, inbuf, sz);
			if (rv == 0)
				errx(1, "full recover unexpected eof");
			else if (rv == -1)
				errx(1, "full recover failed");
			else if (rv != sz)
				errx(1, "invalid size recovered");
		}

		if (outfile)
			if (fwrite(inbuf, sz, 1, ofd) == -1)
				err(1, "fwrite");
		if (!quiet) {
			p = 1 - (((double)size - (double)offs) / (double)size);
			printf("\r%.1f%%", p * 100);
			fflush(stdout);
		}
	}
	printf("\n");

	return (0);
}