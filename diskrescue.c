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
#include <signal.h>

#include <crypto/sha1.h>

#include <sys/syslimits.h>
#include <sys/param.h>
#include <sys/disklabel.h>
#include <sys/dkio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define	VERSION		"0.2"
/*
 * todo:
 *	rewrite whole disk
 *	add blocks to GLIST
 *	add more scsi/sata magic to "heal" a disk
 *	add skip offset
 *	add continue option in case of bombed kernel
 */

struct dr_hdr {
	daddr64_t		disk_sz;
	daddr64_t		block_sz;
	char			output[PATH_MAX];
};

struct dr_entry {
	daddr64_t		offset;
	daddr64_t		size;
	char			digest[SHA1_DIGEST_LENGTH * 2 + 1];
};

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
volatile sig_atomic_t   running = 1;

void
sighdlr(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGHUP:
	case SIGQUIT:
		running = 0;
		break;
	}
}

void
installsignal(int sig, char *name)
{
	struct sigaction	sa;

	sa.sa_handler = sighdlr;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(sig, &sa, NULL) == -1)
		err(1, "could not install %s handler", name);
}

int
hdr_write(FILE *f, struct dr_hdr *h)
{
	if (f == NULL || h == NULL)
		return (-1);

	if (fprintf(f, "%llu %llu %.1024s\n",
	    h->disk_sz, h->block_sz, h->output) <= 0)
		err(1, "hdr_write: fprintf");
	fflush(f);

	return (0);
}

int
hdr_read(FILE *f, struct dr_hdr *h)
{
	int			rv = 0;

	if (f == NULL || h == NULL)
		return (-1);

	rewind(f);
	rv = fscanf(f, "%llu %llu %1024s",
	    &h->disk_sz, &h->block_sz, h->output);
	if (rv != 3)
		return (-1);

	return (0);
}

int
ent_write(FILE *f, daddr64_t offset, daddr64_t sz, char *inbuf)
{
	u_int8_t		digest[SHA1_DIGEST_LENGTH];
	char			digest_text[SHA1_DIGEST_LENGTH * 2 + 1];
	SHA1_CTX		ctx;
	int			i;

	if (f == NULL || inbuf == NULL || sz == 0)
		return (-1);

	SHA1Init(&ctx);
	SHA1Update(&ctx, inbuf, sz);
	SHA1Final((u_int8_t *)&digest, &ctx);
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
		snprintf(&digest_text[i * 2], 3, "%02x", digest[i]);

	if (fprintf(f, "%llu %llu %.40s\n", offset, sz, digest_text) <= 0)
		err(1, "ent_write: fprintf");
	fflush(f);

	return (0);
}

int
ent_read(FILE *f, FILE *outf, struct dr_entry *e)
{
	u_int8_t		digest[SHA1_DIGEST_LENGTH];
	char			digest_text[SHA1_DIGEST_LENGTH * 2 + 1];
	SHA1_CTX		ctx;
	int			i;
	u_int8_t		*buf;
	int			rv = 0;

	if (f == NULL || e == NULL)
		return (-1);

	rv = fscanf(f, "%llu %llu %40s", &e->offset, &e->size, e->digest);
	if (rv != 3)
		return (-1);

	if (outf) {
		buf = malloc(e->size);
		if (buf == NULL)
			err(1, "ent_read: malloc");
		if (fseeko(outf, e->offset, SEEK_SET))
			err(1, "ent_read: fsseko");
		if (fread(buf, e->size, 1, outf) != 1)
			err(1, "ent_read fread");

		SHA1Init(&ctx);
		SHA1Update(&ctx, buf, e->size);
		SHA1Final((u_int8_t *)&digest, &ctx);
		for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
			snprintf(&digest_text[i * 2], 3, "%02x", digest[i]);
		if (strcmp(digest_text, e->digest))
			errx(1, "outfile has an invalid digest at offset %llu",
			    e->offset);

		free(buf);
	}

	return (0);
}

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

	rv = pread(fd, buf, bs, offs);
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
		"usage: %s [-aqv] [-R results file] [-b block size] "
		"[-o out file] [-r raw device] operation\n",
		__progname);
	
	exit(1);
}
int
main(int argc, char *argv[])
{
	FILE			*ofd = NULL;
	char			*rawdev = NULL, *outfile = NULL, *resfile = NULL;
	daddr64_t		size = 0, bs = 512;
	daddr64_t		offs, sz, start = 0;
	int			fd, c, rv, i, operation = OPC_INVALID, exists = 0;
	int			abort_on_error = 0;
	char			*inbuf, *error = "no error", *mode = "w+";
	struct stat		sb;
	double			p = 0;
	struct dr_hdr		hdr;
	struct dr_entry		entry;

	while ((c = getopt(argc, argv, "R:ab:r:qo:v")) != -1) {
		switch (c) {
		case 'R':
			/* result file */
			resfile = optarg;
			break;
		case 'a':
			abort_on_error = 1;
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
		if (outfile == NULL && resfile == NULL) {
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

	/* are we the full raw device? */
	if (rawdev == NULL)
		errx(1, "must supply raw device");
	if (lstat(rawdev, &sb))
		err(1, "lstat");
	if (!S_ISCHR(sb.st_mode))
		errx(1, "not a raw device");
	if (rawdev[strlen(rawdev) - 1] != 'c')
		errx(1, "must use c partition");

	/* open raw disk */
	if ((fd = open(rawdev, O_RDWR, 0)) == -1)
		err(1, "can't open %s", rawdev);
	if (rawsize(fd, &size))
		errx(1, "can't obtain raw size");
	if (size == 0)
		errx(1, "invalid disk size");

	/* open results file */
	bzero(&hdr, sizeof hdr);
	if (resfile != NULL) {
		if (!lstat(resfile, &sb))
			exists = 1;
		if ((resfd = fopen(resfile, "a+")) == NULL)
			err(1, "results file");

		if (exists) {
			/* retrieve state */
			if (outfile)
				errx(1,
				    "can't specify outfile when restarting");
			if (bs != 512)
				errx(1,
				    "can't specify block size when restarting");
			mode = "r+";
			/* get parameters from results file */
			if (hdr_read(resfd, &hdr))
				errx(1, "invalid header");
			if (hdr.disk_sz != size)
				errx(1, "invalid disk size in header");
			if (hdr.block_sz % DEV_BSIZE)
				errx(1, "invalid block size in header");
			if (strlen(hdr.output) == 0)
				errx(1, "invalid filename in header");

			bs = hdr.block_sz;
			outfile = hdr.output;
		} else {
			/* get state from options */
			mode = "w+";
			hdr.disk_sz = size;
			hdr.block_sz = bs;
			if (outfile)
				strlcpy(hdr.output, outfile, sizeof hdr.output);

			if (hdr_write(resfd, &hdr))
				err(1, "hdr_write");
		}
	}

	/* open out file */
	if (outfile) {
		if ((ofd = fopen(outfile, mode)) == NULL)
			err(1, "fopen outfile");

		if (exists) {
			bzero(&entry, sizeof entry);
			entry.size = bs;
			do {
				if (ent_read(resfd, ofd, &entry))
					break;
			} while (!feof(resfd));
			start = entry.offset + entry.size;

			if (start >= size) {
				if (!quiet)
					printf("no need to restart\n");
				goto done;
			}

			/* setup size */
			sz = MIN(size - offs, bs);
			if (fseeko(ofd, start, SEEK_SET))
				err(1, "fsseko");
			if (!quiet)
				printf("restarting at: %llu\n", start);
		}
	}

	/* here we go */
	inbuf = malloc(bs);
	if (inbuf == NULL)
		err(1, "inbuf");

	/* handle some signals */
	installsignal(SIGINT, "INT");
	installsignal(SIGHUP, "HUP");
	installsignal(SIGQUIT, "QUIT");
	installsignal(SIGTERM, "TERM");

	for (offs = start; offs < size; offs += sz) {
		sz = MIN(size - offs, bs);

		rv = readoffset(offs, fd, inbuf, sz);
		if (rv == 0)
			errx(1, "unexpected eof");
		else if (rv == -1) {
			if (abort_on_error) {
				printf("read failed, aborting\n");
				goto done;
			}
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

		if (resfile) {
			if (ent_write(resfd, offs, sz, inbuf))
				errx(1, "can't write results");
		}

		if (!quiet) {
			p = 1 - (((double)size - (double)offs) / (double)size);
			printf("\r%.1f%%", p * 100);
			fflush(stdout);
		}

		if (running == 0) {
			if (!quiet)
				printf("terminating\n");
			break;
		}
	}
	if (!quiet && running == 1)
		printf("\r%.1f%%\n", 100.0);

done:
	fflush(ofd);
	fflush(resfd);
	fclose(ofd);
	fclose(resfd);
	close(fd);

	return (0);
}
