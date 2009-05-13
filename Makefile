# $diskrescue$

PROG=diskrescue
MAN=diskrescue.8

SRCS= diskrescue.c
COPT+= -O2
#DEBUG+= -ggdb3 
CFLAGS+= -Wall

.include <bsd.prog.mk>
