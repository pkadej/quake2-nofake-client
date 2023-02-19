# Makefile to use with linux gcc compiler
ifdef OLDGCC
	CC=gcc-2.7.2.3
	LIBCURL=../../src/libcurl-2.7.2.3.a
else
	CC=gcc
	LIBCURL=../../src/libcurl.a
endif

CFLAGS=-D__linux__ -D__i386__ -Dstricmp=strcasecmp -O2 -ffast-math \
	-funroll-loops -fexpensive-optimizations

DO_SHLIB_CC=$(CC) $(CFLAGS) -fPIC -o $@ -c $<

OBJS=nofake.o

AES_OBJS=aes/aescrypt.o aes/aeskey.o aes/aestab.o aes/aes_modes.o

MD5_OBJS=md5/md5.o

../nofake.so : $(OBJS) $(AES_OBJS) $(MD5_OBJS)
	$(CC) $(CFLAGS) -lpthread -shared -o $@ $(OBJS) $(AES_OBJS) $(MD5_OBJS) $(LIBCURL)
	
nofake.o : nofake.c
	$(DO_SHLIB_CC)

aes/aescrypt.o: aes/aescrypt.c aes/aes.h aes/aesopt.h aes/aestab.h aes/brg_endian.h aes/brg_types.h
	$(DO_SHLIB_CC)

aes/aeskey.o: aes/aeskey.c aes/aes.h aes/aesopt.h aes/aestab.h aes/brg_endian.h aes/brg_types.h
	$(DO_SHLIB_CC)

aes/aestab.o: aes/aestab.c aes/aes.h aes/aesopt.h aes/aestab.h aes/brg_endian.h aes/brg_types.h
	$(DO_SHLIB_CC)

aes/aes_modes.o: aes/aes_modes.c aes/aes.h aes/aesopt.h aes/aestab.h aes/brg_endian.h aes/brg_types.h
	$(DO_SHLIB_CC)

md5/md5.o: md5/md5.c md5/md5.h
	$(DO_SHLIB_CC)
