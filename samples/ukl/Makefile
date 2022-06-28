# SPDX-License-Identifier: GPL-2.0

CFLAGS += -I usr/include -fno-PIC -mno-red-zone -mcmodel=kernel

UKL.a: tcp_server.o syscall.o userspace
	$(AR) cr UKL.a tcp_server.o syscall.o
	objcopy --prefix-symbols=ukl_ UKL.a

tcp_server.o: tcp_server.c
syscall.o: syscall.S

userspace:
	gcc -o tcp_server tcp_server.c

clean:
	rm -f UKL.a tcp_server.o syscall.o tcp_server
