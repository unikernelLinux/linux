# SPDX-License-Identifier: GPL-2.0
#
# UKL Pledge Test Build
#
# To build the pledge test instead of tcp_server:
#   make clean
#   make TEST=pledge
#
# To build original tcp_server:
#   make clean
#   make
#

CFLAGS += -I usr/include -fno-PIC -mno-red-zone -mcmodel=kernel

# Default to tcp_server, use TEST=pledge to switch
TEST ?= tcp_server

ifeq ($(TEST),pledge)
  APP_SRC = pledge_test.c
  APP_OBJ = pledge_test.o
  APP_BIN = pledge_test
else
  APP_SRC = tcp_server.c
  APP_OBJ = tcp_server.o
  APP_BIN = tcp_server
endif

UKL.a: $(APP_OBJ) syscall.o userspace
	$(AR) cr UKL.a $(APP_OBJ) syscall.o
	objcopy --prefix-symbols=ukl_ UKL.a

$(APP_OBJ): $(APP_SRC)

syscall.o: syscall.S

userspace:
	gcc -o $(APP_BIN) $(APP_SRC)

clean:
	rm -f UKL.a *.o tcp_server pledge_test

.PHONY: clean userspace
