# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

TARGET := rss

LLC ?= llc
CLANG ?= clang
CC ?= gcc

XDP_C = ${TARGET:=_kern.c}
XDP_OBJ = ${XDP_C:.c=.o}
USER_C = ${TARGET:=_user.c}
USER_OBJ = ${USER_C:.c=.o}

# LIBS REQUIRED FOR USER PROG
OBJECT_NLATTR = ../kernel/tools/lib/bpf/nlattr.o
OBJECT_BTF = ../kernel/tools/lib/bpf/btf.o
OBJECT_BPF_SYSCALLS = ../kernel/tools/lib/bpf/bpf.o
OBJECT_LIBBPF = ../kernel/tools/lib/bpf/libbpf.o
OBJECTS = $(OBJECT_NLATTR) $(OBJECT_BTF) $(OBJECT_BPF_SYSCALLS) $(OBJECT_LIBBPF)

KERNEL ?= /lib/modules/$(shell uname -r)/build/

CFLAGS ?= -I../kernel/tools
CFLAGS += -I../kernel/tools/include
CFLAGS += -I../kernel/tools/lib

CFLAGS_LIBBPF ?= -I$(KERNEL)/tools/include
CFLAGS_LIBBPF += -I$(KERNEL)/tools/perf
CFLAGS_LIBBPF += -I$(KERNEL)/usr/include
CFLAGS_lIBBPF += -I$(KERNEL)/arch/x86/include

LDFLAGS = -lelf

all: llvm-check kernel-source-devel-headers $(TARGET) $(XDP_OBJ)

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -f $(OBJECTS)
	rm -f $(TARGET)
	rm -f $(XDP_OBJ)
	rm -f $(USER_OBJ)
	rm -f *.ll

kernel-source:
	@if [ ! -d $(KERNEL)/ ]; then \
		echo "(No source code located at $(KERNEL)) " ;\
		exit 1; \
	else true; fi

kernel-source-devel-headers: kernel-source
	@if [ ! -d $(KERNEL)/usr/include/ ]; then \
		echo "Error: Need kernel headers"; \
		echo "May need to run make headers_install within"; \
		echo "$(KERNEL)"; \
		exit 1; \
	else true; fi

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

# LIBBPF OBJECTS
$(OBJECTS): %.o: %.c
	$(CC) $(CFLAGS_LIBBPF) -o $@ -c $<

$(TARGET): %: %_user.c $(OBJECTS) Makefile
	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@ $<

$(XDP_OBJ): %.o: %.c
	$(CLANG) -S \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
