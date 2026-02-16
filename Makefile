CC	?= cc
CFLAGS	= -O2 -Wall -Wextra -Wunused -Wmissing-prototypes -Wstrict-prototypes
CFLAGS += -g

INSTALL_PROGRAM ?= install

PREFIX	?= /usr/local
BINDIR	?= $(PREFIX)/bin

PROG	= avahi-proxy
OBJS	= avahi-proxy.o

RC	= avahi_proxy.rc
RCDEST	= avahi_proxy

all: $(PROG)

clean:
	rm -f $(PROG) $(OBJS)

$(PROG): $(OBJS)
	$(CC) $(OBJS) -o $@

$(OBJS): *.c
	$(CC) $(CFLAGS) -c avahi-proxy.c -o $@

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	$(INSTALL_PROGRAM) -s $(PROG) $(DESTDIR)$(BINDIR)
	$(INSTALL_PROGRAM) $(RC) /etc/rc.d/$(RCDEST)

clean:
	rm -f $(PROG) $(OBJS)

.PHONY: all install clean
