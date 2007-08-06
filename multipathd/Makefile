BUILD = glibc
EXEC = multipathd
SEND = mpathsend

include ../Makefile.inc

#
# basic flags setting
#
CFLAGS += -DDAEMON -I$(multipathdir) -I$(checkersdir)
LDFLAGS = -lpthread -ldevmapper -lsysfs -lreadline -lncurses

#
# debuging stuff
#
#CFLAGS += -DLCKDBG
#CFLAGS += -D_DEBUG_
#CFLAGS += -DLOGDBG

#
# object files
#
OBJS = main.o pidfile.o uxlsnr.o uxclnt.o cli.o cli_handlers.o \
       $(MULTIPATHLIB)-glibc.a $(CHECKERSLIB)-glibc.a \


#
# directives
#
all : $(BUILD)

glibc: $(EXEC) $(SEND)

klibc:
	$(MAKE) BUILD=glibc glibc

$(EXEC): clean $(OBJS)
	$(CC) $(OBJS) -o $(EXEC) $(LDFLAGS)

$(SEND): mpathsend.o
	$(CC) mpathsend.o -o $@ $(LDFLAGS)

$(CHECKERSLIB)-glibc.a:
	$(MAKE) -C $(checkersdir) BUILD=glibc glibc

$(MULTIPATHLIB)-glibc.a:
	$(MAKE) -C $(multipathdir) DAEMON=1 BUILD=glibc glibc

install:
	install -d $(DESTDIR)$(bindir)
	install -m 755 $(EXEC) $(DESTDIR)$(bindir)
	install -m 755 $(SEND) $(DESTDIR)$(bindir)
	install -d $(DESTDIR)$(rcdir)
	install -d $(DESTDIR)$(mandir)
	install -m 644 $(EXEC).8 $(DESTDIR)$(mandir)

uninstall:
	rm -f $(DESTDIR)$(bindir)/$(EXEC)
	rm -f $(DESTDIR)$(rcdir)/$(EXEC)
	rm -f $(DESTDIR)$(mandir)/$(EXEC).8

clean:
	$(MAKE) -C $(multipathdir) prepare DAEMON=1
	rm -f core *.o $(EXEC)

mpathsend.o: mpathsend.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -c mpathsend.c -o $@
