include ../Makefile.inc

CFLAGS += $(BIN_CFLAGS) -I$(multipathdir) -I$(mpathcmddir)
LIBDEPS += -L$(multipathdir) -lmultipath -lcmocka

TESTS := uevent parser util dmevents hwtable

.SILENT: $(TESTS:%=%.o)
.PRECIOUS: $(TESTS:%=%-test)

all:	$(TESTS:%=%.out)

# test-specific linker flags
# XYZ-test_OBJDEPS: object files from libraries to link in explicitly
#    That may be necessary if functions called from the object file are wrapped
#    (wrapping works only for symbols which are undefined after processing a
#    linker input file).
# XYZ-test_LIBDEPS: Additional libs to link for this test

dmevents-test_LIBDEPS = -lpthread -ldevmapper -lurcu
hwtable-test_OBJDEPS := ../libmultipath/discovery.o
hwtable-test_LIBDEPS := -ludev -lpthread

%.out:	%-test
	@echo == running $< ==
	@LD_LIBRARY_PATH=$(multipathdir):$(mpathcmddir) ./$< >$@

clean: dep_clean
	$(RM) $(TESTS:%=%-test) $(TESTS:%=%.out) $(TESTS:%=%.o) $(TESTS:%=%.o.wrap)

OBJS = $(TESTS:%=%.o)
.SECONDARY: $(OBJS)

include $(wildcard $(OBJS:.o=.d))

dep_clean:
	$(RM) $(OBJS:.o=.d)

%.o.wrap:	%.c
	@sed -n 's/^.*__wrap_\([a-zA-Z0-9_]*\).*$$/-Wl,--wrap=\1/p' $< | \
		sort -u | tr '\n' ' ' >$@

.SECONDEXPANSION:
%-test:	%.o %.o.wrap $$($$@_OBJDEPS) $(multipathdir)/libmultipath.so Makefile
	$(CC) $(OPTFLAGS) -o $@ $< $(LDFLAGS) $($@_OBJDEPS) $(LIBDEPS) $($@_LIBDEPS) $(file <$<.wrap)
