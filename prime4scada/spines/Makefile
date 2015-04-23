include ../Makefile.general

.PHONY: all clean distclean


top_srcdir=..

all: libspines.a

libspines.a: spines_lib.o ../libspread-util/lib/libspread-util.a ../stdutil/lib/libstdutil.a
	$(AR) x ../libspread-util/lib/libspread-util.a
	$(AR) x ../stdutil/lib/libstdutil.a
	$(AR) rv $@ *.o *.to
	$(RANLIB) $@

libspines-core.a: spines_lib.o
	$(AR) rv $@ spines_lib.o
	$(RANLIB) $@

clean:
	rm -f *.o
	rm -f *.to
	rm -f libspines.a
	rm -f libspines-core.a

distclean: clean
	rm -f *~
	rm -f core*
	rm -f Makefile
