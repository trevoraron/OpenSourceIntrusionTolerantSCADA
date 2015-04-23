.SUFFIXES: .lo .to .tlo

prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
libdir=${exec_prefix}/lib
includedir=${prefix}/include
mandir=${datarootdir}/man
mansubdir=man
sysconfdir=${prefix}/etc
datarootdir=${prefix}/share
datadir=${datarootdir}
docdir=${datadir}/doc/libspread-util
piddir=@piddir@
srcdir=.
top_srcdir=..
buildtoolsdir=$(top_srcdir)/buildtools

DESTDIR=


PATHS= 

INSTALL=/usr/bin/install -c
SOFTLINK=ln -s
PERL=/usr/bin/perl

MANPAGES	= E_get_time.3.out libspread-util.3.out
MANPAGES_IN	= E_get_time.3 libspread-util.3 

PAGENAMES = E_get_time libspread-util

# Misc documentation files in docs/ directory that should be installed
DOCFILES = Readme.txt license.txt

MANTYPE		= doc


all: $(MANPAGES)

$(MANPAGES): $(MANPAGES_IN)
	@if test "$(MANTYPE)" = "cat"; then \
		manpage=$(srcdir)/`echo $@ | sed 's/\.[1-9]\.out$$/\.0/'`; \
	else \
		manpage=$(srcdir)/`echo $@ | sed 's/\.out$$//'`; \
	fi; \
	if test "$(MANTYPE)" = "man"; then \
		cat $${manpage} | $(PERL) $(buildtoolsdir)/mdoc2man.pl > $@; \
	else \
		cat $${manpage} > $@; \
	fi

clean:
	rm -f *.out 

distclean: clean
	rm -f Makefile config.h config.status *~

mrproper: distclean

veryclean: distclean
	rm -f configure

catman-do:
	@for f in $(MANPAGES_IN) ; do \
		base=`echo $$f | sed 's/\..*$$//'` ; \
		echo "$$f -> $$base.0" ; \
		nroff -mandoc $$f | cat -v | sed -e 's/.\^H//g' \
			>$$base.0 ; \
	done

distprep: catman-do
	autoreconf

install: install-files install-man

install-man:
	$(buildtoolsdir)/mkinstalldirs $(DESTDIR)$(mandir)
	$(buildtoolsdir)/mkinstalldirs $(DESTDIR)$(mandir)/$(mansubdir)3
	for page in $(PAGENAMES); \
	do \
	  $(INSTALL) -m 644 $$page.3.out $(DESTDIR)$(mandir)/$(mansubdir)3/$$page.3; \
	done

install-files:
	$(buildtoolsdir)/mkinstalldirs $(DESTDIR)$(docdir)
	for docfile in $(DOCFILES); \
	do \
	  $(INSTALL) -m 644 $(srcdir)/$$docfile $(DESTDIR)$(docdir)/$$docfile; \
	done

uninstallall:	uninstall
	-rmdir $(DESTDIR)$(sysconfdir)
	-rmdir $(DESTDIR)$(docdir)
	-rmdir $(DESTDIR)$(mandir)/$(mansubdir)3
	-rmdir $(DESTDIR)$(mandir)

uninstall: 
	for page in $(PAGENAMES); \
	do \
	  rm -f $(DESTDIR)$(mandir)/$(mansubdir)3/$$page.3; \
	done
	for docfile in $(DOCFILES); \
	do \
	  rm -f $(DESTDIR)$(docdir)/$$docfile; \
	done
