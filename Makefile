PROGNAME = ocaml-ssl
DISTFILES = bootstrap CHANGES configure configure.ac COPYING Makefile README \
            src/Makefile.in src/OCamlMakefile src/META.in src/*.ml src/*.mli src/*.c \
            examples/configure* examples/Makefile*.in examples/OCamlMakefile examples/Makefile examples/*.ml \
            doc/html
VERSION := $(shell grep 'AC_INIT' configure.ac| sed -e 's/AC_INIT([^,]*,\[\([^,]*\)\],.*)/\1/')

all byte opt install uninstall update:
	$(MAKE) -C src $@

doc:
	mkdir -p doc/html
	ocamldoc -html -stars -d doc/html $(wildcard src/*.mli)

clean:
	-$(MAKE) -C src clean
	-$(MAKE) -C examples clean

distclean: clean
	rm -rf autom4te.cache config.log config.status
	rm -rf doc
	rm -f src/META src/Makefile
	-$(MAKE) -C examples distclean

dist: doc
	mkdir $(PROGNAME)-$(VERSION)
	cp -R -L --parents $(DISTFILES) $(PROGNAME)-$(VERSION)
	tar zcvf $(PROGNAME)-$(VERSION).tar.gz $(PROGNAME)-$(VERSION)
	rm -rf $(PROGNAME)-$(VERSION)

.PHONY: all byte opt doc install uninstall update clean distclean dist
