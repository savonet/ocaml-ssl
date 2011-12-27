all: stelnet stalkd

clean:
	$(MAKE) -f Makefile.stelnet clean
	$(MAKE) -f Makefile.stalkd clean

distclean: clean
	rm -rf autom4te.cache config.log config.status
	rm -f Makefile.stelnet Makefile.stalkd

stelnet:
	$(MAKE) -f Makefile.stelnet

stalkd:
	$(MAKE) -f Makefile.stalkd

.PHONY: stelnet stalkd
