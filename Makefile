.PHONY: build clean test install uninstall clean all-supported-ocaml-versions

build:
	dune build @default

test:
	dune runtest

install:
	dune install

uninstall:
	dune uninstall

clean:
	dune clean

all-supported-ocaml-versions:
	dune build @default @runtest --workspace dune-workspace.dev

install-dev:
	opam install -y opam-query opam-publish tls

VERSION      := $$(opam query --version)
NAME_VERSION := $$(opam query --name-version)
ARCHIVE      := $$(opam query --archive)

release:
	git tag -a $(VERSION) -m "Version $(VERSION)."
	git push origin $(VERSION)
	opam publish prepare $(NAME_VERSION) $(ARCHIVE)
	cp descr $(NAME_VERSION)
	grep -Ev '^(name|version):' opam >$(NAME_VERSION)/opam
	opam publish submit $(NAME_VERSION)
	rm -rf $(NAME_VERSION)
