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
