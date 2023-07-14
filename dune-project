(lang dune 2.7)

(name ssl)
(version 0.7.0)

(generate_opam_files true)

(source
 (github melange-re/melange))

(maintainers "Antonio Monteiro <anmonteiro@gmail.com>")

(authors "Samuel Mimram <samuel.mimram@ens-lyon.org>")

(homepage "https://github.com/savonet/ocaml-ssl")

(bug_reports "https://github.com/savonet/ocaml-ssl/issues")

(license "LGPL-2.1-only WITH OCaml-LGPL-linking-exception")

(package
 (name ssl)
 (synopsis "Bindings for OpenSSL")
 (depends
  (ocaml
   (>= "4.03.0"))
  (ocaml (and :with_test (>= "4.08.0")))
  dune-configurator
  conf-libssl
  (alcotest :with-test)
  (bisect_ppx
   (and
    :dev
    (>= "2.5.0")))))
