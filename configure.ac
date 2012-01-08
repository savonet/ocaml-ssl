AC_INIT([ocaml-ssl],[0.4.6],[savonet-users@lists.sourceforge.net])

VERSION=$PACKAGE_VERSION
AC_MSG_RESULT([configuring $PACKAGE_STRING])

MINGW=`uname -s | grep -c "MINGW"`

OCAMLFIND_LDCONF=""
AC_ARG_ENABLE([ldconf], AS_HELP_STRING([--disable-ldconf],[don't modify the dynamic loader configuration file (default is enable)]),[ac_enable_ldconf=$enableval],[ac_enable_ldconf=$enableval],[ac_enable_ldconf=yes])
if test "$ac_enable_ldconf" = no ; then
	AC_MSG_RESULT([disabling modification of ld.conf])
	OCAMLFIND_LDCONF=dummy
fi

AC_CHECK_LIB(pthread, pthread_create)

# Check for Ocaml compilers

# we first look for ocamlc in the path; if not present, we fail
AC_CHECK_PROG(OCAMLC,ocamlc,`which ocamlc`,no)
if test "$OCAMLC" = no ; then
	AC_MSG_ERROR(Cannot find ocamlc.)
fi

# we look for the directory of ocamlc in $OCAMLC
OCAMLBIN=`dirname $OCAMLC`

# we extract Ocaml version number and library path
OCAMLVERSION=`$OCAMLC -v | sed -n -e 's|.*version* *\(.*\)$|\1|p' `
echo "ocaml version is $OCAMLVERSION"
OCAMLLIB=`$OCAMLC -v | tail -n 1 | cut -f 4 -d " "`
echo "ocaml library path is $OCAMLLIB"

# then we look for ocamlopt; if not present, we issue a warning
# if the version is not the same, we also discard it
# we set OCAMLBEST to "opt" or "byte", whether ocamlopt is available or not
AC_PATH_PROG(OCAMLOPT,ocamlopt,no)
OCAMLBEST=byte
if test "$OCAMLOPT" = no ; then
	AC_MSG_WARN(Cannot find ocamlopt; bytecode compilation only.)
else
	AC_MSG_CHECKING(ocamlopt version)
	TMPVERSION=`$OCAMLOPT -v | sed -n -e 's|.*version* *\(.*\)$|\1|p' `
	if test "$TMPVERSION" != "$OCAMLVERSION" ; then
	    AC_MSG_RESULT(differs from ocamlc; ocamlopt discarded.)
	    OCAMLOPT=no
	else
	    AC_MSG_RESULT(ok)
	    OCAMLBEST=opt
	fi
fi

# checking for ocamlc.opt
AC_PATH_PROG(OCAMLCDOTOPT,ocamlc.opt,no)
if test "$OCAMLCDOTOPT" != no ; then
	AC_MSG_CHECKING(ocamlc.opt version)
	TMPVERSION=`$OCAMLCDOTOPT -v | sed -n -e 's|.*version* *\(.*\)$|\1|p' `
	if test "$TMPVERSION" != "$OCAMLVERSION" ; then
	    AC_MSG_RESULT(differs from ocamlc; ocamlc.opt discarded.)
	else
	    AC_MSG_RESULT(ok)
	    OCAMLC=$OCAMLCDOTOPT
	fi
fi

# checking for ocamlopt.opt
if test "$OCAMLOPT" != no ; then
    AC_PATH_PROG(OCAMLOPTDOTOPT,ocamlopt.opt,no)
    if test "$OCAMLOPTDOTOPT" != no ; then
	AC_MSG_CHECKING(ocamlc.opt version)
	TMPVER=`$OCAMLOPTDOTOPT -v | sed -n -e 's|.*version* *\(.*\)$|\1|p' `
	if test "$TMPVER" != "$OCAMLVERSION" ; then
	    AC_MSG_RESULT(differs from ocamlc; ocamlopt.opt discarded.)
	else
	    AC_MSG_RESULT(ok)
	    OCAMLOPT=$OCAMLOPTDOTOPT
	fi
    fi
fi

if test "$OCAMLOPT" = no ; then
    BEST="bcl"
else
    BEST="bcl ncl"
fi

# ocamldep, ocamllex and ocamlyacc should also be present in the path
AC_PATH_PROG(OCAMLDEP,ocamldep,no)
if test "$OCAMLDEP" = no ; then
	AC_MSG_ERROR(Cannot find ocamldep.)
fi

AC_PATH_PROG(OCAMLLEX,ocamllex,no)
if test "$OCAMLLEX" = no ; then
	AC_MSG_ERROR(Cannot find ocamllex.)
fi

AC_PATH_PROG(OCAMLYACC,ocamlyacc,no)
if test "$OCAMLYACC" = no ; then
	AC_MSG_ERROR(Cannot find ocamlyacc.)
fi

AC_PATH_PROG(OCAMLDOC,ocamldoc,no)

AC_ARG_ENABLE([debugging],
   AS_HELP_STRING([--enable-debugging],[compile with debugging information (backtrace printing in particular)]))

if test "x$enable_debugging" = "xyes" ; then
  OCAMLFLAGS="$OCAMLFLAGS -g"
fi

AC_PATH_PROG(OCAMLMKTOP,ocamlmktop,no)
if test "$OCAMLMKTOP" = no ; then
	AC_MSG_ERROR(Cannot find ocamlmktop.)
fi

CAMLLIBPATH=`$OCAMLC -where`

AC_PROG_CC
if test "$MINGW" = 0; then
	AC_CHECK_LIB(ssl, SSL_new,,AC_MSG_ERROR(Cannot find libssl.))
else
	AC_CHECK_LIB(ssl, SSL_new,,AC_MSG_ERROR(Cannot find libssl.), [-lcrypto -lws2_32 -lgdi32 -lcrypt32])
fi
AC_CHECK_HEADER(openssl/ssl.h,,AC_MSG_ERROR(Cannot find libssl headers.))

# other progs
AC_PATH_PROG(OCAMLFIND,ocamlfind,no)
if test "$OCAMLFIND" = no ; then
	AC_MSG_ERROR(Cannot find ocamlfind.)
fi

AC_PATH_PROG(OCAMLCP,ocamlcp,no)
#if test "$OCAMLCP" = no ; then
#	AC_MSG_ERROR(Cannot find ocamlcp.)
#fi

AC_PATH_PROG(LATEX,latex,no)
#if test "$LATEX" = no ; then
#	AC_MSG_ERROR(Cannot find LaTeX.)
#fi

AC_PATH_PROG(DVIPS,dvips,no)
#if test "$DVIPS" = no ; then
#	AC_MSG_ERROR(Cannot find dvips.)
#fi

AC_PATH_PROG(PS2PDF,ps2pdf,no)
#if test "$PS2PDF" = no ; then
#	AC_MSG_ERROR(Cannot find ps2pdf.)
#fi

# substitutions to perform
AC_SUBST(VERSION)
AC_SUBST(OCAMLC)
AC_SUBST(OCAMLOPT)
AC_SUBST(OCAMLFLAGS)
AC_SUBST(BEST)
AC_SUBST(OCAMLDEP)
AC_SUBST(OCAMLLEX)
AC_SUBST(OCAMLYACC)
AC_SUBST(OCAMLBEST)
AC_SUBST(OCAMLVERSION)
AC_SUBST(OCAMLLIB)
AC_SUBST(OCAMLBIN)
AC_SUBST(OCAMLDOC)
AC_SUBST(OCAMLMKTOP)	# TODO
AC_SUBST(OCAMLFIND)	# TODO
AC_SUBST(OCAMLFIND_LDCONF)
AC_SUBST(OCAMLCP)	# TODO
AC_SUBST(CAMLLIBPATH)

AC_SUBST(LATEX)		# TODO
AC_SUBST(DVIPS)		# TODO
AC_SUBST(DVIPS)		# TODO
AC_SUBST(PS2PDF)	# TODO

# Finally create the Makefile and samples
AC_CONFIG_FILES([src/Makefile],[chmod a-w src/Makefile])
AC_CONFIG_FILES([src/META])
AC_OUTPUT
