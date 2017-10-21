AC_INIT([ocaml-ssl],[0.5.5],[savonet-users@lists.sourceforge.net])

VERSION=$PACKAGE_VERSION
AC_MSG_RESULT([configuring $PACKAGE_STRING])

AC_BASE_CHECKS()

if test "$OCAMLOPT" = no ; then
    BEST="bcl"
else
    BEST="bcl ncl"
fi

AC_SUBST(BEST)

MINGW=`$CC -dumpmachine | grep -c mingw`

if test "$MINGW" != 0; then
   OTHER_LIBS="-lcrypto -lws2_32 -lgdi32 -lcrypt32 -lz"
fi

AC_CHECK_LIB(ssl,SSL_new,,AC_MSG_ERROR(Cannot find libssl.),[$OTHER_LIBS])
AC_CHECK_HEADER(openssl/ssl.h,,AC_MSG_ERROR(Cannot find libssl headers.))
AC_CHECK_LIB(ssl,TLSv1_1_method,[CFLAGS="$CFLAGS -DHAVE_TLS11"],,[$OTHER_LIBS])
AC_CHECK_LIB(ssl,TLSv1_2_method,[CFLAGS="$CFLAGS -DHAVE_TLS12"],,[$OTHER_LIBS])
AC_CHECK_LIB(crypto,EC_KEY_free,[CFLAGS="$CFLAGS -DHAVE_EC"],,[$OTHER_LIBS])
AC_CHECK_DECL([SSL_set_tlsext_host_name], [CFLAGS="$CFLAGS -DHAVE_SNI"], [], [[#include <openssl/ssl.h>]])

# Finally create the Makefile and samples
AC_CONFIG_FILES([src/Makefile],[chmod a-w src/Makefile])
AC_CONFIG_FILES([src/META])
AC_OUTPUT
