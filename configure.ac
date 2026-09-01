AC_INIT([nesca4], [20240926])
AC_PREREQ([2.69])

dnl configure

echo ""
echo "RUNNING CONFIGURE NESCA4"
echo ""

LIBNCSNET_PATH="libncsnet/libncsnet.a"
CFLAGS="-Wall -g"
OCFLAGS="-O3"

AC_SUBST(CFLAGS)
AC_SUBST(OCFLAGS)

AC_CONFIG_SRCDIR([nesca4.cc])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_CXX


dnl check libncsnet

AC_CHECK_FILE([$LIBNCSNET_PATH], [LIBNCSNET_FOUND=no=yes], [LIBNCSNET_FOUND=no])
if test "$LIBNCSNET_FOUND" = "no"; then
  echo "library (libncsnet.a) not found, configuring ncsnet"
  echo ""
  echo "RUNNING CONFIGURE LIBNCSNET/"
  echo ""
  (cd libncsnet && ./configure && cd ..)
else
  echo "library (libncsnet.a) found, no need to configure and make ncsnet"
fi

dnl check libssh (optional, enables SSH bruteforce)

LIBS_EXTRA=""
AC_CHECK_HEADER([libssh/libssh.h],
  [AC_CHECK_LIB([ssh], [ssh_new],
    [AC_DEFINE([HAVE_LIBSSH], [1], [libssh is available, SSH bruteforce enabled])
     LIBS_EXTRA="$LIBS_EXTRA -lssh"
     echo "libssh found, SSH bruteforce enabled"],
    [echo "libssh library not found, SSH bruteforce disabled"])],
  [echo "libssh headers not found, SSH bruteforce disabled"])
AC_SUBST(LIBS_EXTRA)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT


