#
# Autoconf initialisation.
#
AC_INIT(test4v, 1.0)
AC_PREREQ(2.13)
AC_CONFIG_HEADERS(src/config.h)
AC_CONFIG_SRCDIR(src/common/include/utils.h)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

#
# Version management.
# +1    : 0     Interface changes breaking retro-compatibility.
# 0     : +1    Internal changes without lost of retro-compatibility.
#
VERSION_MAJOR=1
VERSION_MINOR=0
AC_DEFINE_UNQUOTED([VERSION_MAJOR], [$VERSION_MAJOR], [test4v major version number])
AC_DEFINE_UNQUOTED([VERSION_MINOR], [$VERSION_MINOR], [test4v minor version number])

#
# Standard checks.
#
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Compiler capabilities.
AC_C_INLINE
AC_C_CONST

# Required modules.
#PKG_CHECK_MODULES([LIBEVENT], [libevent])

# Output files
AC_OUTPUT([Makefile
	   src/Makefile
           src/socket-ops/Makefile
           src/spam/Makefile
	   ])
