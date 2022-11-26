dnl $Id$
dnl 
dnl Process this file with autoconf to produce a configure script.
AC_INIT(sauron)
AC_CONFIG_AUX_DIR(aux)


AC_CANONICAL_HOST
HOST_TYPE=$host
AC_DEFINE_UNQUOTED(HOST_TYPE,"$host")

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LN_S

PERL_DB_BACKEND="DB-DBI.pm"

AC_ARG_WITH(DBI, [  --with-DBI              use DBI module (default) ],
	[ if test $withval = yes; then
            PERL_DB_BACKEND="DB-DBI.pm" 
          fi
          echo "foo: $withval"
        ])

AC_ARG_WITH(Pg, [  --with-Pg               use Pg module instead of default DBI (DBD::Pg) ],
	[ if test $withval = yes; then
            PERL_DB_BACKEND="DB-Pg.pm" 
          fi
          echo "foo: $withval"
        ])

AC_PATH_PROG(PERL,perl)

dnl Checks for libraries.


dnl Checks for header files.


dnl Checks for typedefs, structures, and compiler characteristics.


dnl Checks for library functions.
AC_SUBST(PERL_DB_BACKEND)

echo "------------------------------------------------------------"
echo "Selected Perl Database backend: $PERL_DB_BACKEND"
echo "------------------------------------------------------------"


AC_OUTPUT(Makefile)


