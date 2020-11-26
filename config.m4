PHP_ARG_ENABLE([threadfpm],,
  [AS_HELP_STRING([--enable-threadfpm],
    [Enable building of the threadfpm SAPI executable])],
  [no],
  [no])

PHP_ARG_ENABLE([threadfpm-debug],,
  [AS_HELP_STRING([--enable-threadfpm-debug],
    [Enable threadfpm debug info for syslog])],
  [no])

if test "$PHP_THREADFPM_DEBUG" != "no"; then
  CFLAGS="$CFLAGS -DTHREADFPM_DEBUG"
fi

AC_MSG_CHECKING(for THREADFPM build)
if test "$PHP_THREADFPM" != "no"; then
  AC_MSG_RESULT($PHP_THREADFPM)

  PHP_ADD_MAKEFILE_FRAGMENT([$abs_srcdir/sapi/threadfpm/Makefile.frag])

  SAPI_THREADFPM_PATH=sapi/threadfpm/threadfpm

  PHP_THREADFPM_CFLAGS="-I$abs_srcdir/sapi/threadfpm -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1"
  PHP_THREADFPM_FILES="threadfpm.c hash.c"

  PHP_SELECT_SAPI(threadfpm, program, $PHP_THREADFPM_FILES, $PHP_THREADFPM_CFLAGS, '$(SAPI_THREADFPM_PATH)')

  case $host_alias in
      *aix*)
        BUILD_THREADFPM="echo '\#! .' > php.sym && echo >>php.sym && nm -BCpg \`echo \$(PHP_GLOBAL_OBJS) \$(PHP_BINARY_OBJS) \$(PHP_THREADFPM_OBJS) | sed 's/\([A-Za-z0-9_]*\)\.lo/\1.o/g'\` | \$(AWK) '{ if (((\$\$2 == \"T\") || (\$\$2 == \"D\") || (\$\$2 == \"B\")) && (substr(\$\$3,1,1) != \".\")) { print \$\$3 } }' | sort -u >> php.sym && \$(LIBTOOL) --mode=link \$(CC) -export-dynamic \$(CFLAGS_CLEAN) \$(EXTRA_CFLAGS) \$(EXTRA_LDFLAGS_PROGRAM) \$(LDFLAGS) -Wl,-brtl -Wl,-bE:php.sym \$(PHP_RPATHS) \$(PHP_GLOBAL_OBJS) \$(PHP_BINARY_OBJS) \$(PHP_FASTCGI_OBJS) \$(PHP_THREADFPM_OBJS) \$(EXTRA_LIBS) \$(THREADFPM_EXTRA_LIBS) \$(ZEND_EXTRA_LIBS) -pthread -o \$(SAPI_THREADFPM_PATH)"
        ;;
      *darwin*)
        BUILD_THREADFPM="\$(CC) \$(CFLAGS_CLEAN) \$(EXTRA_CFLAGS) \$(EXTRA_LDFLAGS_PROGRAM) \$(LDFLAGS) \$(NATIVE_RPATHS) \$(PHP_GLOBAL_OBJS:.lo=.o) \$(PHP_BINARY_OBJS:.lo=.o) \$(PHP_FASTCGI_OBJS:.lo=.o) \$(PHP_THREADFPM_OBJS:.lo=.o) \$(PHP_FRAMEWORKS) \$(EXTRA_LIBS) \$(THREADFPM_EXTRA_LIBS) \$(ZEND_EXTRA_LIBS) -pthread -o \$(SAPI_THREADFPM_PATH)"
      ;;
      *)
        BUILD_THREADFPM="\$(LIBTOOL) --mode=link \$(CC) -export-dynamic \$(CFLAGS_CLEAN) \$(EXTRA_CFLAGS) \$(EXTRA_LDFLAGS_PROGRAM) \$(LDFLAGS) \$(PHP_RPATHS) \$(PHP_GLOBAL_OBJS) \$(PHP_BINARY_OBJS) \$(PHP_FASTCGI_OBJS) \$(PHP_THREADFPM_OBJS) \$(EXTRA_LIBS) \$(THREADFPM_EXTRA_LIBS) \$(ZEND_EXTRA_LIBS) -pthread -o \$(SAPI_THREADFPM_PATH)"
      ;;
  esac

  PHP_SUBST(SAPI_THREADFPM_PATH)
  PHP_SUBST(BUILD_THREADFPM)

else
  AC_MSG_RESULT(no)
fi
