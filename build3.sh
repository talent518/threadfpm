#!/bin/bash -l

if [ -z "$ANDROID_ROOT" -o ! "$HOME" = "/data/data/com.termux/files/home" ]; then
    echo "Isn't android termux"
    exit 1
fi

php=${1:-phpts}
opt=$(dirname $PREFIX)/opt

EXTENSION_DIR=$opt/$php/lib/extensions ./configure CFLAGS=-O2 CXXFLAGS=-O2 --prefix=$opt/$php --with-config-file-path=$opt/$php/etc --with-config-file-scan-dir=$opt/$php/etc/php.d --enable-maintainer-zts --with-tsrm-pthreads --enable-inline-optimization --enable-threadfpm --enable-threadfpm-debug --enable-embed --enable-fpm --enable-phpdbg --with-openssl --with-kerberos --with-system-ciphers --with-zlib --enable-bcmath --with-bz2=$PREFIX --enable-calendar --with-curl --enable-dba=shared --enable-exif --with-ffi --enable-ftp --enable-gd --with-webp --with-jpeg --with-xpm --with-freetype --with-gmp --with-mhash --with-kerberos --enable-mbstring --disable-mbregex --with-mysqli --enable-pcntl --with-pdo-mysql --with-libedit --with-readline --enable-soap --enable-sockets --with-tidy=$PREFIX --with-expat --with-xmlrpc --with-xsl --enable-zend-test=shared --with-zip --enable-mysqlnd --with-iconv=$PREFIX $2 && sed -i 's|#define HAVE_RES_NSEARCH 1|//#define HAVE_RES_NSEARCH 1|g' main/php_config.h && LDFLAGS='-llog -lc' make -j4 && make install
