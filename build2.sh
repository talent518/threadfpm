#!/bin/bash -l

php=${1:-phpts}

EXTENSION_DIR=/opt/$php/lib/extensions ./configure CFLAGS=-O2 CXXFLAGS=-O2 --prefix=/opt/$php --with-config-file-path=/opt/$php/etc --with-config-file-scan-dir=/opt/$php/etc/php.d --enable-maintainer-zts --with-tsrm-pthreads --enable-inline-optimization --enable-threadfpm --enable-threadfpm-debug --enable-embed --enable-fpm --with-fpm-systemd --with-fpm-acl --with-system-ciphers --with-zlib-dir=/usr --enable-bcmath --with-bz2 --enable-calendar --with-curl --with-enchant --enable-exif --enable-ftp --with-gd --with-webp-dir=/usr --with-jpeg-dir=/usr --with-png-dir=/usr --with-xpm-dir=/usr --with-freetype-dir=/usr --with-gettext --with-gmp --with-mhash --with-imap-ssl --enable-intl --enable-mbstring --with-mysqli=mysqlnd --enable-pcntl --enable-pdo --with-pdo-mysql --with-readline --enable-shmop --with-snmp --enable-soap --enable-sockets --enable-sysvmsg --enable-sysvsem --enable-sysvshm --with-xmlrpc --with-xsl --enable-mysqlnd --with-pear --with-kerberos --with-libxml-dir=/usr --enable-dom --enable-xml --enable-zip --with-libzip --with-icu-dir=/usr --with-tidy --enable-wddx --with-iconv-dir=/usr --with-zlib-dir=/usr --with-openssl --enable-zend-test=shared $2 && make -j4 && make install