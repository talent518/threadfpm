#!/bin/bash -l

php=${1:-phpts}

EXTENSION_DIR=/opt/$php/lib/extensions ./configure CFLAGS=-O2 CXXFLAGS=-O2 --prefix=/opt/$php --with-config-file-path=/opt/$php/etc --with-config-file-scan-dir=/opt/$php/etc/php.d --enable-zts --enable-threadfpm --enable-threadfpm-debug --enable-embed --enable-fpm --with-fpm-systemd --with-fpm-acl --enable-phpdbg --with-openssl --with-kerberos --with-system-ciphers --with-zlib --enable-bcmath --with-bz2 --enable-calendar --with-curl --enable-dba=shared --with-enchant --enable-exif --with-ffi --enable-ftp --enable-gd --with-external-gd --with-webp --with-jpeg --with-xpm --with-freetype --enable-gd-jis-conv --with-gettext --with-gmp --with-mhash --with-imap --with-kerberos --with-imap-ssl --enable-intl --with-ldap --with-ldap-sasl --enable-mbstring --with-mysqli --enable-pcntl --with-pdo-mysql --with-pspell --with-libedit --with-readline --enable-shmop --with-snmp --enable-soap --enable-sockets --enable-sysvmsg --enable-sysvsem --enable-sysvshm --with-tidy --with-expat --with-xsl --enable-zend-test=shared --with-zip --enable-mysqlnd $ZTS && make -j4 && make install
