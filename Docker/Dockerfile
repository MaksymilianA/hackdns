FROM php:7.1-apache
#FROM php:5.6-apache


RUN apt update
RUN apt install vim mysql-client -y

RUN docker-php-source extract \
    # do important things \
    && docker-php-source delete
    
RUN apt-get install -y \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libmcrypt-dev \
        libpng12-dev \
        mc \
    && docker-php-ext-install -j$(nproc) iconv mcrypt \
    && docker-php-ext-configure gd --with-freetype-dir=/usr/include/ --with-jpeg-dir=/usr/include/ \
    && docker-php-ext-install -j$(nproc) gd mysqli
    
RUN rm -rf /var/log/apache2/*    

