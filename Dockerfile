FROM php:7.4-fpm
RUN apt-get update && apt-get install -y \
		libfreetype6-dev \
		libjpeg62-turbo-dev \
		libpng-dev \
		libzip-dev \
		git \
	&& docker-php-ext-configure gd --with-freetype --with-jpeg \
	&& docker-php-ext-configure zip \
	&& docker-php-ext-install -j$(nproc) gd zip

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

VOLUME /srv/api
WORKDIR /srv/api

COPY composer.json ./


