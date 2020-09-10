FROM composer:1.10.10 as composer

WORKDIR /usr/src/php-pcap

COPY composer.* /usr/src/php-pcap/

RUN composer install --no-scripts --no-suggest --no-interaction --prefer-dist --optimize-autoloader

COPY . /usr/src/php-pcap

RUN composer dump-autoload --optimize --classmap-authoritative

FROM php:7.4-cli-alpine

WORKDIR /usr/src/php-pcap

COPY . /usr/src/php-pcap

COPY --from=composer /usr/src/php-pcap/vendor /usr/src/php-pcap/vendor

CMD ["php", "-i"]
