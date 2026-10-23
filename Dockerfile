# ChainProof ships as one container that carries both halves of the thesis:
# PHP runs the adversarial agents, Foundry/Anvil provide the on-chain judge.
#
# The three image arguments exist so a restricted network can point at a
# registry mirror without editing the file, e.g.
#   docker compose build --build-arg PHP_IMAGE=docker.m.daocloud.io/library/php:8.3-cli
ARG COMPOSER_IMAGE=composer:2
ARG FOUNDRY_IMAGE=ghcr.io/foundry-rs/foundry:stable
ARG PHP_IMAGE=php:8.3-cli

FROM ${COMPOSER_IMAGE} AS composer
FROM ${FOUNDRY_IMAGE} AS foundry

FROM ${PHP_IMAGE}

ENV COMPOSER_ALLOW_SUPERUSER=1 \
    COMPOSER_NO_INTERACTION=1 \
    PHP_MEMORY_LIMIT=512M

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git unzip procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer /usr/bin/composer /usr/bin/composer
COPY --from=foundry /usr/local/bin/forge /usr/local/bin/cast /usr/local/bin/anvil /usr/local/bin/chisel /usr/local/bin/

WORKDIR /app

# Resolve PHP dependencies before copying source so edits do not bust the cache.
COPY composer.json ./
RUN composer install --no-dev --prefer-dist --no-progress --no-scripts

COPY bin ./bin
COPY config ./config
COPY foundry ./foundry
COPY prompts ./prompts
COPY public ./public
COPY src ./src
COPY templates ./templates
COPY .env ./.env

RUN mkdir -p var/runs var/cache var/log \
    && php bin/console about --env=dev >/dev/null \
    && cd foundry && forge build

EXPOSE 8000 8545

CMD ["php", "-S", "0.0.0.0:8000", "-t", "public", "public/index.php"]
