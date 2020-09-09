#!/usr/bin/env bash

mkdir -p /srv/docker/registry && chmod -Rf 777 /srv/docker/registry

docker run -d \
-p 5000:5000 \
--restart=always \
--name registry \
-v /srv/docker/registry:/var/lib/registry \
-e SEARCH_BACKEND=sqlalchemy \
-v /etc/ssl/CA:/etc/ssl/CA \
-e REGISTRY_HTTP_TLS_CERTIFICATE=/etc/ssl/CA/CasjaysDev/certs/localhost.crt \
-e REGISTRY_HTTP_TLS_KEY=/etc/ssl/CA/CasjaysDev/private/localhost.key \
registry
