#!/usr/bin/env bash

APPNAME="registry"
DATADIR="/srv/docker/$APPNAME"

mkdir -p "$DATADIR" && chmod -Rf 777 "$DATADIR"

if docker ps -a | grep "$APPNAME" >/dev/null 2>&1; then
docker pull registry:v2 && docker restart $APPNAME
else
docker run -d \
-p 5000:5000 \
--restart=always \
--name "$APPNAME" \
-v $DATADIR:/var/lib/registry \
-v /etc/ssl/CA:/etc/ssl/CA \
-e REGISTRY_HTTP_TLS_CERTIFICATE=/etc/ssl/CA/CasjaysDev/certs/localhost.crt \
-e REGISTRY_HTTP_TLS_KEY=/etc/ssl/CA/CasjaysDev/private/localhost.key \
-e SEARCH_BACKEND=sqlalchemy \
registry
fi
