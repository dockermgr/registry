#!/usr/bin/env bash

APPNAME="registry"
DOCKER_HUB_URL="registry"

sudo mkdir -p "$DATADIR" && chmod -Rf 777 "$DATADIR"

if docker ps -a | grep "$APPNAME" >/dev/null 2>&1; then
  sudo docker stop "$APPNAME"
  sudo docker rm -f "$APPNAME"
  sudo docker pull "$DOCKER_HUB_URL"
  sudo docker restart "$APPNAME"
else
  sudo docker run -d \
    -p 5000:5000 \
    --restart=always \
    --name "$APPNAME" \
    -v "$DATADIR":/var/lib/registry \
    -v /etc/ssl/CA:/etc/ssl/CA \
    -e REGISTRY_HTTP_TLS_CERTIFICATE=/etc/ssl/CA/CasjaysDev/certs/localhost.crt \
    -e REGISTRY_HTTP_TLS_KEY=/etc/ssl/CA/CasjaysDev/private/localhost.key \
    -e SEARCH_BACKEND=sqlalchemy \
    "$DOCKER_HUB_URL"
fi
