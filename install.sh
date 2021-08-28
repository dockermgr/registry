#!/usr/bin/env bash
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
APPNAME="registry-web"
VERSION="202107311147-git"
USER="${SUDO_USER:-${USER}}"
HOME="${USER_HOME:-${HOME}}"
SRC_DIR="${BASH_SOURCE%/*}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#set opts

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
##@Version       : 202107311147-git
# @Author        : casjay
# @Contact       : casjay
# @License       : WTFPL
# @ReadME        : dockermgr --help
# @Copyright     : Copyright: (c) 2021 casjay, casjay
# @Created       : Saturday, Jul 31, 2021 11:47 EDT
# @File          : registry-web
# @Description   : registry-web docker container installer
# @TODO          :
# @Other         :
# @Resource      :
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Import functions
CASJAYSDEVDIR="${CASJAYSDEVDIR:-/usr/local/share/CasjaysDev/scripts}"
SCRIPTSFUNCTDIR="${CASJAYSDEVDIR:-/usr/local/share/CasjaysDev/scripts}/functions"
SCRIPTSFUNCTFILE="${SCRIPTSAPPFUNCTFILE:-testing.bash}"
SCRIPTSFUNCTURL="${SCRIPTSAPPFUNCTURL:-https://github.com/dfmgr/installer/raw/$GIT_DEFAULT_BRANCH/functions}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if [ -f "$PWD/$SCRIPTSFUNCTFILE" ]; then
  . "$PWD/$SCRIPTSFUNCTFILE"
elif [ -f "$SCRIPTSFUNCTDIR/$SCRIPTSFUNCTFILE" ]; then
  . "$SCRIPTSFUNCTDIR/$SCRIPTSFUNCTFILE"
else
  echo "Can not load the functions file: $SCRIPTSFUNCTDIR/$SCRIPTSFUNCTFILE" 1>&2
  exit 1
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# user system devenv dfmgr dockermgr fontmgr iconmgr pkmgr systemmgr thememgr wallpapermgr
dockermgr_install
__options "$@"
__sudo() { if sudo -n true; then eval sudo "$*"; else eval "$*"; fi; }
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Begin installer
APPNAME="registry-web"
DOCKER_HUB_URL="konradkleine/docker-registry-frontend:v2"
REGISTRY_WEB_SERVER_PORT="${REGISTRY_WEB_SERVER_PORT:-7080}"
REGISTRY_WEB_SERVER_HOST="${REGISTRY_WEB_SERVER_HOST:-$(hostname -f 2>/dev/null)}"
REPO="${DOCKERMGRREPO:-https://github.com/dockermgr}/$APPNAME"
REPO_BRANCH="${GIT_REPO_BRANCH:-main}"
REGISTRY_WEB_SERVER_TIMEZONE="${TZ:-${TIMEZONE:-America/New_York}}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if user_is_root; then
  APPDIR="$CASJAYSDEVDIR/$SCRIPTS_PREFIX/$APPNAME"
  INSTDIR="$CASJAYSDEVDIR/$SCRIPTS_PREFIX/$APPNAME"
  DATADIR="/srv/docker/$APPNAME"
else
  APPDIR="$HOME/.local/share/CasjaysDev/$SCRIPTS_PREFIX/$APPNAME"
  INSTDIR="$HOME/.local/share/CasjaysDev/$SCRIPTS_PREFIX/$APPNAME"
  DATADIR="$HOME/.local/share/srv/docker/$APPNAME"
fi
REPORAW="$REPO/raw/$REPO_BRANCH"
APPVERSION="$(__appversion "$REPORAW/version.txt")"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
__sudo mkdir -p "$DATADIR/data"
__sudo chmod -Rf 777 "$DATADIR"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if [ -f "$INSTDIR/docker-compose.yml" ] && cmd_exists docker-compose; then
  printf_blue "Installing containers using docker compose"
  sed -i "s|REPLACE_DATADIR|$DATADIR" "$INSTDIR/docker-compose.yml"
  if cd "$INSTDIR"; then
    __sudo docker-compose pull &>/dev/null
    __sudo docker-compose up -d &>/dev/null
  fi
else
  if docker ps -a | grep -qsw "$APPNAME"; then
    __sudo docker stop "$APPNAME" &>/dev/null
    __sudo docker rm -f "$APPNAME" &>/dev/null
  fi
  if [ -f "/etc/ssl/CA/CasjaysDev/certs/localhost.crt" ] && [ -f "/etc/ssl/CA/CasjaysDev/private/localhost.key" ]; then
    ## SSL
    __sudo docker run -d \
      --name="$APPNAME" \
      --hostname "$APPNAME" \
      --restart=unless-stopped \
      --privileged \
      -e SEARCH_BACKEND=sqlalchemy \
      -v /etc/ssl/CA:/etc/ssl/CA \
      -e REGISTRY_HTTP_TLS_CERTIFICATE=/etc/ssl/CA/CasjaysDev/certs/localhost.crt \
      -e REGISTRY_HTTP_TLS_KEY=/etc/ssl/CA/CasjaysDev/private/localhost.key \
      -e TZ="$REGISTRY_SERVER_TIMEZONE" \
      -v "$DATADIR/data":/data:z \
      -v "$DATADIR/config":/config:z \
      -p "$REGISTRY_SERVER_PORT":5000 \
      "$DOCKER_HUB_URL" &>/dev/null
  else
    __sudo docker run -d \
      --name="$APPNAME" \
      --hostname "$APPNAME" \
      --restart=unless-stopped \
      --privileged \
      -e SEARCH_BACKEND=sqlalchemy \
      -e TZ="$REGISTRY_SERVER_TIMEZONE" \
      -v "$DATADIR/data":/var/lib/registry:z \
      -p "$REGISTRY_SERVER_PORT":5000 \
      "$DOCKER_HUB_URL" &>/dev/null
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if docker ps -a | grep -qs "$APPNAME"; then
  printf_blue "Service is available at: http://$REGISTRY_WEB_SERVER_HOST:$REGISTRY_WEB_SERVER_PORT"
else
  false
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# End script
exit $?
