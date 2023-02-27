## 👋 Welcome to registry 🚀  

registry README  
  
  
## Requires scripts to be installed  

```shell
 sudo bash -c "$(curl -q -LSsf "https://github.com/systemmgr/installer/raw/main/install.sh")"
 systemmgr --config && systemmgr install scripts  
```

## Automatic install/update  

```shell
dockermgr update registry
```

OR

```shell
mkdir -p "$HOME/.local/share/srv/docker/registry/dataDir"
git clone "https://github.com/dockermgr/registry" "$HOME/.local/share/CasjaysDev/dockermgr/registry"
cp -Rfva "$HOME/.local/share/CasjaysDev/dockermgr/registry/dataDir/." "$HOME/.local/share/srv/docker/registry/dataDir/"
```

## via command line  

```shell
docker pull casjaysdevdocker/registry:latest && \
docker run -d \
--restart always \
--privileged \
--name casjaysdevdocker-registry \
--hostname casjaysdev-registry \
-e TZ=${TIMEZONE:-America/New_York} \
-v $HOME/.local/share/srv/docker/registry/dataDir/data:/data:z \
-v $HOME/.local/share/srv/docker/registry/dataDir/config:/config:z \
-p 80:80 \
casjaysdevdocker/registry:latest
```

## via docker-compose  

```yaml
version: "2"
services:
  registry:
    image: casjaysdevdocker/registry
    container_name: registry
    environment:
      - TZ=America/New_York
      - HOSTNAME=casjaysdev-registry
    volumes:
      - $HOME/.local/share/srv/docker/registry/dataDir/data:/data:z
      - $HOME/.local/share/srv/docker/registry/dataDir/config:/config:z
    ports:
      - 80:80
    restart: always
```

## Author  

📽 dockermgr: [Github](https://github.com/dockermgr) 📽  
🤖 casjay: [Github](https://github.com/casjay) [Docker](https://hub.docker.com/r/casjay) 🤖  
⛵ CasjaysDevDocker: [Github](https://github.com/casjaysdevdocker) [Docker](https://hub.docker.com/r/casjaysdevdocker) ⛵  
