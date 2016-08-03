#!/usr/bin/env bash

set -e

CWD="$(cd $(dirname $0); pwd)"

##
# Read defaults
##

CACHE_DIR=".cache"
USERNAME="elasticsearch"
PASSWORD="not-secure"
SSL_KEY=""
SSL_CERT=""
PORT="443"

while [[ ${1} ]]; do
    PARAMETER="${1:2}"

    case "${PARAMETER}" in
        cache-dir)
            CACHE_DIR=${2}
            shift
            ;;
        username)
            USERNAME=${2}
            shift
            ;;
        password)
            PASSWORD=${2}
            shift
            ;;
        ssl-key)
            SSL_KEY=${2}
            shift
            ;;
        ssl-certificate)
            SSL_CERT=${2}
            shift
            ;;
        port)
            PORT=${2}
            shift
            ;;
        help)
            echo -e ''
            echo -e 'Install a Nginx / Elastic Search docker container combo.'
            echo -e 'This file will install Docker and Docker-compose. It will also add the vagrant user to docker, and'
            echo -e 'add autocompletion for docker and docker-compose to bash. Configuration files will be created in a'
            echo -e 'temporary directory, used by docker-compose and the resulting containers.'
            echo -e 'Then it will start two container: a Nginx container and an Elastic Search container. The Nginx'
            echo -e 'container is a proxy container to the Elastic Search container. It is only reachable over port 443.'
            echo -e ''
            echo -e 'Use the following parameters to overwrite the default settings:'
            echo -e '\e[1;40;36m--username\e[0m  \e[2m"elasticsearch"\e[0m username to use for the HTTP Basic Authentication'
            echo -e '\e[1;40;36m--password\e[0m  \e[2m"not-secure"\e[0m    password to use for the HTTP Basic Authentication'
            echo -e '\e[1;40;36m--ssl-key\e[0m   \e[2mauto-generated\e[0m  path to a SSL key'
            echo -e '\e[1;40;36m--ssl-cert\e[0m  \e[2mauto-generated\e[0m  path to a SSL certifate'
            echo -e '\e[1;40;36m--port\e[0m      \e[2m"443"\e[0m           port to open'
            echo -e '\e[1;40;36m--cache-dir\e[0m \e[2m".cache"\e[0m        name for the cache directory'
            echo -e ''
            exit 0
            ;;
        *)
            echo "Unknown parameter \"${PARAMETER}\"" >&2
            exit 1
    esac

    if ! shift; then
        echo 'Missing argument' >&2
        exit 1
    fi
done

##
# Install Docker & Docker Compose
##

if test ! $(command -v docker 2>/dev/null); then
    echo -e "\e[1;40;33mInstall certificates\e[0m"
    sudo apt-get update && sudo apt-get install apt-transport-https ca-certificates

    echo -e "\e[1;40;33mAdd repositories\e[0m"
    # more info: https://docs.docker.com/engine/installation/ubuntulinux/#update-your-apt-sources
    sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
    mkdir -p /etc/apt/sources.list.d
    sudo sh -c "echo deb https://apt.dockerproject.org/repo ubuntu-xenial main > /etc/apt/sources.list.d/docker.list"
    sudo apt-get update

    echo -e "\e[1;40;33mPurge lxc\e[0m"
    sudo apt-get purge lxc-docker

    echo -e "\e[1;40;33mInstall Docker\e[0m"
    # more info: https://docs.docker.com/engine/installation/ubuntulinux/#install
    sudo apt-get -y -q install linux-image-extra-$(uname -r)
    sudo apt-get -y -q install docker-engine

    echo -e "\e[1;40;33mAdd vagrant user to docker group\e[0m"
    sudo usermod -aG docker vagrant
    awk -F ':' '/docker/{print $4}' /etc/group

    echo -e "\e[1;40;33mEnable docker service on boot\e[0m"
    sudo systemctl enable docker

    echo -e "\e[1;40;33mStart docker service\e[0m"
    sudo systemctl start docker
    sudo systemctl --full --no-pager status docker
fi

if test ! $(command -v docker-compose 2>/dev/null); then
    echo -e "\e[1;40;33mInstall Docker Compose\e[0m"
    sudo apt-get -y -q install curl
    sudo curl -sSL https://github.com/docker/compose/releases/download/1.7.1/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

if test ! -f /etc/bash_completion.d/docker-compose; then
    echo -e "\e[1;40;33mInstall bash completion\e[0m"
    sudo apt-get -y -q install curl
    sudo bash -c "curl -sSL https://raw.githubusercontent.com/docker/compose/$(docker-compose version --short)/contrib/completion/bash/docker-compose -o /etc/bash_completion.d/docker-compose"
fi

##
# Enable swap
##

if test -n "$(cat "/etc/sysctl.conf" | grep "vm.swappiness = 1")"; then
    echo -e "\e[1;40;33mConfigure swappiness to swap only when necessary\e[0m"
    # more info: https://www.elastic.co/guide/en/elasticsearch/guide/current/heap-sizing.html#_swapping_is_the_death_of_performance
    # more info: http://askubuntu.com/questions/103915/how-do-i-configure-swappiness
    sudo bash -c "echo 'vm.swappiness = 1' >> /etc/sysctl.conf" && sudo sysctl -p
fi

##
# Create config directory
##

mkdir -p "${CWD}/${CACHE_DIR}/"

##
# Create ssl key
##

if test -n "${SSL_KEY}" && test -f "${SSL_KEY}"; then
    cp -f "${SSL_KEY}" "${CWD}/${CACHE_DIR}/key.pem"
fi
if test -n "${SSL_CERT}" && test -f "${SSL_CERT}"; then
    cp -f "${SSL_CERT}" "${CWD}/${CACHE_DIR}/cert.pem"
fi
if test -z "${SSL_KEY}" || test -z "${SSL_CERT}"; then
    echo -e "\e[1;40;33mGenerate self-signed certificate\e[0m"
    # Generate self signed certificate - ONLY FOR LOCAL CONFIGURATION
    openssl req -newkey rsa:2048 -days 365 -nodes -x509 -subj "/C=BE/O=KU Leuven/CN=KU Leuven" -keyout "${CWD}/${CACHE_DIR}/key.pem" -out "${CWD}/${CACHE_DIR}/cert.pem"
fi

##
# Create htpasswd file
# more info: https://en.wikipedia.org/wiki/Htpasswd
# more info: http://man7.org/linux/man-pages/man8/chpasswd.8.html
# more info: https://en.wikipedia.org/wiki/SHA-2
##

echo -e "\e[1;40;33mEnabling HTTP Basic Authentication\e[0m"
echo -n "${USERNAME}:$(openssl passwd -crypt ${PASSWORD})" > "${CWD}/${CACHE_DIR}/.htpasswd"
echo "${USERNAME} ${PASSWORD}"

##
# Create Elastic Search configuration
# more info: https://www.elastic.co/guide/en/elasticsearch/reference/1.7/setup-configuration.html
# more info: https://www.elastic.co/guide/en/elasticsearch/reference/1.7/modules-scripting.html
##

echo -e "\e[1;40;33mCreate Elastic Search configuration\e[0m"
cat <<EOF | sudo tee "${CWD}/${CACHE_DIR}/elasticsearch.yml"
script.inline: off
script.indexed: off
EOF
cat <<EOF | sudo tee "/etc/systemd/system/docker-elasticsearch.service"
[Unit]
Description = Elastic Search Service
After = docker.service
Requires = docker.service
BindsTo = docker.service
Conflicts = shutdown.target reboot.target halt.target

[Service]
RestartForceExitStatus = 0
StartLimitInterval = 20
StartLimitBurst = 5
TimeoutStartSec = 600
TimeoutStopSec = 30
Restart = always
RestartSec = 10

ExecStartPre = -/usr/local/bin/docker-compose --project elasticsearch --file "${CWD}/${CACHE_DIR}/docker-compose.yml" kill elasticsearch
ExecStart = /usr/local/bin/docker-compose --project elasticsearch --file "${CWD}/${CACHE_DIR}/docker-compose.yml" up --force-recreate --no-deps elasticsearch
ExecStop = /usr/local/bin/docker-compose --project elasticsearch --file "${CWD}/${CACHE_DIR}/docker-compose.yml" stop elasticsearch
ExecStopPost = /usr/local/bin/docker-compose --project elasticsearch --file "${CWD}/${CACHE_DIR}/docker-compose.yml" rm -f -v elasticsearch

NotifyAccess = all

[Install]
WantedBy = multi-user.target
EOF

##
# Create Nginx configuration
# more info: https://www.elastic.co/blog/playing-http-tricks-nginx
# more info: http://nginx.org/en/docs/http/ngx_http_auth_basic_module.html
# more info: http://nginx.org/en/docs/http/configuring_https_servers.html
##

echo -e "\e[1;40;33mCreate Nginx configuration\e[0m"
cat <<EOF | sudo tee "${CWD}/${CACHE_DIR}/nginx.conf"
server {
    listen 443 ssl;

    ssl_certificate cert.pem;
    ssl_certificate_key key.pem;

    auth_basic "Username and password are required";
    auth_basic_user_file .htpasswd;

    location / {
        proxy_pass http://elasticsearch:9200;
    }
}
EOF
cat <<EOF | sudo tee "/etc/systemd/system/docker-nginx.service"
[Unit]
Description = Nginx Service
After = docker.service docker-elasticsearch.service
Requires = docker.service docker-elasticsearch.service
Conflicts = shutdown.target reboot.target halt.target

[Service]
RestartForceExitStatus = 0
StartLimitInterval = 20
StartLimitBurst = 5
TimeoutStartSec = 600
TimeoutStopSec = 30
Restart = always
RestartSec = 10

ExecStartPre = -/usr/local/bin/docker-compose --project elasticsearch --file "${CWD}/${CACHE_DIR}/docker-compose.yml" kill nginx
ExecStart = /usr/local/bin/docker-compose --project elasticsearch --file "${CWD}/${CACHE_DIR}/docker-compose.yml" up --force-recreate --no-deps nginx
ExecStop = /usr/local/bin/docker-compose --project elasticsearch --file "${CWD}/${CACHE_DIR}/docker-compose.yml" stop nginx
ExecStopPost = /usr/local/bin/docker-compose --project elasticsearch --file "${CWD}/${CACHE_DIR}/docker-compose.yml" rm -f -v nginx

NotifyAccess = all

[Install]
WantedBy = multi-user.target
EOF

##
# Create Docker Compose configuration
##

echo -e "\e[1;40;33mCreate Docker Compose configuration\e[0m"
cat <<EOF | sudo tee "${CWD}/${CACHE_DIR}/docker-compose.yml"
version: "2"

services:

  elasticsearch:
    image: elasticsearch:1.7
    volumes:
    - ./elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml
    expose:
    - "9200"
    networks:
    - back

  nginx:
    image: nginx
    depends_on:
    - elasticsearch
    links:
    - elasticsearch
    volumes:
    - ./nginx.conf:/etc/nginx/conf.d/default.template
    - ./key.pem:/etc/nginx/key.pem
    - ./cert.pem:/etc/nginx/cert.pem
    - ./.htpasswd:/etc/nginx/.htpasswd
    ports:
    - "${PORT}:443"
    command: /bin/bash -c "envsubst < /etc/nginx/conf.d/default.template > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"
    networks:
    - proxy
    - back

networks:
  proxy:
  back:
EOF

##
# Build containers
##

echo -e "\e[1;40;33mBuild containers (~ creating cache)\e[0m"
sudo docker-compose --project elasticsearch --file "${CWD}/${CACHE_DIR}/docker-compose.yml" up -d --force-recreate

##
# Enable/Start Elastic Search service
##

echo -e "\e[1;40;33mEnable/Start Elastic Search service\e[0m"
sudo systemctl enable docker-elasticsearch
sudo systemctl start docker-elasticsearch
sudo systemctl --full --no-pager status docker-elasticsearch

##
# Enable/Start Nginx service
##

echo -e "\e[1;40;33mEnable/Start Nginx service\e[0m"
sudo systemctl enable docker-nginx
sudo systemctl start docker-nginx
sudo systemctl --full --no-pager status docker-nginx

##
# Check containers
##

check_connection () {
    MAX_FAILS=20
    TIME_BEGIN=$(date +%s)
    FAILS=0
    while true; do
        if ! nc -z -w 1 ${2} ${3}; then
            FAILS=$[FAILS + 1]
            if test ${FAILS} -gt ${MAX_FAILS}; then
                echo -e "\033[2K\r\e[1;40;31m${1} not responding (timeout)\e[0m" >&2
                return 1
            fi
            TIME_PASSED="$[$(date +%s) - $TIME_BEGIN]"
            echo -ne "\033[2K\rWait for ${1} at ${2}:${3} - ${TIME_PASSED} seconds \033[0K\r" >&2
            sleep 1
            continue
        fi
        echo -e "\033[2K\e[1;40;32m${1} at ${2}:${3} ready!\e[0m" >&2
        return 0
    done
}

echo -e "\e[1;40;33mCheck containers\e[0m"

ELASTICSEARCH_ID=$(sudo docker-compose --project elasticsearch --file "${CWD}/${CACHE_DIR}/docker-compose.yml" ps -q elasticsearch)
ELASTICSEARCH_IP=$(sudo docker inspect --format="{{ .NetworkSettings.Networks.elasticsearch_back.IPAddress }}" ${ELASTICSEARCH_ID})
if test "true" != "$(sudo docker inspect --format="{{ .State.Running }}" ${ELASTICSEARCH_ID})"; then
    echo -e "\e[1;40;31mElastic Search container failed to run!\e[0m"
    exit 1
else
    check_connection "Elastic Search" ${ELASTICSEARCH_IP} 9200
fi

NGINX_ID=$(sudo docker-compose --project elasticsearch --file "${CWD}/${CACHE_DIR}/docker-compose.yml" ps -q nginx)
NGINX_IP=$(sudo docker inspect --format="{{ .NetworkSettings.Networks.elasticsearch_proxy.IPAddress }}" ${NGINX_ID})
if test "true" != "$(sudo docker inspect --format="{{ .State.Running }}" ${NGINX_ID})"; then
    echo -e "\e[1;40;31mNginx container failed to run!\e[0m"
    exit 1
else
    check_connection "Nginx" ${NGINX_IP} 443
fi

sleep 0.1

echo -e "\e[1;40;33mCheck request\e[0m"
# more info: http://curl.haxx.se/docs/manpage.html
# While making request require SSL, allow self signed certificate, login with use of HTTP Basic Auth
sudo curl -sS https://127.0.0.1:${PORT} --ssl-reqd --insecure --user ${USERNAME}:${PASSWORD}

echo -e "\e[1;40;33mReport environment\e[0m"
echo -e "\e[1;40;32m$(sudo docker --version) ready!\e[0m"
echo -e "\e[1;40;32m$(sudo docker-compose --version) ready!\e[0m"
echo -e "\e[1;40;32murl: https://$(ifconfig | grep 192.168 | awk '{print $2}' | awk -F ':' '{print $2}'):${PORT}\e[0m"
echo -e "\e[1;40;32musername: ${USERNAME}\e[0m"
echo -e "\e[1;40;32mpassword: ${PASSWORD}\e[0m"


