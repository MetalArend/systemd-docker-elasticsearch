#Install a Nginx / Elastic Search docker container combo.

This file will install Docker and Docker-compose. It will also add the vagrant user to docker, and
add autocompletion for docker and docker-compose to bash. Configuration files will be created in a
temporary directory, used by docker-compose and the resulting containers.

Then it will start two containers: a Nginx container and an Elastic Search container. The Nginx
container is a proxy container to the Elastic Search container. It is only reachable over https on port 443.

##Installation

```
wget https://raw.githubusercontent.com/MetalArend/systemd-docker-elasticsearch/master/install.sh -O ./install.sh && bash install.sh
```

##Parameters

- For more options, check ```bash install.sh --help```

##Vagrant

- This script uses the packer created box found at https://github.com/MetalArend/ubuntu-16.04-server-amd64
- Always remove the box from vagrant if you changed the file in some way: ```vagrant box remove ubuntu-16.04-server-amd64```

