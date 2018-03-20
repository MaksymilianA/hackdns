#!/bin/bash

if docker --version 2>/dev/null; then
     printf " + Docker found!\n";
else
     printf " >>> ERROR: docker command not found. Install docker first.\n\n"; exit 1;
fi

if docker ps -a 2>/dev/null; then
     printf " + dockerd ps success.\n";
else
     printf " >>> ERROR: dockerd not working? Check docker status\n\n"; exit 1;
fi


DOCKER_PS=$(docker ps -a -q -f name=hackdns)
if [ -n "$DOCKER_PS" ]; then
    printf "\n\nERROR: hackdns already installed\n\n"
    exit;
fi

docker build -t hackdns .

docker run --name hackdns -d -it hackdns
