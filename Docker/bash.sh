#!/bin/bash

DOCKER_PS=$(docker ps -a -q -f name=hackdns)
if [ -n "$DOCKER_PS" ]; then
    docker exec -it $DOCKER_PS bash -c 'cd /hackdns/ && bash'
fi
