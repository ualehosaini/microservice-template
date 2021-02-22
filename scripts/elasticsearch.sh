#!/bin/bash
#script to pull and run elasticsearch v7.11 in single node inside a docker container

# If elasticsearch container is running, exit.
running_app_container=`docker ps | grep elasticsearch | wc -l`
if [ $running_app_container -gt "0" ]
then
	printf "container already running... \n"
	printf "press any key to close the terminal \n"	
	read junk
	exit 1
fi
		
# If elasticsearch container exists and is off, run.
existing_app_container=`docker ps -a | grep elasticsearch | grep Exit | wc -l`
if [ $existing_app_container -gt "0" ]
then
	printf "starting container... \n"
	docker start elasticsearch
	printf "container is now running \n"
	printf "press any key to close the terminal \n"
	read junk
	exit 1
fi
		
# Else, pull image and run.
printf "pulling image for elasticsearch... \n\n"
docker pull docker.elastic.co/elasticsearch/elasticsearch:7.11.0
printf "running container... \n\n"
docker run --name elasticsearch -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" docker.elastic.co/elasticsearch/elasticsearch:7.11.0
