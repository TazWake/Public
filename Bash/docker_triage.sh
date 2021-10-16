#!/bin/bash

# This script gather triage data about containers on a target system
#
# Version 0.3

OUTPATH=$1
LOGFILE=$OUTPATH/collection_log.txt

# Check docker is running
if ! [ -x "$(command -v docker)" ]
then
    echo "*** Docker does not appear to be installed."
    echo "*** exiting."
    exit 255;
else
    echo -e "Collection commenced at $(date -u).\n\n" > $LOGFILE
fi

# Host data
echo "Collecting host metadata"
echo "**********************************************************" >> $OUTPATH/host_metadata.txt
echo -e "\nDOCKER VERSION\n" >> $OUTPATH/host_metadata.txt
echo -e "**********************************************************" >> $OUTPATH/host_metadata.txt
docker version >> $OUTPATH/host_metadata.txt
echo "Docker version data collected and stored in $OUTPATH/host_metadata.txt" >> $LOGFILE
echo -e "\n\n**********************************************************" >> $OUTPATH/host_metadata.txt
echo -e "\nDOCKER INFO\n" >> $OUTPATH/host_metadata.txt
echo "**********************************************************" >> $OUTPATH/host_metadata.txt
docker info >> $OUTPATH/host_metadata.txt
echo "**********************************************************" >> $OUTPATH/host_metadata.txt
echo "Docker container information data collected and stored in $OUTPATH/host_metadata.txt" >> $LOGFILE
echo -e "# File hash: $(md5sum $OUTPATH/host_metadata.txt). \n" >> $LOGFILE

# Image data
echo "Gathering list of available images"
docker image ls > $OUTPATH/docker_image_ls.txt
echo "Docker image ls output stored to $OUTPATH/docker_image_ls.txt" >> $LOGFILE
echo "# File hash: $(md5sum $OUTPATH/docker_image_ls.txt)" >> $LOGFILE

echo "Collecting image build history"
TMPZ=$(docker image ls | grep -v 'IMAGE ID' | awk '{ print $1 ":" $2}')
echo "Checking History" > $OUTPATH/docker_history.txt
echo -e "\nChecking image build history" >> $LOGFILE
for i in $TMPZ
do
    echo "### Checking history for $i ###" >> $OUTPATH/docker_history.txt
    echo "Checking history for $i, output stored in $OUTPATH/docker_history.txt" >> $LOGFILE
    docker history $i >> $OUTPATH/docker_history.txt
    docker inspect $i >> $OUTPATH/inspect_image_$(echo $i | cut -d: -f1).txt
    echo "  Image $i inspected. Output at $OUTPATH/inspect_image_$(echo $i | cut -d: -f1).txt" >> $LOGFILE
    echo "# File hash: $(md5sum $OUTPATH/inspect_image_$(echo $i | cut -d: -f1).txt)" >> $LOGFILE
done
echo "  Docker image history extracted to $OUTPATH/docker_history.txt" >> $LOGFILE
echo -e "# File hash: $(md5sum $OUTPATH/docker_history.txt). \n" >> $LOGFILE
echo "Build history complete."

# Container data
echo "Gathering information on running containers."
echo "Checking running container data." >> $LOGFILE
docker container ls > $OUTPATH/containers_active.txt
echo "Currently running containers listed at $OUTPATH/containers_active.txt" >> $LOGFILE
echo "# File hash: $(md5sum $OUTPATH/containers_active.txt)" >> $LOGFILE
TMPZ=$(docker container ls | grep -v 'CONTAINER ID' | awk '{ print $1":"$2}')
echo -e "Container inspect output\n" > $OUTPATH/container_inspect.txt
echo -e "Container logs output\n" > $OUTPATH/container_logs.txt
echo -e "Running Processes\n" > $OUTPATH/running_processes.txt
echo 
for i in $TMPZ
do
    ID=$(echo $i | cut -d: -f1)
    FN=$(echo $i | cut -d: -f2)
    echo "### Checking $FN ###" >> $OUTPATH/container_inspect.txt
    echo "  Inspecting containers: $FN, output stored in $OUTPATH/container_inspect.txt" >> $LOGFILE
    docker inspect $FN >> $OUTPATH/container_inspect.txt
    echo "  Checking logs: $FN, output stored in $OUTPATH/container_logs.txt" >> $LOGFILE
    echo "### Checking $FN ###" >> $OUTPATH/container_logs.txt
    docker logs $ID >> $OUTPATH/container_logs.txt
    echo "### Checking $FN ###" >> $OUTPATH/running_processes.txt
    echo "  Running processes: $FN, output stored in $OUTPATH/running_processes.txt" >> $LOGFILE
    docker top $ID >> $OUTPATH/running_processes.txt
done
echo "Container inspection and log extraction complete."
echo "# File hash: $(md5sum $OUTPATH/container_inspect.txt)" >> $LOGFILE
echo "# File hash: $(md5sum $OUTPATH/container_logs.txt)" >> $LOGFILE
echo "# File hash: $(md5sum $OUTPATH/running_processes.txt)" >> $LOGFILE

# Create Snapshot
echo "Creating snapshots."
echo -e "\nCreating container snapshot(s) at $(date -u)" >> $LOGFILE
TMPZ=$(docker container ls | grep -v 'CONTAINER ID' | awk '{ print $1":"$2}')
for i in $TMPZ
do
    ID=$(echo $i | cut -d: -f1)
    NM=$(echo $i | cut -d: -f2)
    FN=$(echo $NM)_evidence_$(date -u +%Y%m%d)
    echo "Creating a snapshot of the $FN container."
    docker commit $ID $FN
    docker save $FN | gzip > $OUTPATH/$FN.tar.gz
    echo "Snapshot completed."
    echo "Snapshot of $FN container saved to $OUTPATH/$FN.tar.gz." >> $LOGFILE
    echo "# File hash: $(md5sum $OUTPATH/$FN.tar.gz)" >> $LOGFILE
    docker image rm $(docker image ls | grep "$FN" | awk '{ print $3 }')
    echo "Evidence snapshot removed from repository."
done
echo -e "Snapshots completed - all running containers have been captured.\n" >> $LOGFILE
echo "Snapshots completed."

echo "Collection completed. Your data is at $OUTPATH."
echo -e "\n\nTriage collection completed at $(date -u)" >> $LOGFILE
