#!/bin/bash

# This script runs a basic assessment against a  running docker container.
#
# The syntax is:
#     dockAnlyze.sh CONTAINER OutputPath
#
# Example:
#     dockAnlyze.sh SUSPICIOUS_JOLIOT /cases/evidence/
#
# The container must be running and the output path must exist.

# set up variables:
CONTAINER=$1
OUTPATH=$2
# Check and remove trailing slash from the output path if it exists
OUTPATH=${OUTPATH%/}
LOGFILE=$OUTPATH/collection_log.txt
TEMPNAME=$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)
TEMPFILE=$OUTPATH/$TEMPNAME

# CHECK PERMS
if [[ $EUID != 0 ]]; then
    echo "[!] This script must be run with root privileges!"
    echo "[!] Exiting"
    exit 255;
else
    echo "- Running with correct privileges."
fi

# Check output path
touch $TEMPFILE
if [ -f $TEMPFILE  ]; then
    echo "- Write to output location successful."
    rm $TEMPFILE
else
    echo "[!] Unable to write to output location."
    echo "[!] Exiting."
    exit 255;
fi

# Check container exists and if so, capture its Container ID

if [[ $(docker inspect -f '{{.State.Running}}' $CONTAINER) != "true" ]]; then
    echo "[!] The container is not running."
    exit 255;
else
    CONTAINERID=$(docker ps -qf "name=$CONTAINER")
fi


# INITIAL HOST REVIEW

# ## Inform user

echo "! Running triage on $CONTAINER."
echo "! Collecting initial metadata."

# ## Start logging.
echo -e "File open\nAnalysis started at: $(date +%Y-%m-%dT%H:%M:%S)" >> $LOGFILE
echo -e "This assessment is running against the $CONTAINER container, Container ID: $CONTAINERID\n" >> $LOGFILE
echo -e "\n******************************************************\nInitial Metadata collection started at: $(date +%Y-%m-%dT%H:%M:%S)." >> $LOGFILE

# ## Get the version details
HOSTDATA=$OUTPATH/hostdata.txt
echo -e "Docker Version" >> $HOSTDATA
echo -e "**************" >> $HOSTDATA
docker version 2>/dev/null >> $HOSTDATA
echo -e "**************" >> $HOSTDATA
# ## Get the host info
echo -e "Docker Info" >> $HOSTDATA
echo -e "***********" >> $HOSTDATA
docker info 2>/dev/null >> $HOSTDATA
echo -e "***********" >> $HOSTDATA

# ## Identify key metadata
KEYDATA=$OUTPATH/keydata.txt
echo ". Host metadata collected."
echo -e "Initial Metadata collection completed at: $(date +%Y-%m-%dT%H:%M:%S)\nStarting key data extraction." >> $LOGFILE
echo -e "Key Metadata" >> $KEYDATA
echo -e "************" >> $KEYDATA
grep -A20 'Server' $HOSTDATA | grep 'API version' >> $KEYDATA
echo -e ". Key Data:\n $(grep -A10 Server $HOSTDATA | grep 'API version')"
grep -A20 'Server' $HOSTDATA | grep 'Built' >> $KEYDATA
echo -e " $(grep -A20 'Server' $HOSTDATA | grep 'Built')"
grep 'Kernel Version' $HOSTDATA >> $KEYDATA
echo -e "  $(grep 'Kernel Version' $HOSTDATA)"
grep 'Operating System' $HOSTDATA >> $KEYDATA
echo -e "  $(grep 'Operating System' $HOSTDATA)"
grep 'Swarm' $HOSTDATA >> $KEYDATA
echo -e "  $(grep 'Swarm' $HOSTDATA)"
grep 'Runtimes' $HOSTDATA >> $KEYDATA
echo -e "  $(grep 'Runtimes' $HOSTDATA)"
grep 'Registry' $HOSTDATA >> $KEYDATA
echo -e "  $(grep 'Registry' $HOSTDATA)"
echo -e "\nKey data extracted from metadata at $(date +%Y-%m-%dT%H:%M:%S)\n******************************************************" >> $LOGFILE
echo ". Key metadata logged."

# ## Inspect container
INSPECT=$OUTPATH/docker_inspect.txt
echo ". Inspecting the container."
echo -e "\nRunning docker inspect at $(date +%Y-%m-%dT%H:%M:%S)\n" >> $LOGFILE
docker inspect $CONTAINER > $INSPECT
echo ". Inspection complete. Review the file at $INSPECT to identify any configuration issues."

# ## Create snapshot
EVIDENCENAME="evidence_$(date +%Y-%m-%d)"
SAVE=$OUTPATH/$EVIDENCENAME.tar.gz
echo ". Creating Snapshot."
echo -e "************\nPrelimary Data Collected\nTaking Snapshot at $(date +%Y-%m-%dT%H:%M:%S)\n" >> $LOGFILE
docker commit $CONTAINER $EVIDENCENAME
docker save $EVIDENCENAME | gzip > $SAVE
echo -e "Snapshot SHA256 Hash: $(sha256sum $SAVE)" >> $LOGFILE
echo -e "Snapshot Complete at: $(date +%Y-%m-%dT%H:%M:%S)\n" >> $LOGFILE
echo ". Snapshot complete."

# ## Capture logs
DOCKLOGS=$OUTPATH/container_logs.txt
DISKLOGS=$OUTPATH/${CONTAINER}_logsFromDisk.tar.gz
echo ". Capturing docker logs."
echo -e "\nCollecting container logs at $(date +%Y-%m-%dT%H:%M:%S)\n" >> $LOGFILE
docker logs $CONTAINER >> $DOCKLOGS
echo -e "Running container logs collected at $(date +%Y-%m-%dT%H:%M:%S)\nCopying files from disk as confirmation." >> $LOGFILE
CONTAINERDIR=$(ls /var/lib/docker/containers | grep $CONTAINERID)
tar -czf $DISKLOGS -C /var/lib/docker/containers/$CONTAINERDIR .
echo -e "Disk logs collected at $(date +%Y-%m-%dT%H:%M:%S)\n" >> $LOGFILE
echo ". Log collection completed."

# ## Capture running processes
PROCESSES=$OUTPATH/processes.txt
echo ". Collecting running processes"
echo -e "\nCollecting running proceses at $(date +%Y-%m-%dT%H:%M:%S)\n" >> $LOGFILE
docker top $CONTAINER > $PROCESSES
echo -e "Process collection complete at $(date +%Y-%m-%dT%H:%M:%S)\n" >> $LOGFILE
echo ". Running processes collected."

# ## hash the evidence
echo -e "\nCollection complete, generating SHA256 hashes" >> $LOGFILE
# ## hashes of HOSTDATA, KEYDATA, INSPECT, DOCKLOGS, $OUTPATH/$CONTAINER_logs_fromDisk.tar.gz, and PROCESSES are required.
for file in $HOSTDATA $KEYDATA $INSPECT $DOCKLOGS $DISKLOGS $PROCESSES; do
    sha256sum $file >> $LOGFILE
done
echo -e "\n******************************************************\nHashing complete at $(date +%Y-%m-%dT%H:%M:%S)" >> $LOGFILE

# ## Notify user
echo "! Collection complete."
echo "  Data is stored in $OUTPATH."
echo "  A log of activity is at $LOGFILE."
echo "  The SHA256 hash of the log is $(sha256sum $LOGFILE)"
echo "[x] Exited"
