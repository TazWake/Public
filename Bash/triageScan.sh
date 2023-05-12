#!/bin/bash

# ###############
# ## IMPORTANT ##
# ###############

# This is an example of running a scaled triage
# it is not designed to be used "as is" and is
# unlikely to work without significant modification.

# ###############
# ## ^^^^^^^^^ ##
# ###############

# OUTLINE & USE
# This script is based on the DFIR team wanting to run a triage collection tool on all devices in a subnet
# To use it, you need to modify the data to match your local circumstances.
# You need an account which has SSH access to the target systems - this is shown as "responder" in the script
# You also need a triage collection tool. This example uses CyLR https://github.com/orlikoski/CyLR - but this should be changed to whatever tool you use.

for i in {1..254} # Modify this to include the range of IP addresses you want to run it against.
do
  ssh responder@10.10.10.$i 'mkdir DFIR' # This is creating a folder to hold the tool and evidence
  scp CyLR responder@10.10.10.$i:/home/responder/DFIR/ # Modify this to match your chosen tool or script
  ssh responder@10.10.10.$i 'cd DFIR && chmod +x CyLR && ./CyLR -od /home/responder/DFIR -of evidence_collection.zip' # Modify this to meet the command line arguments your tool needs and remember to make the tool executable.
  scp responder@10.10.10.$i:/home/responder/DFIR/evidence_collection.zip ./10.10.10.$i_evidence_collection.zip # Download the output evidence
  # Consider adding logic to validate the download and remove it from the endpoint to reduce disk use.
  # for example ssh responder@10.10.10.$i 'md5sum /home/responder/DFIR/evidence_collection.zip' then compare this with the local MD5 if they match run ssh responder@10.10.10.$i 'rm /home/responder/DFIR/evidence_collection.zip'
done
