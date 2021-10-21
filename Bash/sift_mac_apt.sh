#!/bin/bash

# This script configures an Ubuntu SIFT workstation to
# use the macOS (and IOS) Artifact Parsing Tool
# 
# The tool was created by Yogesh Khatri (@swiftforensics)
# https://github.com/ydkhatri/mac_apt
# NOTE:
# This script assumes pip will call python3-pip and that python will call python 3.7+
#
# ############ WARNING ############
# This script uses the potentially 
# dangerous --ignore-installed
# switch on pip3 to avoid an issue
# with PyYAML. This may leave your
# system unstable. If this is an 
# issue, consider using VENV.
# ############ WARNING ############

# Check Requirements
if [[ $EUID != 0 ]]; then
    echo "[!] This script must be run with root privileges!"
    echo "[!] Exiting"
    exit 255;
else
    echo "[ ] Initial check completed, script is running with correct privileges."
fi

# Update repos.
echo "[ ] Updating repositories. You might get prompted for answers."
apt update && apt install -y python3-pip python3-dev libbz2-dev zlib1g-dev

# Clone gits
echo -e "\n\n\n[*] Seting up mac_apt now."
cd /opt
wget https://github.com/libyal/libewf-legacy/releases/download/20140808/libewf-20140808.tar.gz
tar xzf libewf-20140808.tar.gz
rm libewf-20140808.tar.gz
cd /opt/libewf-20140808
python setup.py build
python setup.py install
cd /opt 
git clone https://github.com/ydkhatri/mac_apt
cd /opt/mac_apt
pip3 install ./other_dependencies/pyaff4-0.31-yk.zip --ignore-installed
pip3 install anytree biplist construct==2.9.45 xlsxwriter plistutils kaitaistruct lz4 pytsk3==20170802 libvmdk-python==20181227 pycryptodome cryptography pybindgen==0.21.0 pillow pyliblzfse nska_deserialize
cd 
# Install completed

echo "[ ] Install Completed."
echo "[ ] You can now run mac_apt as follows"
echo "python /opt/mac_apt/mac_apt.py -h"

