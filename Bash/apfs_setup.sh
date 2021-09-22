#!/bin/sh

# #######################################
# # This script sets up an Ubuntu-based #
# # Linux system to be able to mount    #
# # and examine evidence images in APFS #
# # format.                             #
# #######################################

#
# Use:
# ./apfs_setup.sh
#
# Notes:
# This script must be run with root permissions.
# This script only works on systems that use apt.
# 
# THANK YOU
# This script is only possible because https://github.com/sgan81/apfs-fuse exists!


# Check Requirements
if [[ $EUID != 0 ]]; then
    echo "[!] This script must be run with root privileges!"
    echo "[!] Exiting"
    exit 255;
else
    echo "Initial check completed, script is running with correct privileges."
fi

# Update repos.
echo "Updating repositories. You might get prompted for answers."
apt update
apt install libicu-dev bzip2 cmake libz-dev libbz2-dev fuse3 libfuse3-3 libfuse3-dev clang git libattr1-dev libplist-utils git -y
echo "Requirement installation complete."

# Install apfs-fuse
echo "Installing apfs-fuse."
cd /opt
git clone https://github.com/sgan81/apfs-fuse.git
cd apfs-fuse
git submodule init
git submodule update

# Build
echo "Building apfs-fuse"
mkdir build
cd build
cmake ..
make

# Set up links
echo "build complete"
ln /opt/afps-fuse/build/apfs-dump /usr/bin/apfs-dump
ln /opt/afps-fuse/build/apfs-dump-quick /usr/bin/apfs-dump-quick
ln /opt/afps-fuse/build/apfs-fuse /usr/bin/apfs-fuse
ln /opt/afps-fuse/build/apfsutil /usr/bin/apfsutil
echo "Script complete. The apfs-fuse has been built and binaries linked to /usr/bin."
echo ""
echo "You can now mount an APFS evidence item with: apfs-fuse -o ro,allow_other IMAGE MOUNTPOINT"
