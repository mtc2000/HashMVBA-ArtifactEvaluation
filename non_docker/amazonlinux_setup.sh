#!/bin/bash

set -x

cwd=$(pwd)
# Assume root access
# ADD `sudo` IF NEEDED

# Update and install development tools
yum update -y
yum groupinstall "Development Tools" -y
yum install -y \
    bison \
    flex \
    tmux \
    less \
    time \
    psmisc \
    wget \
    which \
    gmp-devel \
    libmpc-devel \
    openssl-devel

# Assume Python 3.9 is installed
yum install -y \
    python3-devel \
    python3-pip

yum remove -y python3-packaging
pip install wheel

# Download and build PBC library
cd /tmp
wget --no-check-certificate https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14
./configure
make
make install

# Set environment variables for library paths
echo 'export LIBRARY_PATH=/usr/local/lib' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/lib' >> ~/.bashrc
export LIBRARY_PATH=/usr/local/lib
export LD_LIBRARY_PATH=/usr/local/lib
source ~/.bashrc

# Download and install specific Charm version
cd /tmp
wget --no-check-certificate https://github.com/JHUISI/charm/archive/6ac1d445fa0bd81b880c1a83accd8791acd2594b.tar.gz
tar -xvf 6ac1d445fa0bd81b880c1a83accd8791acd2594b.tar.gz
mv charm-6ac1d445fa0bd81b880c1a83accd8791acd2594b charm
cd charm
./configure.sh
make install

# Assumes requirements.txt is in current directory
cd $cwd
pip install -r requirements.txt

echo please manually run the following command: 
echo '$ source ~/.bashrc'
