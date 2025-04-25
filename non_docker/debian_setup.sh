#!/bin/bash

set -x

cwd=$(pwd)

# Assume root access
# ADD `sudo` IF NEEDED

# Update and install required packages
apt-get update
# For Python 3.11
# apt-get -y install \
#     python3 python3-pip python3-dev python3-venv
# For Python 3.8
# Install required build dependencies
apt update
apt install -y \
  wget build-essential libssl-dev zlib1g-dev \
  libncurses5-dev libncursesw5-dev libreadline-dev \
  libsqlite3-dev libgdbm-dev libdb5.3-dev libbz2-dev \
  libexpat1-dev liblzma-dev tk-dev libffi-dev uuid-dev

# Download Python 3.8 source
cd /tmp
wget https://www.python.org/ftp/python/3.8.18/Python-3.8.18.tgz
tar -xf Python-3.8.18.tgz
cd Python-3.8.18

# Build and install
./configure --enable-optimizations
make -j"$(nproc)"
make install

# Check installation
python3 --version

apt-get -y install \
    bison flex libgmp-dev libmpc-dev libssl-dev \
    tmux less time psmisc wget curl build-essential

# Install PBC (Pairing-Based Cryptography Library)
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

# Install CHARM crypto library from specific commit
cd /tmp
# For Python 3.8
wget --no-check-certificate https://github.com/JHUISI/charm/archive/6ac1d445fa0bd81b880c1a83accd8791acd2594b.tar.gz
tar -xvf 6ac1d445fa0bd81b880c1a83accd8791acd2594b.tar.gz
mv charm-6ac1d445fa0bd81b880c1a83accd8791acd2594b charm
# For Python 3.11
# wget --no-check-certificate https://github.com/JHUISI/charm/archive/3e00d283712dec789375f75235fb35f11158c970.tar.gz
# tar -xvf 3e00d283712dec789375f75235fb35f11158c970.tar.gz
# mv charm-3e00d283712dec789375f75235fb35f11158c970 charm
cd charm
./configure.sh
make install

# Assumes requirements.txt is in current directory
cd $cwd
pip3 install wheel
pip3 install --break-system-packages -r requirements.txt

echo please manually run the following command: 
echo '$ source ~/.bashrc'
