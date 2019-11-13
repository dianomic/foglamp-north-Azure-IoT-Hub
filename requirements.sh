#!/usr/bin/env bash

#
# Azure IoT
#

dir_name=$(pwd)

if [[ ! -e "${dir_name}/requirements.sh" ]]; then

    echo "ERROR: the working directory should be the one in which requirements.sh exists, executing ./requirements.sh"
fi

os_name=`(grep -o '^NAME=.*' /etc/os-release | cut -f2 -d\" | sed 's/"//g')`
os_version=`(grep -o '^VERSION_ID=.*' /etc/os-release | cut -f2 -d\" | sed 's/"//g')`
echo "Platform is ${os_name}, Version: ${os_version}"

if [[ $os_name == *"Red Hat"* || $os_name == *"CentOS"* ]]; then

        #TODO: implement CentOS
        echo "Not implemented yet"

elif apt --version 2>/dev/null; then

    sudo apt-get install -y cmake build-essential libssl-dev libcurl4-openssl-dev uuid-dev git-all
else
	echo "Requirements cannot be automatically installed, please refer README.rst to install requirements manually"
	exit 1
fi

# Creates the cmake tree
git clone https://github.com/Azure/azure-iot-sdk-c.git --recursive
mkdir ./azure-iot-sdk-c/cmake
cd    ./azure-iot-sdk-c/cmake
cmake -Dhsm_type_symm_key:BOOL=ON -Duse_prov_client:BOOL=ON  ..

# Builds libraries
cd ./azure-iot-sdk-c/cmake/provisioning_client/samples/prov_dev_client_sample
cmake --build . --target prov_dev_client_sample --config Debug

#// FIXME_I:
exit

cd /tmp

git clone https://github.com/akheron/jansson.git
git clone https://github.com/benmcollins/libjwt.git
git clone https://github.com/eclipse/paho.mqtt.c.git

#
# jansson
#
cd jansson
mkdir build
cd build
cmake ..
make && sudo make install

#
# libjwt
#
cd ../../libjwt
autoreconf -i
./configure
make  && sudo make install

#
# paho.mqtt.c
#
sudo apt-get install -y libssl1.0.0
cd ../paho.mqtt.c
make && sudo make install