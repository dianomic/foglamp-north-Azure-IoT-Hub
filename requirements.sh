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

# TODO : to be verified
sudo apt-get install -y libssl1.0.0

cd ../paho.mqtt.c
make && sudo make install

