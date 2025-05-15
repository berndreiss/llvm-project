#/bin/bash

git pull
if [ ! -d release ]; then
  ./config/cmakeconf.sh
fi
./config/buildconf.sh
./config/install.sh
