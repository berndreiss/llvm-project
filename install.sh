#/bin/bash

git pull
if [ ! -d release ]; then
  ./config/cmakeconf.sh
fi
./config/buildconf.sh
./config/install.sh
./release/bin/llvm-lit -v clang/test/Analysis/postgres.c clang/test/Analysis/malloc.c 
