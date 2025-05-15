#/bin/bash
cd $LLVM_HOME/release
ninja install -j$LLVM_INSTALL_CORES
