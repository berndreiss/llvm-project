#/bin/bash
cd $LLVM_HOME/release
ninja clang lldb -j $LLVM_INSTALL_CORES
