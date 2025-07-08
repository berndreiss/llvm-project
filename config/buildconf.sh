#/bin/bash
cd $LLVM_HOME/release
ninja clang lldb clang-check -j $LLVM_INSTALL_CORES
