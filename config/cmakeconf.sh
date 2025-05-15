#/bin/bash
rm -r ../llvm-project/release ../llvm-project/install
mkdir ../llvm-project/release ../llvm-project/install
cd ../llvm-project/release
#cmake -G Ninja -DCMAKE_BUILD_TYPE=DEBUG -DCMAKE_INSTALL_PREFIX=../install -DLLVM_TARGETS_TO_BUILD='X86' -DLLVM_ENABLE_PROJECTS="lldb;clang;clang-tools-extra" -DLLVM_USE_LINKER=gold -DLLVM_USE_SPLIT_DWARF=ON -DBUILD_SHARED_LIBS=ON ../llvm
cmake -G Ninja -DCMAKE_BUILD_TYPE=DEBUG -DCMAKE_INSTALL_PREFIX=../install -DLLVM_TARGETS_TO_BUILD='X86' -DLLVM_ENABLE_PROJECTS="lldb;clang" -DLLVM_USE_LINKER=gold -DLLVM_USE_SPLIT_DWARF=ON -DBUILD_SHARED_LIBS=ON ../llvm
