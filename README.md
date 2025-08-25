# The PostgresChecker Fork

This fork of the LLVM project contains the PostgresChecker. 

For the checker see: https://github.com/berndreiss/llvm-project/blob/main/clang/lib/StaticAnalyzer/Checkers/PostgresChecker.cpp

For the test file see: https://github.com/berndreiss/llvm-project/blob/main/clang/test/Analysis/postgres.c

To compile LLVM with the checker, simply run the install.sh script. To remove existing builds and start from scratch run the reinstall.sh script.

For information on how to register checkers in the Clang Static Analyzer framework, see: https://clang-analyzer.llvm.org/checker_dev_manual.html
