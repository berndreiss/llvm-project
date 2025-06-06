set(LLVM_LINK_COMPONENTS
  FrontendOpenMP
  Support
  TargetParser
  )

add_clang_library(clangStaticAnalyzerCheckers
  AnalysisOrderChecker.cpp
  AnalyzerStatsChecker.cpp
  ArrayBoundChecker.cpp
  ArrayBoundCheckerV2.cpp
  BasicObjCFoundationChecks.cpp
  BitwiseShiftChecker.cpp
  BlockInCriticalSectionChecker.cpp
  BoolAssignmentChecker.cpp
  BuiltinFunctionChecker.cpp
  CStringChecker.cpp
  CStringSyntaxChecker.cpp
  CallAndMessageChecker.cpp
  CastSizeChecker.cpp
  CastToStructChecker.cpp
  CastValueChecker.cpp
  CheckObjCDealloc.cpp
  CheckObjCInstMethSignature.cpp
  CheckPlacementNew.cpp
  CheckSecuritySyntaxOnly.cpp
  CheckerDocumentation.cpp
  ChrootChecker.cpp
  CloneChecker.cpp
  ContainerModeling.cpp
  ConversionChecker.cpp
  CXXDeleteChecker.cpp
  CXXSelfAssignmentChecker.cpp
  DeadStoresChecker.cpp
  DebugCheckers.cpp
  DebugContainerModeling.cpp
  DebugIteratorModeling.cpp
  DereferenceChecker.cpp
  DirectIvarAssignment.cpp
  DivZeroChecker.cpp
  DynamicTypePropagation.cpp
  DynamicTypeChecker.cpp
  EnumCastOutOfRangeChecker.cpp
  ErrnoChecker.cpp
  ErrnoModeling.cpp
  ErrnoTesterChecker.cpp
  ExprInspectionChecker.cpp
  FixedAddressChecker.cpp
  FuchsiaHandleChecker.cpp
  GCDAntipatternChecker.cpp
  GenericTaintChecker.cpp
  GTestChecker.cpp
  IdenticalExprChecker.cpp
  InnerPointerChecker.cpp
  InvalidatedIteratorChecker.cpp
  cert/InvalidPtrChecker.cpp
  Iterator.cpp
  IteratorModeling.cpp
  IteratorRangeChecker.cpp
  IvarInvalidationChecker.cpp
  LLVMConventionsChecker.cpp
  LocalizationChecker.cpp
  MacOSKeychainAPIChecker.cpp
  MacOSXAPIChecker.cpp
  MallocChecker.cpp
  MallocOverflowSecurityChecker.cpp
  MallocSizeofChecker.cpp
  MismatchedIteratorChecker.cpp
  MmapWriteExecChecker.cpp
  MIGChecker.cpp
  MoveChecker.cpp
  MPI-Checker/MPIBugReporter.cpp
  MPI-Checker/MPIChecker.cpp
  MPI-Checker/MPIFunctionClassifier.cpp
  NSAutoreleasePoolChecker.cpp
  NSErrorChecker.cpp
  NoReturnFunctionChecker.cpp
  NonNullParamChecker.cpp
  NonnullGlobalConstantsChecker.cpp
  NoOwnershipChangeVisitor.cpp
  NullabilityChecker.cpp
  NumberObjectConversionChecker.cpp
  ObjCAtSyncChecker.cpp
  ObjCAutoreleaseWriteChecker.cpp
  ObjCContainersASTChecker.cpp
  ObjCContainersChecker.cpp
  ObjCMissingSuperCallChecker.cpp
  ObjCPropertyChecker.cpp
  ObjCSelfInitChecker.cpp
  ObjCSuperDeallocChecker.cpp
  ObjCUnusedIVarsChecker.cpp
  OSObjectCStyleCast.cpp
  PaddingChecker.cpp
  PointerArithChecker.cpp
  PointerIterationChecker.cpp
  PointerSortingChecker.cpp
  PointerSubChecker.cpp
  PostgresChecker.cpp
  PthreadLockChecker.cpp
  PutenvStackArrayChecker.cpp
  RetainCountChecker/RetainCountChecker.cpp
  RetainCountChecker/RetainCountDiagnostics.cpp
  ReturnPointerRangeChecker.cpp
  ReturnUndefChecker.cpp
  ReturnValueChecker.cpp
  RunLoopAutoreleaseLeakChecker.cpp
  SetgidSetuidOrderChecker.cpp
  SimpleStreamChecker.cpp
  SmartPtrChecker.cpp
  SmartPtrModeling.cpp
  StackAddrEscapeChecker.cpp
  StdLibraryFunctionsChecker.cpp
  StdVariantChecker.cpp
  STLAlgorithmModeling.cpp
  StreamChecker.cpp
  StringChecker.cpp
  Taint.cpp
  TaintTesterChecker.cpp
  TestAfterDivZeroChecker.cpp
  TraversalChecker.cpp
  TrustNonnullChecker.cpp
  TrustReturnsNonnullChecker.cpp
  UndefBranchChecker.cpp
  UndefCapturedBlockVarChecker.cpp
  UndefResultChecker.cpp
  UndefinedArraySubscriptChecker.cpp
  UndefinedAssignmentChecker.cpp
  UndefinedNewArraySizeChecker.cpp
  UninitializedObject/UninitializedObjectChecker.cpp
  UninitializedObject/UninitializedPointee.cpp
  UnixAPIChecker.cpp
  UnreachableCodeChecker.cpp
  VforkChecker.cpp
  VLASizeChecker.cpp
  ValistChecker.cpp
  VirtualCallChecker.cpp
  WebKit/NoUncountedMembersChecker.cpp
  WebKit/ASTUtils.cpp
  WebKit/PtrTypesSemantics.cpp
  WebKit/RefCntblBaseVirtualDtorChecker.cpp
  WebKit/UncountedCallArgsChecker.cpp
  WebKit/UncountedLambdaCapturesChecker.cpp
  WebKit/UncountedLocalVarsChecker.cpp

  LINK_LIBS
  clangAST
  clangASTMatchers
  clangAnalysis
  clangBasic
  clangLex
  clangStaticAnalyzerCore

  DEPENDS
  omp_gen
  ClangDriverOptions
  )
