//Realloc -> 0 might free memory
//std::tie(StateNull, StateNonNull) = needs to be incorporated for the following test case:
//
//void reallocSizeZero2(void) {
  //char *p = palloc(12);
  //char *r = repalloc(p, 0);
  //if (!r) {
    //pfree(p); // expected-warning {{Attempt to free released memory}}
  //} else {
    //pfree(r);
  //}
  //pfree(p); // expected-warning {{Attempt to free released memory}}
//}

//== PostgresChecker.cpp ------------------------------*- C++ -*--==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines PostgresChecker, which is a ...
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/Analysis/PathDiagnostic.h>
#include <clang/Analysis/ProgramPoint.h>
#include <clang/Basic/LLVM.h>
#include <clang/Basic/SourceLocation.h>
#include <clang/Basic/SourceManager.h>
#include <clang/StaticAnalyzer/Core/BugReporter/BugReporter.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/ProgramState_Fwd.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/SVals.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/raw_ostream.h>
#include <memory>
#include <string>

using namespace clang;
using namespace ento;

struct DependencyInfo;
enum Category {Strict, Dependent, Arbitrary};

namespace{
class PostgresChecker :
    public Checker<check::PreCall, check::PostCall, check::Location, check::PreStmt<ReturnStmt>, check::EndFunction> {
  mutable std::unique_ptr<BugType> BT_Free_Strict;
  mutable std::unique_ptr<BugType> BT_Free_Dependent;
  mutable std::unique_ptr<BugType> BT_Free_Arbitrary;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal l, bool isLoad, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *S, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *S, CheckerContext &C) const;
  bool checkUseAfterFree(SymbolRef Sym, CheckerContext &C, const Stmt * S) const;
private:
  void HandleFree(const CallEvent &Call, CheckerContext &C, Category Cat) const;
  void HandleStrictFree(const CallEvent &Call, CheckerContext &C) const;
  void HandleDependentFree(const CallEvent &Call, CheckerContext &C, DependencyInfo DI) const;
  void HandleArbitraryFree(const CallEvent &Call, CheckerContext &C, std::string Str) const;
  void HandleUseAfterFree(CheckerContext &C, SourceRange Range,
                          SymbolRef Sym, Category Cat) const;
  void HandleDoubleFree(CheckerContext &C, SourceRange Range, bool Released,
                        SymbolRef Sym, SymbolRef PrevSym, Category Cat) const;
  void emitReport(SymbolRef Sym, BugType *BT, CheckerContext &C, std::string message) const;
   // Implementation of the checkPreStmt and checkEndFunction callbacks.
  void checkEscapeOnReturn(const ReturnStmt *S, CheckerContext &C) const;

};
} // end of anonymous namespace
namespace {
class RefState {
  enum Kind {
    // Reference to released/freed memory.
    Released,
    // Possilbe reference to released/freed memory.
    PossiblyReleased
  };

  const Stmt *S;

  Kind K;

  ExplodedNode *EN;

  const FunctionDecl *FD;

  RefState(Kind k, const Stmt *s, ExplodedNode *EN, const FunctionDecl *FD)
      : S(s), K(k), EN(EN), FD(FD) {}

public:
  bool isReleased() const { return K == Released; }
  bool isPossiblyReleased() const { return K == PossiblyReleased; }
  const Stmt *getStmt() const { return S; }
  const FunctionDecl *getFunction() const { return FD; }
  ExplodedNode *getNode() const { return EN; }



  bool operator==(const RefState &X) const {
    return K == X.K && S == X.S;
  }

  static RefState getReleased(const Stmt *s, ExplodedNode *EN, const FunctionDecl *FD) {
    return RefState(Released, s, EN, FD);
  }
  static RefState getPossiblyReleased(const Stmt *s, ExplodedNode *EN, const FunctionDecl *FD) {
    return RefState(PossiblyReleased, s, EN, FD);
  }
  
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(K);
    ID.AddPointer(S);
    ID.AddPointer(EN);
    ID.AddPointer(FD);
  }

  LLVM_DUMP_METHOD void dump(raw_ostream &OS) const {
    switch (K) {
#define CASE(ID) case ID: OS << #ID; break;
    CASE(Released)
    CASE(PossiblyReleased)
    }
  }

  LLVM_DUMP_METHOD void dump() const { dump(llvm::errs()); }

};
} // end of anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(RegionStatePG, SymbolRef, RefState)

static bool isReleased(SymbolRef Sym, CheckerContext &C);

//This struct contains information about a dependent function.
struct DependencyInfo{
  //the number of the argument (0 for first, 1 for second etc.)
  int argNum;
  //the condition for making this function strict
  std::function<bool(void *)> isFreeing;

  DependencyInfo(int an, std::function<bool(void *)> f)
    : argNum(an), isFreeing(f) {}
};

llvm::StringMap<std::string> CMemoryMap{
  {{"free"}, {""}},
  {{"realloc"}, {""}}, 
};

llvm::StringMap<std::string> StrictMap{
  {{"pfree"}, {"void *"}}
};

llvm::StringMap<DependencyInfo> DependentMap{
  {"dependent", DependencyInfo(1, [](void *x){return *static_cast<int*>(x) != 0;})}
};

llvm::StringMap<std::string> ArbitraryMap{
  {"arbitrary", "type"}
};

void PostgresChecker::HandleUseAfterFree(CheckerContext &C, SourceRange Range,
                          SymbolRef Sym, Category Cat) const{

  BugType *BT;
  std::string message;
  switch(Cat){
    case (Strict):
      message = "Attempt to use released memory";
      if (!BT_Free_Strict)
        BT_Free_Strict.reset(new BugType(this, message));
      BT = BT_Free_Strict.get();
    break;
      //TODO REMOVE??
    //case (Dependent):
    //break;
    case (Arbitrary):
      message = "Attempt to use potentially released memory";
      if (!BT_Free_Arbitrary)
        BT_Free_Arbitrary.reset(new BugType(this, message));
      BT = BT_Free_Arbitrary.get();
    break;
  }
  emitReport(Sym, BT, C, message);
}

void PostgresChecker::HandleDoubleFree(CheckerContext &C, SourceRange Range, bool Released,
                        SymbolRef Sym, SymbolRef PrevSym, Category Cat) const{

  BugType *BT;
  std::string message;
  switch(Cat){
    case (Strict):
      message = "Attempt to free released memory";
      if (!BT_Free_Strict)
        BT_Free_Strict.reset(new BugType(this, message));
      BT = BT_Free_Strict.get();
    break;
    case (Dependent):
    break;
    case (Arbitrary):
      message = "Attempt to free potentially released memory";
      if (!BT_Free_Arbitrary)
        BT_Free_Arbitrary.reset(new BugType(this, message));
      BT = BT_Free_Arbitrary.get();
    break;

  }
  emitReport(Sym, BT, C, message);
}

void PostgresChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;
  if (StrictMap.contains(FD->getNameAsString()) || FD->getNameAsString() == "free")
    return;
  for (unsigned I = 0, E = Call.getNumArgs(); I != E; ++I) {
    SVal ArgSVal = Call.getArgSVal(I);
    if (isa<Loc>(ArgSVal)) {
      SymbolRef Sym = ArgSVal.getAsSymbol();
      if (!Sym)
        continue;
      if (checkUseAfterFree(Sym, C, Call.getArgExpr(I)))
        const auto *CE = dyn_cast_or_null<CallExpr>(Call.getOriginExpr());
    }
  }
}

void PostgresChecker::HandleStrictFree(const CallEvent &Call, CheckerContext &C) const{
  HandleFree(Call, C, Strict);
}
void PostgresChecker::HandleDependentFree(const CallEvent &Call, CheckerContext &C, DependencyInfo DI) const{
  HandleFree(Call, C, Dependent);
}
void PostgresChecker::HandleArbitraryFree(const CallEvent &Call, CheckerContext &C, std::string Str) const{
  HandleFree(Call, C, Arbitrary);
}
void PostgresChecker::HandleFree(const CallEvent &Call, CheckerContext &C, Category Cat) const{

  const FunctionDecl *fd = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  //if (fd){
    //if (fd->getNumParams() > 0)
    //llvm::errs() << "PARMNAME: " << fd->getParamDecl(0)->getNameAsString() << "\n";
  //}
  ProgramStateRef State = C.getState();
  
   if (!State)
    return;

  SVal ArgVal =  C.getSVal(Call.getArgExpr(0));
  auto SymExpr = Call.getArgExpr(0);
  //if (!isa<DefinedOrUnknownSVal>(ArgVal))
    //return;

  //DefinedOrUnknownSVal location = ArgVal.castAs<DefinedOrUnknownSVal>();
  //if (!isa<Loc>(location))
    //return;
  // TODO checks for this: free(0); Do we care about this?
  // The explicit NULL case, no operation is performed.
  //ProgramStateRef notNullState, nullState;
  //std::tie(notNullState, nullState) = State->assume(location);
  //if (nullState && !notNullState)
    //return;

  // Unknown values could easily be okay
  // Undefined values are handled elsewhere
  if (ArgVal.isUnknownOrUndef())
    return;
  DefinedSVal location = ArgVal.castAs<DefinedSVal>();
  if (!isa<Loc>(location))
    return;
   const MemRegion *R = ArgVal.getAsRegion();
  const Expr *ParentExpr = Call.getOriginExpr();

  if (!R)
    return;
  //TODO do we need this?
  R = R->StripCasts();

  const SymbolicRegion *SrBase = dyn_cast<SymbolicRegion>(R->getBaseRegion());
  // Various cases could lead to non-symbol values here.
  // For now, ignore them.
  if (!SrBase)
    return;

  SymbolRef SymBase = SrBase->getSymbol();

  //llvm::errs() << ArgVal.getAsSymbol() << "\n";
  //llvm::errs() << "SymBase: " << SymBase << "\n";
  //llvm::errs() << "Symbol: " << SrBase->getKind() << "\n";
  const RefState *RsBase = State->get<RegionStatePG>(SymBase);
  SymbolRef PreviousRetStatusSymbol = nullptr;

  if (RsBase){
    // Check for double free
    if (RsBase->isReleased() || RsBase->isPossiblyReleased()){
        HandleDoubleFree(C, ParentExpr->getSourceRange(), RsBase->isReleased(), SymBase, PreviousRetStatusSymbol, RsBase->isReleased() ? Strict : Dependent);
      return;
    }
  }

  ExplodedNode * EN = C.generateNonFatalErrorNode();

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());

  State = State->set<RegionStatePG>(SymBase, RefState::getReleased(ParentExpr, EN, FD));

  C.addTransition(State);
}

void PostgresChecker::checkPostCall(const CallEvent &Call,
                                  CheckerContext &C) const {
  //TODO do we care?
  //if (C.wasInlined)
    //return;
  if (!Call.getOriginExpr())
    return;

  ProgramStateRef State = C.getState();

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;

  //llvm::errs() << "SEARCHING FOR: " << FD->getNameAsString() << "\n";

  if (DependentMap.contains(FD->getNameAsString())){
   llvm::errs() << "FOUND\n";
    auto It = DependentMap.find(FD->getNameAsString());
    if (It != DependentMap.end()) {
      llvm::errs() << "Something there\n";
      DependencyInfo Info = It->second;
      int i = 0;
      for (const ParmVarDecl *param : FD->parameters()) {
        if (i != Info.argNum){
          i++;
          continue;
        }
  llvm::errs() << "Found param: '" << param->getNameAsString() << "'\n";
        SVal argVal = Call.getArgSVal(i);
        if (auto CI = argVal.getAs<nonloc::ConcreteInt>()){
          llvm::APSInt intValue = CI->getValue();
          llvm::errs() << "Konkreter Argumentwert: " << intValue << "\n";

          if (Info.isFreeing(&intValue)){
            HandleFree(Call, C, Strict);
            llvm::errs() << "FREE\n";
          } else{
            llvm::errs() << "FALSE\n";
          }
        } else {
            HandleFree(Call, C, Arbitrary);
          llvm::errs() << "Argument ist symbolisch oder nicht konkret\n";
        }
        i++;
      }
    }
    return;
  }

  if (StrictMap.contains(FD->getName()) || FD->getName() == "free"){
    HandleFree(Call, C, Strict);
    return;
  }
}

void PostgresChecker::checkPreStmt(const ReturnStmt *S,
                                 CheckerContext &C) const {
  checkEscapeOnReturn(S, C);
}

// In the CFG, automatic destructors come after the return statement.
// This callback checks for returning memory that is freed by automatic
// destructors, as those cannot be reached in checkPreStmt().
void PostgresChecker::checkEndFunction(const ReturnStmt *S,
                                     CheckerContext &C) const {
  checkEscapeOnReturn(S, C);
}

void PostgresChecker::checkEscapeOnReturn(const ReturnStmt *S,
                                        CheckerContext &C) const {
  if (!S)
    return;

  const Expr *E = S->getRetValue();
  if (!E)
    return;

  // Check if we are returning a symbol.
  ProgramStateRef State = C.getState();
  SVal RetVal = C.getSVal(E);
  SymbolRef Sym = RetVal.getAsSymbol();
  if (!Sym)
    // If we are returning a field of the allocated struct or an array element,
    // the callee could still free the memory.
    // TODO: This logic should be a part of generic symbol escape callback.
    if (const MemRegion *MR = RetVal.getAsRegion())
      if (isa<FieldRegion, ElementRegion>(MR))
        if (const SymbolicRegion *BMR =
              dyn_cast<SymbolicRegion>(MR->getBaseRegion()))
          Sym = BMR->getSymbol();

  // Check if we are returning freed memory.
  if (Sym)
    checkUseAfterFree(Sym, C, E);
}



bool PostgresChecker::checkUseAfterFree(SymbolRef Sym, CheckerContext &C, const Stmt * S) const{
  if (isReleased(Sym, C)) {
    HandleUseAfterFree(C, S->getSourceRange(), Sym, Strict);
    return true;
  }
  return false;
}

static bool isReleased(SymbolRef Sym, CheckerContext &C) {
  assert(Sym);
  const RefState *RS = C.getState()->get<RegionStatePG>(Sym);
  if (!RS)
    return false;
  return (RS && RS->isReleased());
}

// Check if the location is a freed symbolic region.
void PostgresChecker::checkLocation(SVal l, bool isLoad, const Stmt *S,
                                  CheckerContext &C) const {

  if (l.getAs<Loc>()){
    const MemRegion *MR = l.getAsRegion();
    if (MR){
      if (const VarRegion *VR = dyn_cast<VarRegion>(MR->getBaseRegion())){
        const VarDecl *VD = VR->getDecl();
      const SymbolicRegion *SrBase = dyn_cast<SymbolicRegion>(MR->getBaseRegion());
      if (SrBase){
         SymbolRef SymBase = SrBase->getSymbol();

      }
  }
    }
  }

  SymbolRef Sym = l.getLocSymbolInBase();
  if (Sym){
    checkUseAfterFree(Sym, C, S);
  }
}


void PostgresChecker::emitReport(SymbolRef Sym, BugType *BT, CheckerContext &C, std::string message) const{
  ExplodedNode *N = C.generateNonFatalErrorNode(C.getState(), this);
  //ExplodedNode *N = C.generateErrorNode(C.getState(), this);
  if (!N)
    return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, message, N);
  const RefState *RS = C.getState()->get<RegionStatePG>(Sym);

  if (!RS)
    return;
  PathDiagnosticLocation PDLoc = PathDiagnosticLocation::createBegin(
    C.getState()->get<RegionStatePG>(Sym)->getStmt(),
    C.getSourceManager(),
    C.getLocationContext()
  ); 
  const FunctionDecl *FD = RS->getFunction();
  R->addNote("Freeing function" + (FD ? (": " + FD->getNameAsString()) : ""), PDLoc);
  C.emitReport(std::move(R));
  
}

namespace clang {
namespace ento {
// Register plugin!
void registerPostgresChecker(CheckerManager &mgr) {
  mgr.registerChecker<PostgresChecker>();
}//namespace postgres

bool shouldRegisterPostgresChecker(const CheckerManager &mgr) {
  return true;
}
//extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  //registry.addChecker<PostgresChecker>(
      //"postgres.PostgresChecker",
      //"Checks for use-after-free and double-free in PostgreSQL",
      //"");
//}
//extern "C"
//const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;

} // namespace ento
} // namespace clang

