
//== ArrayBoundChecker.cpp ------------------------------*- C++ -*--==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines ArrayBoundChecker, which is a path-sensitive check
// which looks for an out-of-bound array element access.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicExtent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/Analysis/ProgramPoint.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/ProgramState_Fwd.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/SVals.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/Object/ObjectFile.h>
#include <string>

using namespace clang;
using namespace ento;

class PostgresChecker :
    public Checker<check::PreCall, check::Location> {
  //const BugType BT{this, "Out-of-bound array access"};

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal l, bool isLoad, const Stmt *S, CheckerContext &C) const;
  bool checkUseAfterFree(SymbolRef Sym, CheckerContext &C, const Stmt * S) const;
private:
  void HandleUseAfterFree(CheckerContext &C, SourceRange Range,
                          SymbolRef Sym) const;
  void HandleDoubleFree(CheckerContext &C, SourceRange Range, bool Released,
                        SymbolRef Sym, SymbolRef PrevSym) const;

};

class RefState {
  enum Kind {
    // Reference to released/freed memory.
    Released,
    // Possilbe reference to released/freed memory.
    PossiblyReleased,
    // The responsibility for freeing resources has transferred from
    // this reference. A relinquished symbol should not be freed.
    // TODO HOW TO HANDLE THIS?
    Relinquished,
    // We are no longer guaranteed to have observed all manipulations
    // of this pointer/memory. For example, it could have been
    // passed as a parameter to an opaque function.
    // TODO HOW TO HANDLE THIS?
    Escaped
  };

  const Stmt *S;

  Kind K;

  RefState(Kind k, const Stmt *s)
      : S(s), K(k) {}

public:
  bool isReleased() const { return K == Released; }
  bool isPossiblyReleased() const { return K == PossiblyReleased; }
  bool isRelinquished() const { return K == Relinquished; }
  bool isEscaped() const { return K == Escaped; }
  const Stmt *getStmt() const { return S; }

  bool operator==(const RefState &X) const {
    return K == X.K && S == X.S;
  }

  static RefState getReleased(const Stmt *s) {
    return RefState(Released, s);
  }
  static RefState getPossiblyReleased(const Stmt *s) {
    return RefState(PossiblyReleased, s);
  }
  static RefState getRelinquished(const Stmt *s) {
    return RefState(Relinquished, s);
  }
  static RefState getEscaped(const RefState *RS) {
    return RefState(Escaped, RS->getStmt());
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(K);
    ID.AddPointer(S);
  }

  LLVM_DUMP_METHOD void dump(raw_ostream &OS) const {
    switch (K) {
#define CASE(ID) case ID: OS << #ID; break;
    CASE(Released)
    CASE(PossiblyReleased)
    CASE(Relinquished)
    CASE(Escaped)
    }
  }

  LLVM_DUMP_METHOD void dump() const { dump(llvm::errs()); }

};


REGISTER_MAP_WITH_PROGRAMSTATE(RegionState, SymbolRef, RefState)

static bool isReleased(SymbolRef Sym, CheckerContext &C);

class Dependency{
  std::string arg;
  int value;
};

llvm::StringMap<std::string> StrictMap;
llvm::StringMap<Dependency> DendentMap;
void PostgresChecker::HandleUseAfterFree(CheckerContext &C, SourceRange Range,
                          SymbolRef Sym) const{

  llvm::outs() << "USE AFTER FREE!\n";
}

  void PostgresChecker::HandleDoubleFree(CheckerContext &C, SourceRange Range, bool Released,
                        SymbolRef Sym, SymbolRef PrevSym) const{

  llvm::outs() << "DOUBLE FREE!\n";
}

void PostgresChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;

  if (FD->getNameAsString() != "pfree")
    return;
  
  llvm::errs() << Call.getCalleeIdentifier()->getName() << "\n";

  ProgramStateRef State = C.getState();
  
   if (!State)
    return;

  SVal ArgVal =  Call.getArgSVal(0);


  //THE FOLLOWING LOGIC IS DERIVED FROM MallocChecker.cpp
  if (!isa<DefinedOrUnknownSVal>(ArgVal))
    return;
  DefinedOrUnknownSVal location = ArgVal.castAs<DefinedOrUnknownSVal>();

  // Check for null dereferences.
  if (!isa<Loc>(location))
    return;

  // The explicit NULL case, no operation is performed.
  ProgramStateRef notNullState, nullState;
  std::tie(notNullState, nullState) = State->assume(location);
  if (nullState && !notNullState)
    return;

  // Unknown values could easily be okay
  // Undefined values are handled elsewhere
  if (ArgVal.isUnknownOrUndef())
    return;
   const MemRegion *R = ArgVal.getAsRegion();
  const Expr *ParentExpr = Call.getOriginExpr();

  if (!R)
    return;

  const SymbolicRegion *SrBase = dyn_cast<SymbolicRegion>(R->getBaseRegion());
  // Various cases could lead to non-symbol values here.
  // For now, ignore them.
  if (!SrBase)
    return;

  SymbolRef SymBase = SrBase->getSymbol();

  const RefState *RsBase = State->get<RegionState>(SymBase);
  SymbolRef PreviousRetStatusSymbol = nullptr;


  if (RsBase){
    // Check for double free
    if (RsBase->isReleased() || RsBase->isRelinquished()){
      HandleDoubleFree(C, ParentExpr->getSourceRange(), RsBase->isReleased(), SymBase, PreviousRetStatusSymbol);
    }
  }

  State = State->set<RegionState>(SymBase, RefState::getReleased(ParentExpr));

  C.addTransition(State);


  for (unsigned int i = 0; i < Call.getNumArgs(); i++){

    const ParmVarDecl *Param = FD->getParamDecl(i);
    auto arg = Call.getArgSVal(i);
    llvm::errs() << Param->getNameAsString() << "\n";

    if (std::optional<nonloc::ConcreteInt> CI = arg.getAs<nonloc::ConcreteInt>()){
      llvm::outs() << "Param " << Param->getNameAsString() << " has value: " << CI->getValue() << "\n";
    }else{
      llvm::outs() << "Param " << Param->getNameAsString() << " has no known value.\n";
    }

    //std::optional<IntegerLiteral> IL = dyn_cast<IntegerLiteral>(arg);
    //if (!IL)
      //continue;
    //llvm::errs() << IL.has_value() << "\n";
  }
}

bool PostgresChecker::checkUseAfterFree(SymbolRef Sym, CheckerContext &C, const Stmt * S) const{

  if (isReleased(Sym, C)) {
    HandleUseAfterFree(C, S->getSourceRange(), Sym);
    return true;
  }

  return false;

}

static bool isReleased(SymbolRef Sym, CheckerContext &C) {
  assert(Sym);
  const RefState *RS = C.getState()->get<RegionState>(Sym);
  return (RS && RS->isReleased());
}

// Check if the location is a freed symbolic region.
void PostgresChecker::checkLocation(SVal l, bool isLoad, const Stmt *S,
                                  CheckerContext &C) const {
  SymbolRef Sym = l.getLocSymbolInBase();
  if (Sym) {
    checkUseAfterFree(Sym, C, S);
  }
}



namespace clang {
namespace ento {
void registerPostgresChecker(CheckerManager &mgr) {
  mgr.registerChecker<PostgresChecker>();
}//namespace postgres

bool shouldRegisterPostgresChecker(const CheckerManager &mgr) {
  return true;
}

} // namespace ento
} // namespace clang
