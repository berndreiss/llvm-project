//== ReturnUndefChecker.cpp -------------------------------------*- C++ -*--==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines ReturnUndefChecker, which is a path-sensitive
// check which looks for undefined or garbage values being returned to the
// caller.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class UnassignedReturnValueChecker : public Checker< check::PreCall, check::PostCall, check::DeadSymbols > {
  const BugType BT_Unassigned{this, "Return value unassigned"};

  void emitUnassigned(CheckerContext & C, const Expr *RetE) const;
  mutable ExplodedNode *ErrorNode = nullptr;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SymbolReaper, CheckerContext &C) const;
private:
  mutable SymbolRef ReturnValueSymbol = nullptr;
  const mutable Expr *ArgExpr = nullptr;
};
}

void UnassignedReturnValueChecker::checkPreCall(const CallEvent &Call,
                                      CheckerContext &C) const {

}

void UnassignedReturnValueChecker::checkPostCall(const CallEvent &Call,
                                      CheckerContext &C) const {
  
  SVal returnValue = Call.getReturnValue();
            if (returnValue.isUndef() || returnValue.isUnknown()) {
                return;
            }
  QualType resultType = Call.getResultType();

  for (unsigned i=0; i < Call.getNumArgs(); i++){
    QualType argType = Call.getArgExpr(i)->getType();

    if (resultType == argType){
      ReturnValueSymbol = returnValue.getAsSymbol();
      ArgExpr = Call.getArgExpr(i);

      ErrorNode = C.generateNonFatalErrorNode();

    }

  
  }
  
}
void UnassignedReturnValueChecker::checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const{
  if (ReturnValueSymbol && SR.isDead(ReturnValueSymbol)){
    if (ErrorNode){
      emitUnassigned(C, ArgExpr);
    }
  }
  ReturnValueSymbol = nullptr; 

}


void UnassignedReturnValueChecker::emitUnassigned(CheckerContext & C, const Expr *RetE) const {
  
  if (!ErrorNode)
    return;

  const Expr *TrackingE = nullptr;
  auto Report = std::make_unique<PathSensitiveBugReport>(BT_Unassigned, "Unassigned return value after passing reference to function:\n\t\t   return value has not been used and became dead code.", ErrorNode);

  Report->addRange(RetE->getSourceRange());
  bugreporter::trackExpressionValue(ErrorNode, TrackingE ? TrackingE : RetE, *Report);

  C.emitReport(std::move(Report));
}

void ento::registerUnassignedReturnValueChecker(CheckerManager &mgr) {
  mgr.registerChecker<UnassignedReturnValueChecker>();
}

bool ento::shouldRegisterUnassignedReturnValueChecker(const CheckerManager &mgr) {
  return true;
}
