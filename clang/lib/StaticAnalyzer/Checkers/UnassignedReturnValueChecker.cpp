//== UnassignedReturnValueChecker.cpp -------------------------------------*- C++ -*--==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines UnassignedReturnValueChecker, which is a path-sensitive
// check which looks for dereferences of variables that have been passed to 
// a function in which the return value was supposed to be assigned to said
// variable.
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
using namespace std;

//A list of lists of SVal representing calls of a function:
//[
//  Call 0: SVal1, Sval2, ...
//  Call 1: SVal1, Sval2, ...
//     .
//     .
//     .
//]
struct NestedSValList{
  vector<vector<SVal>> Symbols;


  bool operator==(const NestedSValList &X) const{
    
    if (Symbols.size() != X.Symbols.size()) 
      return false;

    auto it1 = Symbols.begin();
    auto it2 = X.Symbols.begin();
    for (; it1 != Symbols.end() && it2 != X.Symbols.end(); ++it1, ++it2) {
      if (it1->size() != it2->size())
        return false;
      auto it12 = it1->begin();
      auto it22 = it2->begin();
      for (; it12 != it1->end() && it22 != it2->end(); ++it12, ++it22){
        
        if (*it12 != *it22) {
          return false;
        }
      }
    }
    return true;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(0);
    for (const vector<SVal> l : Symbols){
      for (const SVal &SV: l) {
          ID.AddPointer(SV.getAsSymbol());
      }
    }
  }
  NestedSValList(){}
  NestedSValList(vector<vector<SVal>> SVList) : Symbols(SVList){}


};

//A struct keeping track of information corresponding to a
//variable (represented in the map as MemRegion).
struct SValStruct{
  
  //Keeps track of functions and their corresponding call number as well
  //as a Expr corresponding to the argument passed to the function that
  //was freed
  vector<pair<const FunctionDecl *, pair<const Expr *, int>>> Functions;
  //The corresponding SVal
  SVal AssociatedSVal;
  //The corresponding SymbolRef of the right hand side of the assignment
  SymbolRef AssociatedV;

  bool operator==(const SValStruct &X) const{
    
    return AssociatedSVal == X.AssociatedSVal && AssociatedV == X.AssociatedV;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(0);
    ID.AddPointer(&AssociatedSVal);
    ID.AddPointer(AssociatedV);
  }
  SValStruct(){}
  SValStruct(vector<pair<const FunctionDecl *, pair<const Expr *, int>>> SVList, SVal SV, SymbolRef SR) : Functions(SVList), AssociatedSVal(SV), AssociatedV(SR){}
  SValStruct(vector<pair<const FunctionDecl *, pair<const Expr *, int>>> SVList) : Functions(SVList){}

};

//A list kepping track of SymbolRef
struct SymbolRefList{

  vector<SymbolRef> Symbols;
  bool operator==(const SymbolRefList &X) const{
    
    if (Symbols.size() != X.Symbols.size()) 
      return false;

    auto it1 = Symbols.begin();
    auto it2 = X.Symbols.begin();
    for (; it1 != Symbols.end() && it2 != X.Symbols.end(); ++it1, ++it2) {
      if (*it1 != *it2) {
        return false;
      }
    }
    return true;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(0);
    for (SymbolRef SR : Symbols) {
        ID.AddPointer(SR);
    }
  }
  SymbolRefList(){}
  SymbolRefList(vector<SymbolRef> SRList) : Symbols(SRList){}

};

//A list keeping track of EplodedNodes
struct ExplodedNodeList{

  vector<ExplodedNode *> ExplodedNodes;
  bool operator==(const ExplodedNodeList &X) const{
    
    if (ExplodedNodes.size() != X.ExplodedNodes.size()) 
      return false;
    //TODO: How to compare ExplodedNodes?
    /*
    auto it1 = ExplodedNodes.begin();
    auto it2 = X.ExplodedNodes.begin();
    for (; it1 != ExplodedNodes.end() && it2 != X.ExplodedNodes.end(); ++it1, ++it2) {
      if (*it1 != *it2) {
        return false;
      }
    }
    */
    return true;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(0);
    for (ExplodedNode *EN : ExplodedNodes) {
        ID.AddPointer(EN);
    }
  }
  ExplodedNodeList(){}
  ExplodedNodeList(vector<ExplodedNode *> ENList) : ExplodedNodes(ENList){}

};

//Maps functions to the number of active calls, representing nesting
REGISTER_MAP_WITH_PROGRAMSTATE(NestedFunctionCallCounter, const FunctionDecl *, int)

//Maps functions that are active at the time to SVals that are freed 
// -> implemented as NestedSValList since there can be nested
// function calls. The last list represents the currently active function.
REGISTER_MAP_WITH_PROGRAMSTATE(FreedOrReallocatedSValsMap,const FunctionDecl *, NestedSValList)

//Maps variables represented as MemRegion to relevant information  
//  -> functions and their call information are used to look up exploded nodes
//  -> SVals are used to compare to other symbolic values
//  -> SymbolRefs of the right hand side of the assigment are used to see
//     when the memory region is freed 
REGISTER_MAP_WITH_PROGRAMSTATE(SValMap, const MemRegion *, SValStruct)
//Maps function calls to return values. 
REGISTER_MAP_WITH_PROGRAMSTATE(ReturnValueMap, const FunctionDecl *, SymbolRefList)
//Maps function calls to exploded nodes.
REGISTER_MAP_WITH_PROGRAMSTATE(ExplodedNodeMap, const FunctionDecl *, ExplodedNodeList)

namespace {

class UnassignedReturnValueChecker : public Checker< check::PreCall, check::PostCall, check::DeadSymbols, check::Bind, check::Location > {
  const BugType BT_Unassigned{this, "Return value unassigned"};
  const BugType BT_DirtyRead{this, "Dirty read after free or reallocate"};

  void emitUnassigned(CheckerContext & C, ExplodedNode *EN, const Expr *RetE) const;
  void emitDirtyRead(CheckerContext & C, ExplodedNode *EN, const Expr *RetE) const;

public:
  void checkBind(SVal L, SVal V, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal location, bool isLoad, const Stmt *S, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SymbolReaper, CheckerContext &C) const;
};
}
//Returns the current counter for function calls
//  -> derived from size of the list of ExplodedNodes
//     and the current NestedFunctionCallCounter
int getCounter(const FunctionDecl *FD, CheckerContext &C){
  auto State = C.getState();
  int offset = *State->get<NestedFunctionCallCounter>(FD);
  vector<ExplodedNode> ENList;
  auto ENListPtr = State->get<ExplodedNodeMap>(FD);
  if (ENListPtr){
    offset += ENListPtr->ExplodedNodes.size();
  }
  return offset;
}

//Print debug information about the user MAPs
void PrintDebug(CheckerContext &C){
  auto State = C.getState();
  int j = 0;

  llvm::outs() << "\n----------DEBUG PRINT---------\n";

  llvm::outs() << "\nPRINTING NestedFunctionCallCounter\n";
  auto COUNTER = State->get<NestedFunctionCallCounter>();

  for (auto p : COUNTER){
    llvm::outs() << "Function " << p.first << ": " << p.second << ", getCounter(): " << getCounter(p.first, C) << "\n";
  }

  auto FRSValsMap = State->get<FreedOrReallocatedSValsMap>();
  llvm::outs() << "\nPRINTING FreedOrReallocatedSValsMap\n";
  j=0;
  for (auto p : FRSValsMap){
    llvm::outs() << "Function " << p.first << ": \n";
    j=0;
    for (auto l : p.second.Symbols){
      llvm::outs() << "  Call " << j++ << ": ";
      for (const auto &i : l){
        llvm::outs() << i << ", ";
      }
      llvm::outs() << "\n";
    }
  }

  auto SVMap = State->get<SValMap>();
  llvm::outs() << "\nPRINTING SValMap\n";
  for (auto p : SVMap){
    llvm::outs() << "MemRegion->" << p.first << ", SVal->" << p.second.AssociatedSVal  << ", SymRef:" << p.second.AssociatedV << ": \n";

    for (auto pp : p.second.Functions)
      llvm::outs() << "  Function " << pp.first << " (Call " << pp.second.second << ")\n";
  }

  auto RVMap = State->get<ReturnValueMap>();
  j = 0;
  llvm::outs() << "\nPRINTING ReturnValueMap\n";
  for (auto p : RVMap){
    llvm::outs() << "Function " << p.first << ": ";
    for (auto i : p.second.Symbols){
      llvm::outs() << j++ << ", ";
    }
    llvm::outs() << "\n";
  }
  auto ENMap = State->get<ExplodedNodeMap>();
  llvm::outs() << "\nPRINTING ExplodedNodeMap\n";
  j=0;
  for (auto p : ENMap){
    llvm::outs() << "Function " << p.first << ": ";
    for (auto i : p.second.ExplodedNodes){
      llvm::outs() << j++ << ", ";
    }
    llvm::outs() << "\n";
  }

  llvm::outs() << "\n----------DEBUG PRINT (END)---------\n\n";
  
}

//On bind add or replace key with empty entry in SValMap
void UnassignedReturnValueChecker::checkBind(SVal L, SVal V, const Stmt *S, CheckerContext &C) const{
  //llvm::outs() << "We are BINDING -> L: " << L << ", V: " << V << "\n";
  
  if (L.isUnknownOrUndef() || V.isUnknownOrUndef())
    return;

  //PrintDebug(C);
  
  auto State = C.getState();
  
  if (V.getAsSymbol() && V.getAsRegion()){
    vector<pair<const FunctionDecl *, pair<const Expr *, int>>> EmptyList;
    SValStruct ListToAdd(EmptyList, L, V.getAsSymbol());
    State = State->set<SValMap>(L.getAsRegion(), ListToAdd);
  }

  C.addTransition(State);
  
}

//When location is checked, look for dirty entries in the SValMap
//If dirty entries are found, emit DirtyRead with information about
//the associated function
void UnassignedReturnValueChecker::checkLocation(SVal location, bool isLoad, const Stmt *S, CheckerContext &C) const{
  //llvm::outs() << "LOCATION CHECK: " << location << ", isLoad: " << (isLoad? "true" : "false") << "\n";
  //TODO HOW TO DEAL WITH DIRTY WRITES, IS THIS AN ISSUE??
  if (!isLoad)
    return;  

  //PrintDebug(C);

  auto State = C.getState();

  if (!location.getAsRegion())
    return;
  
  //Get the current entry for the region and emit DirtyRead
  //for every entry in the list of functions
  auto SVList = State->get<SValMap>(location.getAsRegion());
  if (SVList){
      for (auto p : SVList->Functions){

        //Get the exploded nodes corresponding to the function
        auto ENList = State->get<ExplodedNodeMap>(p.first);

        if (!ENList)
          continue;

        int i = 0;
        
        //Get the exploded node for the correct function call
        //and emit DirtyRead
        for (auto en : ENList->ExplodedNodes){
          bool ShouldBreak = false;
          if (i++ == p.second.second){
                //llvm::outs() << "!!!!!!!DIRTY READ!!!!!!!" << "\n";
                emitDirtyRead(C, en, p.second.first);
                C.generateSink(C.getState(), nullptr);
                break;
            } 
          }
        }
      }
}

//Before the call we need to keep track of the NestedFunctionCallCounter and add an entry to 
//the FreedOrReallocatedSValsMap
//We also need to handle memory being reallocated/freed.
void UnassignedReturnValueChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {

  const FunctionDecl *FD = dyn_cast<FunctionDecl>(Call.getDecl());

  //llvm::outs() << "---------------" << FD->getNameAsString() << " (PRE)-------------" << "\n";
  //llvm::outs() <<  FD << "\n";
  //llvm::outs() <<  "-------------------------------------------------------------" << "\n";

  //PrintDebug(C);
  
  if (!FD)
    return;  

  //Functions we don't want to check
  //KEEP THIS IN SYNC WITH checkPostCall!!
  if (FD->getNameAsString() == "malloc" ||
      FD->getNameInfo().getName().getAsString() == "__builtin_constant_p" || 
      FD->getNameInfo().getName().getAsString() == "errmsg" ||
      FD->getNameInfo().getName().getAsString() == "errcode"
      )
    return;

  auto State = C.getState();

  if (!(FD->getNameAsString() == "free" || 
        FD->getNameAsString() == "realloc" || 
        FD->getNameAsString() == "pfree" || 
        FD->getNameAsString() == "repalloc" 
        
        )){
  
    //Incrementing the NestedFunctionCallCounter
    auto NestedFCCounterPtr = State->get<NestedFunctionCallCounter>(FD);
    if (NestedFCCounterPtr){
      int counter = *NestedFCCounterPtr;
      State = State->set<NestedFunctionCallCounter>(FD, ++counter);
    }    
    else 
      State = State->set<NestedFunctionCallCounter>(FD, 0);

    //Add new entry to FreedOrReallocatedSValsMap
    vector<vector<SVal>> UpdatedFreeList;
    auto CurrentFreedListPtr = State->get<FreedOrReallocatedSValsMap>(FD);
    if (CurrentFreedListPtr)
      UpdatedFreeList = CurrentFreedListPtr->Symbols;
    vector<SVal> EmptyList;
    UpdatedFreeList.push_back(EmptyList);
    State = State->set<FreedOrReallocatedSValsMap>(FD, UpdatedFreeList);
  } 
  
  //Handle memory being reallocated/freed
  if (FD->getNameAsString() == "free" || 
      FD->getNameAsString() == "realloc" ||
      FD->getNameAsString() == "pfree" ||
      FD->getNameAsString() == "repalloc"
      ){
    
    SVal Arg = Call.getArgSVal(0);
    if (!Arg.getAsSymbol())
      return;
    auto SVMap = State->get<SValMap>();
    
    //Get and keep track of the SVals being freed
    vector<SVal> SVBeingFreed;
    for (auto p : SVMap){
      if (p.second.AssociatedV == Arg.getAsSymbol()){
        SVBeingFreed.push_back(p.second.AssociatedSVal);
      }
    }
    
    //Get functions and their currrent call and add 
    //information to FreedOrReallocatedSValsMap
    auto FMap = State->get<NestedFunctionCallCounter>();
    for (auto p : FMap){
      
      //will not be null, since it has been added on PreCall
      auto UpdatedList = State->get<FreedOrReallocatedSValsMap>(p.first)->Symbols;  
      vector<SVal> SVBeingFreedList = UpdatedList.back();
      UpdatedList.pop_back();
      for (auto sv : SVBeingFreed)
        SVBeingFreedList.push_back(sv);
      UpdatedList.push_back(SVBeingFreedList);
      State = State->set<FreedOrReallocatedSValsMap>(p.first, UpdatedList);
    }
  }

  C.addTransition(State); 

}

//After the call we need to look at the variables being freed during
//the function call. If so and it corresponds to any of the arguments
//mark it as dirty given that the type of the return value corresponds
//to the variables type.
//Clean up afterwards.
//TODO implement check whether return value corresponds to ANY variable
//being passed. If not remember
void UnassignedReturnValueChecker::checkPostCall(const CallEvent &Call,
                                      CheckerContext &C) const {
  
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(Call.getDecl());
  
  //llvm::outs() << "--------------" << FD->getNameAsString() << "--------------"  << "\n";   
  
  //Functions we don't want to check]
  if (const FunctionDecl *FD = Call.getDecl()->getAsFunction()) {
        if (FD->getNameInfo().getName().getAsString() == "__builtin_constant_p" || 
            FD->getNameInfo().getName().getAsString() == "errmsg" ||
            FD->getNameInfo().getName().getAsString() == "errcode" ||
            FD->getNameInfo().getName().getAsString() == "malloc" ||
            FD->getNameInfo().getName().getAsString() == "free" ||
            FD->getNameInfo().getName().getAsString() == "realloc" 
        ) {
            return; // skip analysis for `ereport` calls
        }
  }
  //PrintDebug(C);

  auto State = C.getState();

  
  
  QualType resultType = Call.getResultType();
  
  //Get and keep track of freed SVals
  vector<SVal> FreedSV;
  auto FreedList = State->get<FreedOrReallocatedSValsMap>(FD)->Symbols;
  if (!FreedList.size() == 0){
    for (auto p : FreedList.back())
      FreedSV.push_back(p);
  }
  
  //Keeps track of whether any arguments type matches the return type.
  //If not we don't need to keep track of any information about the function.
  bool ReturnValueTypeMatches = false;

  //Iterate through arguments and if necessary add information about a dirty variable
  for (unsigned i=0; i < Call.getNumArgs(); i++){

    QualType argType = Call.getArgExpr(i)->getType();

    if (resultType != argType)
      continue;

    ReturnValueTypeMatches = true;
    
    SVal ArgSV = Call.getArgSVal(i);
    if (!ArgSV.getAsSymbol())
      continue;
    
    auto SVMap = State->get<SValMap>();
    for (auto p : SVMap){
      if (p.second.AssociatedV != ArgSV.getAsSymbol())
        continue;
      for (auto sv : FreedList.back()){
        if (p.second.AssociatedSVal != sv)
          continue;
        vector<pair<const FunctionDecl *, pair<const Expr *, int>>> Functions = p.second.Functions;
        Functions.push_back(make_pair(FD, make_pair(Call.getArgExpr(i), getCounter(FD, C))));
        SValStruct UpdatedEntry(Functions, p.second.AssociatedSVal, p.second.AssociatedV);
        State = State->set<SValMap>(p.first, UpdatedEntry); 
      }
    }
  }

  int NestedFCCounter = *State->get<NestedFunctionCallCounter>(FD);

  //Keep track of ExplodedNodes and return value 
  if (ReturnValueTypeMatches){

    ExplodedNode *EN = C.generateNonFatalErrorNode();
    vector<ExplodedNode *> UpdatedENList;
    auto ENListPtr = State->get<ExplodedNodeMap>(FD);
    if (ENListPtr)
      UpdatedENList = ENListPtr->ExplodedNodes;
    //Insert dummy entries for functions that have not yet returned
    for (int i=0; i <= NestedFCCounter; i++){
      UpdatedENList.insert(UpdatedENList.begin() + UpdatedENList.size(), EN);
    }
    State = State->set<ExplodedNodeMap>(FD, UpdatedENList);

    vector<SymbolRef> UpdatedRVList;
    auto RVListPtr = State->get<ReturnValueMap>(FD);
    if (RVListPtr)
      UpdatedRVList = RVListPtr->Symbols;
    SVal returnValue = Call.getReturnValue();
    SymbolRef ReturnValueSR = nullptr;
    if (!(returnValue.isUndef() || returnValue.isUnknown() || returnValue.getAsSymbol())) 
      ReturnValueSR = returnValue.getAsSymbol(); 
    //Insert dummy entries for functions that have not yet returned
    for (int i=0; i <= NestedFCCounter; i++)
      UpdatedRVList.insert(UpdatedRVList.begin() + UpdatedRVList.size(), ReturnValueSR);
    State = State->set<ReturnValueMap>(FD, UpdatedRVList);
  }

  //CLEAN UP
  if (NestedFCCounter == 0)
    State = State->remove<NestedFunctionCallCounter>(FD);
  else
    State = State->set<NestedFunctionCallCounter>(FD, NestedFCCounter-1);
  vector<vector<SVal>> UpdatedMap = State->get<FreedOrReallocatedSValsMap>(FD)->Symbols;
  UpdatedMap.pop_back();
  if (NestedFCCounter == 0)
    State = State->remove<FreedOrReallocatedSValsMap>(FD);
  else
    State = State->set<FreedOrReallocatedSValsMap>(FD, UpdatedMap);
  C.addTransition(State);
}

//Remove entries in SValMap when variables go out of scope
void UnassignedReturnValueChecker::checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const{
  /*
  if (ReturnValueSymbol && SR.isDead(ReturnValueSymbol)){
    if (ErrorNode){
      //emitUnassigned(C, ArgExpr);
    } 

  }
  */
  /*
  if (PostValueSymbol && SR.isDead(PostValueSymbol)){
    //llvm::outs() << "NOT USED AGAIN" << "\n";
  }
  */
  auto State = C.getState();
  auto SVMap = State->get<SValMap>();
  for (auto p : SVMap){
    auto Symbol = State->getSVal(p.first).getAsSymbol();
    //if variable out of scope
    if (!Symbol){
      //llvm::outs() << "REMOVING " << p.first << "\n";
      State = State->remove<SValMap>(p.first);
    }
  }
  C.addTransition(State);
  //llvm::outs() << "\n";

}


void UnassignedReturnValueChecker::emitDirtyRead(CheckerContext & C, ExplodedNode *EN, const Expr *RetE) const {
  
  if (!EN)
    return;

  const Expr *TrackingE = nullptr;
  auto Report = std::make_unique<PathSensitiveBugReport>(BT_DirtyRead, "Read after free or reallocate:\n\t\t   You may have forgotten to assign return value.", EN);

  Report->addRange(RetE->getSourceRange());
  bugreporter::trackExpressionValue(EN, TrackingE ? TrackingE : RetE, *Report);

  C.emitReport(std::move(Report));
}

void UnassignedReturnValueChecker::emitUnassigned(CheckerContext & C, ExplodedNode *EN, const Expr *RetE) const {
  
  if (!EN)
    return;

  const Expr *TrackingE = nullptr;
  auto Report = std::make_unique<PathSensitiveBugReport>(BT_Unassigned, "Unassigned return value after passing reference to function:\n\t\t   return value has not been used and became dead code.", EN);

  Report->addRange(RetE->getSourceRange());
  bugreporter::trackExpressionValue(EN, TrackingE ? TrackingE : RetE, *Report);

  C.emitReport(std::move(Report));
}

void ento::registerUnassignedReturnValueChecker(CheckerManager &mgr) {
  mgr.registerChecker<UnassignedReturnValueChecker>();
}

bool ento::shouldRegisterUnassignedReturnValueChecker(const CheckerManager &mgr) {
  return true;
}
