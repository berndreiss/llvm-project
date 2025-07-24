// RUN: %clang_analyze_cc1 -Wno-strict-prototypes -Wno-error=implicit-int -verify %s \
// RUN:   -analyzer-checker=postgres.PostgresChecker

#include "Inputs/system-header-simulator.h"

void clang_analyzer_eval(int);
void clang_analyzer_dump(int);
void clang_analyzer_dumpExtent(void *);

// Without -fms-compatibility, wchar_t isn't a builtin type. MSVC defines
// _WCHAR_T_DEFINED if wchar_t is available. Microsoft recommends that you use
// the builtin type: "Using the typedef version can cause portability
// problems", but we're ok here because we're not actually running anything.
// Also of note is this cryptic warning: "The wchar_t type is not supported
// when you compile C code".
//
// See the docs for more:
// https://msdn.microsoft.com/en-us/library/dh8che7s.aspx
#if !defined(_WCHAR_T_DEFINED)
// "Microsoft implements wchar_t as a two-byte unsigned value"
typedef unsigned short wchar_t;
#define _WCHAR_T_DEFINED
#endif // !defined(_WCHAR_T_DEFINED)

typedef __typeof(sizeof(int)) size_t;
void *malloc(size_t);
void *palloc(size_t);
void free(void *);
void pfree(void *);
void *realloc(void *ptr, size_t size);
void *repalloc(void *ptr, size_t size);
char *strdup(const char *s);
wchar_t *wcsdup(const wchar_t *s);
char *strndup(const char *s, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);

// Windows variants
char *_strdup(const char *strSource);
wchar_t *_wcsdup(const wchar_t *strSource);

void myfoo(int *p);
void myfooint(int p);
char *fooRetPtr(void);

//HANDLE NORMAL FREE
void normal_free(void){
  int *p = palloc(12);
  free(p); // expected-note{{Freeing function: free (p)}}
  pfree(p); // expected-warning{{Attempt to free released memory: p}}
}
//HANDLE NORMAL REALLOC
//PFREE
void f2(void) {
  int *p = palloc(12);
  pfree(p); // expected-note{{Freeing function: pfree (p)}}
  pfree(p); // expected-warning{{Attempt to free released memory: p}}
}

void f7(void) {
  char *x = (char*) palloc(4);
  pfree(x); // expected-note{{Freeing function: pfree (x)}}
  x[0] = 'a'; // expected-warning{{Attempt to use released memory}}
}

void f8(void) {
  char *x = (char*) palloc(4);
  pfree(x); // expected-note{{Freeing function: pfree (x)}}
  char *y = strndup(x, 4); // expected-warning{{Attempt to use released memory: x}}
}

void paramFree(int *p) {
  myfoo(p);
  pfree(p); // expected-note{{Freeing function: pfree (p)}}
  myfoo(p); // expected-warning {{Attempt to use released memory: p}}
}


void mallocEscapeFree(void) {
  int *p = palloc(12);
  myfoo(p);
  pfree(p);
}

void mallocEscapeFreeFree(void) {
  int *p = palloc(12);
  myfoo(p);
  pfree(p); // expected-note{{Freeing function: pfree (p)}}
  pfree(p); // expected-warning{{Attempt to free released memory: p}}
}

void mallocEscapeFreeUse(void) {
  int *p = palloc(12);
  myfoo(p);
  pfree(p); // expected-note{{Freeing function: pfree (p)}}
  myfoo(p); // expected-warning{{Attempt to use released memory: p}}
}

int *myalloc(void);
void myalloc2(int **p);

void mallocEscapeFreeCustomAlloc(void) {
  int *p = palloc(12);
  myfoo(p);
  pfree(p);
  p = myalloc();
  pfree(p); // no warning
}

//avoid false positives
void mallocEscapeFreeCustomAlloc2(void) {
  int *p = palloc(12);
  myfoo(p);
  pfree(p);
  myalloc2(&p);
  pfree(p); // no warning
}

void mallocBindFreeUse(void) {
  int *x = palloc(12);
  int *y = x;
  pfree(y); // expected-note{{Freeing function: pfree (y)}}
  myfoo(x); // expected-warning{{Attempt to use released memory: x}}
}

void mallocFreeMalloc(void) {
  int *p = palloc(12);
  pfree(p);
  p = palloc(12);
  pfree(p);
}

void mallocFreeUse_params(void) {
  int *p = palloc(12);
  pfree(p); // expected-note{{Freeing function: pfree (p)}}
  myfoo(p); //expected-warning{{Attempt to use released memory: p}}
}

void mallocFreeUse_params2(void) {
  int *p = palloc(12);
  pfree(p); // expected-note{{Freeing function: pfree (p)}}
  myfooint(*p); //expected-warning{{Attempt to use released memory}}
}

struct StructWithInt {
  int g;
};

int *mallocReturnFreed(void) {
  int *p = palloc(12);
  pfree(p); // expected-note{{Freeing function: pfree (p)}}
  return p; // expected-warning {{Attempt to use released memory: p}}
}

int useAfterFreeStruct(void) {
  struct StructWithInt *px= palloc(sizeof(struct StructWithInt));
  px->g = 5;
  pfree(px); // expected-note{{Freeing function: pfree (px)}}
  return px->g; // expected-warning {{Attempt to use released memory}}
}

int *Gl;
struct GlStTy {
  int *x;
};

struct GlStTy GlS = {0};

void GlobalFree(void) {
  pfree(Gl);
}

void GlobalMalloc(void) {
  Gl = palloc(12);
}

void GlobalStructMalloc(void) {
  int *a = palloc(12);
  GlS.x = a;
}

void GlobalStructMallocFree(void) {
  int *a = palloc(12);
  GlS.x = a;
  pfree(GlS.x);
}

char *ArrayG[12];

void globalArrayTest(void) {
  char *p = (char*)palloc(12);
  ArrayG[0] = p;
}

void testElemRegion1(void) {
  char *x = (void*)palloc(2);
  int *ix = (int*)x;
  pfree(&(x[0]));
}

void testElemRegion2(int **pp) {
  int *p = palloc(12);
  *pp = p;
  pfree(pp[0]);
}

void testElemRegion3(int **pp) {
  int *p = palloc(12);
  *pp = p;
  pfree(*pp);
}

// Make sure we catch errors when we free in a function which does not allocate memory.
void freeButNoMalloc(int *p, int x){
  if (x) {
    pfree(p); // expected-note{{Freeing function: pfree (p)}}
    //user forgot a return here.
  }
  pfree(p); // expected-warning {{Attempt to free released memory: p}}
}

void testOffsetZeroDoubleFree(void) {
  int *array = palloc(sizeof(int)*2);
  int *p = &array[0];
  pfree(p); // expected-note{{Freeing function: pfree (p)}}
  pfree(&array[0]); // expected-warning{{Attempt to free released memory}}
}

char **_vectorSegments;
int _nVectorSegments;

void poolFreeC(void* s) {
  pfree(s); // no-warning
}
void freeMemory(void) {
  while (_nVectorSegments) {
    poolFreeC(_vectorSegments[_nVectorSegments++]);
  }
}

struct IntAndPtr {
  int x;
  int *p;
};

void constEscape(const void *ptr);

void testConstEscapeThroughAnotherField(void) {
  struct IntAndPtr s;
  s.p = palloc(sizeof(int));
  constEscape(&(s.x)); // could free s->p!
} // no-warning

// PR15623
int testNoCheckerDataPropogationFromLogicalOpOperandToOpResult(void) {
   char *param = palloc(10);
   char *value = palloc(10);
   int ok = (param && value);
   pfree(param);
   pfree(value);
   // Previously we ended up with 'Attempt to use released memory' on return.
   return ok; // no warning
}

typedef struct {
    // no members
} RelOptInfo;
typedef struct {
    // no members
} Path;
void add_partial_path(RelOptInfo *parent_rel, Path *new_path);
void use_path(Path *path);
void arbitrary_use(void){
  Path *new_path= palloc(sizeof(Path));
  RelOptInfo *parent_rel= palloc(sizeof(Path));
  add_partial_path(parent_rel, new_path); // expected-note{{Freeing function: add_partial_path (new_path)}}
  use_path(new_path); // expected-warning{{Attempt to use potentially released memory: new_path}}
}

void arbitrary_double_free(void){
  Path *new_path= palloc(sizeof(Path));
  RelOptInfo *parent_rel= palloc(sizeof(Path));
  add_partial_path(parent_rel, new_path); // expected-note{{Freeing function: add_partial_path (new_path)}}
  pfree(new_path); // expected-warning{{Attempt to free potentially released memory: new_path}}
}

void arbitrary_potential_double_free(void){
  Path *new_path= palloc(sizeof(Path));
  RelOptInfo *parent_rel= palloc(sizeof(Path));
  pfree(new_path); // expected-note{{Freeing function: pfree (new_path)}}
  add_partial_path(parent_rel, new_path); // expected-warning{{Possible attempt to free released memory: new_path}}
}

void arbitrary_possibly_potential_double_free(void){
  Path *new_path= palloc(sizeof(Path));
  RelOptInfo *parent_rel= palloc(sizeof(Path));
  add_partial_path(parent_rel, new_path); // expected-note{{Freeing function: add_partial_path (new_path)}}
  add_partial_path(parent_rel, new_path); // expected-warning{{Possible attempt to free potentially released memory: new_path}}
}

typedef struct {} Bitmapset;
Bitmapset *bms_int_members(Bitmapset *a, const Bitmapset *b);
void use_bms(Bitmapset *a);

void bitmapset(void){
  Bitmapset *a = palloc(sizeof(Bitmapset));
  Bitmapset *b = NULL;
  bms_int_members(a, b); // expected-note{{The return value should probably be reassigned (a)}}
  use_bms(a); // expected-warning{{Attempt to use released memory: a}}

  a = palloc(sizeof(Bitmapset));
  b = palloc(sizeof(Bitmapset));
  bms_int_members(a, b); // expected-note{{The return value should probably be reassigned (a)}}
  use_bms(a); // expected-warning{{Attempt to use potentially released memory: a}}
}

void bitmapset_argument(Bitmapset *b){
  Bitmapset *a = palloc(sizeof(Bitmapset));
  bms_int_members(a, b); // expected-note{{The return value should probably be reassigned (a)}}
  use_bms(a); // expected-warning{{Attempt to use potentially released memory: a}}
}

struct arguments {};
void dump_variables(struct arguments *list, int mode);
void use_arguments(struct arguments *list);
void dump_vars(void){
  struct arguments *list = palloc(sizeof(struct arguments));
  dump_variables(list, 0);
  use_arguments(list);
  dump_variables(list, 1); // expected-note{{Freeing function: dump_variables (list)}}
  use_arguments(list); // expected-warning{{Attempt to use released memory: list}}
}
void dump_vars_argument(int mode){
  struct arguments *list = palloc(sizeof(struct arguments));
  dump_variables(list, mode); // expected-note{{Freeing function: dump_variables (list)}}
  use_arguments(list); // expected-warning{{Attempt to use potentially released memory: list}}
}

typedef int bool;
#define true 1
#define false 0

typedef struct {}TupleTableSlot;
typedef struct {}MinimalTupleStruct;
typedef MinimalTupleStruct * MinimalTuple;
typedef struct {}HeapTupleStruct;
typedef HeapTupleStruct * HeapTuple;

void ExecForceStoreMinimalTuple(MinimalTuple mtup, TupleTableSlot *slot, bool shouldFree);
void ExecForceStoreHeapTuple(HeapTuple mtup, TupleTableSlot *slot, bool shouldFree);
void useTupleMin(MinimalTuple tup);
void useTupleHeap(HeapTuple tup);

void exec_force_minimal(void){
  MinimalTuple tuple = palloc(sizeof(MinimalTuple));
  TupleTableSlot *slot = palloc(sizeof(TupleTableSlot));
  ExecForceStoreMinimalTuple(tuple, slot, false);
  useTupleMin(tuple);
  ExecForceStoreMinimalTuple(tuple, slot, true); // expected-note{{Freeing function: ExecForceStoreMinimalTuple (tuple)}}
  useTupleMin(tuple); // expected-warning{{Attempt to use potentially released memory: tuple}}

}

void exec_force_minimal_argument(bool shouldFree){
  MinimalTuple tuple = palloc(sizeof(MinimalTuple));
  TupleTableSlot *slot = palloc(sizeof(TupleTableSlot));
  ExecForceStoreMinimalTuple(tuple, slot, shouldFree); // expected-note{{Freeing function: ExecForceStoreMinimalTuple (tuple)}}
  useTupleMin(tuple); // expected-warning{{Attempt to use potentially released memory: tuple}}

}

void exec_force_heap(void){
  HeapTuple tuple = palloc(sizeof(HeapTuple));
  TupleTableSlot *slot = palloc(sizeof(TupleTableSlot));
  ExecForceStoreHeapTuple(tuple, slot, false);
  useTupleHeap(tuple);
  ExecForceStoreHeapTuple(tuple, slot, true); // expected-note{{Freeing function: ExecForceStoreHeapTuple (tuple)}}
  useTupleHeap(tuple); // expected-warning{{Attempt to use potentially released memory: tuple}}

}

void exec_force_heap_argument(bool shouldFree){
  HeapTuple tuple = palloc(sizeof(HeapTuple));
  TupleTableSlot *slot = palloc(sizeof(TupleTableSlot));
  ExecForceStoreHeapTuple(tuple, slot, shouldFree); // expected-note{{Freeing function: ExecForceStoreHeapTuple (tuple)}}
  useTupleHeap(tuple); // expected-warning{{Attempt to use potentially released memory: tuple}}

}

typedef struct {}List;

void ExecResetTupleTable(List *tupleTable,	bool shouldFree);
void useList(List *list);

void exec_reset_tt(void){
  List *list = palloc(sizeof(List));
  ExecResetTupleTable(list, false);
  useList(list);
  ExecResetTupleTable(list, true); // expected-note{{Freeing function: ExecResetTupleTable (list)}}
  useList(list); // expected-warning{{Attempt to use released memory: list}}
}

void exec_reset_tt_argument(bool shouldFree){
  List *list = palloc(sizeof(List));
  ExecResetTupleTable(list, shouldFree); // expected-note{{Freeing function: ExecResetTupleTable (list)}}
  useList(list); // expected-warning{{Attempt to use potentially released memory: list}}
}

typedef unsigned int bits32;
typedef struct {
  bits32 flags;
}JsonLexContext;
void freeJsonLexContext(JsonLexContext *lex);
void useJsonLexContext(JsonLexContext *lex);

void free_json_lc(void){
  JsonLexContext *lexContext = palloc(sizeof(JsonLexContext));
  lexContext->flags = 0;
  freeJsonLexContext(lexContext);
  useJsonLexContext(lexContext);
  lexContext->flags |= (1 << 0);
  lexContext->flags = (1 << 0);
  freeJsonLexContext(lexContext); // expected-note{{Freeing function: freeJsonLexContext (lexContext)}}
  useJsonLexContext(lexContext); // expected-warning{{Attempt to use released memory: lexContext}}
}

void free_json_lc_argument(bits32 flags){
  JsonLexContext *lexContext = palloc(sizeof(JsonLexContext));
  lexContext->flags = flags;
  freeJsonLexContext(lexContext); // expected-note{{Freeing function: freeJsonLexContext (lexContext)}}
  useJsonLexContext(lexContext); // expected-warning{{Attempt to use potentially released memory: lexContext}}
}

typedef struct {}PGresult;
typedef struct {}PGconn;

void pgfdw_report_error(int elevel, PGresult *res, PGconn *conn, bool clear, const char *sql);

void usePGresult(PGresult *res);

void free_pgfdw_report_error(void){
  PGresult *res = palloc(sizeof(PGresult));
  PGconn *conn = palloc(sizeof(PGconn));
  pgfdw_report_error(0, res, conn, false, "PG is great");
  usePGresult(res); 
  pgfdw_report_error(0, res, conn, true, "PG is great"); // expected-note{{Freeing function: pgfdw_report_error (res)}}
  usePGresult(res); // expected-warning{{Attempt to use released memory: res}}
}

void free_pgfdw_report_error_argument(bool clear){
  PGresult *res = palloc(sizeof(PGresult));
  PGconn *conn = palloc(sizeof(PGconn));
  pgfdw_report_error(0, res, conn, clear, "PG is great"); // expected-note{{Freeing function: pgfdw_report_error (res)}}
  usePGresult(res); // expected-warning{{Attempt to use potentially released memory: res}}
}

static const PGresult OOM_result = {};

void PQclear(PGresult *res);

void free_PQclear(void){
  PGresult *res = palloc(sizeof(PGresult));
  const PGresult *resOOM = &OOM_result;
  PQclear(res); // expected-note{{Freeing function: PQclear (res)}}
  usePGresult(res); // expected-warning{{Attempt to use released memory: res}}
  PQclear((PGresult *) resOOM);
  usePGresult((PGresult *) resOOM);

}

void free_argument(PGresult * res){
  PQclear(res); // expected-note{{Freeing function: PQclear (res)}}
  usePGresult(res); // expected-warning{{Attempt to use potentially released memory: res}}
}

typedef struct{} BrinTuple;
typedef unsigned int Size;

BrinTuple *brin_copy_tuple(BrinTuple *tuple, Size len, BrinTuple *dest, Size *destsz);
void useBrinTuple(BrinTuple * tuple);

void free_brin_copy_tuple(void){
  BrinTuple *tuple = palloc(sizeof(BrinTuple));
  BrinTuple *otherTuple = palloc(sizeof(BrinTuple));
  Size destsz = 5;
  Size *destszPtr = &destsz;
  Size len = 3;
  brin_copy_tuple(tuple, len, otherTuple, destszPtr);
  useBrinTuple(otherTuple);
  destsz = 0;
  brin_copy_tuple(tuple, len, otherTuple, destszPtr); // expected-note{{The return value should probably be reassigned (otherTuple)}}
  useBrinTuple(otherTuple); // expected-warning{{Attempt to use potentially released memory: otherTuple}}
  destsz = 0;
  otherTuple = palloc(sizeof(BrinTuple));
  destsz = 2;
  brin_copy_tuple(tuple, len, otherTuple, destszPtr); // expected-note{{The return value should probably be reassigned (otherTuple)}}
  useBrinTuple(otherTuple); // expected-warning{{Attempt to use potentially released memory: otherTuple}}
}
enum COMPAT_MODE{MODE};

bool ecpg_check_PQresult (PGresult *results, int lineno, PGconn *	connection,	enum COMPAT_MODE compat);

void free_ecpg_check(void){
  PGresult *res = palloc(sizeof(PGresult));
  PGconn *conn = palloc(sizeof(PGconn));
  ecpg_check_PQresult(res, 0, conn, MODE); // expected-note{{The return value should probably be checked}}
  usePGresult(res); // expected-warning{{Attempt to use potentially released memory: res}}
}

void PQfinish(PGconn *conn);

// PQfinish should not thorw double-free
void PGfinish_double(void){
  PGconn *conn = palloc(sizeof(PQfinish));  
  PQfinish(conn);
  PQfinish(conn);
}

void PQerrorMessage(const PGconn *conn);

// ignore use in PQerrorMessage
void PQerrorMessage_use(void){
  PGconn *conn = palloc(sizeof(PGconn));
  pfree(conn);
  PQerrorMessage(conn);
}
