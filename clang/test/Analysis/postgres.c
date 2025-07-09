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
//HANDLE NORMAL REALLOC
//PFREE
void f2(void) {
  int *p = palloc(12);
  pfree(p); // expected-note{{Freeing function: pfree}}
  pfree(p); // expected-warning{{Attempt to free released memory}}
}

void f7(void) {
  char *x = (char*) palloc(4);
  pfree(x); // expected-note{{Freeing function: pfree}}
  x[0] = 'a'; // expected-warning{{Attempt to use released memory}}
}

void f8(void) {
  char *x = (char*) palloc(4);
  pfree(x); // expected-note{{Freeing function: pfree}}
  char *y = strndup(x, 4); // expected-warning{{Attempt to use released memory}}
}

void paramFree(int *p) {
  myfoo(p);
  pfree(p); // expected-note{{Freeing function: pfree}}
  myfoo(p); // expected-warning {{Attempt to use released memory}}
}


void mallocEscapeFree(void) {
  int *p = palloc(12);
  myfoo(p);
  pfree(p);
}

void mallocEscapeFreeFree(void) {
  int *p = palloc(12);
  myfoo(p);
  pfree(p); // expected-note{{Freeing function: pfree}}
  pfree(p); // expected-warning{{Attempt to free released memory}}
}

void mallocEscapeFreeUse(void) {
  int *p = palloc(12);
  myfoo(p);
  pfree(p); // expected-note{{Freeing function: pfree}}
  myfoo(p); // expected-warning{{Attempt to use released memory}}
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
  pfree(y); // expected-note{{Freeing function: pfree}}
  myfoo(x); // expected-warning{{Attempt to use released memory}}
}

void mallocFreeMalloc(void) {
  int *p = palloc(12);
  pfree(p);
  p = palloc(12);
  pfree(p);
}

void mallocFreeUse_params(void) {
  int *p = palloc(12);
  pfree(p); // expected-note{{Freeing function: pfree}}
  myfoo(p); //expected-warning{{Attempt to use released memory}}
}

void mallocFreeUse_params2(void) {
  int *p = palloc(12);
  pfree(p); // expected-note{{Freeing function: pfree}}
  myfooint(*p); //expected-warning{{Attempt to use released memory}}
}

struct StructWithInt {
  int g;
};

int *mallocReturnFreed(void) {
  int *p = palloc(12);
  pfree(p); // expected-note{{Freeing function: pfree}}
  return p; // expected-warning {{Attempt to use released memory}}
}

int useAfterFreeStruct(void) {
  struct StructWithInt *px= palloc(sizeof(struct StructWithInt));
  px->g = 5;
  pfree(px); // expected-note{{Freeing function: pfree}}
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
    pfree(p); // expected-note{{Freeing function: pfree}}
    //user forgot a return here.
  }
  pfree(p); // expected-warning {{Attempt to free released memory}}
}

void testOffsetZeroDoubleFree(void) {
  int *array = palloc(sizeof(int)*2);
  int *p = &array[0];
  pfree(p); // expected-note{{Freeing function: pfree}}
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
  add_partial_path(parent_rel, new_path); // expected-note{{Freeing function: add_partial_path}}
  use_path(new_path); // expected-warning{{Attempt to use potentially released memory}}
}

void arbitrary_double_free(void){
  Path *new_path= palloc(sizeof(Path));
  RelOptInfo *parent_rel= palloc(sizeof(Path));
  add_partial_path(parent_rel, new_path); // expected-note{{Freeing function: add_partial_path}}
  pfree(new_path); // expected-warning{{Attempt to free potentially released memory}}
}

void arbitrary_potential_double_free(void){
  Path *new_path= palloc(sizeof(Path));
  RelOptInfo *parent_rel= palloc(sizeof(Path));
  pfree(new_path); // expected-note{{Freeing function: pfree}}
  add_partial_path(parent_rel, new_path); // expected-warning{{Possible attempt to free released memory}}
}

void arbitrary_possibly_potential_double_free(void){
  Path *new_path= palloc(sizeof(Path));
  RelOptInfo *parent_rel= palloc(sizeof(Path));
  add_partial_path(parent_rel, new_path); // expected-note{{Freeing function: add_partial_path}}
  add_partial_path(parent_rel, new_path); // expected-warning{{Possible attempt to free potentially released memory}}
}

typedef struct {} Bitmapset;
Bitmapset *bms_int_members(Bitmapset *a, const Bitmapset *b);
void use_bms(Bitmapset *a);

void bitmapset(void){
  Bitmapset *a = palloc(sizeof(Bitmapset));
  Bitmapset *b = NULL;
  bms_int_members(a, b); // expected-note{{Freeing function: bms_int_members}}
  use_bms(a); // expected-warning{{Attempt to use released memory}}

  a = palloc(sizeof(Bitmapset));
  b = palloc(sizeof(Bitmapset));
  bms_int_members(a, b); // expected-note{{Freeing function: bms_int_members}}
  use_bms(a); // expected-warning{{Attempt to use potentially released memory}}
}

void bitmapset_argument(Bitmapset *b){
  Bitmapset *a = palloc(sizeof(Bitmapset));
  bms_int_members(a, b); // expected-note{{Freeing function: bms_int_members}}
  use_bms(a); // expected-warning{{Attempt to use potentially released memory}}
}

typedef struct TupleDescData{
  int tdrefcount;
}TupleDescData;
typedef struct TupleDescData *TupleDesc;

void DecrTupleDescRefCount(TupleDesc tupdesc);
void use_tupledesc(TupleDesc tupdesc);

void tupledesc(void){
  TupleDesc tupdesc = palloc(sizeof(TupleDescData));
  tupdesc->tdrefcount = 2;
  DecrTupleDescRefCount(tupdesc);
  use_tupledesc(tupdesc);
  tupdesc->tdrefcount = 1;  
  DecrTupleDescRefCount(tupdesc); // expected-note{{Freeing function: DecrTupleDescRefCount}}
  use_tupledesc(tupdesc); // expected-warning{{Attempt to use released memory}}
}

struct arguments {};
void dump_variables(struct arguments *list, int mode);
void use_arguments(struct arguments *list);
void dump_vars(void){
  struct arguments *list = palloc(sizeof(struct arguments));
  dump_variables(list, 0);
  use_arguments(list);
  dump_variables(list, 1); // expected-note{{Freeing function: dump_variables}}
  use_arguments(list); // expected-warning{{Attempt to use released memory}}
}
void dump_vars_argument(int mode){
  struct arguments *list = palloc(sizeof(struct arguments));
  dump_variables(list, mode); // expected-note{{Freeing function: dump_variables}}
  use_arguments(list); // expected-warning{{Attempt to use potentially released memory}}
}

//HANDLE DEPENDENT
//
