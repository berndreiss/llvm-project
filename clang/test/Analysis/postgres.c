// RUN: %clang_analyze_cc1 -Wno-strict-prototypes -Wno-error=implicit-int -verify %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=alpha.deadcode.UnreachableCode \
// RUN:   -analyzer-checker=alpha.core.CastSize \
// RUN:   -analyzer-checker=unix \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -analyzer-checker=alpha.security.taint.TaintPropagation \
// RUN:   -analyzer-checker=optin.taint.TaintedAlloc \
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
struct BitmapSet;
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

void f2(void) {
  int *p = palloc(12);
  pfree(p);
  pfree(p); // expected-warning{{Attempt to free memory released by pfree at line 56}}
}
//HANDLE NORMAL FREE
//HANDLE ARBITRARY AND DEPENDENT
/*
void f2_realloc_0(void) {
  int *p = palloc(12);
  repalloc(p,0);
  repalloc(p,0); // expected-warning{{Attempt to free released memory}}
}
//HANDLE NORMAL REALLOC
//HANDLE ARBITRARY AND DEPENDENT

void f2_realloc_1(void) {
  int *p = palloc(12);
  int *q = repalloc(p,0); // no-warning
}

// p should be freed if realloc fails.
void reallocFails(void) {
  char *p = palloc(12);
  char *r = repalloc(p, 12+1);
  if (!r) {
    pfree(p);
  } else {
    pfree(r);
  }
}

void reallocSizeZero1(void) {
  char *p = palloc(12);
  char *r = repalloc(p, 0);
  if (!r) {
    pfree(p); // expected-warning {{Attempt to free released memory}}
  } else {
    pfree(r);
  }
}

void reallocSizeZero2(void) {
  char *p = palloc(12);
  char *r = repalloc(p, 0);
  if (!r) {
    pfree(p); // expected-warning {{Attempt to free released memory}}
  } else {
    pfree(r);
  }
  pfree(p); // expected-warning {{Attempt to free released memory}}
}

void reallocSizeZero3(void) {
  char *p = palloc(12);
  char *r = repalloc(p, 0);
  pfree(r);
}

void reallocSizeZero4(void) {
  char *r = repalloc(0, 0);
  pfree(r);
}

void reallocPtrZero2(void) {
  char *r = repalloc(0, 12);
  if (r)
    pfree(r);
}

void reallocPtrZero3(void) {
  char *r = repalloc(0, 12);
  pfree(r);
}

void reallocfRadar6337483_3(void) {
    char * buf = palloc(100);
    char * tmp;
    tmp = (char*)repalloc(buf, 0x1000000);
    if (!tmp) {
        pfree(buf); // expected-warning {{Attempt to free released memory}}
        return;
    }
    buf = tmp;
    pfree(buf);
}

void f7(void) {
  char *x = (char*) palloc(4);
  pfree(x);
  x[0] = 'a'; // expected-warning{{Use of memory after it is freed}}
}

void f8(void) {
  char *x = (char*) palloc(4);
  pfree(x);
  char *y = strndup(x, 4); // expected-warning{{Use of memory after it is freed}}
}

void f7_realloc(void) {
  char *x = (char*) palloc(4);
  repalloc(x,0);
  x[0] = 'a'; // expected-warning{{Use of memory after it is freed}}
}

void paramFree(int *p) {
  myfoo(p);
  pfree(p); // no warning
  myfoo(p); // expected-warning {{Use of memory after it is freed}}
}


void mallocEscapeFree(void) {
  int *p = palloc(12);
  myfoo(p);
  pfree(p);
}

void mallocEscapeFreeFree(void) {
  int *p = palloc(12);
  myfoo(p);
  pfree(p);
  pfree(p); // expected-warning{{Attempt to free released memory}}
}

void mallocEscapeFreeUse(void) {
  int *p = palloc(12);
  myfoo(p);
  pfree(p);
  myfoo(p); // expected-warning{{Use of memory after it is freed}}
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
  pfree(y);
  myfoo(x); // expected-warning{{Use of memory after it is freed}}
}

void mallocFreeMalloc(void) {
  int *p = palloc(12);
  pfree(p);
  p = palloc(12);
  pfree(p);
}

void mallocFreeUse_params(void) {
  int *p = palloc(12);
  pfree(p);
  myfoo(p); //expected-warning{{Use of memory after it is freed}}
}

void mallocFreeUse_params2(void) {
  int *p = palloc(12);
  pfree(p);
  myfooint(*p); //expected-warning{{Use of memory after it is freed}}
}

struct StructWithInt {
  int g;
};

int *mallocReturnFreed(void) {
  int *p = palloc(12);
  pfree(p);
  return p; // expected-warning {{Use of memory after it is freed}}
}

int useAfterFreeStruct(void) {
  struct StructWithInt *px= palloc(sizeof(struct StructWithInt));
  px->g = 5;
  pfree(px);
  return px->g; // expected-warning {{Use of memory after it is freed}}
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
// TO WE NEED THE NEXT TWO?
// Region escape testing.

unsigned takePtrToPtr(int **p);
void PassTheAddrOfAllocatedData(int f) {
  int *p = malloc(12);
  // We don't know what happens after the call. Should stop tracking here.
  if (takePtrToPtr(&p))
    f++;
  free(p); // no warning
}

struct X {
  int *p;
};
unsigned takePtrToStruct(struct X *s);
int ** foo2(int *g, int f) {
  int *p = malloc(12);
  struct X *px= malloc(sizeof(struct X));
  px->p = p;
  // We don't know what happens after this call. Should not track px nor p.
  if (takePtrToStruct(px))
    f++;
  free(p);
  return 0;
}

// Make sure we catch errors when we free in a function which does not allocate memory.
void freeButNoMalloc(int *p, int x){
  if (x) {
    pfree(p);
    //user forgot a return here.
  }
  pfree(p); // expected-warning {{Attempt to free released memory}}
}

struct HasPtr {
  char *p;
};

char* reallocButNoMalloc(struct HasPtr *a, int c, int size) {
  int *s;
  char *b = repalloc(a->p, size);
  char *m = repalloc(a->p, size); // expected-warning {{Attempt to free released memory}}
  // We don't expect a use-after-free for a->P here because the warning above
  // is a sink.
  return a->p; // no-warning
}

// Test realloc with no visible malloc.
void *test(void *ptr) {
  void *newPtr = repalloc(ptr, 4);
  if (newPtr == 0) {
    if (ptr)
      pfree(ptr); // no-warning
  }
  return newPtr;
}

//DO WE WANT TO COVER THESE?
//void testOffsetOfRegionFreed(void) {
  //__int64_t * array = malloc(sizeof(__int64_t)*2);
  //array += 1;
  //free(&array[0]); // expected-warning{{Argument to free() is offset by 8 bytes from the start of memory allocated by malloc()}}
//}

//void testOffsetOfRegionFreed2(void) {
  //__int64_t *p = malloc(sizeof(__int64_t)*2);
  //p += 1;
  //free(p); // expected-warning{{Argument to free() is offset by 8 bytes from the start of memory allocated by malloc()}}
//}

//void testOffsetOfRegionFreed3(void) {
  //char *r = malloc(sizeof(char));
  //r = r - 10;
  //free(r); // expected-warning {{Argument to free() is offset by -10 bytes from the start of memory allocated by malloc()}}
//}

//void testOffsetOfRegionFreedAfterFunctionCall(void) {
  //int *p = malloc(sizeof(int)*2);
  //p += 1;
  //myfoo(p);
  //free(p); // expected-warning{{Argument to free() is offset by 4 bytes from the start of memory allocated by malloc()}}
//}

//void testFixManipulatedPointerBeforeFree(void) {
  //int * array = malloc(sizeof(int)*2);
  //array += 1;
  //free(&array[-1]); // no-warning
//}

//void testFixManipulatedPointerBeforeFree2(void) {
  //char *r = malloc(sizeof(char));
  //r = r + 10;
  //free(r-10); // no-warning
//}

//void freeOffsetPointerPassedToFunction(void) {
  //__int64_t *p = malloc(sizeof(__int64_t)*2);
  //p[1] = 0;
  //p += 1;
  //myfooint(*p); // not passing the pointer, only a value pointed by pointer
  //free(p); // expected-warning {{Argument to free() is offset by 8 bytes from the start of memory allocated by malloc()}}
//}

//int arbitraryInt(void);
//void freeUnknownOffsetPointer(void) {
  //char *r = malloc(sizeof(char));
  //r = r + arbitraryInt(); // unable to reason about what the offset might be
  //free(r); // no-warning
//}

//void testFreeNonMallocPointerWithNoOffset(void) {
  //char c;
  //char *r = &c;
  //r = r + 10;
  //free(r-10); // expected-warning {{Argument to free() is the address of the local variable 'c', which is not memory allocated by malloc()}}
//}

//void testFreeNonMallocPointerWithOffset(void) {
  //char c;
  //char *r = &c;
  //free(r+1); // expected-warning {{Argument to free() is the address of the local variable 'c', which is not memory allocated by malloc()}}
//}

void testOffsetZeroDoubleFree(void) {
  int *array = palloc(sizeof(int)*2);
  int *p = &array[0];
  pfree(p);
  pfree(&array[0]); // expected-warning{{Attempt to free released memory}}
}

//void testOffsetPassedToStrlenThenFree(void) {
  //char * string = malloc(sizeof(char)*10);
  //string += 1;
  //int length = strlen(string);
  //free(string); // expected-warning {{Argument to free() is offset by 1 byte from the start of memory allocated by malloc()}}
//}

//void testOffsetPassedAsConst(void) {
  //char * string = malloc(sizeof(char)*10);
  //string += 1;
  //passConstPtr(string);
  //free(string); // expected-warning {{Argument to free() is offset by 1 byte from the start of memory allocated by malloc()}}
//}

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
   // Previously we ended up with 'Use of memory after it is freed' on return.
   return ok; // no warning
}

void (*fnptr)(int);
void freeIndirectFunctionPtr(void) {
  void *p = (void *)fnptr;
  pfree(p); // expected-warning {{Argument to free() is a function pointer}}
}

//DO WE WANT TO COVER THIS?
void freeFunctionPtr(void) {
  free((void *)fnptr);
  // expected-warning@-1{{Argument to free() is a function pointer}}
  // expected-warning@-2{{attempt to call free on non-heap object '(void *)fnptr'}}
}

// Test a false positive caused by a bug in liveness analysis.
struct A {
  int *buf;
};
struct B {
  struct A *a;
};
void livenessBugRealloc(struct A *a) {
  a->buf = repalloc(a->buf, sizeof(int)); // no-warning
}
void testLivenessBug(struct B *in_b) {
  struct B *b = in_b;
  livenessBugRealloc(b->a);
 ((void) 0); // An attempt to trick liveness analysis.
  livenessBugRealloc(b->a);
}

struct ListInfo {
  struct ListInfo *next;
};

struct ConcreteListItem {
  struct ListInfo li;
  int i;
};

void list_add(struct ListInfo *list, struct ListInfo *item);

//DO WE NEED THIS?
void testCStyleListItems(struct ListInfo *list) {
  struct ConcreteListItem *x = malloc(sizeof(struct ConcreteListItem));
  list_add(list, &x->li); // will free 'x'.
}

// MEM34-C. Only free memory allocated dynamically
// Second non-compliant example.
// https://wiki.sei.cmu.edu/confluence/display/c/MEM34-C.+Only+free+memory+allocated+dynamically
enum { BUFSIZE = 256 };

//DO WE WANT TO COVER THIS?
void MEM34_C(void) {
  char buf[BUFSIZE];
  char *p = (char *)realloc(buf, 2 * BUFSIZE);
  // expected-warning@-1{{Argument to realloc() is the address of the local \
variable 'buf', which is not memory allocated by malloc() [unix.Malloc]}}
  if (p == NULL) {
    /// Handle error 
  }
}
*/
