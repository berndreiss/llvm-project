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
void *malloc(size_t);
void *alloca(size_t);
void *valloc(size_t);
void free(void *);
void pfree(void *);
void *realloc(void *ptr, size_t size);
void *reallocf(void *ptr, size_t size);
void *calloc(size_t nmemb, size_t size);
char *strdup(const char *s);
wchar_t *wcsdup(const wchar_t *s);
char *strndup(const char *s, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);

// Windows variants
char *_strdup(const char *strSource);
wchar_t *_wcsdup(const wchar_t *strSource);
void *_alloca(size_t size);

void myfoo(int *p);
void myfooint(int p);
char *fooRetPtr(void);

void f2(void) {
  int *p = malloc(12);
  pfree(p);
  pfree(p); // expected-warning{{Attempt to pfree released memory}}
}

