
/******************************************************************************
*                                                                             *
*  Differential prototypes for VC6 and older backward compatibility           *
*  requires: differential MSVC70RT.lib and MSVCRT.DLL v7.0 or later(WinXP)    *
*                                                                             *
*******************************************************************************/

#ifndef _MSVC70RT_H_20080524_
#define _MSVC70RT_H_20080524_

#if defined(_MSC_VER) && _MSC_VER < 1300

#ifdef __cplusplus

#include <new>

extern "C" {
#endif /* __cplusplus */

/* Define _CRTIMP */
#ifndef _CRTIMP
#ifdef  _DLL
#define _CRTIMP __declspec(dllimport)
#else   /* !_DLL */
#define _CRTIMP
#endif  /* _DLL */
#endif  /* _CRTIMP */

#ifndef _VA_LIST_DEFINED
#ifdef  _M_ALPHA
typedef struct {
	char *a0;    /* pointer to first homed integer argument */
	int offset;  /* byte offset of next parameter */
} va_list;
#else
typedef char *  va_list;
#endif /* _M_ALPHA */
#define _VA_LIST_DEFINED
#endif /* !_VA_LIST_DEFINED */

#ifndef _WCHAR_T_DEFINED
typedef unsigned short wchar_t;
#define _WCHAR_T_DEFINED
#endif

#ifndef _WCTYPE_T_DEFINED
typedef wchar_t wint_t;
typedef wchar_t wctype_t;
#define _WCTYPE_T_DEFINED
#endif

#ifndef _TIME64_T_DEFINED
typedef __int64 __time64_t;
#define _TIME64_T_DEFINED
#endif

#ifndef _INTPTR_T_DEFINED
#define _INTPTR_T_DEFINED
#ifdef _WIN64
  typedef __int64 intptr_t;
#else
  typedef int intptr_t;
#endif
#endif

/* here are all functions listed not available in original VC6 runtime */
_CRTIMP int __cdecl _scprintf(const char *, ...);
_CRTIMP int __cdecl _fstat64(int, struct __stat64 *);
_CRTIMP void __cdecl _ftime64(struct __timeb64 *);
_CRTIMP int __cdecl _futime64(int, struct __utimbuf64 *);
_CRTIMP int __cdecl _resetstkoflw(void);
_CRTIMP int __cdecl _set_SSE2_enable(int);
_CRTIMP int __cdecl _snscanf(const char *, size_t, const char *, ...);
_CRTIMP int __cdecl _stat64(const char *, struct __stat64 *);
_CRTIMP __int64 __cdecl _strtoi64(const char *, char **, int);
_CRTIMP unsigned __int64 __cdecl _strtoui64(const char *, char **, int);
_CRTIMP int __cdecl _utime64(const char *, struct __utimbuf64 *);
_CRTIMP int __cdecl ___mb_cur_max_func(void);
_CRTIMP int __cdecl _vscprintf(const char *, va_list);
_CRTIMP int __cdecl _scwprintf(const wchar_t *, ...);
_CRTIMP int __cdecl _vscwprintf(const wchar_t *, va_list);
_CRTIMP wchar_t * __cdecl _cgetws(wchar_t *);
_CRTIMP int __cdecl _cputws(const wchar_t *);
_CRTIMP int __cdecl _cwprintf(const wchar_t *, ...);
_CRTIMP int __cdecl _cwscanf(const wchar_t *, ...);
_CRTIMP int __cdecl _snwscanf(const wchar_t *, size_t, const wchar_t *, ...);
_CRTIMP wchar_t * __cdecl _wcserror(int);
_CRTIMP __int64   __cdecl _wcstoi64(const wchar_t *, wchar_t **, int);
_CRTIMP unsigned __int64  __cdecl _wcstoui64(const wchar_t *, wchar_t **, int);
_CRTIMP int __cdecl _wstat64(const wchar_t *, struct __stat64 *);
_CRTIMP double __cdecl _wtof(const wchar_t *);
_CRTIMP int __cdecl _wutime64(const wchar_t *, struct __utimbuf64 *);
_CRTIMP wchar_t * __cdecl __wcserror(const wchar_t *);
_CRTIMP wint_t __cdecl _getwch(void);
_CRTIMP wint_t __cdecl _getwche(void);
_CRTIMP wint_t __cdecl _putwch(wchar_t);
_CRTIMP wint_t __cdecl _ungetwch(wint_t);
_CRTIMP char * __cdecl _ctime64(const __time64_t *);
_CRTIMP struct tm * __cdecl _gmtime64(const __time64_t *);
_CRTIMP struct tm * __cdecl _localtime64(const __time64_t *);
_CRTIMP __time64_t __cdecl _mktime64(struct tm *);
_CRTIMP __time64_t __cdecl _time64(__time64_t *);
_CRTIMP wchar_t * __cdecl _wctime64(const __time64_t *);
_CRTIMP intptr_t __cdecl _findfirst64(const char *, struct __finddata64_t *);
_CRTIMP int __cdecl _findnext64(intptr_t, struct __finddata64_t *);
_CRTIMP intptr_t __cdecl _get_heap_handle(void);
_CRTIMP intptr_t __cdecl _wfindfirst64(const wchar_t *, struct __wfinddata64_t *);
_CRTIMP int __cdecl _wfindnext64(intptr_t, struct __wfinddata64_t *);

/* data */
_CRTIMP extern unsigned int _osplatform;

#ifdef __cplusplus

_CRTIMP bool __cdecl __uncaught_exception();

} /* extern "C" */

#ifndef __PLACEMENT_VEC_NEW_INLINE
#define __PLACEMENT_VEC_NEW_INLINE

void *__cdecl operator new[](size_t) _THROW1(std::bad_alloc);
void __cdecl operator delete[](void *) _THROW0();

#endif /* __PLACEMENT_VEC_NEW_INLINE */

#ifndef __NOTHROW_T_DEFINED
#define __NOTHROW_T_DEFINED

void *__cdecl operator new(size_t, const std::nothrow_t&) _THROW0();
void *__cdecl operator new[](size_t, const std::nothrow_t&) _THROW0();

inline void __cdecl operator delete(void *ptr, const std::nothrow_t&) _THROW0()
	{ operator delete(ptr); }
inline void __cdecl operator delete[](void *ptr, const std::nothrow_t&) _THROW0()
	{ operator delete[](ptr); }

#endif /* __NOTHROW_T_DEFINED */

#endif /* __cplusplus */

#pragma comment(lib, "msvc70rt.lib")

#endif /* _MSC_VER < 1300 */

#endif /* once */
