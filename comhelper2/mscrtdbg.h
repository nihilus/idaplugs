
#ifndef _MSCRTDBG_H_df4g65df4g864deer1gf4894a_ /* #pragma once */
#define _MSCRTDBG_H_df4g65df4g864deer1gf4894a_ 1

#ifdef _MSC_VER

#	define _CRTDBG_MAP_ALLOC 1
#	ifdef __cplusplus
#		include <cstdlib>
#	else
#		include <stdlib.h>
#	endif
#	include <malloc.h>
#	include <crtdbg.h>
#	ifndef _DEBUG
#		define _CrtDbgReport __noop
#	endif

#else /* !_MSC_VER */

#	define _ASSERT(x)
#	define _ASSERTE(x)
#	define _RPT0(fmt)
#	define _RPT1(fmt, arg1)
#	define _RPT2(fmt, arg1, arg2)
#	define _RPT3(fmt, arg1, arg2, arg3)
#	define _RPT4(fmt, arg1, arg2, arg3, arg4)
#	define _RPTF0(fmt)
#	define _RPTF1(fmt, arg1)
#	define _RPTF2(fmt, arg1, arg2)
#	define _RPTF3(fmt, arg1, arg2, arg3)
#	define _RPTF4(fmt, arg1, arg2, arg3, arg4)

#	define _CRT_WARN             0
#	define _CRT_ERROR            0
#	define _CRT_ASSERT           0
#	define _CRT_ERRCNT           0

#	define _CRTDBG_MODE_FILE     0
#	define _CRTDBG_MODE_DEBUG    0
#	define _CRTDBG_MODE_WNDW     0
#	define _CRTDBG_REPORT_MODE   0

#	define _CRTDBG_INVALID_HFILE 0
#	define _CRTDBG_HFILE_ERROR   0
#	define _CRTDBG_FILE_STDOUT   0
#	define _CRTDBG_FILE_STDERR   0
#	define _CRTDBG_REPORT_FILE   0

#	define _CRT_RPTHOOK_INSTALL  0
#	define _CRT_RPTHOOK_REMOVE   0

#	define _HOOK_ALLOC           0
#	define _HOOK_REALLOC         0
#	define _HOOK_FREE            0

#	define _CRTDBG_ALLOC_MEM_DF        0
#	define _CRTDBG_DELAY_FREE_MEM_DF   0
#	define _CRTDBG_CHECK_ALWAYS_DF     0
#	define _CRTDBG_RESERVED_DF         0
#	define _CRTDBG_CHECK_CRT_DF        0
#	define _CRTDBG_LEAK_CHECK_DF       0

#	define _CRTDBG_CHECK_EVERY_16_DF   0
#	define _CRTDBG_CHECK_EVERY_128_DF  0
#	define _CRTDBG_CHECK_EVERY_1024_DF 0
#	define _CRTDBG_CHECK_DEFAULT_DF    0

#	define _CRTDBG_REPORT_FLAG   0

#	define _FREE_BLOCK           0
#	define _NORMAL_BLOCK         0
#	define _CRT_BLOCK            0
#	define _IGNORE_BLOCK         0
#	define _CLIENT_BLOCK         0
#	define _MAX_BLOCKS           0

#	define _malloc_dbg(s, t, f, l)         malloc(s)
#	define _calloc_dbg(c, s, t, f, l)      calloc(c, s)
#	define _realloc_dbg(p, s, t, f, l)     realloc(p, s)
#	define _expand_dbg(p, s, t, f, l)      _expand(p, s)
#	define _free_dbg(p, t)                 free(p)
#	define _msize_dbg(p, t)                _msize(p)

#	define _aligned_malloc_dbg(s, a, f, l)     _aligned_malloc(s, a)
#	define _aligned_realloc_dbg(p, s, a, f, l) _aligned_realloc(p, s, a)
#	define _aligned_free_dbg(p)                _aligned_free(p)
#	define _aligned_offset_malloc_dbg(s, a, o, f, l)       _aligned_offset_malloc(s, a, o)
#	define _aligned_offset_realloc_dbg(p, s, a, o, f, l)   _aligned_offset_realloc(p, s, a, o)

#	define _CrtSetReportHook(f)                (0)
#	define _CrtSetReportHook2(t, f)            ((int)0)
#	define _CrtSetReportMode(t, f)             ((int)0)
#	define _CrtSetReportFile(t, f)             ((void)0)

#	define _CrtDbgBreak()                      ((void)0)

#	define _CrtSetBreakAlloc(a)                ((long)0)

#	define _CrtSetAllocHook(f)                 ((void)0)

#	define _CrtCheckMemory()                   ((int)1)
#	define _CrtSetDbgFlag(f)                   ((int)0)
#	define _CrtDoForAllClientObjects(f, c)     ((void)0)
#	define _CrtIsValidPointer(p, n, r)         ((int)1)
#	define _CrtIsValidHeapPointer(p)           ((int)1)
#	define _CrtIsMemoryBlock(p, t, r, f, l)    ((int)1)
#	define _CrtReportBlockType(p)              ((int)-1)

#	define _CrtSetDumpClient(f)                ((void)0)

#	define _CrtMemCheckpoint(s)                ((void)0)
#	define _CrtMemDifference(s1, s2, s3)       ((int)0)
#	define _CrtMemDumpAllObjectsSince(s)       ((void)0)
#	define _CrtMemDumpStatistics(s)            ((void)0)
#	define _CrtDumpMemoryLeaks()               ((int)0)

__inline int _CrtDbgReport(int, const char *, int, const char *, const char *, ...)
	{ return -1; /* not supported */ }

#endif /* _MSC_VER */

#ifdef _DEBUG

#ifdef _MSC_VER
#	define BPX if (IsDebuggerPresent()) _CrtDbgBreak()
#else
#	define BPX if (IsDebuggerPresent()) __asm__(int 3) // ???
#endif
#else // !_DEBUG
#	define BPX
#endif // _DEBUG

#endif /* _MSCRTDBG_H_df4g65df4g864deer1gf4894a_ */
