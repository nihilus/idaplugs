
/*****************************************************************************
 *                                                                           *
 * mikmod memory helper v0.2 beta by _servil_ 2002-2006                      *
 *                                                                           *
 * module to supplement MikMod sound library by Miodrag Vallat.              *
 * via MHELPERREADER and MHELPERWRITER objects you can play in-memory        *
 * modules.                                                                  *
 * usage is simple - include this header in your source, initialize the      *
 * module by mh_NewReader/mh_NewReaderFromRsrc function and use              *
 * Player_LoadGeneric func with reference to Reader object. example of       *
 * usage:                                                                    *
 *                                                                           *
 *	#include <mikmod.h>                                                      *
 *	#include "mikmod_memoryhelper.h"                                         *
 *	.                                                                        *
 *	.                                                                        *
 *	.                                                                        *
 *	MREADER *Reader = mh_NewReader(hInstance, hModuleData, dwModuleSize);    *
 *	if (Reader != 0) {                                                       *
 *		MODULE *Module = Player_LoadGeneric(Reader, 128, 0);                   *
 *		...                                                                    *
 *                                                                           *
 * or                                                                        *
 *                                                                           *
 *	MREADER *Reader = mh_NewReaderFromRsrc(hInstance,                        *
 *		MAKEINTRESOURCE(IDR_MODULE), RT_RCDATA);                               *
 *	...                                                                      *
 *                                                                           *
 *****************************************************************************/

#ifndef _mikmod_memoryhelper_inc_
#define _mikmod_memoryhelper_inc_

#include <mikmod.h>

#ifdef LIBMIKMOD_STATIC
#define MEMHELPERAPI
#else // !LIBMIKMOD_STATIC
#define MEMHELPERAPI __declspec(dllimport)
#endif // LIBMIKMOD_STATIC

// Initializes, call first/ retval: EAX points to MemReader object
extern "C" {
MEMHELPERAPI MREADER *__cdecl mh_NewReader(const void *const init_hMod,
	size_t const init_Size);
MEMHELPERAPI MREADER *__cdecl mh_NewReaderFromRsrc(HMODULE const hModule,
	LPCTSTR const lpName, LPCTSTR const lpType = RT_RCDATA);
MEMHELPERAPI int __cdecl mh_FreeReader(MREADER *const);
MEMHELPERAPI MWRITER *__cdecl mh_NewWriter(const void *const init_hMod,
	size_t const init_Size);
MEMHELPERAPI int __cdecl mh_FreeWriter(MWRITER *const);
}

#endif /* _mikmod_memoryhelper_inc_ */
