
comment ~

 mikmod memory helper v0.1 prebeta by _servil_ 2002-2006

 module to supplement MikMod sound library by Miodrag Vallat.
 via MHELPERREADER and MHELPERWRITER objects you can play in-memory modules.
 usage is simple - include this header in your source, initialize the module
 by mh_NewReader/mh_NewReaderFromRsrc function and use Player_LoadGeneric
 func with reference to Reader object. example of usage:

 	#include <mikmod.h>
 	#include "mikmod_memoryhelper.h"
 	.
 	.
 	.
	MREADER *Reader = mh_NewReader(hInstance, hModuleData, dwModuleSize);
	if (Reader != 0) {
		MODULE *Module = Player_LoadGeneric(Reader, 128, 0);
		...

 or

	MREADER *Reader = mh_NewReaderFromRsrc(hInstance,
		MAKEINTRESOURCE(IDR_MODULE), RT_RCDATA);
	...

~

ifndef _mikmod_memoryhelper_inc_
_mikmod_memoryhelper_inc_ = 1

include vc32decl.inc

mh_NewReader proto C init_hMod: ptr, init_Size: size_t
mh_NewReaderFromRsrc proto C hModule: HMODULE, lpName: LPCTSTR, lpType: LPCTSTR
mh_FreeReader proto C :ptr MREADER
mh_NewWriter proto C init_hMod: ptr, init_Size: size_t
mh_FreeWriter proto C :ptr MWRITER

endif ; _mikmod_memoryhelper_inc_
