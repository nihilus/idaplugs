
/*****************************************************************************
 *                                                                           *
 *  plugfgrp.hpp: ida plugins shared code                                    *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef _PLUGFGRP_HPP_
#define _PLUGFGRP_HPP_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#pragma warning(disable:   47) // incompatible redefinition of macro "XXX"
#elif defined(_MSC_VER)
#pragma warning(disable: 4005) // macro redefinition
#endif

#include "undbgnew.h"
#include "mscrtdbg.h"
#include <string>
#include <set>
#include <map>
#include <algorithm>
#define NOMINMAX 1
#include <windows.h>
#include <commctrl.h>
#include "fixdcstr.hpp"
#define BYTES_SOURCE                1
#include "idasdk.hpp"
#include "plg_rsrc.h"
#include "dbgnew.h"

extern HINSTANCE hInstance;

class CFileGroups {
public:
	typedef std::map<std::string, std::set<fixed_path_t> > filegroups_t;

	static int Load(filegroups_t &, const char *prefix = 0);
	static bool Save(const filegroups_t &, const char *prefix = 0);

	static inline void SetFilter(LPCTSTR filter) { lpstrFilter = filter; }
	static inline void SetFilterIndex(DWORD filterindex) {
		_ASSERTE(filterindex >= 1);
		nFilterIndex = std::max<DWORD>(filterindex, 1);
	}
	static inline void SetExtension(LPCTSTR extension) { lpstrDefExt = extension; }
	static inline void SetTitle(LPCTSTR title) { lpstrTitle = title; }

	// result: true on OK / false on cancel
	static inline bool Manage(HWND hwndDlg, filegroups_t &groups) {
		return DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_GROUPMGR), hwndDlg,
			DialogProc, (LPARAM)&groups) == IDOK;
	}
	static bool CreateAddFilesMenu(HWND, HMENU &, const filegroups_t &, UINT base = 0x1000);
	static void DestroyAddFilesMenu(HMENU &hAddMenu) {
		if (hAddMenu == NULL) return;
		//MENUITEMINFO mi;
		//if (GetMenuItemInfo(hAddMenu, 1, TRUE, &mi)) DestroyMenu(mi.hSubMenu);
		DestroyMenu(hAddMenu);
		hAddMenu = NULL;
	}

private:
	static LPCTSTR lpstrFilter, lpstrTitle, lpstrDefExt;
	static DWORD nFilterIndex;

	static INT_PTR CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);
	static bool AddFile(HWND, HTREEITEM, const char *filepath);
};

#endif // _PLUGFGRP_HPP_
