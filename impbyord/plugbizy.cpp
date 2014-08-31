
/*****************************************************************************
 *                                                                           *
 *  plugbizy.cpp: auto-analysis running wait dialog                          *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#pragma warning(disable: 47) // incompatible redefinition of macro "XXX"
#endif

#include "mscrtdbg.h"
#include "plg_rsrc.h"
#include "plugbizy.hpp"
#define BYTES_SOURCE                1
#include "idasdk.hpp"
#include "plugsys.hpp"
#include "plugxcpt.hpp"
#include "plugcmn.hpp"

// running auto-analysis in the background may involve unrecoverable idabase
// corruption. because plugin's main thread self doesnot call kernel inside
// dialog loop, this happens probably due to concurrent ida ui updates and
// auto-analysis (or related kernel activity) interference.
// since ida doesn't 'oficially' enforce such racing condition, running
// analysis in background always will be highly experimentable
// (leave undefined to ensure idabase health).
//#define _IDA_BKGND_ANALYSIS 1

// use Boost.Thread library instead native API to control running
// background thread (size overhead)
//#define _IDA_BKGND_ANALYSIS_USE_BOOST_THREAD

// #if defined(_IDA_BKGND_ANALYSIS) && IDP_INTERFACE_VERSION < 76
// #undef _IDA_BKGND_ANALYSIS
// #endif

#ifdef _IDA_BKGND_ANALYSIS
#	ifndef _IDA_BKGND_ANALYSIS_USE_BOOST_THREAD

static DWORD WINAPI idabizy_bganal(LPVOID hwndDlg) {
	_ASSERTE(IsWindow((HWND)hwndDlg));
	//if (!IsWindow((HWND)hwndDlg)) return (DWORD)-1;
	/*
	//HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, "IDA");
	do {
		//if (hMutex != NULL) WaitForSingleObject(hMutex, INFINITE);
		//bool _autoIsOk = autoIsOk();
		//if (hMutex != NULL) ReleaseMutex(hMutex);
		if (autoIsOk()) {
			PostMessage((HWND)hwndDlg, WM_COMMAND, MAKELONG(IDRETRY, BN_CLICKED), NULL);
			break;
		}
		//if (hMutex != NULL) WaitForSingleObject(hMutex, INFINITE);
		autoStep();
		//if (hMutex != NULL) ReleaseMutex(hMutex);
	} while (IsWindow((HWND)hwndDlg));
	//if (hMutex != NULL) CloseHandle(hMutex);
	*/
	__try {
		while (!autoIsOk()) {
			if (!IsWindow((HWND)hwndDlg)/* || wasBreak()*/) return 0;
			autoStep();
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		warning("exception in %s(...): exiting thread", __FUNCTION__);
		return (DWORD)-2;
	}
	PostMessage((HWND)hwndDlg, WM_COMMAND, MAKELONG(IDIGNORE, BN_CLICKED), NULL);
	return 1;
}

#	else // _IDA_BKGND_ANALYSIS_USE_BOOST_THREAD

#include "undbgnew.h"
#define NOMINMAX 1
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include "dbgnew.h"

static void idabizy_bganal(HWND hwndDlg) {
	_ASSERTE(IsWindow(hwndDlg));
	//if (!IsWindow(hwndDlg)) return;
	__try {
		while (!autoIsOk()) {
			if (!IsWindow(hwndDlg)/* || wasBreak()*/) return;
			autoStep();
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		warning("exception in %s(...): exiting thread", __FUNCTION__);
		return;
	}
	PostMessage(hwndDlg, WM_COMMAND, MAKELONG(IDIGNORE, BN_CLICKED), NULL);
}

#	endif // _IDA_BKGND_ANALYSIS_USE_BOOST_THREAD
#endif // _IDA_BKGND_ANALYSIS

struct idabizy_dlg_params_t {
	LPCSTR title, info;
};

#ifdef _IDA_BKGND_ANALYSIS
#	ifdef _IDA_BKGND_ANALYSIS_USE_BOOST_THREAD
static boost::thread *bgnd_analysis;
#	else
static HANDLE hBkgndAnalysis;
static DWORD dwBkgndAnalysis;
#	endif
#endif // _IDA_BKGND_ANALYSIS

static INT_PTR CALLBACK idabizy_dlgproc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	INT_PTR result(0);
	switch (uMsg) {
		case WM_INITDIALOG:
			if (reinterpret_cast<idabizy_dlg_params_t *>(lParam) != 0) {
				if (reinterpret_cast<idabizy_dlg_params_t *>(lParam)->title != 0
					&& *reinterpret_cast<idabizy_dlg_params_t *>(lParam)->title != 0)
					SetWindowText(hwndDlg,
						reinterpret_cast<idabizy_dlg_params_t *>(lParam)->title);
				if (reinterpret_cast<idabizy_dlg_params_t *>(lParam)->info != 0/*
					&& *reinterpret_cast<idabizy_dlg_params_t *>(lParam)->info != 0*/)
					SetDlgItemText(hwndDlg, IDC_LABEL1,
						reinterpret_cast<idabizy_dlg_params_t *>(lParam)->info);
			}
			//SendDlgItemMessage(hwndDlg, IDIGNORE, WM_KILLFOCUS, NULL, NULL);
			//SendDlgItemMessage(hwndDlg, IDRETRY, WM_SETFOCUS, NULL, NULL);
			//_ASSERTE(hMutex == NULL);
			//if (autoEnabled == 0) EnableDlgItem(hwndDlg, IDRETRY, FALSE);
#ifdef _IDA_BKGND_ANALYSIS
			//else/* if (kernel_version >= 5.2)*/ {
				//while (!IsWindow(hwndDlg)) Sleep(10);
#	ifndef _IDA_BKGND_ANALYSIS_USE_BOOST_THREAD
				hBkgndAnalysis = CreateThread(NULL, 0,
					idabizy_bganal, hwndDlg, 0, &dwBkgndAnalysis);
#		ifdef _DEBUG
				if (hBkgndAnalysis == NULL) _RPTF1(_CRT_WARN,
					"%s(...): CreateThread(..., idabizy_bganal, ...) returned NULL\n",
						__FUNCTION__);
#		endif // _DEBUG
#	else
				try {
					bgnd_analysis = new boost::thread(boost::bind(idabizy_bganal, hwndDlg));
				} catch (GENERAL_CATCH_FILTER) {
					bgnd_analysis = 0;
					_RPT2(_CRT_WARN, "%s(...): failed to create background analysis thread: %s\n", __FUNCTION__, e.what());
				}
#	endif // _IDA_BKGND_ANALYSIS_USE_BOOST_THREAD
			//}
#endif // _IDA_BKGND_ANALYSIS
			result = 1;
			break;
		case WM_COMMAND:
			if (HIWORD(wParam) == BN_CLICKED) switch (LOWORD(wParam)) {
				case IDRETRY:
				case IDCANCEL:
				case IDIGNORE:
					SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
					EndDialog(hwndDlg, LOWORD(wParam));
					break;
			}
			result = 1;
			break;
	}
	return result;
}

bool decide_ida_bizy(LPCSTR title, LPCSTR message) {
	if (autoIsOk()) return true; // nothing to wait for
#ifdef _IDA_BKGND_ANALYSIS
#	ifdef _IDA_BKGND_ANALYSIS_USE_BOOST_THREAD
	bgnd_analysis = 0;
#	else
	hBkgndAnalysis = NULL;
#	endif
	__try {
		__try {
#endif // _IDA_BKGND_ANALYSIS
			//autoEnabled = 1;
			const idabizy_dlg_params_t idabizy_dlg_params = { title, message, };
			INT_PTR button = DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_IDABIZY),
				get_ida_hwnd(), idabizy_dlgproc, (LPARAM)&idabizy_dlg_params);
			return LOWORD(button) == IDIGNORE || LOWORD(button) == IDRETRY && autoWait();
#ifdef _IDA_BKGND_ANALYSIS
		} __finally {
#	ifdef _IDA_BKGND_ANALYSIS_USE_BOOST_THREAD
			if (bgnd_analysis != 0) {
				bgnd_analysis->join();
				delete bgnd_analysis;
			}
#	else
			if (hBkgndAnalysis != NULL) {
				WaitForSingleObject(hBkgndAnalysis, INFINITE);
				CloseHandle(hBkgndAnalysis);
			}
#	endif
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		warning("WARNING: caught exception during dialog loop in %s(\"%s\", ...)",
			__FUNCTION__, title);
	}
	return false;
#endif // _IDA_BKGND_ANALYSIS
}
