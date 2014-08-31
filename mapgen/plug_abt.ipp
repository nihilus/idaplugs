
/*****************************************************************************
 *                                                                           *
 * plug_abt.ipp: about dialog common handler                                 *
 * (c) 2003-2008 servil                                                      *
 *                                                                           *
 *****************************************************************************/

#include "plugida.hpp"
#include "undbgnew.h"
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include "syncpmtv.hpp"
#include "dbgnew.h"

static boost::thread_group threads;
static boost::mutex io_mutex;
static event player_ready;

#ifdef SOUNDFX

#include "undbgnew.h"
#include "mikmod.h"
#include "mikmod_memoryhelper.h"
#include "dbgnew.h"

// c++ thread frontend for MikMod playback
struct module_player {
private:
	boost::shared_ptr<MREADER> Reader;
	MLOADER &ldr;
	HWND hwnd;
	bool infinite;
	DWORD fade_speed;

	static void about_errorhandler(void) {
		_ASSERTE(MikMod_errno != 0);
		cmsg << __FUNCTION__ << "(): error " << dec << MikMod_errno << " during playback: " <<
			MikMod_strerror(MikMod_errno) << " (critical:" <<
			(MikMod_critical ? "yes" : "no") << ')' << endl;
		_RPT3(_CRT_ERROR, "MikMod error %i during playback: %s (critical:%s)\n",
			MikMod_errno, MikMod_strerror(MikMod_errno), MikMod_critical ? "yes" : "no");
	}

public:
	// create from resource
	module_player(HINSTANCE hInstance, LPCTSTR ModuleId, MLOADER &ldr,
		HWND hwnd = NULL, bool infinite = false, DWORD fade_speed = 30) throw(exception) :
		Reader(mh_NewReaderFromRsrc(hInstance, ModuleId, RT_RCDATA), mh_FreeReader),
		ldr(ldr), infinite(infinite), fade_speed(fade_speed), hwnd(hwnd) {
		/*
		HRSRC hRes(FindResource(hInstance, ModuleId, RT_RCDATA));
		if (hRes == NULL) {
			//cmsg << __FUNCTION__ << "(): could not find module in resource (directory=RT_RCDATA, ID=" <<
			//	dec << reinterpret_cast<UINT>(ModuleId) << "), silent only" << endl;
			_RPT3(_CRT_WARN, "%s(): FindResource(%08X, %u, RT_RCDATA) returned NULL\n",
				__FUNCTION__, hInstance, ModuleId);
			throw logic_error("could not load resource");
		}
		HGLOBAL hSoundFx(LoadResource(hInstance, hRes));
		if (hSoundFx == NULL) {
			//cmsg << __FUNCTION__ << "(): could not load module from resource, silent only" << endl;
			_RPT3(_CRT_WARN, "%s(): LoadResource(%08X, %08X) returned NULL\n",
				__FUNCTION__, hInstance, hRes);
			throw logic_error("could not load resource");
		}
		Reader.reset(mh_NewReader(LockResource(hSoundFx), SizeofResource(hInstance, hRes)), mh_FreeReader);
		*/
		if (!Reader) {
			//cmsg << __FUNCTION__ << "(): could not create new memory reader from resource, silent only" << endl;
			//_RPT3(_CRT_ERROR, "%s(...): mh_NewReaderFromRsrc(%08X, %u, RT_RCDATA) returned NULL\n",
			//	__FUNCTION__, hInstance, ModuleId);
			throw fmt_exception("could not create new memory reader from resource, silent only (hInstance=%08X, ModuleId=%u)",
				hInstance, ModuleId);
		}
	}
	// create from memory block
	module_player(const void *pvModule, size_t cbSize, MLOADER &ldr,
		HWND hwnd = NULL, bool infinite = false, DWORD fade_speed = 30) throw(exception) :
		Reader(mh_NewReader(pvModule, cbSize), mh_FreeReader),
		ldr(ldr), infinite(infinite), fade_speed(fade_speed), hwnd(hwnd) {
		if (!Reader) {
			//_RPT3(_CRT_ERROR, "%s(...): mh_NewReader(%08X, 0x%X) returned NULL\n",
			//	__FUNCTION__, pvModule, cbSize);
			throw fmt_exception("could not create new memory reader from memory, silent only (pvModule=%08X, cbSize=0x%IX)",
				pvModule, cbSize);
		}
	}

	void operator ()() const {
		if (hwnd != NULL && !IsWindow(hwnd)) {
			player_ready.set();
			cmsg << __FUNCTION__ << "(): no parent window" << endl;
			_RPT2(_CRT_ASSERT, "%s(): IsWindow(%08X) returned FALSE\n", __FUNCTION__, hwnd);
			return;
		}
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
		__try {
			if (MikMod_InitThreads() == 0) {
				player_ready.set();
				cmsg << __FUNCTION__ << "(): player not thread-safe, silent only" << endl;
				_RPT1(_CRT_WARN, "%s(): MikMod_InitThreads() returned 0\n", __FUNCTION__);
				__leave;
			}
			MikMod_Lock(); // request exclusive access to player engine
			__try { // unlock terminator
				MikMod_RegisterDriver(&drv_win);
#ifdef _DEBUG
				MikMod_RegisterDriver(&drv_ds); // pøes DirectX nehraje, proè?
#endif // _DEBUG
				MikMod_RegisterLoader(&ldr);
				md_mode |= DMODE_SURROUND/* | DMODE_HQMIXER*/;
				md_reverb = 0; // zátìž CPU
				if (MikMod_Init("globalfocus") == 0) __try { // MikMod terminator
					_ASSERTE(Reader);
					MODULE *Module(Player_LoadGeneric(Reader.get(), 128/*maxchan*/, 0/*curious*/));
					if (Module != 0) __try { // module unloader
						Module->loop = infinite ? 1 : 0;
						Module->wrap = infinite ? 1 : 0;
						Module->fadeout = infinite ? 0 : 1;
						md_musicvolume = 0; // start muted
						MikMod_handler_t olderrorhandler(MikMod_RegisterErrorHandler(about_errorhandler));
						__try {
							Player_Start(Module);
							player_ready.set();
							// fade-in
							while (Player_Active() && (hwnd == NULL || IsWindow(hwnd))
								&& md_musicvolume < 128) {
								++md_musicvolume; //Player_SetVolume(Module->volume + 1);
								MikMod_Update();
								Sleep(fade_speed);
							}
							// normal play
							while (Player_Active() && (hwnd == NULL || IsWindow(hwnd))) {
								MikMod_Update();
								Sleep(300); // update interval
							}
							// fade-out
							while (Player_Active() && md_musicvolume > 0) {
								--md_musicvolume; //Player_SetVolume(Module->volume - 1);
								MikMod_Update();
								Sleep(fade_speed);
							}
						} __finally {
							Player_Stop();
							MikMod_RegisterErrorHandler(olderrorhandler);
						}
					} __finally {
						Player_Free(Module);
					} else {
						player_ready.set();
						cmsg << __FUNCTION__ << "(): could not load module, reason: " <<
								MikMod_strerror(MikMod_errno) << endl;
						_RPT2(_CRT_ERROR, "%s(): Player_LoadGeneric(Reader, 128, 0) returned 0, reason: %s\n",
							__FUNCTION__, MikMod_strerror(MikMod_errno));
					}
				} __finally {
					MikMod_Exit();
				} else {
					player_ready.set();
					cmsg << __FUNCTION__ << "(): could not initialize audio, reason: " <<
							MikMod_strerror(MikMod_errno) << endl;
					_RPT2(_CRT_ERROR, "%s(): MikMod_Init(\"globalfocus\") returned 1, reason: %s\n",
						__FUNCTION__, MikMod_strerror(MikMod_errno));
				}
			} __finally {
				MikMod_Unlock();
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			cmsg << __FUNCTION__ << "(): abnormal exception in module player, silent only" << endl;
			_RPT1(_CRT_ERROR, "%s(): abnormal exception in module player\n", __FUNCTION__);
		}
	} // operator ()
}; // module_player

#endif // SOUNDFX

typedef WINUSERAPI BOOL (WINAPI *SetLayeredWindowAttributes_p)(HWND, COLORREF, BYTE, DWORD);

void window_fadein(HWND hwnd, DWORD Speed = 10) throw(exception) {
	if (_winmajor < 5/*Win2000*/) return; // too old windows
	_ASSERTE(hwnd != NULL);
	if (hwnd == NULL) __stl_throw_invalid_argument("window handle cannot be NULL");
	if (!IsWindow(hwnd)) {
		{
			boost::mutex::scoped_lock io_lock(io_mutex);
			cmsg << __FUNCTION__ << "(): no parent dialog (hwnd=" <<
				ashex(reinterpret_cast<uint>(hwnd)) << ')' << endl;
		}
		_RPT2(_CRT_ASSERT, "%s(): IsWindow(%08X) returned FALSE\n",
			__FUNCTION__, hwnd);
		return;
	}
	HMODULE hUser32(GetModuleHandle("user32.dll"));
	if (hUser32 == NULL) {
		_RPT2(_CRT_WARN, "%s(): GetModuleHandle(\"user32.dll\") returned NULL (hwnd=%08X)\n",
			__FUNCTION__, hwnd);
		return; // user32 not found (never should happen)
	}
	SetLayeredWindowAttributes_p SetLayeredWindowAttributes((SetLayeredWindowAttributes_p)
		GetProcAddress(hUser32, "SetLayeredWindowAttributes"));
	if (SetLayeredWindowAttributes == NULL) return; // API not present
	//SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
	BYTE alpha(0);
	SetLayeredWindowAttributes(hwnd, 0, alpha++, LWA_ALPHA);
	player_ready.wait();
	do {
		SetLayeredWindowAttributes(hwnd, 0, alpha++, LWA_ALPHA);
		//UpdateWindow(hwnd);
		if (Speed > 0) Sleep(Speed);
	} while (IsWindow(hwnd) && alpha > 0);
}

void idaapi wait_threads(void) { threads.join_all(); }

INT_PTR CALLBACK about_dlgproc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
// 	OutputDebugString("%s(0x%X, %s, %08X, %08X)", __FUNCTION__, hwndDlg,
// 		GetMessageName(uMsg), wParam, lParam);
	static bool DragFlag;
	static uint16 BtnDownX, BtnDownY;
	RECT DlgPos;
	switch (uMsg) {
		case WM_INITDIALOG: {
			DragFlag = false;
			SendDlgItemMessage(hwndDlg, IDS_ABOUTSPLASH, STM_SETIMAGE,
				IMAGE_BITMAP, (LPARAM)LoadBitmap(hInstance,
					MAKEINTRESOURCE(IDB_ABOUTSPLASH)));
			if (lParam != NULL)
				SetDlgItemText(hwndDlg, IDC_VERSIONTEXT, (LPCTSTR)lParam);
#ifdef SOUNDFX
			player_ready.reset();
			try {
				if (threads.create_thread(module_player(hInstance,
					MAKEINTRESOURCE(IDR_SOUNDFX), SOUNDFX, hwndDlg, TRUE/*repeat*/, 30)) == 0)
					throw fmt_exception("%s(module_player(...)) returned NULL",
						"boost::threads::create_thread");
			} catch (const exception &e) {
				player_ready.set();
				//cmsg << __FUNCTION__ << "(...): failed to start module player (" <<
				//	e.what() << ')' << endl;
				_RPT3(_CRT_ERROR, "%s(...): %s (%s)\n", __FUNCTION__, e.what(), typeid(e).name());
			}
#else // !SOUNDFX
			player_ready.set();
#endif // SOUNDFX
			if (_winmajor >= 5/*Win2000*/) try {
				if (threads.create_thread(boost::bind(window_fadein, hwndDlg, 10)) == 0)
					throw fmt_exception("%s(window_fadein(...)) returned NULL",
						"boost::threads::create_thread");
			} catch (const exception &e) {
				//cmsg << __FUNCTION__ << "(...): failed to start fader (" <<
				//	e.what() << ')' << endl;
				_RPT3(_CRT_ERROR, "%s(...): %s (%s)\n", __FUNCTION__, e.what(), typeid(e).name());
			}
			return 1;
		}
		case WM_COMMAND:
			switch (LOWORD(wParam)) {
				case IDCANCEL:
					EndDialog(hwndDlg, 0);
					SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
			}
			return 1;
		case WM_LBUTTONUP:
			DragFlag = false;
			SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
			return 1;
		case WM_LBUTTONDOWN:
			BtnDownX = LOWORD(lParam);
			BtnDownY = HIWORD(lParam);
			DragFlag = true;
			SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
			return 1;
		case WM_MOUSEMOVE:
			if ((wParam & MK_LBUTTON) == 0) DragFlag = false;
			if (DragFlag && (BtnDownX != LOWORD(lParam) || BtnDownY != HIWORD(lParam))
				&& GetWindowRect(hwndDlg, &DlgPos))
				MoveWindow(hwndDlg, DlgPos.left + LOWORD(lParam) - BtnDownX,
					DlgPos.top + HIWORD(lParam) - BtnDownY,
					DlgPos.right - DlgPos.left, DlgPos.bottom - DlgPos.top, TRUE);
			SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
			return 1;
	}
	return 0;
}
