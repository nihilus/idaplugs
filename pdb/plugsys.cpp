
/*****************************************************************************
 *                                                                           *
 *  plugsys.cpp: ida plugins system routines                                 *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#pragma warning(disable: 1011) // missing return statement at end of non-void function
#endif

#include <excpt.h>
#include "msvc70rt.h"
#include <stdexcept>
#include <boost/scoped_array.hpp>
#define NOMINMAX 1
#include <windows.h>
#include <CommCtrl.h>
#include <Richedit.h>
#include "plugsys.hpp"
#include "plughlpr.hpp"
#include "plugxcpt.hpp"

HINSTANCE hInstance;
char inipath[QMAXPATH];

int __wcstombs_internal(const wchar_t *wcstr, size_t len, char *mbstr,
	size_t size, DWORD dwFlags, LPCSTR lpDefaultChar, bool exact) {
	_ASSERTE(mbstr != 0 && size > 0);
	if (mbstr == 0 || size <= 0) return 0;
	*mbstr = 0;
	_ASSERTE(wcstr != 0/* && len > 0*/);
	if (wcstr == 0/* || len <= 0*/) return 0;
	BOOL UsedDefaultChar(FALSE);
	int count(WideCharToMultiByte(CP_ACP, dwFlags, wcstr,
		len, mbstr, size, lpDefaultChar, &UsedDefaultChar));
	_ASSERTE(count <= size);
	if (count > size) count = size;
	if (count > 0 && mbstr[count - 1] != 0) // ok but last char not null
	// ensure zero-terminated or signal overflow
	if (count < size) mbstr[count++] = 0; else count = 0;
	// general error or overflow -> result string may be filled
	if (count <= 0) mbstr[size - 1] = 0; // ensure zero-terminated
	return !exact || !UsedDefaultChar ? count : -1;
}

static class __sized_printf_traits {
private:
	int _M_delta;

public:
	__sized_printf_traits() throw() {
		__try {
#define TEST_ARGS "%i", 123456789
			const int r[] = {
				_scprintf(TEST_ARGS),
				qsnprintf(NULL, 0, TEST_ARGS),
			};
#undef TEST_ARGS
			_M_delta = r[0] > 0 && r[1] > 0 ? r[1] - r[0] : r[1] > 0 ? 0 : -1;
		} __except(EXCEPTION_EXECUTE_HANDLER) { // something wrong - force kernel
			_M_delta = -1;
		}
	}

	inline bool use_kernel() const throw() { return _M_delta >= 0; }
	inline int delta() const throw() { _ASSERTE(use_kernel()); return _M_delta; }

	int _vscprintf(const char *format, va_list va) const {
		return use_kernel() ? qvsnprintf(NULL, 0, format, va) - delta() :
			::_vscprintf(format, va);
	}
	int _vsnprintf(char *buf, size_t bufsize, const char *format, va_list va) const {
		return use_kernel() ? qvsnprintf(buf, bufsize, format, va) - delta() :
			::_vsnprintf(buf, bufsize, format, va);
	}
	void adjust_length(int &len) const throw()
		{ if (use_kernel()) len += std::max(1, delta()); }
	void adjust_string(std::string &s) const {
		if (use_kernel()) {
			_ASSERTE(back(s) == '\0');
			if (back(s) == '\0')
				if (delta() == 0) s.pop_back(); else s.erase(s.size() - delta());
		}
	}
} sized_printf_traits;

int _vsprintf(std::string &s, const char *format, va_list va) {
	s.clear();
	_ASSERTE(format != 0);
	if (format == 0) return -1;
	int len;
	try {
		if ((len = sized_printf_traits._vscprintf(format, va)) > 0) {
			sized_printf_traits.adjust_length(len);
			s.resize(len);
			len = sized_printf_traits._vsnprintf(const_cast<char *>(s.data()),
				len, format, va);
			sized_printf_traits.adjust_string(s);
		}
	} catch (GENERAL_CATCH_FILTER) {
		s.clear();
		len = -1;
		_RPT4(_CRT_ERROR, "%s(...): _vs*printf(..., \"%-.4000s\", ...) crashed: %s\n",
			__FUNCTION__, format, e.what(), typeid(e).name());
	}
	return len;
}

std::string _sprintf(const char *format, ...) {
	std::string result;
	va_list va;
	va_start(va, format);
	_vsprintf(result, format, va);
	va_end(va);
	return result;
}

int _vsprintf_append(std::string &s, const char *format, va_list va) {
	_ASSERTE(format != 0);
	if (format == 0) return -1;
	const std::string::size_type restore(s.length());
	int len;
	try {
		if ((len = sized_printf_traits._vscprintf(format, va)) > 0) {
			sized_printf_traits.adjust_length(len);
			s.append(len, 0);
			len = sized_printf_traits._vsnprintf(const_cast<char *>(s.data() +
				(restore * sizeof(std::string::value_type))), len, format, va);
			sized_printf_traits.adjust_string(s);
		}
	} catch (GENERAL_CATCH_FILTER) {
		s.erase(restore);
		len = -1;
		_RPT4(_CRT_ERROR, "%s(...): _vs*printf(..., \"%-.4000s\", ...) crashed: %s (%s)\n",
			__FUNCTION__, format, e.what(), typeid(e).name());
	}
	return len;
}

int _vswprintf(std::wstring &ws, const wchar_t *format, va_list va) {
	ws.clear();
	_ASSERTE(format != 0);
	if (format == 0) return -1;
	int len;
	try {
		if ((len = _vscwprintf(format, va)) >= 0) {
			ws.resize(len, 0);
			_vsnwprintf(const_cast<wchar_t *>(ws.data()), len, format, va);
		}
	} catch (GENERAL_CATCH_FILTER) {
		ws.clear();
		len = -1;
		_RPT4(_CRT_ERROR, "%s(...): _vs*wprintf(..., \"%-.4000S\", ...) crashed: %s (%s)\n",
			__FUNCTION__, format, e.what(), typeid(e).name());
	}
	return len;
}

std::wstring _swprintf(const wchar_t *format, ...) {
	std::wstring result;
	va_list va;
	va_start(va, format);
	_vswprintf(result, format, va);
	va_end(va);
	return result;
}

int _vswprintf_append(std::wstring &ws, const wchar_t *format, va_list va) {
	_ASSERTE(format != 0);
	if (format == 0) return -1;
	const std::wstring::size_type restore(ws.length());
	int len;
	try {
		if ((len = _vscwprintf(format, va)) >= 0) {
			ws.append(len, 0);
			_vsnwprintf(const_cast<wchar_t *>(ws.data() +
				restore * sizeof(std::wstring::value_type)), len, format, va);
		}
	} catch (GENERAL_CATCH_FILTER) {
		ws.erase(restore);
		len = -1;
		_RPT4(_CRT_ERROR, "%s(...): _vs*wprintf(..., \"%-.4000S\", ...) crashed: %s (%s)\n",
			__FUNCTION__, format, e.what(), typeid(e).name());
	}
	return len;
}

#ifdef _DEBUG

void OutputDebugString(const char *format, ...) {
	std::string dbg_out;
	va_list va;
	va_start(va, format);
	if (_vsprintf(dbg_out, format, va) > 0) OutputDebugStringA(dbg_out.c_str());
	va_end(va);
}

void OutputDebugString(const wchar_t *format, ...) {
	std::wstring dbg_out;
	va_list va;
	va_start(va, format);
	if (_vswprintf(dbg_out, format, va) > 0) OutputDebugStringW(dbg_out.c_str());
	va_end(va);
}

#endif // _DEBUG

char *chomp(char *s, size_t maxlen, bool allcliterals) {
	// flatenns all control codes id string
	if (s == 0 || *s == 0) return s;
	std::string tgt;
	for (uchar *scansrc = (uchar *)s; *scansrc != 0; ++scansrc) {
		switch (*scansrc) {
#define tokenize_c_ctrlchar(x, y) case #@x: tgt.append("\\" #y); break;
			tokenize_c_ctrlchar(\a, a);
			tokenize_c_ctrlchar(\b, b);
			tokenize_c_ctrlchar(\t, t);
			tokenize_c_ctrlchar(\n, n);
			tokenize_c_ctrlchar(\v, v);
			tokenize_c_ctrlchar(\f, f);
			tokenize_c_ctrlchar(\r, r);
#undef tokenize_c_ctrlchar
			default:
				if (allcliterals)
					switch (*scansrc) {
						case '\"': tgt.append("\\\""); break;
						case '\'': tgt.append("\\\'"); break;
						//case '?': tgt.append("\\?"); break;
						case '\\': tgt.append("\\\\"); break;
						default:
							if (!isprint(*scansrc))
								_sprintf_append(tgt, "\\x%03X", *scansrc);
							else
								tgt.push_back(*(const char *)scansrc);
					}
				else
					tgt.push_back(*(const char *)scansrc);
		}
	}
	return qstrncpy(s, tgt.c_str(), maxlen);
}

char *caption_to_asmname(char *caption) {
	_ASSERTE(caption != 0);
	if (caption != 0 && *caption != 0) {
		std::string tgt;
		bool upcase(true);
		for (uchar *scansrc = (uchar *)caption; *scansrc != 0; ++scansrc) {
			if (__iscsym(*scansrc) != 0 || strchr("?$@", *(const char *)scansrc) != 0) {
				tgt.push_back(upcase && islower(*scansrc) ?
					static_cast<char>(toupper(*(char *)scansrc)) : *(const char *)scansrc);
				upcase = false;
			} else if (isspace(*scansrc) != 0 || ispunct(*scansrc) != 0)
				upcase = true;
		}
		_ASSERTE(tgt.length() <= strlen(caption));
		qstrncpy(caption, tgt.c_str(), tgt.length() + 1);
	}
	return caption;
}

char *stripeoln(char *s) {
	_ASSERTE(s != 0);
	if (s != 0) {
		char *x(strpbrk(s, "\r\n"));
		if (x != 0) *x = 0;
	}
	return s;
}

// return value: pointer to first occurence of sf, otherwise null pointer
const char *_stristr(const char *s, const char *sf) {
	_ASSERTE(s != 0);
	_ASSERTE(sf != 0);
	if (s == 0 || *s == 0 || sf == 0 || *sf == 0) return 0;
	const size_t sz(strlen(s) + 1);
	boost::scoped_array<char> S(new char[sz]);
	if (!S) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new string of size 0x%IX\n",
			__FUNCTION__, sz);
		throw std::bad_alloc(); //return 0;
	}
	const size_t sfz(strlen(sf) + 1);
	boost::scoped_array<char> SF(new char[sfz]);
	if (!SF) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new string of size 0x%IX\n",
			__FUNCTION__, sfz);
		throw std::bad_alloc(); //return 0;
	}
	char *const result(strstr(_strupr(qstrncpy(S.get(), s, sz)),
		_strupr(qstrncpy(SF.get(), sf, sfz))));
	return result >= S.get() ? s + (result - S.get()) : 0;
}

// return value: pointer to first occurence of sf, otherwise null pointer
const wchar_t *_wcsistr(const wchar_t *s, const wchar_t *sf) {
	_ASSERTE(s != 0);
	_ASSERTE(sf != 0);
	if (s == 0 || *s == 0 || sf == 0 || *sf == 0) return 0;
	const size_t sz(wcslen(s) + 1);
	boost::scoped_array<wchar_t> S(new wchar_t[sz]);
	if (!S) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new wstring of size 0x%IX\n",
			__FUNCTION__, sz);
		throw std::bad_alloc(); //return 0;
	}
	const size_t sfz(wcslen(sf) + 1);
	boost::scoped_array<wchar_t> SF(new wchar_t[sfz]);
	if (!SF) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new string of size 0x%IX\n",
			__FUNCTION__, sfz);
		throw std::bad_alloc(); //return 0;
	}
	wchar_t *const result(wcsstr(_wcsupr(wcsncpy(S.get(), s, sz)),
		_wcsupr(wcsncpy(SF.get(), sf, sfz))));
	return result >= S.get() ? s + (result - S.get()) : 0;
}

int iwcsfunc(const wchar_t *ws, const char *s,
	int (__cdecl &func)(const wchar_t *, const wchar_t *)) {
	_ASSERTE(ws != 0);
	_ASSERTE(s != 0);
	if (ws == 0 && s != 0) return -1;
	if (ws != 0 && s == 0) return 1;
	if (ws == 0 && s == 0) return 0;
	const size_t sz(strlen(s) + 1);
	boost::scoped_array<wchar_t> WS(new wchar_t[sz]);
	if (!WS) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new wstring of size 0x%IX\n",
			__FUNCTION__, sz);
		throw std::bad_alloc(); //return 0;
	}
	if (static_cast<int>(mbstowcs(WS.get(), s, sz)) >= 1) return func(ws, WS.get());
	_RPTF3(_CRT_ERROR, "%s(\"%ls\", \"%s\", ...): failed to convert parameter to unicode\n",
		__FUNCTION__, ws, s);
	return 0;
}

int iwcsfunc(const char *s, const wchar_t *ws,
	int (__cdecl &func)(const wchar_t *, const wchar_t *)) {
	_ASSERTE(s != 0 && ws != 0);
	if (s == 0 && ws != 0) return -1;
	if (s != 0 && ws == 0) return 1;
	if (s == 0 && ws == 0) return 0;
	const size_t sz(strlen(s) + 1);
	boost::scoped_array<wchar_t> WS(new wchar_t[sz]);
	if (!WS) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new wstring of size 0x%IX\n",
			__FUNCTION__, sz);
		throw std::bad_alloc(); //return 0;
	}
	if (static_cast<int>(mbstowcs(WS.get(), s, sz)) >= 1) return func(WS.get(), ws);
	_RPTF3(_CRT_ERROR, "%s(\"%s\", \"%ls\", ...): failed to convert parameter to unicode\n",
		__FUNCTION__, s, ws);
	return 0;
}

/*
int wswcsfunc(const wchar_t *const ws, const char *const s, wchar_t *(__cdecl &func)(const wchar_t *, const wchar_t *)) {
	_ASSERTE(ws != 0);
	 && s != 0);
	if (ws == 0 && s != 0) return -1;
	if (ws != 0 && s == 0) return 1;
	if (ws == 0 && s == 0) return 0;
	const size_t sz(strlen(s) + 1);
	boost::scoped_array<wchar_t> WS(new wchar_t[sz]);
	if (!WS) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new wstring of size 0x%IX\n",
			__FUNCTION__, sz);
		throw std::bad_alloc(); //return 0;
	}
	if (static_cast<int>(mbstowcs(WS, s, sz)) >= 1) return func(ws, WS.get());
	_RPTF3(_CRT_ERROR, "%s(\"%ls\", \"%s\", ...): failed to convert parameter to unicode\n",
		__FUNCTION__, ws, s);
	return 0;
}
*/

char *ConstructHomeFileName(char *buffer, const char *fname, const char *ext) {
	_ASSERTE(buffer != 0);
	if (buffer != 0) {
		char path[MAX_PATH], drive[_MAX_DRIVE], dir[_MAX_DIR], _fname[_MAX_FNAME],
			_ext[_MAX_EXT];
		if (GetModuleFileName(hInstance, CPY(path)) > 0) {
			_splitpath(path, drive, dir, _fname, _ext);
			_makepath(buffer, drive, dir, fname != 0 ? fname : _fname, ext != 0 ? ext : _ext);
		} else {
			*buffer = 0;
			_RPT2(_CRT_ERROR, "%s(...): GetModuleFileName(%08X, ...) returned 0\n",
				__FUNCTION__, hInstance);
			return 0;
		}
	}
	return buffer;
}

char *validate_filename(char *buf, char substchar) {
	_ASSERTE(buf != 0);
	if (buf != 0) for (char *osfriendly = buf; *osfriendly != 0; ++osfriendly)
		if (__iscsym(*(uchar *)osfriendly) == 0
			&& strchr(",.\';[]{}=+-()&^%$#@!~` ", *osfriendly) == 0)
				*osfriendly = substchar;
	return buf;
}

void safe_free(void *&p) {
	if (p != 0) __try {
		free(p);
		p = 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		_RPT4(_CRT_ERROR, "%s(%08X): free(%08X) failed: %s\n",
			__FUNCTION__, p, p, "unknown exceptioon");
	}
}

POINT GetCtrlAnchorPoint(HWND hwndDlg, int nIdDlgItem) {
	POINT pt = { 0, 0 };
	const HWND hwnd(GetDlgItem(hwndDlg, nIdDlgItem));
	if (hwnd != NULL) {
		RECT r;
		GetWindowRect(hwnd, &r);
		pt.x = r.left;
		pt.y = r.bottom;
	}
	return pt;
}

void RestoreDialogPos(HWND hwndDlg, const char *inisection) {
	UINT dlg_pos(GetPrivateProfileInt(inisection, "dlg_pos", 0, inipath));
	if (dlg_pos != 0) {
		RECT rect;
		GetWindowRect(hwndDlg, &rect);
		MoveWindow(hwndDlg, LOWORD(dlg_pos), HIWORD(dlg_pos),
			rect.right - rect.left, rect.bottom - rect.top, FALSE);
	}
}

void SaveDialogPos(HWND hwndDlg, const char *inisection) {
	RECT rect;
	GetWindowRect(hwndDlg, &rect);
	save_dword(inisection, "dlg_pos", MAKELONG(rect.left, rect.top));
}

bool save_dword(const char *section, const char *name, uint32 value) {
	char tmp[12];
	return WritePrivateProfileString(section, name, _ultoa(value, tmp, 10), inipath);
}

bool save_byte(const char *section, const char *name, uint8 value) {
	char tmp[4];
	return WritePrivateProfileString(section, name, _ultoa(value, tmp, 10), inipath);
}

bool is_pe32(const char *lpAppPath) {
	bool is(false);
	_ASSERTE(lpAppPath != 0 && *lpAppPath != 0);
	if (lpAppPath != 0 && *lpAppPath != 0) {
		int fio(_open(lpAppPath, _O_BINARY | _O_RDONLY, _S_IREAD));
		if (fio != -1) {
			if (_lseek(fio, 0, SEEK_SET) == 0) {
				IMAGE_DOS_HEADER doshdr;
				if (_read(fio, &doshdr, sizeof doshdr) == sizeof doshdr
					&& doshdr.e_magic == IMAGE_DOS_SIGNATURE
					&& _lseek(fio, doshdr.e_lfanew, SEEK_SET) == doshdr.e_lfanew) {
					IMAGE_NT_HEADERS nthdr;
					if (_read(fio, &nthdr, sizeof nthdr) == sizeof nthdr
						&& nthdr.Signature == IMAGE_NT_SIGNATURE
						//&& nthdr.FileHeader.Machine == IMAGE_FILE_MACHINE_I386
						&& (nthdr.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0
						//&& (nthdr.FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) != 0
						//&& (nthdr.FileHeader.Characteristics & IMAGE_FILE_DLL) == 0
						&& nthdr.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
						is = true;
				} // seek pe ok
			} // seek start ok
			_close(fio);
		} // _open ok
	} // filename present
	return is;
}

bool is_winnt() {
	OSVERSIONINFO VerInfo;
	memset(&VerInfo, 0, sizeof VerInfo);
	VerInfo.dwOSVersionInfoSize = sizeof VerInfo;
	return GetVersionEx(&VerInfo) && VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT;
}

BOOL GetFixedFileInfo(LPCTSTR lpstrFilename, VS_FIXEDFILEINFO &pFixedFileInfo) {
	ZeroMemory(&pFixedFileInfo, sizeof VS_FIXEDFILEINFO);
	_ASSERTE(lpstrFilename != 0);
	if (lpstrFilename == 0 || !qfileexist(lpstrFilename)) return FALSE;
	DWORD Handle, Len(GetFileVersionInfoSize(lpstrFilename, &Handle));
	if (Len <= 0) return FALSE;
	boost::shared_localptr<VOID, NONZEROLPTR> Data(Len);
	if (!Data) {
		_RPT2(_CRT_ERROR, "%s(...): failed to allocate memory block of size 0x%lX (LocalAlloc)\n",
			__FUNCTION__, Len);
		throw std::bad_alloc(); //return FALSE;
	}
	LPVOID lpBuffer;
	UINT uLen;
	BOOL ok = GetFileVersionInfo(lpstrFilename, Handle, Len, Data.get())
		&& VerQueryValue(Data.get(), "\\", &lpBuffer, &uLen);
	if (ok) pFixedFileInfo = *static_cast<VS_FIXEDFILEINFO *>(lpBuffer);
	return ok;
}

BOOL GetFixedFileInfo(HMODULE hModule, VS_FIXEDFILEINFO &fi) {
	ZeroMemory(&fi, sizeof VS_FIXEDFILEINFO);
	TCHAR strFilename[MAX_PATH];
	return GetModuleFileName(hModule, CPY(strFilename)) > 0 ?
		GetFixedFileInfo(strFilename, fi) : FALSE;
}

bool test_for_mask(DWORD value) {
	__asm {
		mov al, 1
		cmp value, 0
		jz test_for_mask_ret
		mov ecx, 20h
	test_for_mask_loop: cmp value, 1
		jz test_for_mask_ret
		cmp value, 0FFFFFFFh
		jz test_for_mask_ret
		ror value, 1
		loop test_for_mask_loop
		dec al
	test_for_mask_ret:
	}
}

int8 log2(uint32 n) {
	__asm {
		mov al, 1Fh
	log2_loop: rol n, 1
		jc log2_ret
		dec al
		jns log2_loop
	log2_ret:
	}
}

uint32 rdownpow2(uint32 n) {
	__asm {
		push 20h
		pop ecx
		mov eax, 80000000h
	rdownpow2_loop: test n, eax
		jnz rdownpow2_ret
		shr eax, 1
		loop rdownpow2_loop
	rdownpow2_ret:
	}
}

uint32 rounduppow2(uint32 n) {
	uint32 ret(rdownpow2(n));
	if (n > ret/* && (ret & 0x80000000) == 0*/) {
		_ASSERTE(ret >> 31 == 0); // free bit for up-shift available?
		ret <<= 1;
	}
	return ret;
}

int8 log2_64(uint64 n) {
	__asm {
		mov al, 3Fh
	log2_64_loop: shl dword ptr n, 1
		rcl dword ptr [n+4], 1
		jc log2_64_ret
		dec al
		jns log2_64_loop
	log2_64_ret:
	}
}

uint64 rdownpow2_64(uint64 n) {
	__asm {
		push 40h
		pop ecx
		xor eax, eax
		mov edx, 80000000h
	rdownpow2_64_loop: test dword ptr [n+4], edx
		jnz rdownpow2_64_ret
		test dword ptr n, eax
		jnz rdownpow2_64_ret
		shr edx, 1
		rcr eax, 1
		loop rdownpow2_64_loop
	rdownpow2_64_ret:
	}
}

uint64 rounduppow2_64(uint64 n) {
	uint64 ret(rdownpow2(n));
	if (n > ret) ret <<= 1;
	return ret;
}

const char *GetMessageName(UINT uMsg) {
	switch (uMsg) {
#define TOKENIZE_EVENT(x) case x: return #x;
		TOKENIZE_EVENT(WM_ACTIVATE)
		TOKENIZE_EVENT(WM_ACTIVATEAPP)
		TOKENIZE_EVENT(WM_AFXFIRST)
		TOKENIZE_EVENT(WM_AFXLAST)
		TOKENIZE_EVENT(WM_APP)
		TOKENIZE_EVENT(WM_APPCOMMAND)
		TOKENIZE_EVENT(WM_ASKCBFORMATNAME)
		TOKENIZE_EVENT(WM_CANCELJOURNAL)
		TOKENIZE_EVENT(WM_CANCELMODE)
		TOKENIZE_EVENT(WM_CAPTURECHANGED)
		TOKENIZE_EVENT(WM_CLEAR)
		TOKENIZE_EVENT(WM_CLOSE)
		TOKENIZE_EVENT(WM_COMMAND)
		TOKENIZE_EVENT(WM_COMMNOTIFY)
		TOKENIZE_EVENT(WM_COMPACTING)
		TOKENIZE_EVENT(WM_COMPAREITEM)
		TOKENIZE_EVENT(WM_CONTEXTMENU)
		TOKENIZE_EVENT(WM_COPY)
		TOKENIZE_EVENT(WM_COPYDATA)
		TOKENIZE_EVENT(WM_CREATE)
		TOKENIZE_EVENT(WM_CTLCOLORBTN)
		TOKENIZE_EVENT(WM_CTLCOLORDLG)
		TOKENIZE_EVENT(WM_CTLCOLOREDIT)
		TOKENIZE_EVENT(WM_CTLCOLORLISTBOX)
		TOKENIZE_EVENT(WM_CTLCOLORMSGBOX)
		TOKENIZE_EVENT(WM_CTLCOLORSCROLLBAR)
		TOKENIZE_EVENT(WM_CTLCOLORSTATIC)
		TOKENIZE_EVENT(WM_CUT)
		TOKENIZE_EVENT(WM_DDE_ACK)
		TOKENIZE_EVENT(WM_DDE_ADVISE)
		TOKENIZE_EVENT(WM_DDE_DATA)
		TOKENIZE_EVENT(WM_DDE_EXECUTE)
		TOKENIZE_EVENT(WM_DDE_INITIATE)
		TOKENIZE_EVENT(WM_DDE_POKE)
		TOKENIZE_EVENT(WM_DDE_REQUEST)
		TOKENIZE_EVENT(WM_DDE_TERMINATE)
		TOKENIZE_EVENT(WM_DDE_UNADVISE)
		TOKENIZE_EVENT(WM_DEADCHAR)
		TOKENIZE_EVENT(WM_DELETEITEM)
		TOKENIZE_EVENT(WM_DESTROY)
		TOKENIZE_EVENT(WM_DESTROYCLIPBOARD)
		TOKENIZE_EVENT(WM_DEVICECHANGE)
		TOKENIZE_EVENT(WM_DEVMODECHANGE)
		TOKENIZE_EVENT(WM_DISPLAYCHANGE)
		TOKENIZE_EVENT(WM_DRAWCLIPBOARD)
		TOKENIZE_EVENT(WM_DRAWITEM)
		TOKENIZE_EVENT(WM_DROPFILES)
		TOKENIZE_EVENT(WM_ENABLE)
		TOKENIZE_EVENT(WM_ENDSESSION)
		TOKENIZE_EVENT(WM_ENTERIDLE)
		TOKENIZE_EVENT(WM_ENTERMENULOOP)
		TOKENIZE_EVENT(WM_ENTERSIZEMOVE)
		TOKENIZE_EVENT(WM_ERASEBKGND)
		TOKENIZE_EVENT(WM_EXITMENULOOP)
		TOKENIZE_EVENT(WM_EXITSIZEMOVE)
		TOKENIZE_EVENT(WM_FONTCHANGE)
		TOKENIZE_EVENT(WM_GETDLGCODE)
		TOKENIZE_EVENT(WM_GETFONT)
		TOKENIZE_EVENT(WM_GETHOTKEY)
		TOKENIZE_EVENT(WM_GETICON)
		TOKENIZE_EVENT(WM_GETMINMAXINFO)
		TOKENIZE_EVENT(WM_GETOBJECT)
		TOKENIZE_EVENT(WM_GETTEXT)
		TOKENIZE_EVENT(WM_GETTEXTLENGTH)
		TOKENIZE_EVENT(WM_HANDHELDFIRST)
		TOKENIZE_EVENT(WM_HANDHELDLAST)
		TOKENIZE_EVENT(WM_HELP)
		TOKENIZE_EVENT(WM_HOTKEY)
		TOKENIZE_EVENT(WM_HSCROLL)
		TOKENIZE_EVENT(WM_HSCROLLCLIPBOARD)
		TOKENIZE_EVENT(WM_CHANGECBCHAIN)
		TOKENIZE_EVENT(WM_CHANGEUISTATE)
		TOKENIZE_EVENT(WM_CHAR)
		TOKENIZE_EVENT(WM_CHARTOITEM)
		TOKENIZE_EVENT(WM_CHILDACTIVATE)
		TOKENIZE_EVENT(WM_ICONERASEBKGND)
		TOKENIZE_EVENT(WM_IME_COMPOSITION)
		TOKENIZE_EVENT(WM_IME_COMPOSITIONFULL)
		TOKENIZE_EVENT(WM_IME_CONTROL)
		TOKENIZE_EVENT(WM_IME_ENDCOMPOSITION)
		TOKENIZE_EVENT(WM_IME_CHAR)
		TOKENIZE_EVENT(WM_IME_KEYDOWN)
		TOKENIZE_EVENT(WM_IME_KEYUP)
		//TOKENIZE_EVENT(WM_IME_KEYLAST)
		TOKENIZE_EVENT(WM_IME_NOTIFY)
		TOKENIZE_EVENT(WM_IME_REQUEST)
		TOKENIZE_EVENT(WM_IME_SELECT)
		TOKENIZE_EVENT(WM_IME_SETCONTEXT)
		TOKENIZE_EVENT(WM_IME_STARTCOMPOSITION)
		TOKENIZE_EVENT(WM_INITDIALOG)
		TOKENIZE_EVENT(WM_INITMENU)
		TOKENIZE_EVENT(WM_INITMENUPOPUP)
		TOKENIZE_EVENT(WM_INPUT)
		TOKENIZE_EVENT(WM_INPUTLANGCHANGE)
		TOKENIZE_EVENT(WM_INPUTLANGCHANGEREQUEST)
		//TOKENIZE_EVENT(WM_KEYFIRST)
		TOKENIZE_EVENT(WM_KEYDOWN)
		TOKENIZE_EVENT(WM_KEYUP)
		//TOKENIZE_EVENT(WM_KEYLAST)
		TOKENIZE_EVENT(WM_KILLFOCUS)
		TOKENIZE_EVENT(WM_LBUTTONDBLCLK)
		TOKENIZE_EVENT(WM_LBUTTONDOWN)
		TOKENIZE_EVENT(WM_LBUTTONUP)
		TOKENIZE_EVENT(WM_MBUTTONDBLCLK)
		TOKENIZE_EVENT(WM_MBUTTONDOWN)
		TOKENIZE_EVENT(WM_MBUTTONUP)
		TOKENIZE_EVENT(WM_MDIACTIVATE)
		TOKENIZE_EVENT(WM_MDICASCADE)
		TOKENIZE_EVENT(WM_MDICREATE)
		TOKENIZE_EVENT(WM_MDIDESTROY)
		TOKENIZE_EVENT(WM_MDIGETACTIVE)
		TOKENIZE_EVENT(WM_MDIICONARRANGE)
		TOKENIZE_EVENT(WM_MDIMAXIMIZE)
		TOKENIZE_EVENT(WM_MDINEXT)
		TOKENIZE_EVENT(WM_MDIREFRESHMENU)
		TOKENIZE_EVENT(WM_MDIRESTORE)
		TOKENIZE_EVENT(WM_MDISETMENU)
		TOKENIZE_EVENT(WM_MDITILE)
		TOKENIZE_EVENT(WM_MEASUREITEM)
		TOKENIZE_EVENT(WM_MENUCOMMAND)
		TOKENIZE_EVENT(WM_MENUDRAG)
		TOKENIZE_EVENT(WM_MENUGETOBJECT)
		TOKENIZE_EVENT(WM_MENUCHAR)
		TOKENIZE_EVENT(WM_MENURBUTTONUP)
		TOKENIZE_EVENT(WM_MENUSELECT)
		TOKENIZE_EVENT(WM_MOUSEACTIVATE)
		//TOKENIZE_EVENT(WM_MOUSEFIRST)
		TOKENIZE_EVENT(WM_MOUSEHOVER)
		TOKENIZE_EVENT(WM_MOUSELEAVE)
		TOKENIZE_EVENT(WM_MOUSEMOVE)
		TOKENIZE_EVENT(WM_MOUSEWHEEL)
		//TOKENIZE_EVENT(WM_MOUSELAST)
		TOKENIZE_EVENT(WM_MOVE)
		TOKENIZE_EVENT(WM_MOVING)
		TOKENIZE_EVENT(WM_NCACTIVATE)
		TOKENIZE_EVENT(WM_NCCALCSIZE)
		TOKENIZE_EVENT(WM_NCCREATE)
		TOKENIZE_EVENT(WM_NCDESTROY)
		TOKENIZE_EVENT(WM_NCLBUTTONDBLCLK)
		TOKENIZE_EVENT(WM_NCLBUTTONDOWN)
		TOKENIZE_EVENT(WM_NCLBUTTONUP)
		TOKENIZE_EVENT(WM_NCMBUTTONDBLCLK)
		TOKENIZE_EVENT(WM_NCMBUTTONDOWN)
		TOKENIZE_EVENT(WM_NCMBUTTONUP)
		TOKENIZE_EVENT(WM_NCMOUSEHOVER)
		TOKENIZE_EVENT(WM_NCMOUSELEAVE)
		TOKENIZE_EVENT(WM_NCMOUSEMOVE)
		TOKENIZE_EVENT(WM_NCPAINT)
		TOKENIZE_EVENT(WM_NCRBUTTONDBLCLK)
		TOKENIZE_EVENT(WM_NCRBUTTONDOWN)
		TOKENIZE_EVENT(WM_NCRBUTTONUP)
		TOKENIZE_EVENT(WM_NCXBUTTONDBLCLK)
		TOKENIZE_EVENT(WM_NCXBUTTONDOWN)
		TOKENIZE_EVENT(WM_NCXBUTTONUP)
		TOKENIZE_EVENT(WM_NEXTDLGCTL)
		TOKENIZE_EVENT(WM_NEXTMENU)
		TOKENIZE_EVENT(WM_NCHITTEST)
		TOKENIZE_EVENT(WM_NOTIFY)
		TOKENIZE_EVENT(WM_NOTIFYFORMAT)
		TOKENIZE_EVENT(WM_NULL)
		TOKENIZE_EVENT(WM_PAINT)
		TOKENIZE_EVENT(WM_PAINTCLIPBOARD)
		TOKENIZE_EVENT(WM_PAINTICON)
		TOKENIZE_EVENT(WM_PALETTECHANGED)
		TOKENIZE_EVENT(WM_PALETTEISCHANGING)
		TOKENIZE_EVENT(WM_PARENTNOTIFY)
		TOKENIZE_EVENT(WM_PASTE)
		TOKENIZE_EVENT(WM_PENWINFIRST)
		TOKENIZE_EVENT(WM_PENWINLAST)
		TOKENIZE_EVENT(WM_POWER)
		TOKENIZE_EVENT(WM_POWERBROADCAST)
		TOKENIZE_EVENT(WM_PRINT)
		TOKENIZE_EVENT(WM_PRINTCLIENT)
		TOKENIZE_EVENT(WM_QUERYDRAGICON)
		TOKENIZE_EVENT(WM_QUERYENDSESSION)
		TOKENIZE_EVENT(WM_QUERYNEWPALETTE)
		TOKENIZE_EVENT(WM_QUERYOPEN)
		TOKENIZE_EVENT(WM_QUERYUISTATE)
		TOKENIZE_EVENT(WM_QUEUESYNC)
		TOKENIZE_EVENT(WM_QUIT)
		TOKENIZE_EVENT(WM_RBUTTONDBLCLK)
		TOKENIZE_EVENT(WM_RBUTTONDOWN)
		TOKENIZE_EVENT(WM_RBUTTONUP)
		TOKENIZE_EVENT(WM_RENDERALLFORMATS)
		TOKENIZE_EVENT(WM_RENDERFORMAT)
		TOKENIZE_EVENT(WM_SETCURSOR)
		TOKENIZE_EVENT(WM_SETFOCUS)
		TOKENIZE_EVENT(WM_SETFONT)
		TOKENIZE_EVENT(WM_SETHOTKEY)
		TOKENIZE_EVENT(WM_SETICON)
		TOKENIZE_EVENT(WM_SETREDRAW)
		TOKENIZE_EVENT(WM_SETTEXT)
		TOKENIZE_EVENT(WM_SETTINGCHANGE)
		TOKENIZE_EVENT(WM_SHOWWINDOW)
		TOKENIZE_EVENT(WM_SIZE)
		TOKENIZE_EVENT(WM_SIZECLIPBOARD)
		TOKENIZE_EVENT(WM_SIZING)
		TOKENIZE_EVENT(WM_SPOOLERSTATUS)
		TOKENIZE_EVENT(WM_STYLECHANGED)
		TOKENIZE_EVENT(WM_STYLECHANGING)
		TOKENIZE_EVENT(WM_SYNCPAINT)
		TOKENIZE_EVENT(WM_SYSCOLORCHANGE)
		TOKENIZE_EVENT(WM_SYSCOMMAND)
		TOKENIZE_EVENT(WM_SYSDEADCHAR)
		TOKENIZE_EVENT(WM_SYSCHAR)
		TOKENIZE_EVENT(WM_SYSKEYDOWN)
		TOKENIZE_EVENT(WM_SYSKEYUP)
		TOKENIZE_EVENT(WM_TABLET_FIRST)
		TOKENIZE_EVENT(WM_TABLET_LAST)
		TOKENIZE_EVENT(WM_TCARD)
		TOKENIZE_EVENT(WM_THEMECHANGED)
		TOKENIZE_EVENT(WM_TIMECHANGE)
		TOKENIZE_EVENT(WM_TIMER)
		TOKENIZE_EVENT(WM_UNDO)
		TOKENIZE_EVENT(WM_UNICHAR)
		TOKENIZE_EVENT(WM_UNINITMENUPOPUP)
		TOKENIZE_EVENT(WM_UPDATEUISTATE)
		//TOKENIZE_EVENT(WM_USER)
		TOKENIZE_EVENT(WM_USERCHANGED)
		TOKENIZE_EVENT(WM_VKEYTOITEM)
		TOKENIZE_EVENT(WM_VSCROLL)
		TOKENIZE_EVENT(WM_VSCROLLCLIPBOARD)
		TOKENIZE_EVENT(WM_WINDOWPOSCHANGED)
		TOKENIZE_EVENT(WM_WINDOWPOSCHANGING)
		//TOKENIZE_EVENT(WM_WININICHANGE)
		TOKENIZE_EVENT(WM_WTSSESSION_CHANGE)
		TOKENIZE_EVENT(WM_XBUTTONDBLCLK)
		TOKENIZE_EVENT(WM_XBUTTONDOWN)
		TOKENIZE_EVENT(WM_XBUTTONUP)
		// Dialog specific
		TOKENIZE_EVENT(DM_GETDEFID)
		TOKENIZE_EVENT(DM_SETDEFID)
		TOKENIZE_EVENT(DM_REPOSITION)
		// MFC specific
		case 0x0019: return "WM_CTLCOLOR";
		case 0x0363: return "WM_IDLEUPDATECMDUI";
		case 0x0366: return "WM_HELPHITTEST";
		case 0x0368: return "WM_RECALCPARENT";
		case 0x036A: return "WM_KICKIDLE";
		case 0x036D: return "WM_FLOATSTATUS";
		// Edit
		TOKENIZE_EVENT(EM_CANUNDO)
		TOKENIZE_EVENT(EM_CHARFROMPOS)
		TOKENIZE_EVENT(EM_EMPTYUNDOBUFFER)
		TOKENIZE_EVENT(EM_FMTLINES)
		TOKENIZE_EVENT(EM_GETFIRSTVISIBLELINE)
		TOKENIZE_EVENT(EM_GETHANDLE)
		TOKENIZE_EVENT(EM_GETIMESTATUS)
		TOKENIZE_EVENT(EM_GETLIMITTEXT)
		TOKENIZE_EVENT(EM_GETLINE)
		TOKENIZE_EVENT(EM_GETLINECOUNT)
		TOKENIZE_EVENT(EM_GETMARGINS)
		TOKENIZE_EVENT(EM_GETMODIFY)
		TOKENIZE_EVENT(EM_GETPASSWORDCHAR)
		TOKENIZE_EVENT(EM_GETRECT)
		TOKENIZE_EVENT(EM_GETSEL)
		TOKENIZE_EVENT(EM_GETTHUMB)
		TOKENIZE_EVENT(EM_GETWORDBREAKPROC)
		TOKENIZE_EVENT(EM_LIMITTEXT)
		TOKENIZE_EVENT(EM_LINEFROMCHAR)
		TOKENIZE_EVENT(EM_LINEINDEX)
		TOKENIZE_EVENT(EM_LINELENGTH)
		TOKENIZE_EVENT(EM_LINESCROLL)
		TOKENIZE_EVENT(EM_POSFROMCHAR)
		TOKENIZE_EVENT(EM_REPLACESEL)
		TOKENIZE_EVENT(EM_SCROLL)
		TOKENIZE_EVENT(EM_SCROLLCARET)
		TOKENIZE_EVENT(EM_SETHANDLE)
		TOKENIZE_EVENT(EM_SETIMESTATUS)
		TOKENIZE_EVENT(EM_SETMARGINS)
		TOKENIZE_EVENT(EM_SETMODIFY)
		TOKENIZE_EVENT(EM_SETPASSWORDCHAR)
		TOKENIZE_EVENT(EM_SETREADONLY)
		TOKENIZE_EVENT(EM_SETRECT)
		TOKENIZE_EVENT(EM_SETRECTNP)
		TOKENIZE_EVENT(EM_SETSEL)
		TOKENIZE_EVENT(EM_SETTABSTOPS)
		TOKENIZE_EVENT(EM_SETWORDBREAKPROC)
		TOKENIZE_EVENT(EM_UNDO)
		// ComboBox
		TOKENIZE_EVENT(CB_ADDSTRING)
		TOKENIZE_EVENT(CB_DELETESTRING)
		TOKENIZE_EVENT(CB_DIR)
		TOKENIZE_EVENT(CB_FINDSTRING)
		TOKENIZE_EVENT(CB_FINDSTRINGEXACT)
		TOKENIZE_EVENT(CB_GETCOMBOBOXINFO)
		TOKENIZE_EVENT(CB_GETCOUNT)
		TOKENIZE_EVENT(CB_GETCURSEL)
		TOKENIZE_EVENT(CB_GETDROPPEDCONTROLRECT)
		TOKENIZE_EVENT(CB_GETDROPPEDSTATE)
		TOKENIZE_EVENT(CB_GETDROPPEDWIDTH)
		TOKENIZE_EVENT(CB_GETEDITSEL)
		TOKENIZE_EVENT(CB_GETEXTENDEDUI)
		TOKENIZE_EVENT(CB_GETHORIZONTALEXTENT)
		TOKENIZE_EVENT(CB_GETITEMDATA)
		TOKENIZE_EVENT(CB_GETITEMHEIGHT)
		TOKENIZE_EVENT(CB_GETLBTEXT)
		TOKENIZE_EVENT(CB_GETLBTEXTLEN)
		TOKENIZE_EVENT(CB_GETLOCALE)
		TOKENIZE_EVENT(CB_GETTOPINDEX)
		TOKENIZE_EVENT(CB_INITSTORAGE)
		TOKENIZE_EVENT(CB_INSERTSTRING)
		TOKENIZE_EVENT(CB_LIMITTEXT)
		TOKENIZE_EVENT(CB_MSGMAX)
		TOKENIZE_EVENT(CB_MULTIPLEADDSTRING)
		TOKENIZE_EVENT(CB_RESETCONTENT)
		TOKENIZE_EVENT(CB_SELECTSTRING)
		TOKENIZE_EVENT(CB_SETCURSEL)
		TOKENIZE_EVENT(CB_SETDROPPEDWIDTH)
		TOKENIZE_EVENT(CB_SETEDITSEL)
		TOKENIZE_EVENT(CB_SETEXTENDEDUI)
		TOKENIZE_EVENT(CB_SETHORIZONTALEXTENT)
		TOKENIZE_EVENT(CB_SETITEMDATA)
		TOKENIZE_EVENT(CB_SETITEMHEIGHT)
		TOKENIZE_EVENT(CB_SETLOCALE)
		TOKENIZE_EVENT(CB_SETTOPINDEX)
		TOKENIZE_EVENT(CB_SHOWDROPDOWN)
		// ListBox
		TOKENIZE_EVENT(LB_ADDFILE)
		TOKENIZE_EVENT(LB_ADDSTRING)
		TOKENIZE_EVENT(LB_DELETESTRING)
		TOKENIZE_EVENT(LB_DIR)
		TOKENIZE_EVENT(LB_FINDSTRING)
		TOKENIZE_EVENT(LB_FINDSTRINGEXACT)
		TOKENIZE_EVENT(LB_GETANCHORINDEX)
		TOKENIZE_EVENT(LB_GETCARETINDEX)
		TOKENIZE_EVENT(LB_GETCOUNT)
		TOKENIZE_EVENT(LB_GETCURSEL)
		TOKENIZE_EVENT(LB_GETHORIZONTALEXTENT)
		TOKENIZE_EVENT(LB_GETITEMDATA)
		TOKENIZE_EVENT(LB_GETITEMHEIGHT)
		TOKENIZE_EVENT(LB_GETITEMRECT)
		TOKENIZE_EVENT(LB_GETLOCALE)
		TOKENIZE_EVENT(LB_GETSEL)
		TOKENIZE_EVENT(LB_GETSELCOUNT)
		TOKENIZE_EVENT(LB_GETSELITEMS)
		TOKENIZE_EVENT(LB_GETTEXT)
		TOKENIZE_EVENT(LB_GETTEXTLEN)
		TOKENIZE_EVENT(LB_GETTOPINDEX)
		TOKENIZE_EVENT(LB_INITSTORAGE)
		TOKENIZE_EVENT(LB_INSERTSTRING)
		TOKENIZE_EVENT(LB_ITEMFROMPOINT)
		TOKENIZE_EVENT(LB_MULTIPLEADDSTRING)
		TOKENIZE_EVENT(LB_RESETCONTENT)
		TOKENIZE_EVENT(LB_SELECTSTRING)
		TOKENIZE_EVENT(LB_SELITEMRANGE)
		TOKENIZE_EVENT(LB_SELITEMRANGEEX)
		TOKENIZE_EVENT(LB_SETANCHORINDEX)
		TOKENIZE_EVENT(LB_SETCARETINDEX)
		TOKENIZE_EVENT(LB_SETCOLUMNWIDTH)
		TOKENIZE_EVENT(LB_SETCOUNT)
		TOKENIZE_EVENT(LB_SETCURSEL)
		TOKENIZE_EVENT(LB_SETHORIZONTALEXTENT)
		TOKENIZE_EVENT(LB_SETITEMDATA)
		TOKENIZE_EVENT(LB_SETITEMHEIGHT)
		TOKENIZE_EVENT(LB_SETLOCALE)
		TOKENIZE_EVENT(LB_SETSEL)
		TOKENIZE_EVENT(LB_SETTABSTOPS)
		TOKENIZE_EVENT(LB_SETTOPINDEX)
		// Button
		TOKENIZE_EVENT(BM_GETCHECK)
		TOKENIZE_EVENT(BM_SETCHECK)
		TOKENIZE_EVENT(BM_GETSTATE)
		TOKENIZE_EVENT(BM_SETSTATE)
		TOKENIZE_EVENT(BM_SETSTYLE)
		TOKENIZE_EVENT(BM_CLICK)
		TOKENIZE_EVENT(BM_GETIMAGE)
		TOKENIZE_EVENT(BM_SETIMAGE)
		// ScrollBar
		TOKENIZE_EVENT(SBM_ENABLE_ARROWS)
		TOKENIZE_EVENT(SBM_GETPOS)
		TOKENIZE_EVENT(SBM_GETRANGE)
		TOKENIZE_EVENT(SBM_GETSCROLLBARINFO)
		TOKENIZE_EVENT(SBM_GETSCROLLINFO)
		TOKENIZE_EVENT(SBM_SETPOS)
		TOKENIZE_EVENT(SBM_SETRANGE)
		TOKENIZE_EVENT(SBM_SETRANGEREDRAW)
		TOKENIZE_EVENT(SBM_SETSCROLLINFO)
		// Animation
		TOKENIZE_EVENT(ACM_OPEN)
		TOKENIZE_EVENT(ACM_PLAY)
		TOKENIZE_EVENT(ACM_STOP)
		// ComboBoxEx
		TOKENIZE_EVENT(CBEM_GETCOMBOCONTROL)
		TOKENIZE_EVENT(CBEM_GETEDITCONTROL)
		TOKENIZE_EVENT(CBEM_GETEXTENDEDSTYLE)
		TOKENIZE_EVENT(CBEM_GETITEM)
		TOKENIZE_EVENT(CBEM_GETUNICODEFORMAT)
		TOKENIZE_EVENT(CBEM_HASEDITCHANGED)
		//TOKENIZE_EVENT(CBEM_INSERTITEM)
		//TOKENIZE_EVENT(CBEM_KILLCOMBOFOCUS)
		//TOKENIZE_EVENT(CBEM_SETCOMBOFOCUS)
		TOKENIZE_EVENT(CBEM_SETEXTENDEDSTYLE)
		//TOKENIZE_EVENT(CBEM_SETIMAGELIST)
		TOKENIZE_EVENT(CBEM_SETITEM)
		TOKENIZE_EVENT(CBEM_SETUNICODEFORMAT)
		TOKENIZE_EVENT(CBEM_SETWINDOWTHEME)
		// DateTime Picker
		TOKENIZE_EVENT(DTM_GETMCCOLOR)
		TOKENIZE_EVENT(DTM_GETMCFONT)
		TOKENIZE_EVENT(DTM_GETMONTHCAL)
		TOKENIZE_EVENT(DTM_GETRANGE)
		TOKENIZE_EVENT(DTM_GETSYSTEMTIME)
		TOKENIZE_EVENT(DTM_SETFORMAT)
		TOKENIZE_EVENT(DTM_SETMCCOLOR)
		TOKENIZE_EVENT(DTM_SETMCFONT)
		TOKENIZE_EVENT(DTM_SETRANGE)
		TOKENIZE_EVENT(DTM_SETSYSTEMTIME)
		// Header
		TOKENIZE_EVENT(HDM_CLEARFILTER)
		TOKENIZE_EVENT(HDM_CREATEDRAGIMAGE)
		TOKENIZE_EVENT(HDM_DELETEITEM)
		TOKENIZE_EVENT(HDM_EDITFILTER)
		TOKENIZE_EVENT(HDM_GETBITMAPMARGIN)
		TOKENIZE_EVENT(HDM_GETIMAGELIST)
		TOKENIZE_EVENT(HDM_GETITEM)
		TOKENIZE_EVENT(HDM_GETITEMCOUNT)
		TOKENIZE_EVENT(HDM_GETITEMRECT)
		TOKENIZE_EVENT(HDM_GETORDERARRAY)
		TOKENIZE_EVENT(HDM_HITTEST)
		TOKENIZE_EVENT(HDM_INSERTITEM)
		TOKENIZE_EVENT(HDM_LAYOUT)
		TOKENIZE_EVENT(HDM_ORDERTOINDEX)
		TOKENIZE_EVENT(HDM_SETBITMAPMARGIN)
		TOKENIZE_EVENT(HDM_SETFILTERCHANGETIMEOUT)
		TOKENIZE_EVENT(HDM_SETHOTDIVIDER)
		TOKENIZE_EVENT(HDM_SETIMAGELIST)
		TOKENIZE_EVENT(HDM_SETITEM)
		TOKENIZE_EVENT(HDM_SETORDERARRAY)
		// IP Address
		TOKENIZE_EVENT(IPM_ISBLANK)
		TOKENIZE_EVENT(IPM_SETFOCUS)
		TOKENIZE_EVENT(IPM_SETRANGE)
		// ListView
		TOKENIZE_EVENT(LVM_APPROXIMATEVIEWRECT)
		TOKENIZE_EVENT(LVM_ARRANGE)
		TOKENIZE_EVENT(LVM_CANCELEDITLABEL)
		TOKENIZE_EVENT(LVM_CREATEDRAGIMAGE)
		TOKENIZE_EVENT(LVM_DELETECOLUMN)
		TOKENIZE_EVENT(LVM_EDITLABEL)
		TOKENIZE_EVENT(LVM_ENABLEGROUPVIEW)
		TOKENIZE_EVENT(LVM_ENSUREVISIBLE)
		TOKENIZE_EVENT(LVM_FINDITEM)
		TOKENIZE_EVENT(LVM_GETBKCOLOR)
		TOKENIZE_EVENT(LVM_GETBKIMAGE)
		TOKENIZE_EVENT(LVM_GETCOLUMN)
		TOKENIZE_EVENT(LVM_GETCOLUMNORDERARRAY)
		TOKENIZE_EVENT(LVM_GETCOLUMNWIDTH)
		TOKENIZE_EVENT(LVM_GETCOUNTPERPAGE)
		TOKENIZE_EVENT(LVM_GETEDITCONTROL)
		TOKENIZE_EVENT(LVM_GETEXTENDEDLISTVIEWSTYLE)
		TOKENIZE_EVENT(LVM_GETGROUPINFO)
		TOKENIZE_EVENT(LVM_GETGROUPMETRICS)
		TOKENIZE_EVENT(LVM_GETHEADER)
		TOKENIZE_EVENT(LVM_GETHOTCURSOR)
		TOKENIZE_EVENT(LVM_GETHOTITEM)
		TOKENIZE_EVENT(LVM_GETHOVERTIME)
		TOKENIZE_EVENT(LVM_GETINSERTMARK)
		TOKENIZE_EVENT(LVM_GETINSERTMARKCOLOR)
		TOKENIZE_EVENT(LVM_GETINSERTMARKRECT)
		TOKENIZE_EVENT(LVM_GETISEARCHSTRING)
		TOKENIZE_EVENT(LVM_GETITEMPOSITION)
		TOKENIZE_EVENT(LVM_GETITEMRECT)
		TOKENIZE_EVENT(LVM_GETITEMSPACING)
		TOKENIZE_EVENT(LVM_GETITEMSTATE)
		TOKENIZE_EVENT(LVM_GETITEMTEXT)
		TOKENIZE_EVENT(LVM_GETNEXTITEM)
		TOKENIZE_EVENT(LVM_GETNUMBEROFWORKAREAS)
		TOKENIZE_EVENT(LVM_GETORIGIN)
		TOKENIZE_EVENT(LVM_GETOUTLINECOLOR)
		TOKENIZE_EVENT(LVM_GETSELECTEDCOLUMN)
		TOKENIZE_EVENT(LVM_GETSELECTEDCOUNT)
		TOKENIZE_EVENT(LVM_GETSELECTIONMARK)
		TOKENIZE_EVENT(LVM_GETSTRINGWIDTH)
		TOKENIZE_EVENT(LVM_GETSUBITEMRECT)
		TOKENIZE_EVENT(LVM_GETTEXTBKCOLOR)
		TOKENIZE_EVENT(LVM_GETTEXTCOLOR)
		TOKENIZE_EVENT(LVM_GETTILEINFO)
		TOKENIZE_EVENT(LVM_GETTILEVIEWINFO)
		TOKENIZE_EVENT(LVM_GETTOOLTIPS)
		TOKENIZE_EVENT(LVM_GETTOPINDEX)
		TOKENIZE_EVENT(LVM_GETVIEW)
		TOKENIZE_EVENT(LVM_GETVIEWRECT)
		TOKENIZE_EVENT(LVM_GETWORKAREAS)
		TOKENIZE_EVENT(LVM_HASGROUP)
		TOKENIZE_EVENT(LVM_HITTEST)
		TOKENIZE_EVENT(LVM_INSERTCOLUMN)
		TOKENIZE_EVENT(LVM_INSERTGROUP)
		TOKENIZE_EVENT(LVM_INSERTGROUPSORTED)
		TOKENIZE_EVENT(LVM_INSERTMARKHITTEST)
		TOKENIZE_EVENT(LVM_ISGROUPVIEWENABLED)
		TOKENIZE_EVENT(LVM_MAPIDTOINDEX)
		TOKENIZE_EVENT(LVM_MAPINDEXTOID)
		TOKENIZE_EVENT(LVM_MOVEGROUP)
		TOKENIZE_EVENT(LVM_MOVEITEMTOGROUP)
		TOKENIZE_EVENT(LVM_REDRAWITEMS)
		TOKENIZE_EVENT(LVM_REMOVEALLGROUPS)
		TOKENIZE_EVENT(LVM_REMOVEGROUP)
		TOKENIZE_EVENT(LVM_SCROLL)
		TOKENIZE_EVENT(LVM_SETBKIMAGE)
		TOKENIZE_EVENT(LVM_SETCALLBACKMASK)
		TOKENIZE_EVENT(LVM_SETCOLUMN)
		TOKENIZE_EVENT(LVM_SETCOLUMNORDERARRAY)
		TOKENIZE_EVENT(LVM_SETCOLUMNWIDTH)
		TOKENIZE_EVENT(LVM_SETEXTENDEDLISTVIEWSTYLE)
		TOKENIZE_EVENT(LVM_SETGROUPINFO)
		TOKENIZE_EVENT(LVM_SETGROUPMETRICS)
		TOKENIZE_EVENT(LVM_SETHOTCURSOR)
		TOKENIZE_EVENT(LVM_SETHOTITEM)
		TOKENIZE_EVENT(LVM_SETHOVERTIME)
		TOKENIZE_EVENT(LVM_SETICONSPACING)
		TOKENIZE_EVENT(LVM_SETINFOTIP)
		TOKENIZE_EVENT(LVM_SETINSERTMARK)
		TOKENIZE_EVENT(LVM_SETINSERTMARKCOLOR)
		TOKENIZE_EVENT(LVM_SETITEMCOUNT)
		TOKENIZE_EVENT(LVM_SETITEMPOSITION)
		TOKENIZE_EVENT(LVM_SETITEMPOSITION32)
		TOKENIZE_EVENT(LVM_SETITEMSTATE)
		TOKENIZE_EVENT(LVM_SETITEMTEXT)
		TOKENIZE_EVENT(LVM_SETOUTLINECOLOR)
		TOKENIZE_EVENT(LVM_SETSELECTEDCOLUMN)
		TOKENIZE_EVENT(LVM_SETSELECTIONMARK)
		TOKENIZE_EVENT(LVM_SETTEXTBKCOLOR)
		TOKENIZE_EVENT(LVM_SETTEXTCOLOR)
		TOKENIZE_EVENT(LVM_SETTILEINFO)
		TOKENIZE_EVENT(LVM_SETTILEVIEWINFO)
		TOKENIZE_EVENT(LVM_SETTILEWIDTH)
		TOKENIZE_EVENT(LVM_SETTOOLTIPS)
		TOKENIZE_EVENT(LVM_SETVIEW)
		TOKENIZE_EVENT(LVM_SETWORKAREAS)
		TOKENIZE_EVENT(LVM_SORTGROUPS)
		TOKENIZE_EVENT(LVM_SORTITEMS)
		TOKENIZE_EVENT(LVM_SORTITEMSEX)
		TOKENIZE_EVENT(LVM_SUBITEMHITTEST)
		TOKENIZE_EVENT(LVM_UPDATE)
		// Pager
		TOKENIZE_EVENT(PGM_FORWARDMOUSE)
		TOKENIZE_EVENT(PGM_GETBKCOLOR)
		TOKENIZE_EVENT(PGM_GETBORDER)
		TOKENIZE_EVENT(PGM_GETBUTTONSIZE)
		TOKENIZE_EVENT(PGM_GETBUTTONSTATE)
		TOKENIZE_EVENT(PGM_GETDROPTARGET)
		TOKENIZE_EVENT(PGM_GETPOS)
		TOKENIZE_EVENT(PGM_RECALCSIZE)
		TOKENIZE_EVENT(PGM_SETBKCOLOR)
		TOKENIZE_EVENT(PGM_SETBORDER)
		TOKENIZE_EVENT(PGM_SETBUTTONSIZE)
		TOKENIZE_EVENT(PGM_SETCHILD)
		TOKENIZE_EVENT(PGM_SETPOS)
		TOKENIZE_EVENT(PGN_SCROLL)
		// ProgressBar
		TOKENIZE_EVENT(PBM_GETPOS)
		TOKENIZE_EVENT(PBM_SETBKCOLOR)
		// Property Sheet
		TOKENIZE_EVENT(PSM_APPLY)
		TOKENIZE_EVENT(PSM_CANCELTOCLOSE)
		TOKENIZE_EVENT(PSM_GETCURRENTPAGEHWND)
		TOKENIZE_EVENT(PSM_GETRESULT)
		TOKENIZE_EVENT(PSM_GETTABCONTROL)
		TOKENIZE_EVENT(PSM_HWNDTOINDEX)
		TOKENIZE_EVENT(PSM_IDTOINDEX)
		TOKENIZE_EVENT(PSM_INDEXTOHWND)
		TOKENIZE_EVENT(PSM_INDEXTOID)
		TOKENIZE_EVENT(PSM_INDEXTOPAGE)
		TOKENIZE_EVENT(PSM_INSERTPAGE)
		TOKENIZE_EVENT(PSM_ISDIALOGMESSAGE)
		TOKENIZE_EVENT(PSM_PAGETOINDEX)
		TOKENIZE_EVENT(PSM_PRESSBUTTON)
		TOKENIZE_EVENT(PSM_QUERYSIBLINGS)
		TOKENIZE_EVENT(PSM_REBOOTSYSTEM)
		TOKENIZE_EVENT(PSM_RECALCPAGESIZES)
		TOKENIZE_EVENT(PSM_SETCURSELID)
		TOKENIZE_EVENT(PSM_SETFINISHTEXT)
		TOKENIZE_EVENT(PSM_SETHEADERSUBTITLE)
		TOKENIZE_EVENT(PSM_SETHEADERTITLE)
		TOKENIZE_EVENT(PSM_SETTITLE)
		TOKENIZE_EVENT(PSM_SETWIZBUTTONS)
		TOKENIZE_EVENT(PSM_UNCHANGED)
		// ReBar
		TOKENIZE_EVENT(RB_BEGINDRAG)
		TOKENIZE_EVENT(RB_DRAGMOVE)
		TOKENIZE_EVENT(RB_ENDDRAG)
		TOKENIZE_EVENT(RB_GETBANDBORDERS)
		TOKENIZE_EVENT(RB_GETBANDCOUNT)
		TOKENIZE_EVENT(RB_GETBANDINFO)
		TOKENIZE_EVENT(RB_GETBANDMARGINS)
		TOKENIZE_EVENT(RB_GETBARHEIGHT)
		TOKENIZE_EVENT(RB_GETBKCOLOR)
		TOKENIZE_EVENT(RB_GETCOLORSCHEME)
		TOKENIZE_EVENT(RB_GETPALETTE)
		TOKENIZE_EVENT(RB_GETROWCOUNT)
		TOKENIZE_EVENT(RB_GETTEXTCOLOR)
		TOKENIZE_EVENT(RB_GETTOOLTIPS)
		TOKENIZE_EVENT(RB_IDTOINDEX)
		TOKENIZE_EVENT(RB_MAXIMIZEBAND)
		TOKENIZE_EVENT(RB_MINIMIZEBAND)
		TOKENIZE_EVENT(RB_MOVEBAND)
		TOKENIZE_EVENT(RB_PUSHCHEVRON)
		TOKENIZE_EVENT(RB_SETBKCOLOR)
		TOKENIZE_EVENT(RB_SETCOLORSCHEME)
		TOKENIZE_EVENT(RB_SETPALETTE)
		TOKENIZE_EVENT(RB_SETTEXTCOLOR)
		TOKENIZE_EVENT(RB_SETTOOLTIPS)
		TOKENIZE_EVENT(RB_SHOWBAND)
		TOKENIZE_EVENT(RB_SIZETORECT)
		// RichText
		TOKENIZE_EVENT(EM_AUTOURLDETECT)
		TOKENIZE_EVENT(EM_CANPASTE)
		TOKENIZE_EVENT(EM_CANREDO)
		TOKENIZE_EVENT(EM_DISPLAYBAND)
		TOKENIZE_EVENT(EM_EXGETSEL)
		TOKENIZE_EVENT(EM_EXLIMITTEXT)
		TOKENIZE_EVENT(EM_EXLINEFROMCHAR)
		TOKENIZE_EVENT(EM_EXSETSEL)
		TOKENIZE_EVENT(EM_FINDTEXT)
		TOKENIZE_EVENT(EM_FINDTEXTEX)
		TOKENIZE_EVENT(EM_FINDTEXTEXW)
		TOKENIZE_EVENT(EM_FINDTEXTW)
		TOKENIZE_EVENT(EM_FINDWORDBREAK)
		TOKENIZE_EVENT(EM_FORMATRANGE)
		TOKENIZE_EVENT(EM_GETAUTOURLDETECT)
		TOKENIZE_EVENT(EM_GETBIDIOPTIONS)
		TOKENIZE_EVENT(EM_GETCHARFORMAT)
		TOKENIZE_EVENT(EM_GETCTFMODEBIAS)
		TOKENIZE_EVENT(EM_GETCTFOPENSTATUS)
		TOKENIZE_EVENT(EM_GETEDITSTYLE)
		TOKENIZE_EVENT(EM_GETEVENTMASK)
		TOKENIZE_EVENT(EM_GETHYPHENATEINFO)
		TOKENIZE_EVENT(EM_GETIMECOMPMODE)
		TOKENIZE_EVENT(EM_GETIMECOMPTEXT)
		TOKENIZE_EVENT(EM_GETIMEPROPERTY)
		TOKENIZE_EVENT(EM_GETLANGOPTIONS)
		TOKENIZE_EVENT(EM_GETOLEINTERFACE)
		TOKENIZE_EVENT(EM_GETOPTIONS)
		TOKENIZE_EVENT(EM_GETPAGEROTATE)
		TOKENIZE_EVENT(EM_GETPARAFORMAT)
		TOKENIZE_EVENT(EM_GETREDONAME)
		TOKENIZE_EVENT(EM_GETSCROLLPOS)
		TOKENIZE_EVENT(EM_GETSELTEXT)
		TOKENIZE_EVENT(EM_GETTEXTEX)
		TOKENIZE_EVENT(EM_GETTEXTLENGTHEX)
		TOKENIZE_EVENT(EM_GETTEXTMODE)
		TOKENIZE_EVENT(EM_GETTEXTRANGE)
		TOKENIZE_EVENT(EM_GETTYPOGRAPHYOPTIONS)
		TOKENIZE_EVENT(EM_GETUNDONAME)
		TOKENIZE_EVENT(EM_GETWORDBREAKPROCEX)
		TOKENIZE_EVENT(EM_GETZOOM)
		TOKENIZE_EVENT(EM_HIDESELECTION)
		TOKENIZE_EVENT(EM_ISIME)
		TOKENIZE_EVENT(EM_PASTESPECIAL)
		TOKENIZE_EVENT(EM_REDO)
		TOKENIZE_EVENT(EM_REQUESTRESIZE)
		TOKENIZE_EVENT(EM_SELECTIONTYPE)
		TOKENIZE_EVENT(EM_SETBIDIOPTIONS)
		TOKENIZE_EVENT(EM_SETBKGNDCOLOR)
		TOKENIZE_EVENT(EM_SETCHARFORMAT)
		TOKENIZE_EVENT(EM_SETCTFMODEBIAS)
		TOKENIZE_EVENT(EM_SETCTFOPENSTATUS)
		TOKENIZE_EVENT(EM_SETEDITSTYLE)
		TOKENIZE_EVENT(EM_SETEVENTMASK)
		TOKENIZE_EVENT(EM_SETFONTSIZE)
		TOKENIZE_EVENT(EM_SETHYPHENATEINFO)
		TOKENIZE_EVENT(EM_SETIMEMODEBIAS)
		TOKENIZE_EVENT(EM_SETLANGOPTIONS)
		TOKENIZE_EVENT(EM_SETOLECALLBACK)
		TOKENIZE_EVENT(EM_SETOPTIONS)
		TOKENIZE_EVENT(EM_SETPAGEROTATE)
		TOKENIZE_EVENT(EM_SETPALETTE)
		TOKENIZE_EVENT(EM_SETPARAFORMAT)
		TOKENIZE_EVENT(EM_SETSCROLLPOS)
		TOKENIZE_EVENT(EM_SETTARGETDEVICE)
		TOKENIZE_EVENT(EM_SETTEXTEX)
		TOKENIZE_EVENT(EM_SETTEXTMODE)
		TOKENIZE_EVENT(EM_SETTYPOGRAPHYOPTIONS)
		TOKENIZE_EVENT(EM_SETUNDOLIMIT)
		TOKENIZE_EVENT(EM_SETWORDBREAKPROCEX)
		TOKENIZE_EVENT(EM_SETZOOM)
		TOKENIZE_EVENT(EM_SHOWSCROLLBAR)
		TOKENIZE_EVENT(EM_STOPGROUPTYPING)
		TOKENIZE_EVENT(EM_STREAMIN)
		TOKENIZE_EVENT(EM_STREAMOUT)
		// StatusBar
		TOKENIZE_EVENT(SB_SETICON)
		// SysLink
		TOKENIZE_EVENT(LM_GETIDEALHEIGHT)
		TOKENIZE_EVENT(LM_GETITEM)
		TOKENIZE_EVENT(LM_HITTEST)
		TOKENIZE_EVENT(LM_SETITEM)
		// Tab Control
		TOKENIZE_EVENT(TCM_ADJUSTRECT)
		TOKENIZE_EVENT(TCM_DELETEALLITEMS)
		TOKENIZE_EVENT(TCM_DELETEITEM)
		TOKENIZE_EVENT(TCM_DESELECTALL)
		TOKENIZE_EVENT(TCM_GETCURFOCUS)
		TOKENIZE_EVENT(TCM_GETCURSEL)
		TOKENIZE_EVENT(TCM_GETEXTENDEDSTYLE)
		TOKENIZE_EVENT(TCM_GETIMAGELIST)
		TOKENIZE_EVENT(TCM_GETITEM)
		TOKENIZE_EVENT(TCM_GETITEMCOUNT)
		TOKENIZE_EVENT(TCM_GETITEMRECT)
		TOKENIZE_EVENT(TCM_GETROWCOUNT)
		TOKENIZE_EVENT(TCM_GETTOOLTIPS)
		TOKENIZE_EVENT(TCM_HIGHLIGHTITEM)
		TOKENIZE_EVENT(TCM_HITTEST)
		TOKENIZE_EVENT(TCM_INSERTITEM)
		TOKENIZE_EVENT(TCM_REMOVEIMAGE)
		TOKENIZE_EVENT(TCM_SETCURFOCUS)
		TOKENIZE_EVENT(TCM_SETCURSEL)
		TOKENIZE_EVENT(TCM_SETEXTENDEDSTYLE)
		TOKENIZE_EVENT(TCM_SETIMAGELIST)
		TOKENIZE_EVENT(TCM_SETITEM)
		TOKENIZE_EVENT(TCM_SETITEMEXTRA)
		TOKENIZE_EVENT(TCM_SETITEMSIZE)
		TOKENIZE_EVENT(TCM_SETMINTABWIDTH)
		TOKENIZE_EVENT(TCM_SETPADDING)
		TOKENIZE_EVENT(TCM_SETTOOLTIPS)
		// ToolBar
		TOKENIZE_EVENT(TB_ADDSTRING)
		TOKENIZE_EVENT(TB_AUTOSIZE)
		TOKENIZE_EVENT(TB_GETBITMAP)
		TOKENIZE_EVENT(TB_GETBITMAPFLAGS)
		TOKENIZE_EVENT(TB_GETBUTTONTEXT)
		TOKENIZE_EVENT(TB_GETIMAGELIST)
		TOKENIZE_EVENT(TB_GETMAXSIZE)
		TOKENIZE_EVENT(TB_ISBUTTONPRESSED)
		TOKENIZE_EVENT(TB_REPLACEBITMAP)
		TOKENIZE_EVENT(TB_SETBITMAPSIZE)
		TOKENIZE_EVENT(TB_SETCMDID)
		TOKENIZE_EVENT(TB_SETIMAGELIST)
		TOKENIZE_EVENT(TB_SETINDENT)
		TOKENIZE_EVENT(TB_SETTOOLTIPS)
		// TreeView
		TOKENIZE_EVENT(TVM_CREATEDRAGIMAGE)
		TOKENIZE_EVENT(TVM_DELETEITEM)
		TOKENIZE_EVENT(TVM_EDITLABEL)
		TOKENIZE_EVENT(TVM_ENDEDITLABELNOW)
		TOKENIZE_EVENT(TVM_ENSUREVISIBLE)
		TOKENIZE_EVENT(TVM_EXPAND)
		TOKENIZE_EVENT(TVM_GETBKCOLOR)
		TOKENIZE_EVENT(TVM_GETCOUNT)
		TOKENIZE_EVENT(TVM_GETEDITCONTROL)
		TOKENIZE_EVENT(TVM_GETIMAGELIST)
		TOKENIZE_EVENT(TVM_GETINDENT)
		TOKENIZE_EVENT(TVM_GETINSERTMARKCOLOR)
		TOKENIZE_EVENT(TVM_GETISEARCHSTRING)
		TOKENIZE_EVENT(TVM_GETITEM)
		TOKENIZE_EVENT(TVM_GETITEMHEIGHT)
		TOKENIZE_EVENT(TVM_GETITEMRECT)
		TOKENIZE_EVENT(TVM_GETITEMSTATE)
		TOKENIZE_EVENT(TVM_GETLINECOLOR)
		TOKENIZE_EVENT(TVM_GETNEXTITEM)
		TOKENIZE_EVENT(TVM_GETSCROLLTIME)
		TOKENIZE_EVENT(TVM_GETTEXTCOLOR)
		TOKENIZE_EVENT(TVM_GETTOOLTIPS)
		TOKENIZE_EVENT(TVM_GETVISIBLECOUNT)
		TOKENIZE_EVENT(TVM_HITTEST)
		TOKENIZE_EVENT(TVM_INSERTITEM)
		TOKENIZE_EVENT(TVM_MAPACCIDTOHTREEITEM)
		TOKENIZE_EVENT(TVM_MAPHTREEITEMTOACCID)
		TOKENIZE_EVENT(TVM_SELECTITEM)
		TOKENIZE_EVENT(TVM_SETBKCOLOR)
		TOKENIZE_EVENT(TVM_SETIMAGELIST)
		TOKENIZE_EVENT(TVM_SETINDENT)
		TOKENIZE_EVENT(TVM_SETINSERTMARK)
		TOKENIZE_EVENT(TVM_SETINSERTMARKCOLOR)
		TOKENIZE_EVENT(TVM_SETITEM)
		TOKENIZE_EVENT(TVM_SETITEMHEIGHT)
		TOKENIZE_EVENT(TVM_SETLINECOLOR)
		TOKENIZE_EVENT(TVM_SETSCROLLTIME)
		TOKENIZE_EVENT(TVM_SETTEXTCOLOR)
		TOKENIZE_EVENT(TVM_SETTOOLTIPS)
		TOKENIZE_EVENT(TVM_SORTCHILDREN)
		TOKENIZE_EVENT(TVM_SORTCHILDRENCB)
#undef TOKENIZE_EVENT
	}
	static char tmpbuf[16];
	_snprintf(tmpbuf, sizeof(tmpbuf) / sizeof(tmpbuf[0]), "WM_%04X", uMsg);
	return (const char *)tmpbuf;
}
