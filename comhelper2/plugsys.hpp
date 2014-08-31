
/*****************************************************************************
 *                                                                           *
 *  plugsys.hpp: ida plugins shared code                                     *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef _PLUGSYS_HPP_
#define _PLUGSYS_HPP_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#pragma warning(disable:   47) // incompatible redefinition of macro "XXX"
#pragma warning(disable:  411) // class "xxxx" defines no constructor to initialize...
#elif defined(_MSC_VER)
#pragma warning(disable: 4005) // macro redefinition
#endif

#include "undbgnew.h"
#include <cstdarg>
#include <string>
#include <cstring>
#include <cstdio>
#include <wchar.h>
#include <ctype.h>
#include "mscrtdbg.h"
#define NOMINMAX 1
#include <wtypes.h>
#include <winnls.h>
#define BYTES_SOURCE                1
#include "idasdk.hpp"
#include "dbgnew.h"

#define LB_MULTIPLEADDSTRING    0x01B1
#define CB_MULTIPLEADDSTRING    0x0163

extern HINSTANCE hInstance;
extern char inipath[QMAXPATH];

inline int __cdecl _isascii(int c) {
	_ASSERTE(c >= 0);
	return isgraph(c) || isspace(c);
}
inline int __cdecl istext(int c) {
	_ASSERTE(c >= 0);
	return !iscntrl(c) || isspace(c);
}
inline int __cdecl isansi(int c) {
	_ASSERTE(c >= 0);
	return (c & ~0xFF) == 0;
}

int _vsprintf(std::string &s, const char *format, va_list va);
inline int _sprintf(std::string &s, const char *format, ...) {
	va_list va;
	va_start(va, format);
	const int result(_vsprintf(s, format, va));
	va_end(va);
	return result;
}
int _vsprintf_append(std::string &s, const char *format, va_list va);
inline int _sprintf_append(std::string &s, const char *format, ...) {
	va_list va;
	va_start(va, format);
	const int result(_vsprintf_append(s, format, va));
	va_end(va);
	return result;
}
std::string _sprintf(const char *format, ...);

int _vswprintf(std::wstring &s, const wchar_t *format, va_list va);
inline int _swprintf(std::wstring &s, const wchar_t *format, ...) {
	va_list va;
	va_start(va, format);
	const int result(_vswprintf(s, format, va));
	va_end(va);
	return result;
}
int _vswprintf_append(std::wstring &s, const wchar_t *format, va_list va);
inline int _swprintf_append(std::wstring &s, const wchar_t *format, ...) {
	va_list va;
	va_start(va, format);
	const int result(_vswprintf_append(s, format, va));
	va_end(va);
	return result;
}
std::wstring _swprintf(const wchar_t *format, ...);

#ifdef _DEBUG

#undef OutputDebugString
void OutputDebugString(const char *format, ...);
void OutputDebugString(const wchar_t *format, ...);

#else // !_DEBUG
#	ifdef _MSC_VER
#		define OutputDebugString  __noop
#		define OutputDebugStringA __noop
#		define OutputDebugStringW __noop
#	else // !_MSC_VER
#		inline void OutputDebugString(const char *, ...) { }
#		inline void OutputDebugString(const wchar_t *, ...) { }
#		define OutputDebugStringA(x) (0)
#		define OutputDebugStringW(x) (0)
#	endif // _MSC_VER
#endif // _DEBUG

// string handling helpers
const char *_stristr(const char *s, const char *sf);
inline char *_stristr(char *s, const char *sf)
	{ return const_cast<char *>(_stristr((const char *)s, sf)); }
#if IDP_INTERFACE_VERSION < 76 // this alias is reserved for regular function
#define stristr  _stristr
#endif
#define _strstri _stristr
#define strstri  _stristr
const wchar_t *_wcsistr(const wchar_t *s, const wchar_t *sf);
inline wchar_t *_wcsistr(wchar_t *s, const wchar_t *sf)
	{ return const_cast<wchar_t *>(_wcsistr((const wchar_t *)s, sf)); }
#define wcsistr  _wcsistr
#define _wcsstri _wcsistr
#define wcsistr  _wcsistr
int iwcsfunc(const wchar_t *, const char *, int (__cdecl &)(const wchar_t *, const wchar_t *));
int iwcsfunc(const char *, const wchar_t *, int (__cdecl &)(const wchar_t *, const wchar_t *));
inline int wcscmp(const wchar_t *ws, const char *s)
	{ return iwcsfunc(ws, s, wcscmp); }
inline int wcscmp(const char *s, const wchar_t *ws)
	{ return iwcsfunc(s, ws, wcscmp); }
inline int _wcsicmp(const wchar_t *ws, const char *s)
	{ return iwcsfunc(ws, s, _wcsicmp); }
inline int _wcsicmp(const char *s, const wchar_t *ws)
	{ return iwcsfunc(s, ws, _wcsicmp); }
inline wchar_t *tail(wchar_t *str)
	{ return wcschr(str, 0); }
inline const wchar_t *tail(const wchar_t *str)
	{ return wcschr(str, 0); }
// result same as of WideCharToMultiByte or -1 if exact true and substituted
int __wcstombs_internal(const wchar_t *ws, size_t len, char *s, size_t size,
	DWORD dwFlags, LPCSTR const lpDefaultChar, bool exact = false);
// result same as of WideCharToMultiByte
inline int _wcstombs(char *s, const wchar_t *ws, size_t size,
	DWORD dwFlags = WC_COMPOSITECHECK | WC_SEPCHARS, LPCSTR lpDefaultChar = "?") {
	return __wcstombs_internal(ws, (size_t)-1, s, size, dwFlags, lpDefaultChar, false);
}
// returns resulting ansi string length (not as of WideCharToMultiByte)
inline size_t wcstombs(const wchar_t *ws, size_t len, char *s, size_t size,
	DWORD dwFlags = WC_COMPOSITECHECK | WC_SEPCHARS, LPCSTR lpDefaultChar = "?") {
	return __wcstombs_internal(ws, len, s, size, dwFlags, lpDefaultChar) > 0 ? strlen(s) : 0;
}

char *caption_to_asmname(char *caption);
char *validate_filename(char *buf, char substchar = '_');
char *chomp(char *s, size_t maxlen, bool allcliterals = true); // flatenns all control codes id string
char *stripeoln(char *s);

int8 log2(uint32) throw(); // return -1 if error, otherwise 2 pow result = arg
int8 log2_64(uint64) throw(); // return -1 if error, otherwise 2 pow result = arg
uint32 rdownpow2(uint32) throw(); // round down to nearest power of 2
uint64 rdownpow2_64(uint64) throw(); // round down to nearest power of 2
uint32 rounduppow2(uint32) throw(); // round up to nearest power of 2
uint64 rounduppow2_64(uint64) throw(); // round up to nearest power of 2
bool test_for_mask(DWORD value) throw();
inline bool can_be_binary_mask(UINT value) throw()
	{ return test_for_mask(value) || test_for_mask(value + 1); }

bool save_dword(const char *section, const char *name, uint32 value);
bool save_byte(const char *section, const char *name, uint8 value);
#define save_bool save_byte
char *ConstructHomeFileName(char *buffer, const char *fname = 0, const char *ext = 0);
void safe_free(void *&p);
inline BOOL CALLBACK enablewndproc(HWND hwnd, LPARAM lParam) {
	EnableWindow(hwnd, static_cast<BOOL>(lParam));
	return TRUE;
}
void RestoreDialogPos(HWND hwndDlg, const char *inisection);
void SaveDialogPos(HWND hwndDlg, const char *inisection);
inline BOOL EnableDlgItem(HWND hwndDlg, int nIdDlgItem, BOOL bEnable)
	{ return EnableWindow(GetDlgItem(hwndDlg, nIdDlgItem), bEnable); }
inline BOOL ShowDlgItem(HWND hwndDlg, int nIdDlgItem, int nCmdShow)
	{ return ShowWindow(GetDlgItem(hwndDlg, nIdDlgItem), nCmdShow); }
inline BOOL IsDlgItemEnabled(HWND hwndDlg, int nIdDlgItem)
	{ return IsWindowEnabled(GetDlgItem(hwndDlg, nIdDlgItem)); }
POINT GetCtrlAnchorPoint(HWND hwndDlg, int nIdDlgItem);
bool is_winnt(void); // true for Win NT4/2000/XP/2003
bool is_pe32(const char *lpAppPath); // validate PE32-executable
BOOL GetFixedFileInfo(LPCTSTR lpstrFilename, VS_FIXEDFILEINFO &);
BOOL GetFixedFileInfo(HMODULE hModule, VS_FIXEDFILEINFO &);
inline BOOL GetFixedFileInfo(VS_FIXEDFILEINFO &fi)
	{ return GetFixedFileInfo((HMODULE)NULL, fi); }
const char *GetMessageName(UINT uMsg);

struct tooltip_item_t {
	const UINT uID;
	const char *const lpText;
};

struct tabdef_t {
	PCSTR const pszTitle;
	PCTSTR const lpTemplateName;
	DLGPROC const lpDialogFunc;
	HWND hWnd;
};

#endif // _PLUGSYS_HPP_
