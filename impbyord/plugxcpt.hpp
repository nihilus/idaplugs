
/*****************************************************************************
 *                                                                           *
 *  plugxcpt.hpp: ida plugins shared code                                    *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef _PLUGXCPT_HPP_
#define _PLUGXCPT_HPP_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "undbgnew.h"
#include <cstdarg>
#include <eh.h>
#include "mscrtdbg.h"
#include "fixdcstr.hpp"
#include <string>
#include <exception>
#define NOMINMAX 1
#include <windows.h>
#include "plugsys.hpp"
#include "dbgnew.h"

#ifdef _DEBUG
#	define GENERAL_CATCH_FILTER const std::exception &e
#else // !_DEBUG
#	define GENERAL_CATCH_FILTER ...
#endif // _DEBUG

// exception class clone for descriptive SEH reporting
class se_exception : public std::exception {
private:
	typedef std::basic_string<TCHAR> string;

	//DWORD _m_code;
	EXCEPTION_RECORD _m_exception;
	CONTEXT _m_context;
	HMODULE _m_hmodule;
	PIMAGE_DOS_HEADER _m_doshdr;
	PIMAGE_NT_HEADERS _m_nthdr;
	fixed_tpath_t _m_module;
	PCTSTR _m_pbasename;
	string _m_name;
	std::string _m_what;
	fixed_tpath_t _m_srcfile;
	LPCVOID _m_procaddr;
	string _m_procname, _m_line;
	DWORD _m_linenumber;

	// creation: you never need to create new se_exception directly
	se_exception(DWORD, const EXCEPTION_POINTERS *) throw()/*??*/;

	static void __cdecl se_translator(unsigned int, struct _EXCEPTION_POINTERS*);

public:
	/// to install se_exception, call se_exception::_set_se_translator() first ///
	inline static _se_translator_function _set_se_translator()                 //
		{ return ::_set_se_translator(se_translator); }                         //
	///////////////////////////////////////////////////////////////////////////

	// General exception information & helpers
	inline const EXCEPTION_RECORD &GetException() const throw()
		{ return _m_exception; }
	inline DWORD GetCode() const throw() // shortcut
		{ return GetException().ExceptionCode/*_m_code*/; }
	inline LPCVOID GetAddress() const throw() // shortcut
		{ return GetException().ExceptionAddress; }
	inline const CONTEXT &GetContext() const throw()
		{ return _m_context; }
	inline LPCVOID GetIP() const throw() // shortcut
		{ return reinterpret_cast<LPCVOID>(GetContext().Eip); }
	PCTSTR GetStdName() const throw();
	inline PCTSTR GetName() const throw()
		{ return _m_name.c_str(); }
	inline HMODULE GetModuleHandle() const throw()
		{ return _m_hmodule; }
	inline const IMAGE_DOS_HEADER *GetDosHdr() const throw()
		{ return _m_doshdr; }
	inline const IMAGE_NT_HEADERS *GetNtHdr() const throw()
		{ return _m_nthdr; }
	inline PCTSTR GetModuleName() const throw()
		{ return _m_module; }
	inline PCTSTR GetModuleBaseName() const throw()
		{ return _m_pbasename; }
	inline LPCVOID GetDeadcodeAddress() const throw() {
		if (GetNtHdr() != NULL) return (LPBYTE)GetAddress() +
			((LPBYTE)GetNtHdr()->OptionalHeader.ImageBase - (LPBYTE)GetModuleHandle());
		_RPT1(_CRT_WARN, "%s(): no image header\n", __FUNCTION__);
		return 0;
	}
	inline DWORD GetRVA() const throw() {
		if (GetModuleHandle() != NULL)
			return (LPBYTE)GetAddress() - (LPBYTE)GetModuleHandle();
		_RPT1(_CRT_WARN, "%s(): no module base\n", __FUNCTION__);
		return 0;
	}

	// std::exception override
	const char* what() const { return _m_what.c_str(); }

	// Debugging support
	inline PCTSTR GetProcName() const throw()
		{ return _m_procname.c_str(); }
	inline LPCVOID GetProcAddr() const throw()
		{ return _m_procaddr; }
	inline PCTSTR GetSourceFile() const throw()
		{ return _m_srcfile; }
	inline PCTSTR GetSourceLine() const throw()
		{ return _m_line.c_str(); }
	inline DWORD GetSourceLineNumber() const throw()
		{ return _m_linenumber; }
}; // se_exception

// simple exception class clone provides throwing text exceptions in
// printf-like manner
class fmt_exception : public std::exception {
protected:
	std::string _m_str;
public:
	explicit fmt_exception(const char *format, ...) throw()/*??*/;
	// std::exception override
	const char *what() const { return _m_str.c_str(); }
};

#endif // _PLUGXCPT_HPP_
