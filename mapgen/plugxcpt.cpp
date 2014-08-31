
/*****************************************************************************
 *                                                                           *
 *  plugxcpt.cpp: ida plugins shared code                                    *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include <tchar.h>
//#include <fstream>
#define NOMINMAX 1
#include <windows.h>
#define __in_bcount_opt(x)
#define __out_bcount_opt(x)
#include <dbghelp.h>
#include "plugxcpt.hpp"
#include "plugsys.hpp"
#include "plughlpr.hpp"

typedef WINBASEAPI BOOL (WINAPI *GetModuleHandleEx_p)(IN DWORD, IN LPCTSTR, OUT HMODULE *);

typedef BOOL (WINAPI *SymInitialize_p)(IN HANDLE hProcess, IN PCSTR UserSearchPath, IN BOOL fInvadeProcess);
typedef DWORD64 (WINAPI *SymLoadModule64_p)(IN HANDLE hProcess, IN HANDLE hFile, IN PCSTR ImageName, IN PCSTR ModuleName, IN DWORD64 BaseOfDll, IN DWORD SizeOfDll);
typedef BOOL (WINAPI *SymFromAddr_p)(IN HANDLE hProcess, IN DWORD64 Address, OUT PDWORD64 Displacement, IN OUT PSYMBOL_INFO Symbol);
typedef BOOL (WINAPI *SymUnloadModule64_p)(IN HANDLE hProcess, IN DWORD64 BaseOfDll);
typedef BOOL (WINAPI *SymCleanup_p)(IN HANDLE hProcess);
typedef DWORD (WINAPI *SymSetOptions_p)(IN DWORD SymOptions);
typedef BOOL (WINAPI *SymGetLineFromAddr64_p)(IN HANDLE hProcess, IN DWORD64 qwAddr, OUT PDWORD pdwDisplacement, OUT PIMAGEHLP_LINE64 Line64);

se_exception::se_exception(DWORD ExceptionCode, const EXCEPTION_POINTERS *ExceptionPointers) :
	//_m_code(ExceptionCode),
	_m_exception(*ExceptionPointers->ExceptionRecord),
	_m_context(*ExceptionPointers->ContextRecord),
	_m_hmodule(NULL), _m_doshdr(NULL), _m_nthdr(NULL),
	_m_procaddr(NULL), _m_linenumber(0), _m_pbasename(NULL) {
	_ASSERTE(ExceptionCode == ExceptionPointers->ExceptionRecord->ExceptionCode);
	GetModuleHandleEx_p GetModuleHandleEx = (GetModuleHandleEx_p)
		GetProcAddress(::GetModuleHandle("kernel32.dll"), "GetModuleHandleExA");
	if (GetModuleHandleEx == NULL || GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
		reinterpret_cast<LPCTSTR>(GetAddress()), &_m_hmodule) == 0) { // workaround for old Windows (Win2000 and older)
		MEMORY_BASIC_INFORMATION mi;
		if (VirtualQuery(GetAddress(),
			&mi, sizeof mi) >= sizeof mi && mi.State == MEM_COMMIT && mi.Type == MEM_IMAGE
			&& VirtualQuery(mi.AllocationBase, &mi, sizeof mi) >= sizeof mi)
			_m_hmodule = (HMODULE)mi.AllocationBase;
		else { // too bad
			_m_hmodule = NULL;
			_RPT2(_CRT_WARN, "%s(...): couldnot get module base for %08X any way - too bad\n",
				__FUNCTION__, GetAddress());
		}
	}
	if (_m_hmodule != NULL) {
		_m_doshdr = (PIMAGE_DOS_HEADER)_m_hmodule;
		if (_m_doshdr->e_magic == IMAGE_DOS_SIGNATURE) {
			_m_nthdr = (PIMAGE_NT_HEADERS)((LPBYTE)_m_hmodule + _m_doshdr->e_lfanew);
			if (_m_nthdr->Signature != IMAGE_NT_SIGNATURE
				|| _m_nthdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
				_m_nthdr = NULL;
				_RPT3(_CRT_WARN, "%s(...): image NT signatures mismatch (0x%lX, 0x%hX)\n",
					__FUNCTION__, _m_nthdr->Signature, _m_nthdr->OptionalHeader.Magic);
			}
		} else {
			_m_doshdr = NULL;
			_RPT2(_CRT_WARN, "%s(...): image DOS signature mismatch (0x%hX)\n",
				__FUNCTION__, _m_doshdr->e_magic);
		}
	}
	if (GetModuleFileName(_m_hmodule, _m_module, _m_module.capacity()) <= 0) {
		_m_module.clear();
		_RPT2(_CRT_WARN, "%s(...): GetModuleFileName(%08X, ...) returned FALSE\n",
			__FUNCTION__, _m_hmodule);
	}
	_m_pbasename = std::max(strrchr(_m_module, '\\'), strrchr(_m_module, '//'));
	if (_m_pbasename != NULL) ++_m_pbasename;
		else if (!_m_module.empty()) _m_pbasename = _m_module.begin();
	const char *tmp = GetStdName();
	if (tmp != 0)
		_m_name.assign(tmp);
	else
		_sprintf(_m_name, "EXCEPTION_%08lX", GetCode());
	_m_what.assign(_m_name);
	if (GetCode() == EXCEPTION_ACCESS_VIOLATION && GetException().NumberParameters >= 2)
		_sprintf_append(_m_what, " (%s %08lX failed)",
			GetException().ExceptionInformation[0] == 0 ?
			"read from" : "write to", GetException().ExceptionInformation[1]);
	_sprintf_append(_m_what, " at %s:%08X", _m_pbasename != NULL ?
		_m_pbasename : "<unknown>", GetDeadcodeAddress());
	HMODULE hDbgHelp;
	if (_m_nthdr == NULL || (hDbgHelp = LoadLibrary("DbgHelp.dll")) == NULL) {
		_RPT2(_CRT_WARN, "%s: %s\n", typeid(this).name(), _m_what.c_str());
		return;
	}
	SymInitialize_p pSymInitialize = (SymInitialize_p)GetProcAddress(hDbgHelp, "SymInitialize");
	SymSetOptions_p pSymSetOptions = (SymSetOptions_p)GetProcAddress(hDbgHelp, "SymSetOptions");
	SymLoadModule64_p pSymLoadModule64 = (SymLoadModule64_p)GetProcAddress(hDbgHelp, "SymLoadModule64");
	SymFromAddr_p pSymFromAddr = (SymFromAddr_p)GetProcAddress(hDbgHelp, "SymFromAddr");
	SymUnloadModule64_p pSymUnloadModule64 = (SymUnloadModule64_p)GetProcAddress(hDbgHelp, "SymUnloadModule64");
	SymCleanup_p pSymCleanup = (SymCleanup_p)GetProcAddress(hDbgHelp, "SymCleanup");
	if (pSymInitialize != NULL && pSymSetOptions != NULL && pSymLoadModule64 != NULL
		&& pSymFromAddr != NULL && pSymUnloadModule64 != NULL && pSymCleanup != NULL) {
		const HANDLE hProcess(GetCurrentProcess());
		if (pSymInitialize(hProcess, NULL, FALSE)) {
			pSymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
			DWORD64 SymBase(pSymLoadModule64(hProcess, NULL, _m_module, _m_pbasename,
				_m_nthdr->OptionalHeader.ImageBase, _m_nthdr->OptionalHeader.SizeOfImage));
			if (SymBase != 0) {
				boost::shared_crtptr<SYMBOL_INFO>
					pSymInfo(sizeof SYMBOL_INFO + MAX_SYM_NAME - 1);
				if (pSymInfo) {
					pSymInfo->SizeOfStruct = sizeof SYMBOL_INFO;
					pSymInfo->MaxNameLen = MAX_SYM_NAME;
					DWORD64 Displacement;
					if (pSymFromAddr(hProcess, (DWORD64)GetAddress(), &Displacement, pSymInfo.get())) {
						_m_procaddr = (LPCVOID)(pSymInfo->Address/* + Delta*/);
						_m_procname.assign(pSymInfo->Name);
						_sprintf_append(_m_what, " (%s+0x%I64X", pSymInfo->Name, Displacement);
						SymGetLineFromAddr64_p pSymGetLineFromAddr64 = (SymGetLineFromAddr64_p)GetProcAddress(hDbgHelp, "SymGetLineFromAddr64");
						IMAGEHLP_LINE64 Line;
						Line.SizeOfStruct = sizeof IMAGEHLP_LINE64;
						if (pSymGetLineFromAddr64 != NULL && pSymGetLineFromAddr64(hProcess,
							(DWORD64)GetAddress(), (PDWORD)&Displacement, &Line)) {
							_m_srcfile = Line.FileName;
							_m_linenumber = Line.LineNumber;
							/*
							ifstream is(Line.FileName);
							if (is.is_open()) {
								uint counter(0);
								while (is.good() && counter < Line.LineNumber) {
									string s;
									getline(is, s);
									if (is.fail()) break;
									if (++counter == Line.LineNumber) _m_line.assign(s);
								}
								is.close();
							} // open ok
							*/
							_sprintf_append(_m_what, ", %s:%lu", Line.FileName, Line.LineNumber);
						} // SymGetLineFromAddr64 ok
						_m_what.push_back(')');
					} // SymFromAddr ok
				} // malloc(pSymInfo) ok
				pSymUnloadModule64(hProcess, SymBase);
			} // SymLoadModule64 ok
#ifndef SE_XCPT_NO_SYMCLEANUP
			pSymCleanup(hProcess);
#endif
		} // SymInitialize ok
	} // have pointers
	FreeLibrary(hDbgHelp);
	//_RPT2(_CRT_WARN, "%s: %s\n", typeid(this).name(), _m_what.c_str());
}

PCTSTR se_exception::GetStdName() const throw() {
		switch (GetCode()) {
#	define TOKENIZE(x) case x: return _T(#x);
		TOKENIZE(EXCEPTION_ACCESS_VIOLATION)
		TOKENIZE(EXCEPTION_ARRAY_BOUNDS_EXCEEDED)
		TOKENIZE(EXCEPTION_BREAKPOINT)
		TOKENIZE(EXCEPTION_DATATYPE_MISALIGNMENT)
		TOKENIZE(EXCEPTION_FLT_DENORMAL_OPERAND)
		TOKENIZE(EXCEPTION_FLT_DIVIDE_BY_ZERO)
		TOKENIZE(EXCEPTION_FLT_INEXACT_RESULT)
		TOKENIZE(EXCEPTION_FLT_INVALID_OPERATION)
		TOKENIZE(EXCEPTION_FLT_OVERFLOW)
		TOKENIZE(EXCEPTION_FLT_STACK_CHECK)
		TOKENIZE(EXCEPTION_FLT_UNDERFLOW)
		TOKENIZE(EXCEPTION_GUARD_PAGE)
		TOKENIZE(EXCEPTION_ILLEGAL_INSTRUCTION)
		TOKENIZE(EXCEPTION_INT_DIVIDE_BY_ZERO)
		TOKENIZE(EXCEPTION_INT_OVERFLOW)
		TOKENIZE(EXCEPTION_INVALID_DISPOSITION)
		TOKENIZE(EXCEPTION_INVALID_HANDLE)
		TOKENIZE(EXCEPTION_IN_PAGE_ERROR)
		TOKENIZE(EXCEPTION_NONCONTINUABLE_EXCEPTION)
		TOKENIZE(EXCEPTION_PRIV_INSTRUCTION)
		TOKENIZE(EXCEPTION_SINGLE_STEP)
		TOKENIZE(EXCEPTION_STACK_OVERFLOW)
		TOKENIZE(DBG_CONTROL_C)
#	undef TOKENIZE
	}
	return 0;
}

void __cdecl se_exception::se_translator(unsigned int u, struct _EXCEPTION_POINTERS* pExp) {
	if (pExp == NULL) {
		_RPT3(_CRT_ASSERT, "%s(%u, %p): pExp != NULL", __FUNCTION__, u, pExp);
		std::__stl_throw_invalid_argument(__FUNCTION__ "(...): _EXCEPTION_POINTERS* cannot be NULL!");
	}
	_ASSERTE(u == pExp->ExceptionRecord->ExceptionCode);
	throw se_exception(u, pExp);
}

fmt_exception::fmt_exception(const char *format, ...) {
	va_list va;
	va_start(va, format);
	_vsprintf(_m_str, format, va);
	va_end(va);
}
