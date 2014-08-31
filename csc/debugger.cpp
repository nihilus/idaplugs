
/*****************************************************************************
 *                                                                           *
 * debugger.cpp: implementation of basic software debugger class             *
 * revision 11                                                               *
 * (c) 2005-2008 servil                                                      *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "undbgnew.h"
#include <cstring>
#include <cstdarg>
#include <excpt.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "msvc70rt.h"
#include <iterator>
#include <memory>
#include <vector>
#include <utility>
#include <typeinfo>
#include <boost/smart_ptr.hpp>
#include <boost/optional.hpp>
#include "debugger.hpp"
#include "dbgnew.h"

#pragma hdrstop

#define DUPLICATEHANDLE_CURRENTPROCESS  ((HANDLE)-1)
#define ObjectNameInformation                     1

// timeout in ms to get ToolHelp snapshot of process, debugee killed if expired
// if undefined, ToolHelp snapshot will not be guarded
//#define TOOLHELPSNAPSHOT_TIMEOUT        (15 * 1000)      // 15s default

// Platform-specific API (Windows 2000, Windows XP, Windows 2003)
typedef WINBASEAPI BOOL (WINAPI *DebugActiveProcessStop_p)(IN DWORD);
typedef WINBASEAPI BOOL (WINAPI *SetProcessWorkingSetSizeEx_p)
	(IN HANDLE hProcess, IN SIZE_T dwMinimumWorkingSetSize,
	IN SIZE_T dwMaximumWorkingSetSize, IN DWORD Flags);
typedef WINBASEAPI BOOL (WINAPI *GetProcessWorkingSetSizeEx_p)
	(IN HANDLE hProcess, OUT PSIZE_T lpMinimumWorkingSetSize,
	OUT PSIZE_T lpMaximumWorkingSetSize, OUT LPDWORD Flags);
typedef WINBASEAPI BOOL (WINAPI *GetThreadStartInformation_p)
	(IN HANDLE hThread, OUT LPVOID* lpStartAddress, OUT LPVOID* lpStartParameter);
typedef WINBASEAPI DWORD (WINAPI *GetThreadId_p)(IN HANDLE Thread);
typedef WINBASEAPI DWORD (WINAPI *GetProcessIdOfThread_p)(IN HANDLE Thread);
typedef WINBASEAPI DWORD (WINAPI *NtQueryObject_p)(IN DWORD, IN DWORD, IN DWORD,
	IN DWORD, IN DWORD);

// MS debugging support
typedef LPAPI_VERSION (WINAPI *ImagehlpApiVersion_t)(VOID);
typedef DWORD (WINAPI *SymSetOptions_t)(IN DWORD SymOptions);
typedef BOOL (WINAPI *SymCleanup_t)(IN HANDLE hProcess);
typedef BOOL (WINAPI *SymGetLineFromAddr64_t)(IN HANDLE hProcess, IN DWORD64 qwAddr, OUT PDWORD pdwDisplacement, OUT PIMAGEHLP_LINE64 Line64);
typedef BOOL (WINAPI *SymInitialize_t)(IN HANDLE hProcess, IN PCSTR UserSearchPath, IN BOOL fInvadeProcess);
typedef DWORD64 (WINAPI *SymLoadModule64_t)(IN HANDLE hProcess, IN HANDLE hFile, IN PCSTR ImageName, IN PCSTR ModuleName, IN DWORD64 BaseOfDll, IN DWORD SizeOfDll);
typedef BOOL (WINAPI *SymSetContext_t)(HANDLE hProcess, PIMAGEHLP_STACK_FRAME StackFrame, PIMAGEHLP_CONTEXT Context);
typedef BOOL (WINAPI *SymFromAddr_t)(IN HANDLE hProcess, IN DWORD64 Address, OUT PDWORD64 Displacement, IN OUT PSYMBOL_INFO Symbol);
typedef BOOL (WINAPI *SymFromName_t)(IN HANDLE hProcess, IN PCSTR Name, OUT PSYMBOL_INFO Symbol);
typedef BOOL (WINAPI *SymGetScope_t)(IN HANDLE hProcess, IN ULONG64 BaseOfDll, IN DWORD Index, OUT PSYMBOL_INFO Symbol);
typedef BOOL (WINAPI *SymGetTypeInfo_t)(IN HANDLE hProcess, IN DWORD64 ModBase, IN ULONG TypeId, IN IMAGEHLP_SYMBOL_TYPE_INFO GetType, OUT PVOID pInfo);
typedef BOOL (WINAPI *SymEnumSymbolsForAddr_t)(IN HANDLE hProcess, IN DWORD64 Address, IN PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback, IN PVOID UserContext);
typedef BOOL (WINAPI *SymEnumSymbols_t)(IN HANDLE hProcess, IN ULONG64 BaseOfDll, IN PCSTR Mask, IN PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback, IN PVOID UserContext);
typedef BOOL (WINAPI *SymEnumLines_t)(IN HANDLE hProcess, IN ULONG64 Base, IN PCSTR Obj, IN PCSTR File, IN PSYM_ENUMLINES_CALLBACK EnumLinesCallback, IN PVOID UserContext);
typedef BOOL (WINAPI *SymEnumSourceFiles_t)(IN HANDLE hProcess, IN ULONG64 ModBase, IN PCSTR Mask, IN PSYM_ENUMSOURCEFILES_CALLBACK cbSrcFiles, IN PVOID UserContext);

template<class T>
inline typename std::iterator_traits<T>::value_type &deconst_it(const T &it)
	{ return const_cast<typename std::iterator_traits<T>::value_type &>(*it); }

// std::string sprintf adaptors

static int _vsprintf(std::string &s, const char *format, va_list va) {
	s.clear();
	_ASSERTE(format != 0);
	if (format == 0) return -1;
	int len;
	try {
		if ((len = _vscprintf(format, va)) >= 0) {
			s.resize(len, 0);
			_vsnprintf(const_cast<char *>(s.data()), len, format, va);
		}
	} catch (...) {
		s.clear();
		len = -1;
		_RPT2(_CRT_ERROR, "%s(...): _vs*printf(..., \"%-.4000s\", ...) crashed\n",
			__FUNCTION__, format);
	}
	return len;
}

static inline int _sprintf(std::string &s, const char *format, ...) {
	va_list va;
	va_start(va, format);
	const int result(_vsprintf(s, format, va));
	va_end(va);
	return result;
}

static int _vsprintf_append(std::string &s, const char *format, va_list va) {
	_ASSERTE(format != 0);
	if (format == 0) return -1;
	const std::string::size_type restore(s.length());
	int len;
	try {
		if ((len = _vscprintf(format, va)) >= 0) {
			s.append(len, 0);
			_vsnprintf(const_cast<char *>(s.data() +
				(restore * sizeof(std::string::value_type))), len, format, va);
		}
	} catch (...) {
		s.erase(restore);
		len = -1;
		_RPT2(_CRT_ERROR, "%s(...): _vs*printf(..., \"%-.4000s\", ...) crashed\n",
			__FUNCTION__, format);
	}
	return len;
}

static inline int _sprintf_append(std::string &s, const char *format, ...) {
	va_list va;
	va_start(va, format);
	const int result(_vsprintf_append(s, format, va));
	va_end(va);
	return result;
}

static std::string _sprintf(const char *format, ...) {
	std::string result;
	va_list va;
	va_start(va, format);
	_vsprintf(result, format, va);
	va_end(va);
	return result;
}

//  CDebugger class implementation 

const CDebugger::module_t::exports_t::const_iterator CDebugger::modules_t::noexport;
const CDebugger::module_t::symbols_t::const_iterator CDebugger::modules_t::nosymbol;
const CDebugger::module_t::lines_t::const_iterator CDebugger::modules_t::noline;

//  Construction/destruction 

CDebugger::CDebugger(BOOL bQuiet, BOOL bIgnoreExternalExceptions, BOOL bUseDbgHelp) :
	bIsAttached(false), dwIdleTimer(INFINITE), hNtDll(LoadLibrary("ntdll.dll")),
	hDbgHelp(NULL), bQuiet(bQuiet), dwExitCode(0),
	bIgnoreExternalExceptions(bIgnoreExternalExceptions),
	bUseDbgHelp(bUseDbgHelp) { Reset(); }

CDebugger::~CDebugger() {
	_ASSERTE(breakpoints.empty());
	_ASSERTE(modules.empty());
	_ASSERTE(threads.empty());
	_ASSERTE(unbound_forwards.empty());
	_ASSERTE(hDbgHelp == NULL);
	if (hDbgHelp != NULL) FreeLibrary(hDbgHelp);
	if (hNtDll != NULL) FreeLibrary(hNtDll);
}

// 

void CDebugger::Reset() {
	//bIsAttached = false;
	hProcess = NULL;
	hMainThread = NULL;
	lpBaseOfImage = NULL;
	lpProcessLocalBase = NULL;
	breakpoints.clear();
	modules.clear();
	threads.clear();
	unbound_forwards.clear();
	ZeroMemory(&ProcessInfo, sizeof ProcessInfo);
	ZeroMemory(&DosHdr, sizeof DosHdr);
	ZeroMemory(&PeHdr, sizeof PeHdr);
	ZeroMemory(&DebugEvent, sizeof DebugEvent);
	DebuggeeFilePath.clear();
	if (hDbgHelp != NULL) {
		FreeLibrary(hDbgHelp);
		hDbgHelp = NULL;
	}
	// dwExitCode neresetovat!
}

DWORD CDebugger::DebugProcess(LPCSTR lpAppPath, LPCSTR lpCommandLine, BOOL OnlyThis) {
	_ASSERTE(lpAppPath != NULL && *lpAppPath != 0);
	if (lpAppPath == NULL || *lpAppPath == 0) return static_cast<DWORD>(-2L); // debugee not specified
	_ASSERTE(!bIsAttached);
	if (bIsAttached) return static_cast<DWORD>(-5L); // still debugged
	// reset everything
	_ASSERTE(breakpoints.empty());
	_ASSERTE(modules.empty());
	_ASSERTE(threads.empty());
	_ASSERTE(unbound_forwards.empty());
	Reset();
	// validate debugee first
	int debugee = _open(lpAppPath, _O_BINARY | _O_RDONLY, _S_IREAD);
	if (debugee == -1) {
		_RPT3(_CRT_WARN, "%s(\"%s\", ...): _open failed: %s\n",
			__FUNCTION__, lpAppPath, strerror(errno));
		return static_cast<DWORD>(-2L);
	} // open error
	try { // validate PE file
		IMAGE_DOS_HEADER doshdr;
		IMAGE_NT_HEADERS pehdr;
		if (_lseek(debugee, 0, SEEK_SET) != 0
			|| _read(debugee, &doshdr, sizeof doshdr) < sizeof doshdr
			|| doshdr.e_magic != IMAGE_DOS_SIGNATURE
			|| _lseek(debugee, doshdr.e_lfanew, SEEK_SET) != doshdr.e_lfanew)
			throw static_cast<DWORD>(-3L);
		if (_read(debugee, &pehdr, sizeof pehdr) >= sizeof pehdr
			&& pehdr.Signature == IMAGE_NT_SIGNATURE
			&& (pehdr.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0
			&& pehdr.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
			if ((pehdr.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0)
				throw static_cast<DWORD>(-5L); // DLL
		}
#ifdef _DEBUG
		else
			_RPT2(_CRT_WARN, "%s(\"%s\", ...): debuggee image format not PE32\n",
				__FUNCTION__, lpAppPath);
#endif // _DEBUG
		_close(debugee);
	} catch (DWORD exitcode) {
		_close(debugee);
		_RPT3(_CRT_WARN, "%s(\"%s\", ...): debugee image format not valid PE32 - errorcode=%li\n",
			__FUNCTION__, lpAppPath, exitcode);
		return exitcode;
	} catch (...) {
		_close(debugee);
		_RPT2(_CRT_WARN, "%s(\"%s\", ...): debugee image format not valid PE32 - unknown exception\n",
			__FUNCTION__, lpAppPath);
		return static_cast<DWORD>(-3L);
	}
	// prepare command line
	std::basic_string<CHAR> cmdln;
	_ASSERTE(lpAppPath != NULL || *lpAppPath != 0);
	if (lpAppPath != NULL && *lpAppPath != 0) {
		if (strchr(lpAppPath, ' ') == 0 || *lpAppPath == '\"') {
			_ASSERTE(*lpAppPath != '\"' || strlen(lpAppPath) >= 2
				&& *(lpAppPath + strlen(lpAppPath) - 1) == '\"');
			cmdln.assign(lpAppPath);
		} else
			_sprintf(cmdln, "\"%s\"", lpAppPath);
		if (lpCommandLine != NULL && *lpCommandLine != 0)
			cmdln.append(1, ' ').append(lpCommandLine); // unsafe: buffer overrun threat for large command lines
	}
	// start debugger
	STARTUPINFO StartupInfo;
	GetStartupInfo(&StartupInfo);
	if (!::CreateProcess(NULL, const_cast<LPSTR>(cmdln.c_str()), NULL, NULL, FALSE,
		(OnlyThis != FALSE ? DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS : DEBUG_PROCESS) | CREATE_DEFAULT_ERROR_MODE,
		NULL, NULL, &StartupInfo, &ProcessInfo)) return static_cast<DWORD>(-4L); // cannot start!
	bIsAttached = true;
	LPTSTR FilePart;
	GetFullPathName(lpAppPath, DebuggeeFilePath.capacity(), DebuggeeFilePath, &FilePart);
	return Dispatcher();
}

DWORD CDebugger::DebugActiveProcess(LPCSTR lpModuleName) {
	_ASSERTE(lpModuleName != NULL && *lpModuleName != 0);
	if (lpModuleName == NULL || *lpModuleName == 0) return static_cast<DWORD>(-2L);
	DWORD dwProcessId(0);
	__try {
		HANDLE hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
		if (hSnapshot != INVALID_HANDLE_VALUE) __try {
			char /*drive[2][_MAX_DRIVE], dir[2][_MAX_DIR], */fname[2][_MAX_FNAME], ext[2][_MAX_EXT];
			_splitpath(lpModuleName, 0/*drive[0]*/, 0/*dir[0]*/, fname[0], ext[0]);
			PROCESSENTRY32 Process32Info;
			Process32Info.dwSize = sizeof PROCESSENTRY32;
			if (Process32First(hSnapshot, &Process32Info)) do {
// 				if (drive[0][0] != 0 || dir[0][0] != 0) {
// 					if (_stricmp(lpModuleName, Process32Info.szExeFile) == 0)
// 						dwProcessId = Process32Info.th32ProcessID;
// 				} else {
					_splitpath(Process32Info.szExeFile, 0/*drive[1]*/, 0/*dir[1]*/, fname[1], ext[1]);
					if (_stricmp(fname[0], fname[1]) == 0 && _stricmp(ext[0], ext[1]) == 0)
						dwProcessId = Process32Info.th32ProcessID;
// 				}
			} while (dwProcessId == 0 && Process32Next(hSnapshot, &Process32Info));
		} __finally {
			CloseHandle(hSnapshot);
		}
#ifdef _DEBUG
		else
			_RPT2(_CRT_ERROR, "%s(\"%s\"): hSnapshot == INVALID_HANDLE_VALUE\n",
				__FUNCTION__, lpModuleName);
#endif // _DEBUG
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		_RPT2(_CRT_ERROR, "%s(\"%s\"): ToolHelp Process Enumerator exception\n",
			__FUNCTION__, lpModuleName);
	}
#ifdef _DEBUG
	if (dwProcessId == 0) _RPT2(_CRT_WARN, "%s(\"%s\"): no valid process Id\n",
		__FUNCTION__, lpModuleName);
#endif // _DEBUG
	return dwProcessId != 0 ? DebugActiveProcess(dwProcessId) : static_cast<DWORD>(-2L);
}

DWORD CDebugger::DebugActiveProcess(DWORD dwProcessId) {
	_ASSERTE(dwProcessId != 0);
	if (dwProcessId == 0) return static_cast<DWORD>(-2L);
	_ASSERTE(!bIsAttached);
	if (bIsAttached) return static_cast<DWORD>(-5L); // still debugged
	// reset everything
	_ASSERTE(breakpoints.empty());
	_ASSERTE(modules.empty());
	_ASSERTE(threads.empty());
	_ASSERTE(unbound_forwards.empty());
	Reset();
	if ((ProcessInfo.hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE,
		ProcessInfo.dwProcessId = dwProcessId)) == NULL) return static_cast<DWORD>(-4L);
	if (!::DebugActiveProcess(dwProcessId)) { // cannot start!
		CloseHandle(ProcessInfo.hProcess);
		Reset();
		return static_cast<DWORD>(-4L);
	}
	bIsAttached = true;
	if (::GetProcessImageFileName(ProcessInfo.hProcess, DebuggeeFilePath, DebuggeeFilePath.capacity()) > 0) {
		char fname[2][_MAX_FNAME], ext[2][_MAX_EXT];
		_splitpath(DebuggeeFilePath, 0, 0, fname[0], ext[0]);
		HANDLE hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId));
		if (hSnapshot != INVALID_HANDLE_VALUE) __try {
			MODULEENTRY32 ModuleInfo;
			ModuleInfo.dwSize = sizeof ModuleInfo;
			if (Module32First(hSnapshot, &ModuleInfo)) do {
				_splitpath(ModuleInfo.szModule/*ModuleInfo.szExePath*/, 0, 0, fname[1], ext[1]);
				if (_stricmp(fname[0], fname[1]) == 0 && _stricmp(ext[0], ext[1]) == 0) {
					_ASSERTE(strlen(ModuleInfo.szExePath) < DebuggeeFilePath.capacity());
#ifndef _UNICODE
					DebuggeeFilePath = ModuleInfo.szExePath;
#else
					WCHAR wExePath[MAX_PATH];
					mbstowcs(wExePath, ModuleInfo.szExePath, ARRAY_SIZE(wExePath));
					DebuggeeFilePath = wExePath;
#endif
// 					AddModule(ModuleInfo.hModule/*(HMODULE)ModuleInfo.modBaseAddr*/,
// 						ModuleInfo.modBaseSize, ModuleInfo.szExePath, 0/*ANSI*/, NULL/*no file handle*/);
					break;
				}
			} while (Module32Next(hSnapshot, &ModuleInfo));
		} __finally {
			CloseHandle(hSnapshot);
		}
	}
	return Dispatcher();
}

typedef LPAPI_VERSION (WINAPI *ImagehlpApiVersion_t)(VOID);

DWORD CDebugger::Dispatcher() {
	_ASSERTE(bIsAttached);
	std::string msg; // for diagnostic messages
	try { // exception frame
		boost::optional<BYTE> EntryByte;
		_ASSERTE(!EntryByte);
		bool user_step(false), xtrn_bpt(false);
		bDetachScheduled = false;
		breakpoints_t reactivate_bpts;
		_ASSERTE(reactivate_bpts.empty());
		breakpoints_t::iterator bpt;
		breakpoints_t::const_iterator cbpt;
		std::vector<modules_t::iterator> resolve_modules;
		_ASSERTE(resolve_modules.empty());
		std::vector<modules_t::iterator>::iterator it;
		modules_t::iterator module(modules.end());
		std::map<fixed_tpath_t, std::hash_map<breakpoint_t, DWORD,
			breakpoint_t::hash/*boost::hash<breakpoint_t>*/>, less::fname> unloaded_breakpoints;
		//HANDLE hSignaledState(NULL);
		while (GetExitCode(&dwExitCode) != 0) {
			// Wait for a debugging event to occur. The second parameter indicates
			// that the function does not return until a debugging event occurs.
			DWORD dwContinueStatus(DBG_CONTINUE); // exception continuation
			const bool isIdle(WaitForDebugEvent(&DebugEvent, dwIdleTimer) == FALSE);
			try {
				if (isIdle) {
					ZeroMemory(&DebugEvent, sizeof DebugEvent);
					OnIdle();
					continue;
				}
 				if (!resolve_modules.empty())
 				reloop1:
 					for (it = resolve_modules.begin(); it != resolve_modules.end(); ++it)
						if (ResolveModule(*it)) {
							resolve_modules.erase(it);
							goto reloop1;
						}
 				if (module != modules.end()) {
 					if (!ResolveModule(module)) resolve_modules.push_back(module);
 					module = modules.end();
 				}
 				// Process the debugging event code.
 				switch (DebugEvent.dwDebugEventCode) {
 					case EXCEPTION_DEBUG_EVENT:
						// EXCEPTION_DEBUG_EVENT Generated whenever an exception occurs in
						// the process being debugged. Possible exceptions include
						// attempting to access inaccessible memory, executing breakpoint
						// instructions, attempting to divide by zero, or any other
						// exception noted in Structured Exception Handling.
						// The DEBUG_EVENT structure contains an EXCEPTION_DEBUG_INFO
						// structure. This structure describes the exception that caused
						// the debugging event.
						// Besides the standard exception conditions, an additional
						// exception code can occur during console process debugging. The
						// system generates a DBG_CONTROL_C exception code when CTRL+C is
						// input to a console process that handles CTRL+C signals and is
						// being debugged. This exception code is not meant to be handled
						// by applications. An application should never use an exception
						// handler to deal with it. It is raised only for the benefit of
						// the debugger and is only used when a debugger is attached to the
						// console process.
						// If a process is not being debugged or if the debugger passes on
						// the DBG_CONTROL_C exception unhandled (through the gn command),
						// the application's list of handler functions is searched, as
						// documented for the SetConsoleCtrlHandler function.
						// If the debugger handles the DBG_CONTROL_C exception (through the
						// gh command), an application will not notice the CTRL+C except in
						// code like this.
						//
						// while ((inputChar = getchar()) != EOF) ...
						// or
						// while (gets(inputString)) ...
						//
						// Thus, the debugger cannot be used to stop the read wait in such
						// code from terminating.
						//
						// Process the exception code. When handling exceptions, remember
						// to set the continuation status parameter (dwContinueStatus).
						// This value is used by the ContinueDebugEvent function.
 						if (bIgnoreExternalExceptions != FALSE
 							&& DebugEvent.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT
 							&& DebugEvent.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP) {
 							const modules_t::const_iterator
 								module(modules.find(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, FALSE));
#ifdef _DEBUG
 							if (module == modules.end()) _RPTF2(_CRT_ASSERT, "%s(): target exception outside of known modules (%08X)\n",
 								__FUNCTION__, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
#endif // _DEBUG
 							if (!isMain(module)) {
 								dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
// 								if (DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags == EXCEPTION_NONCONTINUABLE
// 									|| DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_NONCONTINUABLE_EXCEPTION)
// 									OnCrash();
 								break;
 							};
 						}
 						switch (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode) {
 							case EXCEPTION_ACCESS_VIOLATION:
 								// First chance: Pass this on to the system.
 								// Last chance: Display an appropriate error.
 								dwContinueStatus = OnAccessViolation();
 								break;
 							case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
 								dwContinueStatus = OnArrayBoundsExceeded();
 								break;
 							case EXCEPTION_BREAKPOINT: {
 								// First chance: Display the current
 								// instruction and register values.
#ifdef _DEBUG
 								const LPCVOID IP(GetIP()), Address(static_cast<LPBYTE>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress) + sizeof(__x86_int3));
 								if (IP != Address) _RPTF4(_CRT_WARN, "%s() [%s]: GetIP() == DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress+sizeof(__x86_int3) (%08X!=%08X)\n",
 									__FUNCTION__, "EXCEPTION_DEBUG_EVENT", IP, Address);
 								_ASSERTE(reactivate_bpts.empty() || SingleStepActive());
#endif // _DEBUG
								//if (xtrn_bpt && user_step) OnSingleStep();
 								bool set_xtrn_bpt_flag(false), step_back(false);
 								if (!xtrn_bpt) bpt = breakpoints.find(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, bpt_sw);
 								// break on entry point?
 								if (!xtrn_bpt && EntryByte
 									&& DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress == getEntryPoint()) {
 									SetIP(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
 									if (!(set_xtrn_bpt_flag = EntryByte.get() == __x86_int3)) {
 										if (bpt != breakpoints.end() && bpt->enabled && bpt->SavedOriginal == __x86_int3)
 											deconst_it(bpt).SavedOriginal = EntryByte.get();
 										WipeSwBreakpoint(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, EntryByte.get());
 									}
 									EntryByte.reset();
 									OnEntryPoint();
 									step_back = true;
 									bpt = breakpoints.find(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, bpt_sw);
 								}
 								// own breakpoint?
 								if (!xtrn_bpt && bpt != breakpoints.end() && bpt->enabled) {
 									if (!step_back) SetIP(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
 									dwContinueStatus = OnBreakpoint(bpt_sw, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
 									step_back = GetIP() == DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
 									set_xtrn_bpt_flag = step_back && bpt->SavedOriginal == __x86_int3;
									if (!set_xtrn_bpt_flag && step_back
										&& (bpt = breakpoints.find(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, bpt_sw)) != breakpoints.end()
										&& bpt->enabled) {
										WipeSwBreakpoint(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, bpt->SavedOriginal);
										reactivate_bpts.insert(*bpt);
 									}
 								} else if (!step_back) // handle external (hardcoded) breakpoint
 									dwContinueStatus = OnBreakpoint(bpt_none, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
 								/*
 								if (step_back) { // (neubít se s hw breakem)
										const breakpoint_t hwbpt(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, bpt_hw_exec);
										CHwBptMgr hwbpts(this);
										const BYTE nIndex(hwbpts.Find(hwbpt));
										if (nIndex != static_cast<BYTE>(-1) && hwbpts.IsActiveLocal(nIndex)) {
											hwbpts.SetActiveLocal(nIndex, FALSE);
											hwbpts.SetActiveGlobal(nIndex, FALSE);
#ifdef _DEBUG
											bpt = breakpoints.find(hwbpt);
											_ASSERTE(bpt != breakpoints.end() && bpt->enabled);
#endif // _DEBUG
											reactivate_bpts.insert(hwbpt);
										}
 								}
 								*/
 								xtrn_bpt = set_xtrn_bpt_flag;
 								if (!(user_step = SingleStepActive()) && !reactivate_bpts.empty())
 									SingleStep();
 								break;
 							} // EXCEPTION_BREAKPOINT
 							case EXCEPTION_DATATYPE_MISALIGNMENT:
 								// First chance: Pass this on to the system.
 								// Last chance: Display an appropriate error.
 								dwContinueStatus = OnDatatypeMisalignment();
 								break;
 							case EXCEPTION_FLT_DENORMAL_OPERAND:
 								dwContinueStatus = OnFltDenormalOperand();
 								break;
 							case EXCEPTION_FLT_DIVIDE_BY_ZERO:
 								dwContinueStatus = OnFltDivideByZero();
 								break;
 							case EXCEPTION_FLT_INEXACT_RESULT:
 								dwContinueStatus = OnFltInexactResult();
 								break;
 							case EXCEPTION_FLT_INVALID_OPERATION:
 								dwContinueStatus = OnFltInvalidOperation();
 								break;
 							case EXCEPTION_FLT_OVERFLOW:
 								dwContinueStatus = OnFltOverflow();
 								break;
 							case EXCEPTION_FLT_STACK_CHECK:
 								dwContinueStatus = OnFltStackCheck();
 								break;
 							case EXCEPTION_FLT_UNDERFLOW:
 								dwContinueStatus = OnFltUnderflow();
 								break;
 							case EXCEPTION_ILLEGAL_INSTRUCTION:
 								dwContinueStatus = OnIllegalInstruction();
 								break;
 							case EXCEPTION_IN_PAGE_ERROR:
 								dwContinueStatus = OnInPageError();
 								break;
 							case EXCEPTION_INT_DIVIDE_BY_ZERO:
 								dwContinueStatus = OnIntDivideByZero();
 								break;
 							case EXCEPTION_INT_OVERFLOW:
 								dwContinueStatus = OnIntOverflow();
 								break;
 							case EXCEPTION_INVALID_DISPOSITION:
 								dwContinueStatus = OnInvalidDisposition();
 								break;
 							case EXCEPTION_NONCONTINUABLE_EXCEPTION:
 								OnNoncontinuableException();
 								dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
 								break;
 							case EXCEPTION_PRIV_INSTRUCTION:
 								dwContinueStatus = OnPrivInstruction();
 								break;
 							case EXCEPTION_SINGLE_STEP: {
 								// First chance: Update the display of the
 								// current instruction and register values.
#ifdef _DEBUG
 								const LPCVOID IP(GetIP());
 								if (IP != DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress)
 									_RPTF4(_CRT_WARN, "%s() [%s]: GetIP() == DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress (%08X!=%08X)\n",
 										__FUNCTION__, "EXCEPTION_SINGLE_STEP", IP,
 										DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
#endif // _DEBUG
 								// was this stop due to need of re-activate past breakpoint(s)?
								const bool stop_by_restore_bpts(!reactivate_bpts.empty());
								// re-activate all queued active breakpoints
								for (cbpt = reactivate_bpts.begin(); cbpt != reactivate_bpts.end(); ++cbpt)
									if ((bpt = breakpoints.find(*cbpt)) != breakpoints.end()
										&& bpt->enabled) {
										ActivateBreakpoint(bpt);
										_ASSERTE(IsBreakpointActive(reinterpret_cast<breakpoints_t::const_iterator &>(bpt)));
									}
 								reactivate_bpts.clear();
 								CHwBptMgr hwbpts(this);
 								// was this stop due hardware breakpoint hit?
 								const bool stop_by_hw_bpt(/*hwbpts.IsBS() && */hwbpts.IsTriggered());
 								if (user_step || !stop_by_restore_bpts && !stop_by_hw_bpt) {
 									dwContinueStatus = OnSingleStep();
 									user_step = SingleStepActive();
 								}
 								if (stop_by_hw_bpt) {
 									for (BYTE nIndex = 0; nIndex < 4; ++nIndex)
 										if (hwbpts.IsTriggered(nIndex)) {
 											if (dwContinueStatus == DBG_CONTINUE) dwContinueStatus =
 												OnBreakpoint(hwbpts.GetType(nIndex), hwbpts.GetAddress(nIndex));
 										} // triggered at nIndex slot
 									// temporary disable all on exec to advance IP pointer
 									hwbpts./*re*/Load();
 									for (nIndex = 0; nIndex < 4; ++nIndex) if (hwbpts.IsActive(nIndex)) {
										const breakpoint_t hwbpt(hwbpts, nIndex);
 										if (hwbpt.Type == bpt_hw_exec
 											&& DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress >= hwbpt.Address
 											&& (LPBYTE)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress < (LPBYTE)hwbpt.Address + hwbpt.Size) {
											hwbpts.SetActiveLocal(nIndex, FALSE);
											//hwbpts.SetActiveGlobal(nIndex, FALSE);
											_ASSERTE(!hwbpts.IsActiveLocal(nIndex));
#ifdef _DEBUG
											bpt = breakpoints.find(hwbpt);
											_ASSERTE(bpt != breakpoints.end());
											_ASSERTE(bpt->enabled);
#endif // _DEBUG
											reactivate_bpts.insert(hwbpt);
 										}
 									}
 									if (!(user_step = SingleStepActive()) && !reactivate_bpts.empty())
 										SingleStep();
 									hwbpts.ClearStatus();
 								} // hw breakpoint triggered
 								break;
 							} // EXCEPTION_SINGLE_STEP
 							case EXCEPTION_STACK_OVERFLOW:
 								dwContinueStatus = OnStackOverflow();
 								break;
 							case EXCEPTION_GUARD_PAGE:
 								dwContinueStatus = OnGuardPage();
 								break;
 							case EXCEPTION_INVALID_HANDLE:
 								dwContinueStatus = OnInvalidHandle();
 								break;
 							case DBG_CONTROL_C:
 								// First chance: Pass this on to the system.
 								// Last chance: Display an appropriate error.
 								dwContinueStatus = OnDbgControlC();
 								break;
 							default:
 								dwContinueStatus = OnCustomException();
 						} // switch ExceptionCode
 						if (DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags == EXCEPTION_NONCONTINUABLE)
 							dwContinueStatus = DBG_TERMINATE_PROCESS/*DBG_EXCEPTION_NOT_HANDLED??*/;
 						else if (DebugEvent.u.Exception.dwFirstChance == 0 && dwContinueStatus != DBG_CONTINUE
 							&& DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags != EXCEPTION_NONCONTINUABLE)
 							dwContinueStatus = OnUnhandledLastChance();
 						// This should be last stop before debugger exit
 						if (DebugEvent.u.Exception.dwFirstChance == 0 && dwContinueStatus != DBG_CONTINUE // !!!
 							|| DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags == EXCEPTION_NONCONTINUABLE
 							|| DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_NONCONTINUABLE_EXCEPTION)
 							OnCrash();
						// If the DBG_CONTINUE flag is specified for this parameter and the
						// thread specified by the dwThreadId parameter previously reported
						// an EXCEPTION_DEBUG_EVENT debugging event, the function stops all
						// exception processing and continues the thread. For any other
						// debugging event, this flag simply continues the thread.
						// If the DBG_EXCEPTION_NOT_HANDLED flag is specified for this
						// parameter and the thread specified by dwThreadId previously
						// reported an EXCEPTION_DEBUG_EVENT debugging event, the function
						// continues exception processing. If this is a first-chance
						// exception event, the search and dispatch logic of the structured
						// exception handler is used; otherwise, the process is terminated.
						// For any other debugging event, this flag simply continues the
						// thread.
 						break;
 					case CREATE_PROCESS_DEBUG_EVENT: {
						// CREATE_PROCESS_DEBUG_EVENT Generated whenever a new process is
						// created in a process being debugged or whenever the debugger
						// begins debugging an already active process. The system generates
						// this debugging event before the process begins to execute in
						// user mode and before the system generates any other debugging
						// events for the new process.
						// The DEBUG_EVENT structure contains a CREATE_PROCESS_DEBUG_INFO
						// structure. This structure includes a handle to the new process,
						// a handle to the process's image file, a handle to the process's
						// initial thread, and other information that describes the new
						// process.
						// The handle to the process has PROCESS_VM_READ and
						// PROCESS_VM_WRITE access. If a debugger has these types of access
						// to a thread, it can read and write to the process's memory by
						// using the ReadProcessMemory and WriteProcessMemory functions. If
						// the system previously reported an EXIT_PROCESS_DEBUG_EVENT
						// event, the system closes this handle when the debugger calls the
						// ContinueDebugEvent function.
						// The handle to the process's image file has GENERIC_READ access
						// and is opened for read-sharing. The debugger should close this
						// handle while processing CREATE_PROCESS_DEBUG_EVENT.
						// The handle to the process's initial thread has
						// THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, and
						// THREAD_SUSPEND_RESUME access to the thread. If a debugger has
						// these types of access to a thread, it can read from and write to
						// the thread's registers by using the GetThreadContext and
						// SetThreadContext functions and can suspend and resume the thread
						// by using the SuspendThread and ResumeThread functions. If the
						// system previously reported an EXIT_PROCESS_DEBUG_EVENT event,
						// the system closes this handle when the debugger calls the
						// ContinueDebugEvent function.
						//
						// As needed, examine or change the registers of the process's
						// initial thread with the GetThreadContext and SetThreadContext
						// functions; read from and write to the process's virtual memory
						// with the ReadProcessMemory and WriteProcessMemory functions; and
						// suspend and resume thread execution with the SuspendThread and
						// ResumeThread functions.
 						lpBaseOfImage = DebugEvent.u.CreateProcessInfo.lpBaseOfImage;
 						_ASSERTE(ProcessInfo.dwProcessId != 0);
 						//if (ProcessInfo.dwProcessId == 0) ProcessInfo.dwProcessId = DebugEvent.dwProcessId;
 						_ASSERTE(DebugEvent.dwProcessId == ProcessInfo.dwProcessId);
 						_ASSERTE(ProcessInfo.hProcess != NULL);
						hProcess = DebugEvent.u.CreateProcessInfo.hProcess;
						//DuplicateHandle(GetCurrentProcess(), DebugEvent.u.CreateProcessInfo.hProcess,
						//	GetCurrentProcess(), &hSignaledState, SYNCHRONIZE, FALSE, 0);
 						if (ProcessInfo.dwThreadId == 0) ProcessInfo.dwThreadId = DebugEvent.dwThreadId;
 						_ASSERTE(ProcessInfo.dwThreadId != 0);
 						_ASSERTE(DebugEvent.dwThreadId == ProcessInfo.dwThreadId);
 						hMainThread = DebugEvent.u.CreateProcessInfo.hThread;
						if (ReadDosHdr((HMODULE)DebugEvent.u.CreateProcessInfo.lpBaseOfImage, DosHdr))
							ReadPeHdr((HMODULE)DebugEvent.u.CreateProcessInfo.lpBaseOfImage, PeHdr);
 						lpProcessLocalBase = GetProcessLocalBase();
 						if (bUseDbgHelp != FALSE && (hDbgHelp = LoadLibrary("DbgHelp.dll")) != NULL) {
 							LPAPI_VERSION version;
 							ImagehlpApiVersion_t pImagehlpApiVersion((ImagehlpApiVersion_t)GetProcAddress(hDbgHelp, "ImagehlpApiVersion"));
 							if (pImagehlpApiVersion != NULL
 								&& (version = pImagehlpApiVersion()) != NULL) {
								if (bQuiet == FALSE && GetStdHandle(STD_ERROR_HANDLE) != NULL)
									fprintf(stderr, "[%s] ImageHlp API v%hu.%hu.%hu is available\n",
										typeid(*this).name(), version->MajorVersion, version->MinorVersion, version->Revision);
#ifdef _DEBUG
								_sprintf(msg, "[%s] ImageHlp API v%hu.%hu.%hu is available\n",
									typeid(*this).name(), version->MajorVersion, version->MinorVersion, version->Revision);
								OutputDebugString(msg.c_str());
#endif // _DEBUG
								if ((pImagehlpApiVersion = (ImagehlpApiVersion_t)GetProcAddress(hDbgHelp, "ExtensionApiVersion")) != NULL
									&& (version = pImagehlpApiVersion()) != NULL) {
									if (bQuiet == FALSE && GetStdHandle(STD_ERROR_HANDLE) != NULL)
										fprintf(stderr, "[%s] Extension API v%hu.%hu.%hu is available\n",
											typeid(*this).name(), version->MajorVersion, version->MinorVersion, version->Revision);
#ifdef _DEBUG
									_sprintf(msg, "[%s] Extension API v%hu.%hu.%hu is available\n",
										typeid(*this).name(), version->MajorVersion, version->MinorVersion, version->Revision);
									OutputDebugString(msg.c_str());
#endif // _DEBUG
								}
							}
 							SymInitialize_t pSymInitialize((SymInitialize_t)GetProcAddress(hDbgHelp, "SymInitialize"));
 							if (pSymInitialize == NULL
 								|| !pSymInitialize(ProcessInfo.hProcess, NULL, FALSE)) {
 								FreeLibrary(hDbgHelp);
 								hDbgHelp = NULL;
 							}
 						}
 						module = AddModule((HMODULE)DebugEvent.u.CreateProcessInfo.lpBaseOfImage,
 							0/*size unknown*/, reinterpret_cast<LPCSTR>(DebugEvent.u.CreateProcessInfo.lpImageName),
 							DebugEvent.u.CreateProcessInfo.fUnicode, DebugEvent.u.CreateProcessInfo.hFile);
 						_ASSERTE(module != modules.end());
 						_ASSERTE(DebugEvent.dwThreadId != 0);
 						if (DebugEvent.dwThreadId != 0) {
							CREATE_THREAD_DEBUG_INFO info;
							ZeroMemory(&info, sizeof(info));
							info.hThread = DebugEvent.u.CreateProcessInfo.hThread;
 							const threads_t::const_iterator
 								thread(AddThread(DebugEvent.dwThreadId, info));
 							_ASSERTE(thread != threads.end());
 							//OnCreateThread(*thread);
 						}
 						OnCreateProcess();
 						if (DebugEvent.u.CreateProcessInfo.lpStartAddress != NULL) {
 							const LPCVOID lpStartAddress(getEntryPoint());
 							if (lpStartAddress != NULL) {
#ifdef _DEBUG
								if (DebugEvent.u.CreateProcessInfo.lpStartAddress != getEntryPoint())
									_RPT3(_CRT_WARN, "%s(): CREATE_PROCESS_DEBUG_EVENT CreateProcessInfo.lpStartAddress != getEntryPoint() (%08X!=%08X)\n",
										__FUNCTION__, DebugEvent.u.CreateProcessInfo.lpStartAddress, getEntryPoint());
#endif // _DEBUG
								EntryByte = PlaceSwBreakpoint(getEntryPoint());
 							}
 						}
 						// Be sure to close the handle to the process image file with CloseHandle.
						if (DebugEvent.u.CreateProcessInfo.hFile != NULL)
							CloseHandle(DebugEvent.u.CreateProcessInfo.hFile);
 						break;
 					} // CREATE_PROCESS_DEBUG_EVENT
 					case CREATE_THREAD_DEBUG_EVENT: {
						// CREATE_THREAD_DEBUG_EVENT Generated whenever a new thread is
						// created in a process being debugged or whenever the debugger
						// begins debugging an already active process. This debugging event
						// is generated before the new thread begins to execute in user
						// mode.
						// The DEBUG_EVENT structure contains a CREATE_THREAD_DEBUG_INFO
						// structure. This structure includes a handle to the new thread
						// and the thread's starting address. The handle has
						// THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, and
						// THREAD_SUSPEND_RESUME access to the thread. If a debugger has
						// these types of access to a thread, it can read from and write to
						// the thread's registers by using the GetThreadContext and
						// SetThreadContext functions and can suspend and resume the thread
						// by using the SuspendThread and ResumeThread functions.
						// If the system previously reported an EXIT_THREAD_DEBUG_EVENT
						// event, the system closes the handle to the new thread when the
						// debugger calls the ContinueDebugEvent function.
						//
						// As needed, examine or change the thread's registers with the
						// GetThreadContext and SetThreadContext functions; and suspend and
						// resume thread execution with the SuspendThread and ResumeThread
						// functions.
 						const threads_t::const_iterator
 							thread(AddThread(DebugEvent.dwThreadId, DebugEvent.u.CreateThread));
 						_ASSERTE(thread != threads.end());
 						OnCreateThread(*thread);
 						break;
 					} // CREATE_THREAD_DEBUG_EVENT
 					case LOAD_DLL_DEBUG_EVENT: {
						// LOAD_DLL_DEBUG_EVENT Generated whenever a process being debugged
						// loads a DLL. This debugging event occurs when the system loader
						// resolves links to a DLL or when the debugged process uses the
						// LoadLibrary function. This debugging event only occurs the first
						// time the system attaches a DLL to the virtual address space of a
						// process.
						// The DEBUG_EVENT structure contains a LOAD_DLL_DEBUG_INFO
						// structure. This structure includes a handle to the newly loaded
						// DLL, the base address of the DLL, and other information that
						// describes the DLL. The debugger should close the handle to the
						// DLL handle while processing LOAD_DLL_DEBUG_EVENT.
						// Typically, a debugger loads a symbol table associated with the
						// DLL on receipt of this debugging event.
 						module = AddModule((HMODULE)DebugEvent.u.LoadDll.lpBaseOfDll, 0/*size unknown*/,
 							reinterpret_cast<LPCSTR>(DebugEvent.u.LoadDll.lpImageName),
 							DebugEvent.u.LoadDll.fUnicode, DebugEvent.u.LoadDll.hFile);
 						_ASSERTE(module != modules.end());
 						std::map<fixed_tpath_t, std::hash_map<breakpoint_t, DWORD, breakpoint_t::hash/*boost::hash<breakpoint_t>*/>, less::fname>::iterator
 							it(unloaded_breakpoints.find(module->FileName));
 						if (it != unloaded_breakpoints.end()) {
 							for (std::hash_map<breakpoint_t, DWORD, breakpoint_t::hash/*boost::hash<breakpoint_t>*/>::const_iterator iit = it->second.begin(); iit != it->second.end(); ++iit) {
 								_ASSERTE(!breakpoints.is(breakpoint_t(module->RVA2VA(iit->second),
 									iit->first.Type, iit->first.Size)));
 								SetBreakpoint(module->RVA2VA(iit->second), iit->first.Type,
 									iit->first.Size, iit->first.enabled);
 							}
 							unloaded_breakpoints.erase(it);
 						}
 						OnLoadDll(*module);
						// Be sure to close the handle to the loaded DLL with CloseHandle.
 						if (DebugEvent.u.LoadDll.hFile != NULL)
 							CloseHandle(DebugEvent.u.LoadDll.hFile);
 						break;
 					} // LOAD_DLL_DEBUG_EVENT
 					case OUTPUT_DEBUG_STRING_EVENT:
						// OUTPUT_DEBUG_STRING_EVENT Generated when a process being
						// debugged uses the OutputDebugString function.
						// The DEBUG_EVENT structure contains an OUTPUT_DEBUG_STRING_INFO
						// structure. This structure specifies the address, length, and
						// format of the debugging string.
 						OnOutputDebugString();
 						break;
 					case RIP_EVENT:
 						OnRip();
 						break;
 					case UNLOAD_DLL_DEBUG_EVENT: {
						// UNLOAD_DLL_DEBUG_EVENT Generated whenever a process being
						// debugged unloads a DLL by using the FreeLibrary function. This
						// debugging event only occurs the last time a DLL is unloaded from
						// a process's address space (that is, when the DLL's usage count
						// is zero).
						// The DEBUG_EVENT structure contains an UNLOAD_DLL_DEBUG_INFO
						// structure. This structure specifies the base address of the DLL
						// in the address space of the process that unloads the DLL.
						// Typically, a debugger unloads a symbol table associated with the
						// DLL upon receiving this debugging event.
						// When a process exits, the system automatically unloads the
						// process's DLLs, but does not generate an UNLOAD_DLL_DEBUG_EVENT
						// debugging event.
 						const modules_t::iterator
 							dll(modules.project<0>(modules.get<1>().find((HMODULE)DebugEvent.u.UnloadDll.lpBaseOfDll)));
 						_ASSERTE(dll != modules.end());
 						it = std::find(resolve_modules.begin(), resolve_modules.end(), dll);
 						if (it != resolve_modules.end()) resolve_modules.erase(it);
 						OnUnloadDll(*dll);
 						for (std::hash_set<DWORD>::const_iterator rva = dll->breakpoint_RVAs.begin(); rva != dll->breakpoint_RVAs.end(); ++rva) {
 							_ASSERTE(dll->RVA2VA(*rva) != NULL);
 							while ((cbpt = breakpoints[dll->RVA2VA(*rva)]) != breakpoints.end()) {
 								unloaded_breakpoints[dll->FileName].
 									insert(std::pair<breakpoint_t, DWORD>(*cbpt, *rva));
	 							DeleteBreakpoint(cbpt); // must clear hw debug registers
 							}
 						}
 						modules.erase(dll);
 						break;
 					} // UNLOAD_DLL_DEBUG_EVENT
 					case EXIT_THREAD_DEBUG_EVENT: {
						// EXIT_THREAD_DEBUG_EVENT Generated whenever a thread that is part
						// of a process being debugged exits. The system generates this
						// debugging event immediately after it updates the thread's exit
						// code.
						// The DEBUG_EVENT structure contains an EXIT_THREAD_DEBUG_INFO
						// structure that specifies the exit code.
						// This debugging event does not occur if the exiting thread is the
						// last thread of a process. In this case, the
						// EXIT_PROCESS_DEBUG_EVENT debugging event occurs instead.
						// The debugger deallocates any internal structures associated with
						// the thread on receipt of this debugging event. The system closes
						// the debugger's handle to the exiting thread. The debugger should
						// not close this handle.
 						threads_t::iterator
 							thread(threads.project<0>(threads.get<1>().find(DebugEvent.dwThreadId)));
 						_ASSERTE(thread != threads.end());
 						OnExitThread(*thread);
 						threads.erase(thread);
 						break;
 					} // EXIT_THREAD_DEBUG_EVENT
 					case EXIT_PROCESS_DEBUG_EVENT:
						// EXIT_PROCESS_DEBUG_EVENT Generated whenever the last thread in a
						// process being debugged exits. This debugging event occurs
						// immediately after the system unloads the process's DLLs and
						// updates the process's exit code.
						// The DEBUG_EVENT structure contains an EXIT_PROCESS_DEBUG_INFO
						// structure that specifies the exit code.
						// The debugger deallocates any internal structures associated with
						// the process on receipt of this debugging event. The system
						// closes the debugger's handle to the exiting process and all of
						// the process's threads. The debugger should not close these
						// handles.
						// The kernel-mode portion of process shutdown cannot be completed
						// until the debugger that receives this event calls
						// ContinueDebugEvent. Until then, the process handles are open and
						// the virtual address space is not released, so the debugger can
						// examine the child process. To receive notification when the
						// kernel-mode portion of process shutdown is complete, duplicate
						// the handle returned with CREATE_PROCESS_DEBUG_EVENT, call
						// ContinueDebugEvent, and then wait for the duplicated process
						// handle to be signaled.
 						dwExitCode = DebugEvent.u.ExitProcess.dwExitCode;
 						OnExitProcess();
 						threads.get<1>().erase(threads.get<1>().find(DebugEvent.dwThreadId));
 						_ASSERTE(threads.empty());
 						modules.clear();
 						bIsAttached = false; // leave the loop
 						break;
 				} // switch dwDebugEventCode
			} catch (const std::exception &e) {
				if (bQuiet == FALSE && GetStdHandle(STD_ERROR_HANDLE) != NULL)
					fprintf(stderr, "%s(): caught %s\n", __FUNCTION__, e.what());
				_RPT2(_CRT_ERROR, "%s(): caught %s\n", __FUNCTION__, e.what());
				dwContinueStatus = DBG_CONTINUE;
			} catch (...) {
				if (bQuiet == FALSE && GetStdHandle(STD_ERROR_HANDLE) != NULL)
					fprintf(stderr, "%s(): caught %s\n", __FUNCTION__, "unknown exception");
				_RPT2(_CRT_ERROR, "%s(): caught %s\n", __FUNCTION__, "unknown exception");
				dwContinueStatus = DBG_CONTINUE;
			}
			if (bDetachScheduled && reactivate_bpts.empty() && !SingleStepActive()) {
				DebugActiveProcessStop_p DebugActiveProcessStop((DebugActiveProcessStop_p)
					GetProcAddress(::GetModuleHandle("kernel32.dll"), "DebugActiveProcessStop"));
				if (DebugActiveProcessStop != NULL) {
					DisableBreakpoints();
					if (DebugActiveProcessStop(ProcessInfo.dwProcessId)) {
 						bIsAttached = false; // leave the loop
						dwExitCode = STILL_ACTIVE;
					} else // not succeed...
						EnableBreakpoints();
				}
				bDetachScheduled = false;
			}
			ContinueDebugEvent(DebugEvent.dwProcessId,
				DebugEvent.dwThreadId, dwContinueStatus);
		} // debug loop
	} catch (const std::exception &e) {
		if (bQuiet == FALSE && GetStdHandle(STD_ERROR_HANDLE) != NULL)
			fprintf(stderr, "%s(): debugger crashed, lame stupid servil ;p (%s)\n", __FUNCTION__, e.what());
		_RPT2(_CRT_ERROR, "%s(): debugger crashed, lame stupid servil ;p (%s)\n", __FUNCTION__, e.what());
		dwExitCode = STILL_ACTIVE;
	} catch (...) {
		if (bQuiet == FALSE && GetStdHandle(STD_ERROR_HANDLE) != NULL)
			fprintf(stderr, "%s(): debugger crashed, lame stupid servil ;p (%s)\n", __FUNCTION__, "unknown exception");
		_RPT2(_CRT_ERROR, "%s(): debugger crashed, lame stupid servil ;p (%s)\n", __FUNCTION__, "unknown exception");
		dwExitCode = STILL_ACTIVE;
	} // main exception sehandler
	modules.clear();
	if (hDbgHelp != NULL) {
		SymCleanup_t pSymCleanup((SymCleanup_t)GetProcAddress(hDbgHelp, "SymCleanup"));
		if (pSymCleanup != NULL) pSymCleanup(ProcessInfo.hProcess);
	}
	// Be sure to call the CloseHandle function to close the hProcess and hThread
	// handles when you are finished with them. Otherwise, when the child process
	// exits, the system cannot clean up these handles because the parent process
	// did not close them. However, the system will close these handles when the
	// parent process terminates, so they would be cleaned up at this point.
	if (ProcessInfo.hThread != NULL) CloseHandle(ProcessInfo.hThread);
	if (ProcessInfo.hProcess != NULL) CloseHandle(ProcessInfo.hProcess);
// 	if (hSignaledState != NULL) {
// 		if (dwExitCode != STILL_ACTIVE) WaitForSingleObject(hSignaledState, INFINITE);
// 		CloseHandle(hSignaledState);
// 	}
	bIsAttached = false;
	Reset();
	if (bQuiet == FALSE && GetStdHandle(STD_ERROR_HANDLE) != NULL)
		fprintf(stderr, "[%s] application status on debugger exit: %li\n",
			typeid(*this).name(), dwExitCode);
#ifdef _DEBUG
	_sprintf(msg, "[%s] application status on debugger exit: %li\n",
		typeid(*this).name(), dwExitCode);
	OutputDebugString(msg.c_str());
#endif // _DEBUG
	return dwExitCode;
}

bool CDebugger::ReadDosHdr(HMODULE hModule, IMAGE_DOS_HEADER &DosHdr) {
	if (ReadMemory(hModule, &DosHdr, sizeof DosHdr) >= sizeof DosHdr
		&& DosHdr.e_magic == IMAGE_DOS_SIGNATURE) return true;
	ZeroMemory(&DosHdr, sizeof DosHdr);
	return false;
}

// return value: raw offset of PE header from module base or -1 if error
LONG CDebugger::ReadPeHdr(HMODULE hModule, IMAGE_NT_HEADERS &PeHdr) {
	IMAGE_DOS_HEADER DosHdr;
	if (ReadDosHdr(hModule, DosHdr)
		&& ReadMemory((LPBYTE)hModule + DosHdr.e_lfanew, &PeHdr, sizeof PeHdr) >= sizeof PeHdr
		&& PeHdr.Signature == IMAGE_NT_SIGNATURE
		&& PeHdr.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC)
			return static_cast<LONG>(DosHdr.e_lfanew);
	ZeroMemory(&PeHdr, sizeof PeHdr);
	return -1;
}

LPVOID CDebugger::GetIP() const {
	if (!bIsAttached) return NULL;
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_CONTROL;
	return GetThreadContext(Context, TRUE) != FALSE ?
		reinterpret_cast<LPVOID>(Context.Eip) : NULL;
}

BOOL CDebugger::SetIP(LPCVOID IP) const {
	if (!bIsAttached) return FALSE;
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(Context, TRUE)) return FALSE;
	Context.Eip = reinterpret_cast<DWORD>(IP);
	return SetThreadContext(Context);
}

BOOL CDebugger::SingleStep() const {
	if (!bIsAttached) return FALSE;
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_CONTROL;
	if (GetThreadContext(Context, TRUE)) {
		Context.EFlags |= 1 << 8;
		return SetThreadContext(Context);
	}
	return FALSE;
}

bool CDebugger::SingleStepActive() const {
	if (!bIsAttached) return false;
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_CONTROL;
	return GetThreadContext(Context, TRUE) && (Context.EFlags & 1 << 8) != 0;
}

// Prcess management

SIZE_T CDebugger::ReadProcessMemory(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) const {
	if (!bIsAttached || nSize <= 0) return 0;
	SIZE_T NumberOfBytesRead;
	BOOL bResult(::ReadProcessMemory(ProcessInfo.hProcess, lpBaseAddress,
		lpBuffer, nSize, &NumberOfBytesRead));
	if (bResult != FALSE && NumberOfBytesRead > 0) return NumberOfBytesRead;
	MEMORY_BASIC_INFORMATION mi;
	DWORD flOldProtect;
	if (VirtualQuery(lpBaseAddress, mi) < sizeof mi || mi.State != MEM_COMMIT
		|| !VirtualProtect(mi.BaseAddress, mi.RegionSize, PAGE_READONLY, &flOldProtect))
		return 0;
	_ASSERTE(flOldProtect == mi.Protect);
	bResult = ::ReadProcessMemory(ProcessInfo.hProcess, lpBaseAddress,
		lpBuffer, nSize, &NumberOfBytesRead);
#ifdef _DEBUG
	BOOL OK =
#endif // _DEBUG
	VirtualProtect(mi.BaseAddress, mi.RegionSize, flOldProtect);
#ifdef _DEBUG
	if (OK == FALSE) _RPT4(_CRT_WARN, "%s(%08X, ..., 0x%IX): failed to restore old page protection (0x%lX)\n",
		__FUNCTION__, lpBaseAddress, nSize, flOldProtect);
	else if (VirtualQuery(lpBaseAddress, mi) >= sizeof mi && mi.Protect != flOldProtect)
		_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "%s(%08X, ..., 0x%IX): old page protection not restored (0x%lX!=0x%lX)\n",
			__FUNCTION__, lpBaseAddress, nSize, mi.Protect, flOldProtect);
#endif // _DEBUG
	return bResult != FALSE ? NumberOfBytesRead : 0;
}

SIZE_T CDebugger::WriteProcessMemory(LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize) const {
	if (!bIsAttached || nSize <= 0) return 0;
	SIZE_T NumberOfBytesWritten;
	BOOL bResult(::WriteProcessMemory(ProcessInfo.hProcess, lpBaseAddress,
		lpBuffer, nSize, &NumberOfBytesWritten));
	if (bResult != FALSE && NumberOfBytesWritten > 0) return NumberOfBytesWritten;
	MEMORY_BASIC_INFORMATION mi;
	DWORD flOldProtect;
	if (VirtualQuery(lpBaseAddress, mi) < sizeof mi || mi.State != MEM_COMMIT
		|| !VirtualProtect(mi.BaseAddress, mi.RegionSize, PAGE_READWRITE, &flOldProtect))
		return 0;
	_ASSERTE(flOldProtect == mi.Protect);
	bResult = ::WriteProcessMemory(ProcessInfo.hProcess, lpBaseAddress,
		lpBuffer, nSize, &NumberOfBytesWritten);
#ifdef _DEBUG
	BOOL OK =
#endif // _DEBUG
	VirtualProtect(mi.BaseAddress, mi.RegionSize, flOldProtect);
#ifdef _DEBUG
	if (OK == FALSE) _RPT4(_CRT_WARN, "%s(%08X, ..., 0x%IX): failed to restore old page protection (0x%lX)\n",
		__FUNCTION__, lpBaseAddress, nSize, flOldProtect);
	else if (VirtualQuery(lpBaseAddress, mi) >= sizeof mi && mi.Protect != flOldProtect)
		_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "%s(%08X, ..., 0x%IX): old page protection not restored (0x%lX!=0x%lX)\n",
			__FUNCTION__, lpBaseAddress, nSize, mi.Protect, flOldProtect);
#endif // _DEBUG
	return bResult != FALSE ? NumberOfBytesWritten : 0;
}

SIZE_T CDebugger::ReadMemory(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) const {
	if (!bIsAttached || nSize <= 0) return 0;
	const SIZE_T Result(ReadProcessMemory(lpBaseAddress, lpBuffer, nSize));
	if (Result > 0)
		for (breakpoints_t::const_iterator bpt = breakpoints.begin(); bpt != breakpoints.end(); ++bpt)
			if (bpt->Type == bpt_sw && bpt->enabled && bpt->Address >= lpBaseAddress
				&& (LPBYTE)bpt->Address < (LPBYTE)lpBaseAddress + Result)
				*((LPBYTE)lpBuffer + ((LPBYTE)bpt->Address - (LPBYTE)lpBaseAddress)) =
					bpt->SavedOriginal;
	return Result;
}

SIZE_T CDebugger::WriteMemory(LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize) const {
	if (!bIsAttached || nSize <= 0) return 0;
	for (breakpoints_t::const_iterator bpt = breakpoints.begin(); bpt != breakpoints.end(); ++bpt)
		if (bpt->Type == bpt_sw && bpt->enabled && bpt->Address >= lpBaseAddress
			&& (LPBYTE)bpt->Address < (LPBYTE)lpBaseAddress + nSize)
			*((LPBYTE)lpBuffer + ((LPBYTE)bpt->Address - (LPBYTE)lpBaseAddress)) = __x86_int3;
	return WriteProcessMemory(lpBaseAddress, lpBuffer, nSize);
}

BOOL CDebugger::SetProcessWorkingSetSizeEx(SIZE_T dwMinimumWorkingSetSize,
	SIZE_T dwMaximumWorkingSetSize, DWORD Flags) const {
	if (bIsAttached) {
		SetProcessWorkingSetSizeEx_p SetProcessWorkingSetSizeEx =
			(SetProcessWorkingSetSizeEx_p)GetProcAddress(::GetModuleHandle("kernel32.dll"),
				"SetProcessWorkingSetSizeEx");
		if (SetProcessWorkingSetSizeEx != 0) return
			SetProcessWorkingSetSizeEx(ProcessInfo.hProcess, dwMinimumWorkingSetSize, dwMaximumWorkingSetSize, Flags);
	}
	return FALSE;
}

BOOL CDebugger::GetProcessWorkingSetSizeEx(PSIZE_T lpMinimumWorkingSetSize,
	PSIZE_T lpMaximumWorkingSetSize, LPDWORD Flags) const {
	if (bIsAttached) {
		GetProcessWorkingSetSizeEx_p GetProcessWorkingSetSizeEx =
			(GetProcessWorkingSetSizeEx_p)GetProcAddress(::GetModuleHandle("kernel32.dll"),
			"GetProcessWorkingSetSizeEx");
		if (GetProcessWorkingSetSizeEx != NULL) return
			GetProcessWorkingSetSizeEx(ProcessInfo.hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize, Flags);
	}
	return FALSE;
}

typedef BOOL (WINAPI *DebugBreakProcess_p)(IN HANDLE Process);
BOOL CDebugger::DebugBreakProcess() const {
	if (bIsAttached) {
		DebugBreakProcess_p DebugBreakProcess =
			(DebugBreakProcess_p)GetProcAddress(::GetModuleHandle("kernel32.dll"),
			"DebugBreakProcess");
		if (DebugBreakProcess != NULL) return DebugBreakProcess(ProcessInfo.hProcess);
	}
	return FALSE;
}

// Thread management

struct CThreadHandle : private boost::noncopyable {
private:
	HANDLE hThread;
public:
	inline CThreadHandle(DWORD dwDesiredAccess, DWORD dwThreadId,
		BOOL bInheritHandle = FALSE) : hThread(::OpenThread(dwDesiredAccess,
			bInheritHandle, dwThreadId)) {
		//if (hThread == NULL) throw std::runtime_error("failed to open thread");
	}
	inline ~CThreadHandle() { if (hThread != NULL) CloseHandle(hThread); }

	inline bool operator !() const { return hThread == NULL; }
	inline operator HANDLE() const { return hThread; }
};

BOOL CDebugger::GetThreadContext(CONTEXT &Context, BOOL bUseFlags, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	if (!bUseFlags) Context.ContextFlags = ~0L; // get everything
	CThreadHandle hThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, dwThreadId == 0 ? DebugEvent.dwThreadId : dwThreadId);
	if (!hThread) {
		_RPT4(_CRT_WARN, "%s(..., %i, 0x%lX): failed to open thread for %s\n",
			__FUNCTION__, bUseFlags, dwThreadId, "THREAD_SUSPEND_RESUME");
		return FALSE;
	}
	// pause debuggee if not stopped by debug event
	if (DebugEvent.dwDebugEventCode == 0) ::SuspendThread(hThread);
	const BOOL result(::GetThreadContext(hThread, &Context));
	if (DebugEvent.dwDebugEventCode == 0) ::ResumeThread(hThread);
	return result;
}

BOOL CDebugger::SetThreadContext(const CONTEXT &Context, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, dwThreadId == 0 ? DebugEvent.dwThreadId : dwThreadId);
	if (!hThread) {
		_RPT3(_CRT_WARN, "%s(..., 0x%lX): failed to open thread for %s\n",
			__FUNCTION__, dwThreadId, "THREAD_SUSPEND_RESUME");
		return FALSE;
	}
	// pause debuggee if not stopped by debug event
	if (DebugEvent.dwDebugEventCode == 0) ::SuspendThread(hThread);
	const BOOL result(::SetThreadContext(hThread, &Context));
	if (DebugEvent.dwDebugEventCode == 0) ::ResumeThread(hThread);
	return result;
}

DWORD CDebugger::ResumeThread(DWORD dwThreadId) const {
	if (!bIsAttached) return static_cast<DWORD>(-1L);
	CThreadHandle hThread(THREAD_SUSPEND_RESUME, dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT3(_CRT_WARN, "%s(0x%lX): failed to open thread for %s\n",
			__FUNCTION__, dwThreadId, "THREAD_SUSPEND_RESUME");
		return static_cast<DWORD>(-1);
	}
	return ::ResumeThread(hThread);
}

DWORD CDebugger::SuspendThread(DWORD dwThreadId) const {
	if (!bIsAttached) return static_cast<DWORD>(-1L);
	CThreadHandle hThread(THREAD_SUSPEND_RESUME, dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT3(_CRT_WARN, "%s(0x%lX): failed to open thread for %s\n",
			__FUNCTION__, dwThreadId, "THREAD_SUSPEND_RESUME");
		return static_cast<DWORD>(-1);
	}
	return ::SuspendThread(hThread);
}

BOOL CDebugger::TerminateThread(DWORD dwExitCode, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_TERMINATE,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT4(_CRT_WARN, "%s(%li, 0x%lX): failed to open thread for %s\n",
			__FUNCTION__, dwExitCode, dwThreadId, "THREAD_TERMINATE");
		return FALSE;
	}
	return ::TerminateThread(hThread, dwExitCode);
}

BOOL CDebugger::GetExitCodeThread(LPDWORD lpExitCode, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_QUERY_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return ::GetExitCodeThread(hThread, lpExitCode);
}

DWORD CDebugger::GetProcessIdOfThread(DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT3(_CRT_WARN, "%s(0x%lX): failed to open thread for %s\n",
			__FUNCTION__, dwThreadId, "THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION");
		return 0;
	}
	return GetProcessIdOfThread(hThread);
}

BOOL CDebugger::SetThreadPriority(int nPriority, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_SET_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT4(_CRT_WARN, "%s(%i, 0x%lX): failed to open thread for %s\n",
			__FUNCTION__, nPriority, dwThreadId, "THREAD_SET_INFORMATION");
		return FALSE;
	}
	return ::SetThreadPriority(hThread, nPriority);
}

int CDebugger::GetThreadPriority(DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_QUERY_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return ::GetThreadPriority(hThread);
}

BOOL CDebugger::SetThreadPriorityBoost(BOOL DisablePriorityBoost, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_SET_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT4(_CRT_WARN, "%s(%i, 0x%lX): failed to open thread for %s\n",
			__FUNCTION__, DisablePriorityBoost, dwThreadId, "THREAD_SET_INFORMATION");
		return FALSE;
	}
	return ::SetThreadPriorityBoost(hThread, DisablePriorityBoost);
}

BOOL CDebugger::GetThreadPriorityBoost(PBOOL pDisablePriorityBoost, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_QUERY_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return ::GetThreadPriorityBoost(hThread, pDisablePriorityBoost);
}

BOOL CDebugger::GetThreadStartInformation(LPVOID *lpStartAddress,
	LPVOID* lpStartParameter, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	const GetThreadStartInformation_p
		GetThreadStartInformation((GetThreadStartInformation_p)GetProcAddress(::GetModuleHandle("kernel32.dll"),
			"GetThreadStartInformation"));
	if (GetThreadStartInformation == NULL) return FALSE;
	CThreadHandle hThread(THREAD_QUERY_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return GetThreadStartInformation(hThread, lpStartAddress, lpStartParameter);
}

BOOL CDebugger::GetThreadSelectorEntry(DWORD dwSelector,
	LDT_ENTRY &SelectorEntry, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_QUERY_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
			"%s(0x%lX, ..., 0x%lX): OpenThread(%s, ..., 0x%lX) failed\n",
			__FUNCTION__, dwSelector, dwThreadId, "THREAD_QUERY_INFORMATION",
			dwThreadId);
#endif // _DEBUG
		return FALSE;
	}
	return ::GetThreadSelectorEntry(hThread, dwSelector, &SelectorEntry);
}

DWORD CDebugger::SetThreadIdealProcessor(DWORD dwIdealProcessor, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_SET_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT4(_CRT_WARN, "%s(0x%lX, 0x%lX): failed to open thread for %s\n",
			__FUNCTION__, dwIdealProcessor, dwThreadId, "THREAD_SET_INFORMATION");
		return FALSE;
	}
	return ::SetThreadIdealProcessor(hThread, dwIdealProcessor);
}

DWORD_PTR CDebugger::SetThreadAffinityMask(DWORD_PTR dwThreadAffinityMask, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_SET_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT4(_CRT_WARN, "%s(0x%IX, 0x%lX): failed to open thread for %s\n",
			__FUNCTION__, dwThreadAffinityMask, dwThreadId, "THREAD_SET_INFORMATION");
		return FALSE;
	}
	return ::SetThreadAffinityMask(hThread, dwThreadAffinityMask);
}

BOOL CDebugger::GetThreadTimes(LPFILETIME lpCreationTime, LPFILETIME lpExitTime,
	LPFILETIME lpKernelTime, LPFILETIME lpUserTime, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_QUERY_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return ::GetThreadTimes(hThread, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime);
}

BOOL CDebugger::GetThreadIOPendingFlag(PBOOL lpIOIsPending, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_QUERY_INFORMATION,
		dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return ::GetThreadIOPendingFlag(hThread, lpIOIsPending);
}

DWORD CDebugger::GetThreadData(DWORD dwOffset, DWORD dwThreadId) const {
	if (!bIsAttached) return 0;
	CThreadHandle hThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
		dwThreadId == 0 ? DebugEvent.dwThreadId : dwThreadId);
	if (!hThread) {
		_RPT4(_CRT_WARN, "%s(0x%lX, 0x%lX): failed to open thread for %s\n",
			__FUNCTION__, dwOffset, dwThreadId, "THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION");
		return 0;
	}
	return GetThreadData(hThread, dwOffset);
}

BOOL CDebugger::SetThreadData(DWORD dwOffset, DWORD dwValue, DWORD dwThreadId) const {
	if (!bIsAttached) return FALSE;
	CThreadHandle hThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
		dwThreadId == 0 ? DebugEvent.dwThreadId : dwThreadId);
	if (!hThread) {
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
			"%s(0x%lX, 0x%lX, 0x%lX): failed to open thread for %s\n",
			__FUNCTION__, dwOffset, dwValue, dwThreadId, "THREAD_QUERY_INFORMATION");
#endif // _DEBUG
		return FALSE;
	}
	return SetThreadData(hThread, dwOffset, dwValue);
}

LPVOID CDebugger::GetProcessLocalBase(DWORD dwThreadId) const {
	LPVOID lpLocalBase(GetThreadLocalBase(dwThreadId));
	DWORD dwValue;
	return lpLocalBase != NULL && ReadMemory((LPBYTE)lpLocalBase + 0x30,
		&dwValue, sizeof dwValue) >= sizeof dwValue ? reinterpret_cast<LPVOID>(dwValue) : 0;
}

bool CDebugger::GetThreadDataSelector(HANDLE hThread, LDT_ENTRY &SelectorEntry) {
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_SEGMENTS;
	return ::GetThreadContext(hThread, &Context) != FALSE
		&& ::GetThreadSelectorEntry(hThread, Context.SegFs, &SelectorEntry) != FALSE ;
}

DWORD CDebugger::GetThreadData(HANDLE hThread, DWORD dwOffset) const {
	LDT_ENTRY SelectorEntry;
	DWORD dwValue;
	return GetThreadDataSelector(hThread, SelectorEntry)
		&& dwOffset + sizeof DWORD <= GetSegmentSize(SelectorEntry)
		&& ReadMemory((LPBYTE)GetSegmentBase(SelectorEntry) + dwOffset,
			&dwValue, sizeof dwValue) >= sizeof dwValue ? dwValue : 0;
}

BOOL CDebugger::SetThreadData(HANDLE hThread, DWORD dwOffset, DWORD dwValue) const {
	LDT_ENTRY SelectorEntry;
	return GetThreadDataSelector(hThread, SelectorEntry)
		&& dwOffset + sizeof DWORD <= GetSegmentSize(SelectorEntry)
		&& WriteMemory((LPBYTE)GetSegmentBase(SelectorEntry) + dwOffset,
			&dwValue, sizeof dwValue) >= sizeof dwValue ? TRUE : FALSE;
}

DWORD CDebugger::GetThreadId(HANDLE hThread) const {
	if (!bIsAttached) return 0;
	const GetThreadId_p GetThreadId((GetThreadId_p)
		GetProcAddress(::GetModuleHandle("kernel32.dll"), "GetThreadId"));
	return GetThreadId != NULL ? GetThreadId(hThread) : hThread != NULL ?
		GetThreadData(hThread, 0x24) : 0;
}

DWORD CDebugger::GetProcessIdOfThread(HANDLE hThread) const {
	if (!bIsAttached) return 0;
	const GetProcessIdOfThread_p GetProcessIdOfThread((GetProcessIdOfThread_p)
		GetProcAddress(::GetModuleHandle("kernel32.dll"), "GetProcessIdOfThread"));
	return GetProcessIdOfThread != NULL ? GetProcessIdOfThread(hThread) :
		hThread != NULL ? GetThreadData(hThread, 0x20) : 0;
}

DWORD CDebugger::GetStackOwner(LPCVOID Address) const {
	if (bIsAttached)
		for (threads_t::const_iterator thread = threads.begin(); thread != threads.end(); ++thread) {
			LPVOID lpStackTop(thread->GetStackTop());
			if (lpStackTop == NULL) {
				_RPTF3(_CRT_WARN, "%s(%08X): couldnot get stack top for 0x%lX\n",
					__FUNCTION__, Address, thread->dwThreadId);
				lpStackTop = GetThreadStackTop(thread->dwThreadId);
				if (lpStackTop == NULL) {
					_RPTF3(_CRT_ERROR, "%s(%08X): couldnot get stack top for 0x%lX\n",
						__FUNCTION__, Address, thread->dwThreadId);
					continue;
				}
			}
			LPVOID lpStackBottom(thread->GetStackBottom());
			if (lpStackBottom == NULL) {
				_RPTF3(_CRT_WARN, "%s(%08X): couldnot get stack bottom for 0x%lX\n",
					__FUNCTION__, Address, thread->dwThreadId);
				lpStackBottom = GetThreadStackBottom(thread->dwThreadId);
				if (lpStackBottom == NULL) {
					_RPTF3(_CRT_ERROR, "%s(%08X): couldnot get stack bottom for 0x%lX\n",
						__FUNCTION__, Address, thread->dwThreadId);
					continue;
				}
			}
			if (Address >= lpStackBottom && Address < lpStackTop) return thread->dwThreadId;
		}
	return 0;
}

// Breakpoint handling

BYTE CDebugger::PlaceSwBreakpoint(LPVOID Address) const {
	if (!bIsAttached) return 0;
	BYTE bResult;
	if (ReadProcessMemory(Address, &bResult, sizeof bResult) < sizeof bResult)
		throw std::runtime_error(__FUNCTION__ "(...): failed to read backup byte from debuggee");
	if (WriteProcessMemory(Address, &__x86_int3, sizeof __x86_int3) < sizeof __x86_int3)
		throw std::runtime_error(__FUNCTION__ "(...): failed to inject breakpoint to debuggee");
	FlushInstructionCache(Address, 0x10);
	return bResult;
}

void CDebugger::WipeSwBreakpoint(LPVOID Address, BYTE SavedOriginal) const {
	if (!bIsAttached) return;
	if (WriteProcessMemory(Address, &SavedOriginal, sizeof SavedOriginal) < sizeof SavedOriginal)
		throw std::runtime_error(__FUNCTION__ "(...): failed to inject backup byte to debuggee");
	FlushInstructionCache(Address, 0x10);
}

BOOL CDebugger::SetSwBreakpoint(LPCVOID Address, BOOL enabled) const {
	if (!IsAddressEnabled(Address)) return FALSE; // trying to set invalid breakpoint
	const std::pair<breakpoints_t::iterator, bool>
		item(const_cast<breakpoints_t &>(breakpoints).insert(breakpoint_t(Address, bpt_sw)));
	_ASSERTE(item.first != const_cast<CDebugger *>(this)->breakpoints.end());
	if (!item.second) {
		if (item.first->enabled == static_cast<bool>(enabled)) {
			_RPT3(_CRT_WARN, "%s(%08X, %i): setting dupe sw breakpoint\n",
				__FUNCTION__, Address, enabled);
			return FALSE;
		}
	}
	if (deconst_it(item.first).enabled = static_cast<bool>(enabled))
		deconst_it(item.first).SavedOriginal = PlaceSwBreakpoint(item.first->Address);
	else if (!item.second)
		WipeSwBreakpoint(item.first->Address, item.first->SavedOriginal);
	if (item.second) const_cast<modules_t &>(modules).track_breakpoint(Address);
	return TRUE;
}

BOOL CDebugger::SetBreakpoint(LPCVOID Address,
	breakpoint_type_t Type, BYTE Size, BOOL enabled) const {
	//_ASSERTE(IsAddressEnabled(Address));
	if (IsAddressEnabled(Address)) switch (Type) {
		case bpt_sw:
			return SetSwBreakpoint(Address, enabled);
		case bpt_hw_exec:
		case bpt_hw_write:
		case bpt_hw_io_access:
		case bpt_hw_access: {
			CHwBptMgr hwbpts(this);
			CHwBptMgr::AdjustSize(Size);
			BYTE nIndex(hwbpts.Find(Address, Type, Size));
			if (nIndex != static_cast<BYTE>(-1)) {
				_ASSERTE(breakpoints.is(breakpoint_t(Address, Type, Size)));
				if (enabled == hwbpts.IsActiveLocal(nIndex)) {
					_RPT4(_CRT_WARN, "%s(%08X, %i, %u, ...): setting dupe hw breakpoint\n",
						__FUNCTION__, Address, Type, Size);
					break;
				}
				hwbpts.SetActiveLocal(nIndex, enabled);
				//hwbpts.SetActiveGlobal(nIndex, enabled);
			} else {
				_ASSERTE(!breakpoints.is(breakpoint_t(Address, Type, Size)));
				if ((nIndex = hwbpts.FirstFree()) == static_cast<BYTE>(-1)) {
					_RPT4(_CRT_WARN, "%s(%08X, %i, %u, ...): no free slot for HW breakpoint\n",
						__FUNCTION__, Address, Type, Size);
					// if no free slot in debug registers, set software breakpoint instead
					// this action return as if ok thus may mess-up front-end user if
					// still expecting hw break
					if (Type == bpt_hw_exec) {
						_RPT1(_CRT_WARN, "%s(...): setting as SW bpt (int3) instead\n", __FUNCTION__);
						return SetSwBreakpoint(Address, enabled);
					}
					break;
				}
				// set as local hw breakpoint
				if (!hwbpts.Set(nIndex, Address, Type, Size, enabled, FALSE)) break; // something wrong
			}
			if (!hwbpts.Save()) break; // something wrong
			const breakpoints_t::iterator
				item(const_cast<breakpoints_t &>(breakpoints).insert(breakpoint_t(Address, Type, Size)).first);
			_ASSERTE(item != const_cast<CDebugger *>(this)->breakpoints.end());
			deconst_it(item).enabled = static_cast<bool>(enabled);
			const_cast<modules_t &>(modules).track_breakpoint(Address);
			return TRUE;
		} // hw breakpoint
#ifdef _DEBUG
		default:
			_RPT4(_CRT_WARN, "%s(%08X, %i, %u, ...): invalid breakpoint type\n",
				__FUNCTION__, Address, Type, Size);
#endif // _DEBUG
	} // switch Type
	return FALSE;
}

BOOL CDebugger::DeleteBreakpoint(const CDebugger::breakpoints_t::const_iterator &bpt) const {
	if (bpt == breakpoints.end()) return FALSE;
	if (bIsAttached) switch (bpt->Type) {
		case bpt_sw:
			if (bpt->enabled) WipeSwBreakpoint(bpt->Address, bpt->SavedOriginal);
			break;
		case bpt_hw_exec:
		case bpt_hw_write:
		case bpt_hw_io_access:
		case bpt_hw_access: {
			CHwBptMgr hwbpts(this);
			const BYTE nIndex(hwbpts.Find(*bpt));
			_ASSERTE(nIndex != static_cast<BYTE>(-1));
			hwbpts.Clear(nIndex);
			break;
		}
#ifdef _DEBUG
		default:
			_RPT3(_CRT_WARN, "%s(...): unexpected breakpoint type for %08X: %i\n",
				__FUNCTION__, bpt->Address, bpt->Type);
#endif // _DEBUG
	} // switch Type
	const_cast<breakpoints_t &>(breakpoints).erase(reinterpret_cast<const breakpoints_t::iterator &>(bpt));
	return TRUE;
}

void CDebugger::DeleteBreakpoints(CDebugger::breakpoint_type_t Type, BYTE Size) const {
	breakpoints_t::iterator bpt;
	while ((bpt = std::find_if(const_cast<CDebugger *>(this)->breakpoints.begin(),
		const_cast<CDebugger *>(this)->breakpoints.end(),
		boost::bind(&breakpoint_t::is_of_type, boost::arg<1>(), Type, Size)))
			!= const_cast<CDebugger *>(this)->breakpoints.end())
				DeleteBreakpoint(reinterpret_cast<breakpoints_t::const_iterator &>(bpt));
}

void CDebugger::ActivateBreakpoint(const CDebugger::breakpoints_t::iterator &bpt) {
	if (bpt == breakpoints.end()) return; // nothing to do!
	if (bIsAttached) switch (bpt->Type) {
		case bpt_sw:
			deconst_it(bpt).SavedOriginal = PlaceSwBreakpoint(bpt->Address);
			break;
		case bpt_hw_exec:
		case bpt_hw_write:
		case bpt_hw_io_access:
		case bpt_hw_access: {
			CHwBptMgr hwbpts(this);
			const BYTE nIndex(hwbpts.Find(*bpt));
			_ASSERTE(nIndex != static_cast<BYTE>(-1));
			hwbpts.SetActiveLocal(nIndex, TRUE);
			//hwbpts.SetActiveGlobal(nIndex, TRUE);
			break;
		}
#ifdef _DEBUG
		default:
			_RPT3(_CRT_WARN, "%s(...): unexpected breakpoint type for %08X: %i\n",
				__FUNCTION__, bpt->Address, bpt->Type);
#endif // _DEBUG
	} // switch Type
}

BOOL CDebugger::IsBreakpointActive(const CDebugger::breakpoints_t::const_iterator &bpt) const {
	if (bIsAttached && bpt != breakpoints.end()) switch (bpt->Type) {
		case bpt_sw: {
			BYTE check;
			if (ReadProcessMemory(bpt->Address, &check, sizeof check) < sizeof check)
				throw std::runtime_error(__FUNCTION__ "(...): couldnot check debuggee memory");
			if (check == __x86_int3) return TRUE;
			break;
		}
		case bpt_hw_exec:
		case bpt_hw_write:
		case bpt_hw_io_access:
		case bpt_hw_access: {
			const CHwBptMgr hwbpts(this);
			const BYTE nIndex(hwbpts.Find(*bpt));
			_ASSERTE(nIndex != static_cast<BYTE>(-1));
			if (hwbpts.IsActive(nIndex)) return TRUE;
			break;
		}
#ifdef _DEBUG
		default:
			_RPT3(_CRT_WARN, "%s(...): unexpected breakpoint type for %08X: %i\n",
				__FUNCTION__, bpt->Address, bpt->Type);
#endif // _DEBUG
	} // switch Type
	return FALSE;
}

BOOL CDebugger::EnableBreakpoint(const CDebugger::breakpoints_t::const_iterator &bpt) const {
	if (bpt == breakpoints.end() || bpt->enabled) return FALSE; // nothing to do!
	const_cast<CDebugger *>(this)->ActivateBreakpoint(reinterpret_cast<const breakpoints_t::iterator &>(bpt));
	deconst_it(bpt).enabled = true;
	return TRUE;
}

BOOL CDebugger::DisableBreakpoint(const CDebugger::breakpoints_t::const_iterator &bpt) const {
	if (bpt == breakpoints.end() || !bpt->enabled) return FALSE; // nothing to do!
	if (bIsAttached) switch (bpt->Type) {
		case bpt_sw:
			WipeSwBreakpoint(bpt->Address, bpt->SavedOriginal);
			break;
		case bpt_hw_exec:
		case bpt_hw_write:
		case bpt_hw_io_access:
		case bpt_hw_access: {
			CHwBptMgr hwbpts(this);
			const BYTE nIndex(hwbpts.Find(*bpt));
			_ASSERTE(nIndex != static_cast<BYTE>(-1));
			hwbpts.SetActiveLocal(nIndex, FALSE);
			//hwbpts.SetActiveGlobal(nIndex, FALSE);
			break;
		}
#ifdef _DEBUG
		default:
			_RPT3(_CRT_WARN, "%s(...): unexpected breakpoint type for %08X: %i\n",
				__FUNCTION__, bpt->Address, bpt->Type);
#endif // _DEBUG
	} // switch Type
	deconst_it(bpt).enabled = false;
	return TRUE;
}

// non-destructive iterator
void CDebugger::ProcessBreakpoints(BOOL (CDebugger::*pMemFn)(const CDebugger::breakpoints_t::const_iterator &) const,
	CDebugger::breakpoint_type_t Type, BYTE Size) {
	_ASSERTE(pMemFn != 0);
	if (pMemFn != 0) for (breakpoints_t::iterator bpt = breakpoints.begin();
		(bpt = std::find_if(bpt, breakpoints.end(),
			boost::bind(&breakpoint_t::is_of_type, boost::arg<1>(), Type, Size)))
				!= breakpoints.end(); ++bpt)
					(this->*pMemFn)(reinterpret_cast<breakpoints_t::const_iterator &>(bpt));
}

// Only wrote this function as yet another enumerator when everything else fail.
// Because it never worked for me probably its mostly useless (left in chain
// just for case)
bool CDebugger::FindModuleEntry(MODULEENTRY32 &Module32Info,
	HMODULE hModule, DWORD dwProcessId) const {
	if (dwProcessId != 0 || bIsAttached) __try {
#if TOOLHELPSNAPSHOT_TIMEOUT > 0
		HANDLE hKiller(StartKiller(__FUNCTION__ "(...)"));
#endif
		HANDLE hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
			dwProcessId != 0 ? dwProcessId : ProcessInfo.dwProcessId));
#if TOOLHELPSNAPSHOT_TIMEOUT > 0
		StopKiller(hKiller);
#endif
		if (hSnapshot != INVALID_HANDLE_VALUE) __try {
			Module32Info.dwSize = sizeof Module32Info;
			if (Module32First(hSnapshot, &Module32Info)) do
				if (hModule == Module32Info.hModule) return true;
			while (Module32Next(hSnapshot, &Module32Info));
		} __finally {
			CloseHandle(hSnapshot);
		}
#ifdef _DEBUG
		else
			_RPTF1(_CRT_ERROR, "%s(...): hSnapshot == INVALID_HANDLE_VALUE\n", __FUNCTION__);
#endif // _DEBUG
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		_RPTF2(_CRT_ERROR, "%s(...): ToolHelp Module Enumerator exception for 0x%lX\n",
			__FUNCTION__, dwProcessId != 0 ? dwProcessId : ProcessInfo.dwProcessId);
	}
	return false;
}

BOOL CALLBACK CDebugger::SymEnumSymbolsProc(PSYMBOL_INFO pSymInfo, ULONG SymbolSize,
	PVOID UserContext) {
	_ASSERTE(pSymInfo != NULL);
	_ASSERTE(UserContext != NULL);
  if (pSymInfo == NULL || UserContext == NULL) return FALSE;
  pSymInfo->Address -= static_cast<CDebugger::module_t *>(UserContext)->SymOffset();
  _ASSERTE(static_cast<CDebugger::module_t *>(UserContext)->has_address(reinterpret_cast<LPVOID>(pSymInfo->Address)));
  _ASSERTE(pSymInfo->Name[0] != 0);
  try {
  	static_cast<CDebugger::module_t *>(UserContext)->symbols.insert(*pSymInfo);
  } catch (const std::exception &e) {
  	_RPT4(_CRT_WARN, "%s(...): %s (address=%016I64X name=%s)\n",
  		__FUNCTION__, e.what(), pSymInfo->Address, pSymInfo->Name);
  } catch (...) { }
  return TRUE; // continue enumeration
}

BOOL CALLBACK CDebugger::SymEnumLinesProc(PSRCCODEINFO LineInfo, PVOID UserContext) {
	_ASSERTE(LineInfo != NULL);
	_ASSERTE(UserContext != NULL);
	if (LineInfo == NULL || UserContext == NULL) return FALSE;
  LineInfo->Address -= static_cast<CDebugger::module_t *>(UserContext)->SymOffset();
  _ASSERTE(static_cast<CDebugger::module_t *>(UserContext)->has_address(reinterpret_cast<LPVOID>(LineInfo->Address)));
	_ASSERTE(LineInfo->FileName[0] != 0);
	try {
	  static_cast<CDebugger::module_t *>(UserContext)->lines.insert(*LineInfo);
  } catch (const std::exception &e) {
  	_RPT4(_CRT_WARN, "%s(...): %s (filename=%s linenumber=%lu)\n",
  		__FUNCTION__, e.what(), LineInfo->FileName, LineInfo->LineNumber);
  } catch (...) { }
	return TRUE; // continue enumeration
}

BOOL CALLBACK CDebugger::SymEnumSourceFilesProc(PSOURCEFILE pSourceFile, PVOID UserContext) {
	_ASSERTE(pSourceFile != NULL);
	_ASSERTE(UserContext != NULL);
	if (pSourceFile == NULL || UserContext == NULL) return FALSE;
	if (pSourceFile->FileName[0] != 0) try {
	  static_cast<CDebugger::module_t *>(UserContext)->srcfiles.insert(pSourceFile->FileName);
  } catch (const std::exception &e) {
  	_RPT3(_CRT_WARN, "%s(...): %s (filename=%s)\n",
  		__FUNCTION__, e.what(), pSourceFile->FileName);
  } catch (...) { }
	return TRUE; // continue enumeration
}

#define _ntdir(nthdr, index) (nthdr.OptionalHeader.DataDirectory[index])
#define _expdir _ntdir(module.pehdr, IMAGE_DIRECTORY_ENTRY_EXPORT)
#define _impdir _ntdir(module.pehdr, IMAGE_DIRECTORY_ENTRY_IMPORT)
#define _delayimpdir _ntdir(module.pehdr, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
#define _ExpBufAddr(RVA) ((LPBYTE)expdir.get() + \
	((DWORD)(RVA) - _expdir.VirtualAddress))
#define _IsInExpBuf(VA) ((LPBYTE)(VA) >= (LPBYTE)expdir.get() \
	&& (LPBYTE)(VA) < (LPBYTE)expdir.get() + _expdir.Size)
#define _IsInExpDir(RVA) (((DWORD)(RVA)) >= _expdir.VirtualAddress \
	&& ((DWORD)(RVA)) < _expdir.VirtualAddress + _expdir.Size)
#define _ExportItem(type, member, index) \
	(((const type *)_ExpBufAddr(expdir->AddressOf##member))[index])
#define _Ordinal(index) _ExportItem(WORD, NameOrdinals, (index))
#define _NameRVA(index) _ExportItem(LPCSTR, Names, (index))
#define _FuncRVA(index) _ExportItem(DWORD, Functions, (index))

typedef struct tagImportDirectory {
	DWORD dwRVAImportNameTable;
	DWORD dwTimeDateStamp;
	DWORD dwForwarderChain;
	DWORD dwRVAModuleName;
	DWORD dwRVAImportAddressTable;
} IMAGE_IMPORT_DIRECTORY, *PIMAGE_IMPORT_DIRECTORY;

typedef struct tagDelayImportDirectory {
	DWORD dwAttributes;
	DWORD dwRVAModuleName;
	HMODULE hModule;
	DWORD dwRVAImportAddressTable;
	DWORD dwRVAImportNameTable;
	DWORD dwRVABoundImportAddressTable;
	DWORD dwRVAUnloadImportAddressTable;
	DWORD dwTimeDateStamp;
} IMAGE_DELAY_IMPORT_DIRECTORY, *PIMAGE_DELAY_IMPORT_DIRECTORY;

CDebugger::modules_t::iterator CDebugger::AddModule(HMODULE hModule,
	SIZE_T dwSize, LPCSTR lpImageName, WORD fUnicode, HANDLE hFile) {
	_ASSERTE(hModule != NULL);
	if (hModule == NULL) return modules.end();
	modules_t::iterator
		tmp(modules.project<0>(modules.get<1>().find(hModule)));
	if (tmp != modules.end()) { // no dupes
		_RPT3(_CRT_WARN, "%s(%08X, ...): trying to (re)add once loaded module (%s)\n",
			__FUNCTION__, hModule, tmp->getBaseName());
		return tmp;
	}
	module_t module(hModule, dwSize);
	// get headers
	const LONG peoff(ReadDosHdr(hModule, module.doshdr) ?
		ReadPeHdr(hModule, module.pehdr) : -1);
	// get size
	MODULEINFO ModInfo;
	MODULEENTRY32 ModEntry;
	if (module.dwSize <= 0)
		if (GetModuleInformation(hModule, ModInfo))
			module.dwSize = ModInfo.SizeOfImage;
		else if (FindModuleEntry(ModEntry, hModule))
			module.dwSize = ModEntry.modBaseSize;
		else if (peoff > 0)
			module.dwSize = module.pehdr.OptionalHeader.SizeOfImage;
	_ASSERTE(module.dwSize > 0);
	// get name
	if (GetModuleFileName(hModule, module.FileName, module.FileName.capacity()) <= 0) {
		MODULEENTRY32 ModEntry;
		if (FindModuleEntry(ModEntry, hModule)) {
#ifndef _UNICODE
			module.FileName = ModEntry.szExePath;
#else
			WCHAR wExePath[MAX_PATH];
			mbstowcs(wExePath, ModEntry.szExePath, ARRAY_SIZE(wExePath));
			module.FileName = wExePath;
#endif
		} else if (lpImageName != 0) {
			LPCSTR lpFileName;
			WCHAR path[MAX_PATH];
			if (ReadProcessMemory(lpImageName, &lpFileName, sizeof lpFileName) < 1
				|| !IsAddressEnabled(lpFileName)
				|| ReadProcessMemory(lpFileName, path, sizeof path) <= 0)
					memcpy(path, lpImageName, sizeof path);
			if (fUnicode != 0)
				wcstombs(module.FileName, path, module.FileName.capacity());
			else
				module.FileName = reinterpret_cast<const char *>(path);
		} else if (hFile == NULL
			|| !GetHandleName(hFile, module.FileName, module.FileName.capacity()))
				module.FileName.clear();
	}
	// load directories
	if (peoff > 0) {
		// get sections
		for (WORD index = 0; index < module.pehdr.FileHeader.NumberOfSections; ++index) {
			module_t::section_t section;
			if (ReadProcessMemory(module.RVA2VA(peoff + sizeof IMAGE_NT_HEADERS + index *
				IMAGE_SIZEOF_SECTION_HEADER), &section.header, sizeof section.header) >= sizeof section.header) {
				section.BaseAddress = module.RVA2VA(section.header.VirtualAddress);
				module.sections.insert(section);
			}
		}
		// get exports if any
		if (_expdir.VirtualAddress != 0 && _expdir.Size != 0) try { // have exports
			boost::shared_ptr<IMAGE_EXPORT_DIRECTORY>
				expdir((PIMAGE_EXPORT_DIRECTORY)malloc(_expdir.Size), free);
			if (!expdir) throw std::bad_alloc();
			if (ReadProcessMemory(module.RVA2VA(_expdir.VirtualAddress), expdir.get(), _expdir.Size) >= _expdir.Size) {
				module_t::export_t export;
				_ASSERTE(expdir->Name != 0);
				if (expdir->Name != 0) {
					_ASSERTE(*reinterpret_cast<LPCSTR>(_ExpBufAddr(expdir->Name)) != 0);
					_ASSERTE(strlen(reinterpret_cast<LPCSTR>(_ExpBufAddr(expdir->Name))) < MAX_PATH);
#ifndef _UNICODE
					export.DllName = reinterpret_cast<LPCSTR>(_ExpBufAddr(expdir->Name));
#else
					WCHAR wbasename[MAX_PATH];
					mbstowcs(wbasename, reinterpret_cast<LPCSTR>(_ExpBufAddr(expdir->Name)), ARRAY_SIZE(wbasename));
					export.DllName = wbasename;
#endif // _UNICODE
				} else
					export.DllName = module.getBaseName();
				for (DWORD iter = 0; iter < expdir->NumberOfFunctions; ++iter) try {
					export.Ordinal = expdir->Base + iter;
					const DWORD *funcrva(&_FuncRVA(iter));
					if (!_IsInExpBuf(funcrva)) {
						_RPTF3(_CRT_ASSERT, "%s(%08X, ...): _IsInExpBuf(&_FuncRVA(%lu))\n",
							__FUNCTION__, hModule, iter);
						std::__stl_throw_out_of_range("(!_IsInExpBuf(funcrva)");
					}
					if (!_IsInExpDir(*funcrva)) { // normal export
						export.lpFunc = module.RVA2VA(*funcrva);
						export.dwRVA = *funcrva;
					} else { // this is forwarded export -> find real address
						export.lpFunc = NULL;
						export.dwRVA = 0; // this is in another module
						LPCSTR dll, name(strrchr(dll = reinterpret_cast<LPCSTR>(_ExpBufAddr(*funcrva)), '.'));
						if (name != NULL) {
							*const_cast<LPSTR>(name++) = 0;
							_ASSERTE(strlen(dll) > 0);
							_ASSERTE(strlen(dll) < MAX_PATH);
							_ASSERTE(strlen(name) > 0);
							const modules_t::const_iterator it(strchr(dll, '.') == 0 ?
								modules.find_basename(dll) : modules.find(dll));
							if (it != modules.end()) {
								const module_t::exports_t::const_iterator export2(it->exports[name]);
								if (export2 != it->exports.end()) export.lpFunc = export2->lpFunc;
#ifdef _DEBUG
								if (export.lpFunc == NULL)
									_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
										"%s(%08X, ...): %lu. export forward (%s.%s) in %s not found despite module loaded: funcRVA=0x%08lX\n",
										__FUNCTION__, hModule, iter, dll, name, module.getBaseName(), *funcrva);
#endif // _DEBUG
							}
							if (export.lpFunc == NULL) { // wild method - no guarantee load address will be same
#ifndef _UNICODE
								unbound_forwards[dll][module.hModule][export.Ordinal] = name;
#else
								WCHAR wdll[MAX_PATH];
								mbstowcs(wdll, dll, ARRAY_SIZE(wdll));
								unbound_forwards[wdll][module.hModule][export.Ordinal] = name;
#endif // _UNICODE
#ifdef _DEBUG
								_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
									"%s(%08X, ...): %lu. export forward (%s.%s) added for module %s@%08X for delay resolve ordinal=%hu funcRVA=0x%08lX\n",
									__FUNCTION__, hModule, iter, dll, name, module.getBaseName(), module.hModule, export.Ordinal, *funcrva);
#endif // _DEBUG
								HMODULE hLib(LoadLibrary(dll));
								if (hLib != NULL) {
									export.lpFunc = GetProcAddress(hLib, name);
#ifdef _DEBUG
									_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "%s(%08X, ...): using unsafe redirect lookup method for `%s.%s` module=%s LoadLibrary(%s)=%08X GetProcAddress(%s)=%08X\n",
										__FUNCTION__, hModule, dll, name, it != modules.end() ? it->hasName() ?
										it->getBaseName() : "<unnamed>" : "<NULL>", dll, hLib, name, export.lpFunc);
#endif // _DEBUG
									FreeLibrary(hLib);
								}
							}
						} // name != NULL
#ifdef _DEBUG
						else
							_CrtDbgReport(_CRT_ASSERT, NULL, 0, NULL,
								"%s(%08X, ...): %s: export function pointer to export table though not valid forward name: %s funcRVA=0x%08lX\n",
								__FUNCTION__, hModule, module.getBaseName(),
								reinterpret_cast<LPCSTR>(_ExpBufAddr(*funcrva)), *funcrva);
#endif // _DEBUG
					}
					export.Name.clear();
					if (expdir->NumberOfNames > 0 && expdir->AddressOfNames != 0
						&& expdir->AddressOfNames != expdir->AddressOfNameOrdinals) { // by name
						DWORD index(std::distance(reinterpret_cast<LPWORD>_ExpBufAddr((expdir->AddressOfNameOrdinals)),
							std::find(reinterpret_cast<LPWORD>(_ExpBufAddr(expdir->AddressOfNameOrdinals)),
							reinterpret_cast<LPWORD>(_ExpBufAddr(expdir->AddressOfNameOrdinals)) +
							expdir->NumberOfNames, iter)));
						if (index < expdir->NumberOfNames) { // has ordinal table index entry --> named
							const LPCSTR *namerva(&_NameRVA(index));
							if (!_IsInExpBuf(namerva) || *namerva == 0 || !_IsInExpDir(*namerva)) {
#ifdef _DEBUG
								_CrtDbgReport(_CRT_ASSERT, __FILE__, __LINE__, __FUNCTION__,
									"%s(%08X, ...): _IsInExpBuf(&_NameRVA(%lu)) && _NameRVA(%lu) != 0 && _IsInExpDir(_NameRVA(%lu))\n",
									__FUNCTION__, hModule, index, index, index);
#endif // _DEBUG
								std::__stl_throw_out_of_range("!_IsInExpBuf(namerva) || *namerva == 0 || !_IsInExpDir(*namerva)");
							}
							const LPCSTR lpExportName(reinterpret_cast<LPCSTR>(_ExpBufAddr(*namerva)));
							_ASSERTE(*lpExportName != 0);
							if (*lpExportName != 0) {
								export.Name.assign(lpExportName);
								_ASSERTE(module.exports.find(lpExportName) == module.exports.end()); // no name dupes!
							}
						}
					}
					module.exports.insert(export);
#ifdef _DEBUG
				} catch (const std::exception &e) {
					_ASSERTE(_IsInExpDir(expdir->Name));
					_CrtDbgReport(_CRT_ERROR, __FILE__, __LINE__, __FUNCTION__,
						"%s(%08X, ...): failed to add export: module=%s index=%lu (%s)\n",
						__FUNCTION__, hModule,
						reinterpret_cast<LPCSTR>(_ExpBufAddr(expdir->Name)), iter, e.what());
#endif // _DEBUG
				} catch (...) {
					_ASSERTE(_IsInExpDir(expdir->Name));
					_RPTF4(_CRT_ERROR, "%s(%08X, ...): failed to add export: module=%s index=%lu\n",
						__FUNCTION__, hModule, reinterpret_cast<LPCSTR>(_ExpBufAddr(expdir->Name)), iter);
				}
			} // export directory read ok
#ifdef _DEBUG
		} catch (const std::exception &e) {
			_RPTF3(_CRT_ERROR, "%s(%08X, ...): %s\n", __FUNCTION__, hModule, e.what());
#endif // _DEBUG
		} catch (...) {
			_RPTF3(_CRT_ERROR, "%s(%08X, ...): %s\n", __FUNCTION__, hModule, "unknown exception");
		} // have exports
		/*
		typedef struct _IMAGE_THUNK_DATA32 {
			union {
				DWORD ForwarderString;      // PBYTE
				DWORD Function;             // PDWORD
				DWORD Ordinal;
				DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
			} u1;
		} IMAGE_THUNK_DATA32;

		typedef struct _IMAGE_IMPORT_BY_NAME {
			WORD    Hint;
			BYTE    Name[1];
		} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
		*/
		IMAGE_THUNK_DATA thunk;
		PIMAGE_THUNK_DATA thunks;
		BYTE ImpByName[sizeof(WORD) + 0x100 * sizeof(char)];
		// get imports if any
		if (_impdir.VirtualAddress != 0 && _impdir.Size > 0) try { // have imports
			boost::shared_array<IMAGE_IMPORT_DIRECTORY>
				impdir((PIMAGE_IMPORT_DIRECTORY)malloc(_impdir.Size), free);
			if (!impdir) throw std::bad_alloc();
			if (ReadProcessMemory(module.RVA2VA(_impdir.VirtualAddress), impdir.get(), _impdir.Size) >= _impdir.Size) {
				for (PIMAGE_IMPORT_DIRECTORY direntry = impdir.get();
					direntry->dwRVAImportNameTable != 0
						&& direntry->dwRVAImportAddressTable != 0
						&& direntry->dwRVAModuleName != 0;
					++direntry) {
					_ASSERTE((LPBYTE)(direntry +  1) <= (LPBYTE)impdir.get() + _impdir.Size);
					module_t::import_t import;
					// FIXME: bacha na _UNICODE!
					if (ReadProcessMemory(module.RVA2VA(direntry->dwRVAModuleName),
						&import.DllName, sizeof import.DllName) > 0) {
						_ASSERTE(!import.DllName.empty());
						_ASSERTE(import.DllName.length() < MAX_PATH);
						for (thunks = (PIMAGE_THUNK_DATA)(module.RVA2VA(direntry->dwRVAImportNameTable));
							ReadProcessMemory(thunks, &thunk, sizeof thunk) >= sizeof thunk
							&& thunk.u1.AddressOfData != 0; ++thunks, direntry->dwRVAImportAddressTable += sizeof DWORD) try {
							if (IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal)) { // ImpByOrd
								import.Ordinal = IMAGE_ORDINAL(thunk.u1.Ordinal);
								import.Name.clear();
								//_ASSERTE(module.imports.find(import.Ordinal) == module.imports.end()); // no dupes?
							} else { // by name
								if (ReadProcessMemory(module.RVA2VA(thunk.u1.AddressOfData), ImpByName, sizeof ImpByName) >= sizeof IMAGE_IMPORT_BY_NAME) {
									import.Hint = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ImpByName)->Hint;
									import.Name.assign(reinterpret_cast<LPCSTR>(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ImpByName)->Name));
									//_ASSERTE(module.imports.find(import.Name.c_str()) == module.imports.end()); // no dupes?
								}
#ifdef _DEBUG
								else
									_CrtDbgReport(_CRT_ASSERT, __FILE__, __LINE__, __FUNCTION__,
										"%s(...): couldnot read %s structure at RVA 0x%08lX(%08X) (%s at %08X) dwRVAImportNameTable=0x%08lX(%08X), %s at %08X, %s at %08X\n",
										__FUNCTION__, "IMAGE_IMPORT_BY_NAME", thunk.u1.AddressOfData,
										module.RVA2VA(thunk.u1.AddressOfData), module.getBaseName(),
										module.hModule, direntry->dwRVAImportNameTable,
										module.RVA2VA(direntry->dwRVAImportNameTable),
										"IMAGE_THUNK_DATA", thunks, "IMAGE_IMPORT_DIRECTORY",
										module.RVA2VA(_impdir.VirtualAddress + ((LPBYTE)direntry - (LPBYTE)impdir.get())));
#endif // _DEBUG
							}
							import.lpIATEntry = module.RVA2VA(import.IATEntry = direntry->dwRVAImportAddressTable);
							_ASSERTE(module.imports[import.IATEntry] == module.imports.end()); // no dupes
							module.imports.insert(import);
						} catch (...) {
#ifdef _DEBUG
							_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
								"%s(...): failed to add %s for module %s %s=%08X %s=%08X (%s at %08X)\n",
								__FUNCTION__, "import", import.DllName.c_str(), "IMAGE_IMPORT_DIRECTORY",
								module.RVA2VA(_impdir.VirtualAddress + ((LPBYTE)direntry - (LPBYTE)impdir.get())),
								"IMAGE_THUNK_DATA", thunks, module.getBaseName(), module.hModule);
#endif // _DEBUG
						}
					}
#ifdef _DEBUG
					else
						_RPTF4(_CRT_ASSERT, "%s(...): couldnot read module name at RVA 0x%08lX (%s at %08X)\n",
							__FUNCTION__, direntry->dwRVAModuleName, module.getBaseName(), module.hModule);
#endif // _DEBUG
				} // iterate dlls
			} // ReadProcessMemory(...) ok
#ifdef _DEBUG
		} catch (const std::exception &e) {
			_RPTF4(_CRT_ERROR, "%s(...): %s (%s at %08X)\n", __FUNCTION__, e.what(), module.getBaseName(), module.hModule);
#endif // _DEBUG
		} catch (...) {
			_RPTF4(_CRT_ERROR, "%s(...): %s (%s at %08X)\n", __FUNCTION__, "unknown exception", module.getBaseName(), module.hModule);
		} // have imports
		// get delay imports if any
		if (_delayimpdir.VirtualAddress != 0 && _delayimpdir.Size > 0) try { // have delay imports
			boost::shared_array<IMAGE_DELAY_IMPORT_DIRECTORY>
				impdir((PIMAGE_DELAY_IMPORT_DIRECTORY)malloc(_delayimpdir.Size), free);
			if (!impdir) throw std::bad_alloc();
			if (ReadProcessMemory(module.RVA2VA(_delayimpdir.VirtualAddress), impdir.get(), _delayimpdir.Size) >= _delayimpdir.Size) {
				for (PIMAGE_DELAY_IMPORT_DIRECTORY direntry = impdir.get();
					direntry->dwRVAImportNameTable != 0
						&& direntry->dwRVAImportAddressTable != 0
						&& direntry->dwRVAModuleName != 0;
					++direntry) {
					_ASSERTE((LPBYTE)(direntry +  1) <= (LPBYTE)impdir.get() + _delayimpdir.Size);
					module_t::delay_import_t delay_import;
					if (ReadProcessMemory(module.RVA2VA(direntry->dwRVAModuleName),
						&delay_import.DllName, sizeof delay_import.DllName) > 0) {
						_ASSERTE(!delay_import.DllName.empty());
						_ASSERTE(delay_import.DllName.length() < MAX_PATH);
						unsigned int offset(0);
						for (thunks = (PIMAGE_THUNK_DATA)(module.RVA2VA(direntry->dwRVAImportNameTable));
							ReadProcessMemory(thunks, &thunk, sizeof thunk) >= sizeof thunk
							&& thunk.u1.AddressOfData != 0; ++thunks, ++offset) try {
							if (IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal)) { // ImpByOrd
								delay_import.Ordinal = IMAGE_ORDINAL(thunk.u1.Ordinal);
								delay_import.Name.clear();
								//_ASSERTE(module.delay_imports.find(delay_import.Ordinal) == module.delay_imports.end()); // no dupes?
							} else { // by name
								if (ReadProcessMemory(module.RVA2VA(thunk.u1.AddressOfData), ImpByName, sizeof ImpByName) >= sizeof IMAGE_IMPORT_BY_NAME) {
									delay_import.Hint = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ImpByName)->Hint;
									delay_import.Name.assign(reinterpret_cast<LPCSTR>(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ImpByName)->Name));
									//_ASSERTE(module.delay_imports.find(delay_import.Name.c_str()) == module.delay_imports.end()); // no dupes?
								}
#ifdef _DEBUG
								else
									_CrtDbgReport(_CRT_ASSERT, __FILE__, __LINE__, __FUNCTION__,
										"%s(...): couldnot read %s structure at RVA 0x%08lX(%08X) (%s at %08X) dwRVAImportNameTable=0x%08lX(%08X), %s at %08X, %s at %08X\n",
										__FUNCTION__, "IMAGE_IMPORT_BY_NAME", thunk.u1.AddressOfData,
										module.RVA2VA(thunk.u1.AddressOfData), module.getBaseName(),
										module.hModule, direntry->dwRVAImportNameTable,
										module.RVA2VA(direntry->dwRVAImportNameTable),
										"IMAGE_THUNK_DATA", thunks, "IMAGE_DELAY_IMPORT_DIRECTORY",
										module.RVA2VA(_delayimpdir.VirtualAddress + ((LPBYTE)direntry - (LPBYTE)impdir.get())));
#endif // _DEBUG
							}
							delay_import.lpIATEntry = module.RVA2VA(delay_import.IATEntry =
								direntry->dwRVAImportAddressTable + (offset << 2));
							delay_import.BIATEntry = direntry->dwRVABoundImportAddressTable != 0 ?
								direntry->dwRVABoundImportAddressTable + (offset << 2) : 0;
							delay_import.UIATEntry = direntry->dwRVAUnloadImportAddressTable != 0 ?
								direntry->dwRVAUnloadImportAddressTable + (offset << 2) : 0;
 							_ASSERTE(module.delay_imports[delay_import.IATEntry] == module.delay_imports.end()); // no dupes
							module.delay_imports.insert(delay_import);
						} catch (...) {
#ifdef _DEBUG
							_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
								"%s(...): failed to add %s for module %s %s=%08X %s=%08X (%s at %08X)\n",
								__FUNCTION__, "delay import", delay_import.DllName.c_str(), "IMAGE_DELAY_IMPORT_DIRECTORY",
								module.RVA2VA(_delayimpdir.VirtualAddress + ((LPBYTE)direntry - (LPBYTE)impdir.get())),
								"IMAGE_THUNK_DATA", thunks, module.getBaseName(), module.hModule);
#endif // _DEBUG
						}
					}
#ifdef _DEBUG
					else
						_RPTF4(_CRT_ASSERT, "%s(...): couldnot read module name at RVA 0x%08lX (%s at %08X)\n",
							__FUNCTION__, direntry->dwRVAModuleName, module.getBaseName(), module.hModule);
#endif // _DEBUG
				} // iterate dlls
			} // ReadProcessMemory(...) ok
#ifdef _DEBUG
		} catch (const std::exception &e) {
			_RPTF4(_CRT_ERROR, "%s(...): %s (%s at %08X)\n", __FUNCTION__, e.what(), module.getBaseName(), module.hModule);
#endif // _DEBUG
		} catch (...) {
			_RPTF4(_CRT_ERROR, "%s(...): %s (%s at %08X)\n", __FUNCTION__, "unknown exception", module.getBaseName(), module.hModule);
		} // have delay imports
	} // nt header ok
	// load debug info
	if (bUseDbgHelp != FALSE && hDbgHelp != NULL) {
		SymSetOptions_t SymSetOptions((SymSetOptions_t)GetProcAddress(hDbgHelp, "SymSetOptions"));
		if (SymSetOptions != NULL) SymSetOptions(SYMOPT_LOAD_LINES);
		SymLoadModule64_t SymLoadModule64((SymLoadModule64_t)GetProcAddress(hDbgHelp, "SymLoadModule64"));
		if (SymLoadModule64 != NULL && (module.SymBase =
			SymLoadModule64(ProcessInfo.hProcess, hFile, module.FileName,
				NULL/*module.getBaseName()*/, reinterpret_cast<DWORD64>(hModule), module.dwSize/*???*/)) != 0) {
			module.dbgr = this;
			// get all symbols
			SymEnumSymbols_t SymEnumSymbols((SymEnumSymbols_t)GetProcAddress(hDbgHelp, "SymEnumSymbols"));
			if (SymEnumSymbols != NULL) {
				if (SymSetOptions != NULL) SymSetOptions(SYMOPT_LOAD_LINES);
				SymEnumSymbols(ProcessInfo.hProcess, module.SymBase, NULL,
					SymEnumSymbolsProc, &module);
				if (SymSetOptions != NULL) {
					SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_PUBLICS_ONLY);
					SymEnumSymbols(ProcessInfo.hProcess, module.SymBase, NULL,
						SymEnumSymbolsProc, &module);
				}
			}
			// get all source lines
			SymEnumLines_t SymEnumLines((SymEnumLines_t)GetProcAddress(hDbgHelp, "SymEnumLines"));
			if (SymEnumLines != NULL) {
				if (SymSetOptions != NULL) SymSetOptions(SYMOPT_LOAD_LINES);
				SymEnumLines(ProcessInfo.hProcess, static_cast<ULONG64>(module.SymBase), NULL, NULL,
					SymEnumLinesProc, &module);
			}
			// get all source files
			SymEnumSourceFiles_t SymEnumSourceFiles((SymEnumSourceFiles_t)GetProcAddress(hDbgHelp, "SymEnumSourceFiles"));
			if (SymEnumSourceFiles != NULL) {
				if (SymSetOptions != NULL) SymSetOptions(SYMOPT_LOAD_LINES);
				SymEnumSourceFiles(ProcessInfo.hProcess, static_cast<ULONG64>(module.SymBase),
					NULL, SymEnumSourceFilesProc, &module);
			}
		} // SymLoadModule64() != 0
	} // bUseDbgHelp && hDbgHelp != NULL
	tmp = modules.insert(module).first;
	_ASSERTE(tmp != modules.end());
	_ASSERTE(*tmp == module);
	if (!module.exports.empty()) { // resolve forwards to this module (if any)
		unbfwds_t::iterator i(unbound_forwards.find(module.FileName));
		if (i != unbound_forwards.end()) { // loaded module has unresolved redirects
			unbfwds_t::mapped_type::iterator j;
			while ((j = i->second.begin()) != i->second.end()) { // iterate all modules referring it
				modules_t::nth_index_iterator<1>::type k(modules.get<1>().find(j->first)); // find the module by hModule
				_ASSERTE(k != modules.get<1>().end());
				/*unbfwds_t::mapped_type::mapped_type*/std::hash_map<WORD, std::string>::iterator l;
				while ((l = j->second.begin()) != j->second.end()) { // iterate names
					module_t::exports_t::const_iterator m(k->exports[l->first]);
					_ASSERTE(m != k->exports.end());
					if (m != k->exports.end()) {
						module_t::exports_t::const_iterator n(module.exports[l->second.c_str()]);
						if (n != module.exports.end()) {
#ifdef _DEBUG
							OutputDebugString(_sprintf("resolved forwarded export %s@%08X:%hu(%08X)=%s@%08X:%s(%08X)\n",
								k->getBaseName(), k->hModule, l->first, m->lpFunc, module.getBaseName(),
								module.hModule, l->second.c_str(), n->lpFunc).c_str());
#endif // _DEBUG
							deconst_it(m).lpFunc = n->lpFunc;
						}
#ifdef _DEBUG
						else
							_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
								"%s(%08X, ...): forwarded export %s@%08X:%hu=%s@%08X:%s not found in this module (left unsafe)\n",
								__FUNCTION__, hModule, k->getBaseName(), k->hModule, l->first, module.getBaseName(),
								module.hModule, l->second.c_str());
#endif // _DEBUG
					}
					j->second.erase(l);
				}
				i->second.erase(j);
			}
			unbound_forwards.erase(i);
		} // i != unbound_forwards.end()
	} // !module.exports.empty()
	return tmp;
}

#undef _ntdir
#undef _expdir
#undef _ExpBufAddr
#undef _IsInExpBuf
#undef _IsInExpDir
#undef _ExportItem
#undef _Ordinal
#undef _NameRVA
#undef _FuncRVA

bool CDebugger::ResolveModule(const CDebugger::modules_t::iterator &module) {
	_ASSERTE(module != modules.end());
	if (module == modules.end()) return false;
	MODULEINFO ModInfo;
	if (GetModuleInformation(module->hModule, ModInfo) && ModInfo.SizeOfImage > 0)
		deconst_it(module).dwSize = ModInfo.SizeOfImage;
	bool knownfromsnapshot(false);
	MODULEENTRY32 ModEntry;
	if (module->dwSize <= 0 && (knownfromsnapshot = FindModuleEntry(ModEntry,
		module->hInstance)) && ModEntry.modBaseSize > 0)
		deconst_it(module).dwSize = ModEntry.modBaseSize;
	if (strpbrk(module->FileName, "\\/") == 0 || !FileExist(module->FileName))
		GetModuleFileName(module->hModule, deconst_it(module).FileName, module->FileName.capacity());
	if ((strpbrk(module->FileName, "\\/") == 0 || !FileExist(module->FileName))
		&& (knownfromsnapshot
		|| (knownfromsnapshot = FindModuleEntry(ModEntry, module->hInstance))))
			deconst_it(module).FileName = ModEntry.szExePath;
#ifdef _DEBUG
	if (module->dwSize <= 0 || !module->hasName()
		|| strpbrk(module->FileName, "\\/") == 0 || !FileExist(module->FileName))
		_RPT4(_CRT_WARN, "%s(...): module at %08X still not fully resolved: size=0x%IX path=%s\n",
			__FUNCTION__, module->hModule, module->dwSize, module->FileName.c_str());
#endif // _DEBUG
	return module->dwSize > 0 && module->hasName()
		&& strpbrk(module->FileName, "\\/") != 0 && FileExist(module->FileName);
}

typedef NTSTATUS (WINAPI *NtQueryInformationThread_p)(HANDLE, THREADINFOCLASS,
	PVOID, ULONG, PULONG);

NTSTATUS CDebugger::NtQueryInformationThread(HANDLE hThread, THREADINFOCLASS Class,
	PVOID buf, ULONG size, PULONG NumberOfBytes) const {
	_ASSERTE(buf != NULL && size > 0);
	if (buf != NULL && size > 0) ZeroMemory(buf, size);
	const NtQueryInformationThread_p NtQueryInformationThread(hNtDll != NULL ?
		(NtQueryInformationThread_p)GetProcAddress(hNtDll, "NtQueryInformationThread") : NULL);
	ULONG discard;
	return NtQueryInformationThread != NULL ? NtQueryInformationThread(hThread,
		Class, buf, size, NumberOfBytes != NULL ? NumberOfBytes : &discard) : -1/*???*/;
}

BOOL CDebugger::GetHandleName(HANDLE theHandle, LPTSTR Name, SIZE_T dwNameSize) const {
	_ASSERTE(Name != NULL && dwNameSize > 0);
	if (Name == NULL || dwNameSize <= 0) return FALSE;
	std::fill_n(Name, dwNameSize * sizeof(tchar), 0);
	NtQueryObject_p NtQueryObject;
	if (ProcessInfo.hProcess == NULL || hNtDll == NULL
		|| (NtQueryObject = (NtQueryObject_p)GetProcAddress(hNtDll, "NtQueryObject")) == NULL)
		return FALSE;
	boost::scoped_array<WCHAR> aName(new WCHAR[dwNameSize]);
	if (!aName) return FALSE; //throw std::bad_alloc();
	std::fill_n(aName.get(), dwNameSize, 0);
	NtQueryObject(reinterpret_cast<DWORD>(theHandle), ObjectNameInformation,
		reinterpret_cast<DWORD>(aName.get()), dwNameSize * sizeof WCHAR, NULL);
	if (aName[0] == 0) return FALSE;
	return WideCharToMultiByte(CP_ACP, 0, aName.get() + 4,
		-1, Name, dwNameSize, NULL, NULL) > 0 ? TRUE : FALSE;
}

// called only on CREATE_THREAD_DEBUG_EVENT or from thread enumerator
CDebugger::threads_t::const_iterator CDebugger::AddThread(DWORD dwThreadId,
	const CREATE_THREAD_DEBUG_INFO &info) {
	_ASSERTE(dwThreadId != 0);
	if (dwThreadId == 0) return threads.end();
	threads_t::const_iterator i(threads[dwThreadId]);
	if (i != threads.end()) {
		_RPTF2(_CRT_WARN, "%s(0x%lX, ...): trying to (re)add once started thread\n",
			__FUNCTION__, dwThreadId);
		return i;
	}
	_ASSERTE(ProcessInfo.hProcess != NULL);
	thread_t thread(dwThreadId, ProcessInfo.hProcess);
	thread.info = info;
	CThreadHandle hThread(THREAD_ALL_ACCESS, dwThreadId);
	if (thread.info.lpThreadLocalBase == NULL) {
		CONTEXT Context;
		Context.ContextFlags = CONTEXT_SEGMENTS;
		LDT_ENTRY SelectorEntry;
		if (::GetThreadContext(hThread, &Context)
			&& ::GetThreadSelectorEntry(hThread, Context.SegFs, &SelectorEntry))
			thread.info.lpThreadLocalBase = GetSegmentBase(SelectorEntry);
	}
	if (thread.info.lpStartAddress == NULL) {
		GetThreadStartInformation_p GetThreadStartInformation =
			(GetThreadStartInformation_p)GetProcAddress(::GetModuleHandle("kernel32.dll"),
			"GetThreadStartInformation");
		if (GetThreadStartInformation != NULL) {
			LPVOID __discard;
			GetThreadStartInformation(hThread,
				reinterpret_cast<LPVOID *>(&thread.info.lpStartAddress), &__discard);
		}
	}
	ULONG ret;
	if (NtQueryInformationThread(hThread, ThreadBasicInformation,
		&thread.basicinfo, sizeof thread.basicinfo, &ret) != 0) {
		ZeroMemory(&thread.basicinfo, sizeof thread.basicinfo);
		//throw std::runtime_error("NtQueryInformationThread(...) failed");
	}
	i = threads.insert(thread).first;
	_ASSERTE(i != threads.end() && *i == thread);
	return i;
}

// exceptions
DWORD CDebugger::OnBreakpoint(CDebugger::breakpoint_type_t Type, LPVOID Address) const {
	ShoutException("EXCEPTION_BREAKPOINT", "Address=%08X Type=%i", Address, Type);
	return Type == bpt_none ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
}
DWORD CDebugger::OnSingleStep() const {
	ShoutException("EXCEPTION_SINGLE_STEP");
	return DBG_EXCEPTION_NOT_HANDLED;
}
DWORD CDebugger::OnAccessViolation() const {
	ShoutException("EXCEPTION_ACCESS_VIOLATION", "(couldnot %s %08lX)",
		DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 0 ?
		"read from" : "write to", DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]);
	ShoutMemoryDump(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
	ShoutContext();
	return DBG_EXCEPTION_NOT_HANDLED;
}
DWORD CDebugger::OnArrayBoundsExceeded() const { return StdExceptionHandler("EXCEPTION_ARRAY_BOUNDS_EXCEEDED"); }
DWORD CDebugger::OnDatatypeMisalignment() const { return StdExceptionHandler("EXCEPTION_DATATYPE_MISALIGNMENT"); }
DWORD CDebugger::OnFltDenormalOperand() const { return StdExceptionHandler("EXCEPTION_FLT_DENORMAL_OPERAND"); }
DWORD CDebugger::OnFltDivideByZero() const { return StdExceptionHandler("EXCEPTION_FLT_DIVIDE_BY_ZERO"); }
DWORD CDebugger::OnFltInexactResult() const { return StdExceptionHandler("EXCEPTION_FLT_INEXACT_RESULT"); }
DWORD CDebugger::OnFltInvalidOperation() const { return StdExceptionHandler("EXCEPTION_FLT_INVALID_OPERATION"); }
DWORD CDebugger::OnFltOverflow() const { return StdExceptionHandler("EXCEPTION_FLT_OVERFLOW"); }
DWORD CDebugger::OnFltStackCheck() const { return StdExceptionHandler("EXCEPTION_FLT_STACK_CHECK"); }
DWORD CDebugger::OnFltUnderflow() const { return StdExceptionHandler("EXCEPTION_FLT_UNDERFLOW"); }
DWORD CDebugger::OnIllegalInstruction() const { return StdExceptionHandler("EXCEPTION_ILLEGAL_INSTRUCTION"); }
DWORD CDebugger::OnInPageError() const { return StdExceptionHandler("EXCEPTION_IN_PAGE_ERROR"); }
DWORD CDebugger::OnIntDivideByZero() const { return StdExceptionHandler("EXCEPTION_INT_DIVIDE_BY_ZERO"); }
DWORD CDebugger::OnIntOverflow() const { return StdExceptionHandler("EXCEPTION_INT_OVERFLOW"); }
DWORD CDebugger::OnInvalidDisposition() const { return StdExceptionHandler("EXCEPTION_INVALID_DISPOSITION"); }
void CDebugger::OnNoncontinuableException() const { StdExceptionHandler("EXCEPTION_NONCONTINUABLE_EXCEPTION"); }
DWORD CDebugger::OnPrivInstruction() const { return StdExceptionHandler("EXCEPTION_PRIV_INSTRUCTION"); }
DWORD CDebugger::OnStackOverflow() const { return StdExceptionHandler("EXCEPTION_STACK_OVERFLOW"); }
DWORD CDebugger::OnGuardPage() const { return StdExceptionHandler("EXCEPTION_GUARD_PAGE"); }
DWORD CDebugger::OnInvalidHandle() const { return StdExceptionHandler("EXCEPTION_INVALID_HANDLE"); }
DWORD CDebugger::OnDbgControlC() const {
	ShoutException("DBG_CONTROL_C");
	//ShoutMemoryDump(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
	//ShoutContext();
	return DBG_EXCEPTION_NOT_HANDLED;
}
// non-standard exceptions
DWORD CDebugger::OnCustomException() const {
	ShoutException("<unknown>", "ExceptionCode=0x%08lX", DebugEvent.u.Exception.ExceptionRecord.ExceptionCode);
	ShoutMemoryDump(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
	ShoutContext();
	return DBG_EXCEPTION_NOT_HANDLED;
}
DWORD CDebugger::OnUnhandledLastChance() const {
	ShoutException("UnhandledLastChance(non-std.)", "ExceptionCode=0x%08lX", DebugEvent.u.Exception.ExceptionRecord.ExceptionCode);
	ShoutMemoryDump(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
	ShoutContext();
	return DBG_EXCEPTION_NOT_HANDLED;
}
void CDebugger::OnCrash() const { // farewell and goodbye...
#ifndef _DEBUG
	if (bQuiet != FALSE || GetStdHandle(STD_ERROR_HANDLE) == NULL) return; // don't bother
#endif // _DEBUG
	const modules_t::const_iterator
		module(modules.find(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, FALSE));
#ifdef _DEBUG
	if (module == modules.end()) _RPT2(_CRT_WARN, "%s(): couldnot find module for exception at %08X\n",
		__FUNCTION__, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
#endif // _DEBUG
	std::string dbg_out;
	_ASSERTE(dbg_out.empty());
	_sprintf(dbg_out, "[%s] application unrecoverable crash in %s at %08X",
		typeid(*this).name(), module != modules.end() && module->hasName() ?
		module->getBaseName() : "<unknown>",
		DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress/* -
			(module != modules.end() ? module->getBaseOffset() ; 0)*/);
	AskDebugInfo(dbg_out, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
	_sprintf_append(dbg_out, ": ExceptionCode=0x%08lX Flags=0x%lX\n",
		DebugEvent.u.Exception.ExceptionRecord.ExceptionCode,
		DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags);
	ShoutMsg(dbg_out.c_str());
	ShoutMemoryDump(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
	ShoutContext();
}
DWORD CDebugger::StdExceptionHandler(const char *ExceptionName) const {
	_ASSERTE(ExceptionName != 0 && *ExceptionName != 0);
	ShoutException(ExceptionName);
	ShoutMemoryDump(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
	ShoutContext();
	return DBG_EXCEPTION_NOT_HANDLED;
}

// events
void CDebugger::OnCreateProcess() const {
	ShoutEvent("CREATE_PROCESS_DEBUG_EVENT", "0x%lX at %08X MainThreadId=0x%lX StartAddress=%08X MainThreadLocalBase=%08X",
		DebugEvent.dwProcessId, DebugEvent.u.CreateProcessInfo.lpBaseOfImage,
		DebugEvent.dwThreadId, DebugEvent.u.CreateProcessInfo.lpStartAddress,
		DebugEvent.u.CreateProcessInfo.lpThreadLocalBase);
}
void CDebugger::OnCreateThread(const thread_t &thread) const {
	ShoutEvent("CREATE_THREAD_DEBUG_EVENT", "0x%lX StartAddress=%08X ThreadLocalBase=%08X",
		DebugEvent.dwThreadId, DebugEvent.u.CreateThread.lpStartAddress,
		DebugEvent.u.CreateThread.lpThreadLocalBase);
}
void CDebugger::OnLoadDll(const module_t &module) const {
	ShoutEvent("LOAD_DLL_DEBUG_EVENT", "%s at %08X", module.hasName() ?
		module.FileName.c_str() : "<unknown>", DebugEvent.u.LoadDll.lpBaseOfDll);
}
void CDebugger::OnOutputDebugString() const {
#ifndef _DEBUG
	if (bQuiet != FALSE || GetStdHandle(STD_ERROR_HANDLE) == NULL) return; // don't bother
#endif // _DEBUG
	const size_t len(DebugEvent.u.DebugString.nDebugStringLength <<
		(DebugEvent.u.DebugString.fUnicode & 1));
	boost::shared_array<char> message(new char[len]);
	if (!message) {
		_RPTF2(_CRT_WARN, "%s(): failed to allocate buffer of size 0x%lX for debug string\n", __FUNCTION__, len);
		return; //throw std::bad_alloc();
	}
	if (ReadMemory(DebugEvent.u.DebugString.lpDebugStringData, message.get(), len) < len) {
		_RPTF1(_CRT_WARN, "%s(): failed to read debug string\n", __FUNCTION__);
		return;
	}
	if (DebugEvent.u.DebugString.fUnicode != 0) {
		boost::shared_array<char> tmp(new char[DebugEvent.u.DebugString.nDebugStringLength]);
		if (!tmp) {
			_RPTF2(_CRT_WARN, "%s(): failed to allocate buffer of size 0x%hX for debug string\n",
				__FUNCTION__, DebugEvent.u.DebugString.nDebugStringLength);
			return; //throw std::bad_alloc();
		}
		WideCharToMultiByte(CP_ACP, WC_DEFAULTCHAR, reinterpret_cast<LPCWSTR>(message.get()),
			-1, tmp.get(), DebugEvent.u.DebugString.nDebugStringLength, NULL, NULL);
		message = tmp;
	}
	ShoutEvent("OUTPUT_DEBUG_STRING_EVENT", "%s", message.get());
}
void CDebugger::OnRip() const {
	ShoutEvent("RIP_EVENT", "Error/Type: 0x%lX/0x%lX\n",
		DebugEvent.u.RipInfo.dwError, DebugEvent.u.RipInfo.dwType);
}
void CDebugger::OnUnloadDll(const module_t &module) const {
	ShoutEvent("UNLOAD_DLL_DEBUG_EVENT", "%s at %08X", module.hasName() ?
		module.FileName.c_str() : "<unknown>", DebugEvent.u.UnloadDll.lpBaseOfDll);
}
void CDebugger::OnExitThread(const thread_t &thread) const {
	ShoutEvent("EXIT_THREAD_DEBUG_EVENT", "0x%lX ExitCode=%li",
		DebugEvent.dwThreadId, DebugEvent.u.ExitThread.dwExitCode);
}
void CDebugger::OnExitProcess() const {
	ShoutEvent("EXIT_PROCESS_DEBUG_EVENT", "ExitCode=%li",
		DebugEvent.u.ExitProcess.dwExitCode);
}
// non-std events
void CDebugger::OnEntryPoint() const {
	ShoutEvent("application entry point", "IP=%08X", DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
}

void CDebugger::ShoutException(LPCSTR lpExceptionName, const char *format, ...) const {
#ifndef _DEBUG
	if (bQuiet != FALSE || GetStdHandle(STD_ERROR_HANDLE) == NULL) return; // don't bother
#endif // _DEBUG
	_ASSERTE(lpExceptionName != NULL && *lpExceptionName != 0);
	if (lpExceptionName == NULL || *lpExceptionName == 0) return;
	const modules_t::const_iterator
		module(modules.find(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, FALSE));
#ifdef _DEBUG
	if (module == modules.end()) _RPT4(_CRT_WARN, "%s(\"%s\", \"%s\", ...): couldnot find module for exception at %08X\n",
		__FUNCTION__, lpExceptionName, format, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
#endif // _DEBUG
	std::string dbg_out;
	_sprintf(dbg_out, "[%s] %s chance %s exception in %s at %08X",
		typeid(*this).name(), DebugEvent.u.Exception.dwFirstChance ? "first" : "second", lpExceptionName,
		module != modules.end() && module->hasName() ? module->getBaseName() : "<unknown>",
		DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress/* -
			(module != modules.end() ? module->getBaseOffset() ; 0)*/);
	AskDebugInfo(dbg_out, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
	_sprintf_append(dbg_out, ": Flags=0x%lX", DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags);
	if (format != 0) {
		dbg_out.push_back(' ');
		va_list argptr;
		va_start(argptr, format);
		_vsprintf_append(dbg_out, format, argptr);
		va_end(argptr);
	}
	dbg_out.push_back('\n');
	ShoutMsg(dbg_out.c_str());
}

void CDebugger::ShoutEvent(LPCSTR lpEventName, const char *format, ...) const {
#ifndef _DEBUG
	if (bQuiet != FALSE || GetStdHandle(STD_ERROR_HANDLE) == NULL) return; // don't bother
#endif // _DEBUG
	_ASSERTE(lpEventName != NULL && *lpEventName != 0);
	if (lpEventName == NULL || *lpEventName == 0) return;
	std::string dbg_out;
// 	LPCVOID const IP(GetIP());
// 	const modules_t::const_iterator module(modules.find(IP, FALSE));
// #ifdef _DEBUG
// 	if (module == modules.end()) _RPT4(_CRT_WARN, "%s(\"%s\", \"%s\", ...): couldnot find module for exception at %08X\n",
// 		__FUNCTION__, lpEventName, format, IP);
// #endif // _DEBUG
	_sprintf(dbg_out, "[%s] %s"/*" at %s:%08X"*/, typeid(*this).name(), lpEventName/*,
		module != modules.end() && module->hasName() ? module->getBaseName() : "<unknown>",
		IP*/);
// 	AskDebugInfo(dbg_out, IP);
	if (format != 0) {
		dbg_out.append(": ");
		va_list argptr;
		va_start(argptr, format);
		_vsprintf_append(dbg_out, format, argptr);
		va_end(argptr);
	}
	dbg_out.push_back('\n');
	ShoutMsg(dbg_out.c_str());
}

void CDebugger::ShoutContext() const {
#ifndef _DEBUG
	if (bQuiet != FALSE || GetStdHandle(STD_ERROR_HANDLE) == NULL) return; // don't bother
#endif // _DEBUG
	std::string dbg_out;
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
	if (GetThreadContext(Context, TRUE)) {
		_sprintf(dbg_out, "[%s]   context dump: eax=%08lX ecx=%08lX edx=%08lX ebx=%08lX esp=%08lX ebp=%08lX esi=%08lX edi=%08lX eip=%08lX\n",
			typeid(*this).name(), Context.Eax, Context.Ecx, Context.Edx, Context.Ebx, Context.Esp, Context.Ebp, Context.Esi, Context.Edi, Context.Eip);
		ShoutMsg(dbg_out.c_str());
	}
}

void CDebugger::ShoutMemoryDump(LPCVOID IP) const {
#ifndef _DEBUG
	if (bQuiet != FALSE || GetStdHandle(STD_ERROR_HANDLE) == NULL) return; // don't bother
#endif // _DEBUG
	BYTE buf[0x10];
	if (ReadMemory(const_cast<LPVOID>(IP), buf, sizeof buf) < sizeof buf) return;
	std::string dbg_out;
	_sprintf(dbg_out, "[%s]   memory dump at IP:", typeid(*this).name());
	for (unsigned int offset = 0; offset < sizeof buf; ++offset)
		_sprintf_append(dbg_out, " %02X", buf[offset]);
	dbg_out.push_back('\n');
	ShoutMsg(dbg_out.c_str());
}

void CDebugger::ShoutMsg(const char *msg) const {
#ifdef _DEBUG
	if (bQuiet == FALSE && GetStdHandle(STD_ERROR_HANDLE) != NULL)
#endif // _DEBUG
		fprintf(stderr, "%s", msg);
#ifdef _DEBUG
	OutputDebugString(msg);
#endif // _DEBUG
}

void CDebugger::AskDebugInfo(std::string &s, LPCVOID addr) const {
	DWORD64 Displacement;
	PSYMBOL_INFO pSymInfo((PSYMBOL_INFO)malloc(sizeof SYMBOL_INFO + MAX_SYM_NAME - 1));
	if (pSymInfo == NULL) return; //throw std::bad_alloc();
	__try {
		pSymInfo->MaxNameLen = MAX_SYM_NAME;
		if (!SymFromAddr(addr, &Displacement, pSymInfo)) __leave;
		_sprintf_append(s, "(%s", pSymInfo->Name);
		if (Displacement > 0) _sprintf_append(s, "+0x%I64X", Displacement);
		s.push_back(')');
	} __finally {
		free(pSymInfo);
	}
	IMAGEHLP_LINE64 Line;
	if (LineFromAddr(addr, reinterpret_cast<PDWORD>(&Displacement), Line)) {
		_sprintf_append(s, "=%s:%lu", Line.FileName, Line.LineNumber);
		if (static_cast<DWORD>(Displacement) > 0)
			_sprintf_append(s, "+0x%lX", static_cast<DWORD>(Displacement));
	}
}

// VisualC++ debug heap block header

#define nNoMansLandSize     4

#define _bAlignLandFill  0xBD /* fill no-man's land for aligned routines */
#define _bCleanLandFill  0xCD /* fill new objects with this */
#define _bDeadLandFill   0xDD /* fill free objects with this */
#define _bNoMansLandFill 0xFD /* fill no-man's land with this */

typedef struct _CrtMemBlockHeader {
	struct _CrtMemBlockHeader * pBlockHeaderNext;
	struct _CrtMemBlockHeader * pBlockHeaderPrev;
	char *                      szFileName;
	int                         nLine;
#ifdef _WIN64
	/* These items are reversed on Win64 to eliminate gaps in the struct
	 * and ensure that sizeof(struct)%16 == 0, so 16-byte alignment is
	 * maintained in the debug heap.
	 */
	int                         nBlockUse;
	size_t                      nDataSize;
#else  /* _WIN64 */
	size_t                      nDataSize;
	int                         nBlockUse;
#endif  /* _WIN64 */
	long                        lRequest;
	unsigned char               gap[nNoMansLandSize];
	/* followed by:
	 *  unsigned char           data[nDataSize];
	 *  unsigned char           anotherGap[nNoMansLandSize];
	 */
} _CrtMemBlockHeader;

bool __fastcall _BLOCK_TYPE_IS_VALID(int use) {
	return _BLOCK_TYPE(use) == _CLIENT_BLOCK || use == _NORMAL_BLOCK
		|| _BLOCK_TYPE(use) == _CRT_BLOCK || use == _IGNORE_BLOCK
		|| use == _FREE_BLOCK;
}

#ifdef __ICL
#pragma warning(disable: 1011) // function doesn't return value
#endif // __ICL

static bool ValidateFill(LPCVOID pGap, SIZE_T gapSize, unsigned char _bFillChar) {
	__asm {
		mov edi, pGap
		mov ecx, gapSize
		mov al, _bFillChar
		cld
		repz scasb
		setz al
	}
}
//#pragma intrinsic(ValidateFill)

SIZE_T CDebugger::FindHeapBlock(LPCVOID lpAddress, BOOL bExactMatch, LPCVOID *lpBaseAddress) const {
	SIZE_T dwResult(static_cast<SIZE_T>(-1L));
	if (lpBaseAddress != NULL) *lpBaseAddress = NULL;
	if (!bIsAttached || !IsAddressEnabled(lpAddress)) return dwResult;
	__try {
#if TOOLHELPSNAPSHOT_TIMEOUT > 0
		HANDLE hKiller(StartKiller(__FUNCTION__ "(...)"));
#endif
		HANDLE h_snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST,
			ProcessInfo.dwProcessId));
#if TOOLHELPSNAPSHOT_TIMEOUT > 0
		StopKiller(hKiller);
#endif
		if (h_snapshot == INVALID_HANDLE_VALUE) {
			_RPTF2(_CRT_ERROR, "%s(%08X, ...): == INVALID_HANDLE_VALUE\n",
				__FUNCTION__, lpAddress);
			return dwResult;
		}
		__try {
			HEAPLIST32 heap_list;
			heap_list.dwSize = sizeof HEAPLIST32;
			BOOL heap_exists(Heap32ListFirst(h_snapshot, &heap_list));
			while (heap_exists != FALSE) {
				HEAPENTRY32 heap_entry;
				heap_entry.dwSize = sizeof HEAPENTRY32;
				BOOL block_exists(Heap32First(&heap_entry, ProcessInfo.dwProcessId,
					heap_list.th32HeapID));
				while (block_exists) {
					if (heap_entry.dwFlags != LF32_FREE
						&& (reinterpret_cast<DWORD>(lpBaseAddress) == heap_entry.dwAddress
						|| bExactMatch == FALSE && reinterpret_cast<DWORD>(lpBaseAddress) > heap_entry.dwAddress
						&& reinterpret_cast<DWORD>(lpBaseAddress) < heap_entry.dwAddress + heap_entry.dwBlockSize)) {
						SIZE_T dwResult(heap_entry.dwBlockSize);
						LPCVOID _lpBaseAddress(reinterpret_cast<LPCVOID>(heap_entry.dwAddress));
						// test for VC++ heap debug header
						__try {
							if (dwResult > sizeof _CrtMemBlockHeader + nNoMansLandSize * sizeof(unsigned char)) {
								void *buf(malloc(dwResult));
								if (buf != 0) __try {
									if (ReadMemory(_lpBaseAddress, buf, dwResult) >= dwResult
										&& _BLOCK_TYPE_IS_VALID(static_cast<_CrtMemBlockHeader *>(buf)->nBlockUse)
										// lRequest may be 0 (IGNORE_REQ)
										&& static_cast<_CrtMemBlockHeader *>(buf)->nDataSize > 0
										&& dwResult >= sizeof _CrtMemBlockHeader +
											static_cast<_CrtMemBlockHeader *>(buf)->nDataSize + nNoMansLandSize * sizeof(unsigned char)
										&& ValidateFill(static_cast<_CrtMemBlockHeader *>(buf)->gap,
											sizeof(static_cast<_CrtMemBlockHeader *>(buf)->gap), _bNoMansLandFill)
										&& ValidateFill((LPBYTE)buf + sizeof _CrtMemBlockHeader + static_cast<_CrtMemBlockHeader *>(buf)->nDataSize,
											nNoMansLandSize * sizeof(unsigned char), _bNoMansLandFill))
										if ((LPBYTE)lpAddress >= (LPBYTE)_lpBaseAddress + sizeof _CrtMemBlockHeader
											&& (LPBYTE)lpAddress < (LPBYTE)_lpBaseAddress + sizeof _CrtMemBlockHeader + static_cast<_CrtMemBlockHeader *>(buf)->nDataSize
											&& static_cast<_CrtMemBlockHeader *>(buf)->nBlockUse != _FREE_BLOCK) {
											dwResult = static_cast<_CrtMemBlockHeader *>(buf)->nDataSize;
											_lpBaseAddress = (_CrtMemBlockHeader *)_lpBaseAddress + 1;
#ifdef _DEBUG
											if (ValidateFill(static_cast<_CrtMemBlockHeader *>(buf) + 1, static_cast<_CrtMemBlockHeader *>(buf)->nDataSize, _bCleanLandFill))
												_RPT4(_CRT_WARN, "%s(%08X, ...): validated VC++ debug heap block <%08X-%08X> probably not initialized (_bCleanLandFill)\n",
													__FUNCTION__, lpAddress, _lpBaseAddress, (LPBYTE)_lpBaseAddress + dwResult);
#endif // _DEBUG
										} else { // points to control area or freed block
											dwResult = static_cast<SIZE_T>(-1L);
											_lpBaseAddress = NULL;
										}
								} __finally {
									free(buf);
								}
							}
						} __except(EXCEPTION_EXECUTE_HANDLER) {
							dwResult = heap_entry.dwBlockSize;
							_lpBaseAddress = reinterpret_cast<LPCVOID>(heap_entry.dwAddress);
						}
						if (lpBaseAddress != NULL) *lpBaseAddress = _lpBaseAddress;
						__leave;
					}
					heap_entry.dwSize = sizeof HEAPENTRY32;
					block_exists = Heap32Next(&heap_entry);
				}
				heap_list.dwSize = sizeof HEAPLIST32;
				heap_exists = Heap32ListNext(h_snapshot, &heap_list);
			}
		} __finally {
			CloseHandle(h_snapshot);
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		_RPTF3(_CRT_ERROR, "%s(%08X, ...): ToolHelp Heap Enumerator exception for 0x%lX\n",
			__FUNCTION__, lpAddress, ProcessInfo.dwProcessId);
	}
	return dwResult;
}

#if TOOLHELPSNAPSHOT_TIMEOUT > 0

HANDLE CDebugger::StartKiller(LPCSTR FuncName) const {
	HANDLE hResult(CreateThread(NULL, 0, ToolHelpKiller, this, 0, NULL));
#ifdef _DEBUG
	if (hResult == NULL) _RPT3(_CRT_WARN, "%s(\"%s\"): failed to start ToolHelp killer thread in %s; if the debugger stops responding for >15s, kill debugee by task manager\n",
		__FUNCTION__, FuncName, FuncName != 0 && *FuncName != 0 ? FuncName : "<unknown>");
#endif // _DEBUG
	if (hResult != NULL) WaitForSingleObject(hResult, 0); // instant start
	return hResult;
}

void CDebugger::StopKiller(HANDLE hKiller) {
	_ASSERTE(hKiller != NULL);
	if (hKiller != NULL) {
		DWORD ExitCodeThread;
#ifdef _DEBUG
		BOOL ok(::GetExitCodeThread(hKiller, &ExitCodeThread));
		_ASSERTE(ok != FALSE);
		if (ok != FALSE && ExitCodeThread == STILL_ACTIVE) {
			ok =
#else // _DEBUG
		if (::GetExitCodeThread(hKiller, &ExitCodeThread)
			&& ExitCodeThread == STILL_ACTIVE) {
#endif // _DEBUG
			::TerminateThread(hKiller, 0);
			_ASSERTE(ok);
		} // thread running
#ifdef _DEBUG
		DWORD obj =
#endif // _DEBUG
		WaitForSingleObject(hKiller, INFINITE);
#ifdef _DEBUG
		if (obj != WAIT_OBJECT_0) _RPTF4(_CRT_WARN,
			"%s(%08X): StopKiller(...): WaitForSingleObject(%08X, ...) reported thread not in signaled state (0x%lX)\n",
			__FUNCTION__, hKiller, hKiller, obj);
#endif // _DEBUG
		CloseHandle(hKiller);
	} // handle valid
}

DWORD WINAPI CDebugger::ToolHelpKiller(LPVOID lpDebugger) {
	_ASSERTE(lpDebugger != 0);
	if (lpDebugger != 0) {
		Sleep(TOOLHELPSNAPSHOT_TIMEOUT); // wait to get the snapshot
		_RPT3(_CRT_WARN, "%s(%08X): TimeOut for CreateToolhelp32Snapshot(0x%lX, ...) reached, terminating debugee now...\n",
			__FUNCTION__, lpDebugger, static_cast<CDebugger *>(lpDebugger)->ProcessInfo.dwProcessId);
		if (static_cast<CDebugger *>(lpDebugger)->Terminate(static_cast<UINT>(-1L))) {
			_RPT3(_CRT_WARN, "%s(%08X): process 0x%lX terminated successfully...\n",
				__FUNCTION__, lpDebugger, static_cast<CDebugger *>(lpDebugger)->ProcessInfo.dwProcessId);
			return 0;
		}
	}
	return static_cast<DWORD>(-1L);
}

#endif // TOOLHELPSNAPSHOT_TIMEOUT > 0

bool CDebugger::FileExist(LPCTSTR FilePath) {
	HANDLE fio(CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE |
		FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
	if (fio == INVALID_HANDLE_VALUE) return false;
	CloseHandle(fio);
	return true;
}

CDebugger::tchar *CDebugger::getBaseName(const CDebugger::tchar *Name) {
	_ASSERTE(Name != 0);
	if (Name == 0) return 0;
	const tchar *foo(std::max(_tcsrchr(Name, '\\'), _tcsrchr(Name, '/')));
	return const_cast<tchar *>(foo != 0 ? foo + 1 : Name);
}

bool CDebugger::less::basename::operator ()(const CDebugger::tchar *s1,
	const CDebugger::tchar *s2) const throw() {
	if (s2 == 0) return false;
	if (s1 == 0) return true;
	tchar fname[2][_MAX_FNAME];
	_tsplitpath(s1, 0, 0, fname[0], 0);
	_tsplitpath(s2, 0, 0, fname[1], 0);
	return _tcsicmp(fname[0], fname[1]) < 0;
}

//  MS debuging support (ImageHlp) 
// todo: translate API names for UNC!

typedef BOOL (WINAPI *SymFromName_t)(IN HANDLE hProcess, IN PCSTR Name, OUT PSYMBOL_INFO Symbol);
BOOL CDebugger::SymFromName(const CDebugger::DBGHELP_TCHAR *Name, PSYMBOL_INFO pSymbol) const {
	_ASSERTE(pSymbol != NULL);
	if (!bIsAttached || bUseDbgHelp == FALSE
		|| hDbgHelp == NULL || pSymbol == NULL) return FALSE;
	pSymbol->SizeOfStruct = sizeof SYMBOL_INFO;
	SymFromName_t pSymFromName((SymFromName_t)GetProcAddress(hDbgHelp, "SymFromName"));
	if (pSymFromName == NULL) return FALSE;
	BOOL ok(pSymFromName(ProcessInfo.hProcess, Name, pSymbol));
	if (ok != FALSE) {
		// TODO: find container module
		// TODO: adjust address respectively to SymBase and real load address of container module
	}
	return ok;
}

typedef BOOL (WINAPI *SymFromAddr_t)(IN HANDLE hProcess, IN DWORD64 Address, OUT PDWORD64 Displacement, IN OUT PSYMBOL_INFO Symbol);
BOOL CDebugger::SymFromAddr(LPCVOID Addr, PDWORD64 Displacement, PSYMBOL_INFO pSymbol) const {
	_ASSERTE(pSymbol != NULL);
	if (!bIsAttached || bUseDbgHelp == FALSE || hDbgHelp == NULL || pSymbol == NULL) return FALSE;
	pSymbol->SizeOfStruct = sizeof SYMBOL_INFO;
	SymFromAddr_t pSymFromAddr((SymFromAddr_t)GetProcAddress(hDbgHelp, "SymFromAddr"));
	if (pSymFromAddr == NULL) return FALSE;
	const modules_t::const_iterator module(modules.find(Addr, FALSE));
	if (module != modules.end())
		Addr = (LPBYTE)Addr + module->SymOffset();
#ifdef _DEBUG
	else
		_RPT2(_CRT_WARN, "%s(%08X, ...): couldnot find module for queried address\n",
			__FUNCTION__, Addr);
#endif // _DEBUG
	BOOL ok(pSymFromAddr(ProcessInfo.hProcess, reinterpret_cast<DWORD64>(Addr),
		Displacement, pSymbol));
	if (ok != FALSE && module != modules.end()) pSymbol->Address -= module->SymOffset();
	return ok;
}

LPVOID CDebugger::GetSymAddr(const CDebugger::DBGHELP_TCHAR *Name) const {
	if (Name != NULL && *Name != 0) {
		PSYMBOL_INFO pSymInfo((PSYMBOL_INFO)malloc(sizeof SYMBOL_INFO + MAX_SYM_NAME - 1));
		if (pSymInfo != NULL) __try {
			pSymInfo->MaxNameLen = MAX_SYM_NAME;
			if (SymFromName(Name, pSymInfo))
				return reinterpret_cast<LPVOID>(pSymInfo->Address);
		} __finally {
			free(pSymInfo);
		}
	}
	return NULL;
}

typedef BOOL (WINAPI *SymGetLineFromName64_t)(IN HANDLE hProcess, IN PCSTR ModuleName, IN PCSTR FileName, IN DWORD dwLineNumber, OUT PLONG plDisplacement, IN OUT PIMAGEHLP_LINE64 Line);
BOOL CDebugger::LineFromName(const CDebugger::DBGHELP_TCHAR *ModuleName,
	const CDebugger::DBGHELP_TCHAR *FileName, DWORD dwLineNumber,
	PLONG lpDisplacement, IMAGEHLP_LINE64 &Line) const {
	ZeroMemory(&Line, sizeof IMAGEHLP_LINE64);
	if (!bIsAttached || bUseDbgHelp == FALSE || hDbgHelp == NULL) return FALSE;
	Line.SizeOfStruct = sizeof IMAGEHLP_LINE64;
	SymGetLineFromName64_t pSymGetLineFromName64((SymGetLineFromName64_t)GetProcAddress(hDbgHelp, "SymGetLineFromName64"));
	if (pSymGetLineFromName64 == NULL) return FALSE;
	BOOL ok(pSymGetLineFromName64(ProcessInfo.hProcess, ModuleName, FileName,
			dwLineNumber, lpDisplacement, &Line));
	if (ok != FALSE) {
		modules_t::const_iterator module(modules.find_fullpath(ModuleName));
		if (module == modules.end()) module = modules.find(ModuleName);
		if (module == modules.end()) module = modules.find_basename(ModuleName);
		if (module != modules.end()) Line.Address -= module->SymOffset();
#ifdef _DEBUG
		else
			_RPT4(_CRT_WARN, "%s(\"%s\", \"%s\", %lu, ...): couldnot find module of queried name\n",
				__FUNCTION__, ModuleName, FileName, dwLineNumber);
#endif // _DEBUG
	}
	return ok;
}

typedef BOOL (WINAPI *SymGetLineFromAddr64_t)(IN  HANDLE hProcess, IN DWORD64 qwAddr, OUT PDWORD pdwDisplacement, OUT PIMAGEHLP_LINE64 Line64);
BOOL CDebugger::LineFromAddr(LPCVOID Addr, PDWORD Displacement, IMAGEHLP_LINE64 &Line) const {
	ZeroMemory(&Line, sizeof IMAGEHLP_LINE64);
	if (!bIsAttached || bUseDbgHelp == FALSE || hDbgHelp == NULL) return FALSE;
	Line.SizeOfStruct = sizeof IMAGEHLP_LINE64;
	SymGetLineFromAddr64_t pSymGetLineFromAddr64((SymGetLineFromAddr64_t)GetProcAddress(hDbgHelp, "SymGetLineFromAddr64"));
	if (pSymGetLineFromAddr64 == NULL) return FALSE;
	const modules_t::const_iterator module(modules.find(Addr, FALSE));
	if (module != modules.end()) Addr = (LPBYTE)Addr + module->SymOffset();
#ifdef _DEBUG
	else
		_RPT2(_CRT_WARN, "%s(%08X, ...): couldnot find module for queried address\n",
			__FUNCTION__, Addr);
#endif // _DEBUG
	BOOL ok(pSymGetLineFromAddr64(ProcessInfo.hProcess,
		reinterpret_cast<DWORD64>(Addr), Displacement, &Line));
	if (ok != FALSE && module != modules.end()) Line.Address -= module->SymOffset();
	return ok;
}

typedef BOOL (WINAPI *StackWalk64_p)(DWORD, HANDLE, HANDLE, LPSTACKFRAME64, PVOID, PREAD_PROCESS_MEMORY_ROUTINE64, PFUNCTION_TABLE_ACCESS_ROUTINE64, PGET_MODULE_BASE_ROUTINE64, PTRANSLATE_ADDRESS_ROUTINE64);
typedef PVOID (WINAPI *SymFunctionTableAccess64_p)(HANDLE, DWORD64);
typedef DWORD64 (WINAPI *SymGetModuleBase64_p)(IN HANDLE, IN DWORD64);
BOOL __stdcall CDebugger::ReadMemoryRoutine64(HANDLE hProcess, DWORD64 qwBaseAddress,
	PVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead) {
	return ::ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(qwBaseAddress),
		lpBuffer, nSize, lpNumberOfBytesRead);
}
BOOL CDebugger::StackWalk(STACKFRAME64 &StackFrame, LPCVOID AddrPC,
	LPCVOID AddrFrame, LPCVOID AddrStack) const {
	ZeroMemory(&StackFrame, sizeof StackFrame);
	if (DebugEvent.dwDebugEventCode == 0 || !bIsAttached
		|| bUseDbgHelp == FALSE || hDbgHelp == NULL) return FALSE;
	StackWalk64_p const StackWalk64((StackWalk64_p)GetProcAddress(hDbgHelp, "StackWalk64"));
	if (StackWalk64 == NULL) return FALSE;
	CThreadHandle hThread(THREAD_ALL_ACCESS, DebugEvent.dwThreadId);
	if (!hThread) {
		_RPT3(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, DebugEvent.dwThreadId, "THREAD_ALL_ACCESS");
		return FALSE;
	}
	CONTEXT Context;
	const BOOL useCtxt(GetThreadContext(Context));
	if (AddrPC != NULL) {
		StackFrame.AddrPC.Offset = reinterpret_cast<DWORD64>(AddrPC);
		StackFrame.AddrPC.Segment = 0;
		StackFrame.AddrPC.Mode = AddrModeFlat;
	} else if (useCtxt != FALSE) {
		StackFrame.AddrPC.Offset = static_cast<DWORD64>(Context.Eip);
		StackFrame.AddrPC.Segment = 0;
		StackFrame.AddrPC.Mode = AddrModeFlat;
	}
	if (AddrFrame != NULL) {
		StackFrame.AddrFrame.Offset = reinterpret_cast<DWORD64>(AddrFrame);
		StackFrame.AddrFrame.Segment = 0;
		StackFrame.AddrFrame.Mode = AddrModeFlat;
	} else if (useCtxt != FALSE) {
		StackFrame.AddrFrame.Offset = static_cast<DWORD64>(Context.Ebp);
		StackFrame.AddrFrame.Segment = 0;
		StackFrame.AddrFrame.Mode = AddrModeFlat;
	}
	if (AddrStack != NULL) {
		StackFrame.AddrStack.Offset = reinterpret_cast<DWORD64>(AddrStack);
		StackFrame.AddrStack.Segment = 0;
		StackFrame.AddrStack.Mode = AddrModeFlat;
	} else if (useCtxt != FALSE) {
		StackFrame.AddrStack.Offset = static_cast<DWORD64>(Context.Esp);
		StackFrame.AddrStack.Segment = 0;
		StackFrame.AddrStack.Mode = AddrModeFlat;
	}
	return StackWalk64(IMAGE_FILE_MACHINE_I386, ProcessInfo.hProcess, hThread,
		&StackFrame, useCtxt != FALSE ? &Context : NULL, &ReadMemoryRoutine64,
		(SymFunctionTableAccess64_p)GetProcAddress(hDbgHelp, "SymFunctionTableAccess64"),
		(SymGetModuleBase64_p)GetProcAddress(hDbgHelp, "SymGetModuleBase64"), NULL/*PTRANSLATE_ADDRESS_ROUTINE64*/);
}

const FPO_DATA *CDebugger::FunctionTableAccess(LPCVOID AddrBase) const {
	if (!bIsAttached || bUseDbgHelp == FALSE || hDbgHelp == NULL) return NULL;
	SymFunctionTableAccess64_p SymFunctionTableAccess64((SymFunctionTableAccess64_p)GetProcAddress(hDbgHelp, "SymFunctionTableAccess64"));
	if (SymFunctionTableAccess64 == NULL) return NULL;
	return static_cast<const FPO_DATA *>(SymFunctionTableAccess64(ProcessInfo.hProcess,
		reinterpret_cast<DWORD64>(AddrBase)));
}

typedef BOOL (WINAPI *SymGetTypeInfo_p)(HANDLE, DWORD64, ULONG, IMAGEHLP_SYMBOL_TYPE_INFO, PVOID);
BOOL CDebugger::GetTypeInfo(HMODULE hModule, ULONG TypeId,
	IMAGEHLP_SYMBOL_TYPE_INFO GetType, PVOID pInfo) const {
	if (!bIsAttached || bUseDbgHelp == FALSE || hDbgHelp == NULL) return FALSE;
	SymGetTypeInfo_p SymGetTypeInfo((SymGetTypeInfo_p)GetProcAddress(hDbgHelp, "SymGetTypeInfo"));
	if (SymGetTypeInfo == NULL) return FALSE;
	return SymGetTypeInfo(ProcessInfo.hProcess, reinterpret_cast<DWORD64>(hModule),
		TypeId, GetType, pInfo);
}

//  class CDebugger::CHwBptMgr 

BOOL CDebugger::CHwBptMgr::Load() {
	if (dbgr == 0) return FALSE;
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!dbgr->GetThreadContext(Context, TRUE)) {
		dbgr = 0;
		return FALSE;
	}
	//std::copy(&Context.Dr0, &Context.Dr0 + 6, DR);
	DR[0] = Context.Dr0;
	DR[1] = Context.Dr1;
	DR[2] = Context.Dr2;
	DR[3] = Context.Dr3;
	DR[4] = Context.Dr6;
	DR[5] = Context.Dr7;
	Snapshot();
	return TRUE;
}

BOOL CDebugger::CHwBptMgr::Save() {
	if (dbgr == 0) return FALSE;
	if (!Changed()) return TRUE;
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	//std::copy(DR, DR + 6, &Context.Dr0);
	Context.Dr0 = DR[0];
	Context.Dr1 = DR[1];
	Context.Dr2 = DR[2];
	Context.Dr3 = DR[3];
	Context.Dr6 = DR[4];
	Context.Dr7 = DR[5];
	if (!dbgr->SetThreadContext(Context)) {
		//dbgr = 0; // ???
		return FALSE;
	}
	Snapshot();
	return TRUE;
}

BOOL CDebugger::CHwBptMgr::Set(BYTE nIndex, LPCVOID Address,
	breakpoint_type_t Type, BYTE Size, BOOL LocalActive, BOOL GlobalActive) {
	if (dbgr == 0) return FALSE; // invalid snapshot
	if (nIndex >= 4) {
		_RPT4(_CRT_WARN, "%s(%u, %08X, %i, ...): index out of range\n",
			__FUNCTION__, nIndex, Address, Type);
		return FALSE;
	}
	BYTE SlotBits;
	switch (Type) {
		case bpt_hw_exec: SlotBits = 0; break;
		case bpt_hw_write: SlotBits = 1; break;
		case bpt_hw_io_access: SlotBits = 2; break;
		case bpt_hw_access: SlotBits = 3; break;
		default:
			_RPT4(_CRT_WARN, "%s(%u, %08X, %i, ...): tried to set hw breakpoint of invalid type\n",
				__FUNCTION__, nIndex, Address, Type);
			return FALSE;
	}
	AdjustSize(Size);
	if ((reinterpret_cast<DWORD>(Address) & Size - 1) != 0) {
		_RPT4(_CRT_WARN, "%s(%u, %08X, %i, ...): tried to set unaligned hw breakpoint with regard to size\n",
			__FUNCTION__, nIndex, Address, Type);
		return FALSE;
	}
	switch (Size) {
		case 1: SlotBits |= 0 << 2; break;
		case 2: SlotBits |= 1 << 2; break;
		case 4: SlotBits |= 3 << 2; break;
		case 8: SlotBits |= 2 << 2; break;
	}
	SetAddress(nIndex, Address);
	ClearControlSlot(nIndex);
	DR[5] |= (SlotBits & 0xF) << 0x10 + (nIndex << 2);
	if (LocalActive != FALSE) {
		SetActiveLocal(nIndex, TRUE);
		SetLE(); // eneble local trigger notification
	}
	if (GlobalActive != FALSE) {
		SetActiveGlobal(nIndex, TRUE);
		SetGE(); // eneble global trigger notification
	}
	return TRUE;
}

CDebugger::breakpoint_type_t CDebugger::CHwBptMgr::GetType(BYTE nIndex) const {
	if (dbgr == 0) return bpt_none;
	if (nIndex >= 4) {
		_RPT2(_CRT_WARN, "%s(%u): index out of range\n", __FUNCTION__, nIndex);
		return bpt_none;
	}
	if (IsUsed(nIndex)) switch (DR[5] >> 0x10 + (nIndex << 2) & 3) {
		case 0: return bpt_hw_exec;
		case 1: return bpt_hw_write;
		case 2: return bpt_hw_io_access;
		case 3: return bpt_hw_access;
	}
	return bpt_none;
}

BYTE CDebugger::CHwBptMgr::GetSize(BYTE nIndex) const throw() {
	if (dbgr == 0) return 0;
	if (nIndex >= 4) {
		_RPT2(_CRT_WARN, "%s(%u): index out of range\n", __FUNCTION__, nIndex);
		return 0;
	}
	if (IsUsed(nIndex)) switch (DR[5] >> 0x12 + (nIndex << 2) & 3) {
		case 0: return 1;
		case 1: return 2;
		case 2: return 8;
		case 3: return 4;
	}
	return 0;
}

BYTE CDebugger::CHwBptMgr::Find(LPCVOID Address, breakpoint_type_t Type, BYTE Size) const {
	if (dbgr != 0) {
		if (Size > 0) AdjustSize(Size);
		for (BYTE nIndex = 0; nIndex < 4; ++nIndex)
			if ((Address == NULL || Address == GetAddress(nIndex))
				&& (Type == bpt_any || Type == GetType(nIndex))
				&& (Size == 0 || Size == GetSize(nIndex))) return nIndex;
	}
	return static_cast<BYTE>(-1);
}

//  class CDebugger::heapmgr 

// returns: amount of allocated heap blocks
DWORD CDebugger::heapmgr::SnapshotNow() {
	if (!Debugger.bIsAttached) return 0;
	clear();
	DWORD dwResult(0);
	HANDLE h_snapshot;
	try {
#if TOOLHELPSNAPSHOT_TIMEOUT > 0
		HANDLE hKiller(Debugger->StartKiller(__FUNCTION__ "()"));
#endif
		h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST,
			Debugger.ProcessInfo.dwProcessId);
#if TOOLHELPSNAPSHOT_TIMEOUT > 0
		StopKiller(hKiller);
#endif
		if (h_snapshot == INVALID_HANDLE_VALUE) {
			_RPTF1(_CRT_ERROR, "%s(): h_snapshot == INVALID_HANDLE_VALUE\n", __FUNCTION__);
			return 0;
		}
		HEAPLIST32 heap_list;
		heap_list.dwSize = sizeof HEAPLIST32;
		for (BOOL heap_exists(Heap32ListFirst(h_snapshot, &heap_list));
			heap_exists != FALSE; heap_exists = Heap32ListNext(h_snapshot, &heap_list)) {
			HEAPENTRY32 heap_entry;
			heap_entry.dwSize = sizeof HEAPENTRY32;
			for (BOOL block_exists = Heap32First(&heap_entry,
				Debugger.ProcessInfo.dwProcessId, heap_list.th32HeapID);
				block_exists != FALSE; block_exists = Heap32Next(&heap_entry)) {
				if (heap_entry.dwFlags != LF32_FREE
					&& insert(memblock_t(reinterpret_cast<LPCVOID>(heap_entry.dwAddress),
					heap_entry.dwBlockSize)).second) ++dwResult;
				heap_entry.dwSize = sizeof HEAPENTRY32;
			}
			heap_list.dwSize = sizeof HEAPLIST32;
		}
		CloseHandle(h_snapshot);
	} catch (...) {
		CloseHandle(h_snapshot);
		_RPTF2(_CRT_ERROR, "%s(): exception for 0x%lX\n",
			__FUNCTION__, Debugger.ProcessInfo.dwProcessId);
	}
	return dwResult;
}

CDebugger::memblock_t CDebugger::heapmgr::find(LPCVOID address, BOOL exact) const {
	memblock_t memblock;
	if (Debugger.bIsAttached) {
		const const_iterator i(exact != FALSE ? __super::find(address) : std::find_if(begin(), end(),
			boost::bind2nd(boost::mem_fun_ref(memblock_t::has_address), address)));
		if (i != end()) try {
			memblock = *i;
			// test for VC++ heap debug header
			if (i->Size > sizeof _CrtMemBlockHeader + nNoMansLandSize * sizeof(unsigned char)) {
				boost::shared_ptr<void> buf(malloc(i->Size), free);
				if (!buf) throw std::bad_alloc();
				if (Debugger.ReadMemory(i->BaseAddress, buf.get(), i->Size) >= i->Size
					&& _BLOCK_TYPE_IS_VALID(static_cast<_CrtMemBlockHeader *>(buf.get())->nBlockUse)
					// lRequest may be 0 (IGNORE_REQ)
					&& static_cast<_CrtMemBlockHeader *>(buf.get())->nDataSize > 0
					&& i->Size >= sizeof _CrtMemBlockHeader +
						static_cast<_CrtMemBlockHeader *>(buf.get())->nDataSize + nNoMansLandSize * sizeof(unsigned char)
					&& ValidateFill(static_cast<_CrtMemBlockHeader *>(buf.get())->gap,
						sizeof(static_cast<_CrtMemBlockHeader *>(buf.get())->gap), _bNoMansLandFill)
					&& ValidateFill((LPBYTE)buf.get() + sizeof _CrtMemBlockHeader + static_cast<_CrtMemBlockHeader *>(buf.get())->nDataSize,
						nNoMansLandSize * sizeof(unsigned char), _bNoMansLandFill)) {
					memblock.BaseAddress = reinterpret_cast<_CrtMemBlockHeader *>(i->BaseAddress) + 1;
					memblock.Size = static_cast<_CrtMemBlockHeader *>(buf.get())->nDataSize;
					if (!memblock.has_address(address) // points to control area or freed block
						|| _BLOCK_TYPE(static_cast<_CrtMemBlockHeader *>(buf.get())->nBlockUse) == _FREE_BLOCK) {
						memblock.BaseAddress = NULL;
						memblock.Size = static_cast<SIZE_T>(-1L);
					}
#ifdef _DEBUG
					else if (ValidateFill(static_cast<_CrtMemBlockHeader *>(buf.get()) + 1, static_cast<_CrtMemBlockHeader *>(buf.get())->nDataSize, _bCleanLandFill))
						_RPT4(_CRT_WARN, "%s(%08X, ...): validated VC++ debug heap block <%08X-%08X> probably not initialized (_bCleanLandFill)\n",
							__FUNCTION__, address, memblock.BaseAddress, (LPBYTE)memblock.BaseAddress + memblock.Size);
#endif // _DEBUG
				}
			}
#ifdef _DEBUG
		} catch (const std::exception &e) {
			_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
				"%s(%08X, ...): %s on examining debug block structure at %08X(0x%lX)\n",
				__FUNCTION__, address, e.what(), memblock.BaseAddress, memblock.Size);
#endif // _DEBUG
		} catch (...) {
#ifdef _DEBUG
			_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
				"%s(%08X, ...): %s on examining debug block structure at %08X(0x%lX)\n",
				__FUNCTION__, address, "unknown exception", memblock.BaseAddress, memblock.Size);
#endif // _DEBUG
		}
	}
	return memblock;
}

//  struct CDebugger::module_t 

bool CDebugger::module_t::has_basename(LPCTSTR Name) const {
	_ASSERTE(Name != NULL);
	if (Name == NULL) return false;
	tchar fname[2][_MAX_FNAME];
	_tsplitpath(FileName, 0, 0, fname[0], 0);
	_tsplitpath(Name, 0, 0, fname[1], 0);
	return _tcsicmp(fname[0], fname[1]) == 0;
}

BOOL CDebugger::module_t::LineFromName(const CDebugger::DBGHELP_TCHAR *FileName,
	DWORD dwLineNumber, PLONG lpDisplacement, IMAGEHLP_LINE64 &Line) const {
	ZeroMemory(&Line, sizeof IMAGEHLP_LINE64);
	if (dbgr == 0 || dbgr->hDbgHelp == NULL || SymBase == 0) return FALSE;
	Line.SizeOfStruct = sizeof IMAGEHLP_LINE64;
	// todo: translate!
	SymGetLineFromName64_t pSymGetLineFromName64((SymGetLineFromName64_t)GetProcAddress(dbgr->hDbgHelp, "SymGetLineFromName64"));
	if (pSymGetLineFromName64 == NULL) return FALSE;
	BOOL ok(pSymGetLineFromName64(dbgr->ProcessInfo.hProcess,
		getBaseName()/*FileName*/, FileName, dwLineNumber, lpDisplacement, &Line));
	if (ok != FALSE) Line.Address -= SymOffset();
	return ok;
}

CDebugger::module_t::symbol_t::symbol_t(const SYMBOL_INFO &syminfo) : Index(syminfo.Index),
	Address(reinterpret_cast<LPCVOID>(syminfo.Address)), Name(syminfo.Name),
	Tag(syminfo.Tag), TypeIndex(syminfo.TypeIndex), Size(syminfo.Size), Flags(syminfo.Flags) {
	if (syminfo.Address == 0)
		std::__stl_throw_invalid_argument("address must be valid");
	if (syminfo.Index == 0)
		std::__stl_throw_invalid_argument("index must be valid number");
	if (syminfo.Name[0] == 0)
		std::__stl_throw_invalid_argument("name must be valid non-empty string");
}

CDebugger::module_t::line_t::line_t(const SRCCODEINFO &srcinfo) :
	FileName(srcinfo.FileName), Address(reinterpret_cast<LPCVOID>(srcinfo.Address)),
	LineNumber(srcinfo.LineNumber), Obj(srcinfo.Obj) {
	_ASSERTE(srcinfo.FileName[0] != 0);
	_ASSERTE(strlen(srcinfo.FileName) < sizeof FileName);
	if (srcinfo.Address == 0)
		std::__stl_throw_invalid_argument("address must be valid");
	if (srcinfo.LineNumber == 0)
		std::__stl_throw_invalid_argument("line number must be valid (>0)");
	if (srcinfo.FileName[0] == 0 || strlen(srcinfo.FileName) >= sizeof FileName)
		std::__stl_throw_invalid_argument("filename must be valid non-empty string");
}

LPSTR CDebugger::module_t::section_t::getName(LPSTR Name/*, SIZE_T NameSize*/) const {
	_ASSERTE(Name != NULL);
	if (Name != NULL) {
		strncpy(Name, reinterpret_cast<LPCSTR>(header.Name), ARRAY_SIZE(header.Name));
		Name[sizeof header.Name] = 0;
		for (int i = ARRAY_SIZE(header.Name) - 1; i >= 0 && Name[i] == ' '; --i)
			Name[i] = 0;
	}
	return Name;
}

//  class CDebugger::modules_t 

void CDebugger::modules_t::track_breakpoint(LPCVOID Address) {
	const iterator module(find(Address, FALSE));
	if (module != end()) {
		_ASSERTE(module->has_address(Address));
		deconst_it(module).breakpoint_RVAs.insert(module->VA2RVA(Address));
	}
#ifdef _DEBUG
	else
		_RPT2(_CRT_WARN, "%s(%08X): breakpoint set outside all mapped modules (no unload tracks kept)\n",
			__FUNCTION__, Address);
#endif // _DEBUG
}

CDebugger::module_t::exports_t::const_iterator
CDebugger::modules_t::find_export(LPCSTR lpName) const { // seek through all modules, return 1-st match
	_ASSERTE(lpName != NULL && *lpName != 0);
	if (lpName != NULL && *lpName != 0)
		for (const_iterator module = begin(); module != end(); ++module) {
			const module_t::exports_t::const_iterator export(module->exports[lpName]);
			if (export != module->exports.end()) return export;
		}
	return noexport;
}

CDebugger::module_t::exports_t::const_iterator
CDebugger::modules_t::find_export(LPCVOID address) const {
	const const_iterator module(find(address, FALSE));
	if (module != end()) {
		const module_t::exports_t::const_iterator export(module->exports[address]);
		if (export != module->exports.end()) return export;
	}
	return noexport;
}

CDebugger::module_t::symbols_t::const_iterator
CDebugger::modules_t::find_symbol(const CDebugger::DBGHELP_TCHAR *Name) const {
	_ASSERTE(Name != NULL && *Name != 0);
	if (Name != NULL && *Name != 0)
		for (const_iterator module = begin(); module != end(); ++module) {
			const module_t::symbols_t::const_iterator symbol(module->symbols[Name]);
			if (symbol != module->symbols.end()) return symbol;
		}
	return nosymbol;
}

CDebugger::module_t::symbols_t::const_iterator
CDebugger::modules_t::find_symbol(LPCVOID address) const {
	const const_iterator module(find(address, FALSE));
	if (module != end()) {
		const module_t::symbols_t::const_iterator symbol(module->symbols[address]);
		if (symbol != module->symbols.end()) return symbol;
	}
	return nosymbol;
}

CDebugger::module_t::lines_t::const_iterator
CDebugger::modules_t::find_line(LPCVOID address) const {
	const const_iterator module(find(address, FALSE));
	if (module != end()) {
		module_t::lines_t::const_iterator line(module->lines[address]);
		if (line != module->lines.end()) return line;
	}
	return noline;
}

CDebugger::module_t::lines_t::const_iterator
CDebugger::modules_t::find_line(const CDebugger::DBGHELP_TCHAR *FileName, DWORD LineNumber) const {
	_ASSERTE(FileName != NULL && *FileName != 0);
	_ASSERTE(LineNumber != 0);
	if (FileName != NULL && *FileName != 0 && LineNumber != 0)
		for (const_iterator module = begin(); module != end(); ++module) {
			const module_t::lines_t::const_iterator
				line(module->lines.find(FileName, LineNumber));
			if (line != module->lines.end()) return line;
		}
	return noline;
}

typedef BOOL (WINAPI *SymUnloadModule64_t)(IN HANDLE hProcess, IN DWORD64 BaseOfDll);
void CDebugger::modules_t::erase(const iterator &it) {
	_ASSERTE(it != end());
	if (it == end()) return;
	if (it->SymBase != 0 && it->dbgr != 0 && it->dbgr->hDbgHelp != NULL) {
		SymUnloadModule64_t pSymUnloadModule64((SymUnloadModule64_t)GetProcAddress(it->dbgr->hDbgHelp, "SymUnloadModule64"));
		if (pSymUnloadModule64 != NULL)
			pSymUnloadModule64(it->dbgr->ProcessInfo.hProcess, it->SymBase);
	}
	__super::erase(it);
}

//  struct CDebugger::thread_t 

DWORD CDebugger::thread_t::GetData(DWORD dwOffset) const {
	if (hProcess == NULL || info.lpThreadLocalBase == NULL) return 0;
	DWORD dwResult, dwValue;
	return ::ReadProcessMemory(hProcess, (LPBYTE)info.lpThreadLocalBase + dwOffset,
		&dwValue, sizeof dwValue, &dwResult) && dwResult >= sizeof dwValue ? dwValue : 0;
}

BOOL CDebugger::thread_t::SetData(DWORD dwOffset, DWORD dwValue) const {
	if (hProcess == NULL || info.lpThreadLocalBase == NULL) return FALSE;
	DWORD dwResult;
	return ::WriteProcessMemory(hProcess, (LPBYTE)info.lpThreadLocalBase + dwOffset,
		&dwValue, sizeof dwValue, &dwResult) && dwResult >= sizeof dwValue ? TRUE : FALSE;
}

bool CDebugger::thread_t::IsSuspended() const {
	return false; // todo: jak zjistím stav threadu?
}

DWORD CDebugger::thread_t::Suspend() const {
	//if (IsSuspended()) return TRUE;
	CThreadHandle hThread(THREAD_SUSPEND_RESUME, dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_SUSPEND_RESUME");
		return static_cast<DWORD>(-1);
	}
	return ::SuspendThread(hThread);
}

DWORD CDebugger::thread_t::Resume() const {
	//if (!IsSuspended()) return TRUE;
	CThreadHandle hThread(THREAD_SUSPEND_RESUME, dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_SUSPEND_RESUME");
		return static_cast<DWORD>(-1);
	}
	return ::ResumeThread(hThread);
}

LPVOID CDebugger::thread_t::GetIP() const {
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_CONTROL;
	return GetContext(Context, TRUE) ? reinterpret_cast<LPVOID>(Context.Eip) : NULL;
}

BOOL CDebugger::thread_t::SetIP(LPCVOID IP) const {
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_CONTROL;
	if (!GetContext(Context, TRUE)) return FALSE;
	Context.Eip = reinterpret_cast<DWORD>(IP);
	return SetContext(Context);
}

BOOL CDebugger::thread_t::GetContext(CONTEXT &Context, BOOL bUseFlags) const {
	if (!bUseFlags) Context.ContextFlags = ~0L; // get everything
	CThreadHandle hThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_SUSPEND_RESUME");
		return FALSE;
	}
	Suspend(); // pause debuggee if not stopped by debug event
	BOOL result = ::GetThreadContext(hThread, &Context);
	Resume();
	return result;
}

BOOL CDebugger::thread_t::SetContext(const CONTEXT &Context) const {
	CThreadHandle hThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_SUSPEND_RESUME");
		return FALSE;
	}
	Suspend(); // pause debuggee if not stopped by debug event
	BOOL result = ::SetThreadContext(hThread, &Context);
	Resume();
	return result;
}

BOOL CDebugger::thread_t::Terminate(DWORD dwExitCode) const {
	CThreadHandle hThread(THREAD_TERMINATE, dwThreadId);
	if (!hThread) {
		_RPT3(_CRT_WARN, "%s(%li): failed to open thread for %s\n",
			__FUNCTION__, dwExitCode, "THREAD_TERMINATE");
		return FALSE;
	}
	return ::TerminateThread(hThread, dwExitCode);
}

BOOL CDebugger::thread_t::GetExitCode(LPDWORD lpExitCode) const {
	CThreadHandle hThread(THREAD_QUERY_INFORMATION, dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return ::GetExitCodeThread(hThread, lpExitCode);
}

int CDebugger::thread_t::GetPriority() const {
	CThreadHandle hThread(THREAD_QUERY_INFORMATION, dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return ::GetThreadPriority(hThread);
}

BOOL CDebugger::thread_t::SetPriority(int nPriority) const {
	CThreadHandle hThread(THREAD_SET_INFORMATION, dwThreadId);
	if (!hThread) {
		_RPT3(_CRT_WARN, "%s(%i): failed to open thread for %s\n",
			__FUNCTION__, nPriority, "THREAD_SET_INFORMATION");
		return FALSE;
	}
	return ::SetThreadPriority(hThread, nPriority);
}

BOOL CDebugger::thread_t::GetPriorityBoost(PBOOL pDisablePriorityBoost) const {
	CThreadHandle hThread(THREAD_QUERY_INFORMATION, dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return ::GetThreadPriorityBoost(hThread, pDisablePriorityBoost);
}

BOOL CDebugger::thread_t::SetPriorityBoost(BOOL DisablePriorityBoost) const {
	CThreadHandle hThread(THREAD_SET_INFORMATION, dwThreadId);
	if (!hThread) {
		_RPT3(_CRT_WARN, "%s(%i): failed to open thread for %s\n",
			__FUNCTION__, DisablePriorityBoost, "THREAD_SET_INFORMATION");
		return FALSE;
	}
	return ::SetThreadPriorityBoost(hThread, DisablePriorityBoost);
}

DWORD CDebugger::thread_t::SetIdealProcessor(DWORD dwIdealProcessor) const {
	CThreadHandle hThread(THREAD_SET_INFORMATION, dwThreadId);
	if (!hThread) {
		_RPT3(_CRT_WARN, "%s(0x%lX): failed to open thread for %s\n",
			__FUNCTION__, dwIdealProcessor, "THREAD_SET_INFORMATION");
		return FALSE;
	}
	return ::SetThreadIdealProcessor(hThread, dwIdealProcessor);
}

DWORD_PTR CDebugger::thread_t::SetAffinityMask(DWORD_PTR dwThreadAffinityMask) const {
	CThreadHandle hThread(THREAD_SET_INFORMATION, dwThreadId);
	if (!hThread) {
		_RPT3(_CRT_WARN, "%s(0x%IX): failed to open thread for %s\n",
			__FUNCTION__, dwThreadAffinityMask, "THREAD_SET_INFORMATION");
		return FALSE;
	}
	return ::SetThreadAffinityMask(hThread, dwThreadAffinityMask);
}

BOOL CDebugger::thread_t::GetTimes(LPFILETIME lpCreationTime, LPFILETIME lpExitTime,
	LPFILETIME lpKernelTime, LPFILETIME lpUserTime) const {
	CThreadHandle hThread(THREAD_QUERY_INFORMATION, dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return ::GetThreadTimes(hThread, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime);
}

BOOL CDebugger::thread_t::GetIOPendingFlag(PBOOL lpIOIsPending) const {
	CThreadHandle hThread(THREAD_QUERY_INFORMATION, dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return ::GetThreadIOPendingFlag(hThread, lpIOIsPending);
}

BOOL CDebugger::thread_t::GetStartInformation(LPVOID* lpStartAddress, LPVOID* lpStartParameter) const {
	const GetThreadStartInformation_p
		GetThreadStartInformation((GetThreadStartInformation_p)GetProcAddress(::GetModuleHandle("kernel32.dll"),
			"GetThreadStartInformation"));
	if (GetThreadStartInformation == NULL) return FALSE;
	CThreadHandle hThread(THREAD_QUERY_INFORMATION, dwThreadId);
	if (!hThread) {
		_RPT2(_CRT_WARN, "%s(...): failed to open thread for %s\n",
			__FUNCTION__, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return GetThreadStartInformation(hThread, lpStartAddress, lpStartParameter);
}

BOOL CDebugger::thread_t::GetSelectorEntry(DWORD dwSelector, LDT_ENTRY &SelectorEntry) const {
	CThreadHandle hThread(THREAD_QUERY_INFORMATION, dwThreadId);
	if (!hThread) {
		_RPT3(_CRT_WARN, "%s(0x%lX, ...): failed to open thread for %s\n",
			__FUNCTION__, dwSelector, "THREAD_QUERY_INFORMATION");
		return FALSE;
	}
	return ::GetThreadSelectorEntry(hThread, dwSelector, &SelectorEntry);
}
