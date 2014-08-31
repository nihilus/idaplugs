
/*****************************************************************************
 *                                                                           *
 * debugger.hpp: definition of basic software debugger class                 *
 * revision 11                                                               *
 * (c) 2005-2008 servil                                                      *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#ifndef _WIN32
#error Only Windows 32-bit supported.
#endif

#ifndef _DEBUGGER_HPP_20080831_
#define _DEBUGGER_HPP_20080831_ 1

#if !defined(__ICL)
#pragma warning(disable: 4503) // decorated name length exceeded, name was truncated
#endif

#include "undbgnew.h"

#include <cstdlib>
#include <cstdio>
#include <malloc.h>
#include <tchar.h>
#include "mscrtdbg.h"
#include <string>
#include <set>
#include <hash_set>
#include <map>
#include <hash_map>
#include <stdexcept>
#include <algorithm>
#include <numeric>
#include <boost/functional.hpp>
#include <boost/functional/hash.hpp>
#include <boost/bind.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/noncopyable.hpp>

#define NOMINMAX 1
#include <windows.h>
//#include <winternl.h>
//#include <ntddk.h>
#include <Psapi.h>
#include <TlHelp32.h>
#define __in_bcount_opt(x)
#define __out_bcount_opt(x)
#include <DbgHelp.h>
#include "fixdcstr.hpp"

#include "dbgnew.h"

#pragma comment(lib, "psapi.lib")

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define multi_index_container boost::multi_index_container
#define BOOST_MNDX(n)         boost::multi_index::n
#define indexed_by            BOOST_MNDX(indexed_by)
#define ordered_unique        BOOST_MNDX(ordered_unique)
#define ordered_non_unique    BOOST_MNDX(ordered_non_unique)
#define hashed_unique         BOOST_MNDX(hashed_unique)
#define hashed_non_unique     BOOST_MNDX(hashed_non_unique)
#define composite_key         BOOST_MNDX(composite_key)
#define composite_key_compare BOOST_MNDX(composite_key_compare)
#define identity              BOOST_MNDX(identity)
#define member_offset         BOOST_MNDX(member_offset)

#define CNTNR_FIND_FRONTEND(Type, Index) \
	const_iterator find(Type __arg) const \
		{ return project<0>(get<Index>().find(__arg)); }

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LONG NTSTATUS;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
} THREADINFOCLASS;

class CDebugger : private boost::noncopyable {
protected:
	typedef TCHAR tchar;
#	ifndef DBGHELP_TRANSLATE_TCHAR
	typedef CHAR DBGHELP_TCHAR;
#	else
	typedef WCHAR DBGHELP_TCHAR;
#	endif // DBGHELP_TRANSLATE_TCHAR
	typedef std::basic_string<tchar> tstring;
	typedef std::basic_string<DBGHELP_TCHAR> dbgstring;
	typedef fixed_cstr_adaptor<MAX_PATH, tchar> fixed_tpath_t;
	typedef fixed_cstr_adaptor<MAX_PATH, DBGHELP_TCHAR> fixed_dbgpath_t;

public:
	CDebugger(BOOL bQuiet/*don't print events to stderr*/ = FALSE,
		BOOL bIgnoreExternalExceptions = FALSE, BOOL bUseDbgHelp = TRUE);
	~CDebugger();

	// front-end
	DWORD DebugProcess(LPCSTR lpAppPath, LPCSTR lpCommandLine = NULL, BOOL bOnlyThis = TRUE);
	DWORD DebugActiveProcess(DWORD dwProcessId);
	DWORD DebugActiveProcess(LPCSTR lpModuleName);

private:
	DWORD dwExitCode, dwIdleTimer;
	LPVOID lpProcessLocalBase;
	bool bIsAttached;
	mutable bool bDetachScheduled;
	static const BYTE __x86_int3 = 0xCC;
	HMODULE hNtDll, hDbgHelp;

	// low level && internal
	void Reset();
	DWORD Dispatcher();
	BYTE PlaceSwBreakpoint(LPVOID) const;
	void WipeSwBreakpoint(LPVOID, BYTE) const;
	bool SingleStepActive() const;
	bool FindModuleEntry(MODULEENTRY32 &Module32Info, HMODULE hModule,
		DWORD dwProcessId = 0) const;
	bool ReadDosHdr(HMODULE hModule, IMAGE_DOS_HEADER &DosHdr);
	LONG ReadPeHdr(HMODULE hModule, IMAGE_NT_HEADERS &PeHdr); // returns offset of pe header to imagebase or zero if invalid module handle
	static bool FileExist(LPCTSTR FilePath);
	static bool GetThreadDataSelector(HANDLE hThread, LDT_ENTRY &SelectorEntry);
	NTSTATUS NtQueryInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG) const;
	void AskDebugInfo(std::string &, LPCVOID) const;
	void ShoutMsg(const char *msg) const;
	// ToolHelpSnapshot protection ;-)
	static DWORD WINAPI ToolHelpKiller(LPCVOID lpDebugger); // ThreadProc
	HANDLE StartKiller(LPCSTR FuncName = NULL) const;
	static void StopKiller(HANDLE hKiller);

protected:
	struct module_t;
	// don't change anything of these in overloads
	// very strictly read-only, changes make debugger crash
	PROCESS_INFORMATION ProcessInfo;
	// The handle to the process has PROCESS_VM_READ and PROCESS_VM_WRITE access
	// System closes this handle after EXIT_PROCESS_DEBUG_EVENT
	HANDLE hProcess;
	// The handle to the process's initial thread has THREAD_GET_CONTEXT,
	// THREAD_SET_CONTEXT, and THREAD_SUSPEND_RESUME access to the thread
	// System closes this handle after EXIT_PROCESS_DEBUG_EVENT
	HANDLE hMainThread;
	LPVOID lpBaseOfImage;
	IMAGE_DOS_HEADER DosHdr;
	IMAGE_NT_HEADERS PeHdr;
	DEBUG_EVENT DebugEvent;
	fixed_tpath_t DebuggeeFilePath;
public:
	mutable BOOL bQuiet, bIgnoreExternalExceptions, bUseDbgHelp;

protected:
	struct memblock_t {
		LPVOID BaseAddress;
		SIZE_T Size;

		inline memblock_t(LPCVOID BaseAddress = NULL, SIZE_T Size = static_cast<SIZE_T>(-1)) throw() :
			BaseAddress(const_cast<LPVOID>(BaseAddress)), Size(Size) { }
		inline memblock_t(LPCVOID BaseAddress, LPCVOID EndAddress) throw() :
			BaseAddress(const_cast<LPVOID>(BaseAddress)),
			Size((LPBYTE)EndAddress - (LPBYTE)BaseAddress) { }

		inline operator LPVOID() const throw()
			{ return BaseAddress; }
		inline operator bool() const throw()
			{ return BaseAddress != NULL && Size != static_cast<SIZE_T>(-1); }
		// VC<=6 workaround
		inline bool operator <(const memblock_t &rhs) const throw()
			{ return operator LPVOID() < rhs.operator LPVOID(); }
		inline bool operator ==(const memblock_t &rhs) const throw()
			{ return operator LPVOID() == rhs.operator LPVOID(); }

		inline bool start_at(LPCVOID Address) const throw()
			{ return BaseAddress == Address; }
		inline bool has_address(LPCVOID Address) const throw() {
			return Address >= BaseAddress
				&& (LPBYTE)Address < (LPBYTE)BaseAddress + Size;
		}
		inline LPCVOID EndAddress() const throw()
			{ return operator bool() ? (LPBYTE)BaseAddress + Size : NULL; }
		inline SIZE_T plus(SIZE_T accumulated) const throw()
			{ return accumulated + Size; }

		struct hash {
			inline size_t operator ()(const memblock_t &__x) const throw()
				{ return reinterpret_cast<size_t>(__x.operator LPVOID()); }
		};
		friend static inline std::size_t hash_value(const memblock_t &__x)
			{ return boost::hash_value(__x.operator LPVOID()); }
	}; // memblock_t

	class heapmgr : public std::hash_set<memblock_t, memblock_t::hash/*boost::hash<memblock_t>*/> {
	private:
		const CDebugger &Debugger;

	public:
		heapmgr(const CDebugger &Debugger) : Debugger(Debugger) { SnapshotNow(); }

		inline memblock_t operator [](LPCVOID address) const
			{ return find(address); };

		DWORD SnapshotNow();
		memblock_t find(LPCVOID address, BOOL exact = FALSE) const;
		SIZE_T accumulate() const {
			return std::accumulate(begin(), end(), 0,
				boost::bind(&memblock_t::plus, boost::arg<2>(), boost::arg<1>()));
		}
	}; // heapmgr
	heapmgr *NewHeapMgr() const throw(std::bad_alloc) {
		heapmgr *newmgr(new heapmgr(*this));
		if (newmgr == 0) throw std::bad_alloc();
		return newmgr;
	}

	// convenience functions
	LPVOID GetIP() const;
	BOOL SetIP(LPCVOID IP) const;
	BOOL SingleStep() const;
	BOOL IsAddressEnabled(LPCVOID lpAddress) const {
		MEMORY_BASIC_INFORMATION MemInfo;
		return bIsAttached && VirtualQuery(lpAddress, MemInfo) >= sizeof MEMORY_BASIC_INFORMATION
			&& MemInfo.State == MEM_COMMIT ? TRUE : FALSE;
	}
	inline DWORD GetAppStatus() const
		{ return dwExitCode; }
	SIZE_T FindHeapBlock(LPCVOID lpAddress, BOOL bExactMatch = TRUE,
		LPCVOID *lpBaseAddress = NULL) const;
	inline HMODULE hModule() const
		{ return reinterpret_cast<HMODULE>(lpBaseOfImage); }
	inline HINSTANCE hInstance() const
		{ return reinterpret_cast<HINSTANCE>(lpBaseOfImage); }
	LPVOID getEntryPoint() const throw() {
		return PeHdr.OptionalHeader.AddressOfEntryPoint != 0 ?
			(LPBYTE)hModule() + PeHdr.OptionalHeader.AddressOfEntryPoint : NULL;
	}
	inline LPVOID getProcessLocalBase() const throw() { return lpProcessLocalBase; }
	inline LPCTSTR getDebuggeeBaseName() const
		{ return getBaseName(DebuggeeFilePath); }
	inline HMODULE DbgHelp() const throw()
		{ return bUseDbgHelp != FALSE ? hDbgHelp : NULL; }

	// WinApi frontends
	// process specific
	inline HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle = FALSE) const {
		return !bIsAttached ? NULL :
			::OpenProcess(dwDesiredAccess, bInheritHandle, ProcessInfo.dwProcessId);
	}
	inline DWORD GetModuleFileName(HMODULE hModule, LPTSTR lpFilename, DWORD nSize) const {
		return bIsAttached ? ::GetModuleFileNameEx(ProcessInfo.hProcess,
			hModule, lpFilename, nSize) : 0;
	}
	inline DWORD GetModuleBaseName(HMODULE hModule, LPTSTR lpBaseName, DWORD nSize) const {
		return bIsAttached ? ::GetModuleBaseName(ProcessInfo.hProcess,
			hModule, lpBaseName, nSize) : 0;
	}
	inline BOOL GetModuleInformation(HMODULE hModule, MODULEINFO &ModInfo) const {
		return bIsAttached && ::GetModuleInformation(ProcessInfo.hProcess,
			hModule, &ModInfo, sizeof MODULEINFO) != FALSE ? TRUE : FALSE;
	}
private:
	SIZE_T ReadProcessMemory(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize = 1) const;
	SIZE_T WriteProcessMemory(LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize = 1) const;
protected:
	// to access or write debuggee memory, don't use kernel's
	// Read/WriteProcessMemory but rather use these frontends to protect
	// software breakpoints set by CDebugger API
	// if read block contains user set breakpoints, original bytes are
	// correctly restored to read buffer
	SIZE_T ReadMemory(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize = 1) const;
	SIZE_T WriteMemory(LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize = 1) const;
	inline BOOL FlushInstructionCache(LPCVOID lpBaseAddress = NULL, SIZE_T dwSize = NULL) const {
		return bIsAttached && ::FlushInstructionCache(ProcessInfo.hProcess,
			lpBaseAddress, dwSize) != FALSE ? TRUE : FALSE;
	}
	inline LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize,
		DWORD flAllocationType, DWORD flProtect) const {
		return bIsAttached ? ::VirtualAllocEx(ProcessInfo.hProcess, lpAddress,
			dwSize, flAllocationType, flProtect) : 0;
	}
	inline BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) const {
		return bIsAttached && ::VirtualFreeEx(ProcessInfo.hProcess, lpAddress,
			dwSize, dwFreeType) != FALSE ? TRUE : FALSE;
	}
	inline BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize,
		DWORD flNewProtect, PDWORD lpflOldProtect = NULL) const {
		DWORD discard;
		return bIsAttached && ::VirtualProtectEx(ProcessInfo.hProcess, lpAddress,
			dwSize, flNewProtect, lpflOldProtect != NULL ? lpflOldProtect : &discard) != FALSE ? TRUE : FALSE;
	}
	inline SIZE_T VirtualQuery(LPCVOID lpAddress, MEMORY_BASIC_INFORMATION &lpBuffer) const {
		return bIsAttached ? ::VirtualQueryEx(ProcessInfo.hProcess, lpAddress,
			&lpBuffer, sizeof MEMORY_BASIC_INFORMATION) : 0;
	}
	inline BOOL TerminateProcess(UINT uExitCode = 0) const {
		return bIsAttached && ::TerminateProcess(ProcessInfo.hProcess, uExitCode) != FALSE ? TRUE : FALSE;
	}
	inline BOOL GetProcessMemoryInfo(PPROCESS_MEMORY_COUNTERS ppsmemCounters, DWORD cb) const {
		return bIsAttached && ::GetProcessMemoryInfo(ProcessInfo.hProcess,
			ppsmemCounters, cb) != FALSE ? TRUE : FALSE;
	}
	inline BOOL QueryWorkingSet(PVOID pv, DWORD cb) const {
		return bIsAttached && ::QueryWorkingSet(ProcessInfo.hProcess, pv, cb) != FALSE ? TRUE : FALSE;
	}
	inline BOOL EmptyWorkingSet() const {
		return bIsAttached && ::EmptyWorkingSet(ProcessInfo.hProcess) != FALSE ? TRUE : FALSE;
	}
	inline BOOL SetProcessWorkingSetSize(SIZE_T dwMinimumWorkingSetSize,
		SIZE_T dwMaximumWorkingSetSize) const {
		return bIsAttached && ::SetProcessWorkingSetSize(ProcessInfo.hProcess,
			dwMinimumWorkingSetSize, dwMaximumWorkingSetSize) != FALSE ? TRUE : FALSE;
	}
	inline BOOL GetProcessWorkingSetSize(PSIZE_T lpMinimumWorkingSetSize,
		PSIZE_T lpMaximumWorkingSetSize) const {
		return bIsAttached && ::GetProcessWorkingSetSize(ProcessInfo.hProcess,
			lpMinimumWorkingSetSize, lpMaximumWorkingSetSize) != FALSE ? TRUE : FALSE;
	}
	BOOL SetProcessWorkingSetSizeEx(SIZE_T dwMinimumWorkingSetSize,
		SIZE_T dwMaximumWorkingSetSize, DWORD Flags) const;
	BOOL GetProcessWorkingSetSizeEx(PSIZE_T lpMinimumWorkingSetSize,
		PSIZE_T lpMaximumWorkingSetSize, LPDWORD Flags) const;
	inline BOOL GetProcessIoCounters(PIO_COUNTERS lpIoCounters) const {
		return bIsAttached && ::GetProcessIoCounters(ProcessInfo.hProcess, lpIoCounters) != FALSE ? TRUE : FALSE;
	}
	inline BOOL SetPriorityClass(DWORD dwPriorityClass) const {
		return bIsAttached && ::SetPriorityClass(ProcessInfo.hProcess,
			dwPriorityClass) != FALSE ? TRUE : FALSE;
	}
	inline DWORD GetPriorityClass() const
		{ return bIsAttached ? ::GetPriorityClass(ProcessInfo.hProcess) : 0; }
	inline BOOL SetProcessPriorityBoost(BOOL DisablePriorityBoost) const {
		return bIsAttached && ::SetProcessPriorityBoost(ProcessInfo.hProcess,
			DisablePriorityBoost) != FALSE ? TRUE : FALSE;
	}
	inline BOOL GetProcessPriorityBoost(PBOOL pDisablePriorityBoost) const {
		return bIsAttached && ::GetProcessPriorityBoost(ProcessInfo.hProcess,
			pDisablePriorityBoost) != FALSE ? TRUE : FALSE;
	}
	inline BOOL GetProcessTimes(LPFILETIME lpCreationTime, LPFILETIME lpExitTime,
		LPFILETIME lpKernelTime, LPFILETIME lpUserTime) const {
		return bIsAttached && ::GetProcessTimes(ProcessInfo.hProcess,
			lpCreationTime, lpExitTime, lpKernelTime, lpUserTime) != FALSE ? TRUE : FALSE;
	}
	inline DWORD GetProcessVersion(DWORD ProcessId = 0) const {
		return bIsAttached ? ::GetProcessVersion(ProcessId != 0 ? ProcessId : ProcessInfo.dwProcessId) : 0;
	}
	inline BOOL SetProcessAffinityMask(DWORD_PTR dwProcessAffinityMask) const {
		return bIsAttached && ::SetProcessAffinityMask(ProcessInfo.hProcess, dwProcessAffinityMask) != FALSE ? TRUE : FALSE;
	}
	inline BOOL GetProcessAffinityMask(PDWORD_PTR lpProcessAffinityMask,
		PDWORD_PTR lpSystemAffinityMask) const {
		return bIsAttached && ::GetProcessAffinityMask(ProcessInfo.hProcess,
			lpProcessAffinityMask, lpSystemAffinityMask) != FALSE ? TRUE : FALSE;
	}
	inline DWORD GetGuiResources(DWORD uiFlags) const {
		return bIsAttached ? ::GetGuiResources(ProcessInfo.hProcess, uiFlags) : FALSE;
	}
	inline DWORD WaitForInputIdle(DWORD dwMilliseconds) const {
		return bIsAttached ? ::WaitForInputIdle(ProcessInfo.hProcess, dwMilliseconds) : FALSE;
	}
	inline void Detach() const { if (bIsAttached) bDetachScheduled = true; }
	inline BOOL Terminate(UINT uExitCode = 0) const
		{ return TerminateProcess(uExitCode); }
	inline BOOL GetExitCode(LPDWORD lpExitCode) const {
		return bIsAttached &&
			::GetExitCodeProcess(ProcessInfo.hProcess, lpExitCode) != FALSE ? TRUE : FALSE;
	}
	DWORD GetProcessData(DWORD dwOffset) const {
		DWORD dwValue;
		return bIsAttached && lpProcessLocalBase != NULL
			&& ReadMemory((LPBYTE)lpProcessLocalBase + dwOffset,
			&dwValue, sizeof dwValue) >= sizeof dwValue ? dwValue : 0;
	}
	BOOL SetProcessData(DWORD dwOffset, DWORD dwValue) const {
		return bIsAttached && lpProcessLocalBase != NULL
			&& WriteMemory((LPBYTE)lpProcessLocalBase + dwOffset,
			&dwValue, sizeof dwValue) >= sizeof dwValue ? TRUE : FALSE;
	}
	BOOL DebugBreakProcess() const;
	// hides debugger from reporting by IsDebuggerPresent()
	BOOL HideDebugger(BOOL Hide = TRUE) const {
		return bIsAttached && lpProcessLocalBase != NULL
			&& WriteMemory((LPBYTE)lpProcessLocalBase + 2,
				&(Hide = Hide != 0 ? 0 : 1), 1) >= 1 ? TRUE : FALSE;
	}
	inline BOOL UnhideDebugger() const
		{ return HideDebugger(FALSE); };
private:
	LPVOID GetProcessLocalBase(DWORD dwThreadId = 0) const;
protected:
	inline DWORD GetModuleHandle() const
		{ return GetProcessData(0x08); }
	inline DWORD GetProcessHeap() const
		{ return GetProcessData(0x18); }

	// thread specific
	BOOL GetThreadContext(CONTEXT &Context, BOOL bUseFlags = FALSE/*get everything*/,
		DWORD dwThreadId = 0) const;
	BOOL SetThreadContext(const CONTEXT &Context, DWORD dwThreadId = 0) const;
	BOOL TerminateThread(DWORD dwExitCode = 0, DWORD dwThreadId = 0) const;
	BOOL GetExitCodeThread(LPDWORD lpExitCode, DWORD dwThreadId = 0) const;
	DWORD SuspendThread(DWORD dwThreadId = 0) const;
	DWORD ResumeThread(DWORD dwThreadId = 0) const;
	BOOL SetThreadPriorityBoost(BOOL DisablePriorityBoost, DWORD dwThreadId = 0) const;
	BOOL SetThreadPriority(int nPriority, DWORD dwThreadId = 0) const;
	DWORD SetThreadIdealProcessor(DWORD dwIdealProcessor, DWORD dwThreadId = 0) const;
	DWORD_PTR SetThreadAffinityMask(DWORD_PTR dwThreadAffinityMask, DWORD dwThreadId = 0) const;
	BOOL GetThreadTimes(LPFILETIME lpCreationTime, LPFILETIME lpExitTime,
		LPFILETIME lpKernelTime, LPFILETIME lpUserTime, DWORD dwThreadId = 0) const;
	BOOL GetThreadIOPendingFlag(PBOOL lpIOIsPending, DWORD dwThreadId = 0) const;
	BOOL GetThreadStartInformation(LPVOID* lpStartAddress,
		LPVOID* lpStartParameter, DWORD dwThreadId = 0) const;
	int GetThreadPriority(DWORD dwThreadId = 0) const;
	BOOL GetThreadPriorityBoost(PBOOL pDisablePriorityBoost, DWORD dwThreadId = 0) const;
	BOOL GetThreadSelectorEntry(DWORD dwSelector, LDT_ENTRY &SelectorEntry, DWORD dwThreadId = 0) const;
	DWORD GetProcessIdOfThread(DWORD dwThreadId = 0) const;
	DWORD GetThreadId(HANDLE Thread) const;
	DWORD GetProcessIdOfThread(HANDLE Thread) const;

	// convenience helpers for thread local storage
	DWORD GetThreadData(DWORD dwOffset, DWORD dwThreadId = 0) const;
	DWORD GetThreadData(HANDLE hThread, DWORD dwOffset) const;
	BOOL SetThreadData(DWORD dwOffset, DWORD dwValue, DWORD dwThreadId = 0) const;
	BOOL SetThreadData(HANDLE hThread, DWORD dwOffset, DWORD dwValue) const;

#	define GET_THREAD_DATA_ALIAS(Name, Type, Offset) \
	inline Type Get##Name(DWORD dwThreadId = 0) const \
		{ return (Type)GetThreadData(static_cast<DWORD>(Offset), dwThreadId); }
	GET_THREAD_DATA_ALIAS(ThreadSehChain, LPVOID, 0x00)
	GET_THREAD_DATA_ALIAS(ThreadStackTop, LPVOID, 0x04)
	GET_THREAD_DATA_ALIAS(ThreadStackBottom, LPVOID, 0x08)
	inline SIZE_T GetThreadStackSize(DWORD dwThreadId = 0) const {
		return (LPBYTE)GetThreadStackTop(dwThreadId) -
			(LPBYTE)GetThreadStackBottom(dwThreadId);
	}
	GET_THREAD_DATA_ALIAS(ThreadLocalBase, LPVOID, 0x18)
	GET_THREAD_DATA_ALIAS(ProcessId, DWORD, 0x20)
	GET_THREAD_DATA_ALIAS(ThreadId, DWORD, 0x24)
	GET_THREAD_DATA_ALIAS(ThreadLocalStorage, LPVOID, 0x2C)
	GET_THREAD_DATA_ALIAS(ThreadLastError, DWORD, 0x34)
	GET_THREAD_DATA_ALIAS(ThreadLocale, DWORD, 0xC4)
	GET_THREAD_DATA_ALIAS(ThreadLCID, DWORD, 0xF98)
#	undef GET_THREAD_DATA_ALIAS

	static inline LPVOID GetSegmentBase(LDT_ENTRY SelectorEntry) {
		return reinterpret_cast<LPVOID>((SelectorEntry.HighWord.Bytes.BaseHi << 0x18) +
			(SelectorEntry.HighWord.Bytes.BaseMid << 0x10) + SelectorEntry.BaseLow);
	}
	static inline SIZE_T GetSegmentSize(LDT_ENTRY SelectorEntry) {
		return (SelectorEntry.HighWord.Bits.LimitHi << 0x10) +
			SelectorEntry.LimitLow + 1;
	}

	inline BOOL DuplicateHandle(HANDLE hSourceHandle, HANDLE hTargetProcessHandle,
		LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle,
		DWORD dwOptions) const {
		return bIsAttached && ::DuplicateHandle(ProcessInfo.hProcess,
			hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess,
			bInheritHandle, dwOptions) != FALSE ? TRUE : FALSE;
	}
	inline BOOL GetProcessHandleCount(LPDWORD pdwHandleCount) const {
		return bIsAttached && ::GetProcessHandleCount(ProcessInfo.hProcess,
			pdwHandleCount) != FALSE ? TRUE : FALSE;
	}
	BOOL GetHandleName(HANDLE theHandle, LPTSTR Name, SIZE_T dwNameSize) const;
	DWORD GetStackOwner(LPCVOID Address) const; // returns ID of thread or zero

	// overridables
	virtual void ShoutException(LPCSTR lpExceptionName, LPCSTR format = NULL, ...) const;
	virtual void ShoutEvent(LPCSTR lpEventName, LPCSTR format = NULL, ...) const;
	virtual void ShoutMemoryDump(LPCVOID IP) const;
	virtual void ShoutContext() const;

	// breakpoints support
protected:
	enum breakpoint_type_t {
		bpt_none = 0,
		bpt_any = bpt_none, // for lookup purposes: find any type
		bpt_sw,             // software (int 3) break
		bpt_hw_exec,        // hardware on execution
		bpt_hw_write,       // hardware on write address
		bpt_hw_io_access,   // hardware on IO read/write (not supported)
		bpt_hw_access,      // hardware on read/write address
	};

	struct breakpoint_t;
	// hardware breakpoints manager, mainly used for internal use
	// in derived classes use only for getting information about hw bpts
	// to manipulate hw breakpoints, use CDebugger::...Breakpoint..(...)
	// frontends to keep breakpoints table in sync
	class CHwBptMgr : private boost::noncopyable {
	friend class CDebugger;
	private:
		const CDebugger *dbgr; // need handle for Get/SetThreadContext
		DWORD DR[6], checkpoint[6];

		// low level - never shoould be called from outside of class
		static inline DWORD LocalActiveBit(BYTE nIndex) throw()
			{ return 1 << (nIndex << 1); }
		static inline DWORD GlobalActiveBit(BYTE nIndex) throw()
			{ return 2 << (nIndex << 1); }
		static inline DWORD SlotBits(BYTE nIndex) throw() {
			return 0xF << 0x10 + (nIndex << 2) | LocalActiveBit(nIndex) | GlobalActiveBit(nIndex);
		}
		inline void ClearControlSlot(BYTE nIndex) throw()
			{ DR[5] &= ~SlotBits(nIndex); }
		static void AdjustSize(BYTE &Size) throw() {
			if (Size < 1) Size = 1; else if (Size > 4) Size = 8; else if (Size > 2) Size = 4;
		}
		inline void Snapshot() throw()
			{ std::copy(DR, DR + ARRAY_SIZE(DR), checkpoint); }
		inline bool Changed() const throw()
			{ return !std::equal(DR, DR + ARRAY_SIZE(DR), checkpoint); }
		void setDR7bit(BYTE nIndex, bool b) throw() {
			if (dbgr != 0) if (b) DR[5] |= 1 << nIndex; else DR[5] &= ~(1 << nIndex);
		}
		bool getDR6bit(BYTE nIndex) const throw()
			{ return dbgr != 0 && (DR[4] & 1 << nIndex) != 0; }
		inline void SetAddress(BYTE nIndex, LPCVOID Address) throw()
			{ DR[nIndex] = reinterpret_cast<DWORD>(Address); }

	public:
		CHwBptMgr(const CDebugger *dbgr) : dbgr(dbgr) {
			std::fill_n(DR, ARRAY_SIZE(DR), 0);
			Snapshot();
			Load();
		}
		inline ~CHwBptMgr() { Save(); }

		// implicit conversion to general breakpoint type
		breakpoint_t operator[](BYTE nIndex) const
			{ return breakpoint_t(*this, nIndex); };

		BOOL Load();
	private: // not to use directly for manipulating breakpoints
		BOOL Save();
		BOOL Set(BYTE nIndex, LPCVOID lpAddress, breakpoint_type_t Type = bpt_hw_exec,
			BYTE Size = 1, BOOL LocalActive = TRUE, BOOL GlobalActive = FALSE) throw();
		void Clear(BYTE nIndex) throw() {
			if (dbgr != 0 && nIndex < 4) {
				SetAddress(nIndex, NULL);
				ClearControlSlot(nIndex);
			}
		}
		void SetActiveLocal(BYTE nIndex, BOOL b = TRUE) throw() {
			if (dbgr != 0 && nIndex < 4) if (b != FALSE)
				DR[5] |= LocalActiveBit(nIndex);
			else
				DR[5] &= ~LocalActiveBit(nIndex);
		}
		void SetActiveGlobal(BYTE nIndex, BOOL b = TRUE) throw() {
			if (dbgr != 0 && nIndex < 4) if (b != FALSE)
				DR[5] |= GlobalActiveBit(nIndex);
			else
				DR[5] &= ~GlobalActiveBit(nIndex);
		}
		inline void SetLE(BOOL b = TRUE) throw()
			{ setDR7bit(8, b != FALSE); } // local exact breakpoint enable
		inline void SetGE(BOOL b = TRUE) throw()
			{ setDR7bit(9, b != FALSE); } // global exact breakpoint enable
		inline void SetGD(BOOL b = TRUE) throw()
			{ setDR7bit(13, b != FALSE); } // general detect enable
		inline void ClearStatus() throw() // clear status register to avoid mess with future events
			{ if (dbgr != 0) DR[4] = 0; /*DR[4] &= ~0xFL;*/ }
	public:
		inline LPVOID GetAddress(BYTE nIndex) const throw() {
			return dbgr != 0 && nIndex < 4 ? reinterpret_cast<LPVOID>(DR[nIndex]) : NULL;
		}
		breakpoint_type_t GetType(BYTE nIndex) const throw();
		BYTE GetSize(BYTE nIndex) const throw();
		inline BOOL IsUsed(BYTE nIndex) const throw()
			{ return GetAddress(nIndex) != NULL ? TRUE : FALSE; }
		inline BOOL IsActiveLocal(BYTE nIndex) const throw() {
			return dbgr != 0 && nIndex < 4 && (DR[5] & LocalActiveBit(nIndex)) != 0 ? TRUE : FALSE;
		}
		inline BOOL IsActiveGlobal(BYTE nIndex) const throw() {
			return dbgr != 0 && nIndex < 4 && (DR[5] & GlobalActiveBit(nIndex)) != 0 ? TRUE : FALSE;
		}
		inline BOOL IsActive(BYTE nIndex) const throw()
			{ return IsActiveLocal(nIndex) || IsActiveGlobal(nIndex) ? TRUE : FALSE; }
		BOOL IsTriggered(BYTE nIndex = static_cast<BYTE>(-1)) const throw() {
			return dbgr != 0 && (nIndex < 4 ? (DR[4] & 1 << nIndex) != 0
				&& IsActive(nIndex) : (DR[4] & 0xF) != 0) ? TRUE : FALSE;
		}
		inline BOOL IsBD() const throw() // BD: debug register access detected
			{ return getDR6bit(13) ? TRUE : FALSE; }
		inline BOOL IsBS() const throw() // BS: dingle step
			{ return getDR6bit(14) ? TRUE : FALSE; }
		inline BOOL IsBT() const throw() // BT: task switch
			{ return getDR6bit(15) ? TRUE : FALSE; }
		BYTE Find(LPCVOID address, breakpoint_type_t Type = bpt_any, BYTE Size = 0) const throw();
		inline BYTE Find(const breakpoint_t &bpt) const throw() {
			_ASSERTE(bpt.Type != bpt_sw);
			return Find(bpt.Address, bpt.Type, bpt.Size);
		}
		BYTE FirstFree() const throw() {
			if (dbgr != 0) for (BYTE i = 0; i < 4; ++i) if (!IsUsed(i)) return i;
			return static_cast<BYTE>(-1);
		}
		BYTE GetFree() const throw() {
			BYTE total(0);
			if (dbgr != 0) for (BYTE i = 0; i < 4; ++i) if (!IsUsed(i)) ++total;
			return total;
		}
		inline BOOL HasFree() const throw()
			{ return FirstFree() != static_cast<BYTE>(-1) ? TRUE : FALSE; }
		// get specific debug register (nIndex = 0..3, 6, 7)
		DWORD GetDR(BYTE nIndex) const throw() {
			if (dbgr != 0) switch (nIndex) {
				case 0: case 1: case 2: case 3: return DR[nIndex];
				case 6: case 7: return DR[nIndex - 2];
#ifdef _DEBUG
				default:
					_RPT2(_CRT_WARN, "%s(%u): trying to get debug register with invalid index\n",
						__FUNCTION__, nIndex);
#endif // _DEBUG
			}
#ifdef _DEBUG
			else
				_RPT2(_CRT_WARN, "%s(%u): trying to get debug register of invalid snapshot\n",
					__FUNCTION__, nIndex);
#endif // _DEBUG
			return 0;
		}
		static inline BOOL is_hardware_bpt(breakpoint_type_t Type) throw() {
			return Type == bpt_hw_exec || Type == bpt_hw_access
				|| Type == bpt_hw_write || Type == bpt_hw_io_access ? TRUE : FALSE;
		}
	}; // CHwBptMgr

	class modules_t;
	struct breakpoint_t {
		LPVOID Address;
		breakpoint_type_t Type;
		union {
			BYTE SavedOriginal; // for sw
			BYTE Size; // for hw
		};
		bool enabled;

	public:
		inline breakpoint_t(LPCVOID Address, breakpoint_type_t Type = bpt_sw) throw() :
			Address(const_cast<LPVOID>(Address)), Type(Type)/*, enabled(true)*/ { }
		inline breakpoint_t(LPCVOID Address, breakpoint_type_t Type, BYTE Size) throw() :
			Address(const_cast<LPVOID>(Address)), Type(Type), Size(Size) { }
		breakpoint_t(const CHwBptMgr &hwbpts, BYTE nIndex) throw(std::exception) :
			Address(hwbpts.GetAddress(nIndex)), Type(hwbpts.GetType(nIndex)),
			Size(hwbpts.GetSize(nIndex)), enabled(hwbpts.IsActive(nIndex)) {
			_ASSERTE(nIndex < 4);
			if (nIndex >= 4 || !hwbpts.IsUsed(nIndex))
				std::__stl_throw_invalid_argument("HW breakpoint slot index out of range or not set");
		}

		inline bool operator ==(const breakpoint_t &r) const throw()
			{ return Address == r.Address && is_of_type(r.Type, r.Size); }

		bool is_of_type(breakpoint_type_t Type, BYTE Size = 0) const throw() {
			return (Type == bpt_any || this->Type == Type)
				&& (Size == 0 || Type == bpt_sw || is_hardware_type() && this->Size == Size);
		}
		inline bool is_software_type() const throw()
			{ return Type == bpt_sw; }
		inline bool is_hardware_type() const throw()
			{ return static_cast<bool>(CHwBptMgr::is_hardware_bpt(Type)); }

		struct hash {
			inline size_t operator ()(const breakpoint_t &__x) const throw()
				{ return reinterpret_cast<size_t>(__x.Address); }
		};
		friend static inline std::size_t hash_value(const breakpoint_t &__x)
			{ return boost::hash_value(__x.Address); }
	}; // breakpoint_t
	class breakpoints_t : public std::hash_set<breakpoint_t, breakpoint_t::hash/*boost::hash<breakpoint_t>*/> {
	public:
		inline iterator find(const_reference bpt) { return __super::find(bpt); }
		iterator find(LPCVOID address, breakpoint_type_t Type = bpt_any, BYTE Size = 0)
			{ return find(value_type(address, Type, Size)); }
		const_iterator find(LPCVOID address, breakpoint_type_t Type = bpt_any, BYTE Size = 0) const
			{ return __super::find(value_type(address, Type, Size)); }
		template<class T>inline const_iterator operator [](T __arg) const
			{ return find(__arg); }
		breakpoint_type_t get_type(LPCVOID Address) const {
			const_iterator const it(find(Address));
			return it != end() ? it->Type : bpt_none;
		}
		BOOL is(const breakpoint_t &bpt) const {
			return const_cast<breakpoints_t *>(this)->find(bpt)
				!= const_cast<breakpoints_t *>(this)->end() ? TRUE : FALSE;
		}
		BOOL is_enabled(const const_iterator &bpt) const
			{ return bpt != end() && static_cast<BOOL>(bpt->enabled) ? TRUE : FALSE; }
		BOOL is_enabled(LPCVOID Address, breakpoint_type_t Type = bpt_any, BYTE Size = 0) const
			{ return is_enabled(find(Address, Type, Size)); }
	} breakpoints;
	// breakpoints manipulation
	BOOL SetSwBreakpoint(LPCVOID Address, BOOL enabled = TRUE) const;
	inline BOOL SetSwBreakpoint(BOOL enabled = TRUE) const
		{ return SetSwBreakpoint(GetIP(), enabled); }
	BOOL SetBreakpoint(LPCVOID lpBaseAddress,
		breakpoint_type_t Type = bpt_sw, BYTE Size = 0, BOOL enabled = TRUE) const;
	inline BOOL SetBreakpoint(breakpoint_type_t Type = bpt_sw,
		BYTE Size = 0, BOOL enabled = TRUE) const
			{ return SetBreakpoint(GetIP(), Type, Size, enabled); }
	inline BOOL SetBreakpoint(const breakpoint_t &bpt) const
		{ return SetBreakpoint(bpt.Address, bpt.Type, bpt.Size, bpt.enabled); }
	BOOL EnableBreakpoint(const breakpoints_t::const_iterator &) const;
	BOOL EnableBreakpoint(LPCVOID Address, breakpoint_type_t Type = bpt_any,
		BYTE Size = 0) const {
		return bIsAttached && EnableBreakpoint(static_cast<const breakpoints_t &>(breakpoints).find(Address, Type, Size)) != FALSE ? TRUE : FALSE;
	}
	inline BOOL EnableBreakpoint(breakpoint_type_t Type = bpt_any, BYTE Size = 0) const
		{ return EnableBreakpoint(GetIP(), Type, Size); }
	inline void EnableBreakpoints(breakpoint_type_t Type = bpt_any, BYTE Size = 0) const {
		const_cast<CDebugger *>(this)->ProcessBreakpoints(EnableBreakpoint, Type, Size);
	}
	BOOL DisableBreakpoint(const breakpoints_t::const_iterator &) const;
	BOOL DisableBreakpoint(LPCVOID Address, breakpoint_type_t Type = bpt_any,
		BYTE Size = 0) const {
		return bIsAttached && DisableBreakpoint(static_cast<const breakpoints_t &>(breakpoints).find(Address, Type, Size)) != FALSE ? TRUE : FALSE;
	}
	inline BOOL DisableBreakpoint(breakpoint_type_t Type = bpt_any, BYTE Size = 0) const
		{ return DisableBreakpoint(GetIP(), Type, Size); }
	inline void DisableBreakpoints(breakpoint_type_t Type = bpt_any, BYTE Size = 0) const {
		const_cast<CDebugger *>(this)->ProcessBreakpoints(DisableBreakpoint, Type, Size);
	}
	BOOL DeleteBreakpoint(const breakpoints_t::const_iterator &) const;
	inline BOOL DeleteBreakpoint(LPCVOID Address,
		breakpoint_type_t Type = bpt_any, BYTE Size = 0) const {
		return bIsAttached && DeleteBreakpoint(static_cast<const breakpoints_t &>(breakpoints).find(Address, Type, Size)) != FALSE ? TRUE : FALSE;
	}
	inline BOOL DeleteBreakpoint(breakpoint_type_t Type = bpt_any, BYTE Size = 0) const
		{ return DeleteBreakpoint(GetIP(), Type, Size); }
	void DeleteBreakpoints(breakpoint_type_t Type = bpt_any, BYTE Size = 0) const;

private:
	void ActivateBreakpoint(const breakpoints_t::iterator &);
	BOOL IsBreakpointActive(const breakpoints_t::const_iterator &) const;
	void ProcessBreakpoints(BOOL (CDebugger::*)(const breakpoints_t::const_iterator &) const,
		breakpoint_type_t Type, BYTE Size);

	// overridable event handlers
protected:
	struct thread_t;
	// std. exceptions
	virtual DWORD OnAccessViolation() const;
	virtual DWORD OnArrayBoundsExceeded() const;
	// breakpoint type bpt_none indicates external (hardcoded) software breakpoint (int 3)
	virtual DWORD OnBreakpoint(breakpoint_type_t, LPVOID) const;
	virtual DWORD OnDatatypeMisalignment() const;
	virtual DWORD OnFltDenormalOperand() const;
	virtual DWORD OnFltDivideByZero() const;
	virtual DWORD OnFltInexactResult() const;
	virtual DWORD OnFltInvalidOperation() const;
	virtual DWORD OnFltOverflow() const;
	virtual DWORD OnFltStackCheck() const;
	virtual DWORD OnFltUnderflow() const;
	virtual DWORD OnIllegalInstruction() const;
	virtual DWORD OnInPageError() const;
	virtual DWORD OnIntDivideByZero() const;
	virtual DWORD OnIntOverflow() const;
	virtual DWORD OnInvalidDisposition() const;
	virtual void OnNoncontinuableException() const;
	virtual DWORD OnPrivInstruction() const;
	virtual DWORD OnSingleStep() const;
	virtual DWORD OnStackOverflow() const;
	virtual DWORD OnGuardPage() const;
	virtual DWORD OnInvalidHandle() const;
	virtual DWORD OnDbgControlC() const;
	// non-std. exceptions
	virtual DWORD OnCustomException() const;
	virtual DWORD OnUnhandledLastChance() const;
	virtual void OnCrash() const;
	// std. events
	virtual void OnCreateThread(const thread_t &thread) const;
	virtual void OnCreateProcess() const;
	virtual void OnExitThread(const thread_t &thread) const;
	virtual void OnExitProcess() const;
	virtual void OnLoadDll(const module_t &module) const;
	virtual void OnUnloadDll(const module_t &module) const;
	virtual void OnOutputDebugString() const;
	virtual void OnRip() const;
	// non-std. events
	virtual void OnEntryPoint() const;
	virtual void OnIdle() const { }

private:
	DWORD StdExceptionHandler(const char *ExceptionName) const;

protected:
	struct less {
		struct fname : public std::binary_function<const tchar *, const tchar *, bool> {
			bool operator ()(const tchar *s1, const tchar *s2) const {
				return s2 == 0 ? false : s1 == 0 ? true :
					_tcsicmp(getBaseName(s1), getBaseName(s2)) < 0;
			}
		};
		struct basename : public std::binary_function<const tchar *, const tchar *, bool> {
			bool operator ()(const tchar *, const tchar *) const;
		};
	};
	static tchar *getBaseName(const tchar *Name);

	// ************************* loaded modules table *************************
	struct module_t {
	friend class CDebugger;
	friend class modules_t;

		union {
			LPVOID lpBaseOfImage;
			HMODULE hModule;
			HINSTANCE hInstance;
		};
		SIZE_T dwSize;
		IMAGE_DOS_HEADER doshdr;
		IMAGE_NT_HEADERS pehdr;
		fixed_tpath_t FileName;

	private:
		// for DbgHelp operations on module
		const CDebugger *dbgr;
		DWORD64 SymBase;
		std::hash_set<DWORD> breakpoint_RVAs;

		module_t(HMODULE hModule, SIZE_T dwSize) throw() :
			hModule(hModule), dwSize(dwSize), dbgr(0), SymBase(0) { }

	public:
		inline operator HMODULE() const throw()
			{ return hModule; }
		inline operator LPCTSTR() const throw()
			{ return FileName; }
		inline bool operator <(const module_t &rhs) const throw()
			{ return hModule < rhs.hModule; }
		inline bool operator ==(const module_t &rhs) const throw()
			{ return hModule == rhs.hModule; }

		inline bool has_address(LPCVOID address) const throw() {
			return address >= lpBaseOfImage
				&& (LPBYTE)address < (LPBYTE)lpBaseOfImage + dwSize;
		}
		inline BOOL hasName() const throw()
			{ return FileName.empty()  ? FALSE : TRUE; }
		inline LPCTSTR getBaseName() const
			{ return CDebugger::getBaseName(FileName); }
		inline LONG getBaseOffset() const throw()
			{ return (LPBYTE)hModule - (LPBYTE)pehdr.OptionalHeader.ImageBase; }
		inline LPVOID RVA2VA(DWORD dwRVA) const throw() {
			_ASSERTE(dwRVA < dwSize);
			return dwRVA < dwSize ? (LPBYTE)hModule + dwRVA : NULL;
		}
		inline DWORD VA2RVA(LPCVOID lpAddress) const throw() {
			_ASSERTE(has_address(lpAddress));
			return has_address(lpAddress) ? (LPBYTE)lpAddress - (LPBYTE)hModule :
				static_cast<DWORD>(-1L);
		}
		inline LPVOID getEntryPoint() const throw() {
			return pehdr.OptionalHeader.AddressOfEntryPoint != 0 ?
				RVA2VA(pehdr.OptionalHeader.AddressOfEntryPoint) : NULL;
		}
		bool has_basename(LPCTSTR Name) const;
		inline bool has_fullpath(LPCTSTR Name) const {
			_ASSERTE(Name != NULL);
			return Name != NULL ? _tcsicmp(FileName, Name) == 0 : false;
		}
		bool has_fname(LPCTSTR Name) const {
			_ASSERTE(Name != NULL);
			return Name != NULL ?
				_tcsicmp(getBaseName(), CDebugger::getBaseName(Name)) == 0 : false;
		}
		inline DWORD64 ModBase() const throw()
			{ return SymBase; }
		inline DWORD64 SymOffset() const throw() {
			return SymBase != 0 ? SymBase - reinterpret_cast<DWORD64>(hModule) : 0;
		}

		// ************************* image sections table *************************
		struct section_t {
		friend class CDebugger;
			LPCVOID BaseAddress;
			IMAGE_SECTION_HEADER header;

		private:
			inline section_t() throw() { }
		public:
			inline section_t(LPCVOID lpBaseAddress) throw() :
				BaseAddress(const_cast<LPCVOID>(lpBaseAddress))
					{ /*ZeroMemory(&header, sizeof header);*/ }
			inline section_t(const section_t &_Other) throw() // copy construct
				{ memcpy(this, &_Other, sizeof section_t); } // is POD-safe

			inline operator LPCVOID() const throw()
				{ return BaseAddress; }
			// VC<=6 workaround
			inline bool operator <(const section_t &rhs) const throw()
				{ return BaseAddress < rhs.BaseAddress; }

			inline bool has_address(LPCVOID address) const throw() {
				return address >= BaseAddress
					&& (LPBYTE)address < (LPBYTE)BaseAddress + header.Misc.VirtualSize;
			}
			LPSTR getName(LPSTR Name/*, SIZE_T NameSize*/) const;
		}; // section_t
		class sections_t : public std::set<section_t> {
		public:
			const_iterator find(LPCVOID address, BOOL exact = FALSE) const {
				return exact != FALSE ? __super::find(address) : std::find_if(begin(), end(),
					boost::bind2nd(boost::mem_fun_ref(section_t::has_address), address));
			}
			template<class T>inline const_iterator operator [](T __arg) const
				{ return find(__arg); }
		} sections;

		// ************************* image exports table *************************
		struct export_t {
			fixed_tpath_t DllName;
			WORD Ordinal;
			LPCVOID lpFunc;
			DWORD dwRVA;
			/*UNC!*/std::string Name;

			inline operator LPCVOID() const throw() { return lpFunc; }
			inline operator WORD() const throw() { return Ordinal; }
			inline operator LPCSTR() const { return Name.c_str(); }
			bool operator <(const export_t &rhs) const throw() {
				const int foo(DllName.compare(rhs.DllName));
				return foo < 0 || foo == 0 && Ordinal < rhs.Ordinal;
			}
			inline bool operator ==(const export_t &rhs) const
				{ return Ordinal == rhs.Ordinal && DllName == rhs.DllName; }
		}; // export_t
		class exports_t : public multi_index_container<export_t, indexed_by<
			/*0*/ordered_unique<identity<export_t> >,
			/*1*/ordered_non_unique<BOOST_MULTI_INDEX_MEMBER(export_t, LPCVOID, lpFunc)>,
			/*2*/ordered_unique<BOOST_MULTI_INDEX_MEMBER(export_t, WORD, Ordinal)>,
			/*3*/ordered_non_unique<BOOST_MULTI_INDEX_MEMBER(export_t, std::string, Name)>,
			/*4*/ordered_non_unique<BOOST_MULTI_INDEX_MEMBER(export_t, DWORD, dwRVA)>
		> > {
		public:
			CNTNR_FIND_FRONTEND(LPCVOID, 1) // Address
			CNTNR_FIND_FRONTEND(WORD, 2) // Ordinal
			const_iterator find(LPCSTR Name) const {
				_ASSERTE(Name != NULL && *Name != 0);
				return Name != NULL && *Name != 0 ? *Name != '#' ?
					project<0>(get<3>().find(Name)) :
					find(static_cast<WORD>(strtoul(Name + 1, 0, 10))) : end();
			}
			CNTNR_FIND_FRONTEND(DWORD, 4) // Func RVA
			template<class T>inline const_iterator operator [](T __arg) const
				{ return find(__arg); }
		} exports;

		// ************************* image imports table *************************
		struct import_t {
			fixed_tpath_t DllName;
			DWORD IATEntry;
			LPCVOID lpIATEntry;
			/*UNC!*/std::string Name;
			union {
				WORD Ordinal, Hint;
			};

			inline operator DWORD() const throw() { return IATEntry; }
			inline operator LPCVOID() const throw() { return lpIATEntry; }
			inline operator LPCSTR() const { return Name.c_str(); }
			inline bool operator <(const import_t &rhs) const throw() {
				const int foo(DllName.compare(rhs.DllName));
				return foo < 0 || foo == 0 && IATEntry < rhs.IATEntry;
			}
			inline bool operator ==(const import_t &rhs) const
				{ return IATEntry == rhs.IATEntry && DllName == rhs.DllName; }

			inline BOOL byOrdinal() const { return Name.empty() ? TRUE : FALSE; }
		}; // import_t
		struct delay_import_t : public import_t {
			DWORD BIATEntry, UIATEntry;
		};
	private:
		template<class T>class __imports_base_t : public multi_index_container<T, indexed_by<
			/*0*/ordered_unique<identity<T> >,
			/*1*/ordered_unique<BOOST_MULTI_INDEX_MEMBER(import_t, DWORD, IATEntry)>,
			/*2*/ordered_non_unique<BOOST_MULTI_INDEX_MEMBER(import_t, std::string, Name)>,
			/*3*/ordered_non_unique<BOOST_MULTI_INDEX_MEMBER(import_t, WORD, Ordinal)>,
			/*4*/ordered_unique<BOOST_MULTI_INDEX_MEMBER(import_t, LPCVOID, lpIATEntry)>
		> > {
		public:
			CNTNR_FIND_FRONTEND(DWORD, 1) // IAT RVA
			const_iterator find(LPCSTR lpName) const {
				_ASSERTE(lpName != NULL && *lpName != 0);
				return lpName != NULL && *lpName != 0 ? *lpName != '#' ?
					project<0>(get<2>().find(lpName)) :
					find(static_cast<WORD>(strtoul(lpName + 1, 0, 10))) : end();
			}
			CNTNR_FIND_FRONTEND(WORD, 3) // Ordinal
			CNTNR_FIND_FRONTEND(LPCVOID, 4) // IAT Entry
			template<class T>inline const_iterator operator [](T __arg) const
				{ return find(__arg); }
		}; // __imports_base_t
	public:
		typedef __imports_base_t<import_t> imports_t;
		imports_t imports;
		typedef __imports_base_t<delay_import_t> delay_imports_t;
		delay_imports_t delay_imports;

		// ***************** image symbols table (from ImgHelp API) *****************
		struct symbol_t {
		friend class CDebugger;
			LPCVOID Address;
			dbgstring Name;
			ULONG Tag, Index, TypeIndex, Size, Flags;
		private:
			symbol_t(const SYMBOL_INFO &syminfo) throw(std::exception);
		};
		class symbols_t : public multi_index_container<symbol_t, indexed_by<
			/*0*/ordered_unique<BOOST_MULTI_INDEX_MEMBER(symbol_t, ULONG, Index)>,
			/*1*/ordered_non_unique<BOOST_MULTI_INDEX_MEMBER(symbol_t, LPCVOID, Address)>,
			/*2*/ordered_non_unique<BOOST_MULTI_INDEX_MEMBER(symbol_t, dbgstring, Name)>
		> > {
		public:
			inline const_iterator find(ULONG Index) const
				{ return __super::find(Index); }
			CNTNR_FIND_FRONTEND(LPCVOID, 1) // Address
			const_iterator find(const DBGHELP_TCHAR *Name) const {
				_ASSERTE(Name != NULL);
				return Name != NULL && *Name != 0 ? project<0>(get<2>().find(Name)) : end();
			}
			template<class T>inline const_iterator operator [](T __arg) const
				{ return find(__arg); }
		} symbols;

		// ***************** image lines table (from ImgHelp API) *****************
		struct line_t {
		friend class CDebugger;
			fixed_dbgpath_t FileName;
			LPCVOID Address;
			DWORD LineNumber;
			dbgstring Obj, Text;
		private:
			line_t(const SRCCODEINFO &srcinfo) throw(std::exception);
		};
		class lines_t : public multi_index_container<line_t, indexed_by<
			/*0*/ordered_unique<BOOST_MULTI_INDEX_MEMBER(line_t, LPCVOID, Address)>,
			/*1*/ordered_unique<composite_key<line_t,
					BOOST_MULTI_INDEX_MEMBER(line_t, fixed_dbgpath_t, FileName),
					BOOST_MULTI_INDEX_MEMBER(line_t, DWORD, LineNumber)
				>, composite_key_compare<std::less<fixed_dbgpath_t>, std::less<DWORD> >
			>
		> > {
		public:
			inline const_iterator find(LPCVOID Address) const
				{ return __super::find(Address); }
			const_iterator find(const DBGHELP_TCHAR *FileName, ULONG LineNumber) const {
				_ASSERTE(FileName != NULL && *FileName != 0);
				_ASSERTE(LineNumber != 0);
				return FileName == NULL || *FileName == 0 || LineNumber <= 0 ? end() :
					project<0>(get<1>().find(boost::make_tuple(FileName, LineNumber)));
			}
			template<class T>inline const_iterator operator [](T __arg) const
				{ return find(__arg); }
		} lines;
		BOOL LineFromName(const DBGHELP_TCHAR *FileName, DWORD dwLineNumber,
			PLONG lpDisplacement, IMAGEHLP_LINE64 &Line) const;

		// ************** image source files table (from ImgHelp API) **************
		class srcfiles_t : public std::set<fixed_dbgpath_t> {
		public:
			// TODO:
		} srcfiles;
	}; // module_t

protected:
	class modules_t : public multi_index_container<module_t, indexed_by<
		/*0*/ordered_unique<identity<module_t> >,
		/*1*/ordered_unique<BOOST_MULTI_INDEX_MEMBER(module_t, HMODULE, hModule)>,
		///*2*/ordered_non_unique<BOOST_MULTI_INDEX_MEMBER(module_t, fixed_tpath_t, FileName), less::fname>,
		/*2*/ordered_non_unique<BOOST_MULTI_INDEX_MEMBER(module_t, fixed_tpath_t, FileName)>
		///*4*/ordered_non_unique<BOOST_MULTI_INDEX_MEMBER(module_t, fixed_tpath_t, FileName), less::basename>
	> > {
	friend class CDebugger;
	public:
		//~modules_t() { clear(); }

		// avoid expensive module_t() construction
		inline const_iterator find(const_reference module) const
			{ return __super::find(module); }
		CNTNR_FIND_FRONTEND(HMODULE, 1) // hModule
		const_iterator find(LPCVOID address, BOOL exact) const {
			return exact != FALSE ? find((HMODULE)address) : std::find_if(begin(), end(),
				boost::bind2nd(boost::mem_fun_ref(module_t::has_address), address));
		}
		const_iterator find(LPCTSTR lpBaseName) const {
			_ASSERTE(lpBaseName != NULL);
			return lpBaseName != NULL ? //project<0>(get<2>().find(lpBaseName))
				std::find_if(begin(), end(),
					boost::bind2nd(boost::mem_fun_ref(module_t::has_fname), lpBaseName)) : end();
		}
		template<class T>inline const_iterator operator [](T __arg) const
			{ return find(__arg); }
		const_iterator find_fullpath(LPCTSTR lpFileName) const {
			_ASSERTE(lpFileName != NULL);
			return lpFileName != NULL ? project<0>(get<2>().find(lpFileName))
				/*std::find_if(begin(), end(),
					boost::bind2nd(boost::mem_fun_ref(module_t::has_fullpath), lpFileName))*/ : end();
		}
		const_iterator find_basename(LPCTSTR lpFileName) const {
			_ASSERTE(lpFileName != NULL);
			return lpFileName != NULL ? //project<0>(get<4>().find(lpFileName))
				std::find_if(begin(), end(),
					boost::bind2nd(boost::mem_fun_ref(module_t::has_basename), lpFileName)) : end();
		}
		// global export search: query accross modules
		static const module_t::exports_t::const_iterator noexport;
		module_t::exports_t::const_iterator find_export(LPCSTR lpName) const;
		module_t::exports_t::const_iterator find_export(LPCVOID address) const;
		// global symbol search: query accross modules
		static const module_t::symbols_t::const_iterator nosymbol;
		module_t::symbols_t::const_iterator find_symbol(const DBGHELP_TCHAR *Name) const; // seek through all modules, return 1-st match
		module_t::symbols_t::const_iterator find_symbol(LPCVOID address) const;
		// global line search: query accross modules
		static const module_t::lines_t::const_iterator noline;
		module_t::lines_t::const_iterator find_line(LPCVOID address) const;
		module_t::lines_t::const_iterator find_line(const DBGHELP_TCHAR *FileName,
			DWORD LineNumber) const; // seek through all modules, return 1-st match

	private:
		void erase(const iterator &it);
		void erase(const key_type &module) { erase(__super::find(module)); }
		void clear() {
			iterator it;
			while ((it = begin()) != end()) erase(it);
		}
		void track_breakpoint(LPCVOID Address);
	} modules;
private:
	modules_t::iterator AddModule(HMODULE hModule, SIZE_T dwSize = 0,
		LPCSTR lpImageName = NULL, WORD fUnicode = 0, HANDLE hFile = NULL);
	bool ResolveModule(const modules_t::iterator &);
	static BOOL CALLBACK SymEnumSymbolsProc(PSYMBOL_INFO, ULONG, PVOID);
	static BOOL CALLBACK SymEnumLinesProc(PSRCCODEINFO, PVOID);
	static BOOL CALLBACK SymEnumSourceFilesProc(PSOURCEFILE pSourceFile, PVOID UserContext);
	typedef std::map<fixed_tpath_t, std::hash_map<HMODULE, std::hash_map<WORD,
		std::string>, boost::hash<HMODULE> >, less::fname> unbfwds_t;
	unbfwds_t unbound_forwards;
protected:
	modules_t::const_iterator mainModule() const {
		_ASSERTE(modules[hModule()] != modules.end());
		return modules[hModule()];
	}
	inline BOOL isMain(const module_t &module) const
		{ return module.hModule == hModule() ? TRUE : FALSE; }
	BOOL isMain(modules_t::const_iterator module) const
		{ return module != modules.end() && isMain(*module) ? TRUE : FALSE; }
	// MS Debugging support
	BOOL SymFromName(const DBGHELP_TCHAR *Name, PSYMBOL_INFO pSymbol) const;
	BOOL SymFromAddr(LPCVOID Addr, PDWORD64 Displacement, PSYMBOL_INFO pSymbol) const;
	BOOL LineFromName(const DBGHELP_TCHAR *ModuleName,
		const DBGHELP_TCHAR *FileName, DWORD dwLineNumber,
		PLONG lpDisplacement, IMAGEHLP_LINE64 &Line) const;
	BOOL LineFromAddr(LPCVOID Addr, PDWORD Displacement, IMAGEHLP_LINE64 &Line) const;
	LPVOID GetSymAddr(const DBGHELP_TCHAR *Name) const;
private:
	static BOOL __stdcall ReadMemoryRoutine64(HANDLE, DWORD64, PVOID, DWORD, LPDWORD);
protected:
	BOOL StackWalk(STACKFRAME64 &StackFrame, LPCVOID AddrPC = NULL,
		LPCVOID AddrFrame = NULL, LPCVOID AddrStack = NULL) const;
	const FPO_DATA *FunctionTableAccess(LPCVOID AddrBase) const;
	BOOL GetTypeInfo(HMODULE ModBase, ULONG TypeId,
		IMAGEHLP_SYMBOL_TYPE_INFO GetType, PVOID pInfo) const;

protected:
	struct thread_t {
	friend class CDebugger;
	private:
		HANDLE hProcess;
	public:
		DWORD dwThreadId;
		CREATE_THREAD_DEBUG_INFO info; // The handle has THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, and THREAD_SUSPEND_RESUME access to the thread
		THREAD_BASIC_INFORMATION basicinfo;

	private:
		thread_t(DWORD dwThreadId, HANDLE hProcess = NULL) throw() :
			dwThreadId(dwThreadId), hProcess(hProcess) {
			ZeroMemory(&info, sizeof info);
			ZeroMemory(&basicinfo, sizeof basicinfo);
		}
	public:
		inline thread_t(const thread_t &_Other) throw() // copy-construct
			{ memcpy(this, &_Other, sizeof thread_t); } // is POD-safe

		inline operator DWORD() const throw() { return dwThreadId; }
		// VC<=6 workaround
		inline bool operator <(const thread_t &rhs) const throw()
			{ return dwThreadId < rhs.dwThreadId; }

		inline bool is_handle(HANDLE hThread) const throw()
			{ return info.hThread == hThread; }

		DWORD GetData(DWORD dwOffset) const;
		BOOL SetData(DWORD dwOffset, DWORD dwValue) const;
#		define GET_DATA_ALIAS(Name, Type, Offset) \
		inline Type Get##Name() const { return (Type)GetData(Offset); }
		GET_DATA_ALIAS(SehChain, LPVOID, 0x00)
		GET_DATA_ALIAS(StackTop, LPVOID, 0x04)
		GET_DATA_ALIAS(StackBottom, LPVOID, 0x08)
		inline SIZE_T GetStackSize() const
			{ return (LPBYTE)GetStackTop() - (LPBYTE)GetStackBottom(); }
		GET_DATA_ALIAS(LocalBase, LPVOID, 0x18)
		GET_DATA_ALIAS(ProcessId, DWORD, 0x20)
		GET_DATA_ALIAS(Id, DWORD, 0x24)
		GET_DATA_ALIAS(LocalStorage, LPVOID, 0x2C)
		GET_DATA_ALIAS(LastError, DWORD, 0x34)
		GET_DATA_ALIAS(Locale, DWORD, 0xC4)
		GET_DATA_ALIAS(LCID, DWORD, 0xF98)
#		undef GET_DATA_ALIAS

		// convenience functions
		bool IsSuspended() const;
		DWORD Suspend() const;
		DWORD Resume() const;
		LPVOID GetIP() const;
		BOOL SetIP(LPCVOID IP) const;
		BOOL GetContext(CONTEXT &Context, BOOL bUseFlags = FALSE/*get everything*/) const;
		BOOL SetContext(const CONTEXT &Context) const;
		BOOL Terminate(DWORD dwExitCode = 0) const;
		BOOL GetExitCode(LPDWORD lpExitCode) const;
		BOOL SetPriorityBoost(BOOL DisablePriorityBoost) const;
		BOOL SetPriority(int nPriority) const;
		DWORD SetIdealProcessor(DWORD dwIdealProcessor) const;
		DWORD_PTR SetAffinityMask(DWORD_PTR dwThreadAffinityMask) const;
		BOOL GetTimes(LPFILETIME lpCreationTime, LPFILETIME lpExitTime,
			LPFILETIME lpKernelTime, LPFILETIME lpUserTime) const;
		BOOL GetIOPendingFlag(PBOOL lpIOIsPending) const;
		BOOL GetStartInformation(LPVOID* pStartAddress, LPVOID* lpStartParameter) const;
		int GetPriority() const;
		BOOL GetPriorityBoost(PBOOL pDisablePriorityBoost) const;
		BOOL GetSelectorEntry(DWORD dwSelector, LDT_ENTRY &SelectorEntry) const;
	}; // thread_t
	class threads_t : public multi_index_container<thread_t, indexed_by<
		/*0*/ordered_unique<identity<thread_t> >,
		/*1*/hashed_unique<BOOST_MULTI_INDEX_MEMBER(thread_t, DWORD, dwThreadId)>,
		/*2*/ordered_non_unique<member_offset<thread_t, HANDLE, offsetof(thread_t, info.hThread)> >
	> > {
	public:
		CNTNR_FIND_FRONTEND(DWORD, 1) // Thread Id
		CNTNR_FIND_FRONTEND(HANDLE, 2) // hThread
		template<class T>inline const_iterator operator [](T __arg) const
			{ return find(__arg); }

		void SuspendAll() const
			{ std::for_each(begin(), end(), boost::mem_fun_ref(thread_t::Suspend)); }
		void ResumeAll() const
			{ std::for_each(begin(), end(), boost::mem_fun_ref(thread_t::Resume)); }
	} threads;
private:
	threads_t::const_iterator AddThread(DWORD/*ThreadId*/, const CREATE_THREAD_DEBUG_INFO &);
public:
	inline BOOL isMainThread(const thread_t &thr) const
		{ return thr.dwThreadId == ProcessInfo.dwThreadId ? TRUE : FALSE; }
	BOOL isMainThread(threads_t::const_iterator &it) const
		{ return it != threads.end() && isMainThread(*it) != FALSE ? TRUE : FALSE; }
	inline threads_t::const_iterator FindThread(DWORD dwThreadId = 0) const
		{ return threads[dwThreadId != 0 ? dwThreadId : DebugEvent.dwThreadId]; }
	threads_t::const_reference mainThread() const {
		if (!bIsAttached) throw std::logic_error("not debugged");
		return *threads[ProcessInfo.dwThreadId];
	}
}; // class CDebugger

#undef multi_index_container
#undef indexed_by
#undef ordered_unique
#undef ordered_non_unique
#undef hashed_unique
#undef hashed_non_unique
#undef composite_key
#undef composite_key_compare
#undef identity
#undef member_offset
#undef BOOST_MNDX
#undef CNTNR_FIND_FRONTEND

#endif // _DEBUGGER_HPP_20080831_
