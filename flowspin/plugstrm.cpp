
/*****************************************************************************
 *                                                                           *
 *  plugstrm.cpp: ida common library stream routines implementation          *
 *  (c) 2006-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include <streambuf>
#include <ostream>
#include <fstream>
#include <boost/scoped_array.hpp>
#define NOMINMAX 1
#include <wtypes.h>
#include <psapi.h>
#include "pcre.hpp"
#include "plugstrm.hpp"
#include "plugsys.hpp"
#include "plugxcpt.hpp"
#include "plughlpr.hpp"

// log window stream frontend handling class
class __ida_buf : public std::streambuf {
private:
	static const bool is_msg_inited;

private:
	typedef int (* logwrite_p)();
	static logwrite_p plogwrite;

	// fast forward to kernel log window raw write (no need of qvsprintf(...))
	// only available if logwrite rva defined for current IDA version
	// returns >= 0 (real count written) if internal logwrite succeed
	// returns -1 if Idag.exe not loaded, function not available, or crashed
	// (signal to use std. msg(...) call)
	static int logwrite(const char *__s, int __n = -1) throw(std::exception) {
		_ASSERTE(__s != 0);
		if (__s == 0 || __n == 0 || !is_msg_inited) return 0;
		if (plogwrite != NULL)
#ifdef _DEBUG
		try
#endif // _DEBUG
		{
			const std::string s(__s, __n != -1 ? __n : (std::string::size_type)std::string::npos);
			const char *const _cs(s.c_str());
			__asm mov eax, _cs
			int __r;
#ifdef __ICL
			__r = plogwrite();
#else // !__ICL
			__asm {
				call plogwrite
				mov __r, eax
			}
#endif // __ICL
			if (__r < 0) throw fmt_exception("internal logwrite(const char *) returned %i", __r);
#ifdef _DEBUG
			if (__n >= 0 && __r != __n) _RPT4(_CRT_WARN,
				"%s(\"%-.3840s\", %i): internal logwrite(const char *) returned %i\n",
				__FUNCTION__, _cs, __n, __r);
#endif // _DEBUG
			return __r;
		}
#ifdef _DEBUG
		catch (const std::exception &e) {
			_RPT4(_CRT_ERROR, "%s(\"%-.3840s\", %i): %s\n", __FUNCTION__, __s, __n, e.what());
			/*if (typeid(e) != typeid(se_exception)) *//*re*/throw;
		}
#endif // _DEBUG
		return -1;
	}
	static bool try_RVA(DWORD RVA, DWORD64 FirstQword = 0, size_t size = 0,
		uint32 CRC32 = 0, const char *MD5 = 0) {
		_ASSERTE(RVA > 0);
		if (plogwrite != NULL || RVA <= 0) return false;
		const HMODULE hIDAG = GetModuleHandle(NULL/*"idag.exe"*/);
		_ASSERTE(hIDAG != NULL);
		if (hIDAG == NULL) return false; // something wrong: couldnot find main module
		try {
			plogwrite = reinterpret_cast<logwrite_p>(reinterpret_cast<PBYTE>(hIDAG) + RVA);
			// verification
			if (MD5 != 0 && *MD5 != 0 && size > 0) {
				_ASSERTE(strlen(MD5) == 0x10 << 1);
				boost::md5 md5(plogwrite, size);
				if (_stricmp(md5.digest().hex_str_value(), MD5) != 0)
					throw fmt_exception("internal logwrite(...) MD5 mismatch (%s != %s)",
						md5.digest().hex_str_value(), MD5);
			} else if (CRC32 != 0 && size > 0) {
				const boost::crc32 crc32(plogwrite, size);
				if (crc32 != CRC32)
					throw fmt_exception("internal logwrite(...) CRC32 mismatch (0x%08I32X != 0x%08I32X)",
						crc32(), CRC32);
			} else if (FirstQword != 0) {
				if (*reinterpret_cast<PDWORD64>(plogwrite) != FirstQword)
					throw fmt_exception("internal logwrite(...) first qword mismatch (0x%16I64X != 0x%16I64X)",
						*reinterpret_cast<PDWORD64>(plogwrite), FirstQword);
			}
#if defined(_DEBUG) || IDP_INTERFACE_VERSION < 76
		} catch (const std::exception &e) {
			MODULEINFO modinfo;
			ZeroMemory(&modinfo, sizeof modinfo);
			if (!GetModuleInformation(NULL/*"Idag.exe"*/, hIDAG, &modinfo, sizeof modinfo))
				ZeroMemory(&modinfo, sizeof modinfo);
			VS_FIXEDFILEINFO fixednfo;
			if (!GetFixedFileInfo(hIDAG, fixednfo)) ZeroMemory(&fixednfo, sizeof fixednfo);
#ifdef _DEBUG
			_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
				"%s(0x%X, ...): %s (%s) [IDP_INTERFACE_VERSION: %u(%i) first qword at %08X: %016I64X %s lpBaseOfDll: %08X SizeOfImage: 0x%lX EntryPoint: %08X version: %hu.%hu.%hu.%hu",
				__FUNCTION__, RVA, e.what(), typeid(e).name(), IDP_INTERFACE_VERSION, ph.version,
				plogwrite, *reinterpret_cast<PDWORD64>(plogwrite),
				"Idag.exe", modinfo.lpBaseOfDll, modinfo.SizeOfImage/*DWORD*/, modinfo.EntryPoint,
				HIWORD(fixednfo.dwFileVersionMS), LOWORD(fixednfo.dwFileVersionMS),
				HIWORD(fixednfo.dwFileVersionLS), LOWORD(fixednfo.dwFileVersionLS));
#endif // _DEBUG
#if IDP_INTERFACE_VERSION < 76
			warning("%s(0x%X, ...): %s (%s)\n\n"
				"Please send me this messagebox to change way of verification:\n"
				"IDP_INTERFACE_VERSION: %u(%i)\n"
				"first qword at %08X: %016I64X\n"
				"%s lpBaseOfDll: %08X SizeOfImage: 0x%lX EntryPoint: %08X\n"
				"%s version: %hu.%hu.%hu.%hu",
				__FUNCTION__, RVA, e.what(), typeid(e).name(),
				IDP_INTERFACE_VERSION, ph.version,
				plogwrite, *reinterpret_cast<PDWORD64>(plogwrite),
				"Idag.exe", modinfo.lpBaseOfDll, modinfo.SizeOfImage/*DWORD*/, modinfo.EntryPoint,
				"Idag.exe", HIWORD(fixednfo.dwFileVersionMS), LOWORD(fixednfo.dwFileVersionMS),
				HIWORD(fixednfo.dwFileVersionLS), LOWORD(fixednfo.dwFileVersionLS));
#endif // IDP_INTERFACE_VERSION < 76
#else // !_DEBUG && IDP_INTERFACE_VERSION >= 76
		} catch (...) {
#endif // _DEBUG || IDP_INTERFACE_VERSION < 76
			plogwrite = NULL;
		}
		return plogwrite != NULL;
	} // try_RVA

public:
	__ida_buf() {
		plogwrite = NULL;
		if (!is_msg_inited) {
			_RPT1(_CRT_WARN, "%s(): kernel messaging subsystem not initialized\n",
				__FUNCTION__);
			return;
		}
#if IDP_INTERFACE_VERSION == 75
		// Idag version 4.8.0.847
		/*
		00419A68  /$  55             PUSH EBP
		00419A69  |.  8BEC           MOV EBP, ESP
		00419A6B  |.  83C4 F0        ADD ESP, -10
		00419A6E  |.  8945 FC        MOV [LOCAL.1], EAX
		00419A71  |.  A0 20975D00    MOV AL, BYTE PTR DS:[5D9720]
		00419A76  |.  84C0           TEST AL, AL
		00419A78  |.  75 31          JNZ SHORT idag.00419AAB
		00419A7A  |.  C605 20975D00 >MOV BYTE PTR DS:[5D9720], 1
		00419A81  |.  68 A0995D00    PUSH idag.005D99A0                 ; /Arg1 = 005D99A0 ASCII "IDALOG"
		00419A86  |.  E8 1DC51A00    CALL idag.005C5FA8                 ; \idag.005C5FA8
		00419A8B  |.  59             POP ECX                            ;  ntdll.7C9507A8
		00419A8C  |.  8945 F8        MOV [LOCAL.2], EAX
		00419A8F  |.  8B55 F8        MOV EDX, [LOCAL.2]                 ;  ntdll.7C9507C8
		00419A92  |.  85D2           TEST EDX, EDX
		00419A94  |.  74 15          JE SHORT idag.00419AAB
		00419A96  |.  68 A7995D00    PUSH idag.005D99A7                 ; /Arg2 = 005D99A7
		00419A9B  |.  FF75 F8        PUSH [LOCAL.2]                     ; |Arg1 = 7C9507C8
		00419A9E  |.  E8 413D1A00    CALL idag.005BD7E4                 ; \idag.005BD7E4
		00419AA3  |.  83C4 08        ADD ESP, 8
		00419AA6  |.  A3 1C975D00    MOV DWORD PTR DS:[5D971C], EAX
		00419AAB  |>  8B0D 1C975D00  MOV ECX, DWORD PTR DS:[5D971C]     ;  idag.00612CF8
		00419AB1  |.  85C9           TEST ECX, ECX
		00419AB3  |.  74 1D          JE SHORT idag.00419AD2
		00419AB5  |.  FF35 1C975D00  PUSH DWORD PTR DS:[5D971C]         ; /Arg2 = 00612CF8
		00419ABB  |.  FF75 FC        PUSH [LOCAL.1]                     ; |Arg1 = 00000000
		00419ABE  |.  E8 693E1A00    CALL idag.005BD92C                 ; \idag.005BD92C
		00419AC3  |.  83C4 08        ADD ESP, 8
		00419AC6  |.  FF35 1C975D00  PUSH DWORD PTR DS:[5D971C]         ;  idag.00612CF8
		00419ACC  |.  E8 A7361A00    CALL idag.005BD178
		00419AD1  |.  59             POP ECX                            ;  ntdll.7C9507A8
		00419AD2  |>  A1 C46F6100    MOV EAX, DWORD PTR DS:[616FC4]
		00419AD7  |.  8B10           MOV EDX, DWORD PTR DS:[EAX]
		00419AD9  |.  85D2           TEST EDX, EDX
		00419ADB  |.  74 79          JE SHORT idag.00419B56
		00419ADD  |.  8B0D C46F6100  MOV ECX, DWORD PTR DS:[616FC4]     ;  idag._IdaWindow
		00419AE3  |.  8B01           MOV EAX, DWORD PTR DS:[ECX]
		00419AE5  |.  8B90 5C070000  MOV EDX, DWORD PTR DS:[EAX+75C]
		00419AEB  |.  85D2           TEST EDX, EDX
		00419AED  |.  74 67          JE SHORT idag.00419B56
		00419AEF  |.  8B4D FC        MOV ECX, [LOCAL.1]
		00419AF2  |.  894D F4        MOV [LOCAL.3], ECX
		00419AF5  |.  EB 56          JMP SHORT idag.00419B4D
		00419AF7  |>  6A 0A          /PUSH 0A
		00419AF9  |.  FF75 F4        |PUSH [LOCAL.3]                    ;  ntdll.7C90EE18
		00419AFC  |.  E8 0F1B1A00    |CALL idag.005BB610
		00419B01  |.  83C4 08        |ADD ESP, 8
		00419B04  |.  8945 F0        |MOV [LOCAL.4], EAX
		00419B07  |.  8B45 F0        |MOV EAX, [LOCAL.4]
		00419B0A  |.  85C0           |TEST EAX, EAX
		00419B0C  |.  75 17          |JNZ SHORT idag.00419B25
		00419B0E  |.  8A15 21975D00  |MOV DL, BYTE PTR DS:[5D9721]
		00419B14  |.  8B45 F4        |MOV EAX, [LOCAL.3]                ;  ntdll.7C90EE18
		00419B17  |.  E8 0FFAFFFF    |CALL idag.0041952B
		00419B1C  |.  C605 21975D00 >|MOV BYTE PTR DS:[5D9721], 1
		00419B23  |.  EB 31          |JMP SHORT idag.00419B56
		00419B25  |>  8B55 F0        |MOV EDX, [LOCAL.4]
		00419B28  |.  C602 00        |MOV BYTE PTR DS:[EDX], 0
		00419B2B  |.  8A15 21975D00  |MOV DL, BYTE PTR DS:[5D9721]
		00419B31  |.  8B45 F4        |MOV EAX, [LOCAL.3]                ;  ntdll.7C90EE18
		00419B34  |.  E8 F2F9FFFF    |CALL idag.0041952B
		00419B39  |.  8B4D F0        |MOV ECX, [LOCAL.4]
		00419B3C  |.  C601 0A        |MOV BYTE PTR DS:[ECX], 0A
		00419B3F  |.  8B45 F0        |MOV EAX, [LOCAL.4]
		00419B42  |.  40             |INC EAX
		00419B43  |.  8945 F4        |MOV [LOCAL.3], EAX
		00419B46  |.  C605 21975D00 >|MOV BYTE PTR DS:[5D9721], 0
		00419B4D  |>  8B55 F4         MOV EDX, [LOCAL.3]                ;  ntdll.7C90EE18
		00419B50  |.  8A0A           |MOV CL, BYTE PTR DS:[EDX]
		00419B52  |.  84C9           |TEST CL, CL
		00419B54  |.^ 75 A1          \JNZ SHORT idag.00419AF7
		00419B56  |>  FF75 FC        PUSH [LOCAL.1]
		00419B59  |.  E8 BE191A00    CALL idag.005BB51C
		00419B5E  |.  59             POP ECX                            ;  ntdll.7C9507A8
		00419B5F  |.  8BE5           MOV ESP, EBP
		00419B61  |.  5D             POP EBP                            ;  ntdll.7C9507A8
		00419B62  \.  C3             RETN
		*/
		try_RVA(0x19A68, 0x4589F0C483EC8B55, 251, 0xE0F8B4F9/*, "4f5d008acd7148201f1ad102359c1056"*/);
#elif IDP_INTERFACE_VERSION >= 76
		static const struct RVA_table_t {
			DWORD RVA;
			DWORD64 FirstQword;
			size_t size;
			uint32 CRC32;
			//const char *MD5;
		} RVA_table[] = {
#ifdef __X64__ // 64-bit kernel
			// version 5.2.0.908
			/*Idag64*/0x5193C, 0xC9EDA0F88B575653, 249, 0xAFAC5FFC/*, "cf78830a1acf93d8932c8d48f920ba42"*/,
			/*Idau64*/0x61B2, 0xF66CB8F08B575653, 367, 0xA7894964/*, "d61f28e1525bece71e0ef70d29e33d04"*/,
			/*Idaw64*/0x19F2, 0xB420B8F08B575653, 367, 0x07EBA8AB/*, "a748614b508e3a49703c825d4fd0110e"*/,
			// version 5.1.0.899
			/*Idag64*/0x50F44, 0x3CB9A0F88B575653, 239, 0x4473B40B/*, "a85f9a245894ef45ab91a657b022196b"*/,
			/*Idau64*/0x5F7E, 0xD660B8F08B575653, 357, 0x31722422/*, "953394bf634613eaa46f5f2a4a0bbb23"*/,
			/*Idaw64*/0x19E0, 0x5653C8C483EC8B55, 363, 0x716CEEA5/*, "da4bd270e6418b484ec90b0273252711"*/,
#endif // 64-bit kernel
			// version 5.2.0.908
			/*Idag*/0x50F38, 0x19EDA0F88B575653, 249, 0xF73DC79F/*, "ae0da52c0b247e00e7ef059d3258b1b2"*/,
			/*Idau*/0x618A, 0x766CB8F08B575653, 367, 0x167AA3C0/*, "ba4d8487c64e59cd6823cce2b50e096b"*/,
			/*Idaw*/0x19F2, 0x3420B8F08B575653, 367, 0x33494A08/*, "2735d1cb675e73f6ec580306a6185e92"*/,
			// version 5.1.0.899
			/*Idag*/0x50550, 0x8CB9A0F88B575653, 239, 0x6CD7471E/*, "e43d38e210e6ccd3446d67788771b413"*/,
			/*Idau*/0x5F56, 0x5660B8F08B575653, 357, 0x5413C2DC/*, "ef65da84f93023bbfa767d1030348024"*/,
			/*Idaw*/0x19E0, 0x5653C8C483EC8B55, 363, 0xCE845F84/*, "69b740afc8fd835a8414da2ab1903ba2"*/,
			// version 5.0.0.879
			/*Idag*/0x5EF58, 0x61F8A0F88B575653, 193, 0x015D78DB/*, "f4b5bc9bf16b3229492ef8eef237b36e"*/,
		}; // RVA_table
		for (const RVA_table_t *it = RVA_table; it != RVA_table + qnumber(RVA_table); ++it)
			if (try_RVA(it->RVA, it->FirstQword, it->size, it->CRC32/*, it->MD5*/)) break;
#endif // IDP_INTERFACE_VERSION
#ifdef _DEBUG
		if (plogwrite != NULL) OutputDebugString("%s(): internal logwrite at %08X and verified\n",
			__FUNCTION__, plogwrite);
#endif // _DEBUG
	}

protected:
	// Writes up to __n characters.  Return value is the number of characters
	// written.
	std::streamsize xsputn(const char_type* __s, std::streamsize __n) {
		_ASSERTE(__s != 0);
		if (__s != 0 && __n > 0 && is_msg_inited) {
#ifdef _DEBUG
			if (strlen(__s) < __n)
				_RPT3(_CRT_WARN, "%s(\"%-.3840s\", %I64i): printed string contains terminating zero (will cause badbit on stream)\n",
					__FUNCTION__, __s, __n);
#endif // _DEBUG
			if (plogwrite != NULL && __n <= INT_MAX) {
				const int __r(logwrite(__s, __n));
				if (__r >= 0) return __r;
			}
#ifdef _DEBUG
			try {
				if (__n >= 0x1000) _RPT3(_CRT_WARN, "%s(...): huge string(%I64i): %-.3840s...\n",
					__FUNCTION__, __n, __s);
#endif // _DEBUG
				std::streamsize __r(0);
				while (__r < __n) {
					const int n(static_cast<int>(std::min<std::streamsize>(__n - __r, 0x0FFF)));
					int __a(msg("%-.*s", n, __s + __r));
					if (*(__s + __r) == '@' && __a == 0) { // IDA workaround to prevent failbit
						_RPT4(_CRT_WARN, "%s(\"%-.1980s\", %I64i): msg(..., \"%-.1980s\") started with '@' (no output)\n",
							__FUNCTION__, __s, __n, __s + __r);
						// try re-print without leading problem char
						if (n > 1) xsputn(__s + __r + 1, n - 1);
						__a = n; // fool stream
					}
					if (__a < 0)
						throw fmt_exception("msg(...) returned %i (should be %i)", __a, n);
					else if (__a == 0) {
#ifdef _DEBUG
						_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
							"%s(\"%-.1980s\", %I64i): msg(..., \"%-.1980s\") returned %i (should be %i)\n",
							__FUNCTION__, __s, __n, __s + __r, __a, n);
#endif // _DEBUG
						break;
					}
					__r += __a;
				}
				return __r;
#ifdef _DEBUG
			} catch (const std::exception &e) {
				_RPT4(_CRT_ERROR, "%s(\"%-.3960s\", %I64i): %s\n",
					__FUNCTION__, __s, __n, e.what());
				/*re*/throw;
			}
#endif // _DEBUG
		}
		return 0;
	}
	// Extension: writes up to __n copies of __c.  Return value is the number
	// of characters written.
	std::streamsize _M_xsputnc(char_type __c, std::streamsize __n) {
		if (__n == 0 || !is_msg_inited) return 0;
		if (plogwrite != NULL && __n <= INT_MAX) {
			const int __r(logwrite(std::string(__n, __c).c_str(), __n));
			if (__r >= 0) return __r;
		}
		std::streamsize __r(0);
		for (std::streamsize cntr = 0; cntr < __n; ++cntr) __r += msg("%c", __c);
		if (__c == '@' && __r < __n) { // IDA workaround to prevent failbit
			_RPT3(_CRT_WARN, "%s(%i, %I64i): nothing written due to starting char('@')\n",
				__FUNCTION__, __c, __n);
			__r = __n; // fool stream
		}
#ifdef _DEBUG
		if (__r < __n) _RPT4(_CRT_WARN, "%s(%i, %I64i): not everything written(%I64i)\n",
			__FUNCTION__, __c, __n, __r);
#endif // _DEBUG
		return __r;
	}
	// Called when there is no write position.  All subclasses are expected to
	// override this virtual member function.
	int_type overflow(int_type __c) {
		int __r(0);
		if (is_msg_inited) {
			_ASSERTE(__c >= CHAR_MIN && __c <= CHAR_MAX);
			if (plogwrite != NULL) {
				const char __buf[] = { __c, 0 };
				if ((__r = logwrite(__buf, 1)) >= 0) goto done;
			}
			__r = msg("%c", __c);
			if (__c == '@' && __r == 0) { // IDA workaround to prevent failbit
				_RPT2(_CRT_WARN, "%s(%i): nothing written('@')\n",
					__FUNCTION__, __c);
				__r = 1; // fool stream
			}
		}
	done:
		return __r >= 1 ? traits_type::not_eof(__c) : traits_type::eof();
	}
}; // __ida_buf

const bool __ida_buf::is_msg_inited(callui(ui_is_msg_inited).cnd);
__ida_buf::logwrite_p __ida_buf::plogwrite;
static __ida_buf __ida_stream;
std::ostream cmsg(&__ida_stream);

std::ostream &operator<<(std::ostream &__os, const asshex &__m) {
	std::ios_base::fmtflags clearmask(__m._M_clrmask | std::ios_base::showbase);
	if ((__m._M_flags & std::ios_base::adjustfield) != 0) clearmask |= std::ios_base::adjustfield;
	if ((__m._M_flags & std::ios_base::basefield) != 0) clearmask |= std::ios_base::basefield;
	if ((__m._M_flags & std::ios_base::floatfield) != 0) clearmask |= std::ios_base::floatfield;
	__os.unsetf(clearmask);
	if (__m._M_flags != 0) __os.setf(__m._M_flags);
	_ASSERTE((__os.flags() & std::ios_base::basefield) == std::ios_base::hex);
	__os << __os.widen(sign(__m._M_value));
	if (__m._M_prefix) {
		__os.width(0);
		__os << __os.widen('0') << __os.widen('x');
	}
	if (__m._M_width > 0) {
		__os.width(__m._M_width);
		__os.fill(__os.widen(__m._M_fill));
	}
	return sizeof(asshex::value_type) > 1 ?
		__os << (__m._M_value < 0 ? -__m._M_value : __m._M_value) :
		__os << (uint16)(__m._M_value < 0 ? -__m._M_value : __m._M_value);
}

size_t _M_put_wstr(std::ostream &__os, const wchar_t *const ws, size_t length) {
	_ASSERTE(ws != 0);
	if (ws == 0) return 0;
	if (length == static_cast<size_t>(-1)) length = wcslen(ws);
	if (length <= 0) return 0;
	boost::scoped_array<char> s(new char[length + 1]);
	if (!s) {
		_RPT2(_CRT_ERROR, "%s(...): failed to allocate new string of size 0x%IX\n",
			__FUNCTION__, length + 1);
		throw std::bad_alloc(); //return 0;
	}
	if ((length = wcstombs(ws, length, s.get(), length + 1)) > 0) __os << s.get();
	return length;
}

ea_t find_signature(const char *s, const char *sigfile) {
	_ASSERTE(s != 0 && *s != 0);
	if (s == 0 || *s == 0) return 0;
	char signspath[QMAXPATH];
	if (sigfile == 0 || *sigfile == 0)
		ConstructHomeFileName(signspath, "signs", "txt");
	else
		qstrcpy(signspath, sigfile);
	std::ifstream is(signspath);
	if (!is.good()) {
		cmsg << "ERROR: cannot open pe-tools signatures (" << signspath << ')' << std::endl;
		return 0;
	}
	const PCRE::regexp is_begin("^\\s*<<BEGIN>>\\s*$", PCRE_CASELESS),
		is_end("^\\s*<<END>>\\s*$", PCRE_CASELESS),
		is_def[] = {
			PCRE::regexp("^\\s*\\[\\s*(.+?)\\s*\\=\\s*(\\S+?)\\s*\\]\\s*$"),
			PCRE::regexp("^\\s*(.+?)\\s*\\=\\s*(\\S+?)\\s*$"),
		};
	if (!is_begin || !is_end || !is_def[0]) {
		cmsg << "ERROR: compile of one or more regexps failed" << std::endl;
		return 0;
	}
	bool have_scope(false);
	while (is.good()) {
		std::string line;
		getline(is, line);
		if (is.fail()) break;
		if (is_end(line) >= 0)
			have_scope = false; //break;
		else if (is_begin(line) >= 0)
			have_scope = true;
		else if (have_scope) {
			PCRE::regexp::result match(is_def[0], line);
			if (match < 2) match(is_def[1], line);
			if (match < 2 || strcmp(match[1], s) != 0) continue;
			if (match < 3 || match(2) <= 0) return BADADDR;
			_ASSERTE((match(2) & 1) == 0); // must be even length
			std::basic_string<uchar> image, mask;
			for (uint offset = 0; offset < match(2); offset += 2) {
				char tmp[3], *end;
				const uint8 value(strtoul(qstrcpy(tmp, match[2] + offset), &end, 16));
				const bool ishex(end == tmp + 2);
				image.push_back(ishex ? value : 0);
				mask.push_back(ishex ? 1 : 0);
			}
			_ASSERTE(image.length() == mask.length());
			_ASSERTE(image.length() << 1 == match(2));
			return bin_search(inf.minEA, inf.maxEA, image.data(), mask.data(),
				image.length(), BIN_SEARCH_FORWARD, BIN_SEARCH_CASE | BIN_SEARCH_NOBREAK);
		} // have_scope
	} // read all signatures
	cmsg << "WARNING: requested pattern name not present in signature file(" <<
		signspath << "): " << s << std::endl;
	return 0;
}
