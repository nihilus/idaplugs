
/*****************************************************************************
 *                                                                           *
 *  idasdk.cpp: ida sdk interversion compatibility                           *
 *  (c) 2006-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#pragma warning(disable: 1011) // missing return statement at end of non-void function
#endif

#ifdef _DEBUG
#include <typeinfo>
#endif
#define NOMINMAX 1
#include <oaidl.h>
#ifdef _DEBUG
#include <psapi.h>
#endif
#include "idasdk.hpp"
#include "plugxcpt.hpp"

#if IDP_INTERFACE_VERSION >= 76

// supplemental interface for not exported functions (forgotten?)
static struct IDAWLL_FUNCPTRS {
private:
	typedef char *(* func0_ptr_type)();
	static HMODULE hIdaWll;

	static void get_func_ptr(func0_ptr_type &pfunc, DWORD const RVA,
		DWORD64 const FirstQword = 0, size_t const size = 0) {
		_ASSERTE(hIdaWll != NULL);
		_ASSERTE(RVA > 0);
		if (hIdaWll == NULL || pfunc != NULL || RVA <= 0) return;
		try {
			pfunc = reinterpret_cast<func0_ptr_type>(reinterpret_cast<PBYTE>(hIdaWll) + RVA);
			// verify
			if (FirstQword != 0 && *reinterpret_cast<PDWORD64>(pfunc) != FirstQword)
				throw fmt_exception("internal logwrite(...) first qword mismatch (0x%16I64X != 0x%16I64X)",
					*reinterpret_cast<PDWORD64>(pfunc), FirstQword);
		} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
			MODULEINFO modinfo;
			ZeroMemory(&modinfo, sizeof modinfo);
			if (!GetModuleInformation(NULL/*"Idag.exe"*/, hIdaWll, &modinfo, sizeof modinfo))
				ZeroMemory(&modinfo, sizeof modinfo);
			const HMODULE hIDAG(GetModuleHandle(NULL/*"idag.exe"*/));
			VS_FIXEDFILEINFO fixednfo;
			if (!GetFixedFileInfo(hIDAG, fixednfo)) ZeroMemory(&fixednfo, sizeof fixednfo);
			_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
				"%s(..., 0x%X, ...): %s (%s) [IDP_INTERFACE_VERSION: %u(%i) first qword at %08X: %016I64X %s lpBaseOfDll: %08X SizeOfImage: 0x%lX EntryPoint: %08X %s version: %hu.%hu.%hu.%hu",
				__FUNCTION__, RVA, e.what(), typeid(e).name(), IDP_INTERFACE_VERSION, ph.version,
				pfunc, *reinterpret_cast<PDWORD64>(pfunc), "IDA.WLL",
				modinfo.lpBaseOfDll, modinfo.SizeOfImage/*DWORD*/, modinfo.EntryPoint,
				"Idag.exe",
				HIWORD(fixednfo.dwFileVersionMS), LOWORD(fixednfo.dwFileVersionMS),
				HIWORD(fixednfo.dwFileVersionLS), LOWORD(fixednfo.dwFileVersionLS));
#endif // _DEBUG
			pfunc = NULL;
		}
	} // get_func_ptr

public:
	func0_ptr_type pget_repeatable_cmt, pget_any_indented_cmt;

	IDAWLL_FUNCPTRS() : pget_repeatable_cmt(0), pget_any_indented_cmt(0) {
#ifdef __X64__ // 64-bit kernel
		if ((hIdaWll = GetModuleHandle("IDA64.WLL")) == NULL)
#endif // 64-bit kernel
		hIdaWll = GetModuleHandle("IDA.WLL");
		_ASSERTE(hIdaWll != NULL);
		if (hIdaWll == NULL) {
			//error("%s(): hIdaWll == NULL!", __FUNCTION__);
			return;
		}
		static const struct RVA_table_t {
			func0_ptr_type &pfun;
			DWORD RVA;
			DWORD64 FirstQword;
			size_t size;
		} RVA_table[] = {
			// checksums in ida.wll are dangerous as offsets are relocated and may vary
			// from instance to instance (mismatches report only)
#ifdef __X64__ // 64-bit kernel (IDA64.WLL)
			// version 5.2.0.908
			pget_repeatable_cmt, 0x6C1E8, 0xFFFBE0C481EC8B55, 273,
			pget_any_indented_cmt, 0x6C2FC, 0xFFFBE4C481EC8B55, 219,
			// version 5.1.0.899
			pget_repeatable_cmt, 0x9A644, 0xFFFBE0C481EC8B55, 495,
			pget_any_indented_cmt, 0x9A758, 0xFFFBE4C481EC8B55, 219,
#endif // 64-bit kernel
			// (IDA.WLL)
			// version 5.2.0.908
			pget_repeatable_cmt, 0x63688, 0xFFFBFCC481575653, 195,
			pget_any_indented_cmt, 0x6374C, 0xFFFFFBF4C4815653, 170,
			// version 5.1.0.899
			/*
			get_repeatable_cmt
			.100875E4: 53               push        ebx
			.100875E5: 56               push        esi
			.100875E6: 57               push        edi
			.100875E7: 81C4FCFBFFFF     add         esp,0FFFFFBFC
			.100875ED: 8BF0             mov         esi,eax
			.100875EF: 8BDE             mov         ebx,esi
			.100875F1: 6A01             push        001
			.100875F3: 53               push        ebx
			.100875F4: E89FDEFFFF       call        get_flags_ex  ---  (1)
			.100875F9: 8BF8             mov         edi,eax
			.100875FB: 81E700060000     and         edi,000000600
			.10087601: 81FF00020000     cmp         edi,000000200  ---  (2)
			.10087607: 0F94C0           sete        al
			.1008760A: 83E001           and         eax,001 ;" "
			.1008760D: 84C0             test        al,al
			.1008760F: 7408             je         .010087619  ---  (3)
			.10087611: 53               push        ebx
			.10087612: E8B9F0FFFF       call        prev_not_tail  ---  (4)
			.10087617: 8BD8             mov         ebx,eax
			.10087619: 8BF3             mov         esi,ebx
			.1008761B: 8BDE             mov         ebx,esi
			.1008761D: 6A01             push        001
			.1008761F: 53               push        ebx
			.10087620: E873DEFFFF       call        get_flags_ex  ---  (5)
			.10087625: 8BD0             mov         edx,eax
			.10087627: 8BCA             mov         ecx,edx
			.10087629: 81E100060000     and         ecx,000000600
			.1008762F: 81F900060000     cmp         ecx,000000600
			.10087635: 0F94C1           sete        cl
			.10087638: 83E101           and         ecx,001 ;" "
			.1008763B: 84C9             test        cl,cl
			.1008763D: 7408             je         .010087647  ---  (1)
			.1008763F: F7C200000010     test        edx,010000000
			.10087645: 7504             jne        .01008764B  ---  (2)
			.10087647: 33D2             xor         edx,edx
			.10087649: EB05             jmps       .010087650  ---  (3)
			.1008764B: BA01000000       mov         edx,000000001  ---  (4)
			.10087650: 84D2             test        dl,dl
			.10087652: 7417             je         .01008766B  ---  (5)
			.10087654: 56               push        esi
			.10087655: E8A267FBFF       call        get_func  ---  (6)
			.1008765A: 8BD8             mov         ebx,eax
			.1008765C: 6A01             push        001
			.1008765E: 53               push        ebx
			.1008765F: 683C9F1110       push        010119F3C ;"  Ÿ<"
			.10087664: E8B353FFFF       call        areacb_t_get_area_cmt  ---  (7)
			.10087669: EB32             jmps       .01008769D  ---  (8)
			.1008766B: F6C408           test        ah,008 ;" "
			.1008766E: 742B             je         .01008769B  ---  (9)
			.10087670: 8BDE             mov         ebx,esi
			.10087672: 8BFB             mov         edi,ebx
			.10087674: 893C24           mov         [esp],edi
			.10087677: 6A53             push        053
			.10087679: 6800040000       push        000000400  ---  (A)
			.1008767E: 8D44240C         lea         eax,[esp][0C]
			.10087682: 50               push        eax
			.10087683: 6A01             push        001
			.10087685: 57               push        edi
			.10087686: E81DA40300       call        netnode_supstr  ---  (1)
			.1008768B: 85C0             test        eax,eax
			.1008768D: 7E0C             jle        .01008769B  ---  (2)
			.1008768F: 8D542404         lea         edx,[esp][04]
			.10087693: 52               push        edx
			.10087694: E8BFB6FDFF       call        qstrdup  ---  (3)
			.10087699: EB02             jmps       .01008769D  ---  (4)
			.1008769B: 33C0             xor         eax,eax
			.1008769D: 81C404040000     add         esp,000000404  ---  (5)
			.100876A3: 5F               pop         edi
			.100876A4: 5E               pop         esi
			.100876A5: 5B               pop         ebx
			.100876A6: C3               retn
			.100876A7: 90               nop
			get_any_indented_cmt
			.100876A8: 53               push        ebx
			.100876A9: 56               push        esi
			.100876AA: 81C4F4FBFFFF     add         esp,0FFFFFBF4
			.100876B0: 8BF2             mov         esi,edx
			.100876B2: 8BD8             mov         ebx,eax
			.100876B4: C60602           mov         b,[esi],002 ;" "
			.100876B7: 6800040000       push        000000400  ---  (6)
			.100876BC: 8D442404         lea         eax,[esp][04]
			.100876C0: 50               push        eax
			.100876C1: 6A00             push        000
			.100876C3: 53               push        ebx
			.100876C4: E893FEFFFF       call        get_cmt  ---  (7)
			.100876C9: 85C0             test        eax,eax
			.100876CB: 7E08             jle        .0100876D5  ---  (1)
			.100876CD: 54               push        esp
			.100876CE: E885B6FDFF       call        qstrdup  ---  (2)
			.100876D3: EB74             jmps       .010087749  ---  (3)
			.100876D5: F6050B00121001   test        b,[1012000B],001 ;" "
			.100876DC: 0F95C2           setne       dl
			.100876DF: 83E201           and         edx,001 ;" "
			.100876E2: 84D2             test        dl,dl
			.100876E4: 7461             je         .010087747  ---  (4)
			.100876E6: 6800040000       push        000000400  ---  (5)
			.100876EB: 8D4C2404         lea         ecx,[esp][04]
			.100876EF: 51               push        ecx
			.100876F0: 6A01             push        001
			.100876F2: 53               push        ebx
			.100876F3: E864FEFFFF       call        get_cmt  ---  (6)
			.100876F8: 85C0             test        eax,eax
			.100876FA: 7E08             jle        .010087704  ---  (7)
			.100876FC: 54               push        esp
			.100876FD: E856B6FDFF       call        qstrdup  ---  (8)
			.10087702: EB45             jmps       .010087749  ---  (9)
			.10087704: C60603           mov         b,[esi],003 ;" "
			.10087707: 8BF3             mov         esi,ebx
			.10087709: 6A01             push        001
			.1008770B: 56               push        esi
			.1008770C: 8D842408040000   lea         eax,[esp][00000408]
			.10087713: 50               push        eax
			.10087714: E8238E0000       call        xrefblk_t_first_from  ---  (A)
			.10087719: 84C0             test        al,al
			.1008771B: 742A             je         .010087747  ---  (1)
			.1008771D: F6059066121080   test        b,[10126690],080 ;"_"
			.10087724: 7510             jne        .010087736  ---  (2)
			.10087726: 8B842404040000   mov         eax,[esp][00000404]
			.1008772D: E8B2FEFFFF       call       .0100875E4  ---  (3)
			.10087732: 85C0             test        eax,eax
			.10087734: 7513             jne        .010087749  ---  (4)
			.10087736: 8D942400040000   lea         edx,[esp][00000400]
			.1008773D: 52               push        edx
			.1008773E: E87D8E0000       call        xrefblk_t_next_from  ---  (5)
			.10087743: 84C0             test        al,al
			.10087745: 75D6             jne        .01008771D  ---  (6)
			.10087747: 33C0             xor         eax,eax
			.10087749: 81C40C040000     add         esp,00000040C  ---  (7)
			.1008774F: 5E               pop         esi
			.10087750: 5B               pop         ebx
			.10087751: C3               retn
			*/
			pget_repeatable_cmt, 0x875E4, 0xFFFBFCC481575653, 195,
			pget_any_indented_cmt, 0x876A8, 0xFFFFFBF4C4815653, 170,
			// version 5.0.0.879
			/*
			.text:00ABDB38                   ; Exported entry 161. get_cmt
			.text:00ABDB38                   ; --------------- S U B R O U T I N E ---------------------------------------
			.text:00ABDB38                   ; Attributes: bp-based frame
			.text:00ABDB38                       public get_cmt
			.text:00ABDB38                   get_cmt proc near ; get_any_indented_cmt+1Cp ...
			.text:00ABDB38                   ...
			.text:00ABDBBC                   get_cmt endp
			.text:00ABDBBC
			.text:00ABDBBF 90                    align 4
			.text:00ABDBC0
			.text:00ABDBC0                   ; --------------- S U B R O U T I N E ---------------------------------------
			.text:00ABDBC0                   get_repeatable_cmt proc near         ; CODE XREF: get_any_indented_cmt+7Cp (0x2DBC0)
			.text:00ABDBC0
			.text:00ABDBC0                   var_404= dword ptr -404h
			.text:00ABDBC0                   var_400= dword ptr -400h
			.text:00ABDBC0
			.text:00ABDBC0 53                    push ebx
			.text:00ABDBC1 56                    push esi
			.text:00ABDBC2 57                    push edi
			.text:00ABDBC3 81 C4 FC FB FF FF     add esp, 0FFFFFBFCh
			.text:00ABDBC9 8B F0                 mov esi, eax
			.text:00ABDBCB 8B DE                 mov ebx, esi
			.text:00ABDBCD 6A 01                 push 1
			.text:00ABDBCF 53                    push ebx
			.text:00ABDBD0 E8 0B DF FF FF        call get_flags_ex
			.text:00ABDBD5 8B F8                 mov edi, eax
			.text:00ABDBD7 81 E7 00 06 00 00     and edi, 600h
			.text:00ABDBDD 81 FF 00 02 00 00     cmp edi, 200h
			.text:00ABDBE3 0F 94 C0              setz al
			.text:00ABDBE6 83 E0 01              and eax, 1
			.text:00ABDBE9 84 C0                 test al, al
			.text:00ABDBEB 74 08                 jz  short loc_ABDBF5
			.text:00ABDBED 53                    push ebx
			.text:00ABDBEE E8 75 F1 FF FF        call prev_not_tail
			.text:00ABDBF3 8B D8                 mov ebx, eax
			.text:00ABDBF5                   loc_ABDBF5:                   ; CODE XREF: get_repeatable_cmt+2Bj
			.text:00ABDBF5 8B F3                 mov esi, ebx
			.text:00ABDBF7 8B DE                 mov ebx, esi
			.text:00ABDBF9 6A 01                 push 1
			.text:00ABDBFB 53                    push ebx
			.text:00ABDBFC E8 DF DE FF FF        call get_flags_ex
			.text:00ABDC01 8B D0                 mov edx, eax
			.text:00ABDC03 8B CA                 mov ecx, edx
			.text:00ABDC05 81 E1 00 06 00 00     and ecx, 600h
			.text:00ABDC0B 81 F9 00 06 00 00     cmp ecx, 600h
			.text:00ABDC11 0F 94 C1              setz cl
			.text:00ABDC14 83 E1 01              and ecx, 1
			.text:00ABDC17 84 C9                 test cl, cl
			.text:00ABDC19 74 08                 jz  short loc_ABDC23
			.text:00ABDC1B F7 C2 00 00 00 10     test edx, 10000000h
			.text:00ABDC21 75 04                 jnz short loc_ABDC27
			.text:00ABDC23                   loc_ABDC23:                   ; CODE XREF: get_repeatable_cmt+59j
			.text:00ABDC23 33 D2                 xor edx, edx
			.text:00ABDC25 EB 05                 jmp short loc_ABDC2C
			.text:00ABDC27                   loc_ABDC27:                   ; CODE XREF: get_repeatable_cmt+61j
			.text:00ABDC27 BA 01 00 00 00        mov edx, 1
			.text:00ABDC2C                   loc_ABDC2C:                   ; CODE XREF: get_repeatable_cmt+65j
			.text:00ABDC2C 84 D2                 test dl, dl
			.text:00ABDC2E 74 17                 jz  short loc_ABDC47
			.text:00ABDC30 56                    push esi
			.text:00ABDC31 E8 4A 15 06 00        call get_func
			.text:00ABDC36 8B D8                 mov ebx, eax
			.text:00ABDC38 6A 01                 push 1
			.text:00ABDC3A 53                    push ebx
			.text:00ABDC3B 68 AC 59 BA 00        push offset funcs
			.text:00ABDC40 E8 0F 59 FF FF        call areacb_t_get_area_cmt
			.text:00ABDC45 EB 32                 jmp short loc_ABDC79
			.text:00ABDC47                   loc_ABDC47:                   ; CODE XREF: get_repeatable_cmt+6Ej
			.text:00ABDC47 F6 C4 08              test ah, 8
			.text:00ABDC4A 74 2B                 jz  short loc_ABDC77
			.text:00ABDC4C 8B DE                 mov ebx, esi
			.text:00ABDC4E 8B FB                 mov edi, ebx
			.text:00ABDC50 89 3C 24              mov [esp+404h+var_404], edi
			.text:00ABDC53 6A 53                 push 53h
			.text:00ABDC55 68 00 04 00 00        push 400h
			.text:00ABDC5A 8D 44 24 0C           lea eax, [esp+40Ch+var_400]
			.text:00ABDC5E 50                    push eax
			.text:00ABDC5F 6A 01                 push 1
			.text:00ABDC61 57                    push edi
			.text:00ABDC62 E8 15 15 02 00        call netnode_supstr
			.text:00ABDC67 85 C0                 test eax, eax
			.text:00ABDC69 7E 0C                 jle short loc_ABDC77
			.text:00ABDC6B 8D 54 24 04           lea edx, [esp+404h+var_400]
			.text:00ABDC6F 52                    push edx
			.text:00ABDC70 E8 3B 67 08 00        call qstrdup
			.text:00ABDC75 EB 02                 jmp short loc_ABDC79
			.text:00ABDC77                   loc_ABDC77:                   ; CODE XREF: get_repeatable_cmt+8Aj
			.text:00ABDC77                                                 ; get_repeatable_cmt+A9j
			.text:00ABDC77 33 C0                 xor eax, eax
			.text:00ABDC79                   loc_ABDC79:                   ; CODE XREF: get_repeatable_cmt+85j
			.text:00ABDC79                                                 ; get_repeatable_cmt+B5j
			.text:00ABDC79 81 C4 04 04 00 00     add esp, 404h
			.text:00ABDC7F 5F                    pop edi
			.text:00ABDC80 5E                    pop esi
			.text:00ABDC81 5B                    pop ebx
			.text:00ABDC82 C3                    retn
			.text:00ABDC82                   get_repeatable_cmt endp
			.text:00ABDC82
			.text:00ABDC83 90                    align 4
			.text:00ABDC84
			.text:00ABDC84                   ; --------------- S U B R O U T I N E ---------------------------------------
			.text:00ABDC84                   get_any_indented_cmt proc near         ; CODE XREF: func111+1Ap (0x2DC84)
			.text:00ABDC84
			.text:00ABDC84                   var_40C= dword ptr -40Ch
			.text:00ABDC84                   var_C= dword ptr -0Ch
			.text:00ABDC84                   var_8= dword ptr -8
			.text:00ABDC84
			.text:00ABDC84 53                    push ebx
			.text:00ABDC85 56                    push esi
			.text:00ABDC86 81 C4 F4 FB FF FF     add esp, 0FFFFFBF4h
			.text:00ABDC8C 8B F2                 mov esi, edx
			.text:00ABDC8E 8B D8                 mov ebx, eax
			.text:00ABDC90 C6 06 02              mov byte ptr [esi], 2
			.text:00ABDC93 68 00 04 00 00        push 400h
			.text:00ABDC98 8D 44 24 04           lea eax, [esp+410h+var_40C]
			.text:00ABDC9C 50                    push eax
			.text:00ABDC9D 6A 00                 push 0
			.text:00ABDC9F 53                    push ebx
			.text:00ABDCA0 E8 93 FE FF FF        call get_cmt
			.text:00ABDCA5 85 C0                 test eax, eax
			.text:00ABDCA7 7E 08                 jle short loc_ABDCB1
			.text:00ABDCA9 54                    push esp
			.text:00ABDCAA E8 01 67 08 00        call qstrdup
			.text:00ABDCAF EB 6B                 jmp short loc_ABDD1C
			.text:00ABDCB1                   loc_ABDCB1:                   ; CODE XREF: get_any_indented_cmt+23j
			.text:00ABDCB1 F6 05 57 BA BA 00+    test byte_BABA57, 1
			.text:00ABDCB8 0F 95 C2              setnz dl
			.text:00ABDCBB 83 E2 01              and edx, 1
			.text:00ABDCBE 84 D2                 test dl, dl
			.text:00ABDCC0 74 58                 jz  short loc_ABDD1A
			.text:00ABDCC2 68 00 04 00 00        push 400h
			.text:00ABDCC7 8D 4C 24 04           lea ecx, [esp+410h+var_40C]
			.text:00ABDCCB 51                    push ecx
			.text:00ABDCCC 6A 01                 push 1
			.text:00ABDCCE 53                    push ebx
			.text:00ABDCCF E8 64 FE FF FF        call get_cmt
			.text:00ABDCD4 85 C0                 test eax, eax
			.text:00ABDCD6 7E 08                 jle short loc_ABDCE0
			.text:00ABDCD8 54                    push esp
			.text:00ABDCD9 E8 D2 66 08 00        call qstrdup
			.text:00ABDCDE EB 3C                 jmp short loc_ABDD1C
			.text:00ABDCE0                   loc_ABDCE0:                   ; CODE XREF: get_any_indented_cmt+52j
			.text:00ABDCE0 C6 06 03              mov byte ptr [esi], 3
			.text:00ABDCE3 8B F3                 mov esi, ebx
			.text:00ABDCE5 6A 01                 push 1
			.text:00ABDCE7 56                    push esi
			.text:00ABDCE8 8D 84 24 08 04 00+    lea eax, [esp+414h+var_C]
			.text:00ABDCEF 50                    push eax
			.text:00ABDCF0 E8 63 4F 00 00        call xrefblk_t_first_from
			.text:00ABDCF5 84 C0                 test al, al
			.text:00ABDCF7 74 21                 jz  short loc_ABDD1A
			.text:00ABDCF9                   loc_ABDCF9:                   ; CODE XREF: get_any_indented_cmt+94j
			.text:00ABDCF9 8B 84 24 04 04 00+    mov eax, [esp+40Ch+var_8]
			.text:00ABDD00 E8 BB FE FF FF        call get_repeatable_cmt
			.text:00ABDD05 85 C0                 test eax, eax
			.text:00ABDD07 75 13                 jnz short loc_ABDD1C
			.text:00ABDD09 8D 94 24 00 04 00+    lea edx, [esp+40Ch+var_C]
			.text:00ABDD10 52                    push edx
			.text:00ABDD11 E8 C6 4F 00 00        call xrefblk_t_next_from
			.text:00ABDD16 84 C0                 test al, al
			.text:00ABDD18 75 DF                 jnz short loc_ABDCF9
			.text:00ABDD1A                   loc_ABDD1A:                   ; CODE XREF: get_any_indented_cmt+3Cj
			.text:00ABDD1A                                                 ; get_any_indented_cmt+73j
			.text:00ABDD1A 33 C0                 xor eax, eax
			.text:00ABDD1C                   loc_ABDD1C:                   ; CODE XREF: get_any_indented_cmt+2Bj
			.text:00ABDD1C                                                 ; get_any_indented_cmt+5Aj
			.text:00ABDD1C                                                 ; get_any_indented_cmt+83j
			.text:00ABDD1C 81 C4 0C 04 00 00     add esp, 40Ch
			.text:00ABDD22 5E                    pop esi
			.text:00ABDD23 5B                    pop ebx
			.text:00ABDD24 C3                    retn
			.text:00ABDD24                   get_any_indented_cmt endp
			*/
			pget_repeatable_cmt, 0x2DBC0, 0xFFFBFCC481575653, 195/*, 0x5AFED089, "a64f81ff18c9f620f6c3b07b5795e19d"*/,
			pget_any_indented_cmt, 0x2DC84, 0xFFFFFBF4C4815653, 161/*, 0x3A8E9085, "e3b25650b3218a9246119435d91b7a71"*/,
			// version 4.9
			pget_repeatable_cmt, 0xB58D4, 0xFFFBFCC481575653/*???*/, 195/*?*/,
			pget_any_indented_cmt, 0xB5998, 0xFFFFFBF4C4815653/*???*/, 161/*?*/,
		}; // RVA_table
		for (const RVA_table_t *it = RVA_table; it != RVA_table + qnumber(RVA_table); ++it)
			get_func_ptr(it->pfun, it->RVA, it->FirstQword, it->size);
#ifdef _DEBUG
		if (pget_repeatable_cmt != 0) OutputDebugString("%s(): internal %s at %08X and verified\n",
			__FUNCTION__, "get_repeatable_cmt", pget_repeatable_cmt);
		if (pget_any_indented_cmt != 0) OutputDebugString("%s(): internal %s at %08X and verified\n",
			__FUNCTION__, "get_any_indented_cmt", pget_any_indented_cmt);
#endif // _DEBUG
	}
} func_ptrs;

HMODULE IDAWLL_FUNCPTRS::hIdaWll;

char *get_repeatable_cmt(ea_t ea) {
	if (func_ptrs.pget_repeatable_cmt == 0) return 0/*get_cmt(ea, true)*/;
	__asm {
		mov eax, ea
		call dword ptr [func_ptrs.pget_repeatable_cmt]
	}
}

char *get_any_indented_cmt(ea_t ea, color_t *cmttype) {
	if (func_ptrs.pget_any_indented_cmt == 0) return 0/*get_cmt(ea, false)*/;
	__asm {
		mov eax, ea
		mov edx, cmttype
		call dword ptr [func_ptrs.pget_any_indented_cmt]
	}
}

#else // IDP_INTERFACE_VERSION < 76

#include "undbgnew.h"
#include <stdexcept>
#include <typeinfo>
#include "dbgnew.h"

#define COMMON_PROLOGUE if (buf != 0 && bufsize > 0) memset(buf, 0, bufsize);
#ifdef _DEBUG
#	define ADAPTOR(type, theCall) return ida::safe_##type##_call(buf, theCall, bufsize, __FUNCTION__);
#else
#	define ADAPTOR(type, theCall) return ida::safe_##type##_call(buf, theCall, bufsize);
#endif // _DEBUG

namespace ida {

ssize_t safe_string_call(char *buf, const char *s, size_t bufsize
#ifdef _DEBUG
	, const char *funcname
#endif
	) {
	COMMON_PROLOGUE
	if (s == 0) return -1;
	if (buf == 0) {
		__try {
			bufsize = strlen(s);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			bufsize = 0;
		}
		return bufsize;
	}
	__try { qstrncpy(buf, s, bufsize); } __except(EXCEPTION_EXECUTE_HANDLER) { }
	return strlen(buf);
}

static size_t explore_allocation_size(const void *pv, size_t bufsize) {
	_ASSERTE(pv != 0);
	_ASSERTE(bufsize > 0);
	size_t passed(0);
	if (pv != 0 && bufsize > 0) __try {
		__asm {
			mov esi, pv
			mov ecx, bufsize
		explore_allocation_size_loop:
			lodsb
			inc passed
			loop explore_allocation_size_loop
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) { }
	_ASSERTE(passed <= bufsize);
	return passed;
}

ssize_t safe_void_call(void *buf, const void *v, size_t bufsize
#ifdef _DEBUG
	, const char *funcname
#endif
	) {
	COMMON_PROLOGUE
	if (v == 0) return -1;
	if (buf != 0 && bufsize > 0) try {
		if (memcpy(buf, v, bufsize) == 0) throw std::logic_error("memcpy(...) failed");
	} catch (const std::exception &e) {
		size_t tmp;
		bufsize = typeid(e) == typeid(se_exception)
			&& static_cast<const se_exception &>(e).GetCode() == EXCEPTION_ACCESS_VIOLATION
			&& static_cast<const se_exception &>(e).GetException().NumberParameters >= 2
			&& (tmp = (LPBYTE)static_cast<const se_exception &>(e).GetException().ExceptionInformation[1] - (LPBYTE)v) < bufsize ?
				tmp : explore_allocation_size(v, bufsize);
		_RPT4(_CRT_WARN, "%s(...): caught exception: %s (%s): returning %u\n",
			funcname, e.what(), typeid(e).name(), bufsize);
	} catch (...) {
		bufsize = explore_allocation_size(v, bufsize);
		_RPT2(_CRT_WARN, "%s(...): caught exception: returning %u\n",
			funcname, bufsize);
	}
	return bufsize;
}

} // namespace ida

ssize_t get_array_parameters(ea_t ea, array_parameters_t *buf, size_t bufsize) {
	_ASSERTE(isEnabled(ea));
	if (buf == 0 || bufsize > sizeof array_parameters_t)
		bufsize = sizeof array_parameters_t;
	ADAPTOR(void, get_array_parameters(ea))
}

#define B2A(n) \
	COMMON_PROLOGUE \
	const char *const s = btoa##n(x, radix); \
	return strlen(buf != 0 ? qstrncpy(buf, s, bufsize) : s);
size_t btoa32 (char *buf, size_t bufsize, ulong x,     int radix) { B2A( 32) }
size_t btoa64 (char *buf, size_t bufsize, ulonglong x, int radix) { B2A( 64) }
size_t btoa128(char *buf, size_t bufsize, uint128 x,   int radix) { B2A(128) }
#undef B2A

#undef COMMON_PROLOGUE
#undef ADAPTOR

#endif // IDP_INTERFACE_VERSION
