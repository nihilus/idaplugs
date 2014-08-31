;
; Common Win32 application prologue, external library references and macros
; by servil <servil@gmx.net>, (c) 2002-2003
; parts taken from template.inc concluded in MASM32v8 distribution
;

ifndef _masm_inc_
_masm_inc_ = 1

; /////////////////////////// Common prologue ///////////////////////////
.686p
.mmx
.k3d
.xmm
.model flat, stdcall
option casemap: none	; case sensitive
option proc: private
option language: stdcall
assume es: nothing
assume fs: nothing
assume gs: nothing

; /////////////////////////// Defines ///////////////////////////
; WIN32 = 1
; _WINDOWS = 1

; /////////////////////////// Common includes ///////////////////////////
;	include files
;	~~~~~~~~~~~~~
include <WINDOWS.INC>
include <MASM32.INC>
include <MACROS.INC>
;include <NTSTATUS.INC>

; ================== Windows API ==================

include <KERNEL32.INC>
include <USER32.INC>
include <ADVAPI32.INC>
include <SHELL32.INC>
include <GDI32.INC>
include <COMCTL32.INC>
include <COMDLG32.INC>
include <WINSPOOL.INC>
include <OLEAUT32.INC>
include <OLE32.INC>
include <PSAPI.INC>
include <NTDLL.INC>
include <WINMM.INC>
include <WSOCK32.INC>
include <VERSION.INC>
include <MSACM32.INC>
include <DSOUND.INC>
include <MPR.INC>

; /////////////////////////// Common libraries ///////////////////////////
;	libraries
;	~~~~~~~~~
ifndef _LIB
includelib MASM32.LIB
includelib FPU.LIB
; Windows API
includelib KERNEL32.LIB
includelib USER32.LIB
includelib ADVAPI32.LIB
includelib SHELL32.LIB
includelib GDI32.LIB
includelib COMCTL32.LIB
includelib COMDLG32.LIB
includelib WINSPOOL.LIB
includelib OLE32.LIB
includelib OLEAUT32.LIB
;includelib NTDLL.LIB
includelib PSAPI.LIB
includelib WINMM.LIB
includelib WSOCK32.LIB
includelib VERSION.LIB
;includelib NTOSKRNL.LIB
includelib MSACM32.LIB
includelib DSOUND.LIB
endif ; !_LIB

; /////////////////////////// Common function prototypes ///////////////////////////
;=================
; Local prototypes
;=================
WinMain          proto hWnd: HWND, uMsg: UINT, wParam: WPARAM, lParam: LPARAM
WndProc          proto hWnd: HWND, uMsg: UINT, wParam: WPARAM, lParam: LPARAM
DialogProc       proto hWnd: HWND, uMsg: UINT, wParam: WPARAM, lParam: LPARAM
TopXY            proto :dword, :dword
Paint_Proc       proto :dword
RegisterWinClass proto :dword, :dword, :dword, :dword, :dword
MsgLoop          proto
Main             proto

; /////////////////////////// Public variables ///////////////////////////

; .data?
; 	align dword
; 	hInstance dd ?
; 	CommandLine dd ?
; 	hIcon dd ?
; 	hCursor dd ?
; 	sWid dd ?
; 	sHgt dd ?
; 	hWnd dd ?

; /////////////////////////// Public constants ///////////////////////////
; --------------------------------------------
; equates to use directly in the message loop
; --------------------------------------------
	m_hWnd   equ <msg.hwnd>
	m_Msg    equ <msg.message>
	m_wParam equ <msg.wParam>
	m_lParam equ <msg.lParam>

	_NUL     equ 00h	; null (end of string)
	_SOH     equ 01h	; start of heading
	_STX     equ 02h	; start of text
	_ETX     equ 03h	; end of text
	_EOT     equ 04h	; end of transmission
	_ENQ     equ 05h	; enquiry
	_ACK     equ 06h	; acknowledge
	_BEL     equ 07h	; bell
	_BS      equ 08h	; backspace
	_HT      equ 09h	; TAB horizontal tab
	_TAB     equ _HT	; TAB horizontal tab
	_LF      equ 0Ah	; line feed
	_VT      equ 0Bh	; vertical tab
	_FF      equ 0Ch	; form feed
	_CR      equ 0Dh	; carriage return
	_SO      equ 0Eh	; shift out
	_SI      equ 0Fh	; shift in
	_DLE     equ 10h	; data line escape
	_DC1     equ 11h	; device ctrl 1 (X-ON)
	_DC2     equ 12h	; device ctrl 2
	_DC3     equ 13h	; device ctrl 3 (X-OFF)
	_DC4     equ 14h	; device ctrl 4
	_NAK     equ 15h	; negative acknowledge
	_SYN     equ 16h	; synchronous idle
	_ETB     equ 17h	; end of transmit block
	_CAN     equ 18h	; cancel
	_EM      equ 19h	; end of medium
	_SUB     equ 1Ah	; substitute
	_EOF     equ 26		; end of file
	_ESC     equ 1Bh	; escape
	_FS      equ 1Ch	; file separator
	_GS      equ 1Dh	; group separator
	_RS      equ 1Eh	; record separator
	_US      equ 1Fh	; unit separator

	_CRLF     equ _CR, _LF

; /////////////////////////// Macro definitions ///////////////////////////
;=============
; Local macros
;=============

szText macro Name: req, Text: vararg
.const
	Name db Text, 0
.code @code
endm

; -------------------------------------------
; put zero terminated string in .const section
; alternative to the szText MACRO
; -------------------------------------------
dsText macro Name: req, Text: vararg
.const
	Name db Text, 0
.code @code
endm

m2m macro M1, M2
	push M2
	pop M1
endm

Bytes macro Values: vararg
local cbSequence
.const
	cbSequence db Values
.code @code
	exitm <offset cbSequence>
endm

Words macro Values: vararg
local cwSequence
.const
	cwSequence dw Values
.code @code
	exitm <offset cwSequence>
endm

Dwords macro Values: vararg
local cdSequence
.const
	cdSequence dd Values
.code @code
	exitm <offset cdSequence>
endm

; -------------------------------
; make 2 WORD values into a dword
; result in eax
; -------------------------------
MAKEDWORD macro LoWord, HiWord
	exitm <HiWord * 010000h + LoWord>
	; mov ax, HiWord
	; ror eax, 16
	; mov ax, LoWord
endm

; -----------------------------
; return IMMEDIATE value in eax
; -----------------------------
retval macro var
	if var eq 0
		xor eax, eax ; slightly more efficient for zero
	elseif var eq 1
		xor eax, eax ; slightly more efficient for one
		inc eax
	elseif var ge -80h and var lt 80h
		push var     ; slightly more efficient for signed byte values
		pop eax
	else
		mov eax, var ; place value in eax
	endif
endm

return macro arg: req
	retval arg
	ret
endm

; ----------------------------
; faster C functions emulation
; ----------------------------
MEMCPY macro lpDest, lpSource, len
	mov esi, lpSource
	mov edi, lpDest
	mov ecx, len
	cld
	rep movsb
endm

MEMCMP macro lpBuff1, lpBuff2, len
	xor eax, eax
	mov esi, lpBuff1
	mov edi, lpBuff2
	mov ecx, len
	cld
	repz cmpsb
	setnz al
	neg eax
	exitm <eax>
endm

MEMSET macro lpDest, value, len
	mov al, value
	mov edi, lpDest
	mov ecx, len
	cld
	rep stosb
endm

; ------------------------
; inline memory copy macro
; ------------------------
Mcopy macro lpSource, lpDest, len
	MEMCPY lpDest, lpSource, len
endm

; ------------------------------------------------------
; macro for concantenating strings using the szMultiCat
; procedure written by Alexander Yackubtchik.
;
; USAGE STRCAT buffer,str1,str2,str3 etc ...
;
; buffer must be large enough to contain all of the
; strings to append. Limit is set by maximum line
; length in MASM.
; ------------------------------------------------------
STRCAT macro arguments: vararg
	txt equ <invoke szMultiCat,>        ;; lead string
	pcount = 0
		for arg, <arguments>
			pcount = pcount + 1             ;; count arguments
		endm
	% pcount = pcount - 1               ;; dec 1 for 1st arg
	txt CATSTR txt,%pcount              ;; append number to lead string
		for arg, <arguments>
			if @InStr(1,<arg>,<addr>) ne 0
				txt CATSTR txt, <,arg>
			else
				txt CATSTR txt, <,addr arg>   ;; append 'ADDR' + args
			endif
		endm
	txt                                 ;; put result in code
endm

STRSTR macro szString, szPattern
local @@done
local @@takenext
local @@loop
local @@notfound

	mov edi, szPattern
	mov esi, szString
	cmp byte ptr edi, 0
	jz @@done
	mov ecx, 0FFFFFFFFh
	cld
@@takenext:
	mov edi, szPattern
@@loop:
	cmp byte ptr esi, 0
	jz @@notfound
	cmpsb
	jz @@loop
	jmp @@takenext
@@notfound:
	xor esi, esi
@@done:
	exitm <esi>
endm

; ----------------------------------------------------------
; function position macros that takes a DWORD parameter and
; returns the address of the buffer that holds the result
; ----------------------------------------------------------
str$ macro DDvalue
local rvstring
.data
	rvstring db 11 dup (0)
.code @code
	invoke dwtoa, DDvalue, addr rvstring
	exitm <addr rvstring>
endm

hex$ macro DDvalue
local rvstring
.data
	rvstring db 9 dup (0)
.code @code
	invoke dw2hex, DDvalue, addr rvstring
	exitm <addr rvstring>
endm

; -----------------------------------
; INPUT red, green & blue BYTE values
; OUTPUT dword COLORREF value in eax
; -----------------------------------
; RGB macro red, green, blue
; 	xor eax, eax
; 	mov al, blue    ; blue
; 	rol eax, 8
; 	mov al, green   ; green
; 	rol eax, 8
; 	mov al, red     ; red
; endm
;  REM: Original macro redefined
RGB macro red, green, blue
	exitm <010000h * blue + 0100h * green + red>
endm

; ------------------------------------------------
; The following macro were written by Ron Thomas
; ------------------------------------------------
; Retrieves the low word from double word argument
; ------------------------------------------------
LOWORD macro bigword
	exitm <bigword and 0FFFFh>
	; mov  eax, bigword
	; and  eax,0FFFFh     ;; Set to low word
endm

HIWORD macro bigword
	exitm <(bigword and 0FFFF0000h) / 010000h>
endm

BSADD macro variable: req
	mov eax, variable
	bswap eax
	exitm <eax>
endm

; ----------------------
; fast lodsb replacement
; ----------------------
lob macro
	mov al, [esi]
	inc esi
endm

; ----------------------
; fast stosb replacement
; ----------------------
stb macro
	mov [edi], al
	inc edi
endm

; -------------------------------
; pascal calling convention macro
; left to right push
; -------------------------------
Pcall macro name: REQ, items: VARARG
local arg
	FOR arg, <items>
	push arg
endm
	call name
endm

; -------------------------
; initialised GLOBAL value
; -------------------------
IGLOBAL macro variable:VARARG
.data
	variable
.code @code
endm

; --------------------------------
; initialised GLOBAL string value
; --------------------------------
STRING macro variable: REQ, args: vararg
.data
	variable db args, 0
.code @code
endm

; ---------------------
; literal string macro
; ---------------------
literal macro quoted_text: VARARG
local local_text
.const
	local_text db quoted_text, 0
.code @code
	exitm <local_text>
endm

; --------------------------------
; string address in INVOKE format
; --------------------------------
SADD macro quoted_text:VARARG
	exitm <addr literal(quoted_text)>
endm

; -----------------------------------------------------
; string address embedded directly in the code section
; -----------------------------------------------------
CADD macro quoted_text
local vname,lbl
	jmp lbl
	vname db quoted_text,0
	lbl:
	exitm <addr vname>
endm

; --------------------------------
; string OFFSET for manual coding
; --------------------------------
CTXT macro quoted_text: VARARG
	exitm <offset literal(quoted_text)>
endm

; ----------------------------------
; Borland string types compatibility
; ----------------------------------
pliteral macro quoted_text: VARARG
local string
local local_text
.const
local_text db sizeof string
string db quoted_text
.code @code
	exitm <local_text>
endm

lliteral macro quoted_text: VARARG
local local_text
.const
	align 4
	dd 0FFFFFFFFh, sizeof local_text - 1
local_text db quoted_text, 0
.code @code
	exitm <local_text>
endm

PTXT macro name: req, quoted_text: VARARG
local local_text
.const
name db sizeof local_text
local_text db quoted_text
.code @code
endm

LTXT macro name: req, quoted_text: VARARG
.const
	align 4
	dd 0FFFFFFFFh, sizeof name - 1
	name db quoted_text, 0
.code @code
endm

CLTXT macro quoted_text: VARARG
	exitm <offset lliteral(quoted_text)>
endm

CPTXT macro quoted_text: VARARG
	exitm <offset pliteral(quoted_text)>
endm

CPPTXT macro quoted_text: VARARG
local local_pointer
local local_text
local string
.data
	align 4
local_pointer dd offset local_text
.const
local_text db sizeof string
string db quoted_text
.code @code
	exitm <offset local_pointer>
endm

CPLTXT macro quoted_text: VARARG
local local_pointer
local local_text
.data
	align 4
local_pointer dd offset local_text
.const
	align 4
	dd 0FFFFFFFFh, sizeof local_text - 1
local_text db quoted_text, 0
.code @code
	exitm <offset local_pointer>
endm

; --------------------------------------------------
; Two macros for allocating and freeing OLE memory.
; stralloc returns the handle/address of the string
; memory in eax. strfree uses the handle to free
; memory after use.
; NOTE that you must use the following INCLUDE &
; LIB files with these two macros.
; --------------------------------------------------
stralloc macro ln
	invoke SysAllocStringByteLen, 0, ln
endm

strfree macro strhandle
	invoke SysFreeString,strhandle
endm

; ---------------------------------------
; Append literal string to end of buffer
; ---------------------------------------
Append MACRO buffer, text
local szTxt
.const
	szTxt db text, 0
.code @code
	invoke szCatStr, addr buffer, addr szTxt
endm

; ----------------------------------------------------------
; load a library and get the procedure address in one macro
; return value for the proc address in in EAX
; ----------------------------------------------------------
LoadProcAddress macro quoted_text1, quoted_text2
local library_name
local proc_name
.const
	library_name db quoted_text1, 0
	proc_name db quoted_text2, 0
.code @code
	invoke LoadLibrary, offset library_name
	invoke GetProcAddress, eax, offset proc_name
endm

; ---------------------------
; Put ascii zero at 1st byte
; ---------------------------
zero1 macro membuf
	mov membuf[0], 0
endm

; -------------------------
; Application startup code
; -------------------------
AppStart macro
.code @code
start:
	invoke GetModuleHandle, NULL
	mov hInstance, eax

	invoke GetCommandLine
	mov CommandLine, eax

	; invoke InitCommonControls

	invoke WinMain, hInstance, NULL, CommandLine, SW_SHOWDEFAULT
	invoke ExitProcess,eax
endm

ShellAboutBox macro handle,IconHandle,quoted_Text_1,quoted_Text_2:VARARG
local AboutTitle,AboutMsg,buffer
.const
	AboutTitle db quoted_Text_1,0
	AboutMsg   db quoted_Text_2,0
.data
	buffer db 128 dup (0)
.code @code
	mov esi, offset AboutTitle
	mov edi, offset buffer
	mov ecx, lengthof AboutTitle
	rep movsb
	invoke ShellAbout,handle,ADDR buffer,ADDR AboutMsg,IconHandle
endm

; --------------------------------------------------------------
; Specifies processor, memory model & case sensitive option.
; The parameter "Processor" should be in the form ".386" etc..
; EXAMPLE : AppModel .586
; --------------------------------------------------------------
AppModel macro Processor
	Processor             ;; Processor type
	.model flat, stdcall  ;; 32 bit memory model
	option casemap :none  ;; case sensitive
endm

DisplayMenu macro handl, IDnum
	invoke LoadMenu, hInstance,IDnum
	invoke SetMenu, handl, eax
endm

; -----------------------------------------
; Encapsulate a non-changing piece of code
; -----------------------------------------
DisplayWindow macro handl, ShowStyle
	invoke ShowWindow, handl, ShowStyle
	invoke UpdateWindow, handl
endm

AutoScale macro swidth, sheight
	invoke GetPercent, sWid, swidth
	mov Wwd, eax
	invoke GetPercent, sHgt, sheight
	mov Wht, eax
	invoke TopXY, Wwd, sWid
	mov Wtx, eax
	invoke TopXY, Wht, sHgt
	mov Wty, eax
endm

SingleInstanceOnly macro lpClassName
	invoke FindWindow, lpClassName, NULL
	.if eax
		push eax
		invoke ShowWindow, eax, SW_RESTORE
		pop eax
		invoke SetForegroundWindow, eax
		return 0
	.endif
endm

; --------------------------------------------
; The following two macros must be used as a
; pair and can only be used once in a module.
; Additional code for processing within the
; message loop can be placed between them.
;
; The single parameter passed to both macros
; is the name of the MSG structure and must be
; the same in both macros.
; --------------------------------------------

BeginMessageLoop macro mStruct
	MessageLoopStart:
	invoke GetMessage, ADDR mStruct, NULL, 0, 0
	cmp eax, 0
	je MessageLoopExit
endm

EndMessageLoop macro mStruct
	invoke TranslateMessage, ADDR mStruct
	invoke DispatchMessage, ADDR mStruct
	jmp MessageLoopStart
MessageLoopExit:
endm

; --------------------------------------------------------
; MsgBox macro takes 2 parameters, both can be either
; literal text in quotes or addresses of zero terminated
; strings passed with "ADDR szString" where szString is
; a zero terminated string. Note that ADDR is uppercase.
;
; example : MsgBox "Greetings all",ADDR szTitle
;           MsgBox ADDR szMessage,"Result"
;
; --------------------------------------------------------

MsgBox macro handl, TxtMsg, TxtTitle, styl

local Msg1
local Titl

	If @InStr(1,<TxtMsg>,<ADDR>) eq 0
		If @InStr(1,<TxtTitle>,<ADDR>) eq 0
.const
			Msg1 db TxtMsg,0
			Titl db TxtTitle,0
.code @code
			invoke MessageBox,handl,ADDR Msg1,ADDR Titl,styl
			exitm
		EndIf
	EndIf

	If @InStr(1,<TxtMsg>,<ADDR>) gt 0
		If @InStr(1,<TxtTitle>,<ADDR>) eq 0
.const
			Titl db TxtTitle,0
.code @code
			invoke MessageBox,handl,TxtMsg,ADDR Titl,styl
			exitm
		EndIf
	EndIf

	If @InStr(1,<TxtMsg>,<ADDR>) eq 0
		If @InStr(1,<TxtTitle>,<ADDR>) gt 0
.const
		Msg1 db TxtMsg,0
.code @code
			invoke MessageBox,handl,ADDR Msg1,TxtTitle,styl
			exitm
		EndIf
	EndIf

	If @InStr(1,<TxtMsg>,<ADDR>) gt 0
		If @InStr(1,<TxtTitle>,<ADDR>) gt 0
			invoke MessageBox,handl,TxtMsg,TxtTitle,styl
			exitm
		EndIf
	EndIf
endm

; ------------------------------------------------------------------
; macro for making STDCALL procedure and API calls.
; ------------------------------------------------------------------
Scall macro name:REQ,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12, \
	p13,p14,p15,p16,p17,p18,p19,p20,p21,p22
	;; ---------------------------------------
	;; loop through arguments backwards, push
	;; NON blank ones and call the function.
	;; ---------------------------------------
	FOR arg,<p22,p21,p20,p19,p18,p17,p16,p15,p14,p13,\
		p12,p11,p10,p9,p8,p7,p6,p5,p4,p3,p2,p1>
	IFNB <arg>    ;; If not blank
		push arg    ;; push parameter
	ENDIF
	endm
	call name       ;; call the procedure
endm

; ---------------------------------------------------------------------
;
; The GLOBALS macro is for allocating uninitialised data in the .DATA?
; section. It is designed to take multiple definitions to make
; allocating uninitialised data more intuitive while coding.
;
; EXAMPLE: GLOBALS item1 dd ?,\
;                  item2 dd ?,\
;                  item3 dw ?,\
;                  item4 db 128 dup (?)
;
; ---------------------------------------------------------------------
GLOBALS macro var1,var2,var3,var4,var5,var6,var7,var8,var9,var0,
	varA,varB,varC,varD,varE,varF,varG,varH,varI,varJ
.data?
	var1
	var2
	var3
	var4
	var5
	var6
	var7
	var8
	var9
	var0
	varA
	varB
	varC
	varD
	varE
	varF
	varG
	varH
	varI
	varJ
.code @code
endm

; -------------------------------------------------------------------
; The following 2 macros are for limiting the size of a window while
; it is being resized. They are to be used in the WM_SIZING message.
; -------------------------------------------------------------------
LimitWindowWidth macro wdth
local label
	mov eax, lParam
	mov ecx, (RECT PTR [eax]).right
	sub ecx, (RECT PTR [eax]).left
	cmp ecx, wdth
	jg label
	.if wParam == WMSZ_RIGHT || wParam == WMSZ_BOTTOMRIGHT || wParam == WMSZ_TOPRIGHT
		mov ecx, (RECT PTR [eax]).left
		add ecx, wdth
		mov (RECT PTR [eax]).right, ecx
	.elseif wParam == WMSZ_LEFT || wParam == WMSZ_BOTTOMLEFT || wParam == WMSZ_TOPLEFT
		mov ecx, (RECT PTR [eax]).right
		sub ecx, wdth
		mov (RECT PTR [eax]).left, ecx
	.endif
label:
endm

LimitWindowHeight macro whgt
local label
	mov eax, lParam
	mov ecx, (RECT PTR [eax]).bottom
	sub ecx, (RECT PTR [eax]).top
	cmp ecx, whgt
	jg label
	.if wParam == WMSZ_TOP || wParam == WMSZ_TOPLEFT || wParam == WMSZ_TOPRIGHT
		mov ecx, (RECT PTR [eax]).bottom
		sub ecx, whgt
		mov (RECT PTR [eax]).top, ecx
	.elseif wParam == WMSZ_BOTTOM || wParam == WMSZ_BOTTOMLEFT || wParam == WMSZ_BOTTOMRIGHT
		mov ecx, (RECT PTR [eax]).top
		add ecx, whgt
		mov (RECT PTR [eax]).bottom, ecx
	.endif
label:
endm

; ----------------------------------------------
; This set of macros were written by Greg Falen
; ----------------------------------------------
; Switch/Case emulation
; ----------------------
$casflg equ <>
$casvar equ <>
$casstk equ <>

switch macro _var: req, _reg:=<eax>
	mov _reg, _var
	$casstk catstr <_reg>, <#>, $casflg, <#>, $casstk
	$casvar equ _reg
	$casflg equ <0>         ;; 0 = emit an .if, 1 an .elseif
endm

case macro _args:vararg     ;; like Pascal: case id1. id4 .. id8, lparam, ...
							;; does an or (case1 || case2 || case3...)
	$cas textequ <>
	irp $v, <_args>         ;; for each case
		t@ instr <$v>, <..> ;; range ?
		if t@               ;; yes
			$LB substr <$v>, 1, t@-1                  ;; lbound = left portion
			$LB catstr <(>, $casvar, <!>=>, $LB, <)>  ;; ($casvar >= lbound)
			$UB substr <$v>, t@+2                     ;; ubound = right portion
			$UB catstr <(>, $casvar, <!<=>, $UB, <)>  ;; ($casvar <= ubound)
			$t catstr <(>, $LB, <&&> , $UB,<)>        ;; (($casvar >= $lb) && ($casvar <= $ub))
		else    ;; no, it's a value (var/const)
			$t catstr <(>, $casvar, <==>, <$v>, <)>   ;; ($casvar == value)
		endif
		$cas catstr <|| >, $t, $cas                   ;; or this case w/ others
	endm
	$cas substr $cas, 3 ;; lose the extra "|| " in front
	ifidn $casflg, <0> ;; 0 = 1'st case
		% .if $cas ;; emit ".if"
	else ;; all others
		% .elseif $cas ;; emit ".elseif"
	endif
	$casflg equ <1> ;; NOT 1'st
endm

default macro _default: vararg
	.else
	_default
endm

endsw macro _cmd:vararg
	ifidn $casstk, <>
		.err <Endsw w/o Switch>
	else
		t@ instr $casstk, <#>
		$casvar substr $casstk, 1, t@-1
		$casstk substr $casstk, t@+1
		t@ instr $casstk, <#>
		$casflg substr $casstk, 1, t@-1
		ifidn $casstk, <#>
			$casstk equ <>
		else
			$casstk substr $casstk, t@+1
		endif
		.endif
	endif
endm

; ------------------------------------------
; equates for case variation in macro names
; ------------------------------------------
Case equ <case>
CASE equ <case>
Switch equ <switch>
SWITCH equ <switch>
Endsw equ <endsw>
EndSw equ <endsw>
ENDSW equ <endsw>

;  -----------------------------------------------------
;   Macros for declaring named floating point variables
;  -----------------------------------------------------

FLOAT4 macro name, value
.const
	name REAL4 value
.code @code
endm

FLOAT8 macro name, value
.const
	name REAL8 value
.code @code
endm

FLOAT10 macro name, value
.const
	name REAL10 value
.code @code
endm

;  -----------------------------------------------------
;   Macros for directly inserting floating point values
;   into floating point instructions and as parameters
;  -----------------------------------------------------

FP4 macro value
local vname
.const
	vname REAL4 value
.code @code
	exitm <vname>
endm

FP8 macro value
local vname
.const
	vname REAL8 value
.code @code
	exitm <vname>
endm

FP10 macro value
local vname
.const
	vname REAL10 value
.code @code
	exitm <vname>
endm

;   This macro is specifically for programmers who use the
;   different format include files created by l2extia.exe.
;   NOTE : windows.inc MUST be included before and of the
;   include file created with l2extia.exe as they require
;   this macro to expand the parameters.

; #####################################################################
ArgCount MACRO number
	LOCAL txt
	txt equ <typedef PROTO :DWORD>
		REPEAT number - 1
			txt CATSTR txt,<,:DWORD>
		ENDM
	EXITM <txt>
ENDM

pr0  typedef PROTO
pr1  ArgCount(1)
pr2  ArgCount(2)
pr3  ArgCount(3)
pr4  ArgCount(4)
pr5  ArgCount(5)
pr6  ArgCount(6)
pr7  ArgCount(7)
pr8  ArgCount(8)
pr9  ArgCount(9)
pr10 ArgCount(10)
pr11 ArgCount(11)
pr12 ArgCount(12)
pr13 ArgCount(13)
pr14 ArgCount(14)
pr15 ArgCount(15)
pr16 ArgCount(16)
pr17 ArgCount(17)
pr18 ArgCount(18)
pr19 ArgCount(19)
pr20 ArgCount(20)
pr21 ArgCount(21)
pr22 ArgCount(22)
pr23 ArgCount(23)
pr24 ArgCount(24)
pr25 ArgCount(25)

unicode macro name, page, string, zero
name label word
	forc c, <string>
	db '&c', page
	endm
	ifnb <zero>
	dw zero
	endif
endm

endif ; _masm_inc_
