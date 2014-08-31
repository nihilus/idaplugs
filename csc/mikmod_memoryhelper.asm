
comment ~

 mikmod memory helper v0.1 prebeta by _servil_ 2002-2006

 module to supplement MikMod sound library by Miodrag Vallat.
 via MHELPERREADER and MHELPERWRITER objects you can play in-memory modules.
 usage is simple - include this header in your source, initialize the module
 by mh_NewReader/mh_NewReaderFromRsrc function and use Player_LoadGeneric
 func with reference to Reader object. example of usage:

 	#include <mikmod.h>
 	#include "mikmod_memoryhelper.h"
 	.
 	.
 	.
	MREADER *Reader = mh_NewReader(hInstance, hModuleData, dwModuleSize);
	if (Reader != 0) {
		MODULE *Module = Player_LoadGeneric(Reader, 128, 0);
		...

 or

	MREADER *Reader = mh_NewReaderFromRsrc(hInstance,
		MAKEINTRESOURCE(IDR_MODULE), RT_RCDATA);
	...

FROM mikmod.doc:

MREADER

The MREADER contains the following function pointers:
BOOL (*Seek)(struct MREADER*, long offset, int whence)
  This function should have the same behaviour as fseek, with offset 0 meaning
the start of the object (module, sample) being loaded.
long (*Tell)(struct MREADER*)
  This function should have the same behaviour as ftell, with offset 0 meaning
the start of the object being loaded.
BOOL (*Read)(struct MREADER*, void *dest, size_t length)
  This function should copy length bytes of data into dest, and return zero if
an error occured, and any nonzero value otherwise. Note that an end-of-file
condition will not be considered as an error in this case.
int (*Get)(struct MREADER*)
  This function should have the same behaviour as fgetc.
BOOL (*Eof)(struct MREADER*)
  This function should have the same behaviour as feof.

For an example of how to build an MREADER object, please refer to the
MFILEREADER object in file mmio/mmio.c in the library sources.

MWRITER

The MREADER contains the following function pointers:
BOOL (*Seek)(struct MWRITER*, long offset, int whence);
  This function should have the same behaviour as fseek, with offset 0 meaning
the start of the object being written.
long (*Tell)(struct MWRITER*);
  This function should have the same behaviour as ftell, with offset 0 meaning
the start of the object being written.
BOOL (*Write)(struct MWRITER*, void *dest, size_t length);
  This function should copy length bytes of data from dest, and return zero if
an error occured, and any nonzero value otherwise.
BOOL (*Put)(struct MWRITER*, int data);
  This function should have the same behaviour as fputc.

For an example of how to build an MWRITER object, please refer to the
MFILEWRITER object in file mmio/mmio.c in the library sources.
~

_DLL equ 1

include masm.inc

ifdef _LIB
MEMHELPERAPI equ public
else ; !_LIB
MEMHELPERAPI equ export
endif ; _LIB

include vc32decl.inc
include <mikmod\mikmod.inc>

option language: C

option proc: private

.const

	MHELPERREADER struct
		mreader MREADER <?>
		mh_hModule dd ?
		mh_Size dd ?
		mh_Pos dd ?
		mh_Eof db ?
	MHELPERREADER ends

	MHELPERWRITER struct
		mwriter MWRITER <?>
		mh_hModule dd ?
		mh_Size dd ?
		mh_Pos dd ?
	MHELPERWRITER ends

.code _TEXT$1A
mh_NewReader proc MEMHELPERAPI init_hMod: ptr, init_Size: dword
	xor eax, eax
	.if init_hMod && init_Size
ifndef _DEBUG
	invoke malloc, sizeof MHELPERREADER
else ; _DEBUG
		invoke _malloc_dbg, sizeof MHELPERREADER, _NORMAL_BLOCK, CTXT('mikmod_memoryhelper.asm'), 111
endif ; !_DEBUG
		.if eax
			assume eax: ptr MHELPERREADER
			mov [eax].mreader.lpSeek, offset mhSeek
			mov [eax].mreader.lpTell, offset mhTell
			mov [eax].mreader.lpRead, offset mhRead
			mov [eax].mreader.lpGet, offset mhGet
			mov [eax].mreader.lpEof, offset mhEof
			m2m [eax].mh_hModule, init_hMod
			m2m [eax].mh_Size, init_Size
			xor ecx, ecx
			mov [eax].mh_Pos, ecx
			mov [eax].mh_Eof, cl
			assume eax: nothing
		.endif
	.endif
	ret
mh_NewReader endp

.code _TEXT$1E
mh_NewReaderFromRsrc proc MEMHELPERAPI uses ebx hModule: HMODULE,
	lpName: LPCTSTR, lpType: LPCTSTR
	xor eax, eax
	.if hModule
		invoke FindResource, hModule, lpName, lpType
		.if eax
			mov ebx, eax
			invoke LoadResource, hModule, ebx
			.if eax
				invoke LockResource, eax
				push 0
				push eax
				invoke SizeofResource, hModule, ebx
				mov [esp+4], eax
				call mh_NewReader
				pop edx
				pop ecx
			.endif
		.endif
	.endif
	ret
mh_NewReaderFromRsrc endp

.code _TEXT$1B
mh_FreeReader proc MEMHELPERAPI handle: ptr MHELPERREADER
	mov eax, handle
	assume eax: ptr MHELPERREADER
	.if eax && [eax].mreader.lpRead == offset mhRead && [eax].mreader.lpGet == offset mhGet
ifndef _DEBUG
		invoke free, eax
else ; _DEBUG
		invoke _free_dbg, eax, _NORMAL_BLOCK
endif ; !_DEBUG
		retval 0
	.else
		xor eax, eax
		dec eax
	.endif
	assume eax: nothing
	ret
mh_FreeReader endp

.code _TEXT$1C
mh_NewWriter proc MEMHELPERAPI init_hMod: ptr, init_Size: dword
	xor eax, eax
	.if init_hMod && init_Size
ifndef _DEBUG
		invoke malloc, sizeof MHELPERWRITER
else ; _DEBUG
		invoke _malloc_dbg, sizeof MHELPERWRITER, _NORMAL_BLOCK, CTXT('mikmod_memoryhelper.asm'), 181
endif ; !_DEBUG
		.if eax
			assume eax: ptr MHELPERWRITER
			mov [eax].mwriter.lpSeek, offset mhSeek
			mov [eax].mwriter.lpTell, offset mhTell
			mov [eax].mwriter.lpWrite, offset mhWrite
			mov [eax].mwriter.lpPut, offset mhPut
			m2m [eax].mh_hModule, init_hMod
			m2m [eax].mh_Size, init_Size
			xor ecx, ecx
			mov [eax].mh_Pos, ecx
			assume eax: nothing
		.endif
	.endif
	ret
mh_NewWriter endp

.code _TEXT$1D
mh_FreeWriter proc MEMHELPERAPI handle: ptr MHELPERWRITER
	mov eax, handle
	assume eax: ptr MHELPERWRITER
	.if eax && [eax].mwriter.lpWrite == offset mhWrite && [eax].mwriter.lpPut == offset mhPut
ifndef _DEBUG
		invoke free, eax
else ; _DEBUG
		invoke _free_dbg, eax, _NORMAL_BLOCK
endif ; !_DEBUG
		retval 0
	.else
		xor eax, eax
		dec eax
	.endif
	assume eax: nothing
	ret
mh_FreeWriter endp

; /////////////////////////////////////////////////////////////////////////////
; //
; // PROCEDURE NAME:   mhSeek
; // ORIGINAL SYNTAX:  long _lseek( int handle, long offset, int origin );
; // RETURN VALUE:     _lseek returns the offset, in bytes, of the new position
; //                   from the beginning of the file. _lseeki64 returns the
; //                   offset in a 64-bit integer. The function returns -1L to
; //                   indicate an error and sets errno either to EBADF,
; //                   meaning the file handle is invalid, or to EINVAL,
; //                   meaning the value for origin is invalid or the position
; //                   specified by offset is before the beginning of the file.
; //                   On devices incapable of seeking (such as terminals and
; //                   printers), the return value is undefined.
; // PARAMETERS:       handle
; //                      Handle referring to open file
; //                   offset
; //                      Number of bytes from origin
; //                   origin
; //                      Initial position
;
.code _TEXT$01
mhSeek proc handle: sdword, _offset: sdword, origin: sdword
	mov edx, handle
	test edx, edx
	jz @@error
	.if dword ptr [edx+8] == offset mhRead && dword ptr [edx+0Ch] == offset mhGet
		add edx, sizeof MREADER
	.elseif dword ptr [edx+8] == offset mhWrite && dword ptr [edx+0Ch] == offset mhPut
		add edx, sizeof MWRITER
	.else
	@@error:
	ifdef _DLL
		invoke _errno
	else ; !_DLL
		mov eax, _errno
	endif ; _DLL
		mov sdword ptr [eax], EBADF
		return TRUE
	.endif
	.if origin == SEEK_SET
		xor eax, eax
	.elseif origin == SEEK_CUR
		mov eax, [edx+8]
	.elseif origin == SEEK_END
		mov eax, [edx+4]
	.else
	@@:
	ifdef _DLL
		invoke _errno
	else ; !_DLL
		mov eax, _errno
	endif ; _DLL
		mov sdword ptr [eax], EINVAL
		return TRUE
	.endif
	add eax, _offset
	cmp eax, [edx+4]
	ja @B
	mov [edx+8], eax
	xor eax, eax
	mov [edx+0Ch], al
	ret
mhSeek endp

; /////////////////////////////////////////////////////////////////////////////
; //
; // PROCEDURE NAME:   mhTell
; // ORIGINAL SYNTAX:  long _tell( int handle );
; // RETURN VALUE:     A return value of –1L indicates an error, and errno is
; //                   set to EBADF to indicate an invalid file-handle
; //                   argument. On devices incapable of seeking, the return
; //                   value is undefined.
; // PARAMETERS:       handle
; //                      Handle referring to open file
; //
;
.code _TEXT$02
mhTell proc handle: sdword
	mov edx, handle
	test edx, edx
	jz @@error
	.if dword ptr [edx+8] == offset mhRead && dword ptr [edx+0Ch] == offset mhGet
		add edx, sizeof MREADER
	.elseif dword ptr [edx+8] == offset mhWrite && dword ptr [edx+0Ch] == offset mhPut
		add edx, sizeof MWRITER
	.else
	@@error:
	ifdef _DLL
		invoke _errno
	else ; !_DLL
		mov eax, _errno
	endif ; _DLL
		mov sdword ptr [eax], EBADF
		return -1
	.endif
	mov eax, [edx+8]
	ret
mhTell endp

; /////////////////////////////////////////////////////////////////////////////
; //
; // PROCEDURE NAME:   mhRead
; // ORIGINAL SYNTAX:  int _read( int handle, void *buffer, unsigned int count );
; // RETURN VALUE:     _read returns the number of bytes read, which may be
; //                   less than count if there are fewer than count bytes left
; //                   in the file or if the file was opened in text mode, in
; //                   which case each carriage return-linefeed (_CR-_LF) pair is
; //                   replaced with a single linefeed character. Only the
; //                   single linefeed character is counted in the return
; //                   value. The replacement does not affect the file pointer.
; //                   If the function tries to read at end of file, it returns
; //                   0. If the handle is invalid, or the file is not open for
; //                   reading, or the file is locked, the function returns –1
; //                   and sets errno to EBADF.
; // PARAMETERS:       handle
; //                      Handle referring to open file
; //                   buffer
; //                      Storage location for data
; //                   count
; //                      Maximum number of bytes
;
.code _TEXT$03
mhRead proc uses ebx esi edi handle: sdword, buffer: dword, count: size_t
	mov ebx, handle
	assume ebx: ptr MHELPERREADER
	.if !ebx || [ebx].mreader.lpRead != offset mhRead || [ebx].mreader.lpGet != offset mhGet
	@@error:
	ifdef _DLL
		invoke _errno
	else ; !_DLL
		mov eax, _errno
	endif ; _DLL
		mov sdword ptr [eax], EBADF
		retval 0
	.else
		xor eax, eax
		mov esi, [ebx].mh_hModule
		mov edi, buffer
		.if esi && edi
			mov edx, count
			mov ecx, [ebx].mh_Size
			.if [ebx].mh_Pos < ecx
				sub ecx, [ebx].mh_Pos
				.if edx > ecx
					mov edx, ecx
				.endif
				.if edx
					mov ecx, edx
					add esi, [ebx].mh_Pos
					cld
					rep movsb
					sub edx, ecx
					add [ebx].mh_Pos, edx
					cmp edx, count
					setae al
				.endif
			.else
				mov [ebx].mh_Eof, 1
			.endif
		.else
		ifdef _DLL
			invoke _errno
		else ; !_DLL
			mov eax, _errno
		endif ; _DLL
			mov sdword ptr [eax], EFAULT
		.endif
	.endif
	assume ebx: nothing
	ret
mhRead endp

; /////////////////////////////////////////////////////////////////////////////
; //
; // PROCEDURE NAME:   mhGet
; // ORIGINAL SYNTAX:  int fgetc( int handle );
; // RETURN VALUE:     fgetc and _fgetchar return the character read as an int
; //                   or return _EOF to indicate an error or end of file.
; //                   fgetwc and _fgetwchar return, as a wint_t, the wide
; //                   character that corresponds to the character read or
; //                   return WEOF to indicate an error or end of file. For all
; //                   four functions, use feof or ferror to distinguish
; //                   between an error and an end-of-file condition. For fgetc
; //                   and fgetwc, if a read error occurs, the error indicator
; //                   for the stream is set.
; // PARAMETERS:       handle
; //                      Handle referring to open file
;
.code _TEXT$04
mhGet proc handle: sdword
	mov edx, handle
	assume edx: ptr MHELPERREADER
	.if !edx || [edx].mreader.lpRead != offset mhRead || [edx].mreader.lpGet != offset mhGet
	@@error:
	ifdef _DLL
		invoke _errno
	else ; !_DLL
		mov eax, _errno
	endif ; _DLL
		mov sdword ptr [eax], EBADF
		retval _EOF
	.elseif [edx].mh_hModule
		mov eax, [edx].mh_Pos
		.if eax < [edx].mh_Size
			add eax, [edx].mh_hModule
			movzx eax, byte ptr [eax]
			inc [edx].mh_Pos
		.else
			mov [edx].mh_Eof, 1
			retval _EOF
		.endif
	.else
	ifdef _DLL
		invoke _errno
	else ; !_DLL
		mov eax, _errno
	endif ; _DLL
		mov sdword ptr [eax], EFAULT
		retval _EOF
	.endif
	assume edx: nothing
	ret
mhGet endp

; /////////////////////////////////////////////////////////////////////////////
; //
; // PROCEDURE NAME:   mhEof
; // ORIGINAL SYNTAX:  int _eof( int handle );
; // RETURN VALUE:     _eof returns 1 if the current position is end of file,
; //                   or 0 if it is not. A return value of -1 indicates an
; //                   error; in this case, errno is set to EBADF, which
; //                   indicates an invalid file handle.
; // PARAMETERS:       handle
; //                      Handle referring to open file
;
comment ~
  Run-Time Library Reference

feof
Requirements
Function Required header Compatibility
feof <stdio.h> ANSI, Win 98, Win Me, Win NT, Win 2000, Win XP

int feof(
   FILE *stream
);
Parameter
stream
	Pointer to FILE structure.
Return Value
The feof function RETURNS A NONZERO VALUE AFTER THE FIRST READ OPERATION THAT
ATTEMPTS TO READ PAST THE END OF THE FILE. It returns 0 if the current position
is not end of file. There is no error return.

Remarks
The feof routine (implemented both as a function and as a macro) determines
whether the end of stream has been reached. When end of file is reached, read
operations return an end-of-file indicator until the stream is closed or until
rewind, fsetpos, fseek, or clearerr is called against it.

Example
// crt_feof.c
/* This program uses feof to indicate when
 * it reaches the end of the file CRT_FEOF.TXT. It also
 * checks for errors with ferror.
 */

#include <stdio.h>
#include <stdlib.h>

int main( void )
{
   int  count, total = 0;
   char buffer[100];
   FILE *stream;

   if( (stream = fopen( "crt_feof.txt", "r" )) == NULL )
      exit( 1 );

   /* Cycle until end of file reached: */
   while( !feof( stream ) )
   {
      /* Attempt to read in 10 bytes: */
      count = fread( buffer, sizeof( char ), 100, stream );
      if( ferror( stream ) )      {
         perror( "Read error" );
         break;
      }

      /* Total up actual bytes read */
      total += count;
   }
   printf( "Number of bytes read = %d\n", total );
   fclose( stream );
}
~
.code _TEXT$05
mhEof proc handle: sdword
	mov edx, handle
	assume edx: ptr MHELPERREADER
	.if !edx || [edx].mreader.lpRead != offset mhRead || [edx].mreader.lpGet != offset mhGet
	@@error:
	ifdef _DLL
		invoke _errno
	else ; !_DLL
		mov eax, _errno
	endif ; _DLL
		mov sdword ptr [eax], EBADF
		retval 0
	.else
		movzx eax, [edx].mh_Eof
	.endif
	assume edx: nothing
	ret
mhEof endp

; /////////////////////////////////////////////////////////////////////////////
; //
; // PROCEDURE NAME:   mhWrite
; // ORIGINAL SYNTAX:  int _write( int handle, const void *buffer, unsigned int count );
; // RETURN VALUE:     _read returns the number of bytes read, which may be
; //                   less than count if there are fewer than count bytes left
; //                   in the file or if the file was opened in text mode, in
; //                   which case each carriage return-linefeed (CR-LF) pair is
; //                   replaced with a single linefeed character. Only the
; //                   single linefeed character is counted in the return
; //                   value. The replacement does not affect the file pointer.
; //                   If the function tries to read at end of file, it returns
; //                   0. If the handle is invalid, or the file is not open for
; //                   reading, or the file is locked, the function returns –1
; //                   and sets errno to EBADF.
; // PARAMETERS:       handle
; //                      Handle referring to open file
; //                   buffer
; //                      Storage location for data
; //                   count
; //                      Maximum number of bytes
;
.code _TEXT$06
mhWrite proc uses esi edi handle: sdword, buffer: dword, count: size_t
	mov eax, handle
	assume eax: ptr MHELPERWRITER
	.if !eax || [eax].mwriter.lpWrite != offset mhWrite || [eax].mwriter.lpPut != offset mhPut
	@@error:
	ifdef _DLL
		invoke _errno
	else ; !_DLL
		mov eax, _errno
	endif ; _DLL
		mov sdword ptr [eax], EBADF
		retval 0
	.else
		mov esi, buffer
		mov edi, [eax].mh_hModule
		.if esi && edi
			mov edx, count
			.if edx
				add edi, [eax].mh_Pos
				mov ecx, edx
				cld
				rep movsb
				sub edx, ecx
				add [eax].mh_Pos, edx
				mov ecx, [eax].mh_Size
				.if [eax].mh_Pos > ecx
					m2m [eax].mh_Size, [eax].mh_Pos
				.endif
				xor eax, eax
				cmp edx, count
				setae al
			.else
				xor eax, eax
			.endif
		.else
		ifdef _DLL
			invoke _errno
		else ; !_DLL
			mov eax, _errno
		endif ; _DLL
			mov sdword ptr [eax], EFAULT
			xor eax, eax
		.endif
	.endif
	assume eax: nothing
	ret
mhWrite endp

; /////////////////////////////////////////////////////////////////////////////
; //
; // PROCEDURE NAME:   mhPut
; // ORIGINAL SYNTAX:  int fputc( int c, int handle );
; // RETURN VALUE:     fgetc and _fgetchar return the character read as an int
; //                   or return EOF to indicate an error or end of file.
; //                   fgetwc and _fgetwchar return, as a wint_t, the wide
; //                   character that corresponds to the character read or
; //                   return WEOF to indicate an error or end of file. For all
; //                   four functions, use feof or ferror to distinguish
; //                   between an error and an end-of-file condition. For fgetc
; //                   and fgetwc, if a read error occurs, the error indicator
; //                   for the stream is set.
; // PARAMETERS:       handle
; //                      Handle referring to open file
;
.code _TEXT$07
mhPut proc nValue: sdword, handle: sdword
	mov edx, handle
	assume edx: ptr MHELPERWRITER
	.if !edx || [edx].mwriter.lpWrite != offset mhWrite || [edx].mwriter.lpPut != offset mhPut
	@@error:
	ifdef _DLL
		invoke _errno
	else ; !_DLL
		mov eax, _errno
	endif ; _DLL
		mov sdword ptr [eax], EBADF
		retval _EOF
	.else
		mov ecx, [edx].mh_hModule
		.if ecx
			add ecx, [edx].mh_Pos
			movzx eax, byte ptr nValue
			mov [ecx], al
			inc [edx].mh_Pos
			mov ecx, [edx].mh_Size
			.if [edx].mh_Pos > ecx
				m2m [edx].mh_Size, [edx].mh_Pos
			.endif
		.else
		ifdef _DLL
			invoke _errno
		else ; !_DLL
			mov eax, _errno
		endif ; _DLL
			mov sdword ptr [eax], EFAULT
			retval _EOF
		.endif
	.endif
	assume edx: nothing
	ret
mhPut endp

end
