comment #
	MikMod sound library
	(c) 1998, 1999, 2000 Miodrag Vallat and others - see file AUTHORS
	for complete list.

	This library is free software; you can redistribute it and/or modify
	it under the terms of the GNU Library General Public License as
	published by the Free Software Foundation; either version 2 of
	the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Library General Public License for more details.

	You should have received a copy of the GNU Library General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
	02111-1307, USA.

*==============================================================================

	$Id: mikmod.h.in,v 1.37 2002/01/08 20:48:03 miod Exp $

	MikMod sound library include file

==============================================================================*
#

ifndef _mikmod_inc
_mikmod_inc = 1

ifndef _LIB
ifndef _DEBUG
ifdef LIBMIKMOD_STATIC
includelib <mikmod_static.lib>
else ; !LIBMIKMOD_STATIC
includelib <mikmod.lib>
endif ; LIBMIKMOD_STATIC
else ; _DEBUG
ifdef LIBMIKMOD_STATIC
includelib <mikmodd_static.lib>
else ; !LIBMIKMOD_STATIC
includelib <mikmodd.lib>
endif ; LIBMIKMOD_STATIC
endif ; !_DEBUG
endif ; _LIB

; ========== Library version
LIBMIKMOD_VERSION_MAJOR equ 3L
LIBMIKMOD_VERSION_MINOR equ 2L
LIBMIKMOD_REVISION      equ 0L

LIBMIKMOD_VERSION equ \
	((LIBMIKMOD_VERSION_MAJOR shl 16) or \
	(LIBMIKMOD_VERSION_MINOR shl 8) or \
	(LIBMIKMOD_REVISION))

; ========== Error codes
MMERR_OPENING_FILE              equ 1
MMERR_OUT_OF_MEMORY             equ 2
MMERR_DYNAMIC_LINKING           equ 3

MMERR_SAMPLE_TOO_BIG            equ 4
MMERR_OUT_OF_HANDLES            equ 5
MMERR_UNKNOWN_WAVE_TYPE         equ 6

MMERR_LOADING_PATTERN           equ 7
MMERR_LOADING_TRACK             equ 8
MMERR_LOADING_HEADER            equ 9
MMERR_LOADING_SAMPLEINFO        equ 10
MMERR_NOT_A_MODULE              equ 11
MMERR_NOT_A_STREAM              equ 12
MMERR_MED_SYNTHSAMPLES          equ 13
MMERR_ITPACK_INVALID_DATA       equ 14

MMERR_DETECTING_DEVICE          equ 15
MMERR_INVALID_DEVICE            equ 16
MMERR_INITIALIZING_MIXER        equ 17
MMERR_OPENING_AUDIO             equ 18
MMERR_8BIT_ONLY                 equ 19
MMERR_16BIT_ONLY                equ 20
MMERR_STEREO_ONLY               equ 21
MMERR_ULAW                      equ 22
MMERR_NON_BLOCK                 equ 23

MMERR_AF_AUDIO_PORT             equ 24

MMERR_AIX_CONFIG_INIT           equ 25
MMERR_AIX_CONFIG_CONTROL        equ 26
MMERR_AIX_CONFIG_START          equ 27

MMERR_GUS_SETTINGS              equ 28
MMERR_GUS_RESET                 equ 29
MMERR_GUS_TIMER                 equ 30

MMERR_HP_SETSAMPLESIZE          equ 31
MMERR_HP_SETSPEED               equ 32
MMERR_HP_CHANNELS               equ 33
MMERR_HP_AUDIO_OUTPUT           equ 34
MMERR_HP_AUDIO_DESC             equ 35
MMERR_HP_BUFFERSIZE             equ 36

MMERR_OSS_SETFRAGMENT           equ 37
MMERR_OSS_SETSAMPLESIZE         equ 38
MMERR_OSS_SETSTEREO             equ 39
MMERR_OSS_SETSPEED              equ 40

MMERR_SGI_SPEED                 equ 41
MMERR_SGI_16BIT                 equ 42
MMERR_SGI_8BIT                  equ 43
MMERR_SGI_STEREO                equ 44
MMERR_SGI_MONO                  equ 45

MMERR_SUN_INIT                  equ 46

MMERR_OS2_MIXSETUP              equ 47
MMERR_OS2_SEMAPHORE             equ 48
MMERR_OS2_TIMER                 equ 49
MMERR_OS2_THREAD                equ 50

MMERR_DS_PRIORITY               equ 51
MMERR_DS_BUFFER                 equ 52
MMERR_DS_FORMAT                 equ 53
MMERR_DS_NOTIFY                 equ 54
MMERR_DS_EVENT                  equ 55
MMERR_DS_THREAD                 equ 56
MMERR_DS_UPDATE                 equ 57

MMERR_WINMM_HANDLE              equ 58
MMERR_WINMM_ALLOCATED           equ 59
MMERR_WINMM_DEVICEID            equ 60
MMERR_WINMM_FORMAT              equ 61
MMERR_WINMM_UNKNOWN             equ 62

MMERR_MAC_SPEED                 equ 63
MMERR_MAC_START                 equ 64

MMERR_OSX_UNKNOWN_DEVICE        equ 65
MMERR_OSX_BAD_PROPERTY          equ 66
MMERR_OSX_UNSUPPORTED_FORMAT    equ 67
MMERR_OSX_SET_STEREO            equ 68
MMERR_OSX_BUFFER_ALLOC          equ 69
MMERR_OSX_ADD_IO_PROC           equ 70
MMERR_OSX_DEVICE_START          equ 71
MMERR_OSX_PTHREAD               equ 72

MMERR_DOSWSS_STARTDMA           equ 73
MMERR_DOSSB_STARTDMA            equ 74

MMERR_MAX                       equ 75

; ========== Samples
; Sample playback should not be interrupted
SFX_CRITICAL                    equ 1

; Sample format [loading and in-memory] flags:
SF_16BITS                       equ 0001h
SF_STEREO                       equ 0002h
SF_SIGNED                       equ 0004h
SF_BIG_ENDIAN                   equ 0008h
SF_DELTA                        equ 0010h
SF_ITPACKED                     equ 0020h

SF_FORMATMASK                   equ 003Fh

; General Playback flags
SF_LOOP                         equ 0100h
SF_BIDI                         equ 0200h
SF_REVERSE                      equ 0400h
SF_SUSTAIN                      equ 0800h

SF_PLAYBACKMASK                 equ 0C00h

; Module-only Playback Flags
SF_OWNPAN                       equ 1000h
SF_UST_LOOP                     equ 2000h

SF_EXTRAPLAYBACKMASK            equ 3000h

; Panning constants
PAN_LEFT                        equ 0
PAN_HALFLEFT                    equ 64
PAN_CENTER                      equ 128
PAN_HALFRIGHT                   equ 192
PAN_RIGHT                       equ 255
PAN_SURROUND                    equ 512 ; panning value for Dolby Surround

SAMPLE struct
	panning sword ?    ; panning (0-255 or PAN_SURROUND)
	speed dword ?      ; Base playing speed/frequency of note
	volume byte ?      ; volume 0-64
	inflags word ?     ; sample format on disk
	flags word ?       ; sample format in memory
	length_ dword ?    ; length of sample (in samples!)
	loopstart dword ?  ; repeat position (relative to start, in samples)
	loopend dword ?    ; repeat end
	susbegin dword ?   ; sustain loop begin (in samples) \ Not Supported
	susend dword ?     ; sustain loop end                / Yet!

	; Variables used by the module player only! (ignored for sound effects)
	globvol byte ?    ; global volume
	vibflags byte ?   ; autovibrato flag stuffs
	vibtype byte ?    ; Vibratos moved from INSTRUMENT to SAMPLE
	vibsweep byte ?
	vibdepth byte ?
	vibrate byte ?
	samplename LPSTR ? ; name of the sample

	; Values used internally only
	avibpos word ?     ; autovibrato pos [player use]
	divfactor byte ?   ; for sample scaling, maintains proper period slides
	seekpos dword ?    ; seek position in file
	handle sword ?     ; sample handle used by individual drivers
SAMPLE ends

; ========== Error handling
externdef C MikMod_errno: sword
externdef C MikMod_critical: BOOL

; ========== Reader, Writer
MREADER STRUCT
	lpSeek dword ?
	lpTell dword ?
	lpRead dword ?
	lpGet  dword ?
	lpEof  dword ?
MREADER ENDS

MWRITER STRUCT
	lpSeek  dword ?
	lpTell  dword ?
	lpWrite dword ?
	lpPut   dword ?
MWRITER ENDS

; ========== Internal module representation (UniMod)
;	Instrument definition - for information only, the only field which may be
;	of use in user programs is the name field

; Instrument note count
INSTNOTES equ 120

; Envelope point
ENVPT struct
	pos sword ?
	val sword ?
ENVPT ends

; Envelope point count
ENVPOINTS equ 32

; Instrument structure
INSTRUMENT struct
	insname LPSTR ?

	flags byte ?
	samplenumber word INSTNOTES dup(?)
	samplenote byte INSTNOTES dup(?)

	nnatype byte ?
	dca byte ?              ; duplicate check action
	dct byte ?              ; duplicate check type
	globvol byte ?
	volfade word ?
	panning sword ?         ; instrument-based panning var

	pitpansep byte ?        ; pitch pan separation (0 to 255)
	pitpancenter byte ?     ; pitch pan center (0 to 119)
	rvolvar byte ?          ; random volume varations (0 - 100%)
	rpanvar byte ?          ; random panning varations (0 - 100%)

	; volume envelope
	volflg byte ?           ; bit 0: on 1: sustain 2: loop
	volpts byte ?
	volsusbeg byte ?
	volsusend byte ?
	volbeg byte ?
	volend byte ?
	volenv ENVPT ENVPOINTS dup(<>)
	; panning envelope
	panflg byte ?           ; bit 0: on 1: sustain 2: loop
	panpts byte ?
	pansusbeg byte ?
	pansusend byte ?
	panbeg byte ?
	panend byte ?
	panenv ENVPT ENVPOINTS dup(<>)
	; pitch envelope
	pitflg byte ?           ; bit 0: on 1: sustain 2: loop
	pitpts byte ?
	pitsusbeg byte ?
	pitsusend byte ?
	pitbeg byte ?
	pitend byte ?
	pitenv ENVPT ENVPOINTS dup(<>)
INSTRUMENT ends

;struct MP_CONTROL
;struct MP_VOICE

;	Module definition

; maximum master channels supported
UF_MAXCHAN	    equ 64

; Module flags
UF_XMPERIODS	equ 0001h ; XM periods / finetuning
UF_LINEAR		equ 0002h ; LINEAR periods (UF_XMPERIODS must be set)
UF_INST			equ 0004h ; Instruments are used
UF_NNA			equ 0008h ; IT: NNA used, set numvoices rather than numchn
UF_S3MSLIDES	equ 0010h ; uses old S3M volume slides
UF_BGSLIDES		equ 0020h ; continue volume slides in the background
UF_HIGHBPM		equ 0040h ; MED: can use >255 bpm
UF_NOWRAP		equ 0080h  ;XM-type (i.e. illogical) pattern break semantics
UF_ARPMEM		equ 0100h ; IT: need arpeggio memory
UF_FT2QUIRKS	equ 0200h ; emulate some FT2 replay quirks
UF_PANNING		equ 0400h ; module uses panning effects or have non-tracker default initial panning

MODULE struct
	; general module information
	songname LPSTR ?                   ; name of the song
	modtype LPSTR ?                    ; string type of module loaded
	comment_ LPSTR ?                   ; module comments

	flags word ?                       ; See module flags above
	numchn byte ?                      ; number of module channels
	numvoices byte ?                   ; max # voices used for full NNA playback
	numpos word ?                      ; number of positions in this song
	numpat word ?                      ; number of patterns in this song
	numins word ?                      ; number of instruments
	numsmp word ?                      ; number of samples
	instruments dword ptr INSTRUMENT ? ; all instruments
	samples dword ptr SAMPLE ?         ; all samples
	realchn byte ?                     ; real number of channels used
	totalchn byte ?                    ; total number of channels used (incl NNAs)

	; playback settings
	reppos word ?                  ; restart position
	initspeed byte ?               ; initial song speed
	inittempo word ?               ; initial song tempo
	initvolume byte ?              ; initial global volume (0 - 128)
	panning byte UF_MAXCHAN dup(?) ; panning positions
	chanvol byte UF_MAXCHAN dup(?) ; channel positions
	bpm word ?                     ; current beats-per-minute speed
	sngspd word ?                  ; current song speed
	volume dword ?                 ; song volume (0-128) (or user volume)

	extspd BOOL ?                  ; extended speed flag (default enabled)
	panflag BOOL ?                 ; panning flag (default enabled)
	wrap BOOL ?                    ; wrap module ? (default disabled)
	_loop BOOL ?                   ; allow module to loop ? (default enabled)
	fadeout BOOL ?	               ; volume fade out during last pattern

	patpos word ?                  ; current row number
	sngpos dword ?                 ; current song position
	sngtime dword ?                ; current song time in 2^-10 seconds

	relspd sword ?                 ; relative speed factor

	; internal module representation
	numtrk word ?                  ; number of tracks
	tracks dword ptr dword ptr byte ? ; array of numtrk pointers to tracks
	patterns dword ptr word ?      ; array of Patterns
	pattrows dword ptr word ?      ; array of number of rows for each pattern
	positions dword ptr word ?     ; all positions

	forbid BOOL ?                  ; if true, no player update!
	numrow word ?                  ; number of rows on current pattern
	vbtick word ?                  ; tick counter (counts from 0 to sngspd)
	sngremainder word ?            ; used for song time computation

	control dword ptr MP_CONTROL   ; Effects Channel info (size pf->numchn)
	voice dword ptr MP_VOICE       ; Audio Voice information (size md_numchn)

	globalslide byte ?             ; global volume slide rate
	pat_repcrazy byte ?            ; module has just looped to position -1
	patbrk word ?                  ; position where to start a new pattern
	patdly byte ?                  ; patterndelay counter (command memory)
	patdly2 byte ?                 ; patterndelay counter (real one)
	posjmp dword ?                 ; flag to indicate a jump is needed...
	bpmlimit word ?	               ; threshold to detect bpm or speed values
MODULE ends

; ========== Drivers
MD_MUSIC equ 0
MD_SNDFX equ 1

MD_HARDWARE equ 0
MD_SOFTWARE equ 1

; Mixing flags

; These ones take effect only after MikMod_Init or MikMod_Reset
DMODE_16BITS     equ 0001h ; enable 16 bit output
DMODE_STEREO     equ 0002h ; enable stereo output
DMODE_SOFT_SNDFX equ 0004h ; Process sound effects via software mixer
DMODE_SOFT_MUSIC equ 0008h ; Process music via software mixer
DMODE_HQMIXER    equ 0010h ; Use high-quality (slower) software mixer
DMODE_FLOAT      equ 0020h ; enable float output
; These take effect immediately.
DMODE_SURROUND   equ 0100h ; enable surround sound
DMODE_INTERP     equ 0200h ; enable interpolation
DMODE_REVERSE    equ 0400h ; reverse stereo

MDRIVER struct
	next dword ptr MDRIVER ?
	Name LPSTR ?
	Version LPSTR ?

	HardVoiceLimit byte ? ; Limit of hardware mixer voices
	SoftVoiceLimit byte ? ; Limit of software mixer voices

	_Alias LPSTR ?
	CmdLineHelp dword ptr byte ?

	CommandLine dword ptr proc
	IsPresent dword ptr proc
	SampleLoad dword ptr proc
	SampleUnload dword ptr proc
	FreeSampleSpace dword ptr proc
	RealSampleLength dword ptr proc
	Init dword ptr proc
	Exit dword ptr proc
	Reset dword ptr proc
	SetNumVoices dword ptr proc
	PlayStart dword ptr proc
	PlayStop dword ptr proc
	Update dword ptr proc
	Pause_ dword ptr proc
	VoiceSetVolume dword ptr proc
	VoiceGetVolume dword ptr proc
	VoiceSetFrequency dword ptr proc
	VoiceGetFrequency dword ptr proc
	VoiceSetPanning dword ptr proc
	VoiceGetPanning dword ptr proc
	VoicePlay dword ptr proc
	VoiceStop dword ptr proc
	VoiceStopped dword ptr proc
	VoiceGetPosition dword ptr proc
	VoiceRealVolume dword ptr proc
MDRIVER ends

; This structure is used to query current playing voices status
VOICEINFO struct
	i dword ptr INSTRUMENT ?  ; Current channel instrument
	s dword ptr SAMPLE ?      ; Current channel sample
	panning sword ?           ; panning position
	volume sbyte ?            ; channel's "global" volume (0..64)
	period word ?             ; period to play the sample at
	kick byte ?               ; if true = sample has been restarted
VOICEINFO ends


; These variables can be changed at ANY time and results will be immediate
externdef C md_volume: byte      ; global sound volume (0-128)
externdef C md_musicvolume: byte ; volume of song
externdef C md_sndfxvolume: byte ; volume of sound effects
externdef C md_reverb: byte      ; 0 = none  15 = chaos
externdef C md_pansep: byte      ; 0 = mono  128 == 100% (full left/right)

; The variables below can be changed at any time, but changes will not be
; implemented until MikMod_Reset is called. A call to MikMod_Reset may result
; in a skip or pop in audio (depending on the soundcard driver and the settings
; changed).
externdef C md_device: word      ; device
externdef C md_mixfreq: word     ; mixing frequency
externdef C md_mode: word        ; mode. See DMODE_? flags above

; The following variable should not be changed!
externdef C md_driver: ptr MDRIVER ; Current driver in use.

; ========== Module loaders
externdef C load_669: ABS	; 669 and Extended-669 (by Tran/Renaissance)
externdef C load_amf: ABS	; DMP Advanced Module Format (by Otto Chrons)
externdef C load_dsm: ABS	; DSIK internal module format
externdef C load_far: ABS	; Farandole Composer (by Daniel Potter)
externdef C load_gdm: ABS	; General DigiMusic (by Edward Schlunder)
externdef C load_it:  ABS	; Impulse Tracker (by Jeffrey Lim)
externdef C load_imf: ABS	; Imago Orpheus (by Lutz Roeder)
externdef C load_med: ABS	; Amiga MED modules (by Teijo Kinnunen)
externdef C load_m15: ABS	; Soundtracker 15-instrument
externdef C load_mod: ABS	; Standard 31-instrument Module loader
externdef C load_mtm: ABS	; Multi-Tracker Module (by Renaissance)
externdef C load_okt: ABS	; Amiga Oktalyzer
externdef C load_stm: ABS	; ScreamTracker 2 (by Future Crew)
externdef C load_stx: ABS	; STMIK 0.2 (by Future Crew)
externdef C load_s3m: ABS	; ScreamTracker 3 (by Future Crew)
externdef C load_ult: ABS	; UltraTracker (by MAS)
externdef C load_uni: ABS	; MikMod and APlayer internal module format
externdef C load_xm:  ABS	; FastTracker 2 (by Triton)
externdef C load_asy: ABS	; ASYLUM Music Format 1.0


; Known drivers list
externdef C drv_nos: ABS     ; no sound
externdef C drv_pipe: ABS    ; piped output
externdef C drv_raw: ABS     ; raw file disk writer [music.raw]
externdef C drv_stdout: ABS  ; output to stdout
externdef C drv_wav: ABS     ; RIFF WAVE file disk writer [music.wav]
externdef C drv_ultra: ABS   ; Linux Ultrasound driver
externdef C drv_sam9407: ABS ; Linux sam9407 driver
externdef C drv_AF: ABS      ; Dec Alpha AudioFile
externdef C drv_aix: ABS     ; AIX audio device
externdef C drv_alsa: ABS    ; Advanced Linux Sound Architecture (ALSA)
externdef C drv_esd: ABS     ; Enlightened sound daemon (EsounD)
externdef C drv_hp: ABS      ; HP-UX audio device
externdef C drv_oss: ABS     ; OpenSound System (Linux,FreeBSD...)
externdef C drv_sgi: ABS     ; SGI audio library
externdef C drv_sun: ABS     ; Sun/NetBSD/OpenBSD audio device
externdef C drv_dart: ABS    ; OS/2 Direct Audio RealTime
externdef C drv_os2: ABS     ; OS/2 MMPM/2
externdef C drv_ds: ABS      ; Win32 DirectSound driver
externdef C drv_win: ABS     ; Win32 multimedia API driver
externdef C drv_mac: ABS     ; Macintosh Sound Manager driver
externdef C drv_aiff: ABS    ; AIFF file disk writer [music.aiff]
externdef C drv_osx: ABS	 ; MacOS X CoreAudio Driver

; ========== Library version
MikMod_GetVersion proto C

; ========== Error handling
MikMod_strerror proto C :dword
MikMod_RegisterErrorHandler proto C :dword

; ========== Library initialization and core functions
MikMod_RegisterAllDrivers proto C

MikMod_InfoDriver proto C
MikMod_RegisterDriver proto C :dword
MikMod_DriverFromAlias proto C :dword
MikMod_DriverByOrdinal proto C :sdword

MikMod_Init proto C :dword;
MikMod_Exit proto C
MikMod_Reset proto C :dword
MikMod_SetNumVoices proto C :dword, :dword
MikMod_Active proto C
MikMod_EnableOutput proto C
MikMod_DisableOutput proto C
MikMod_Update proto C

MikMod_InitThreads proto C
MikMod_Lock proto C
MikMod_Unlock proto C

; Sample functions
Sample_Load proto C :dword
Sample_LoadFP proto C :dword
Sample_LoadGeneric proto C :dword
Sample_Free proto C :dword
Sample_Play proto C :dword, :dword, :dword

Voice_SetVolume proto C :dword, :dword
Voice_GetVolume proto C
Voice_SetFrequency proto C :dword, :dword
Voice_GetFrequency proto C :dword
Voice_SetPanning proto C :dword, :dword
Voice_GetPanning proto C :dword
Voice_Play proto C :dword, :dword, :dword
Voice_Stop proto C :dword
Voice_Stopped proto C :dword
Voice_GetPosition proto C :dword
Voice_RealVolume proto C :dword

; ========== Module loaders
MikMod_InfoLoader proto C
MikMod_RegisterAllLoaders proto C
MikMod_RegisterLoader proto C :dword

; ========== Module player
Player_Load proto C :dword, :dword, :dword
Player_LoadFP proto C :dword, :dword, :dword
Player_LoadGeneric proto C :dword, :dword, :dword
Player_LoadTitle proto C :dword
Player_LoadTitleFP proto C :dword
Player_Free proto C :dword
Player_Start proto C :dword
Player_Active proto C
Player_Stop proto C
Player_TogglePause proto C
Player_Paused proto C
Player_NextPosition proto C
Player_PrevPosition proto C
Player_SetPosition proto C :dword
Player_Muted proto C :dword
Player_SetVolume proto C :dword
Player_GetModule proto C :dword
Player_SetSpeed proto C :dword
Player_SetTempo proto C :dword
Player_Unmute proto C :dword, :vararg
Player_Mute proto C :dword, :vararg
Player_ToggleMute proto C :dword, :vararg
Player_GetChannelVoice proto C :dword
Player_GetChannelPeriod proto C :dword
Player_QueryVoices proto C numvoices:word, vinfo: ptr VOICEINFO

MikMod_RegisterPlayer proto C :dword

; ========== Virtual channel mixer interface (for user-supplied drivers only)
VC_Init proto C
VC_Exit proto C
VC_SetNumVoices proto C :dword
VC_SampleSpace proto C :dword
VC_SampleLength proto C :dword, :dword

VC_PlayStart proto C
VC_PlayStop proto C

VC_SampleLoad proto C :dword, :dword
VC_SampleUnload proto C :dword

VC_WriteBytes proto C :dword, :dword
VC_SilenceBytes proto C :dword, :dword

VC_VoiceSetVolume proto C :dword, :dword
VC_VoiceGetVolume proto C :dword
VC_VoiceSetFrequency proto C :dword, :dword
VC_VoiceGetFrequency proto C :dword
VC_VoiceSetPanning proto C :dword, :dword
VC_VoiceGetPanning proto C :dword
VC_VoicePlay proto C :dword, :dword, :dword, :dword, :dword, :dword, :dword

VC_VoiceStop proto C :dword
VC_VoiceStopped proto C :dword
VC_VoiceGetPosition proto C :dword
VC_VoiceRealVolume proto C :dword

; ========== Memory helper

; Initializes, call first/ retval: EAX points to MemReader object
mh_ReaderInit proto C init_hMod: ptr, init_Size: dword
mh_WriterInit proto C init_hMod: ptr, init_Size: dword

endif ; _mikmod_inc
