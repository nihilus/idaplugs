
!IFNDEF _DEBUG

!IFNDEF DYNAMIC
LIBS = $(LIBS) libmikmod.lib # dsound.lib
LDFLAGS = $(LDFLAGS) -delayload:winmm.dll # -delayload:dsound.dll
!ELSE # DYNAMIC
LIBS = $(LIBS) mikmod.lib
!ENDIF # !DYNAMIC

!ELSE # _DEBUG

!IFDEF NMBC
!IFDEF STATIC
LIBS = $(LIBS) nmbc_libmikmodd.lib dsound.lib
LDFLAGS = $(LDFLAGS) -delayload:winmm.dll -delayload:dsound.dll
!ELSE # !STATIC
LIBS = $(LIBS) nmbc_mikmodd.lib
!ENDIF # STATIC
!ELSEIFDEF NMTT
!IFDEF STATIC
LIBS = $(LIBS) nmtt_libmikmodd.lib dsound.lib
LDFLAGS = $(LDFLAGS) -delayload:winmm.dll -delayload:dsound.dll
!ELSE # !STATIC
LIBS = $(LIBS) nmtt_mikmodd.lib
!ENDIF # STATIC
!ELSEIFDEF NMTC
!IFDEF STATIC
LIBS = $(LIBS) nmtc_libmikmodd.lib dsound.lib
LDFLAGS = $(LDFLAGS) -delayload:winmm.dll -delayload:dsound.dll
!ELSE # !STATIC
LIBS = $(LIBS) nmtc_mikmodd.lib
!ENDIF # STATIC
!ELSE # !NMBC
!IFDEF STATIC
LIBS = $(LIBS) libmikmodd.lib dsound.lib
LDFLAGS = $(LDFLAGS) -delayload:winmm.dll -delayload:dsound.dll
!ELSE # !STATIC
LIBS = $(LIBS) mikmodd.lib
!ENDIF # STATIC
!ENDIF # NMBC

!ENDIF # !_DEBUG
