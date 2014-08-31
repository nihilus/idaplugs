
!IFNDEF _DEBUG

!IFNDEF DYNAMIC
LIBS = $(LIBS) libpcre.lib
!ELSE # DYNAMIC
LIBS = $(LIBS) pcre.lib
!ENDIF # !DYNAMIC

!ELSE # _DEBUG

!IFDEF NMBC
!IFDEF STATIC
LIBS = $(LIBS) nmbc_libpcred.lib
!ELSE # !STATIC
LIBS = $(LIBS) nmbc_pcred.lib
!ENDIF # STATIC
!ELSEIFDEF NMTT
!IFDEF STATIC
LIBS = $(LIBS) nmtt_libpcred.lib
!ELSE # !STATIC
LIBS = $(LIBS) nmtt_pcred.lib
!ENDIF # STATIC
!ELSEIFDEF NMTC
!IFDEF STATIC
LIBS = $(LIBS) nmtc_libpcred.lib
!ELSE # !STATIC
LIBS = $(LIBS) nmtc_pcred.lib
!ENDIF # STATIC
!ELSE # !NMBC
!IFDEF STATIC
LIBS = $(LIBS) libpcred.lib
!ELSE # !STATIC
LIBS = $(LIBS) pcred.lib
!ENDIF # STATIC
!ENDIF # NMBC

!ENDIF # !_DEBUG
