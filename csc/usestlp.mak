
!IFNDEF _DEBUG # RELEASE

!IFNDEF DYNAMIC
LIBS = $(LIBS) stlport_statix.lib
!ELSE # DYNAMIC
LIBS = $(LIBS) stlport.lib
!ENDIF # !DYNAMIC

!ELSE # DEBUG

!IFDEF NMBC
!IFDEF STATIC
LIBS = $(LIBS) nmbc_stlportd_statix.lib
!ELSE # !STATIC
LIBS = $(LIBS) nmbc_stlportd.lib
#LIBS = $(LIBS) nmbc_stlportstld.lib
!ENDIF # STATIC
!ELSEIFDEF NMTT
!IFDEF STATIC
LIBS = $(LIBS) nmtt_stlportd_statix.lib
!ELSE # !STATIC
LIBS = $(LIBS) nmtt_stlportd.lib
#LIBS = $(LIBS) nmtt_stlportstld.lib
!ENDIF # STATIC
!ELSEIFDEF NMTC
!IFDEF STATIC
LIBS = $(LIBS) nmtc_stlportd_statix.lib
!ELSE # !STATIC
LIBS = $(LIBS) nmtc_stlportd.lib
#LIBS = $(LIBS) nmtc_stlportstld.lib
!ENDIF # STATIC
!ELSE
!IFDEF STATIC
LIBS = $(LIBS) stlportd_statix.lib
!ELSE # !STATIC
LIBS = $(LIBS) stlportd.lib
#LIBS = $(LIBS) stlportstld.lib
!ENDIF # STATIC
!ENDIF # NMBC

!ENDIF # !_DEBUG
