
!IFNDEF _DEBUG

LIBS = $(LIBS) boost-thread.lib

!ELSE # _DEBUG

!IFDEF NMBC
LIBS = $(LIBS) nmbc-boost-threadd.lib
!ELSEIFDEF NMTT
LIBS = $(LIBS) nmtt-boost-threadd.lib
!ELSEIFDEF NMTC
LIBS = $(LIBS) nmtc-boost-threadd.lib
!ELSE # !NMBC
LIBS = $(LIBS) boost-threadd.lib
#LIBS = $(LIBS) boost-threadstld.lib
!ENDIF # NMBC

!ENDIF # !_DEBUG
