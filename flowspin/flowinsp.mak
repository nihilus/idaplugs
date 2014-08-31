
# ///////////////// Project name: Flow inspector /////////////////

PLUGIN = flowinsp
MODEXT = plw

PLUGINNAME = Runtime-evaluated addressing resolver: a plugin for ida pro by servil
PLUGINVERSION = 0,9,78,1238
PLUGINVERSIONTEXT = 0.978 beta

LDFLAGS = -base:0x12A00000 $(LDFLAGS)
OBJS = $(INTDIR)/debugger.obj
RESOURCES = "$(INTDIR)\$(PLUGIN).res" "$(INTDIR)\plugbizy.res"
PLUGIN_SRC = ..\debugger.?pp rtrlist.?pp ..\fixdcstr.hpp

!INCLUDE ./basicdef.mak
#!INCLUDE ./usepcre.mak
!INCLUDE ./common.mak

# ----------------------------- file dependencies -----------------------------
"$(INTDIR)/flowinsp.obj": ./flowinsp.cpp ..\debugger.hpp ..\undbgnew.h \
	..\mscrtdbg.h ..\fixdcstr.hpp ..\dbgnew.h ./plugida.hpp ..\msvc70rt.h \
	./NmApiLib.hpp ./plg_rsrc.h ./idasdk.hpp ./idaview.hpp ./areaex.hpp \
	./plughlpr.hpp ./plugxcpt.hpp ./plugsys.hpp ./plugcmn.hpp ./plugtinf.hpp \
	./plugcom.hpp ./plugstrm.hpp ./pluginsn.hpp ./plugfgrp.hpp ./plugbizy.hpp \
	./batchres.hpp ./rtrlist.hpp
"$(INTDIR)/debugger.obj": ../debugger.cpp ../undbgnew.h ../msvc70rt.h \
	../debugger.hpp ../mscrtdbg.h ../fixdcstr.hpp ../dbgnew.h
