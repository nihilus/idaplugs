
# ///////////////// Project name: Code snippet creator /////////////////

PLUGIN = csc
MODEXT = plw

PLUGINNAME = Code snippet creator: a plugin for IDA Pro
PLUGINVERSION = 0,9,90,1501
PLUGINVERSIONTEXT = 0.990 beta

DEFINES = $(DEFINES) -DSOUNDFX=load_xm
RFLAGS = $(RFLAGS) /d SOUNDFX
LDFLAGS = -base:0x127A0000 -delayload:psapi.dll -delayload:version.dll $(LDFLAGS) # -delayload:perl58.dll -delayload:PerlEz.dll
RESOURCES = "$(INTDIR)\$(PLUGIN).res" "$(INTDIR)\flirtmatch.res" \
	"$(INTDIR)\plug_abt.res" "$(INTDIR)\plugbizy.res" "$(INTDIR)\xtrnresolver.res"
OBJS = $(INTDIR)/debugger.obj $(INTDIR)/flirtmatch.obj \
	$(INTDIR)/xtrnresolver.obj $(INTDIR)/pcre_replacer.obj
#LIBS = $(LIBS) perl58.lib PerlEz.lib
SAVE_ORIGINAL = 1
PLUGIN_BIN = flowinsp
PLUGIN_SRC = ..\debugger.?pp .\flirtmatch.* .\xtrnresolver.* .\graphvwr.?pp \
	.\xrefmgr.?pp ..\cmangle.h .\rtrlist.?pp ..\pcre_replacer.?pp ..\syncpmtv.?pp \
	.\plug_abt.* ..\..\RCE\servil_about.bmp .\codesnippet.ico \
	..\..\assembler\mikmod_memoryhelper.* temp\masm.inc \
	D:\Microsoft\MASM\INCLUDE\mikmod\mikmod.inc ..\fixdcstr.hpp

!INCLUDE ./basicdef.mak
!INCLUDE ./usepcre.mak
!INCLUDE ./usemikmod.mak
!INCLUDE ./usethread.mak
!INCLUDE ./common.mak

# ----------------------------- file dependencies -----------------------------
"$(INTDIR)/csc.obj": ./csc.cpp ..\debugger.hpp ..\undbgnew.h ..\mscrtdbg.h \
	..\fixdcstr.hpp ..\dbgnew.h ..\pcre.hpp ..\pcre_replacer.hpp ./plugida.hpp \
	..\msvc70rt.h ./NmApiLib.hpp ./plg_rsrc.h ./idasdk.hpp ./idaview.hpp \
	./areaex.hpp ./plughlpr.hpp ./plugxcpt.hpp ./plugsys.hpp ./plugcmn.hpp \
	./plugtinf.hpp ./plugcom.hpp ./plugstrm.hpp ./pluginsn.hpp ./plugfgrp.hpp \
	./plugbizy.hpp ./rtrlist.hpp ./xtrnresolver.h ./flirtmatch.h ./batchres.hpp \
	./warnlist.hpp ./graphvwr.hpp ./plug_abt.ipp ..\syncpmtv.hpp ./xrefmgr.hpp
"$(INTDIR)/flirtmatch.obj": ./flirtmatch.cpp ..\fixdcstr.hpp ..\cmangle.h \
	..\pcre.hpp ..\undbgnew.h ..\mscrtdbg.h ..\dbgnew.h ./flirtmatch.h \
	./plugida.hpp ..\msvc70rt.h ./NmApiLib.hpp ./plg_rsrc.h ./idasdk.hpp \
	./idaview.hpp ./areaex.hpp ./plughlpr.hpp ./plugxcpt.hpp ./plugsys.hpp \
	./plugcmn.hpp ./plugtinf.hpp ./plugcom.hpp ./plugstrm.hpp ./pluginsn.hpp \
	./plugfgrp.hpp ./plugbizy.hpp
"$(INTDIR)/xtrnresolver.obj": ./xtrnresolver.cpp ..\pcre.hpp ..\undbgnew.h \
	..\mscrtdbg.h ..\dbgnew.h ./plugida.hpp ..\msvc70rt.h ./NmApiLib.hpp \
	./plg_rsrc.h ./idasdk.hpp ./idaview.hpp ./areaex.hpp ./plughlpr.hpp \
	./plugxcpt.hpp ..\fixdcstr.hpp ./plugsys.hpp ./plugcmn.hpp ./plugtinf.hpp \
	./plugcom.hpp ./plugstrm.hpp ./pluginsn.hpp ./plugfgrp.hpp ./plugbizy.hpp \
	./rtrlist.hpp ./xtrnresolver.h
"$(INTDIR)/debugger.obj": ../debugger.cpp ../undbgnew.h ../msvc70rt.h \
	../debugger.hpp ../mscrtdbg.h ../fixdcstr.hpp ../dbgnew.h
"$(INTDIR)/pcre_replacer.obj": ../pcre_replacer.cpp ../mscrtdbg.h ../msvc70rt.h \
	../pcre_replacer.hpp ../undbgnew.h ../pcre.hpp ../dbgnew.h
