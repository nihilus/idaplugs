
# ///////////////// Project name: Code snippet creator /////////////////

PLUGIN = mapgen
MODEXT = plw

PLUGINNAME = Extended map file exporter: a plugin for ida pro by servil
PLUGINVERSION = 0,9,86,1230
PLUGINVERSIONTEXT = 0.986 beta

DEFINES = -DSOUNDFX=load_mod $(DEFINES)
RFLAGS = /d SOUNDFX $(RFLAGS)
LDFLAGS = -base:0x12D60000 -delayload:psapi.dll -delayload:version.dll $(LDFLAGS)
RESOURCES = "$(INTDIR)\$(PLUGIN).res" "$(INTDIR)\plug_abt.res" \
	"$(INTDIR)\plugbizy.res"
PLUGIN_BIN = mapconv
PLUGIN_SRC = ..\syncpmtv.?pp .\plug_abt.* ..\..\RCE\servil_about.bmp \
	..\..\assembler\mikmod_memoryhelper.* temp\masm.inc \
	D:\Microsoft\MASM\INCLUDE\mikmod\mikmod.inc -x*.xm

!INCLUDE ./basicdef.mak
!INCLUDE ./usepcre.mak
!INCLUDE ./usemikmod.mak
!INCLUDE ./usethread.mak
!INCLUDE ./common.mak

# ----------------------------- file dependencies -----------------------------
"$(INTDIR)/mapgen.obj": ./mapgen.cpp ..\pcre.hpp ..\undbgnew.h ..\mscrtdbg.h \
	..\dbgnew.h ./plugida.hpp ..\msvc70rt.h ./NmApiLib.hpp ./plg_rsrc.h \
	./idasdk.hpp ./idaview.hpp ./areaex.hpp ./plughlpr.hpp ./plugxcpt.hpp \
	..\fixdcstr.hpp ./plugsys.hpp ./plugcmn.hpp ./plugtinf.hpp ./plugcom.hpp \
	./plugstrm.hpp ./pluginsn.hpp ./plugfgrp.hpp ./plugbizy.hpp ./plug_abt.ipp \
	..\syncpmtv.hpp
