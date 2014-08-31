
# ///////////////// Project name: Ordinal imports resolver /////////////////

PLUGIN = impbyord
MODEXT = plw

PLUGINNAME = Ordinal imports/exports resolver: a plugin for ida pro by servil
PLUGINVERSION = 0,9,80,663
PLUGINVERSIONTEXT = 0.980 beta

LDFLAGS = -base:0x12D20000 $(LDFLAGS)
RESOURCES = "$(INTDIR)\plugbizy.res"

!INCLUDE ./basicdef.mak
!INCLUDE ./usepcre.mak
!INCLUDE ./common.mak

# ----------------------------- file dependencies -----------------------------
"$(INTDIR)/impbyord.obj": ./impbyord.cpp ..\fixdcstr.hpp ..\pcre.hpp \
	..\undbgnew.h ..\mscrtdbg.h ..\dbgnew.h ./plugida.hpp ..\msvc70rt.h \
	./NmApiLib.hpp ./plg_rsrc.h ./idasdk.hpp ./idaview.hpp ./areaex.hpp \
	./plughlpr.hpp ./plugxcpt.hpp ./plugsys.hpp ./plugcmn.hpp ./plugtinf.hpp \
	./plugcom.hpp ./plugstrm.hpp ./pluginsn.hpp ./plugfgrp.hpp ./plugbizy.hpp
