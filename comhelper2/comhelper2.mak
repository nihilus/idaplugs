
# ///////////////// Project name: OLE/COM Helper /////////////////

PLUGIN = comhelper2
MODEXT = plw

PLUGINNAME = OLE/COM helper: a plugin for ida pro by servil
PLUGINVERSION = 0,2,26,994
PLUGINVERSIONTEXT = 0.226 beta

CFLAGS = $(CFLAGS)
LDFLAGS = -base:0x12750000 $(LDFLAGS)
RESOURCES = "$(INTDIR)\$(PLUGIN).res" # "$(INTDIR)\plugbizy.res"

!INCLUDE ./basicdef.mak
!INCLUDE ./common.mak

# ----------------------------- file dependencies -----------------------------
"$(INTDIR)/comhelper2.obj": ./comhelper2.cpp ./plugida.hpp ..\undbgnew.h \
	..\mscrtdbg.h ..\msvc70rt.h ./NmApiLib.hpp ./plg_rsrc.h ./idasdk.hpp \
	..\dbgnew.h ./idaview.hpp ./areaex.hpp ./plughlpr.hpp ./plugxcpt.hpp \
	..\fixdcstr.hpp ./plugsys.hpp ./plugcmn.hpp ./plugtinf.hpp ./plugcom.hpp \
	./plugstrm.hpp ./pluginsn.hpp ./plugfgrp.hpp ./plugbizy.hpp
