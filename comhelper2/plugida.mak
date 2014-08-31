
LIBNAME = plugida

!INCLUDE basicdef.mak

CFLAGS = -Gy -Zl $(CFLAGS)
CPPFLAGS = $(CFLAGS)

OBJS = "$(INTDIR)/idasdk.obj" "$(INTDIR)/plugbizy.obj" "$(INTDIR)/plugcmn.obj" \
  "$(INTDIR)/plugcmn2.obj" "$(INTDIR)/plugcmn3.obj" "$(INTDIR)/plugcom.obj" \
  "$(INTDIR)/plugcom2.obj" "$(INTDIR)/plugfgrp.obj" "$(INTDIR)/pluginsn.obj" \
  "$(INTDIR)/plugstrm.obj" "$(INTDIR)/plugsys.obj" "$(INTDIR)/plugtinf.obj" \
  "$(INTDIR)/plugxcpt.obj" "$(INTDIR)/pcre.obj" "$(INTDIR)/md5.obj"
TARBALL = $(INTDIR)/$(LIBNAME).lib

all: "$(TARBALL)"
	@echo $(LIBNAME): all targets are up to date.

"$(TARBALL)": $(OBJS) $(RESOURCES) $(INTDIR)
	$(AR) $(ARFLAGS) -out:$@ $(OBJS) $(RESOURCES) $(DEFS)
!IF $(SDK) == $(IDAAPI)
!IFNDEF _DEBUG
#	"$(IDA_ROOT)\sig\flair\win\pcf.exe" -v $(INTDIR)/$(LIBNAME).lib $(@B).pat
#	call ..\..\Perl\pat2sig.pl -u $(@B).pat "IDA helper library"
#	rm -f $(@B).log $(@B).pat $(@B).exc $(@B).err
!ENDIF # !_DEBUG
!ENDIF # SDK == IDAAPI
	@echo $@ is up to date.

!INCLUDE rules.mak

# ----------------------------- file dependencies -----------------------------
"$(INTDIR)/idasdk.obj": ./idasdk.cpp ./idasdk.hpp ..\undbgnew.h ..\dbgnew.h \
	./plugxcpt.hpp ..\mscrtdbg.h ..\fixdcstr.hpp ./plugsys.hpp
"$(INTDIR)/plugbizy.obj": ./plugbizy.cpp ..\mscrtdbg.h ./plg_rsrc.h \
	./plugbizy.hpp ./idasdk.hpp ..\undbgnew.h ..\dbgnew.h ./plugsys.hpp \
	./plugxcpt.hpp ..\fixdcstr.hpp ./plugcmn.hpp
"$(INTDIR)/plugcmn.obj": ./plugcmn.cpp ..\mscrtdbg.h ./plugcmn.hpp \
	..\undbgnew.h ./idasdk.hpp ..\dbgnew.h ./plugsys.hpp ./plughlpr.hpp \
	./pluginsn.hpp ./areaex.hpp
"$(INTDIR)/plugcmn2.obj": ./plugcmn2.cpp ..\mscrtdbg.h ./plugcmn.hpp \
	..\undbgnew.h ./idasdk.hpp ..\dbgnew.h ./plugsys.hpp ./pluginsn.hpp \
	./areaex.hpp ./batchres.hpp ./idaview.hpp ./plughlpr.hpp ./warnlist.hpp
"$(INTDIR)/plugcmn3.obj": ./plugcmn3.cpp ..\mscrtdbg.h ..\pcre.hpp \
	..\undbgnew.h ..\dbgnew.h ./plugcmn.hpp ./idasdk.hpp ./plugsys.hpp \
	./plughlpr.hpp ./plugxcpt.hpp ..\fixdcstr.hpp
"$(INTDIR)/plugcom.obj": ./plugcom.cpp ..\mscrtdbg.h ./plugcom.hpp \
	..\undbgnew.h ..\fixdcstr.hpp ./idasdk.hpp ..\dbgnew.h ./plughlpr.hpp \
	./plugtinf.hpp ./plugsys.hpp
"$(INTDIR)/plugcom2.obj": ./plugcom2.cpp ..\mscrtdbg.h ./plugcom.hpp \
	..\undbgnew.h ..\fixdcstr.hpp ./idasdk.hpp ..\dbgnew.h ./plughlpr.hpp \
	./plugtinf.hpp ./plugsys.hpp
"$(INTDIR)/plugfgrp.obj": ./plugfgrp.cpp ..\pcre.hpp ..\undbgnew.h \
	..\mscrtdbg.h ..\dbgnew.h ./plugfgrp.hpp ..\fixdcstr.hpp ./idasdk.hpp \
	./plg_rsrc.h ./plugsys.hpp ./plughlpr.hpp
"$(INTDIR)/pluginsn.obj": ./pluginsn.cpp ./pluginsn.hpp ..\undbgnew.h \
	..\mscrtdbg.h ./idasdk.hpp ..\dbgnew.h
"$(INTDIR)/plugstrm.obj": ./plugstrm.cpp ..\pcre.hpp ..\undbgnew.h \
	..\mscrtdbg.h ..\dbgnew.h ./plugstrm.hpp ./idasdk.hpp ./plugsys.hpp \
	./plugxcpt.hpp ..\fixdcstr.hpp ./plughlpr.hpp
"$(INTDIR)/plugsys.obj": ./plugsys.cpp ..\msvc70rt.h ./plugsys.hpp \
	..\undbgnew.h ..\mscrtdbg.h ./idasdk.hpp ..\dbgnew.h ./plughlpr.hpp \
	./plugxcpt.hpp ..\fixdcstr.hpp
"$(INTDIR)/plugtinf.obj": ./plugtinf.cpp ./plugtinf.hpp ..\undbgnew.h \
	..\mscrtdbg.h ./idasdk.hpp ..\dbgnew.h ./plughlpr.hpp
"$(INTDIR)/plugxcpt.obj": ./plugxcpt.cpp ./plugxcpt.hpp ..\undbgnew.h \
	..\mscrtdbg.h ..\fixdcstr.hpp ./plugsys.hpp ./idasdk.hpp ..\dbgnew.h \
	./plughlpr.hpp
"$(INTDIR)/pcre.obj": ../pcre.cpp ../pcre.hpp ../undbgnew.h ../mscrtdbg.h \
	../dbgnew.h
"$(INTDIR)/md5.obj ": "$(COMMONSDKS_ROOT)/md5.cpp"
