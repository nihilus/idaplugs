
# local machine configuration, must set manually
# SDK is a target IDA version number without punctuation for that the plugin is
# being compiled, e.g. 490 or 500
# global environment variable IDAAPI can carry the default for convenience
!IFNDEF SDK
SDK = $(IDAAPI)
!ENDIF # !SDK
!IF "$(SDK)" == ""
!ERROR ERROR: SDK id is not defined, append "SDK=XXX" to nmake commandline where XXX is current IDA version or define environment variable IDAAPI=XXX
!ENDIF # !SDK
!IFNDEF IDA_ROOT
IDA_ROOT = D:\develop\decomp\IDA
!ENDIF # !IDA_ROOT
!IFNDEF IDASDK_ROOT
IDASDK_ROOT = $(IDA_ROOT)\SDK\$(SDK)
!ENDIF # !IDASDK_ROOT
!IFNDEF PROGRAMFILES
PROGRAMFILES = C:\Program Files
!MESSAGE WARNING: %PROGRAMFILES% not defined, defaulting to C:\Program Files.
!ENDIF # !PROGRAMFILES
!IFNDEF COMMONPROGRAMFILES
COMMONPROGRAMFILES = $(PROGRAMFILES)\Common Files
!ENDIF # !COMMONPROGRAMFILES
!IFNDEF MSVCDIR
MSVCDIR = $(PROGRAMFILES)\Visual Studio .NET 2003\Vc7
!ENDIF # !MSVCDIR
!IFNDEF MSDBG_ROOT
MSDBG_ROOT = D:\Microsoft\Debugging Tools for Windows
!ENDIF # !MSDBG_ROOT
!IFNDEF DPS_ROOT
DPS_ROOT = D:\develop\Compuware
!ENDIF # !DPS_ROOT
!IFNDEF PERL_ROOT
PERL_ROOT = D:\develop\Perl
!ENDIF # !PERL_ROOT
!IFNDEF COMMONSDKS_ROOT
COMMONSDKS_ROOT = ../3rd_party
!ENDIF # !COMMONSDKS_ROOT
!IFNDEF STLPORT_ROOT
STLPORT_ROOT = $(COMMONSDKS_ROOT)/STLport
!ENDIF # !STLPORT_ROOT
!IFNDEF BOOST_ROOT
BOOST_ROOT = $(COMMONSDKS_ROOT)/boost
!ENDIF # !BOOST_ROOT
!IFNDEF PCRE_ROOT
PCRE_ROOT = $(COMMONSDKS_ROOT)/pcre
!ENDIF # !PCRE_ROOT
!IFNDEF MIKMOD_ROOT
MIKMOD_ROOT = $(COMMONSDKS_ROOT)/libmikmod
!ENDIF # !MIKMOD_ROOT
PKG_ROOT = F:\CD_ROOT\archive\RCE\release

# link with Comupware always static
!IF DEFINED(NMBC) || DEFINED(NMTT) || DEFINED(NMTC)
STATIC = 1
!ENDIF # NM

# project paths, defines, select tools
#PATH = "$(MSVCDIR)\bin";$(PATH)
!IFNDEF DEBUG
CC = icl
CPP = $(CC)
AR = xilib
LD = xilink
INTDIR = .\$(SDK)
!IF "$(SDK)" == "$(IDAAPI)"
OUTDIR = .\plugins
!ELSE
OUTDIR = $(INTDIR)
!ENDIF
!IFNDEF DYAMIC
STATIC = 1
!ENDIF # DYAMIC
!ELSE # DEBUG
_DEBUG = 1
CC = cl
CPP = $(CC)
AR = lib
LD = link
INTDIR = .\$(SDK)\debug
OUTDIR = $(IDA_ROOT)\plugins
!IFNDEF STATIC
DYNAMIC = 1
!ENDIF # STATIC
!ENDIF # !DEBUG
RC = rc
AS = ml
MTL = midl

# command lines
CLRSP =
CFLAGS = -nologo -G6 -GF -GR -GX $(CFLAGS)
AFLAGS = -nologo -coff $(AFLAGS)
RFLAGS = $(RFLAGS) /l 0x409 /c 1252 /d SDK=\"$(SDK)\" \
	/d PLUGINVERSION=$(PLUGINVERSION) /d "PLUGINVERSIONTEXT=\"$(PLUGINVERSIONTEXT)\"" \
	/d "PLUGINNAME=\"$(PLUGINNAME)\"" /d "PLUGIN=\"$(PLUGIN)\"" /d "MODEXT=\"$(MODEXT)\""
MTLFLAGS = /mktyplib203 /win32
ARFLAGS = -nologo -machine:I386 -subsystem:windows $(ARFLAGS)
LDFLAGS = -nologo -machine:I386 -subsystem:windows -incremental:no \
	-delay:nobind $(LDFLAGS)
DEFINES = -D__IDP__=1 -D__PLUGIN__=1 -DBYTES_SOURCE=1 -DENUM_SOURCE=1 \
	-D_AFXDLL=1 -D_ATL_DLL=1 -D_ATL_DISABLE_DEPRECATED=1 -DBOOST_THREAD_USE_LIB=1 \
	-D"PLUGINVERSIONTEXT=\"$(PLUGINVERSIONTEXT)\"" \
	-D"PLUGINVERSION=$(PLUGINVERSION)" -D"PLUGINNAME=\"$(PLUGINNAME)\"" $(DEFINES)
INCPATHS = $(INCPATHS) -I"$(STLPORT_ROOT)/stlport" -I"$(BOOST_ROOT)" \
	-I"$(IDASDK_ROOT)/INCLUDE" -I"$(PCRE_ROOT)" -I"$(MIKMOD_ROOT)/include" \
	-I"$(COMMONSDKS_ROOT)" -I"$(PERL_ROOT)/lib/CORE" -I"$(MSDBG_ROOT)/sdk/inc" \
	-I..
LIBPATHS = -libpath:"$(STLPORT_ROOT)/lib" -libpath:"$(BOOST_ROOT)/lib" \
	-libpath:"$(PCRE_ROOT)/lib" -libpath:"$(MIKMOD_ROOT)/win32" \
	-libpath:$(PERL_ROOT)/lib/CORE -libpath:"$(MSDBG_ROOT)/sdk/lib/i386"

!IFNDEF _DEBUG # RELEASE

!IFDEF DYNAMIC
DEFINES = $(DEFINES) -U_STLP_USE_STATIC_LIB -UPCRE_STATIC
!ELSE # !DYNAMIC
DEFINES = $(DEFINES) -D_STLP_USE_STATIC_LIB=1 -DPCRE_STATIC=1
!ENDIF # DYNAMIC

CFLAGS = -Gd -MD -O1 -Ob1 -Qoption,c,--arg_dep_lookup \
	-Qoption,cpp,--arg_dep_lookup $(CFLAGS)
!IF "$(SDK)" == "$(IDAAPI)"
CFLAGS = -Zi $(CFLAGS)
!ENDIF
CPPFLAGS = $(CFLAGS) $(CPPFLAGS)
AFLAGS = -Zi $(AFLAGS)
RFLAGS = $(RFLAGS)
MTLFLAGS = $(MTLFLAGS)
DEFINES = -DNDEBUG=1 $(DEFINES)
#LDFLAGS = -release -opt:ref,icf,nowin98 -pdb:"$(@R).pdb" \
#	-mapinfo:lines -map:"$(OUTDIR)/$(PLUGIN).map" $(LDFLAGS)
LDFLAGS = -release -opt:ref,icf,nowin98 $(LDFLAGS)
!IF "$(SDK)" == "$(IDAAPI)"
LDFLAGS = -debug:full $(LDFLAGS)
!ENDIF

!ELSE # _DEBUG

CFLAGS = -Gd -MDd -GS -GZ -Od -Zi -Fm -wd4103 $(CFLAGS)
CPPFLAGS = $(CFLAGS) $(CPPFLAGS)
AFLAGS = -Zi $(AFLAGS)
RFLAGS = $(RFLAGS) /d "_DEBUG"
MTLFLAGS = /D _DEBUG $(MTLFLAGS)
LDFLAGS = -debug:full -opt:noref,noicf,nowin98 -pdb:"$(@R).pdb" $(LDFLAGS)
#LDFLAGS = $(LDFLAGS) -mapinfo:lines -map:"$(OUTDIR)/$(PLUGIN).map"
DEFINES = -D_DEBUG=1 -D_STLP_LEAKS_PEDANTIC=1 $(DEFINES)
!IFDEF STATIC
DEFINES = $(DEFINES) -D_STLP_USE_STATIC_LIB=1 -DPCRE_STATIC=1
!ELSE # !STATIC
DEFINES = $(DEFINES) -U_STLP_USE_STATIC_LIB -UPCRE_STATIC
#DEFINES = $(DEFINES) -D_STLP_DEBUG=1 -D_STLP_DEBUG_ALLOC=1
DEFINES = $(DEFINES) -U_STLP_DEBUG
!ENDIF # STATIC
#LIBS = $(LIBS) boost-smart_ptrd.lib
TARBALLS = # force

!ENDIF # !_DEBUG

NMFLAGS =
!IFDEF NMBC
NMFLAGS = $(NMFLAGS) /NMbcOn
DEFINES = $(DEFINES) -DNMBC=1
INCPATHS = $(INCPATHS) /I"$(DPS_ROOT)/BoundsChecker/ERptApi"
LIBS = $(LIBS) "$(DPS_ROOT)/BoundsChecker/ERptApi/NmApiLib.lib"
!ENDIF # NMBC
!IFDEF NMTT
NMFLAGS = $(NMFLAGS) /NMttOn # /NMttInlines
DEFINES = $(DEFINES) -DNMTT=1
!ENDIF # NMTT
!IFDEF NMTC
NMFLAGS = $(NMFLAGS) /NMtcOn
DEFINES = $(DEFINES) -DNMTC=1
!ENDIF # NMTC
!IF "$(NMFLAGS)" != ""
CC = NMcl
CPP = $(CC)
LD = NMlink
PATH = "$(COMMONPROGRAMFILES)\Compuware\NMShared";$(PATH)
CLRSP = @"$(MSVCDIR)\bin\cl.cfg"
!ELSE # !NMFLAGS
CLRSP =
!ENDIF # NMFLAGS

!IF "$(CC)" != "icl" && "$(CC)" != "icl.exe" && "$(CPP)" != "icl" && "$(CPP)" != "icl.exe"
INCPATHS = $(INCPATHS) -I"$(MSVCDIR)\include" -I"$(MSVCDIR)\AtlMfc\include"
LIBPATHS = $(LIBPATHS) -libpath:"$(MSVCDIR)\lib" -libpath:"$(MSVCDIR)\AtlMfc\lib"
!ENDIF # not Intel Compiler

LIBHDRS = ./areaex.hpp ./idasdk.hpp ./idaview.hpp ./NmApiLib.hpp ./plg_rsrc.h \
	./plugbizy.hpp ./plugcmn.hpp ./plugcom.hpp ./plugfgrp.hpp ./plughlpr.hpp \
	./plugida.hpp ./pluginsn.hpp ./plugstrm.hpp ./plugsys.hpp ./plugtinf.hpp \
	./plugxcpt.hpp ../pcre.hpp ../mscrtdbg.h ../dbgnew.h ../undbgnew.h \
	../fixdcstr.hpp
LIBSRCS = $(LIBHDRS) ./idasdk.cpp ./plugbizy.cpp ./plugcmn.cpp ./plugcmn2.cpp \
	./plugcmn3.cpp ./plugcom.cpp ./plugcom2.cpp ./plugfgrp.cpp ./pluginsn.cpp \
	./plugstrm.cpp ./plugsys.cpp ./plugtinf.cpp ./plugxcpt.cpp ../pcre.cpp \
	./batchres.hpp ./warnlist.hpp
OBJS = $(INTDIR)/$(PLUGIN).obj $(OBJS)
