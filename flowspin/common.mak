
!IFNDEF _DEBUG # RELEASE
CFLAGS = -LD $(CFLAGS)
CPPFLAGS = $(CFLAGS)
!ELSE # DEBUG
CFLAGS = -LDd $(CFLAGS)
CPPFLAGS = $(CFLAGS)
TARBALLS = # force
!ENDIF # !_DEBUG
COMMON_ZIP_FLAGS = -u -whs -Jhrs -ex
COMMON_BIN_FLAGS = -P -x*.?db -x*.map -x*.exp -x*.lib -x*.obj -x*.res

!INCLUDE ./usestlp.mak
#!INCLUDE ./usethread.mak

!IFDEF STATIC
DEFINES = $(DEFINES) -DLIBMIKMOD_STATIC=1
!ELSE # !STATIC
DEFINES = $(DEFINES) -ULIBMIKMOD_STATIC
!ENDIF # STATIC

TARGETS = "$(OUTDIR)/$(PLUGIN).$(MODEXT)" $(TARGETS)

all: $(TARGETS)
	@echo $(PLUGIN): all targets are up to date.

IDALIB = $(INTDIR)/plugida.lib
LIBS = $(LIBS) "$(IDA_ROOT)/sdk/$(SDK)/libvc.w32/ida.lib" "$(IDALIB)" \
	Kernel32.Lib User32.Lib AdvAPI32.Lib Shell32.Lib ComDlg32.Lib \
	ComCtl32.Lib Gdi32.Lib Ole32.Lib OleAut32.Lib WinMM.Lib Version.Lib \
	psapi.lib "$(MSVCDIR)/lib/delayimp.lib"
!IF $(SDK) == 490
# extend SDK4.9 by IDA5.0 exports
LIBS = $(LIBS) "$(IDA_ROOT)/sdk/$(SDK)/libvc.w32/ida50.lib"
!ENDIF
# for source package
COMMON_SRC = .\plugida.* .\idasdk.?pp .\plug*.hpp .\plug*.cpp .\areaex.?pp \
	.\idaview.?pp .\batchres.?pp .\warnlist.?pp \
	.\plg_rsrc.h .\plugbizy.rc ..\3rd_party\md5.?pp ..\pcre.?pp .\NmApiLib.hpp \
	..\dbgnew.h ..\undbgnew.h ..\fixdcstr.hpp \
	.\basicdef.mak .\rules.mak .\common.mak .\use*.mak \
	..\msvc70rt.h ..\lib\msvc70rt.lib .\chkrdata.cpp ..\mscrtdbg.h

"$(OUTDIR)/$(PLUGIN).$(MODEXT)": $(OBJS) $(RESOURCES) "$(OUTDIR)" "$(IDALIB)" $(TARBALLS)
	@rm -f $*.pdb
	$(LD) $(LDFLAGS) -dll -export:PLUGIN,DATA -out:$@ $(OBJS) $(RESOURCES) \
		$(DEFS) $(NMFLAGS) @<<
$(LIBPATHS) $(LIBS)
<<
	@rm -f $*.exp $*.lib
!IFNDEF _DEBUG
##############################################################################
# chkrdata post-edit tool is required to restore page protection of packed
# images: if chkrdata is not present within search path, you must remove
# VirtualProtect(...) command from DllMain, otherwise running plugin may
# danger IDA stability
##############################################################################
	@chkrdata $@ "./$(PLUGIN).cpp"                                   #
##############################################################################
!IF $(SDK)==$(IDAAPI) && DEFINED(SAVE_ORIGINAL)
	@setcsum $@ /A
	@cp -f $@ $*.pdb "$(TEMP)"
!ENDIF
	@..\binsr $@ "$(HOMEDRIVE)$(HOMEPATH)\\"
#	@if exist $*.pdb ..\binsr $*.pdb "$(HOMEDRIVE)$(HOMEPATH)\\"
	@upx --best --lzma --strip-relocs=0 $@
#	@pec2 $@ /Nb:Yes /Cl:9 /Ch:pec2codec_lzma.dll
!IF $(SDK) == $(IDAAPI)
	@rm -f $(IDA_ROOT)/plugins/$(@B).pdb $(IDA_ROOT)/plugins/$(@B).map
	@cp -f $@ $(IDA_ROOT)/plugins/$(@F)
!ENDIF
	@setcsum $@ /A
!ELSE # DEBUG
	@rm -f D:\develop\debug\OllyDbg\UDD\$(@B).udd
!IF "$(NMFLAGS)" == " /NMbcOn"
	@startonce "$(DPS_ROOT)\BoundsChecker\BC7.exe" "$(IDA_ROOT)\Idag.exe"
!ELSE # "$(NMFLAGS)" != "/NMbcOn"
	@startonce "$(IDA_ROOT)\Idag.exe"
	@startonce "D:\develop\debug\OllyDbg\ollydbg.exe"
#	@startonce "D:\develop\debug\DbgView\Dbgview.exe"
!ENDIF # "$(NMFLAGS)" == "/NMbcOn"
!ENDIF # !DEBUG
	@call ++build.pl "$(PLUGIN).mak" "$(PLUGIN).rc"
	@echo $@ is up to date.
!IFNDEF NOPKG
!IF $(SDK) == $(IDAAPI)
	@wzzip $(COMMON_ZIP_FLAGS) $(COMMON_BIN_FLAGS) \
		"$(PKG_ROOT)\$(PLUGIN)-bin.zip" ".\plugins\$(PLUGIN).*" $(PLUGIN_BIN)
!ELSEIF $(SDK) == 480
	@wzzip $(COMMON_ZIP_FLAGS) $(COMMON_BIN_FLAGS) \
		"$(PKG_ROOT)\$(PLUGIN)-bin48.zip" ".\$(SDK)\$(PLUGIN).*" $(PLUGIN_BIN)
!ENDIF
	@wzzip $(COMMON_ZIP_FLAGS) -p "$(PKG_ROOT)\$(PLUGIN)-src.zip" "$(PLUGIN).*" \
		$(PLUGIN_SRC) $(COMMON_SRC)
!ENDIF # NOPKG

!INCLUDE rules.mak

$(IDALIB) : $(LIBSRCS)
	$(MAKE) -nologo -$(MAKEFLAGS) -f ./plugida.mak

force:
	@rm -f "$(OUTDIR)/$(PLUGIN).$(MODEXT)"
