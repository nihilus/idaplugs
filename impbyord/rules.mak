
# //////////////// Build dirs ////////////////
$(OUTDIR) :
	@if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

!IF "$(INTDIR)"!="$(OUTDIR)"
$(INTDIR) :
	@if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"
!ENDIF # "$(INTDIR)"!="$(OUTDIR)"

# //////////////// Build dependencies ////////////////
deps: $(INTDIR)
	@echo Building source dependencies...
	$(CC) $(CFLAGS) $(DEFINES) $(INCPATHS)  -Fo"$(INTDIR)/" /QMM ./*.c ./*.cpp > .\makefile.dep
	@echo dependencies file created.

# //////////////// Cleanup ////////////////
clean:
	@rm -f $(OBJS) $(RESOURCES) $(TARGETS)
	@echo Project files are cleaned.

# //////////////// Inferrence rulez ////////////////
.SUFFIXES : .exe .obj .asm .c .cpp .cxx .cc .bas .cbl .for .pas .res .rc .S \
	.sin .sed .lo .y

$(INTDIR)/$(PLUGIN).obj : ./$(PLUGIN).cpp
$(INTDIR)/$(PLUGIN).res : ./$(PLUGIN).mak ./plg_rsrc.h
$(INTDIR)/plug_abt.res : ./plg_rsrc.h
$(INTDIR)/plugbizy.res : ./plg_rsrc.h

{.}.c{$(INTDIR)}.obj::
	$(CC) -c $(CLRSP) $(CFLAGS) -Fo"$(INTDIR)/" $(NMFLAGS) $< @<<
$(DEFINES) $(INCPATHS)
<<

{.}.cpp{$(INTDIR)}.obj::
	$(CPP) -c $(CLRSP) $(CPPFLAGS) -Fo"$(INTDIR)/" $(NMFLAGS) $< @<<
$(DEFINES) $(INCPATHS)
<<

{..}.cpp{$(INTDIR)}.obj::
	$(CPP) -c $(CLRSP) $(CPPFLAGS) -Zl -Gy -Fo"$(INTDIR)/" $(NMFLAGS) $< @<<
$(DEFINES) $(INCPATHS)
<<

{$(COMMONSDKS_ROOT)}.cpp{$(INTDIR)}.obj::
	$(CPP) -c $(CLRSP) $(CPPFLAGS) -Zl -Gy -Fo"$(INTDIR)/" $(NMFLAGS) $< @<<
$(DEFINES) $(INCPATHS)
<<

{.}.cc{$(INTDIR)}.obj::
	$(CPP) -c $(CLRSP) $(CPPFLAGS) -Fo"$(INTDIR)/" $(NMFLAGS) $< @<<
$(DEFINES) $(INCPATHS)
<<

{.}.asm{$(INTDIR)}.obj:
	$(AS) -c $(AFLAGS) $(DEFINES) $(INCPATHS) -Fo"$@" "$<"
	D:\Microsoft\MASM\EnableCOMDATs.exe "$@"

{.}.rc{$(INTDIR)}.res:
	$(RC) $(RFLAGS) /fo"$@" "$<"
