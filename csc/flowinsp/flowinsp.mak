all: flowinsp.dll

SDKDIR = D:\develop\debug\OllyDbg\SDK

!IF "$(DEBUG)" < "1"

flowinsp.dll: flowinsp.obj
	xilink -dll -release ./flowinsp.obj -out:flowinsp.dll \
		-export:_ODBG_Pluginaction -export:_ODBG_Plugindata \
		-export:_ODBG_Plugininit -export:_ODBG_Pausedex -export:_ODBG_Pluginmenu \
		user32.lib comdlg32.lib $(SDKDIR)/ollydbg.lib
	rm -f flowinsp.exp flowinsp.lib vc??.idb flowinsp.obj
	call upx flowinsp.dll
	call setcsum flowinsp.dll /A

flowinsp.obj: flowinsp.c
	icl -c -G5 -MD -I"$(SDKDIR)" -J -Zp1 -Gd -Ox flowinsp.c

!ELSE # $(DEBUG) == 1

flowinsp.dll: flowinsp.obj
	link -dll -debug -opt:ref ./flowinsp.obj -out:flowinsp.dll \
		-export:_ODBG_Pluginaction -export:_ODBG_Plugindata \
		-export:_ODBG_Plugininit -export:_ODBG_Pausedex -export:_ODBG_Pluginmenu \
		user32.lib comdlg32.lib $(SDKDIR)/ollydbg.lib
	rm -f vc??.idb flowinsp.obj

flowinsp.obj: flowinsp.c
	cl -c -G6 -MDd -I"$(SDKDIR)" -J -Zp1 -Gd -Od -Zi flowinsp.c

!ENDIF
