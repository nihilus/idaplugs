all: mapconv.dll

!IF "$(DEBUG)" < "1"

mapconv.dll: mapconv.obj
	xilink -dll -release .\mapconv.obj -out:mapconv.dll \
		-export:_ODBG_Pluginaction -export:_ODBG_Plugindata \
		-export:_ODBG_Plugininit \
		user32.lib comdlg32.lib D:\develop\debug\OllyDbg\SDK\ollydbg.lib
	rm -f mapconv.exp mapconv.lib
	call upx mapconv.dll
	call setcsum mapconv.dll /A

mapconv.obj: mapconv.c
	icl -c -G5 -MD -EHac -GR -I D:/develop/debug/OllyDbg/SDK -J -Zp1 -Gd -Ox mapconv.c

!ELSE # $(DEBUG) == 1

mapconv.dll: mapconv.obj
	link -dll -debug .\mapconv.obj -out:mapconv.dll \
		-export:_ODBG_Pluginaction -export:_ODBG_Plugindata \
		-export:_ODBG_Plugininit \
		user32.lib comdlg32.lib D:/develop/debug/OllyDbg/SDK/ollydbg.lib
	rm -f mapconv.exp mapconv.lib

mapconv.obj: mapconv.c
	cl -c -G6 -MDd -EHac -GR -I D:/develop/debug/OllyDbg/SDK -J -Zp1 -Gd -Od -Zi mapconv.c

!ENDIF
