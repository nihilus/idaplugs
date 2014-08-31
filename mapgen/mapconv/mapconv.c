/*
 * MapConv 1.04
 * Purpose: converts IDA and Dede map files to OllyDbg
 * by godfather+
 * modified by TBD and SHaG
 *
 * VERY IMPORTANT NOTICE: COMPILE THIS DLL WITH BYTE ALIGNMENT OF STRUCTURES
 * AND UNSIGNED CHAR!
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>

#include <windows.h>

#include "Plugin.h"

DWORD GetCurrentEIP(void);
char *chomp(char *s, const size_t maxlen);

HINSTANCE hInstance; /* DLL instance */
HWND      hwmain;    /* Handle of main OllyDbg window */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) hInstance = hinstDLL; /* Mark plugin instance */
	return TRUE;
}

int cdecl ODBG_Plugindata(char shortname[32]) {
	strcpy(shortname, "Import MAP file");  /* Name of plugin */
	return PLUGIN_VERSION;
};

int cdecl ODBG_Plugininit(int ollydbgversion, HWND hw, ulong *features) {
	if (ollydbgversion < PLUGIN_VERSION) return -1;
	hwmain = hw;
	Addtolist(0, 0, "MapConv ver 1.4 by godfather+, TBD and SHaG");
	return 0;
};

void information(char *message) {
	MessageBox(hwmain, message, "MapConv v1.4", MB_OK | MB_ICONINFORMATION);
}

DWORD GetCurrentEIP(void) {
	t_thread* t2;
	t2 = Findthread(Getcputhreadid());
	return t2->reg.ip;
}

char FindModuleBase(const char *modulename, LPDWORD imagebase) {
	int cntr;
	t_table *modules;
	if (!(modules = (t_table *)Plugingetvalue(VAL_MODULES))) return 0;
	for (cntr = 0; cntr < modules->data.n; ++cntr) {
		char *tmp = ((t_module *)((char *)modules->data.data + cntr *
			modules->data.itemsize))->path;
		if (strrchr(tmp, '\\')) tmp = strrchr(tmp, '\\') + 1;
		if (!_stricmp(modulename, tmp)) {
			*imagebase = ((t_module *)((char *)modules->data.data +
				cntr * modules->data.itemsize))->base;
			Addtolist(*imagebase, 0, "MapConv message: imagebase for module %s found at %08lX",
				tmp, *imagebase);
			return 1;
		}
	} /* for loop */
	return 0;
}

void cdecl ODBG_Pluginaction(int origin, int action, void *item) {
	char path[_MAX_PATH], mapline[TEXTLEN], log[128], msg[80], flag;
	OPENFILENAME ofn;
	FILE *in;
	unsigned int totals[2];
	unsigned __int32 signature;
	if (!*(char *)Plugingetvalue(VAL_PROCESSNAME)) {
		Addtolist (0,1,"MapConv ERROR: No process to add map info");
		information("Well - if you don't debug anything - your don't need .map file ;-)");
		return;
	}
	*path = 0;
	memset(&ofn, 0, sizeof ofn);
	ofn.lStructSize = sizeof ofn;
	ofn.hwndOwner = hwmain;
	ofn.hInstance = hInstance;
	ofn.nFilterIndex = 1;
	ofn.nMaxFile = sizeof path;
	ofn.lpstrFile = path;
	ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
		OFN_LONGNAMES | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
		OFN_HIDEREADONLY;
	ofn.lpstrFilter = "all mapfiles (*.map;*.map2)\0*.map;*.map2\0"
		"std. mapfiles (*.map)\0*.map\0"
		"idaplug extension mapfiles (*.map2)\0*.map2\0"
		"all files\0*.*\0";
	ofn.lpstrTitle = "Enter MAP file name";
	ofn.lpstrDefExt = "map";
	if (!GetOpenFileName(&ofn)) return;
#ifdef _DEBUG
	if (IsDebuggerPresent()) __asm int 3
#endif
	totals[0] = totals[1] = 0;
	if (!(in = fopen(path, "rbS")) || !fread(&signature, sizeof signature, 1, in)) {
		Addtolist(0, 1, "MapConv ERROR: Cannot open %s", path);
		return;
	}
	if (signature != '2pam') { /* std. format */
		t_module *pmodule = Findmodule((ulong)GetCurrentEIP());
		fclose(in);
		if (!(in = fopen(path, "rtS"))) return;
		while (fgets(mapline, sizeof mapline, in)) {
			/* strip line breaks */
			while (*mapline && (mapline[strlen(mapline) - 1] == '\r'
				|| mapline[strlen(mapline) - 1] == '\n'))
				mapline[strlen(mapline) - 1] = 0;
			/* parse line */
			if (pmodule && !strncmp(mapline, " 0001:", 6)
				&& !strncmp(mapline + 15, "      ", 6)) {
				char iscomment;
				mapline[14] = 0;
				if (!Insertname(pmodule->codebase + strtoul(mapline + 6, 0, 16),
					(iscomment = (flag = mapline[21] == ';')) ? NM_COMMENT : NM_LABEL,
					mapline + 21 + flag)) totals[iscomment]++;
			}
		} /* file scan */
	} else { /* .map2 format */
		unsigned long offset;
		DWORD imagebase = 0;
		while (fread(&offset, sizeof offset, 1, in)) {
			char discard, index, *ptr = mapline;
			int type;
			while (fread(ptr < mapline + sizeof mapline ? ptr : &discard, 1, 1, in)
				&& (ptr < mapline + sizeof mapline ? *ptr++ : discard));
			mapline[sizeof mapline - 1] = 0;
			ptr = mapline;
			flag = *ptr;
			if (flag && flag < 0x20 || flag == ';') ++ptr; else flag = 0;
			if (!*ptr) continue;
			chomp(ptr, sizeof mapline - (flag ? 1 : 0));
			if (!imagebase) { /* header? */
				imagebase = offset;
				Addtolist(imagebase, 0, "MapConv message: setting imagebase from mapfile to %08lX",
					imagebase);
				FindModuleBase(ptr, &imagebase);
				if (!imagebase) break; /* imagebase = Findmodule((ulong)GetCurrentEIP())->base; */
				continue;
			} /* header? */
			if (index = flag == ';')
				type = NM_COMMENT;
			else if ((flag & 0x18) == 0x18 /* function start */
				|| !(flag & 0x10) /* data label or unknown type */)
				type = NM_LIBRARY;
			else
				type = NM_LABEL;
			if (!Insertname(imagebase + offset, type, ptr)) totals[index]++;
		} /* file walk */
	}
	fclose(in);
	strcpy(log, "MapConv: OK: ");
	sprintf(msg, "Map file successfuly imported.\n%8u labels updated\n%8u comments updated",
		totals[0], totals[1]);
	Addtolist(0, 0, strcat(log, msg));
	information(msg);
	Setcpu(0, 0, 0, 0, CPU_ASMFOCUS);
}

char *chomp(char *s, const size_t maxlen) {
	char *tmp, *scansrc, *scantgt;
	if (!s || !*s || !(tmp = (char *)malloc(strlen(s) * 5 + 1))) return s;
	scansrc = s;
	scantgt = tmp;
	*tmp = 0;
	while (*scansrc) {
		switch (*(unsigned char *)scansrc) {
			case 0x07: { sprintf(scantgt, "\\a"); scantgt += 2; break; }
			case 0x08: { sprintf(scantgt, "\\b"); scantgt += 2; break; }
			case 0x09: { sprintf(scantgt, "\\t"); scantgt += 2; break; }
			case 0x0A: { sprintf(scantgt, "\\n"); scantgt += 2; break; }
			case 0x0B: { sprintf(scantgt, "\\v"); scantgt += 2; break; }
			case 0x0C: { sprintf(scantgt, "\\f"); scantgt += 2; break; }
			case 0x0D: { sprintf(scantgt, "\\r"); scantgt += 2; break; }
			default: *scantgt++ = *scansrc;
		}
		++scansrc;
	}
	*scantgt = 0;
	strncpy(s, tmp, maxlen - 1);
	s[maxlen - 1] = 0;
	free(tmp);
	return s;
}
