
#include <stdlib.h>
#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys\stat.h>
#include <string.h>
#include <memory.h>

#include <windows.h>

#include <Plugin.h>

HINSTANCE hInstance; // DLL instance
HWND      hwmain;    // Handle of main OllyDbg window
char      quickresolvemode, runtraceinit;
DWORD     callee;

unsigned long disassm(const unsigned long ip, t_disasm *disasm);

struct _flowpair_t;
typedef struct _flowpair_t *flowpair_p;
typedef struct _flowpair_t {
	unsigned long callee, called;
	flowpair_p next;
} flowpair_t;

flowpair_p flowtable;

char AddFlowPair(const DWORD callee, const DWORD called) {
	char msg[64];
	flowpair_p tmp, current = flowtable;
	while (current && current->next) {
		if (current->callee == callee && current->called == called) return 0; /* no dupes */
		current = current->next;
	}
	if (current && current->callee == callee && current->called == called)
		return 0; /* no dupes */
	tmp = (flowpair_p)malloc(sizeof (struct _flowpair_t));
	if (!tmp) return 0;
	tmp->callee = callee;
	tmp->called = called;
	tmp->next = 0;
	if (current) current->next = tmp; else flowtable = tmp;
	sprintf(msg, "[ip flow resolver] flow pair found: %08lX -> %08lX", callee, called);
	Addtolist(0, 0, msg);
	return 1;
}

void CleanFlowTable() {
	flowpair_p current = flowtable;
	while (current) {
		flowtable = current->next;
		free(current);
		current = flowtable;
	}
	return;
}

struct _bpxlist_t;
typedef struct _bpxlist_t *bpxlist_p;
typedef struct _bpxlist_t {
	DWORD ip;
	bpxlist_p next;
} bpxlist_t;

bpxlist_p ownbreakpoints, importedbreakpoints;

char AddOwnBreakpoint(bpxlist_p *listptr, const DWORD ip, const char cancelling) {
	bpxlist_p tmp, current;
	if (cancelling)
		Tempbreakpoint(ip, TY_ONESHOT | TY_KEEPCOND | TY_STOPAN);
	else
		if (Setbreakpointext(ip, TY_ACTIVE, 0, 0)) return 0;
	current = *listptr;
	while (current && current->next) {
		if (current->ip == ip) return 0; /* no dupes */
		current = current->next;
	}
	if (current && current->ip == ip) return 0; /* no dupes */
	tmp = (bpxlist_p)malloc(sizeof (struct _bpxlist_t));
	if (!tmp) return 0;
	tmp->ip = ip;
	tmp->next = 0;
	if (current) current->next = tmp; else *listptr = tmp;
	return 1;
}

void CleanBpxTable(bpxlist_p *listptr) {
	bpxlist_p current = *listptr;
	while (current) {
		*listptr = current->next;
		free(current);
		current = *listptr;
	}
	return;
}

char ForgetOwnBreakpoint(const DWORD ip) {
	bpxlist_p current, previous = 0;
	current = ownbreakpoints;
	while (current) {
		if (current->ip == ip) {
			bpxlist_p next = current->next;
			free(current);
			if (previous) previous->next = next; else ownbreakpoints = next;
			return 1;
		}
		previous = current;
		current = current->next;
	}
	return 0;
}

char IsImportedBreakpoint(const DWORD ip) {
	bpxlist_p current = importedbreakpoints;
	while (current) {
		if (current->ip == ip) return 1;
		current = current->next;
	}
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) hInstance = hinstDLL; // Mark plugin instance
	return TRUE;
}

int cdecl ODBG_Plugindata(char shortname[32]) {
	strcpy(shortname, "IP flow resolver");
	return PLUGIN_VERSION;
};

int cdecl ODBG_Pluginmenu(int origin, char data[4096], void *item) {
	static char menu[] =
		"0 &Import breakpoints from file|"
		"1 &Start quick ip resolving mode,"
		"2 S&top quick ip resolving mode|"
		"3 Sa&ve gathered flowtable to file,"
		"4 &Clear flowtable,"
		"5 &Delete imported breakpoints";
	switch (origin) {
		case PM_MAIN: {
			strcpy(data, menu);
			return 1;
		}
		case PM_DISASM: {
			sprintf(data, "IP flow resolver{%s}", menu);
			return 1;
		}
	} /* switch command */
	return 0;
};

int cdecl ODBG_Plugininit(int ollydbgversion, HWND hw, ulong *features) {
	if (ollydbgversion < PLUGIN_VERSION) return -1;
	hwmain = hw;
	quickresolvemode = 0;
	callee = 0;
	flowtable = 0;
	importedbreakpoints = ownbreakpoints = 0;
	runtraceinit = 0;
	return 0;
};

char FindModuleHandle(const char *modulename, LPDWORD imagebase) {
	int cntr;
	t_table *modules;
	if (!(modules = (t_table *)Plugingetvalue(VAL_MODULES))) return 0;
	for (cntr = 0; cntr < modules->data.n; ++cntr) {
		char *tmp = ((t_module *)((char *)modules->data.data + cntr *
			modules->data.itemsize))->path;
		if (strrchr(tmp, '\\')) tmp = strrchr(tmp, '\\') + 1;
		if (strrchr(tmp, '/')) tmp = strrchr(tmp, '/') + 1;
		if (!_stricmp(modulename, tmp)) {
			*imagebase = ((t_module *)((char *)modules->data.data +
				cntr * modules->data.itemsize))->base;
			return 1;
		}
	} // for loop
	return 0;
}

void cdecl ODBG_Pluginaction(int origin, int action, void *item) {
	char path[_MAX_PATH];
	OPENFILENAME ofn;
	unsigned int total;
	switch (action) {
		case 0: {
			char log[128], msg[80];
			FILE *in;
			DWORD signature, offset, imagebase;
			int cntr;
			if (!Plugingetvalue(VAL_HPROCESS)) {
				Addtolist(0, 1, "[ip flow resolver] error: %s", "no process to add breakpoints info");
				MessageBox(hwmain, "no process active", "IP flow resolver v1.0",
					MB_OK | MB_ICONERROR);
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
			ofn.lpstrFilter = "exported breakpoints (*.BPX)\0*.BPX\0"
				"all files\0*.*\0";
			ofn.lpstrTitle = "locate breakpoints file...";
			ofn.lpstrDefExt = "map";
			if (!GetOpenFileName(&ofn)) return;
			total = 0;
			signature = 0;
			if (!(in = fopen(path, "rbS")) || !fread(&signature, 3, 1, in)) {
				Addtolist(0, 1, "[ip flow resolver] error: %s", "cannot open %s", path);
				return;
			}
			if (signature != '\0xpb') {
				Addtolist(0, 1, "[ip flow resolver] error: %s", "invalid file format");
				return;
			}
			imagebase = 0;
			while (fread(&offset, sizeof offset, 1, in)) {
				ulong nextinsn;
				if (!imagebase) { // header?
					char discard, modulename[TEXTLEN], *ptr = modulename;
					while (fread(ptr < modulename + sizeof modulename ? ptr : &discard, 1, 1, in)
						&& (ptr < modulename + sizeof modulename ? *ptr++ : discard));
					modulename[sizeof modulename - 1] = 0;
					imagebase = offset;
					Addtolist(imagebase, 0, "[ip flow resolver] setting imagebase to default %08lX",
						imagebase);
					if (FindModuleHandle(modulename, &imagebase))
						Addtolist(imagebase, 0, "[ip flow resolver] imagebase for module %s found at %08lX",
							modulename, imagebase);
					if (!imagebase) break;
					continue;
				} // header?
				if (AddOwnBreakpoint(&importedbreakpoints, offset += imagebase, 0))
					++total;
			} // file walk
			fclose(in);
			strcpy(log, "[ip flow resolver] ok: ");
			sprintf(msg, "%u breakpoints successfuly imported", total);
			Addtolist(0, 0, strcat(log, msg));
			MessageBox(hwmain, msg, "IP flow resolver v1.0", MB_OK | MB_ICONINFORMATION);
			Setcpu(0, 0, 0, 0, CPU_ASMFOCUS);
			break;
		}
		case 1: {
			quickresolvemode = 1;
			Addtolist(0, 0, "[ip flow resolver] quick address resolving mode  %s", "started");
			if (Plugingetvalue(VAL_HPROCESS))
				Go(0, 0, STEP_RUN, 1, 1);
			else
				MessageBox(hwmain, "no process is active. the quick resolver feature\n"
					"will activate when a new process is run", "IP flow resolver v1.0",
					MB_OK | MB_ICONINFORMATION);
			break;
		}
		case 2: {
			quickresolvemode = 0;
			Addtolist(0, 0, "[ip flow resolver] quick address resolving mode %s", "stopped");
			if (Plugingetvalue(VAL_HPROCESS)) Suspendprocess(1);
			break;
		}
		case 3: {
			char *namepart;
			t_module* mod;
			int fio;
			flowpair_p current;

			if (!flowtable) {
				Addtolist(0,1,"[ip flow resolver] error: %s", "no flow data collected");
				MessageBox(hwmain, "no flow data collected yet", "IP flow resolver v1.0",
					MB_OK | MB_ICONERROR);
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
				OFN_LONGNAMES | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY;
			ofn.lpstrFilter = "flow data file (*.flw)\0*.flw\0"
				"all files\0*.*\0";
			ofn.lpstrTitle = "locate output file...";
			ofn.lpstrDefExt = "flw";
			if (!GetSaveFileName(&ofn)) return;
			mod = Findmodule(flowtable->callee);
			if (!mod) return; /* error */
			fio = _open(path, _O_BINARY | _O_CREAT | _O_TRUNC | _O_WRONLY, _S_IREAD);
			if (fio == -1) return; /* error */
			_write(fio, "flw", 3);
			namepart = strrchr(mod->path, '\\');
			if (!namepart) namepart = strrchr(mod->path, '/');
			if (!namepart) namepart = mod->path; else ++namepart;
			_write(fio, namepart, strlen(namepart) + 1);
			total = 0;
			current = flowtable;
			while (current != 0) {
				unsigned long buf = current->callee - mod->base;
				_write(fio, &buf, 4);
				buf = current->called - mod->base;
				_write(fio, &buf, 4);
				current = current->next;
				++total;
			}
			_close(fio);
			_chmod(path, _S_IREAD | _S_IWRITE);
			sprintf(path, "[ip flow resolver] %u flow pairs saved", total);
			Addtolist(0,0,path);
			break;
		}
		case 4: {
			CleanFlowTable();
			Addtolist(0, 0, "[ip flow resolver] flowtable was killed");
			break;
		}
		case 5: {
			t_table *bptable;
			t_bpoint *bpoint;
			unsigned int cntr;
			if (!importedbreakpoints) {
				Addtolist(0,1,"[ip flow resolver] error: %s", "cannot delete imported breakpoints");
				MessageBox(hwmain, "no breakpoint were imported in this session",
					"IP flow resolver v1.0", MB_OK | MB_ICONERROR);
				return;
			}
			bptable = (t_table *)Plugingetvalue(VAL_BREAKPOINTS);
			if (bptable)
				for (cntr = 0; cntr < bptable->data.n; ++cntr) {
					bpoint = (t_bpoint *)(bptable->data.data) + cntr;
					if (IsImportedBreakpoint(bpoint->addr))
						Manualbreakpoint(bpoint->addr, VK_F2, 0, 0, 0);
				}
			CleanBpxTable(&importedbreakpoints);
			Addtolist(0, 0, "[ip flow resolver] imported breakpoints killed");
			break;
		}
	} // switch statement
	return;
}

unsigned long disassm(const unsigned long ip, t_disasm *disasm) {
	unsigned long offset, psize;
	char src[MAXCMDSIZE];
	Readcommand(ip, src);
	offset = Disasm(src, sizeof src, ip, Finddecode(ip, &psize), disasm,
		DISASM_ALL, Getcputhreadid());
	return offset;
}

char isjump(const int cmdtype) {
	return cmdtype == C_JMP || cmdtype == C_CAL
		|| cmdtype == C_JMC || cmdtype == C_RET;
}

int cdecl ODBG_Pausedex(int reason, int extdata, t_reg *reg,
	DEBUG_EVENT *debugevent) {
	char isoneshot, isi3;
	if ((reason & PP_MAIN) == PP_TERMINATED) {
		quickresolvemode = 0;
		callee = 0;
		runtraceinit = 0;
		CleanBpxTable(&ownbreakpoints);
		CleanFlowTable();
		Addtolist(0,0,"[ip flow resolver] plugin was reset on program close");
		return 0;
	}
	if ((reason & PP_MAIN) != PP_EVENT || !quickresolvemode) return 0;
	isoneshot = reason == (PP_EVENT | PP_SINGLESTEP) || reason == (PP_EVENT | PP_HWBREAK);
	isi3 = reason == (PP_EVENT | PP_INT3BREAK);
	if (isoneshot || isi3) {
		t_disasm disasm;
		unsigned long offset = disassm(reg->ip, &disasm);
		if (callee) {
			AddFlowPair(callee, reg->ip);
			if (!isjump(disasm.cmdtype)) AddOwnBreakpoint(&ownbreakpoints, reg->ip + offset, 1);
			callee = 0;
			Go(0, 0, STEP_RUN, 1, 1);
		}
		if ((disasm.memtype != DEC_UNKNOWN || disasm.optype[0] >= 0x024
			&& disasm.optype[0] < 0x02C) && (disasm.cmdtype == C_JMP
			|| disasm.cmdtype == C_CAL || disasm.cmdtype == C_JMC)) {
			callee = disasm.ip;
			if (disasm.jmpaddr) {
				AddFlowPair(disasm.ip, disasm.jmpaddr);
				offset = disassm(disasm.jmpaddr, &disasm);
				if (!isjump(disasm.cmdtype)) AddOwnBreakpoint(&ownbreakpoints,
					disasm.ip + offset, 1);
			}
			/*
			else if (disasm.cmdtype == C_CAL)
				AddOwnBreakpoint(&ownbreakpoints, disasm.ip + offset, 1);
			*/
			if (!runtraceinit) Startruntrace(reg);
			runtraceinit = 1;
			/* Animate(ANIMATE_TRIN); */
			Go(0, 0, STEP_IN, 1, 1);
			return 0;
		} // is a [mem] jump
		if (ForgetOwnBreakpoint(reg->ip)) {
			Go(0, 0, STEP_RUN, 1, 1);
			return 1;
		}
	}
	return 0;
}
