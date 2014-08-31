
/*****************************************************************************
 *                                                                           *
 *  flowinsp.cpp: Simple runtime address resolver                            *
 *  (c) 2005-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif // __cplusplus

#if IDP_INTERFACE_VERSION >= 76
//#include <algorithm>
//#include <boost/functional.hpp>
#else
#include <numeric>
#endif
#include <memory>
#include <hash_map>
#include <hash_set>
#include <boost/ptr_container/ptr_vector.hpp>
#include "debugger.hpp"
#ifdef GetModuleBaseName
#undef GetModuleBaseName
#endif
#include "plugida.hpp"
#include "batchres.hpp"
#include "rtrlist.hpp"

#define _SHOWADDRESS     1

#define OPT_FUNCSONLY    1
#define OPT_USRONLY      (OPT_FUNCSONLY << 1)
#define OPT_CODEONLY     (OPT_USRONLY << 1)
#define OPT_XREFS        (OPT_CODEONLY << 1)
#define OPT_COMMENTS     (OPT_XREFS << 1)
#define OPT_NAMEOFFSETS  (OPT_COMMENTS << 1)
#define OPT_MAKEFUNCS    (OPT_NAMEOFFSETS << 1)
#define OPT_SHOWPROGRESS (OPT_MAKEFUNCS << 1)

class CResolver : public CDebugger {
private:
	mutable bool oncestarted;
	mutable uint total_resolved;
	uint16 options;
	CBatchResults *pBatchResults;
	mutable modules_t::const_iterator module;
	mutable layered_wait_box wait_box;
	mutable hash_map<ea_t, hash_set<PVOID> > trigerred;
	mutable hash_map<ea_t, hash_set<PVOID> >::iterator it;
	mutable auto_ptr<CRTRList> list;

	bool isLoaded() const { return module != modules.end(); }
	void NameAnonOffsets(const char *tgtname, const char *cmt = 0);
	static cref_t GetCRefType(const insn_t &cmd) {
		switch (cmd.itype) {
			case NN_jmp: return cmd.Op1.type == o_near ? fl_JN : fl_JF;
			case NN_call: return cmd.Op1.type == o_near ? fl_CN : fl_CF;
			case NN_jmpshort: return fl_JN;
			case NN_jmpni: return fl_JN;
			case NN_callni: return fl_CN;
			case NN_jmpfi: return fl_JF;
			case NN_callfi: return fl_CF;
		} // switch
		_RPT3(_CRT_WARN, "%s(...): unknown itype(%hu) for %08IX\n", __FUNCTION__,
			cmd.itype, cmd.ea);
		return is_jump_insn(cmd.itype) ? fl_JN : is_call_insn(cmd.itype) ? fl_CN : fl_U;
	}

protected:
	// debugger overrides
	void OnCreateProcess() const;
	void OnLoadDll(const module_t &) const;
	/*virtual */void OnModuleAvailable() const;
	DWORD OnBreakpoint(breakpoint_type_t Type, LPVOID Address) const {
		__super::OnBreakpoint(Type, Address);
		if (wasBreak()) {
			msg("user break\n");
			clearBreak();
			Terminate();
			return DBG_TERMINATE_PROCESS;
		}
		if (Type == bpt_sw/* || Type == bpt_hw_exec*/) {
			_ASSERTE(isLoaded());
			const ea_t ea =
				reinterpret_cast<ea_t>(Address) - module->getBaseOffset()/*???*/;
			_ASSERTE(::isLoaded(ea));
			_ASSERTE(is_indirectflow_insn(ea));
			if ((it = trigerred.find(ea)) == trigerred.end())
				it = trigerred.insert(make_pair(ea, hash_set<PVOID>())).first;
			if ((options & OPT_SHOWPROGRESS) != 0) showAddr(ea);
			SingleStep();
		}
		return DBG_CONTINUE;
	}
	DWORD OnSingleStep() const;
	void OnUnloadDll(const module_t &module) const {
		__super::OnUnloadDll(module);
		if (islibrary && isLoaded() && module == *this->module) {
			DisableBreakpoints(bpt_sw);
			this->module = modules.end();
			it = trigerred.end();
			msg("%stracing stopped due to dll unload, waiting till loaded again or process exit...\n", prefix);
		}
	}
	void OnCrash() const;
	void OnExitProcess() const;

public:
	static const char prefix[];
	static boost::ptr_vector<CRTRList> lists;
	bool islibrary;

	CResolver(uint16 options = OPT_FUNCSONLY | OPT_XREFS | OPT_COMMENTS |
		OPT_NAMEOFFSETS | OPT_MAKEFUNCS) : CDebugger(TRUE), it(trigerred.end()),
		total_resolved(0), options(options), islibrary(false) {
		bIgnoreExternalExceptions = TRUE;
		pBatchResults = (CBatchResults *)GetProcAddress(::GetModuleHandle("fubar.plw"),
			"?batchlist@@3VCBatchResults@@A");
		if (pBatchResults != 0 && *pBatchResults <= 0) pBatchResults = 0; // only add to existing list
	}
}; // CResolver

const char CResolver::prefix[] = "[flowinsp] ";
boost::ptr_vector<CRTRList> CResolver::lists;

void CResolver::OnCreateProcess() const {
	__super::OnCreateProcess();
	if (islibrary) {
		char inpath[QMAXPATH];
		module = get_input_file_path(CPY(inpath)) > 0 ? modules[inpath] : modules.end();
		_ASSERTE(!isLoaded() || !isMain(module));
		if (!isLoaded()) msg("%swaiting for the dll to load...\n", prefix);
	} else {
		module = mainModule();
		_ASSERTE(isMain(module));
	}
	oncestarted = false;
	if (isLoaded()) OnModuleAvailable();
	HideDebugger();
}

void CResolver::OnLoadDll(const CDebugger::module_t &module) const {
	__super::OnLoadDll(module);
	if (!isLoaded() && islibrary) {
		_ASSERTE(!isMain(module));
		char inpath[QMAXPATH];
		if (get_input_file_path(CPY(inpath)) > 0 && module.has_fname(inpath)) {
			this->module = modules[module];
			_ASSERTE(isLoaded() && !isMain(this->module));
		}
		if (isLoaded()/* || (this->module = modules[inpath]) != modules.end()*/) {
			msg("%s%s was loaded at %08X\n", prefix, this->module->getBaseName(),
				this->module->lpBaseOfImage);
			OnModuleAvailable();
		}
#ifdef _DEBUG
		else
			_ASSERTE(modules[inpath] == modules.end());
#endif // _DEBUG
	}
}

void CResolver::OnModuleAvailable() const {
	_ASSERTE(isLoaded());
	if (isLoaded()) {
		if (!oncestarted) {
			wait_box.open("gathering evaluated flow points, be patient...");
			msg("%scollecting indirect callz...", prefix);
			area_t area;
			// if selection, trace only selection
			if (!read_selection(area)) {
				area.startEA = inf.minEA;
				area.endEA = inf.maxEA;
			}
			uint total(0);
#ifdef _SHOWADDRESS
			ea_t lastAuto(0);
#endif // _SHOWADDRESS
			try {
				while (area.startEA < area.endEA) {
					if (wasBreak()) {
						DeleteBreakpoints();
						msg("user break, ");
						clearBreak();
						break;
					}
					segment_t *segment(getseg(area.startEA));
					if (segment == 0) {
						area.startEA = next_head(area.startEA, area.endEA);
						continue;
					} else { // segment
						if ((options & OPT_CODEONLY) != 0 && segment->type != SEG_CODE) {
							area.startEA = segment->endEA;
							continue;
						}
						while (area.startEA < std::min(segment->endEA, area.endEA)) {
#ifdef _SHOWADDRESS
							if (area.startEA > lastAuto + AUTOFREQ) showAddr(lastAuto = area.startEA);
#endif // _SHOWADDRESS
							func_t *func(get_fchunk(area.startEA));
							if ((options & OPT_USRONLY) != 0 && is_true_libfunc(func)) {
								area.startEA = func->endEA;
								continue;
							}
							hash_set<RegNo, hash<int> > seg_sels;
							if ((func != 0 || (options & OPT_FUNCSONLY) == 0
								&& !is_fake_code(area.startEA))
								&& (seg_sels = get_segs_used(area.startEA)).count(R_es) <= 0
								&& seg_sels.count(R_fs) == 0 && seg_sels.count(R_gs) <= 0
								&& is_indirectflow_insn(area.startEA)
								&& (get_flags_novalue(area.startEA) & FF_JUMP) == 0 // ignore jumptables
								&& !does_ref_extern(area.startEA)
								&& SetSwBreakpoint(reinterpret_cast<LPCVOID>(area.startEA + module->getBaseOffset()))) {
#ifdef _SHOWADDRESS
								showAddr(area.startEA);
#endif // _SHOWADDRESS
								++total;
							}
							area.startEA = next_head(area.startEA, area.endEA);
						} // subloop
					} // segment
				} // range loop
			} catch (const exception &e) {
				msg("got %s, dying\n", e.what());
			} catch (...) {
				msg("got %s, dying\n", "unknown exception");
			}
			wait_box.close();
			if (!breakpoints.empty()) {
				_ASSERTE(total == breakpoints.size());
				msg("%u found\n", total);
				if (!oncestarted && MessageBox(get_ida_hwnd(),
					"only those calls/jumps can be resolved that will be passed by the instruction pointer\n"
					"its recommended to run the app the way desired functions are executed.\n\n"
					"warning, the application may run _very_ slow, if it has anti-debug traps it may crash\n"
					"even. close the application manually when needed, address resolving works infinitely as\n"
					"long as host app is alive.\n\n"
					"another warning: the tracer fully relies on ida's analysis, if there are misplaced\n"
					"indirect callz/jumpz at real data area, the application may behave unexpectedly or\n"
					"even crash.\n\n"
					"another another warning: plugin fully executes code in target module so beware of\n"
					"resolving targets possibly containing malicious code (ie. viruses, trojans, spyware\n"
					"etc.)\n\n"
					"are you sure to start resolving now?", PLUGINNAME " v" PLUGINVERSIONTEXT,
					MB_ICONQUESTION | MB_YESNO) != IDYES) {
					Terminate();
					return;
				}
				wait_box.open("please wait, plugin is running...");
				_ASSERTE(list.get() == 0);
				list.reset(new(nothrow) CRTRList);
				_ASSERTE(list.get() != 0);
				oncestarted = true;
			} else {
				msg("none found, dying\n");
				Terminate(0);
				return;
			}
		} else // oncestarted
			EnableBreakpoints(bpt_sw);
		msg("%stracing started...\n", prefix);
	}
}

void CResolver::NameAnonOffsets(const char *tgtname, const char *cmt) {
	_ASSERTE(it != trigerred.end());
	if (it == trigerred.end()) return;
	_ASSERTE(isEnabled(it->first));
	_ASSERTE(tgtname != 0);
	flags_t flags;
	if (!isEnabled(it->first) || tgtname == 0 || *tgtname == 0
		|| !isCode(flags = get_flags_novalue(it->first)) || ua_ana0(it->first) <= 0)
		return;
	member_t *stkvar;
	char newname[MAXNAMESIZE];
	ea_t tgt;
	sval_t actval;
	if (cmd.Op1.type == o_mem && isEnabled(tgt = calc_reference_target(cmd, 0))
		&& !is_in_rsrc(tgt) && !has_name(get_flags_novalue(tgt))) {
		_ASSERTE(!does_ref_extern(it->first));
		qsnprintf(CPY(newname), "lp%s", tgtname);
		newname[2] = static_cast<char>(toupper(static_cast<uchar>(newname[2])));
		if (do_name_anyway(tgt, newname, MAXNAMESIZE - 1)) {
			msg("%s  info: offset at %08a renamed to %s\n", prefix, tgt, newname);
			if (cmt != 0 && *cmt != 0) append_unique_cmt(tgt, cmt, true/*repeatable*/);
		}
		if (tgt == get_item_head(tgt) && !isArray(tgt)
			&& op_offset(tgt, 0, get_default_reftype(tgt)) != 0) {
			analyze_area(tgt, next_not_tail(tgt));
			if (pBatchResults != 0) pBatchResults->Add(tgt, 0x0005,
				_sprintf("ok: dref to %s", tgtname).c_str());
			msg("%s  info: offset created at %08a\n", prefix, tgt);
			nameanonoffsets_internal(tgt, 3/*verbosity*/, prefix, pBatchResults);
		} // new offset ok
	} else if (isStkvar0(flags) && (stkvar = get_stkvar(cmd.Op1,
		static_cast<sval_t>(cmd.Op1.addr), &actval)) != 0
		&& (get_member_name(stkvar->id, CPY(newname)) <= 0
		|| is_dummy_member_name(newname))) {
		qsnprintf(CPY(newname), "lp%s", tgtname);
		newname[2] = static_cast<char>(toupper(static_cast<uchar>(newname[2])));
		uint16 suffix(2);
		uval_t discard;
		while (suffix != 0 && get_name_value(it->first, newname, &discard) == NT_STKVAR) {
			qsnprintf(CPY(newname), "lp%s_%hu", tgtname, suffix++);
			newname[2] = static_cast<char>(toupper(static_cast<uchar>(newname[2])));
		}
		if (set_member_name(get_frame(get_func(it->first)), stkvar->get_soff(), newname)) {
			msg("%s  info: variable at %08a renamed to %s\n", prefix, it->first, newname);
			if (cmt != 0 && *cmt != 0) set_member_cmt(stkvar, cmt, true/*repeatable*/);
		}
	} // is stkvar
}

DWORD CResolver::OnSingleStep() const {
	__super::OnSingleStep();
	_ASSERTE(isLoaded());
	_ASSERTE(it != trigerred.end());
	if (it == trigerred.end()) return DBG_CONTINUE;
	if (it->second.insert(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress).second
		&& isEnabled(it->first)) {
		const modules_t::const_iterator module(modules.find(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, FALSE));
		if (module == modules.end()) {
			_RPT2(_CRT_WARN, "%smodule not found for IP=%08X\n", prefix, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
			return DBG_CONTINUE;
		}
		char name[MAXNAMESIZE], tmpstr[512];
		if (module == this->module) { // same module
			const ea_t to(reinterpret_cast<ea_t>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress) - module->getBaseOffset());
			if ((options & OPT_SHOWPROGRESS) != 0) showAddr(to);
			if (isEnabled(to)) {
				xrefblk_t xref;
				for (bool dupe = xref.first_from(it->first, XREF_FAR); dupe; dupe = xref.next_from()) {
					if (!xref.iscode) continue;
					if (xref.to == to) break;
				}
				if (!dupe) {
					++total_resolved;
					uint16 type;
					// care x-ref
					if (isCode(get_flags_novalue(it->first)) && ua_ana0(it->first) > 0) {
						type = static_cast<uint16>(GetCRefType(cmd));
						if ((options & OPT_XREFS) != 0)
							add_cref(it->first, to, static_cast<cref_t>(type | XREF_USER));
						if ((options & OPT_MAKEFUNCS) != 0 && is_call_insn(cmd.itype)) {
							func_t *func(get_fchunk(to));
							if (func != 0 && func->startEA != to) {
								del_func(func->startEA);
								func = 0;
							}
							if (func == 0 && add_func(to, BADADDR) != 0) {
								if ((func = get_fchunk(to)) != 0) analyze_area(*func);
								if (get_func_name(to, CPY(name)) == 0) {
									name[0] = 0;
									_RPTF2(_CRT_WARN, "%s(): get_func_name(%08IX, ...) returned NULL\n",
										__FUNCTION__, to);
								}
								msg("%snew function at %08a created: %s\n", prefix, to, name);
								if (pBatchResults != 0) pBatchResults->Add(to, 0x0003,
									_sprintf("new function %s created", name).c_str());
							} // new func created
						} // is call
					} else {
						type = static_cast<uint16>(dr_I);
						if ((options & OPT_XREFS) != 0)
							add_dref(it->first, to, static_cast<dref_t>(type | XREF_USER));
					}
					if (get_true_name(BADADDR, to, CPY(name)) == 0) name[0] = 0;
					// care overview list
					qstrcpy(tmpstr, (options & OPT_XREFS) != 0 ? "xref created" :
						(options & OPT_COMMENTS) != 0 ? "target denoted in comment" : "reported only");
					if (name[0] != 0) qsnprintf(CAT(tmpstr), " (%s)", name);
					if (list.get() != 0) list->Add(it->first, to, type, tmpstr);
					// care comment
					if ((options & OPT_COMMENTS) != 0) {
						qsnprintf(CPY(tmpstr), "evaluated address resolved: %08a", to);
						const ea_t caller_head(get_item_head(it->first));
						char cmt[MAXSPECSIZE];
						if (GET_CMT(caller_head, false, CPY(cmt)) < 1
							|| strstr(cmt, tmpstr) == 0) {
							if (name[0] != 0) qsnprintf(CAT(tmpstr), " (%s)", name);
							append_cmt(caller_head, tmpstr, false);
						}
					}
					// care log window
					msg("%sevaluated address resolved: %08a -> %08a", prefix, it->first, to);
					if (name[0] != 0) msg(" (%s)", name);
					msg("\n");
					// rename if offset by operand and convert to offset
					if ((options & OPT_NAMEOFFSETS) != 0)
						const_cast<CResolver *>(this)->NameAnonOffsets(name);
				} // x-ref unique
			} // isEnabled(to)
#ifdef _DEBUG
			else
				_RPT2(_CRT_WARN, "%s(): address %08IX not enabled despite in main module\n",
					__FUNCTION__, to);
#endif // _DEBUG
		} else { // module == extarnal module
			const module_t::exports_t::const_iterator
				export(module->exports[DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress]);
			if (export != module->exports.end()) {
#define to (reinterpret_cast<ea_t>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress))
				if ((options & OPT_SHOWPROGRESS) != 0) showAddr(to);
				++total_resolved;
				if (!export->Name.empty()) // ImpByName
					qsnprintf(CPY(name), "%s (%s)", export->Name.c_str(), module->getBaseName());
				else // ImpByOrd care if not 1-based
					qsnprintf(CPY(name), "%s@%hu", module->getBaseName(), export->Ordinal);
				// care overview list
				if (list.get() != 0) list->Add(it->first, to,
					static_cast<uint16>(isCode(get_flags_novalue(it->first))
					&& ua_ana0(it->first) > 0 ? GetCRefType(cmd) : dr_I), name);
				// care comment
				if ((options & OPT_COMMENTS) != 0) {
					qsnprintf(CPY(tmpstr), "evaluated address resolved: %s", name);
					append_unique_cmt(get_item_head(it->first), tmpstr);
				}
				// care log window
				msg("%sevaluated address resolved: %08a -> %08X (%s)\n",
					prefix, it->first, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, name);
				// rename if offset by operand and convert to offset
				if ((options & OPT_NAMEOFFSETS) != 0) {
					const char *cmt(0);
					if (!export->Name.empty()) { // ImpByName
						qstrcpy(name, export->Name.c_str());
						if (module->hasName()) cmt = module->getBaseName();
					} else { // ImpByOrd care if not 1-based
						char basename[_MAX_FNAME];
						_splitpath(module->getBaseName(), 0, 0, basename, 0);
						qsnprintf(CPY(name), "%s@%hu", basename, export->Ordinal);
					}
					const_cast<CResolver *>(this)->NameAnonOffsets(name, cmt);
				} // OPT_NAMEOFFSETS
#undef to
			} // has export
		} // what module?
	} // caller is set and not seen this pair
	it = trigerred.end();
	return DBG_CONTINUE;
}

void CResolver::OnCrash() const {
	__super::OnCrash();
	const modules_t::const_iterator
		module(modules.find(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, FALSE));
	msg("%swarning: application crash with exception %08lX in %s at %08X",
		prefix, DebugEvent.u.Exception.ExceptionRecord.ExceptionCode,
		module != modules.end() ? module->getBaseName() : "<unknown>",
		(LPBYTE)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress -
			(module != modules.end() ? module->getBaseOffset() : 0));
	boost::shared_crtptr<SYMBOL_INFO> pSymInfo(sizeof SYMBOL_INFO + MAX_SYM_NAME - 1);
	if (pSymInfo) {
		pSymInfo->MaxNameLen = MAX_SYM_NAME;
		DWORD64 Displacement;
		if (SymFromAddr(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress,
			&Displacement, pSymInfo.get())) {
			msg("(%s", pSymInfo->Name);
			if (Displacement > 0) msg("+0x%I64X", Displacement);
			msg(")");
		}
		pSymInfo.reset();
	}
	if (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
		msg(": couldnot %s %08lX", DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 0 ?
			"read from" : "write to", DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]);
	msg("\n%s  caller_ea=%08a flags=0x%lX\n", prefix, it != trigerred.end() ? it->first : BADADDR,
		DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags);
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
	if (GetThreadContext(Context, TRUE)) msg("%s  context dump: eax=%08lX ecx=%08lX edx=%08lX ebx=%08lX ebp=%08lX esp=%08lX esi=%08lX edi=%08lX eip=%08lX\n",
		prefix, Context.Eax, Context.Ecx, Context.Edx, Context.Ebx, Context.Ebp, Context.Esp, Context.Esi, Context.Edi, Context.Eip);
}

void CResolver::OnExitProcess() const {
	__super::OnExitProcess();
	trigerred.clear();
	it = trigerred.end();
	if (!breakpoints.empty()) {
		wait_box.close();
		msg("%sthe process terminated with exit code %li\n%stotal %u target addresses captured\n",
			prefix, DebugEvent.u.ExitProcess.dwExitCode, prefix, total_resolved);
	}
	if (list.get() != 0)
		if (*list > 0 && list->Open()) lists.push_back(list); else list.reset();
}

int idaapi init(void) {
	if (ph.id == PLFM_386 && inf.filetype == f_PE) return PLUGIN_OK;
	msg("%splugin not available for this processor or format\n", CResolver::prefix);
	return PLUGIN_SKIP;
}

void idaapi run(int arg) {
	BPX;
	if (arg == 0xFFFF || arg == -1) { // forced unload
#if IDP_INTERFACE_VERSION < 76
		if (accumulate(CONTAINER_RANGE(CResolver::lists), 0) > 0
			&& MessageBox(get_ida_hwnd(),
				"there is one or more lists hooked to this plugin.\n"
				"unloading the plugin now invalidates their callback\n"
				"handlers which results in producing program\n"
				"exceptions on accessing the lists, unload anyway?",
				"flowinsp forced unload",
			MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) return;
#endif // IDP_INTERFACE_VERSION < 76
		PLUGIN.flags |= PLUGIN_UNL;
		MessageBeep(MB_OK);
		return;
	}
	try {
		ushort opts[] = {
			OPT_FUNCSONLY | OPT_CODEONLY,
			(OPT_COMMENTS | OPT_XREFS | OPT_NAMEOFFSETS | OPT_MAKEFUNCS) >> 3,
			OPT_SHOWPROGRESS >> 7,
		};
		if (AskUsingForm_c(PLUGINNAME "\n<##Filter tracing regions##Inside functions only:C>\n"
			"<User code only (no library functions):C>\n<Inside code segments only:C>>\n\n"
			"<##If resolved...##Make code XRef:C>\n<Denote target in comment:C>\n"
			"<#Give anonymous static offsets meningful name according to target name for cases like call dword ptr [off_4580F0]#Rename dummy static offsets:C>\n"
			"<#Ensure target address is function or chunk start for all call type commands (existing functions are deleted first if not starting at target)#Care defined function at target:C>>\n\n"
			"<#Progress indicator is helpful to see how tracing executes but at some speed cost, so uncheck if speed is at prior###Show tracing progress:C>>\n\n",
			&opts[0], &opts[1], &opts[2]) == 0) return;
		if (!decide_ida_bizy(PLUGINNAME " v" PLUGINVERSIONTEXT)) {
			// Let the analysis make all data references to avoid variables merging.
			msg("%sautoanalysis is running now. call me again when finished\n", CResolver::prefix);
			MessageBeep(MB_ICONEXCLAMATION);
			return;
		}
		CResolver resolver(opts[0] | opts[1] << 3 | opts[2] << 7);
		char pathToExe[QMAXPATH];
		const ssize_t s = netnode("$ loader").valstr(CPY(pathToExe));
		if (s > 0)
			resolver.islibrary = true;
		else
			get_input_file_path(CPY(pathToExe));
		OPENFILENAME ofn;
		if (!qfileexist(pathToExe)) {
			memset(&ofn, 0, sizeof OPENFILENAME);
			ofn.lStructSize = sizeof OPENFILENAME;
			ofn.hwndOwner = get_ida_hwnd();
			ofn.hInstance = hInstance;
			ofn.nFilterIndex = 1;
			ofn.nMaxFile = QMAXPATH;
			ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
				OFN_LONGNAMES | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
				OFN_HIDEREADONLY;
			ofn.lpstrTitle = "host application not found, locate it...";
			ofn.lpstrFile = pathToExe;
			ofn.lpstrDefExt = "exe";
			char drive[_MAX_DRIVE], dir[_MAX_DIR], path[QMAXPATH];
			get_input_file_path(CPY(path));
			_splitpath(path, drive, dir, 0, 0);
			_makepath(path, drive, dir, 0, 0);
			ofn.lpstrInitialDir = path;
			ofn.lpstrFilter = "applications\0*.exe\0all files\0*.*\0";
			if (!GetOpenFileName(&ofn)) {
				msg("%suser cancel\n", CResolver::prefix);
				return;
			}
			if (s > 0)
				netnode("$ loader", 0, true).set(pathToExe);
			else if (MessageBox(get_ida_hwnd(), "remember new root?",
				PLUGINNAME " v" PLUGINVERSIONTEXT, MB_ICONQUESTION | MB_YESNO) == IDYES)
				change_root(pathToExe);
		}
	resolveagain:
		switch (resolver.DebugProcess(pathToExe)) {
			//case (DWORD)-1L:
			//	msg("%sthe app crushed!\n", prefix);
			//	break;
			case (DWORD)-2L:
				msg("%sprogramfile not found!\n", CResolver::prefix);
				_RPT3(_CRT_ASSERT, "%s(...): %s(\"%s\"): file doesnot exist\n",
					__FUNCTION__, "CDebugger::DebugProcess", pathToExe);
				break;
			case (DWORD)-3L:
				msg("%starget not a valid pe file!\n", CResolver::prefix);
				break;
			case (DWORD)-4L:
				msg("%sthe app failed to start!\n", CResolver::prefix);
				break;
			case (DWORD)-5L: {
				memset(&ofn, 0, sizeof OPENFILENAME);
				ofn.lStructSize = sizeof OPENFILENAME;
				ofn.hwndOwner = get_ida_hwnd();
				ofn.hInstance = hInstance;
				ofn.nFilterIndex = 1;
				ofn.nMaxFile = QMAXPATH;
				ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
					OFN_LONGNAMES | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
					OFN_HIDEREADONLY;
				ofn.lpstrFile = pathToExe;
				ofn.lpstrFilter = "Win32 applications\0*.exe\0all files\0*.*\0";
				ofn.lpstrTitle = "disassemblee is a dll, please locate a host loader first (must be directly executable)...";
				ofn.lpstrDefExt = "exe";
				char drive[_MAX_DRIVE], dir[_MAX_DIR], path[QMAXPATH];
				get_input_file_path(CPY(path));
				_splitpath(path, drive, dir, 0, 0);
				_makepath(path, drive, dir, 0, 0);
				ofn.lpstrInitialDir = path;
				if (!GetOpenFileName(&ofn)) {
					msg("%suser cancel\n", CResolver::prefix);
					return;
				}
				netnode("$ loader", 0, true).set(pathToExe);
				resolver.islibrary = true;
				goto resolveagain;
			}
			default:
				MessageBeep(MB_OK);
		}
	} catch (const exception &e) {
		msg("%s, lame stoopid servil ;p\n", e.what());
		MessageBeep(MB_ICONERROR);
		warning("%s, lame stoopid servil ;p", e.what());
	} catch (...) {
		msg("%s, lame stoopid servil ;p\n", "unhandled exception");
		MessageBeep(MB_ICONERROR);
		warning("%s, lame stoopid servil ;p", "unhandled exception");
	}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
#if IDP_INTERFACE_VERSION < 76
		if (ph.version != IDP_INTERFACE_VERSION) {
			char msg[MAX_PATH], tmp[MAX_PATH];
			GetModuleFileName(hinstDLL, CPY(msg));
			lstrcpyn(tmp, msg, qnumber(tmp));
			lstrcat(tmp, ".old");
			MoveFile(msg, tmp);
#ifdef wsprintfA
#undef wsprintfA
#endif // wsprintfA
			wsprintf(msg, "Cannot load plugin: this plugin is for IDP version %u (%i reported by kernel)\n\n"
				"Update or delete the plugin file", IDP_INTERFACE_VERSION, ph.version);
			MessageBox(get_ida_hwnd(), msg, PLUGINNAME " v" PLUGINVERSIONTEXT, MB_ICONEXCLAMATION | MB_OK);
			return FALSE;
		}
#endif // IDP_INTERFACE_VERSION < 76
#ifdef _DEBUG
		_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
		_CrtSetDbgFlag(/*_CRTDBG_CHECK_EVERY_1024_DF | */_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#else // !_DEBUG
		DWORD flOldProtect;
		VirtualProtect((PBYTE)hInstance + 0xE000, 0x4000, PAGE_READONLY, &flOldProtect);
#endif // _DEBUG
		DisableThreadLibraryCalls((HMODULE)hInstance = hinstDLL);
		se_exception::_set_se_translator();
	}
	return TRUE;
}

// ================================ENTRY POINT================================
plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION, PLUGIN_MOD | PLUGIN_DRAW | PLUGIN_UNL,
	init, 0, run, PLUGINNAME " v" PLUGINVERSIONTEXT, 0,
	"Resolve indirect calls/jumps\x085", "Ctrl-Y"
};
// ================================ENTRY POINT================================
