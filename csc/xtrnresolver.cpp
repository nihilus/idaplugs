
/*****************************************************************************
 *                                                                           *
 *  xtrnresolver.cpp: Code snippet creator plugin for ida pro               *
 *  (c) 2004-2005 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "pcre.hpp"
#include "plugida.hpp"
#include "rtrlist.hpp"
#include "xtrnresolver.h"

INT_PTR CALLBACK about_dlgproc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

/*****************************************************************************
 *  *
 *  C0MPONENT 2: RUNTIME ADDRESS RESOLVER  *
 *  *
 *****************************************************************************/

#define _SHOWADDRESS               1         // display progress

namespace RTR {

static char tracelog[QMAXPATH] = "";
static bool cmtrta, addref, quiet, verbose;
static ea_t imagebase, imgbase_history[9];
static uint8 traceregs;
static const char *options;
static const char prefix[] = "[rt] ";
static const char cfgsection[] = "RTI";

static void careview(bool listwasopen) {
	if (rtrlist > 0)
		if (!listwasopen)
			rtrlist.Open();
#if IDA_SDK_VERSION >= 520
		else
			rtrlist.Refresh();
#endif
#if IDP_INTERFACE_VERSION >= 76
// 	else
// 		rtrlist.Close();
#endif
}

static bool makeref(ea_t from, ea_t to) {
	if (!isEnabled(from) || !isEnabled(to)) return false;
	xrefblk_t xref;
	for (int ok = xref.first_from(from, XREF_FAR); ok; ok = xref.next_from()) {
		if (!xref.iscode) continue;
		if (to == xref.to) return false; // no dupes
	}
	if (ua_ana0(from) == 0) return true;
	// care x-ref
	if (addref)
		if (isCode(get_flags_novalue(from)) && ua_ana0(from))
#if IDP_INTERFACE_VERSION < 66
			add_cref(from, to, fl_US);
#else
		{
			cref_t ref;
			switch (cmd.itype) {
				case NN_jmp:
					ref = cmd.Op1.type == o_near ? fl_JN : fl_JF;
					break;
				case NN_jmpshort:
				case NN_jmpni:
					ref = fl_JN;
					break;
				case NN_call:
					ref = cmd.Op1.type == o_near ? fl_CN : fl_CF;
					break;
				case NN_callni:
					ref = fl_CN;
					break;
				case NN_jmpfi:
					ref = fl_JF;
					break;
				case NN_callfi:
					ref = fl_CF;
					break;
				default:
					ref = is_jump_insn(cmd.itype) ? fl_JN : fl_U;
			}
			add_cref(from, to, cref_t(ref | XREF_USER));
		}
#endif
		else
#if IDP_INTERFACE_VERSION < 66
			add_dref(from, to, dr_I);
#else
			add_dref(from, to, dref_t(dr_I | XREF_USER));
#endif
	char name[MAXNAMESIZE];
	if (get_true_name(BADADDR, to, CPY(name)) == 0) name[0] = 0;
	char tmpstr[512];
	// care comment
	if (cmtrta) {
		qsnprintf(CPY(tmpstr), "%sevaluated address resolved: %08a", prefix, to);
		char cmt[MAXSPECSIZE];
		if (GET_CMT(from, false, CPY(cmt)) <= 0 || strstr(cmt, tmpstr) == 0) {
			if (name[0]) qsnprintf(CAT(tmpstr), " (%s)", name);
			append_cmt(from, tmpstr, false);
		}
	}
	// care log window
	if (!quiet) cmsg << prefix << "evaluated address resolved at " << asea(from) << endl;
	// care overview list
	qstrcpy(tmpstr, "created ok");
	if (name[0]) qsnprintf(CAT(tmpstr), " (%s)", name);
	rtrlist.Add(from, to, cmd.itype == NN_callni ? fl_CN :
		cmd.itype == NN_jmpni ? fl_JN : cmd.itype == NN_callfi ? fl_CF :
		cmd.itype == NN_jmpfi ? fl_JF : fl_U, tmpstr);
	return true;
}

INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_INITDIALOG: {
			netnode rtr("$ rtr");
			CheckDlgButton(hwndDlg, IDC_REFRTI, GetPrivateProfileInt(cfgsection, "addref", true, inipath));
			CheckDlgButton(hwndDlg, IDC_CMTRTI, GetPrivateProfileInt(cfgsection, "cmtrta", true, inipath));
			traceregs = GetPrivateProfileInt(cfgsection, "traceregs", 0, inipath);
			for (UINT cntr = IDC_EAX; cntr <= IDC_EDI; ++cntr)
				CheckDlgButton(hwndDlg, cntr, (traceregs >> cntr - IDC_EAX & 1) * BST_CHECKED);
			GetPrivateProfileString(cfgsection, "tracelog", "", CPY(tracelog), inipath);
			SetDlgItemText(hwndDlg, IDC_TRACELOG, tracelog);
			SendDlgItemMessage(hwndDlg, IDC_IMGBASE, CB_RESETCONTENT, NULL, NULL);
			netnode penode("$ PE header");
			char tmp[17];
			IMAGE_NT_HEADERS pehdr;
			imagebase = penode != BADNODE
				&& penode.valobj(&pehdr, sizeof pehdr) >= sizeof pehdr ?
				pehdr.OptionalHeader.ImageBase : 0x00400000;
			qsnprintf(CPY(tmp), "%08a", imagebase);
			SetDlgItemText(hwndDlg, IDC_IMGBASE, tmp);
			for (cntr = 0; cntr < 9; ++cntr) {
				if ((imgbase_history[cntr] = GetPrivateProfileInt(cfgsection,
					_sprintf("imgbase_history_%u", cntr + 1).c_str(), 0, inipath)) != 0) {
					qsnprintf(CPY(tmp), "%08a", imgbase_history[cntr]);
					SendDlgItemMessage(hwndDlg, IDC_IMGBASE, CB_ADDSTRING, NULL, (LPARAM)tmp);
				}
			}
			quiet = GetPrivateProfileInt(cfgsection, "quiet", false, inipath);
			verbose = GetPrivateProfileInt(cfgsection, "verbose", false, inipath);
			RestoreDialogPos(hwndDlg, cfgsection);
			return 1;
		}
		case WM_DESTROY:
			SaveDialogPos(hwndDlg, cfgsection);
			SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
			return 1;
		case WM_COMMAND: {
			switch (LOWORD(wParam)) {
				case IDOK: {
					GetDlgItemText(hwndDlg, IDC_TRACELOG, CPY(tracelog));
					if (!qfileexist(tracelog)) {
						MessageBox(hwndDlg, "trace log doesnot exist!",
							"import runtime information", MB_ICONERROR);
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
						break;
					}
					char tmp[0x100];
					GetDlgItemText(hwndDlg, IDC_IMGBASE, CPY(tmp));
					imagebase = strtoul(tmp, 0, 16);
					if (imagebase == 0) {
						MessageBox(hwndDlg, "Image base is invalid!",
							"import runtime information", MB_ICONERROR);
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
						break;
					}
					WritePrivateProfileString(cfgsection, "tracelog", tracelog, inipath);
					save_bool(cfgsection, "addref", addref = IsDlgButtonChecked(hwndDlg, IDC_REFRTI));
					save_bool(cfgsection, "cmtrta", cmtrta = IsDlgButtonChecked(hwndDlg, IDC_CMTRTI));
					traceregs = 0;
					int cntr;
					for (cntr = 0; cntr < 8; ++cntr)
						traceregs |= (bool)IsDlgButtonChecked(hwndDlg, IDC_EAX + cntr) << cntr;
					save_byte(cfgsection, "traceregs", traceregs);
					for (cntr = 0; cntr < 9; ++cntr) {
						if (imgbase_history[cntr] == imagebase) imgbase_history[cntr] = 0;
						if (!imgbase_history[cntr]) break;
					}
					if (cntr > 8) cntr = 8;
					while (cntr > 0) imgbase_history[cntr--] = imgbase_history[cntr - 1];
					imgbase_history[0] = imagebase;
					for (cntr = 0; cntr < 9; ++cntr) save_dword(cfgsection,
						_sprintf("imgbase_history_%u", cntr + 1).c_str(), imgbase_history[cntr]);
				}
				case IDCANCEL:
					EndDialog(hwndDlg, LOWORD(wParam));
					SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
					break;
				case IDBROWSE: {
					GetDlgItemText(hwndDlg, IDC_TRACELOG, CPY(tracelog));
					char tmp2[QMAXPATH];
					if (!qfileexist(tracelog) && (!pcre_match("^\".*\"$", tracelog)
						|| (qstrcpy(tmp2, tracelog + 1), tmp2[strlen(tmp2) - 1]
						= 0, qstrcpy(tracelog, tmp2), !qfileexist(tracelog))))
						tracelog[0] = 0;
					OPENFILENAME ofn;
					memset(&ofn, 0, sizeof OPENFILENAME);
					ofn.lStructSize = sizeof OPENFILENAME;
					ofn.hwndOwner = hwndDlg;
					ofn.hInstance = hInstance;
					ofn.lpstrFilter = "ollydbg logs or ip flow resolver files\0*.txt;*.flw\0all files\0*.*\0";
					ofn.nFilterIndex = 1;
					ofn.nMaxFile = QMAXPATH;
					ofn.lpstrFile = tracelog;
					ofn.lpstrTitle = "locate ollydbg exported file";
					ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
						OFN_LONGNAMES | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
						OFN_HIDEREADONLY;
					ofn.lpstrDefExt = "txt";
					if (GetOpenFileName(&ofn)) SetDlgItemText(hwndDlg, IDC_TRACELOG, tracelog);
					SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
					break;
				}
				case IDABOUT:
					/*
					HFONT hFont = CreateFontIndirect((LPLOGFONT)LoadResource(hInstance,
						FindResource(hInstance, MAKEINTRESOURCE(IDF_CALIGRAPHIC),
						RT_FONT)));
					*/
					DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_ABOUT), hwndDlg,
						about_dlgproc, (LPARAM)"by _servil_ v" PLUGINVERSIONTEXT " " __DATE__);
					/* DeleteObject((HGDIOBJ)hFont); */
					SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
					break;
			} // switch WM_COMMAND
			return 1;
		} // WM_COMMAND
	} // switch uMsg
	return 0;
}

bool Execute() {
	if (DialogBox(hInstance, MAKEINTRESOURCE(IDD_RUNTIMEIMPORT), get_ida_hwnd(),
		DialogProc) != IDOK) false;
	if (!decide_ida_bizy("runtime flow resolver")) {
		// Let the analysis make all data references to avoid variables merging.
		cmsg << prefix << "autoanalysis is running now. call me again when finished" << endl;
		MessageBeep(MB_ICONEXCLAMATION);
		return false;
	}
	options = get_plugin_options("rtr");
	ea_t offset;
	IMAGE_NT_HEADERS pehdr;
	try {
		offset = netnode("$ PE header").valobj(&pehdr, sizeof pehdr) >= sizeof pehdr ?
			pehdr.OptionalHeader.ImageBase : 0;
	} catch (...) {
		cmsg << prefix << "  warning: failed to get image header" << endl;
		offset = 0x400000;
		if (!askaddr(
#if IDP_INTERFACE_VERSION < 66
			offset,
#else
			&offset,
#endif
			"enter image base manually:")) {
			cmsg << prefix << "user abort" << endl;
			return false;
		}
	}
	offset -= imagebase;
	bool listwasopen(rtrlist > 0);
	uint total(0);
	cmsg << prefix << "runtime address resolver importing from file '" <<
		tracelog << "'..." << endl;
	FILE *fio(qfopen(tracelog, "rtS"));
	if (fio == 0) {
		cmsg << prefix << "couldnot open input file, dying..." << endl;
		return false;
	}
	try {
		layered_wait_box wait_box("please wait, plugin is running...");
		char sig[3];
		if (qfread(fio, sig, sizeof sig) == sizeof sig
			&& strncmp(sig, "flw", 3) != 0) { // not a flow file
			qfseek(fio, 0, SEEK_SET);
			boost::scoped_array<char> line(new char[0x8000]);
			if (!line) throw bad_alloc();
			rtrlist.Clear();
			ea_t xref_ea(BADADDR), last_known_ea(BADADDR);
			asize_t last_known_ea_offset, tgt_ea_offset;
			uint32 r32[8];
			fill_n(CPY(r32), 0);
			const PCRE::regexp regex("^call|(?:j(?:mp|(?:n?(?:[abglp]e|[abceglopsz]))|cxz|po))|ret", PCRE_CASELESS, true);
			while (qfgets(line.get(), 0x8000, fio)) {
				if (wasBreak()) throw fmt_exception("user break");
				// cut the line
				char *addr, *insn, *cmt, *mod(strchr(line.get(), '\t'));
				addr = line.get();
				ea_t ea(BADADDR);
				if (mod != 0) { // tabulated format
					*mod++ = 0;
					if (!(insn = strchr(mod, '\t'))) continue; // invalid line
					*insn++ = 0;
					if (cmt = strchr(insn, '\t')) *cmt++ = 0;
				} else {
					if (line[0] == '<') ++addr;
					if (line[17] == ' ' || line[17] == '>')
						line[17] = 0;
					else {
						char name[19];
						qstrcpy(name, addr);
						name[18 + (line.get() - addr)] = 0;
						ea = get_name_ea(BADADDR, name);
					}
					if (!(mod = strchr(line.get(), ' '))) mod = line.get() + 17;
					*mod++ = 0;
					insn = line.get() + 18;
					if ((cmt = strchr(insn, ';')) != 0) {
						*cmt = 0;
						cmt += 2;
					}
				}
				char *stopscan;
				if (ea == BADADDR) {
					ea = strtoul(addr, &stopscan, 16) + offset;
					if ((stopscan < mod - 1 || !isEnabled(ea))) ea = get_name_ea(BADADDR, addr);
				}
				++last_known_ea_offset;
				if (ea == BADADDR) {
					while (last_known_ea != BADADDR && last_known_ea_offset-- > 0)
						last_known_ea = next_head(last_known_ea, getseg(last_known_ea)->endEA);
					ea = last_known_ea;
				}
				// handle run-time address from previous loop - must pass
				if (xref_ea != BADADDR && ea != BADADDR) { // ea points to unknown function start address
					while (ea != BADADDR && tgt_ea_offset-- > 0)
						ea = prev_head(ea, getseg(ea)->startEA);
					if (ea != BADADDR && (!get_func(ea)
						|| !get_func(xref_ea) || get_func(ea)->startEA != get_func(xref_ea)->startEA)
						&& ea != xref_ea + ua_ana0(xref_ea) && makeref(xref_ea, ea)) ++total;
					xref_ea = BADADDR;
				}
				// handle ea backward lookup information - must pass
				if (regex.match(insn))
					xref_ea = last_known_ea = BADADDR;
				else if (ea != BADADDR) {
					last_known_ea = ea;
					last_known_ea_offset = 0;
				} else
					++tgt_ea_offset;
				if (ea == BADADDR) continue; // couldnot get line address
#ifdef _SHOWADDRESS
				showAddr(ea);
#endif
				// detect runtime address calls/jumps
				flags_t flags(get_flags_novalue(ea));
				if (isCode(flags) && (flags & FF_JUMP) == 0 // ignore jumptables
					&& ua_ana0(ea) > 0 && is_indirectflow_insn(cmd.itype)
					&& !does_ref_extern(ea))
					if (cmd.Op1.type == o_reg && isEnabled(r32[cmd.Op1.reg] + offset)
						&& !is_in_rsrc(r32[cmd.Op1.reg] + offset)) {
						if (makeref(ea, r32[cmd.Op1.reg] + offset)) ++total;
					} else {
						xref_ea = ea;
						tgt_ea_offset = 0;
					}
				// care runtime register values
				if (cmt != 0) for (uint8 cntr = 0; cntr < 8; ++cntr) {
					char re[MAXNAMESIZE];
					int ovector[6];
					static const char r32names[][4] = {
						"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
					};
					if (!qsnprintf(CPY(re), "\\b%s\\s*=\\s*([[:xdigit:]]{8})\\b", r32names[cntr])
						|| pcre_exec(re, cmt, ovector, 6, PCRE_CASELESS) < 0) continue;
					r32[cntr] = strtoul(cmt + ovector[2], 0, 16);
					if ((traceregs >> cntr & 1) != 0 && ua_ana0(ea) > 0
						&& (cmd.itype != NN_mov || cmd.Op1.type != o_imm)) {
						string tmpbuf;
						_sprintf(tmpbuf, "%s%s = %08I32X", prefix, r32names[cntr], r32[cntr]);
						char idacmt[MAXSPECSIZE];
						if (GET_CMT(ea, false, CPY(idacmt)) <= 0
							|| strstr(idacmt, tmpbuf.c_str()) == 0) {
							if (get_true_name(BADADDR, r32[cntr] + offset, CPY(re)) != 0)
								_sprintf_append(tmpbuf, " (%s)", re);
							append_cmt(ea, tmpbuf.c_str(), false);
						} // comment doesn't exist
					} // not immediate assignments
				} // eveluate registers
			}
		} else {
			qfclose(fio);
			fio = qfopen(tracelog, "rbS"); // flow files are binary format
			if (fio == 0) throw fmt_exception("failed to open file '%s'", tracelog);
			rtrlist.Clear();
			qfseek(fio, 3, SEEK_SET); // skip signature
			char modname[QMAXPATH], *ptr(modname), rootname[QMAXPATH];
			do { qfread(fio, ptr, 1); } while (*ptr++ && !feof(fio));
			get_root_filename(CPY(rootname));
			if (_stricmp(modname, rootname) != 0) {
				cmsg << prefix << "warning: module name (" << modname << ") doesn't match" << endl;
				if (MessageBox(get_ida_hwnd(), "module name doesnot match, continue anyway?",
					"tracelog import plugin", MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2)
					!= IDYES) throw fmt_exception("module name mismatch ('%s'!='%s')",
						modname, rootname);
			}
			try {
				imagebase = netnode("$ PE header").valobj(&pehdr, sizeof pehdr) >= sizeof pehdr ?
					pehdr.OptionalHeader.ImageBase : 0x00400000;
			} catch (...) {
				imagebase = 0x00400000;
			}
			while (!feof(fio)) {
				ea_t callee, called;
				if (qfread(fio, &callee, sizeof callee) < sizeof callee
					|| qfread(fio, &called, sizeof called) < sizeof called) break;
				if (makeref(imagebase + callee, imagebase + called)) ++total;
			}
		}
	} catch (const exception &e) {
		if (fio != 0) qfclose(fio);
		cmsg << prefix << "fatal: " << e.what() << ", " << dec << total <<
			" xrefs resovled so far. giving up" << endl;
		careview(listwasopen);
		return false;
	}
	qfclose(fio);
	cmsg << prefix << "done: total " << dec << total << " xrefs resolved" << endl;
	careview(listwasopen);
	return true;
}

} // namespace
