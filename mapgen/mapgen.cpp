
/*****************************************************************************
 *                                                                           *
 *  mapgen.cpp: Extended map file exporter plugin for ida pro                *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif // __cplusplus

#include "pcre.hpp"      // regular expressions support
#include "plugida.hpp"   // common plugin functions

#include "undbgnew.h"
#include <list>
#include <fstream>
#include <iomanip>
#include "dbgnew.h"

static INT_PTR CALLBACK gen_map_dlgproc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
static void treat_checkbox(HWND hwndDlg, int nIDButton, const bool enable);

#define _SHOWADDRESS                          1         // display progress
#define BUFSIZE                          0x4000

#define GENFLG_MAPCOMMENTS             0x004000
#define GENFLG_MAPOLLY                 0x008000
#define GENFLG_MAPLOC                  0x010000
#define GENFLG_MAPENUM                 0x020000
#define GENFLG_MAPSTROFF               0x040000
#define GENFLG_MAPSTKVAR               0x080000
#define GENFLG_MAPFOP                  0x100000
#define GENFLG_MAPREGVAR               0x200000
#define GENFLG_TINFO                   0x400000

static UINT gen_map_file_flags, dlgpos_genmapfileex;
static const char prefix[] = "[mapgen] ";
static ea_t imagebase;
static uint totalnames, totalcomments, totalmembers, totalstkvars,
	totalfops, totalenums, totalstroffs, totalr32aliases, totaltypeinfos;
static char delimiter[16] = "; "; // use this sequence to divide altering descriptions in comments

#include "plug_abt.ipp"  // about box common handler

static int idaapi init(void) {
	if (ph.id == PLFM_386 && (inf.filetype == f_PE || inf.filetype == f_WIN
		|| inf.filetype == f_LX || inf.filetype == f_LE)) return PLUGIN_OK;
	cmsg << prefix << "plugin not available for current processor or format" << endl;
	return PLUGIN_SKIP;
}

static bool unique(const boost::scoped_array<char> &buf, const char *s,
	bool caseless = false) {
	_ASSERTE(buf);
	if (!buf) return false;
	const char *const match = caseless ?
		_stristr(buf.get(), s) : strstr(buf.get(), s);
	if (match == 0) return true;
	_ASSERTE(match >= buf.get());
	const size_t len[] = { strlen(delimiter), strlen(s), };
	return *(match + len[1]) != 0
			&& strncmp(match + len[1], delimiter, len[0]) != 0
		|| match != buf.get() && (match < buf.get() + len[0]
			|| strncmp(match - len[0], delimiter, len[0]) != 0);
}

static bool cat(const boost::scoped_array<char> &buf, const char *s, size_t size) {
	_ASSERTE(buf);
	if (!buf || !unique(buf, s)) return false;
	if (buf[0] != 0) qstrncat(buf.get(), delimiter, size);
	qstrncat(buf.get(), s, size);
}

static inline bool cat(const boost::scoped_array<char> &buf,
	const boost::scoped_array<char> &s, size_t size)
		{ return cat(buf, s.get(), size); }

static void enum_struct_members(const struc_t *struc, ea_t ea,
	const char *basename, ofstream &ofh) throw(exception) {
	_ASSERTE(struc != 0);
	if (struc == 0) return; //__stl_throw_invalid_argument("struct can't be NULL");
	_ASSERTE(isEnabled(ea));
	if (!isEnabled(ea)) return; //__stl_throw_invalid_argument("static address must be valid within module range");
	_ASSERTE(basename != 0 && *basename != 0);
	if (basename == 0 || *basename == 0) return; //__stl_throw_invalid_argument("basename must be nonempty C string");
	for (ea_t offset = get_struc_first_offset(struc);
		offset != BADADDR;
		offset = get_struc_next_offset(struc, offset)) {
		const member_t *const mem = get_member(struc, offset);
		if (mem == 0) continue;
		char memname[MAXSPECSIZE];
		if (get_member_name(mem->id, CPY(memname)) > 0 && isData(mem->flag)
			&& ((gen_map_file_flags & GENFLG_MAPNAME) != 0
			|| !is_dummy_member_name(memname) || isStruct(mem->flag))) {
			string name(basename);
			name.push_back('.');
			name.append(memname);
			if (!isStruct(mem->flag)) {
				const DWORD RVA = ea + offset - imagebase;
				if (!ofh.write((char *)&RVA, sizeof RVA)
					|| !ofh.write(name.c_str(), name.length() + 1))
					throw logic_error("error writing to file");
				++totalmembers;
			} else // is struct
				enum_struct_members(get_sptr(mem), ea + offset, name.c_str(), ofh);
		}
	}
}

#define GATHER_COMMENTS(startEA) \
	if (isFunc(get_flags_novalue(startEA))) { \
		func_t *const func(get_func(startEA)); \
		if ((tmp = get_func_cmt(func, true)) != 0) { WRITE_CMT(tmp) } \
		if ((tmp = get_func_cmt(func, false)) != 0) { WRITE_CMT(tmp) } \
	} \
	if (get_cmt(startEA, true, tmpbuf.get(), BUFSIZE) > 0) { WRITE_CMT(tmpbuf.get()) } \
	if (get_cmt(startEA, false, tmpbuf.get(), BUFSIZE) > 0) { WRITE_CMT(tmpbuf.get()) }

static void idaapi run(int arg) {
	BPX;
	try {
		dlgpos_genmapfileex = GetPrivateProfileInt("GenMapFileEx", "dlg_pos", 0, inipath);
		gen_map_file_flags = GetPrivateProfileInt("GenMapFileEx", "flags",
			GENFLG_MAPSEG | GENFLG_MAPCOMMENTS, inipath);
		if (DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_MAPOPTS), get_ida_hwnd(),
			gen_map_dlgproc, 0) != IDOK) return;
		char drive[_MAX_DRIVE], dir[_MAX_DIR], fname[_MAX_FNAME], path[QMAXPATH], outputfn[QMAXPATH];
		_splitpath(database_idb, drive, dir, fname, 0);
		_makepath(outputfn, drive, dir, fname, "map");
		if (gen_map_file_flags & GENFLG_MAPOLLY) qstrcat(outputfn, "2");
		OPENFILENAME ofn;
		memset(&ofn, 0, sizeof OPENFILENAME);
		ofn.lStructSize = sizeof OPENFILENAME;
		ofn.hwndOwner = get_ida_hwnd();
		ofn.hInstance = hInstance;
		ofn.nFilterIndex = 1;
		ofn.nMaxFile = QMAXPATH;
		ofn.lpstrFile = outputfn;
		ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
			OFN_LONGNAMES | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST |
			OFN_HIDEREADONLY;
		ofn.lpstrFilter = (gen_map_file_flags & GENFLG_MAPOLLY) != 0 ?
			"MapConv mapfiles (*.map2)\0*.map2\0all files\0*.*\0" :
			"Mapfiles (*.map)\0*.map\0all files\0*.*\0";
		ofn.lpstrTitle = "Enter MAP file name";
		ofn.lpstrDefExt = (gen_map_file_flags & GENFLG_MAPOLLY) != 0 ? "map2" : "map";
		_makepath(path, drive, dir, 0, 0);
		ofn.lpstrInitialDir = path;
		if (!GetSaveFileName(&ofn)) return;
		if (!decide_ida_bizy("map file exporter")) {
			// Let the analysis make all data references to avoid variables merging.
			cmsg << prefix << "autoanalysis is running now. call me again when finished" << endl;
			MessageBeep(MB_ICONEXCLAMATION);
			return;
		}
		const char *const plugin_options = get_plugin_options("mapgen");
		if (plugin_options != 0) {
			int ovector[6];
			const char *tmp;
			if (pcre_exec("\\bdelimiter\\s*[\\:\\=]\\s*(\\S*)", plugin_options,
				ovector, qnumber(ovector), PCRE_CASELESS) >= 2
				&& pcre_get_substring(plugin_options, ovector, 2, 1, &tmp) >= 0) {
				user2str(delimiter, tmp, qnumber(delimiter));
				pcre_free_substring(tmp);
			}
		}
		area_t area;
#ifdef _SHOWADDRESS
		ea_t lastAuto(0);
#endif // _SHOWADDRESS
		if (!read_selection(area)) {
			area.startEA = inf.minEA;
			area.endEA = inf.maxEA;
		}
		totalnames = 0;
		totalcomments = 0;
		totalmembers = 0;
		totalstkvars = 0;
		totalfops = 0;
		totalenums = 0;
		totalstroffs = 0;
		totalr32aliases = 0;
		totaltypeinfos = 0;
		boost::scoped_array<char> tmpbuf(new char[BUFSIZE]);
		if (!tmpbuf) {
			_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new string of size 0x%X\n",
				__FUNCTION__, BUFSIZE);
			throw bad_alloc(); //return;
		}
		layered_wait_box wait_box;
		char *tmp;
		if ((gen_map_file_flags & GENFLG_MAPOLLY) == 0) { // std. format
			FILE *fp(ecreateT(outputfn));
			if (fp == 0) return;
			if (gen_file(OFILE_MAP, fp, area, gen_map_file_flags & 0x7FFF) == -1) {
				eclose(fp);
				cmsg << prefix << "sjit, sumfing wrong during gen_file(...), sorry" << endl;
				return;
			}
			eclose(fp);
			if ((gen_map_file_flags & GENFLG_MAPCOMMENTS) != 0) { // append comments to mapfile
				wait_box.open("please wait, plugin is running...");
				list<string> mapfile;
				fstream is(outputfn, ios_base::in);
				if (is.is_open()) {
					while (is.good()) {
						string s;
						getline(is, s);
						if (is.fail()) break;
						mapfile.push_back(s);
					}
					is.close();
				}
				list<string>::iterator insert_at(mapfile.end());
				{
					const PCRE::regexp
						regex("entry point at\\s+[[:xdigit:]]{4}\\:[[:xdigit:]]{8}", 0, true);
					for (list<string>::iterator i = mapfile.begin(); i != mapfile.end(); ++i) {
						if (i->length() >= 19 && i->operator[](18) == ' ') ++totalnames;
						if (insert_at == mapfile.end() && regex.match(*i)) {
							insert_at = i;
							while (insert_at != mapfile.begin())
								if (!(--insert_at)->empty()) break;
							if (!insert_at->empty() && insert_at != i) ++insert_at;
						}
					}
				}
				if (mapfile.empty() || insert_at == mapfile.end()) return;
				while (area.startEA < area.endEA) {
					if (wasBreak()) {
						cmsg << prefix << "user break" << endl;
						clearBreak();
						break;
					}
#ifdef _SHOWADDRESS
					if (area.startEA > lastAuto + AUTOFREQ) showAddr(lastAuto = area.startEA);
#define SHOWADDR showAddr(area.startEA);
#else // !_SHOWADDRESS
#define SHOWADDR
#endif // _SHOWADDRESS
#define WRITE_CMT(cmt) { \
	SHOWADDR \
	segment_t *seg(getseg(area.startEA)); \
	_ASSERTE(seg != 0); \
	if (seg != 0) { \
		qsnprintf(CPY(line), " %04IX:%08IX       ;%s", seg->sel, \
			area.startEA - seg->startEA, cmt); \
		mapfile.insert(insert_at, chomp(CPY(line), false)); \
		++totalcomments; \
	} \
}
					char line[MAXSTR + 12];
					GATHER_COMMENTS(area.startEA)
#undef SHOWADDR
					area.startEA = next_not_tail(area.startEA); //nextthat(area.startEA, area.endEA, TESTFUNC(hasCmt));
				}
				is.open(outputfn, ios_base::out | ios_base::trunc);
				if (is.good()) {
					copy(CONTAINER_RANGE(mapfile), ostream_iterator<string>(is));
					is.close();
				}
			} // export comments ext.
		} else { // GENFLG_MAPOLLY
			boost::scoped_array<char> buf(new char[BUFSIZE]);
			if (!buf) {
				_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new string of size 0x%X\n",
					__FUNCTION__, BUFSIZE);
				throw bad_alloc(); //return;
			}
			ofstream ofh(outputfn, ios_base::out | ios_base::binary | ios_base::trunc);
			if (!ofh) {
				cmsg << prefix << "there was problem to open output file" << endl;
				return;
			}
			IMAGE_NT_HEADERS pehdr;
			if (netnode("$ PE header").valobj(&pehdr, sizeof pehdr) >= sizeof pehdr)
				imagebase = pehdr.OptionalHeader.ImageBase;
			else {
				imagebase = 0x00400000;
				cmsg << prefix << "WARNING: unable to get image header (image base defaulting to " <<
					ashex(imagebase, (streamsize)10, true) << ')' << endl;
				if (!askaddr(&imagebase, "guessed image base:")) {
					cmsg << prefix << "user abort" << endl;
					return;
				}
			}
			wait_box.open("please wait, plugin is running...");
			if (!ofh.write("map2", 4) || !ofh.write((char *)&imagebase, sizeof imagebase))
				throw fmt_exception("%s: error writing to file", outputfn);
			if (get_root_filename(tmpbuf.get(), BUFSIZE) <= 0)
				throw logic_error("couldnot get rootname");
			if (!ofh.write(tmpbuf.get(), strlen(tmpbuf.get()) + 1))
				throw fmt_exception("%s: error writing to file", outputfn);
			for (; area.startEA < area.endEA;
				area.startEA = (gen_map_file_flags & GENFLG_MAPCOMMENTS) != 0 ?
					next_not_tail(area.startEA) :
					nextthat(area.startEA, area.endEA, hasAnyName)) {
				if (wasBreak()) {
					cmsg << prefix << "user break" << endl;
					clearBreak();
					break;
				}
#ifdef _SHOWADDRESS
				if (area.startEA > lastAuto + AUTOFREQ) showAddr(lastAuto = area.startEA);
#endif
				const flags_t flags = get_flags_novalue/*getFlags*/(area.startEA);
				_ASSERTE(isNotTail(flags));
				if (isTail(flags)) continue; // never should trigger
				ea_t RVA = area.startEA - imagebase;
				if ((flags & (FF_NAME | ((gen_map_file_flags & GENFLG_MAPNAME) != 0 ? FF_LABL : 0))) != 0) {
#ifdef _SHOWADDRESS
					//showAddr(area.startEA);
#endif // _SHOWADDRESS
					const ea_t from = (gen_map_file_flags & GENFLG_MAPLOC) != 0 ?
						area.startEA : BADADDR;
// 						reinterpret_cast<char *(ida_export *)(ea_t, ea_t, char *, size_t)>
// 							((gen_map_file_flags & GENFLG_MAPDMNG) != 0 ? get_short_name :
// 							get_true_name)(from, area.startEA, buf, BUFSIZE);
					if (((gen_map_file_flags & GENFLG_MAPDMNG) != 0 ?
						get_short_name/*get_long_name*/(from, area.startEA, buf.get(), BUFSIZE) :
						get_true_name(from, area.startEA, buf.get(), BUFSIZE)) > 0) {
						uval_t answer;
						int value = get_name_value(from, buf.get(), &answer) & 7;
						/*NT_BMASK 8 // name is a bit group mask name*/
						if (isCode(flags)) {
							value |= 0x10;
							if ((flags & FF_FUNC) != 0) value |= 0x08;
						} else
							if (isData(flags)) value |= 0x08;
						if (!ofh.write((char *)&RVA, sizeof RVA)
							|| (value & 0x1F) != 0 && !ofh.write((char *)&value, 1)
							|| !ofh.write(buf.get(), strlen(buf.get()) + 1))
							throw fmt_exception("%s: error writing to file", outputfn);
						++totalnames;
						if ((gen_map_file_flags & GENFLG_MAPSTROFF) != 0) {
							typeinfo_t ti;
							struc_t *struc;
							if (isStruct(flags)
								&& (get_typeinfo(area.startEA, 0, flags, &ti) != 0
									&& (struc = get_struc(ti.tid)) != 0
								|| (struc = get_struc(get_strid(area.startEA))) != 0)) {
								//char *basename(get_struc_name(struc->id));
								enum_struct_members(struc, area.startEA, buf.get(), ofh);
							} // struct offset
						} // struct members enabled
					} else
						cmsg << prefix << "WARNING: couldnot get name at " <<
							asea(area.startEA) << endl;
				} // name
				if ((gen_map_file_flags & GENFLG_MAPCOMMENTS) != 0) {
					buf[0] = 0;
#define WRITE_CMT(x) cat(buf, x, BUFSIZE);
					GATHER_COMMENTS(area.startEA)
					for (int opndx = 0; opndx < UA_MAXOP; ++opndx) {
						if (opndx > 0 && !isCode(flags)) break;
						static const char x86_cannons[][4] = {
							"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
						};
						if ((gen_map_file_flags & GENFLG_MAPENUM) != 0 && isEnum(flags, opndx)) {
							uchar serial;
							const enum_t eid = get_enum_id(area.startEA, opndx, &serial);
							if (eid != BADNODE) {
								if (get_enum_name(eid, tmpbuf.get(), BUFSIZE) > 0)
									qstrncat(tmpbuf.get(), ".", BUFSIZE);
								else
									tmpbuf[0] = 0;
								uval_t immvals[UA_MAXOP * 2];
								if (isCode(flags) && get_operand_immvals(area.startEA, opndx, immvals) > 0
									|| isData(flags) && get_data_value(area.startEA, immvals, 0))
									if (is_bf(eid)) {
										// test all bitmasks for value
										for (bmask_t bmask = get_first_bmask(eid);
											bmask != DEFMASK; bmask = get_next_bmask(eid, bmask))
											if (get_const_name(get_const(eid, immvals[0] & bmask,
												serial, bmask), tail(tmpbuf.get()),
												BUFSIZE - strlen(tmpbuf.get())) > 0)
												qstrncat(tmpbuf.get(), "|", BUFSIZE);
										if (tmpbuf[0] != 0 && *(tail(tmpbuf.get()) - 1) == '|') {
											*(tail(tmpbuf.get()) - 1) = 0;
											if (cat(buf, tmpbuf, BUFSIZE)) ++totalenums;
										}
									} else // !bitfield - use DEFMASK
										if (get_const_name(get_const(eid, immvals[0], serial, DEFMASK),
											tail(tmpbuf.get()), BUFSIZE - strlen(tmpbuf.get())) > 0
											&& cat(buf, tmpbuf, BUFSIZE)) ++totalenums;
							} // got enum_id
						} // enum
						if ((gen_map_file_flags & GENFLG_MAPFOP) != 0
							&& is_forced_operand(area.startEA, opndx)/*isFop(flags, opndx)*/
							&& get_forced_operand(area.startEA, opndx, tmpbuf.get(), BUFSIZE) > 0
							&& cat(buf, tmpbuf, BUFSIZE)) ++totalfops;
						if ((gen_map_file_flags & GENFLG_MAPSTROFF) != 0
							&& isStroff(flags, opndx) && cmd.Operands[opndx].type == o_displ) {
							strpath_t strpath;
							if ((strpath.len = get_stroff_path(area.startEA, opndx,
								strpath.ids, &strpath.delta)) > 0) {
								adiff_t disp;
								if (get_struc_name(strpath.ids[0/*strpath.len - 1*/],
									tmpbuf.get(), BUFSIZE) > 0) {
									append_struct_fields(opndx, strpath.ids, strpath.len,
										byteflag(), tail(tmpbuf.get()), tmpbuf.get() + BUFSIZE,
										&(disp = cmd.Operands[opndx].addr), strpath.delta, true);
#if IDP_INTERFACE_VERSION < 76
									append_disp(tmpbuf.get(), tmpbuf.get() + BUFSIZE, disp);
#else // IDP_INTERFACE_VERSION >= 76
									print_disp(tail(tmpbuf.get()), tmpbuf.get() + BUFSIZE, disp);
#endif // IDP_INTERFACE_VERSION < 76
									if (cat(buf, tmpbuf, BUFSIZE)) ++totalstroffs;
								}
							}
						} // stroff
						sval_t actval;
						if ((gen_map_file_flags & GENFLG_MAPSTKVAR) != 0 && isStkvar(flags, opndx)) {
							const member_t *const stkvar = get_stkvar(cmd.Operands[opndx],
								static_cast<sval_t>(cmd.Operands[opndx].addr), &actval);
							if (stkvar != 0) {
								if (get_member_name(stkvar->id, tmpbuf.get(), BUFSIZE) > 0
									&& ((gen_map_file_flags & GENFLG_MAPNAME) != 0
									|| !is_dummy_member_name(tmpbuf.get())
									|| (gen_map_file_flags & GENFLG_MAPSTROFF) != 0
									&& isStruct(stkvar->flag))) {
									if (isStruct(stkvar->flag)) {
										if (cat_stkvar_struct_fields(cmd.ea, opndx, tmpbuf.get(),
											BUFSIZE) < 0 && opndx < 2) cmsg << prefix <<
												"WARNING: couldnot get struct members for stack var at " <<
												asea(cmd.ea) << '(' << dec << opndx + 1 << ')' << endl;
										/*
										adiff_t disp;
										strpath_t strpath;
										if ((strpath.len = get_struct_operand(cmd.ea, opndx,
											strpath.ids, &disp, &strpath.delta) - 1) >= 0)
											if (get_member_name(stkvar, disp, buf, bufsize) > 0)
#if IDP_INTERFACE_VERSION < 76
												append_disp(buf, buf + bufsize, strpath.delta);
#else // IDP_INTERFACE_VERSION >= 76
												print_disp(tail(buf), buf + bufsize, strpath.delta);
#endif // IDP_INTERFACE_VERSION
#ifdef _DEBUG
											else
												_RPTF2(_CRT_ASSERT, "%s(...): get_member_name(..., %Ii, ...) returned <= 0 despite stkvar struct member\n",
													__FUNCTION__, disp);
										else
											_RPTF3(_CRT_ASSERT, "%s(...): get_struct_operand(%08IX, %i, ...) returned < 0 despite stkvar struct member\n",
												__FUNCTION__, cmd.ea, opndx);
#endif // _DEBUG
										*/
									}
									if (cat(buf, tmpbuf, BUFSIZE)) ++totalstkvars;
								}
							}
						} // stkvar
						func_t *func;
						const regvar_t *regvar;
						if ((gen_map_file_flags & GENFLG_MAPREGVAR) != 0
							&& isCode(flags) && ua_ana0(area.startEA) > 0
							&& cmd.Operands[opndx].type == o_reg
							&& (func = get_func(area.startEA)) != 0
							&& (regvar = find_regvar(func, area.startEA,
								x86_cannons[cmd.Operands[opndx].reg])) != 0) {
							qsnprintf(tmpbuf.get(), BUFSIZE, "%s=%s",
								x86_cannons[cmd.Operands[opndx].reg], regvar->user);
							if (cat(buf, tmpbuf, BUFSIZE)) ++totalr32aliases;
						} // regvar
					} // iterate operands
					type_t type[MAXSPECSIZE], fnames[MAXSPECSIZE];
					if ((gen_map_file_flags & GENFLG_TINFO) != 0 && has_ti(area.startEA)
						&& get_ti(area.startEA, CPY(type), CPY(fnames))
						&& print_type_to_one_line(tmpbuf.get(), BUFSIZE, idati, type,
							NULL, NULL, fnames) == T_NORMAL
						&& cat(buf, tmpbuf, BUFSIZE)) ++totaltypeinfos;
					if (buf[0] != 0) {
#ifdef _SHOWADDRESS
						//showAddr(area.startEA);
#endif // _SHOWADDRESS
						if (!ofh.write((char *)&RVA, sizeof RVA) || !ofh.write(";", 1)
							|| !ofh.write(buf.get(), strlen(buf.get()) + 1))
							throw fmt_exception("%s: error writing to file", outputfn);
						++totalcomments;
					} // have comment
				} // comments
			} // code walk
			ofh.close();
		} // GENFLG_MAPOLLY
		wait_box.close();
		cmsg << prefix << "output file \'" << outputfn <<
			"\' successfully generated" << endl << prefix << "resume:" << endl;
		if (totalnames > 0) {
			cmsg << prefix << dec << setfill(' ') << setw(7) << totalnames << " names";
			if (totalmembers > 0) cmsg << " (" << totalmembers << " structure members)";
			cmsg << endl;
		}
		if (totalcomments > 0) {
			cmsg << prefix << dec << setfill(' ') << setw(7) << totalcomments << " comments";
			if (totalenums > 0 || totalfops > 0 || totalstkvars > 0 || totalstroffs > 0) {
				bool comma(false);
#				define PRINT_TOTAL(x, y) if (x > 0) { \
					cmsg << (comma ? ", " : " (") << dec << x << " " y; \
					comma = true; \
				}
				PRINT_TOTAL(totalenums, "enum consts");
				PRINT_TOTAL(totalfops, "forced operands")
				PRINT_TOTAL(totalstkvars, "stack variables")
				PRINT_TOTAL(totalstroffs, "structure offsets")
				PRINT_TOTAL(totalr32aliases, "register aliases")
				PRINT_TOTAL(totaltypeinfos, "typeinfos")
#				undef PRINT_TOTAL
				if (comma) cmsg << ')';
			}
			cmsg << endl;
		}
	} catch (const exception &e) {
		cmsg << prefix << e.what() << ", lame stoopid servil ;p" << endl;
		MessageBeep(MB_ICONERROR);
		warning("%s, lame stoopid servil ;p", e.what());
		return;
	} catch (...) {
		cmsg << prefix << "unhandled exception" << ", lame stoopid servil ;p" << endl;
		MessageBeep(MB_ICONERROR);
		warning("%s, lame stoopid servil ;p", "unhandled exception");
		return;
	}
	MessageBeep(MB_OK);
}

static void treat_checkbox(HWND hwndDlg, int nIDButton, const bool enable) {
	CheckDlgButton(hwndDlg, nIDButton,
		(IsDlgButtonChecked(hwndDlg, nIDButton) & enable) * BST_CHECKED);
	EnableDlgItem(hwndDlg, nIDButton, static_cast<BOOL>(enable));
}

static INT_PTR CALLBACK gen_map_dlgproc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_INITDIALOG: {
			bool ollyext = (gen_map_file_flags & GENFLG_MAPOLLY) != 0;
			CheckDlgButton(hwndDlg, IDC_MAPCONV2, ollyext * BST_CHECKED);
			CheckDlgButton(hwndDlg, IDC_SEGINFOBOX, ((gen_map_file_flags & GENFLG_MAPSEG) != 0) * !ollyext * BST_CHECKED);
			EnableDlgItem(hwndDlg, IDC_SEGINFOBOX, ((gen_map_file_flags & GENFLG_MAPOLLY) == 0));
			CheckDlgButton(hwndDlg, IDC_LOCBOX, ((gen_map_file_flags & GENFLG_MAPLOC) != 0) * ollyext * BST_CHECKED);
			EnableDlgItem(hwndDlg, IDC_LOCBOX, ollyext);
			CheckDlgButton(hwndDlg, IDC_STROFFBOX, ((gen_map_file_flags & GENFLG_MAPSTROFF) != 0) * ollyext * BST_CHECKED);
			EnableDlgItem(hwndDlg, IDC_STROFFBOX, ollyext);
			CheckDlgButton(hwndDlg, IDC_AUTOGENBOX, ((gen_map_file_flags & GENFLG_MAPNAME) != 0) * BST_CHECKED);
			CheckDlgButton(hwndDlg, IDC_DEMANGLEDBOX, ((gen_map_file_flags & GENFLG_MAPDMNG) != 0) * BST_CHECKED);
			CheckDlgButton(hwndDlg, IDC_CMTBOX, ((gen_map_file_flags & GENFLG_MAPCOMMENTS) != 0) * BST_CHECKED);
			ollyext = ollyext && gen_map_file_flags & GENFLG_MAPCOMMENTS;
			CheckDlgButton(hwndDlg, IDC_ENUMBOX, ((gen_map_file_flags & GENFLG_MAPENUM) != 0) * ollyext * BST_CHECKED);
			EnableDlgItem(hwndDlg, IDC_ENUMBOX, ollyext);
			CheckDlgButton(hwndDlg, IDC_STKVARBOX, ((gen_map_file_flags & GENFLG_MAPSTKVAR) != 0) * ollyext * BST_CHECKED);
			EnableDlgItem(hwndDlg, IDC_STKVARBOX, ollyext);
			CheckDlgButton(hwndDlg, IDC_FOPBOX, ((gen_map_file_flags & GENFLG_MAPFOP) != 0) * ollyext * BST_CHECKED);
			EnableDlgItem(hwndDlg, IDC_FOPBOX, ollyext);
			CheckDlgButton(hwndDlg, IDC_REGVARBOX, ((gen_map_file_flags & GENFLG_MAPREGVAR) != 0) * ollyext * BST_CHECKED);
			EnableDlgItem(hwndDlg, IDC_REGVARBOX, ollyext);
			//CheckDlgButton(hwndDlg, IDC_TINFOBOX, ((gen_map_file_flags & GENFLG_TINFO) != 0) * ollyext * BST_CHECKED);
			//EnableDlgItem(hwndDlg, IDC_TINFOBOX, ollyext);
			if (dlgpos_genmapfileex) {
				RECT rect;
				GetWindowRect(hwndDlg, &rect);
				MoveWindow(hwndDlg, LOWORD(dlgpos_genmapfileex), HIWORD(dlgpos_genmapfileex),
					rect.right - rect.left, rect.bottom - rect.top, FALSE);
			}
			return 1;
		}
		case WM_DESTROY: {
			RECT rect;
			GetWindowRect(hwndDlg, &rect);
			save_dword("GenMapFileEx", "dlg_pos", dlgpos_genmapfileex = rect.left + (rect.top << 0x10));
			SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
			return 1;
		}
		case WM_COMMAND:
			switch (HIWORD(wParam)) {
				case BN_CLICKED:
					switch (LOWORD(wParam)) {
						case IDOK:
							save_dword("GenMapFileEx", "flags", gen_map_file_flags =
								IsDlgButtonChecked(hwndDlg, IDC_SEGINFOBOX) * GENFLG_MAPSEG |
								IsDlgButtonChecked(hwndDlg, IDC_AUTOGENBOX) * GENFLG_MAPNAME |
								IsDlgButtonChecked(hwndDlg, IDC_DEMANGLEDBOX) * GENFLG_MAPDMNG |
								IsDlgButtonChecked(hwndDlg, IDC_CMTBOX) * GENFLG_MAPCOMMENTS |
								IsDlgButtonChecked(hwndDlg, IDC_LOCBOX) * GENFLG_MAPLOC |
								IsDlgButtonChecked(hwndDlg, IDC_ENUMBOX) * GENFLG_MAPENUM |
								IsDlgButtonChecked(hwndDlg, IDC_FOPBOX) * GENFLG_MAPFOP |
								IsDlgButtonChecked(hwndDlg, IDC_REGVARBOX) * GENFLG_MAPREGVAR |
								IsDlgButtonChecked(hwndDlg, IDC_STKVARBOX) * GENFLG_MAPSTKVAR |
								IsDlgButtonChecked(hwndDlg, IDC_STROFFBOX) * GENFLG_MAPSTROFF |
								//IsDlgButtonChecked(hwndDlg, IDC_TINFOBOX) * GENFLG_TINFO |
								IsDlgButtonChecked(hwndDlg, IDC_MAPCONV2) * GENFLG_MAPOLLY);
						case IDCANCEL:
							EndDialog(hwndDlg, LOWORD(wParam));
							SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
							break;
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
						case IDC_MAPCONV2:
						case IDC_CMTBOX: {
							bool ollyext = IsDlgButtonChecked(hwndDlg, IDC_MAPCONV2);
							treat_checkbox(hwndDlg, IDC_SEGINFOBOX, !ollyext);
							treat_checkbox(hwndDlg, IDC_LOCBOX, ollyext);
							treat_checkbox(hwndDlg, IDC_STROFFBOX, ollyext);
							ollyext = ollyext && IsDlgButtonChecked(hwndDlg, IDC_CMTBOX);
							treat_checkbox(hwndDlg, IDC_ENUMBOX, ollyext);
							treat_checkbox(hwndDlg, IDC_STKVARBOX, ollyext);
							treat_checkbox(hwndDlg, IDC_FOPBOX, ollyext);
							treat_checkbox(hwndDlg, IDC_REGVARBOX, ollyext);
							SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
							break;
						}
					} // switch BN_CLICKED
					break;
			} // switch HIWORD(wParam)
			return 1;
	}
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		char ModuleFileName[MAX_PATH], tmp[MAX_PATH];
		GetModuleFileName(hinstDLL, CPY(ModuleFileName));
#if IDP_INTERFACE_VERSION < 76
		if (ph.version != IDP_INTERFACE_VERSION) {
			lstrcpyn(tmp, ModuleFileName, qnumber(tmp));
			lstrcat(tmp, ".old");
			MoveFile(ModuleFileName, tmp);
#ifdef wsprintfA
#undef wsprintfA
#endif // wsprintfA
			wsprintf(ModuleFileName, "Cannot load plugin: this plugin is for IDP version %u (%i reported by kernel)\n\n"
				"Update or delete the plugin file", IDP_INTERFACE_VERSION, ph.version);
			MessageBox(get_ida_hwnd(), ModuleFileName,
				PLUGINNAME " v" PLUGINVERSIONTEXT, MB_ICONEXCLAMATION | MB_OK);
			return FALSE;
		}
#endif // IDP_INTERFACE_VERSION < 76
		DisableThreadLibraryCalls((HMODULE)hInstance = hinstDLL);
		se_exception::_set_se_translator();
#ifdef _DEBUG
		_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
		_CrtSetDbgFlag(/*_CRTDBG_CHECK_EVERY_1024_DF | */_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#else // !_DEBUG
		DWORD flOldProtect;
		VirtualProtect((PBYTE)hInstance + 0xA9000, 0xBC00, PAGE_READONLY, &flOldProtect);
#endif // _DEBUG
		ConstructHomeFileName(inipath, 0, "ini");
	}
	return TRUE;
}

// ================================ENTRY POINT================================
plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION, PLUGIN_MOD | PLUGIN_DRAW | PLUGIN_UNL,
	init, wait_threads, run, PLUGINNAME " v" PLUGINVERSIONTEXT,
	0, "Create MAP file\x085", "Ctrl-H"
};
// ================================ENTRY POINT================================
