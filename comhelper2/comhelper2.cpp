
/*****************************************************************************
 *                                                                           *
 *  comhelper2.cpp: OLE/COM helper (based on DataRescue's com helper plugin) *
 *  (c) 2006-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

// plugin should be replacement of datarescue's original comhelper plugin, main
// enhancements against original plugin:
// - all GUID-based structures are recognised by structure, not name, this
//   extends recognition to all generic GUID type aliases like
//   IID, TGUID, CLSID etc...
// - GUID scanner implemented to scan through image for possible
//   GUIDs/IIDs/CLSIDs not recognised by kernel
// - full ida typeinfo to vtable members for typed interfaces, ti also applied
//   to all targets after vtable applied to static area
// - source code availability
// - other minor things not remembering to mention

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include <numeric>
#include <boost/range.hpp>
#include <boost/scoped_array.hpp>
#include "plugida.hpp"
#include "undbgnew.h"
#include <Guiddef.h>
#include "dbgnew.h"

#define _SHOWADDRESS    1                   // display progress (costs time)
#define NSUP_FNAMES     (NSUP_TYPEINFO + 1) // supval index to store param names, this should be kernel's convention
#undef FUNC_STATIC

static int idaapi comhelper(void *, int, va_list);

static const char prefix[] = "[com helper] ";
static const char vt_prefix[] = "vtIID_";

extern "C" __declspec(dllexport) simple_hooker hooker(HT_IDP, comhelper);

static struc_t *get_guid(ea_t ea, struc_t *struc = 0,
	ea_t struc_ea = BADADDR, asize_t size = 0);
/*
static inline tid_t get_guid(ea_t ea, const struc_t *struc = 0,
	ea_t struc_ea = BADADDR, asize_t size = 0) {
	struc_t *struc2 = get_guid(ea, struc, struc_ea, size);
	return struc2 != 0 ? struc2->id : BADNODE;
}
*/
static inline bool is_guid(ea_t ea) { return get_guid(ea) != 0; }

// have GUID type same structure
static bool is_guid(const struc_t *struc) {
	member_t *member;
	return get_struc_size(struc) == sizeof GUID
		/*&& get_struc_first_offset(struc) == 0*/
		&& (member = get_member(struc, 0)) != 0
		&& get_member_size(member) == sizeof DWORD // sizeof long
		&& is_same_data_type(member->flag, dwrdflag())
		/*&& get_struc_next_offset(struc, 0) == 4*/
		&& (member = get_member(struc, sizeof DWORD)) != 0
		&& get_member_size(member) == sizeof WORD // sizeof short
		&& is_same_data_type(member->flag, wordflag())
		/*&& get_struc_next_offset(struc, 4) == 6*/
		&& (member = get_member(struc, sizeof DWORD + sizeof WORD)) != 0
		&& get_member_size(member) == sizeof WORD // sizeof short
		&& is_same_data_type(member->flag, wordflag())
		/*&& get_struc_next_offset(struc, 6) == 8*/
		&& (member = get_member(struc, sizeof DWORD + sizeof WORD + sizeof WORD)) != 0
		&& get_member_size(member) == 8 * sizeof BYTE // sizeof char
		&& is_same_data_type(member->flag, byteflag());
}

static struc_t *get_guid(ea_t ea, struc_t *struc, ea_t struc_ea, asize_t size) {
	_ASSERTE(isEnabled(ea));
	if (isEnabled(ea))
		if (struc == 0) { // get struc at ea
			const flags_t flags = get_flags_novalue(struc_ea = get_item_head(ea));
			if (isStruct(flags)) {
				typeinfo_t ti;
				if (get_typeinfo(struc_ea, 0, flags, &ti) != 0
					&& (struc = get_struc(ti.tid)) != 0
					|| (struc = get_struc(get_strid(struc_ea))) != 0)
					return get_guid(ea, struc, struc_ea, get_item_size(struc_ea));
			} // isStruct
		} else { // struc != 0
			_ASSERTE(isEnabled(struc_ea) && struc_ea <= ea);
			if (isEnabled(struc_ea) && struc_ea <= ea) {
				if (struc_ea == ea && is_guid(struc))
					return struc; // exactly
				else { // not exactly structGUID
					const asize_t strucsize(get_struc_size(struc));
					_ASSERTE(struc->is_varstr() || size % strucsize == 0);
					if (size <= 0 || struc->is_varstr()) size = strucsize;
					for (uint index = 0; index * strucsize < size; ++index)
						for (ea_t offset = get_struc_first_offset(struc); offset != BADADDR
							&& struc_ea + index * strucsize + offset <= ea;
							offset = get_struc_next_offset(struc, offset)) {
							const member_t *const member(get_member(struc, offset));
							if (member != 0 && isStruct(member->flag)) {
								struc_t *const struc2 = get_guid(ea, get_sptr(member), struc_ea +
									index * strucsize + member->get_soff(), get_member_size(member));
								if (struc2 != 0) return struc2;
							}
						} // enumerate substructs
				} // scan substructs
			} // isEnabled(struc_ea) && struc_ea <= ea
		} // struc != 0
	return 0;
}

static bool try_guid(ea_t ea, struc_t *struc) {
	_ASSERTE(isLoaded(ea) && struc != 0);
	if (struc != 0 && isLoaded(ea) && is_guid(struc)) try {
		char name[MAXNAMESIZE];
		const interface_t intf(ea);
		if (intf.isSet()) { // ok, iid known
			if (!intf.name.empty()) {
				qsnprintf(CPY(name), "IID_%s", intf.name.c_str());
				if (get_name_ea(BADADDR, make_ident_name(CPY(name))) != ea)
					do_name_anyway(ea, name);
				msg("%s%s interface recognized at %08a", prefix, intf.name.c_str(), ea);
				if (intf.pti != NULL) try {
					msg(": typeinfo present");
					make_ident_name(qstrncat(qstrcpy(name, vt_prefix),
						intf.name.c_str(), qnumber(name)), qnumber(name));
					tid_t tid(add_struc(BADADDR, name));
					if ((tid != BADNODE || (tid = get_struc_id(name)) != BADNODE)
						&& (struc = get_struc(tid)) != 0) { // can create or get this struct
						CComBSTR strName, strDesc;
						if (intf.pti->GetDocumentation(MEMBERID_NIL, &strName, &strDesc, NULL, NULL) == S_OK) {
							boost::scoped_array<char> desc(new char[strDesc.Length() + 1]);
							if (!desc) throw bad_alloc();
							if (strDesc != NULL && _wcstombs(desc.get(), strDesc, strDesc.Length() + 1) > 0) {
								set_struc_cmt(tid, desc.get(), true);
								append_unique_cmt(ea, desc.get(), false);
							}
							strName.Empty();
							strDesc.Empty();
						}
						/*CComTypeAttr*/TYPEATTR *typeattr;
						if (intf.pti->GetTypeAttr(&typeattr) == S_OK) {
							_ASSERTE(typeattr != NULL);
							for (uint16 index = 0; index < typeattr->cFuncs; ++index) {
								/*CComFuncDesc*/FUNCDESC *funcdesc;
								if (intf.pti->GetFuncDesc(index, &funcdesc) == S_OK) {
									_ASSERTE(funcdesc != NULL);
									if (intf.pti->GetDocumentation(funcdesc->memid, &strName, &strDesc, NULL, NULL) == S_OK) {
										if (strName != NULL) {
											char typestr[0x100];
											typestr[0] = 0;
											switch (funcdesc->invkind) {
												case INVOKE_PROPERTYGET:
													qsnprintf(CPY(typestr), "propget%ls", (BSTR)strName);
													break;
												case INVOKE_PROPERTYPUT:
													qsnprintf(CPY(typestr), "propput%ls", (BSTR)strName);
													break;
												case INVOKE_PROPERTYPUTREF:
													qsnprintf(CPY(typestr), "propputref%ls", (BSTR)strName);
													break;
												default:
													//_ASSERTE(funcdesc->invkind == INVOKE_FUNC);
													wcstombs(typestr, strName, sizeof typestr);
													break;
											} // switch
#if IDP_INTERFACE_VERSION < 76
											static const typeinfo_t ti_off32 = { /*get_default_reftype(ea)*/REF_OFF32, 0, BADADDR, 0, 0 };
#else
											static const typeinfo_t ti_off32 = { BADADDR, 0, 0, /*get_default_reftype(ea)*/REF_OFF32 };
#endif
											add_struc_member(struc, typestr, funcdesc->oVft,
												dwrdflag() | offflag(), &ti_off32, sizeof DWORD);
											member_t *const member(get_member(struc, funcdesc->oVft));
											if (member != 0) {
												if (strDesc != NULL && _wcstombs(typestr, strDesc, sizeof typestr) > 0)
													set_member_cmt(member, typestr, false);
												uint namescount(0);
												boost::scoped_array<BSTR FAR> names(new BSTR FAR[1 + funcdesc->cParams]);
												if (!names) throw bad_alloc();
												fill_n(names.get(), 1 + funcdesc->cParams, (BSTR)NULL);
												intf.pti->GetNames(funcdesc->memid, names.get(), 1 + funcdesc->cParams, &namescount);
												string type;
												typestring typinfo;
												plist fnames;
												typinfo << (BT_PTR | BTMT_DEFPTR) << (BT_FUNC | BTMT_DEFCALL);
												switch (funcdesc->funckind) {
													case FUNC_VIRTUAL:
													case FUNC_PUREVIRTUAL: type.assign("virtual "); break; // ???
													//case FUNC_NONVIRTUAL: break; // ???
													case FUNC_STATIC: type.assign("static "); break;
													//case FUNC_DISPATCH: type.assign("dispatch "); break; // ???
													default: type.clear();
												}
												if (!GetCDeclStrFromTYPEDESC(funcdesc->elemdescFunc.tdesc, type, intf.pti)) {
													type.append("void");
													_RPT4(_CRT_WARN, "%s(...): GetCDeclStrFromTYPEDESC(...) couldnot parse VarType=0x%X(%s) (result) for %ls\n",
														__FUNCTION__, funcdesc->elemdescFunc.tdesc.vt, TokenizeVarType(funcdesc->elemdescFunc.tdesc.vt), static_cast<BSTR>(strName));
												}
												if (!type.empty() && strchr("&*", back(type)) == 0)
													type.push_back(' ');
												cm_t cm/*(inf.cc.cm)*/;
												switch (funcdesc->callconv) {
													case CC_CDECL:
														type.append("__cdecl ");
														cm = CM_CC_CDECL;
														break;
													case CC_FASTCALL:
														type.append("__fastcall ");
														cm = CM_CC_FASTCALL;
														break;
													case CC_FPFASTCALL:
														type.append("__fpfastcall ");
														cm = CM_CC_FASTCALL; // ???
														break;
													case CC_MACPASCAL:
														type.append("__macpascal ");
														cm = CM_CC_PASCAL; // ???
														break;
													case CC_MPWCDECL:
														type.append("__mpwcdecl ");
														cm = CM_CC_CDECL; // ???
														break;
													case CC_MPWPASCAL:
														type.append("__mpwpascal ");
														cm = CM_CC_PASCAL; // ???
														break;
													case CC_PASCAL:
														type.append("__pascal ");
														cm = CM_CC_PASCAL;
														break;
													case CC_STDCALL:
														type.append("__stdcall ");
														cm = CM_CC_STDCALL;
														break;
													case CC_SYSCALL:
														type.append("__syscall ");
														cm = CM_CC_UNKNOWN; // not in IDA defined
														break;
													default:
														cm = CM_CC_UNKNOWN;
														_RPT3(_CRT_WARN, "%s(...): unexpected calling convention for %ls: %i\n",
															__FUNCTION__, (BSTR)strName, funcdesc->callconv);
												} // switch calling convention
												typinfo.push_back(get_cc(cm) | inf.cc.cm & (CM_MASK | CM_M_MASK));
												if ((int)wcstombs(typestr, strName, sizeof typestr) > 0)
													type.append(typestr);
#ifdef _DEBUG
												else
													_RPTF3(_CRT_WARN, "%s(...): wcstombs(..., %ls, 0x%IX) failed\n",
														__FUNCTION__, static_cast<BSTR>(strName), sizeof typestr);
												if (namescount != 1 + funcdesc->cParams) {
													_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
														"%s(...): name count mismatch for function %ls: names=%u params=%hi optparams=%hi\n",
														__FUNCTION__, (BSTR)strName, namescount, funcdesc->cParams, funcdesc->cParamsOpt);
													if (names)
														for (uint16 index = 0; index < namescount; ++index)
															_RPT2(_CRT_WARN, "%4hu: %ls", index, names[index]);
												}
#endif // _DEBUG
												if (!GetTypeInfoFromTYPEDESC(funcdesc->elemdescFunc.tdesc, typinfo, intf.pti)) {
													typinfo.push_back(BTF_VOID)/*tdef("VOID")*/; // void: type not determined
													_RPT4(_CRT_WARN, "%s(...): GetTypeInfoFromTYPEDESC(...) couldnot parse VarType=0x%X(%s) (result) for %ls\n",
														__FUNCTION__, funcdesc->elemdescFunc.tdesc.vt, TokenizeVarType(funcdesc->elemdescFunc.tdesc.vt), static_cast<BSTR>(strName));
												}
												type.push_back('(');
												typinfo << dt(funcdesc->cParams);
												for (uint16 index = 0; index < funcdesc->cParams; ++index) {
													if (index > 0) type.append(", ");
													char n[MAXNAMESIZE];
													if (!names || names[index + 1] == NULL
														|| (int)wcstombs(n, names[index + 1], sizeof n) <= 0)
														n[0] = 0;
													_ASSERTE(funcdesc->lprgelemdescParam != NULL);
													if (funcdesc->lprgelemdescParam != NULL) {
														const ELEMDESC &elemdesc(funcdesc->lprgelemdescParam[index]);
														// gen cdecl prototype
														// flags not supported by IDA parser
														if ((elemdesc.paramdesc.wParamFlags & PARAMFLAG_FIN) != 0) type.append("IN ");
														if ((elemdesc.paramdesc.wParamFlags & PARAMFLAG_FOUT) != 0) type.append("OUT ");
														if ((elemdesc.paramdesc.wParamFlags & PARAMFLAG_FOPT) != 0) type.append("OPTIONAL ");
														//if ((elemdesc.paramdesc.wParamFlags & PARAMFLAG_FLCID) != 0) type.append("LCID ");
														//if ((elemdesc.paramdesc.wParamFlags & PARAMFLAG_FRETVAL) != 0) type.append("RETVAL ");
														//if ((elemdesc.paramdesc.wParamFlags & PARAMFLAG_FHASCUSTDATA) != 0) type.append("HASCUSTDATA ");
														if (!GetCDeclStrFromTYPEDESC(elemdesc.tdesc, type, intf.pti, n)) {
															type.append("void"); // void: type not determined
															if (n[0] != 0) type.append(1, ' ').append(n);
#ifdef _DEBUG
															_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
																"%s(...): GetCDeclStrFromTYPEDESC(...) couldnot parse VarType=0x%X(%s) (param %hu) for %ls\n",
																__FUNCTION__, elemdesc.tdesc.vt, TokenizeVarType(elemdesc.tdesc.vt), index, static_cast<BSTR>(strName));
#endif // _DEBUG
														}
														if ((elemdesc.paramdesc.wParamFlags & PARAMFLAG_FHASDEFAULT) != 0) {
															// optional: add default value (defaults ignored by IDA)
															type.append(" = ");
															try {
																_ASSERTE(elemdesc.paramdesc.pparamdescex != NULL);
																if (!TokenizePARAMDESCEX(*elemdesc.paramdesc.pparamdescex, type))
																	throw logic_error("default value is empty");
															} catch (const exception &e) {
																type.push_back('0');
																_RPT4(_CRT_WARN, "%s(...): TokenizePARAMDESCEX(...) threw %s for %ls (param %hu)\n",
																	__FUNCTION__, (BSTR)strName, e.what(), index);
															}
														}
														if (!GetTypeInfoFromTYPEDESC(elemdesc.tdesc, typinfo, intf.pti)) {
															typinfo.push_back(BTF_VOID)/*tdef("VOID")*/; // void: type not determined
#ifdef _DEBUG
															_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
																"%s(...): GetTypeInfoFromTYPEDESC(...) couldnot parse VarType=0x%X(%s) (param %hu) for %ls\n",
																__FUNCTION__, elemdesc.tdesc.vt, TokenizeVarType(elemdesc.tdesc.vt), index, static_cast<BSTR>(strName));
#endif // _DEBUG
														}
													} else { // funcdesc->lprgelemdescParam == NULL
														type.append("void"); // void: type not determined
														if (n[0] != 0) type.append(1, ' ').append(n);
														typinfo.push_back(BTF_VOID)/*tdef("VOID")*/; // void: type not determined
														_RPT4(_CRT_WARN, "%s(...): LPFUNCDESC->lprgelemdescParam is NULL despite function %ls having params (%hi mandatory/%hi optional)\n",
															__FUNCTION__, (BSTR)strName, funcdesc->cParams, funcdesc->cParamsOpt);
													}
													fnames << n;
												} // iterate arguments
												if (names) {
													for (index = 0; index < namescount; ++index)
														if (names[index] != NULL) SysFreeString(names[index]);
													names.reset();
												}
												if (funcdesc->cParams == 0) type.append("void"); // no params
												type.push_back(')');
												if (funcdesc->funckind == FUNC_PUREVIRTUAL) type.append(" = 0");
												type.push_back(';');
												set_member_cmt(member, type.c_str(), true);
												if (!typinfo.empty()) {
													set_member_ti(struc, member, typinfo, true);
													netnode namenode(member->id);
													if (!fnames.empty())
														namenode.supset(NSUP_FNAMES, fnames.c_str(), fnames.size() + 1);
													else
														namenode.supdel(NSUP_FNAMES);
												}
											} // member ok
#ifdef _DEBUG
											else
												_RPTF3(_CRT_WARN, "%s(...): wcstombs(..., %ls, 0x%IX) failed\n",
													__FUNCTION__, static_cast<BSTR>(strName), sizeof typestr);
#endif // _DEBUG
											strName.Empty();
										} // strName != NULL
										if (strDesc != NULL) strDesc.Empty();
									} // intf.pti->GetDocumentation(...) ok for func
									intf.pti->ReleaseFuncDesc(funcdesc);
								} // GetFuncDesc() ok
							} // iterate all functions
							intf.pti->ReleaseTypeAttr(typeattr);
						} // GetTypeAttr() ok
					} // add_struc(...) ok
					struc->props |= SF_HIDDEN;
					save_struc(struc);
				} catch (const exception &e) {
					msg(" [%s when getting func descriptor from ITypeInfo]", e.what());
				}
				//tih.Cleanup();
				msg("\n");
			} // !intf.name.empty()
			return true;
		} // known iid
		const clsid_t cls(ea);
		if (cls.isSet()) { // only name can be applied
			if (!cls.name.empty()) {
				qsnprintf(CPY(name), "CLSID_%s", cls.name.c_str());
				if (get_name_ea(BADADDR, make_ident_name(CPY(name))) != ea)
					do_name_anyway(ea, name);
				msg("%s%s class recognized at %08a\n", prefix, cls.name.c_str(), ea);
			}
			return true;
		} // known clsid
		const typelib_t tlb(ea);
		if (tlb.isSet()) { // only name can be applied
			if (!tlb.name.empty()) {
				qsnprintf(CPY(name), "GUID_%s", tlb.name.c_str());
				if (get_name_ea(BADADDR, make_ident_name(CPY(name))) != ea)
					do_name_anyway(ea, name);
				msg("%s%s typelib recognized at %08a\n", prefix, tlb.name.c_str(), ea);
			}
			return true;
		} // known guid
		return true; // this is guid, don't try further...
	} catch (const exception &e) {
		msg("%s%080a: %s\n", prefix, ea, e.what());
		//MessageBeep(MB_ICONERROR);
		//warning("%s, lame stoopid servil ;p", e.what());
	}
	return false;
}

static bool try_vtable(ea_t ea, const struc_t *struc) {
	_ASSERTE(isEnabled(ea));
	_ASSERTE(struc != 0);
	char tmp[MAXNAMESIZE];
	if (isLoaded(ea) && struc != 0) try {
		if (get_struc_name(struc->id, CPY(tmp)) <= sizeof(vt_prefix) - 1
			|| strncmp(tmp, vt_prefix, sizeof(vt_prefix) - 1) != 0) return false;
		const char *const strucname = tmp + sizeof(vt_prefix) - 1;
		for (ea_t offset = get_struc_first_offset(struc); offset != BADADDR;
			offset = get_struc_next_offset(struc, offset)) {
			member_t *const member(get_member(struc, offset));
			if (member == 0 || !isOff0(member->flag)) continue;
			ea_t const tgt(calc_reference_target(ea, member));
			if (!isLoaded(tgt)) continue;
			flags_t const flags(get_flags_novalue(tgt));
			if (!isFunc(flags)) add_func(tgt, BADADDR);
			if (!has_name(flags)) {
				char memname[MAXNAMESIZE];
				if (get_member_name(member->id, CPY(memname)) > 0) {
					char name[MAXNAMESIZE];
					qsnprintf(CPY(name), "%s::%s", strucname, memname);
					if (get_name_ea(BADADDR, name) != tgt) do_name_anyway(tgt, name);
				}
			}
			type_t ti[MAXSPECSIZE], *pti;
			if (member->has_ti() && !has_ti(tgt)
				&& get_member_ti(member, CPY(ti)) && is_resolved_type_ptr(ti)
				&& is_resolved_type_func(pti = skip_ptr_type_header(ti))) {
				p_list fnames[MAXSPECSIZE];
				if (netnode(member->id).supval(NSUP_FNAMES, CPY(fnames)) <= 0)
					fnames[0] = 0;
				set_ti(tgt, pti, fnames[0] != 0 ? fnames : 0);
			}
		} // iterate offsets
		return true;
	} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
		if (get_struc_name(struc->id, CPY(tmp)) <= 0) tmp[0] = 0;
		_RPT4(_CRT_ERROR, "%s(%08IX, ...): %s (struct '%s')\n",
			__FUNCTION__, ea, e.what(), tmp);
#endif // _DEBUG
	}
	return false;
}

static void try_struct(ea_t ea, const struc_t *struc) {
	_ASSERTE(isEnabled(ea));
	_ASSERTE(struc != 0);
	if (isLoaded(ea) && struc != 0) {
		struc_t strucbuf(*struc);
		if (!try_guid(ea, &strucbuf) && !try_vtable(ea, &strucbuf))
			for (ea_t offset = get_struc_first_offset(&strucbuf); offset != BADADDR;
				offset = get_struc_next_offset(&strucbuf, offset)) {
				member_t *member(get_member(&strucbuf, offset));
				if (member != 0) try_struct(ea + member->get_soff(), get_sptr(member));
			}
	}
}

static int idaapi comhelper(void *user_data, int notification_code, va_list va) {
	ea_t ea;
	if (/*user_data == NULL && */notification_code == processor_t::make_data
		&& isLoaded(ea = va_argi(va, ea_t)) && isStruct(va_argi(va, flags_t)))
			try_struct(ea, get_struc(va_argi(va, tid_t)));
	return 0; // ida kernel continue
}

static class CGuidList : public CIdaChooser {
protected:
	struct item_t {
		ea_t ea;
		string name;
		uint16 type;
		bool hastypelib;

		item_t(ea_t ea, uint16 type = 0, const char *name = 0, bool hastypelib = false) :
			ea(ea), type(type), hastypelib(hastypelib)
				{ if (name != 0) this->name.assign(name); }

		inline bool operator ==(const item_t &r) const
			{ return ea == r.ea && type == r.type; }
		inline bool operator <(const item_t &r) const
			{ return ea < r.ea || ea == r.ea && type < r.type; }
		inline operator ea_t() const { return ea; }
	};

	set<item_t> items;

public:
	operator size_t() const { return items.size(); }

	bool Add(ea_t ea, uint16 type = 0, const char *name = 0, bool hastypelib = false)
		{ return items.insert(item_t(ea, type, name, hastypelib)).second; }
	bool Open() {
		if (items.empty()) {
#if IDP_INTERFACE_VERSION >= 76
			Close();
#endif
			return false;
		}
#if IDA_SDK_VERSION >= 520
		if (IsOpen() && Refresh()) return true; // re-use existing rather than opening new
#endif
		static int const widths[] = { 13, 60, 4, };
		choose2(0, -1, -1, -1, -1, this, qnumber(widths), widths, sizer, getl,
			GetTitle(), GetIcon(0), 1, 0, 0, 0, 0, enter, destroy, 0, get_icon);
		PLUGIN.flags &= ~PLUGIN_UNL;
		return true;
	}
	void Clear() { items.clear(); }

protected:
	const char *GetTitle() const { return "Lost GUIDs"; }
	// IDA callback overrides
	void GetLine(ulong n, char * const *arrptr) const {
		if (n == 0) { // header
			static const char *const headers[] = { "address", "name", "typelib", };
			for (uint i = 0; i < qnumber(headers); ++i)
				qstrncpy(arrptr[i], headers[i], MAXSTR);
		} else { // regular item
			if (n > operator size_t()) return; //_ASSERTE(n <= operator size_t());
			const item_t &item(at(items, n - 1));
			ea2str(item.ea, arrptr[0], MAXSTR); //qsnprintf(arrptr[0], MAXSTR, "%08a", item.ea);
			if (!item.name.empty())
				qstrncpy(arrptr[1], item.name.c_str(), MAXSTR);
			else
				*arrptr[1] = 0;
			qstrncpy(arrptr[2], item.hastypelib ? "yes":"no", MAXSTR);
		} // regular item
	}
	void Enter(ulong n) const {
		_ASSERTE(n > 0);
		if (n > operator size_t()) return; //_ASSERTE(n <= operator size_t());
		const ea_t ea(at(items, n - 1));
		if (isEnabled(ea)) jumpto(ea); else MessageBeep(MB_ICONWARNING);
	}
	int GetIcon(ulong n) const {
		if (n == 0) return 103; // list head icon
		//_ASSERTE(n <= operator size_t());
		if (n <= operator size_t()) switch (at(items, n - 1).type) {
			case 1: return 75; // IID
			case 2: return 74; // CLSID
			case 3: return 69; // GUID(TLB)
		}
		return -1;
	}
} list;

template<class T>static uint EnumerateGUIDs(const char *root, T &container) {
	container.clear();
	_ASSERTE(root != NULL && *root != 0);
	boost::scoped_array<char> subkey(new char[0x4000]);
	if (!subkey) {
		msg("%s...", bad_alloc().what());
		throw bad_alloc(); //return 0;
	}
	CRegKey hKey;
	DWORD dwSubkeys;
	if (hKey.Open(HKEY_CLASSES_ROOT, root) != ERROR_SUCCESS
		|| RegQueryInfoKey(hKey, NULL, NULL, NULL, &dwSubkeys, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL) != ERROR_SUCCESS) return 0;
	uint total(0);
	for (DWORD index = 0; index < dwSubkeys; ++index) try {
		DWORD dwSz;
		FILETIME ft;
		if (RegEnumKeyEx(hKey, index, subkey.get(), &(dwSz = 0x4000), NULL, NULL, NULL, &ft) == ERROR_SUCCESS
			&& container.insert(T::value_type(subkey.get())).second) ++total;
	} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
			"%s(...): %s (root=%s index=%lu subkey=%s)\n", __FUNCTION__,
			e.what(), root, index, subkey.get());
#endif // _DEBUG
	}
	return total;
}

static bool doStruct(ea_t ea, const char *struc_name) {
	_ASSERTE(isEnabled(ea));
	_ASSERTE(struc_name != 0 && *struc_name != 0);
	if (!isEnabled(ea) || struc_name == 0 || *struc_name == 0) return false;
	tid_t struc_id = get_struc_id(struc_name);
	if (struc_id == BADNODE) {
		til2idb(-1, struc_name);
		if ((struc_id = get_struc_id(struc_name)) == BADNODE) return false;
	}
	do_unknown_range(ea, get_struc_size(struc_id), false);
	return doStruct(ea, get_struc_size(struc_id), struc_id);
}

static uint scan_for_guids(bool create = false) {
	const bool listwasopen(::list > 0);
	::list.Clear();
	layered_wait_box wait_box("please wait, plugin is running...");
	msg("%sCollecting all GUIDs from registry: this may take some while...", prefix);
	hash_set<IIDEX, IIDEX::hash/*boost::hash<IIDEX>*/> interfaces;
	uint total = EnumerateGUIDs("Interface", interfaces);
	hash_set<CLSIDEX, CLSIDEX::hash/*boost::hash<CLSIDEX>*/> classes;
	total += EnumerateGUIDs("CLSID", classes);
	hash_set<GUIDEX, GUIDEX::hash/*boost::hash<GUIDEX>*/> typelibs;
	total += EnumerateGUIDs("TypeLib", typelibs);
	msg("done (%u known).\n", total);
	if (total > 0) {
#ifdef _SHOWADDRESS
		ea_t lastAuto(0);
#endif
		uint totals[3];
		fill_n(CPY(totals), 0);
		for (int n = 0; n < get_segm_qty(); ++n) {
			if (wasBreak()) break;
			const segment_t *const segment = getnseg(n);
			if (segment == 0 || is_spec_segm(segment->type)
				|| is_in_rsrc(segment->startEA)) continue;
			ea_t scan(BADADDR);
			for (ea_t ea = segment->startEA;
				ea <= segment->endEA - sizeof GUID; ea = nextaddr(ea)) try {
#ifdef _SHOWADDRESS
				if (ea > lastAuto + AUTOFREQ) {
					if (wasBreak()) break;
					showAddr(lastAuto = ea);
				}
#endif // _SHOWADDRESS
				if (scan < ea || scan == BADADDR) scan = ea;
				while (scan < ea + sizeof GUID && isLoaded(scan)) ++scan;
				if (scan < ea + sizeof GUID || is_guid(ea)) continue;
				const GUIDEX guid(ea);
				if (!guid.isSet()) continue;
				tid_t struc_id;
				if (interfaces.find(guid) != interfaces.end()) {
					const interface_t intf(guid);
					_ASSERTE(intf.isSet());
					if (intf.isSet()) {
						++totals[0];
						::list.Add(ea, 1, intf.name.c_str(), intf.TypeLib.hasTypeLib());
						msg("%s%08a: %s possible IID of %s%s\n", prefix, ea,
							intf.toString().c_str(), !intf.name.empty() ?
							intf.name .c_str() : "<nameless interface>",
							intf.TypeLib.hasTypeLib() ? " (typeinfo present)" : "");
						if (create) doStruct(ea, "IID");
					}
				}
				if (classes.find(guid) != classes.end()) {
					const clsid_t cls(guid);
					_ASSERTE(cls.isSet());
					if (cls.isSet()) {
						++totals[1];
						::list.Add(ea, 2, cls.name.c_str());
						msg("%s%08a: %s possible CLSID of %s\n", prefix, ea,
							cls.toString().c_str(), !cls.name.empty() ?
							cls.name.c_str() : "<nameless class>");
						if (create) doStruct(ea, "CLSID");
					}
				}
				if (typelibs.find(guid) != typelibs.end()) {
					const typelib_t tlb(guid);
					_ASSERTE(tlb.isSet());
					if (tlb.isSet()) {
						++totals[2];
						::list.Add(ea, 3, tlb.name.c_str());
						msg("%s%08a: %s possible GUID of %s\n", prefix, ea,
							tlb.toString().c_str(), !tlb.name.empty() ?
							tlb.name.c_str() : "<nameless typelib>");
						if (create) doStruct(ea, "GUID");
					}
				}
			} catch (const exception &e) {
				msg("%08a: %s\n", ea, e.what());
			}
		} // iterate segments
		total = accumulate(ARRAY_RANGE(totals), 0);
		msg("%sTOTALS:\n%s-------\n%s%8u interfaces\n"
			"%s%8u classes\n%s%8u typelibs\n", prefix, prefix,
			prefix, totals[0], prefix, totals[1], prefix, totals[2]);
	} // have GUIDS from registry
	wait_box.close();
	if (::list > 0)
		if (!listwasopen/* && ::list.GetTForm() == NULL*/)
			::list.Open();
#if IDP_INTERFACE_VERSION >= 76
#if IDA_SDK_VERSION >= 520
		else
			::list.Refresh();
#endif
	else
		::list.Close();
#endif
	return total;
}

static int idaapi init(void) {
	if (ph.id != PLFM_386/* || inf.filetype != f_PE*/) {
		msg("%sINFO: plugin not available for current architecture or file format\n", prefix);
		return PLUGIN_SKIP;
	}
	CoInitialize(NULL);
	if (hooker.activate()) return PLUGIN_KEEP;
	msg("%sERROR: failed to set callback, plugin will not assist on doData() during current session\n", prefix);
	warning("com helper error: failed to set callback, plugin will not be available during current session.");
	return PLUGIN_OK;
}

static void idaapi term(void) {
	if (!hooker.deactivate())
		msg("%sWARNING: could not unhook callback function\n", prefix);
	CoUninitialize();
}

static void idaapi run(int arg) {
	BPX;
	try {
		switch (arg) {
			case 0: // toggle com helper
				if (hooker) {
					if (!hooker.deactivate()) {
						warning("COM HELPER error: cannot unhook callback");
						return;
					}
					if (::list <= 0) PLUGIN.flags |= PLUGIN_UNL;
				} else {
					if (!hooker.activate()) {
						warning("COM HELPER error: failed to set callback, plugin will not be available during current session.");
						return;
					}
				}
				info("This is a COM HELPER plugin\n\nIt watches for the GUID variables and renames them\n"
					"depending on their values. As soon as a GUID is seen,\n"
					"it adds the corresponding vtable to the list of structures.\n\n"
					"You have just changed the plugin state to: %s.", hooker ? "ON" : "OFF");
				break;
			case 1:
			case 2:
				scan_for_guids(arg >= 2);
				break;
			case 0xFFFF: // forced plugin unload
			case -1:
#if IDP_INTERFACE_VERSION < 76
				if (::list > 0 && askyn_c(0, "HIDECANCEL\n"
					"There is one or more open viewer pane(s)\n"
					"associated with this plugin, unload anyway?\n"
					"(will be cut-off from his data store)") != 1) return;
#endif
				if (!hooker.deactivate()) {
					warning("COM HELPER error: cannot unhook callback");
					return;
				}
				PLUGIN.flags |= PLUGIN_UNL;
				break;
			default:
				warning("comhelper2: this is bad plugin parameter!\n\n"
					"supported functions are:\n"
					"\t 0: toggle com-helper\n"
					"\t 1: scan for GUIDs (report only)\n"
					"\t 2: scan for GUIDs (auto-create)\n"
					"\t-1: forced plugin unload");
				return;
		} // switch
	} catch (const exception &e) {
		msg("%s%s: %s, %s\n", prefix, "ERROR", e.what(), "lame stoopid servil ;p");
		MessageBeep(MB_ICONERROR);
		warning("%s, %s", e.what(), "lame stoopid servil ;p");
		return;
	} catch (...) {
		msg("%s%s: %s, %s\n", prefix, "ERROR", "unhandled exception", "lame stoopid servil ;p");
		MessageBeep(MB_ICONERROR);
		warning("%s, %s", "unhandled exception", "lame stoopid servil ;p");
		return;
	}
	MessageBeep(MB_OK);
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
		DisableThreadLibraryCalls((HMODULE)hInstance = hinstDLL);
		se_exception::_set_se_translator();
#ifdef _DEBUG
		_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
		_CrtSetDbgFlag(/*_CRTDBG_CHECK_EVERY_1024_DF | */_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#else // !_DEBUG
		DWORD flOldProtect;
		VirtualProtect((PBYTE)hInstance + 0x14000, 0x5000, PAGE_READONLY, &flOldProtect);
#endif // _DEBUG
	}
	return TRUE;
}

// ================================ENTRY POINT================================
plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION, PLUGIN_MOD,
	init, term, run, PLUGINNAME " v" PLUGINVERSIONTEXT, 0, "OLE/COM helper", 0
};
// ================================ENTRY POINT================================
