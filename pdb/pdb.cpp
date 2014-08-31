
// IDA Pro plugin to load function name information from PDB files

// This file was modify from the old PDB plugin.

// I rewrite the sybmol loading code.
// It use native dbghelp.dll now and it should support 64 bit if
// IDA does. Test with windows XP SP1 PDB files.

// Make sure you have the lastest dbghelp.dll in your search
// path. I put the dbghelp.dll in the plugin directory.

// You can define the symbol search path like windbg does.
//                                  - Christopher Li

// Revision history:
//      - Removed static linking to DBGHELP.DLL
//      - Added support for different versions of DBGHELP.DLL
//                                                      Ilfak Guilfanov

#ifdef _MSC_VER
#	ifdef __ICL // IntelC++ specific
#		pragma warning(disable:   47) // incompatible redefinition of macro "xxx"
#		pragma warning(disable:  269) // invalid format string conversion
#		pragma warning(disable:  903) // __declspec attribute ignored
#		pragma warning(disable: 1011) // missing return statement at end of non-void function
#	else // MSVC
#		pragma warning(disable:  903)
#		pragma warning(disable:  791)
#	endif
// ensure old good VC for sscoping model
#	pragma conform(forScope, off)
#endif

#define NOMINMAX            1

#include <cstdlib>
#include <cstdarg>
#include <malloc.h>
#include <excpt.h>
#include "mscrtdbg.h"
#include "msvc70rt.h"
#include <string>
#include <deque>
#include <queue>
#include <set>
#include <hash_set>
#include <hash_map>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <bitset>
#include <stdexcept>
#include <new>
//#define BOOST_SP_ENABLE_DEBUG_HOOKS 1
#include <boost/smart_ptr.hpp>
#include <boost/next_prior.hpp>
#include <boost/bind.hpp>
//#include <boost/functional.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/functional/hash.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
//#include <boost/lambda/lambda.hpp>
//#include <boost/lambda/bind.hpp>
//#include <boost/lambda/if.hpp>
#include <windows.h>
#include <cvconst.h>
#include <dia2.h>
#include <diacreate.h>
#include <OAIdl.h>
#include <oleauto.h>
#include <atlbase.h>
#define __in_bcount_opt(x)
#define __out_bcount_opt(x)
#include <DbgHelp.h>
#include <psapi.h>
#if defined(_DEBUG) && defined(NMBC)
#include <NmApiLib.h>
#endif

#ifdef PDB_RUN_WATCHER_THREAD
#include <boost/thread.hpp>
#include "syncpmtv.hpp"
#endif
#include "md5.hpp"
#include "pcre.hpp"
#define __PLUGIN__ 1
#define BYTES_SOURCE 1
#define ENUM_SOURCE 1
#define SE_XCPT_NO_SYMCLEANUP 1
#include "idasdk.hpp"
#include "plughlpr.hpp"
#include "plugxcpt.hpp"
#include "plugsys.hpp"
#include "plugstrm.hpp"
#include "plugtinf.hpp"
#include "plugcmn.hpp"
#include "plugcom.hpp"
#include "pluginsn.hpp"

#ifdef _DEBUG
#define PRINT_TYPE_ONCE 1 // if defined, print type in expanded form only once
#endif
#define DBGHELP_DLL     "DbgHelp.dll"
#define IMAGEHLP_DLL    "ImageHlp.dll"
#define SCOPE_DELIMITER "::"           // used to separate nested type names
#define UNNAMED_NAME    L"__unnamed"   // dummy name for nameless user types
#define UNNAMED_FMT     "%S$%08lx"     // dummy format to anonymous complex types
                                       // 1-st parameter: member name in UNC (UNNAMED_NAME expected)
                                       // 2-nd: unique type index (DWORD)
                                       // resulting name must be globally unique
#define FORMAL_NAME     L"__formal"    // version of __unnamed for dummy function parameter
#define FORMAL_FMT      "%S$%08lx"     // version of __unnamed for dummy function parameter
#define VTABLE_NAME     "___VTable"    // autoname for VTable class members if
                                       // nameless (expected)
#if IDP_INTERFACE_VERSION < 76
#define showAddr        __noop         // IDA progress is time expensive on older versions
#endif
#define DYNPROC_TYPE(fname) fname##_t
#define DYNPROC_PTR(fname) p##fname
#define DECL_DYNPROC_PTR(fname) static DYNPROC_TYPE(fname) DYNPROC_PTR(fname)(NULL);
#define SET_DYNPROC_PTR(hDll, fname) DYNPROC_PTR(fname) = \
	reinterpret_cast<DYNPROC_TYPE(fname)>(GetProcAddress(hDll, #fname));

#ifndef BAD_ARGLOC
inline bool is_user_cc(cm_t cm) {
#	ifdef CM_CC_SPECIALP
	return(get_cc(cm) >= CM_CC_SPECIALP);
#	else
	return(get_cc(cm) >= CM_CC_SPECIAL);
#	endif
}
#endif // BAD_ARGLOC

#define DEF_NTF_FLAGS (NTF_SYMM | NTF_TYPE/* | NTF_NOBASE*/)

using namespace std;
//using namespace boost::lambda;

// ix86 registers representation for pc.w32
static RegNo ix86_getReg(CV_HREG_e); // map PDB representation to IDA's pc.w32 id
static size_t ix86_getRegBitness(CV_HREG_e); // get register size
static WORD phid2mt();
static bool is_far_call(DWORD CallConv);
static ULONGLONG VarToUI64(const VARIANT &);
static tid_t CreateStructCY();
static bool CreateBSTR() throw();
static bool CreateHRESULT() throw();
static bool CreateDATE() throw();
static bool CreateCURRENCY() throw();
// tokenizers
static string TokenizeSymTag(enum SymTagEnum SymTag);
static string TokenizeLocationType(enum LocationType LocType);
static string TokenizeSymFlag(ULONG Flags);
string TokenizeBasicType(enum BasicType BaseType);
string TokenizeDataKind(enum DataKind DataKind);
static const char *TokenizePlatform(enum CV_CPU_TYPE_e Platform);
static string TokenizeUDTKind(enum UdtKind UDTKind);
static const char *TokenizeCallConv(enum CV_call_e CallConv);
static const char *ix86_getRegCanon(enum CV_HREG_e Register);

// general exception passed higher when PDB type can't be 1:1 translated to IDA
class not_convertible : public exception {
public:
	const char *what() const
		{ return "PDB type not losslessly convertible to type_t[] string"; }
};

struct elem_t {
	typestring type;
	argloc loc;
};

#ifdef _DEBUG
static bool idaapi dbg_printer(void *cbdata, const char *buf) {
	OutputDebugString("%s(...): %s\n", cbdata, buf);
	return true;
}
#endif // _DEBUG

template<class _ErrT>
static void error_msg_base(_ErrT err_code, const char *api_name) {
	string s;
	_ASSERTE(api_name != 0);
	_sprintf(s, "%s error %0*X", api_name, sizeof(err_code) << 1, err_code);
	SimpleString<TCHAR, LocalAllocator<> > lpMsgBuf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		static_cast<DWORD>(err_code), LANG_USER_DEFAULT, (LPTSTR)&lpMsgBuf, 0, NULL);
	if (lpMsgBuf) _sprintf_append(s, " (%s)", static_cast<LPCTSTR>(lpMsgBuf));
	warning("%s", s.c_str());
}

// enumeration helper collections
typedef hash_map<ea_t, string> sym_t, *sym_p;

static DWORD64 SymBase;
static uint totalnames, totaltypeinfos, totalfuncs, totaldata,
	totalstructs, totalenums, totaltypedefs;
static const sclass_t sc_tdef(sc_type);
static const char log_prefix[] = "[PDB] ";
static bool foreign_pdb;
static struct {
	hash_set<DWORD> by_id;
	hash_set<string> by_name;
} types_created;
static hash_set<DWORD> inheritance_path;
#ifdef PRINT_TYPE_ONCE
static hash_set<DWORD> printed_types;
#endif
/*
static const struct {
	const wchar_t *name;
	const char *format;
} dummy_names[] = {
	UNNAMED_NAME, UNNAMED_FMT,
	//FORMAL_NAME, FORMAL_FMT,
};
*/
static layered_wait_box wait_box;

static void reset_globals(bool all_empty = false) {
	_ASSERTE(types_created.by_id.empty());
	types_created.by_id.clear();
	_ASSERTE(types_created.by_name.empty());
	types_created.by_name.clear();
	_ASSERTE(inheritance_path.empty());
	inheritance_path.clear();
#ifdef PRINT_TYPE_ONCE
	_ASSERTE(!all_empty || printed_types.empty());
	printed_types.clear();
#endif
}

static bool create_func_if_necessary(ea_t ea, const char *name) {
	int stype(segtype(ea));
	if (stype != SEG_NORM && stype != SEG_CODE // only for code or normal segments
		|| get_mangled_name_type(name) == MANGLED_DATA || !ua_ana0(ea)
		|| !ph.notify(ph.is_sane_insn, 1)) return false;
	auto_make_proc(ea);
	return true;
}

static bool looks_like_function_name(const char *name) {
	// this is not quite correct: the presence of an opening brace
	// in the demangled name indicates a function
	// we can have a pointer to a function and there will be a brace
	// but this logic is not applied to data segments
	if (strchr(name, '(') != NULL) return true;
	// check various function keywords
	static const char *const keywords[] = {
		"__cdecl ", "__stdcall ", "__fastcall ", "__thiscall ", "__pascal ",
		"public: ", "protected: ", "private: ",
		"virtual ", "operator ",
	};
	for (int i = 0; i < qnumber(keywords); ++i)
		if (strstr(name, keywords[i]) != NULL) return true;
	return false;
}

static bool check_for_ids(ea_t ea, const char *name) {
	_ASSERTE(name != 0 && *name != 0);
	if (name == 0 || *name == 0) return false;
  // Seems to be a GUID?
  const char *ptr = name;
  while (*ptr == '_') ++ptr;

  static const char *guids[] = { "IID", "DIID", "GUID", "CLSID", "TGUID", NULL };
  static const char *sids[] = { "SID", NULL };
  static const struct id_info_t {
    const char **names;
    const char *type;
  } ids[] = {
    { guids, "GUID x;" },
    { sids, "SID x;" },
  };

  for ( int k=0; k < qnumber(ids); k++ )
    for ( const char **p2=ids[k].names; *p2; p2++ ) {
      const char *guid = *p2;
      size_t len = strlen(guid);
      if ( strncmp(ptr, guid, len) == 0
        && (ptr[len] == '_' || ptr[len] == ' ') ) { // space can be in demangled names
        // keep IDA 4.9 compatibility
        apply_cdecl(ea, ids[k].type); //apply_cdecl2(idati, ea, ids[k].type);
        return true;
      }
    }
  return false;
}

static bool get_validated_name(const char *name, string &validated_name) throw(exception) {
	validated_name.clear();
	_ASSERTE(name != 0 && *name != 0);
	if (name == 0 || *name == 0) return false;
	const size_t sz = strlen(name) + 1;
	const boost::scoped_array<char> tmp(new char[sz]);
	if (!tmp) throw bad_alloc();
	if (validate_name(qstrncpy(tmp.get(), name, sz)) == NULL) return false;
	validated_name.assign(tmp.get());
	return true;
}

// returns true if named successfully
static bool apply_static_name(ea_t ea, const char *name) {
	_ASSERTE(!foreign_pdb);
	_ASSERTE(name != 0 && *name != 0);
	if (!isEnabled(ea) || name == 0 || *name == 0) return false;
	char idaname[MAXNAMESIZE], demname[MAXSTR];
	// make local copy not longer than MAXNAMESIZE chars
	// kernel may crash if receiving longer names
	qstrcpy(idaname, name);
	_ASSERTE(strlen(idaname) < MAXNAMESIZE);
	// check for meaningless 'string' names (??_C@......)
	if (demangle(CPY(demname), idaname, inf.short_demnames) > 0
		&& strcmp(demname, "`string'") == 0/*boost::equals(demname, "`string'")*/)
		make_ascii_string(ea, 0, get_max_ascii_length(ea, ASCSTR_C) >=
			get_max_ascii_length(ea, ASCSTR_UNICODE) ? ASCSTR_C : ASCSTR_UNICODE);
	/*
	// check for function telltales
	if (segtype(ea) != SEG_DATA && demangle(CPY(demname), name, MNG_LONG_FORM) > 0
		&& looks_like_function_name(demname))
		// fixme: when we will implement lvars, we have to process these request
		// before handling lvars
		auto_make_proc(ea);
	create_func_if_necessary(ea, name);
	*/
	bool ok = do_name_anyway(ea, idaname, MAXNAMESIZE);
	if (!ok && validate_name(idaname) != NULL)
		ok = do_name_anyway(ea, idaname, MAXNAMESIZE);
	if (ok) {
		showAddr(ea); // so the user doesn't get bored
		if (strlen(name) >= MAXNAMESIZE) cmsg << log_prefix <<
			"WARNING: name truncation(" << dec << strlen(name) << ") at " <<
			asea(ea) << " due to B-tree limitation: " << name << endl;
	}
	return ok;
}

static int add_struc_member_anyway(struc_t *sptr, const char *fieldname,
	ea_t offset, flags_t flag, const typeinfo_t *mt, asize_t nbytes) {
	_ASSERTE(sptr != 0);
	if (sptr == 0) return STRUC_ERROR_MEMBER_STRUCT;
	_ASSERTE(!sptr->is_union() || offset == 0);
	//if (sptr->is_union()) offset = 0;
	if (fieldname != 0 && *fieldname == 0) fieldname = 0;
	_ASSERTE(isData(flag));
	//_ASSERTE(nbytes > 0);
	int err = add_struc_member(sptr, fieldname, offset, flag, mt, nbytes);
	if (err == STRUC_ERROR_MEMBER_NAME && fieldname != 0) {
		string validated_name;
		if (!get_validated_name(fieldname, validated_name)) return err; // can't help
		err = add_struc_member(sptr, validated_name.c_str(), offset, flag, mt, nbytes);
		if (err == STRUC_ERROR_MEMBER_NAME) {
			char newname[MAXNAMESIZE];
			for (uint suffix = 0; suffix < 1000; ++suffix) {
				qsnprintf(CPY(newname), "%s_%u", validated_name.c_str(), suffix);
				err = add_struc_member(sptr, newname, offset, flag, mt, nbytes);
				if (err != STRUC_ERROR_MEMBER_NAME) break;
			}
			if (err == STRUC_ERROR_MEMBER_NAME) // try nameless
				err = add_struc_member(sptr, 0, offset, flag, mt, nbytes);
		}
	}
	return err;
}

static tid_t get_struc_id_anyway(const char *name) {
	_ASSERTE(name != 0 && *name != 0);
	if (name == 0 || *name == 0) return BADNODE;
	tid_t tid = get_struc_id(name);
	if (tid != BADNODE) return tid;
	string validated_name;
	return get_validated_name(name, validated_name) ?
		get_struc_id(validated_name.c_str()) : BADNODE;
}

static enum_t get_enum_anyway(const char *name) {
	_ASSERTE(name != 0 && *name != 0);
	if (name == 0 || *name == 0) return BADNODE;
	enum_t enu = get_enum(name);
	if (enu != BADNODE) return enu;
	string validated_name;
	return get_validated_name(name, validated_name) ?
		get_enum(validated_name.c_str()) : BADNODE;
}

static flags_t getDataFlagsByLength(ULONG64 Length) {
	switch (Length) {
		case sizeof(BYTE): return byteflag();
		case sizeof(WORD): return wordflag();
		case sizeof(DWORD): return dwrdflag();
		case 8/*sizeof(QWORD)*/: return qwrdflag();
		case 16/*sizeof(OWORD)*/: return owrdflag();
#if IDP_INTERFACE_VERSION >= 76
		case 3: return tribyteflag();
#endif
	}
	if (Length == ph.tbyte_size) return tbytflag();
	_RPT2(_CRT_WARN, "%s(0x%I64X): unexpected length\n", __FUNCTION__, Length);
#if IDP_INTERFACE_VERSION >= 76
	if (hIdaWll != NULL) {
		typedef flags_t (ida_export *DYNPROC_TYPE(get_flags_by_size))(size_t);
		const DYNPROC_TYPE(get_flags_by_size) SET_DYNPROC_PTR(hIdaWll, get_flags_by_size)
		if (DYNPROC_PTR(get_flags_by_size) != NULL)
			return DYNPROC_PTR(get_flags_by_size)((size_t)Length);
	}
#endif
	return 0/*FF_DATA?*/;
}

static flags_t ptrflag(flags_t flag = FF_DATA)
	{ return getDataFlagsByLength(get_ptr_size(flag)) | offflag(); }

static void ix86_apply_sp_delta(ea_t ea, adiff_t sp_delta) {
	_ASSERTE(isEnabled(ea));
	if (!isEnabled(ea)) return;
	if (get_ind_purged(ea) != sp_delta) set_ind_purged(ea, sp_delta);
	if (ph.id == PLFM_386 && hasRef(get_flags_novalue(ea))) {
		xrefblk_t xrefs;
		for (bool ok = xrefs.first_to(ea, XREF_FAR); ok; ok = xrefs.next_to())
			if (isCode(get_flags_novalue(xrefs.from))) {
				if (is_call_insn(xrefs.from)) {
					func_t *const func(get_fchunk(xrefs.from));
					if (func != 0 && get_sp_delta(func, (ea = next_not_tail(xrefs.from))) != sp_delta) {
						showAddr(ea);
						if (add_user_stkpnt(ea, sp_delta))
							OutputDebugString("User SP delta changed to %c%IX at %08IX\n",
								SIGNED_PAIR(sp_delta), xrefs.from);
					}
				}
				if (is_pure_import_func(xrefs.from))
					ix86_apply_sp_delta(xrefs.from, sp_delta);
			}
	}
}

static bool ix86_fix_stkframes() {
	if (ph.id != PLFM_386) return false;
	cmsg << log_prefix << "Fixing SP deltas...";
	ea_t scan;
	const PCRE::regexp is_stdcall_name("^\\w+\\@(\\d+)(?:_\\d+)?$");
	if (is_stdcall_name) for (int n = 0; n < get_segm_qty(); ++n) {
		const segment_t *const segment(getnseg(n));
		_ASSERTE(segment != 0);
		if (segment != 0 && segment->type == SEG_XTRN)
			for (scan = segment->startEA; scan < segment->endEA;
				scan = nextthat(scan, segment->endEA, TESTFUNC(has_name))) {
				if (wasBreak()) {
					cmsg << "cancelled" << endl;
					return false;
				}
				char funcname[MAXNAMESIZE];
				int ovector[6];
				uint argsize;
				if (has_name(get_flags_novalue(scan))
					&& get_true_name(BADADDR, scan, CPY(funcname)) != 0
					&& is_stdcall_name(funcname, ovector, 6) >= 2
					&& (funcname[ovector[3]] = 0, (argsize = strtoul(funcname + ovector[2], 0, 10)) > 0)) {
					showAddr(scan);
					ix86_apply_sp_delta(scan, argsize);
				}
			}
	}
	/*
	for (size_t iter = 0; iter < get_func_qty(); ++iter) {
		if (wasBreak()) {
			cmsg << "cancelled" << endl;
			return false;
		}
		func_t *const func(getn_func(iter));
		//_ASSERTE(func != 0);
		if (func != 0) {
			showAddr(func->startEA);
			func_tail_iterator_t fti(func);
			for (bool ok = fti.main(); ok; ok = fti.next())
				for (scan = fti.chunk().startEA; scan < fti.chunk().endEA;
					scan = next_head(scan, fti.chunk().endEA))
					if (isCode(get_flags_novalue(scan)) && ua_ana0(scan) > 0) {
						sval_t spdelta(0);
						switch (cmd.itype) {
							case NN_push: spdelta = -get_dtyp_size(cmd.Op1.dtyp); break;
							case NN_pop: spdelta = +get_dtyp_size(cmd.Op1.dtyp); break;
							case NN_add:
								if (cmd.Op1.is_reg(R_sp) && cmd.Op2.type == o_imm)
									spdelta = +cmd.Op2.value;
								break;
							case NN_sub:
								if (cmd.Op1.is_reg(R_sp) && cmd.Op2.type == o_imm)
									spdelta = -cmd.Op2.value;
								break;
						}
						ea_t ea;
						if (spdelta != 0 && get_sp_delta(func, (ea = next_not_tail(scan))) == 0) {
							showAddr(ea);
							if (add_auto_stkpnt(ea, spdelta))
								OutputDebugString("Auto SP delta changed to %c%IX at %08IX\n",
									SIGNED_PAIR(spdelta), scan);
						}
					}
		} // func stucture avail
	} // iterate functions
	*/
	cmsg << "done" << endl;
	return true;
}

// ix86 only
static asize_t ix86_get_frame_locals(const func_t *func) {
	_ASSERTE(func != 0);
	if (func == 0) __stl_throw_invalid_argument("NULL function pointer");
	char name[MAXNAMESIZE];
	if (ph.id == PLFM_386) {
		const PCRE::regexp is_chkstk("^(?:" FUNC_IMPORT_PREFIX ")?_*chkstk$");
		for (ea_t scan = func->startEA; scan < func->endEA; scan = next_head(scan, func->endEA))
			if (isCode(get_flags_novalue(scan)) && ua_ana0(scan) > 0)
				if (cmd.Op1.is_reg(R_sp)) {
					if (cmd.Op2.type == o_imm)
						if (cmd.itype == NN_sub) {
							if (static_cast<sval_t>(cmd.Op2.value) <= 0) break;
							OutputDebugString("%08IX: frame pointer delta = 0x%IX\n", scan, cmd.Op2.value);
							return cmd.Op2.value;
						} else if (cmd.itype == NN_add) {
							if (static_cast<sval_t>(cmd.Op2.value) >= 0) break;
							OutputDebugString("%08IX: frame pointer delta = 0x%IX\n", scan, -cmd.Op2.value);
							return -cmd.Op2.value;
						}
					if (insn_changes_opnd(cmd.itype, 0)) break;
				} else if (is_call_insn(scan) && has_name(get_flags_novalue(cmd.Op1.addr))
					&& get_true_name(BADADDR, cmd.Op1.addr, CPY(name)) != 0
					&& is_chkstk.match(name)) {
					while ((scan = prev_head(scan, func->startEA)) != BADADDR)
						if (isCode(get_flags_novalue(scan)) && ua_ana0(scan) > 0
							&& (cmd.itype == NN_mov || cmd.itype == NN_movzx || cmd.itype == NN_movsx)
							&& cmd.Op1.is_reg(R_ax) && cmd.Op2.type == o_imm) {
							if (static_cast<sval_t>(cmd.Op2.value) <= 0) break;
							OutputDebugString("%08IX: frame pointer delta = 0x%IX\n", scan, cmd.Op2.value);
							return cmd.Op2.value;
						}
					break;
				}
	} // ph.id == PLFM_386
	_RPT2(_CRT_WARN, "%s(...): frame size not found from disassembly - assuming func->frsize (0x%IX)\n",
		__FUNCTION__, func->frsize);
	return func->frsize;
}

// fully reconstruct data type based on typeinfo
static tid_t set_named_type(const char *name, const typestring &type,
	const plist &fnames, int ntf_flags = DEF_NTF_FLAGS, const sclass_t *sclass = 0,
	const char *cmt = 0, const p_list *fieldcmts = 0, const ulong *value = 0) {
	_ASSERTE(name != 0 && *name != 0);
	if (name == 0 || *name == 0) return BADNODE;
	tid_t tid;
	return ((tid = get_struc_id(name)) != BADNODE
		|| (tid = static_cast<tid_t>(get_enum(name))) != BADNODE) ? tid :
			::set_named_type(idati, name, ntf_flags, type.c_str(),
				!fnames.empty() ? fnames.c_str() : NULL, cmt, fieldcmts, sclass, value)
					? 0 : BADNODE;
}

static tid_t get_named_type(const char *name, int ntf_flags = DEF_NTF_FLAGS) {
	_ASSERTE(name != 0 && *name != 0);
	if (name == 0 || *name == 0) return BADNODE;
	tid_t tid;
	return ((tid = get_struc_id(name)) != BADNODE
		|| (tid = static_cast<tid_t>(get_enum(name))) != BADNODE) ? tid :
			get_named_type(idati, name, ntf_flags) >/*!=(?)*/ 0 ? 0 : BADNODE;
}

static inline bool is_named_type(const char *name, int ntf_flags = DEF_NTF_FLAGS)
	{ return get_named_type(name, ntf_flags) != BADNODE; }

template<class _CntnrT>class __declspec(novtable) typesview_t : public _CntnrT {
public:
	operator typename _CntnrT::size_type() const { return size(); }

	bool Open() {
		if (empty()) return false;
		static int const widths[] = { 46, 2, };
		static const char *popup_names[] = {
			"", "Delete selected", "Filter", "Refresh",
		};
		return choose2(CH_MODAL | CH_MULTI, -1, -1, -1, -1, this, qnumber(widths),
			widths, sizer, getl, "Revise types to be imported", GetIcon(0),
			1/*default*/, del, 0/*ins*/, 0/*update*/, edit, 0/*enter*/,
			0/*destroy*/, popup_names, get_icon) > 0;
	}

protected:
	virtual bool IsTypeEmpty(typename _CntnrT::const_reference) const = 0;

private:
	typename _CntnrT::const_reference at(typename _CntnrT::size_type n) const {
		_ASSERTE(n < operator size_type());
		if (n >= operator size_type()) __stl_throw_out_of_range("::typesview_t");
		return *boost::next(begin(), n);
	}

	// IDA callback handlers
	void GetLine(ulong n, char * const *arrptr) const {
		if (n == 0) { // header
			static const char *const headers[] = { "name", "type", };
			for (uint i = 0; i < qnumber(headers); ++i)
				qstrncpy(arrptr[i], headers[i], MAXSTR);
		} else { // regular item
			if (n > operator size_type()) return; //_ASSERTE(n <= operator size_t());
			const_reference item(at(n - 1));
			item.getAnsiName(arrptr[0], MAXSTR);
			switch (item.SymTag) {
				case SymTagUDT:
					switch (item.UDTKind) {
						case UdtStruct: qstrncpy(arrptr[1], "S", MAXSTR); break;
						case UdtUnion: qstrncpy(arrptr[1], "U", MAXSTR); break;
						case UdtClass: qstrncpy(arrptr[1], "C", MAXSTR); break;
						default:
							_RPT3(_CRT_WARN, "%s(%lu): unexpected UDTKind value (%lu)\n",
								__FUNCTION__, n, item.UDTKind);
							qstrncpy(arrptr[1], "UDT(?)", MAXSTR);
					}
					break;
				case SymTagEnum: qstrncpy(arrptr[1], "E", MAXSTR); break;
				case SymTagTypedef: qstrncpy(arrptr[1], "T", MAXSTR); break;
				default:
					qstrncpy(arrptr[1], "?", MAXSTR);
					_RPT3(_CRT_WARN, "%s(%lu): unexpected symbol tag (%s)\n",
						__FUNCTION__, n, item.TokenizeSymTag().c_str());
			}
		} // regular item
	}
	int GetIcon(ulong n) const {
		if (n == 0) return 157; // list head icon
		//_ASSERTE(n <= operator size_type());
		if (n <= operator size_type()) switch (at(n - 1).SymTag) {
			case SymTagUDT: return 52;
			case SymTagEnum: return 63;
			case SymTagTypedef: return 69;
#ifdef _DEBUG
			default:
				_RPT3(_CRT_WARN, "%s(%lu): unexpected symbol tag (%s)\n",
					__FUNCTION__, n, at(n - 1).TokenizeSymTag().c_str());
#endif // _DEBUG
		}
		return -1;
	}
	// The chooser will allow multi-selection (only for GUI choosers).
	// If multi-selection is enabled, a multi-selection callback will be called with:
	//   ulong = START_SEL   before calling the first selected item
	//   ulong =  1..n       for each selected item
	//   ulong = END_SEL     after calling the last  selected item
	// If the callback returns 'false', further processing
	//   of selected items is cancelled.
	ulong Delete(ulong n) {
		// EMPTY_SEL =  0, // no item was selected
		if (IS_EMPTY_SEL(n)) {
			//Filter(n);
			return 0/*???*/;
		}
		// START_SEL = -1, // before calling the first selected item
		// END_SEL   = -2; // after calling the last  selected item
		if (IS_START_SEL(n) || IS_END_SEL(n)) return 1/*???*/;
		_ASSERTE(n >= 1 && n <= operator size_type());
		if (n < 1 || n > operator size_type()) __stl_throw_out_of_range("::typesview_t");
		erase(boost::next(begin(), n - 1));
		return 1/*???*/; // returns 0:ok 1:failed ?????
	}
	// returns true if some types were removed
	bool Filter(ulong n) {
		char regex[MAXSTR];
		if (n >= 1 && n <= operator size_type())
			at(n - 1).getAnsiName(CPY(regex));
		else
			fill_n(CPY(regex), 0);
		ushort entities(1 | 2 | 4), flags(0), re_flags(1), mode(0);
		PCRE::tables tables(""/*use system locale*/);
		PCRE::regexp re;
	reentry:
		if (AskUsingForm_c("Filter imported types\n"
			"<#To match all names, leave blank (perl regular expressions are supported)#Match name by regular e~x~pression :A:1023:45::>\n"
			"<##Apply to##~U~DTs:c> <~E~nums:c> <~T~ypedefs:c>> "
			"<E~m~pty:c> <~N~ested:c>> "
			"<##Search options##~C~ase sensitive:c> <Ungreedy:c>> "
			"<~D~elete matched:r> <~R~etain matched:r>>\n\n\n",
			regex, &entities, &flags, &re_flags, &mode) == 0) return false;
		const char *errptr;
		int erroffset;
		if (re.compile(regex, ((re_flags & 1) == 0 ? PCRE_CASELESS : 0) |
			((re_flags & 2) != 0 ? PCRE_UNGREEDY : 0), errptr, erroffset, tables) != 0) {
			warning("Invalid regular expression: %s\n%s[%i]",
				errptr, regex, erroffset);
			goto reentry;
		}
		_ASSERTE(re.compiled());
		const size_type sz(size());
		if ((entities & 7) == 0) {
			if (mode == 1) clear();
		} else {
			iterator it(begin());
			while (it != end()) {
				const bool match = (it->SymTag == SymTagUDT && (entities & 1) != 0
					|| it->SymTag == SymTagEnum && (entities & 2) != 0
					|| it->SymTag == SymTagTypedef && (entities & 4) != 0)
					&& ((flags & 1) == 0 || IsTypeEmpty(*it))
					&& ((flags & 2) == 0 || it->Nested) && re.match(it->getAnsiName());
				if (match && mode == 0 || !match && mode == 1) it = erase(it); else ++it;
			}
		}
		return size() < sz;
	}

	// IDA chooser callback functions
	static ulong idaapi sizer(void *obj)
		{ return static_cast<ulong>(static_cast<typesview_t *>(obj)->operator size_type()); }
	static void idaapi getl(void *obj,ulong n,char * const *arrptr)
		{ static_cast<typesview_t *>(obj)->GetLine(n, arrptr); }
	static ulong idaapi del(void *obj,ulong n)
		{ return static_cast<typesview_t *>(obj)->Delete(n); }
	static void idaapi edit(void *obj,ulong n)
		{ static_cast<typesview_t *>(obj)->Filter(n); }
	static int idaapi get_icon(void *obj,ulong n)
		{ return static_cast<typesview_t *>(obj)->GetIcon(n); }
}; // typesview_t

static void load_vc_til() {
	// We managed to load the PDB file.
	// It is very probably that the file comes from VC
	// Load the corresponding type library immediately
	IMAGE_NT_HEADERS nthdr;
	if (ph.id != PLFM_386
		|| netnode("$ PE header").valobj(&nthdr, sizeof(nthdr)) < sizeof(nthdr)
		|| nthdr.OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE) return;
#ifdef ADDTIL_INCOMP
	typedef int (idaapi *DYNPROC_TYPE(add_til2))(const char *, int);
	const DYNPROC_TYPE(add_til2) SET_DYNPROC_PTR(hIdaWll, add_til2);
	if (DYNPROC_PTR(add_til2) != NULL)
		DYNPROC_PTR(add_til2)(nthdr.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ?
			"vc8amd64" : "vc6win", ADDTIL_INCOMP);
	else
#endif
		add_til("vc6win");
}

// ! musí být v global namespace !
inline bool operator <(const SRCCODEINFO &lhs, const SRCCODEINFO &rhs)
	{ return lhs.LineNumber < rhs.LineNumber; }
inline bool operator ==(const SRCCODEINFO &lhs, const SRCCODEINFO &rhs)
	{ return lhs.Address == rhs.Address; }
namespace std {
template<>struct hash<SRCCODEINFO> {
	inline size_t operator ()(const SRCCODEINFO &__x) const
  	{ return static_cast<size_t>(__x.Address); }
};
}

// ImgHelp API specific versions of parse functions
// not much updated anymore at cost of focus to DIA SDK
// (only bugs found in sibling DIA function will be fixed)
namespace ImageHlp {

static const HANDLE hProcess(reinterpret_cast<HANDLE>(0xDEADBEEF));
static HMODULE hImageHlp(NULL), hDbgHelp(NULL);
static adiff_t Delta;
static bool use_old(false); // use old method
static char download_path[QMAXPATH];

//----------------------------------------------------------------------
// Support of new debug interface
//----------------------------------------------------------------------
typedef LPAPI_VERSION (WINAPI *ImagehlpApiVersion_t)(VOID);
typedef DWORD (WINAPI *SymSetOptions_t)(IN DWORD SymOptions);
typedef BOOL (WINAPI *SymCleanup_t)(IN HANDLE hProcess);
typedef BOOL (WINAPI *SymEnumSourceFiles_t)(IN HANDLE hProcess, IN ULONG64 ModBase, IN PCSTR Mask, IN PSYM_ENUMSOURCEFILES_CALLBACK cbSrcFiles, IN PVOID UserContext);
typedef PVOID (WINAPI *SymFunctionTableAccess64_t)(HANDLE hProcess, DWORD64 AddrBase);
typedef BOOL (WINAPI *SymEnumLines_t)(IN HANDLE hProcess, IN ULONG64 Base, IN PCSTR Obj, IN PCSTR File, IN PSYM_ENUMLINES_CALLBACK EnumLinesCallback, IN PVOID UserContext);
typedef BOOL (WINAPI *SymGetLineFromAddr64_t)(IN HANDLE hProcess, IN DWORD64 qwAddr, OUT PDWORD pdwDisplacement, OUT PIMAGEHLP_LINE64 Line64);
typedef BOOL (WINAPI *SymInitialize_t)(IN HANDLE hProcess, IN PCSTR UserSearchPath, IN BOOL fInvadeProcess);
typedef DWORD64 (WINAPI *SymLoadModule64_t)(IN HANDLE hProcess, IN HANDLE hFile, IN PCSTR ImageName, IN PCSTR ModuleName, IN DWORD64 BaseOfDll, IN DWORD SizeOfDll);
typedef BOOL (WINAPI *SymUnloadModule64_t)(IN HANDLE hProcess, IN DWORD64 BaseOfDll);
typedef BOOL (WINAPI *SymSetContext_t)(HANDLE hProcess, PIMAGEHLP_STACK_FRAME StackFrame, PIMAGEHLP_CONTEXT Context);
typedef BOOL (WINAPI *SymFromAddr_t)(IN HANDLE hProcess, IN DWORD64 Address, OUT PDWORD64 Displacement, IN OUT PSYMBOL_INFO Symbol);
typedef BOOL (WINAPI *SymFromName_t)(IN HANDLE hProcess, IN PCSTR Name, OUT PSYMBOL_INFO Symbol);
typedef BOOL (WINAPI *SymEnumSymbols_t)(IN HANDLE hProcess, IN ULONG64 BaseOfDll, IN PCSTR Mask, IN PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback, IN PVOID UserContext);
typedef BOOL (WINAPI *SymEnumSymbolsForAddr_t)(IN HANDLE hProcess, IN DWORD64 Address, IN PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback, IN PVOID UserContext);
typedef BOOL (WINAPI *SymGetScope_t)(IN HANDLE hProcess, IN ULONG64 BaseOfDll, IN DWORD Index, OUT PSYMBOL_INFO Symbol);
typedef BOOL (WINAPI *SymGetTypeInfo_t)(IN HANDLE hProcess, IN DWORD64 ModBase, IN ULONG TypeId, IN IMAGEHLP_SYMBOL_TYPE_INFO GetType, OUT PVOID pInfo);
typedef BOOL (WINAPI *SymGetTypeInfoEx_t)(IN HANDLE hProcess, IN DWORD64 ModBase, IN OUT PIMAGEHLP_GET_TYPE_INFO_PARAMS Params);
typedef BOOL (WINAPI *SymEnumTypes_t)(IN HANDLE hProcess, IN ULONG64 BaseOfDll, IN PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback, IN PVOID UserContext);
typedef DBHLP_DEPRECIATED BOOL (WINAPI *SymEnumerateSymbols64_t)(IN HANDLE hProcess, IN DWORD64 BaseOfDll, IN PSYM_ENUMSYMBOLS_CALLBACK64 EnumSymbolsCallback, IN PVOID UserContext);

DECL_DYNPROC_PTR(SymSetOptions)
DECL_DYNPROC_PTR(SymInitialize)
DECL_DYNPROC_PTR(SymLoadModule64)
DECL_DYNPROC_PTR(SymEnumSymbols)
DECL_DYNPROC_PTR(SymEnumTypes)
DECL_DYNPROC_PTR(SymUnloadModule64)
DECL_DYNPROC_PTR(SymCleanup)
DECL_DYNPROC_PTR(SymGetTypeInfoEx)
DECL_DYNPROC_PTR(SymGetTypeInfo)
DECL_DYNPROC_PTR(SymEnumLines)
DECL_DYNPROC_PTR(SymFunctionTableAccess64)
DECL_DYNPROC_PTR(SymFromName)
DECL_DYNPROC_PTR(SymSetContext)
DECL_DYNPROC_PTR(SymEnumSymbolsForAddr)
DECL_DYNPROC_PTR(SymGetScope)
//DECL_DYNPROC_PTR(SymEnumerateSymbols64)
//DECL_DYNPROC_PTR(SymEnumSourceFiles)

typedef hash_map<string, map<DWORD/*LineNumber*/, hash_set<SRCCODEINFO> > > ln_t, *ln_p;
typedef class loc_t : public deque<pair<SYMBOL_INFO, string> > {
private:
	static inline sint8 cmp(const value_type &lhs, const value_type &rhs, ULONG FlagsMask)
		{ return ::cmp(lhs.first.Flags & FlagsMask, rhs.first.Flags & FlagsMask); }

public:
	static bool less(const value_type &lhs, const value_type &rhs) {
		sint8 x = cmp(lhs, rhs, SYMFLAG_PARAMETER);
		if (x != 0) return x < 0;
		x = cmp(lhs, rhs, SYMFLAG_REGISTER);
		if (x != 0) return x > 0;
		return (lhs.first.Flags & SYMFLAG_REGISTER) != 0
			&& (rhs.first.Flags & SYMFLAG_REGISTER) != 0 ?
			lhs.first.Register < rhs.first.Register :
			lhs.first.Address < rhs.first.Address;
	}
} *loc_p;

struct typeinfoex_t;

//----------------------------------------------------------------------
// Display a system error message
static void error_msg(const char *apiname) {
	const DWORD err = GetLastError();
	if (err != ERROR_SUCCESS) error_msg_base(err, apiname);
}

#if IDP_INTERFACE_VERSION >= 76

//--------------------------------------------------------------------------
// callback for parsing config file
static const char *idaapi parse_options(const char *keyword, int value_type, const void *value) {
  if (strcmp(keyword, "PDBSYM_DOWNLOAD_PATH") != 0)  return IDPOPT_BADKEY;
  if (value_type != IDPOPT_STR) return IDPOPT_BADTYPE;
  qstrcpy(download_path, static_cast<const char *>(value));
  // empty string used for ida program directory
  if (download_path[0] != 0 && !qisdir(download_path)) return IDPOPT_BADVALUE;
  return IDPOPT_OK;
}

#endif // IDP_INTERFACE_VERSION >= 76

static bool GetLocalsFor(ULONG64 Address, loc_t &locals);
// get many types version
static ULONG SymGetTypeInfoEx(PULONG TypeIds, ULONG NumIds,
	typeinfoex_t *typinfo, IMAGEHLP_GET_TYPE_INFO_PARAMS *lpgtip = 0);
// get one type version
static inline BOOL SymGetTypeInfoEx(ULONG TypeId, typeinfoex_t *typinfo,
	IMAGEHLP_GET_TYPE_INFO_PARAMS *lpgtip = 0) {
	_ASSERTE(TypeId != 0);
	return SymGetTypeInfoEx((PULONG)&TypeId, 1, typinfo, lpgtip) >= 1;
}

static tid_t CreateTypeFromPDB(const typeinfoex_t &typinfo,
	const char *parent = 0, bool accept_incomplete = false);

static string TokenizeTypeIds(PULONG TypeIds, ULONG NumIds = 1) {
	_ASSERTE(TypeIds != NULL);
	_ASSERTE(NumIds > 0);
	string s;
	if (TypeIds != NULL && NumIds > 0) for (ULONG iter = 0; iter < NumIds; ++iter)
		_sprintf_append(s, "0x%lX,", TypeIds[iter]);
	if (!s.empty()) s.erase(back_pos(s));
	return s;
}

// handled as POD-type with care
typedef __declspec(align(4)) struct typeinfoex_t {
	DWORD SymTag; // 1
	SimpleString<WCHAR, LocalAllocator<> > Name; // 2
	ULONG64 Length; // 3
	DWORD Type, TypeId, BaseType, ArrayIndexTypeId; // 7
	DWORD DataKind, AddressOffset, Offset; // 10
	CComVariant Value; // 11
	DWORD Count, ChildrenCount, BitPosition, VirtualBaseClass,
		VirtualTableShapeId, VirtualBasePointerOffset, ClassParentId,
		Nested, SymIndex, LexicalParent; // 21
	ULONG64 Address; // 22
	DWORD ThisAdjust, UDTKind, IsEquivTo, CallConv, IsCloseEquivTo; // 27
	ULONG64 ReqsValid; // 28
	DWORD VirtualBaseOffset, VirtualBaseDispIndex; // 30

public:
	typeinfoex_t() { Reset(); }
	typeinfoex_t(ULONG TypeId) {
		Reset();
		SymGetTypeInfoEx(TypeId, this);
	}
	typeinfoex_t(PSYMBOL_INFO pSymInfo) {
		Reset();
		if (pSymInfo != NULL && pSymInfo->TypeIndex != 0)
			SymGetTypeInfoEx(pSymInfo->TypeIndex, this);
	}
	typeinfoex_t(const SYMBOL_INFO &SymInfo) {
		Reset();
		if (SymInfo.TypeIndex != 0) SymGetTypeInfoEx(SymInfo.TypeIndex, this);
	}
	/*
	typeinfoex_t(const typeinfoex_t &_Other) {
		Reset();
		if (_Other.TypeId != 0) SymGetTypeInfoEx(_Other.TypeId, this);
	}
	*/

	bool operator ()(ULONG TypeId) {
		Name.Empty();
		return SymGetTypeInfoEx(TypeId, this);
	}
	bool operator ()(PSYMBOL_INFO pSymInfo) {
		Name.Empty();
		return pSymInfo != NULL && pSymInfo->TypeIndex != 0
			&& SymGetTypeInfoEx(pSymInfo->TypeIndex, this);
	}
	bool operator ()(const SYMBOL_INFO &SymInfo) {
		Name.Empty();
		return SymInfo.TypeIndex != 0 && SymGetTypeInfoEx(SymInfo.TypeIndex, this);
	}
	inline bool operator ()() const { return operator bool(); }
	inline operator bool() const { return SymIndex != 0; }
	inline bool operator ==(const typeinfoex_t &rhs) const { return SymIndex == rhs.SymIndex; }

#	define TEST_BIT_IMPL(Name, Bit) inline bool has##Name() const { \
		_ASSERTE(hasReqsValid()); \
		return (ReqsValid & 1ULL << (Bit)) != 0; \
	}
	TEST_BIT_IMPL(SymTag, 0)
	bool hasName() const {
		_ASSERTE(hasReqsValid());
		return (ReqsValid & 1ULL << 1) != 0 && static_cast<bool>(Name);
	}
	TEST_BIT_IMPL(Length, 2)
	TEST_BIT_IMPL(Type, 3)
	TEST_BIT_IMPL(TypeId, 4)
	TEST_BIT_IMPL(BaseType, 5)
	TEST_BIT_IMPL(ArrayIndexTypeId, 6)
	TEST_BIT_IMPL(DataKind, 7)
	TEST_BIT_IMPL(AddressOffset, 8)
	TEST_BIT_IMPL(Offset, 9)
	TEST_BIT_IMPL(Value, 10)
	TEST_BIT_IMPL(Count, 11)
	TEST_BIT_IMPL(ChildrenCount, 12)
	TEST_BIT_IMPL(BitPosition, 13)
	TEST_BIT_IMPL(VirtualBaseClass, 14)
	TEST_BIT_IMPL(VirtualTableShapeId, 15)
	TEST_BIT_IMPL(VirtualBasePointerOffset, 16)
	TEST_BIT_IMPL(ClassParentId, 17)
	TEST_BIT_IMPL(Nested, 18)
	TEST_BIT_IMPL(SymIndex, 19)
	TEST_BIT_IMPL(LexicalParent, 20)
	TEST_BIT_IMPL(Address, 21)
	TEST_BIT_IMPL(ThisAdjust, 22)
	TEST_BIT_IMPL(UDTKind, 23)
	TEST_BIT_IMPL(IsEquivTo, 24)
	TEST_BIT_IMPL(CallConv, 25)
	TEST_BIT_IMPL(IsCloseEquivTo, 26)
	inline bool hasReqsValid() const { return (ReqsValid & 1ULL << 27) != 0; }
	TEST_BIT_IMPL(VirtualBaseOffset, 28)
	TEST_BIT_IMPL(VirtualBaseDispIndex, 29)
#	undef TEST_BIT_IMPL

	// name extraction helpers
	int getAnsiName(char *buf, size_t bufsize) const {
		_ASSERTE(buf != 0 && bufsize > 0);
		if (buf == 0 || bufsize <= 0) return -1;
		*buf = 0;
		if (!hasName()) return 0;
		if (wcscmp(Name, UNNAMED_NAME) == 0/*boost::equals(static_cast<PCWSTR>(Name), UNNAMED_NAME)*/)
			return qsnprintf(buf, bufsize, UNNAMED_FMT, static_cast<PCWSTR>(Name), SymIndex);
		//else if (wcscmp(Name, FORMAL_NAME) == 0/*boost::equals(static_cast<PCWSTR>(Name), FORMAL_NAME)*/)
		//	return qsnprintf(buf, bufsize, FORMAL_FMT, static_cast<PCWSTR>(Name), SymIndex);
		_wcstombs(buf, Name, bufsize);
		return strlen(buf);
	}
	string getAnsiName() const {
		string result;
		if (hasName()) {
			if (wcscmp(Name, UNNAMED_NAME) == 0/*boost::equals(static_cast<PCWSTR>(Name), UNNAMED_NAME)*/)
				_sprintf(result, UNNAMED_FMT, static_cast<PCWSTR>(Name), SymIndex);
			//else if (wcscmp(Name, FORMAL_NAME) == 0/*boost::equals(static_cast<PCWSTR>(Name), FORMAL_NAME)*/)
			//	_sprintf(result, FORMAL_FMT, static_cast<PCWSTR>(Name), SymIndex);
			else {
				const size_t sz = Name.Length() + 1;
				boost::scoped_array<char> buf(new char[sz]);
				if (!buf) {
					_RPT2(_CRT_ERROR, "%s(...): failed to allocate new string of size 0x%IX\n",
						__FUNCTION__, sz);
					throw bad_alloc();
				}
				if (_wcstombs(buf.get(), Name, sz) > 0) result.assign(buf.get());
			}
		}
		return result;
	}

	// stringify meaningful values
	inline string TokenizeSymTag() const
		{ return ::TokenizeSymTag(static_cast<enum SymTagEnum>(SymTag)); }
	inline string TokenizeBasicType() const
		{ return /*SymTag == SymTagBaseType ? */::TokenizeBasicType(static_cast<enum BasicType>(BaseType))/* : "<none>"*/; }
	inline const char *TokenizeCallConv() const
		{ return /*SymTag == SymTagFunctionType ? */::TokenizeCallConv(static_cast<enum CV_call_e>(CallConv))/* : "<none>"*/; }
	inline string TokenizeDataKind() const
		{ return /*SymTag == SymTagData ? */::TokenizeDataKind(static_cast<enum DataKind>(DataKind))/* : "<none>"*/; }
	inline string TokenizeUDTKind() const
		{ return SymTag == SymTagUDT ? ::TokenizeUDTKind(static_cast<enum UdtKind>(UDTKind)) : "<none>"; }

	struct hash {
		inline size_t operator ()(const typeinfoex_t &__x) const throw()
			{ return static_cast<size_t>(__x.SymIndex); }
	};
	friend inline std::size_t hash_value(const typeinfoex_t &__x)
		{ return boost::hash_value(__x.SymIndex); }
	struct sort_by_name : public binary_function<typeinfoex_t, typeinfoex_t, bool> {
		bool operator ()(const typeinfoex_t &lhs, const typeinfoex_t &rhs) const {
			const int cmp = static_cast<bool>(lhs.Name) && static_cast<bool>(rhs.Name) ?
				wcscmp(lhs.Name, rhs.Name) : !lhs.Name && static_cast<bool>(rhs.Name) ?
				-1 : static_cast<bool>(lhs.Name) && !rhs.Name ? 1 : 0;
			return cmp < 0 || cmp == 0 && lhs.SymTag < rhs.SymTag;
		}
	};

private:
	inline void Reset() { memset(this, 0, sizeof *this); }
} *typeinfoex_p;

typedef class types_t : public boost::multi_index::multi_index_container<typeinfoex_t, boost::multi_index::indexed_by<
	/*0*/boost::multi_index::ordered_non_unique<boost::multi_index::identity<typeinfoex_t>, typeinfoex_t::sort_by_name>,
	/*1*/boost::multi_index::sequenced<>,
	/*2*/boost::multi_index::hashed_unique<boost::multi_index::identity<typeinfoex_t>, typeinfoex_t::hash>
> > {
public:
	bool Add(const_reference val) {
		if (static_cast<bool>(val.Name) && wcslen(val.Name) > 0
			&& wcscmp(val.Name, UNNAMED_NAME) != 0
			&& wcscmp(val.Name, FORMAL_NAME) != 0) {
			const iterator dupe(find(val));
			if (dupe != end()) return replace(dupe, val); // replace old versions
		}
		return get<2>().insert(val).second;
	}
	void SaveTypes() const {
		cmsg << log_prefix << "Creating types...";
		for_each(CONTAINER_RANGE(get<1>())/* pass in sequenced order */,
			boost::bind(CreateTypeFromPDB, _1, 0, false));
		cmsg << "done" << endl;
	}
} *types_p; // types_t

// get many types version
static ULONG SymGetTypeInfoEx(PULONG TypeIds, ULONG NumIds,
	typeinfoex_t *typinfo, IMAGEHLP_GET_TYPE_INFO_PARAMS *lpgtip) {
	_ASSERTE(typinfo != 0);
	_ASSERTE(NumIds > 0);
	if (typinfo == 0 || NumIds <= 0) return 0;
	for (ULONG i = 0; i < NumIds; ++i) typinfo[i].Name.Empty();
	memset(typinfo, 0, sizeof(typeinfoex_t) * NumIds);
	if (lpgtip != NULL) memset(lpgtip, 0, sizeof IMAGEHLP_GET_TYPE_INFO_PARAMS);
	_ASSERTE(TypeIds != NULL);
	if (TypeIds == NULL || pSymGetTypeInfoEx == NULL) return 0;
	static const IMAGEHLP_SYMBOL_TYPE_INFO ReqKinds[] = {
		TI_GET_SYMTAG,                                 //  1
		TI_GET_SYMNAME,                                //  2
		TI_GET_LENGTH,                                 //  3
		TI_GET_TYPE,                                   //  4
		TI_GET_TYPEID,                                 //  5
		TI_GET_BASETYPE,                               //  6
		TI_GET_ARRAYINDEXTYPEID,                       //  7
		TI_GET_DATAKIND,                               //  8
		TI_GET_ADDRESSOFFSET,                          //  9
		TI_GET_OFFSET,                                 // 10
		TI_GET_VALUE,                                  // 11
		TI_GET_COUNT,                                  // 12
		TI_GET_CHILDRENCOUNT,                          // 13
		TI_GET_BITPOSITION,                            // 14
		TI_GET_VIRTUALBASECLASS,                       // 15
		TI_GET_VIRTUALTABLESHAPEID,                    // 16
		TI_GET_VIRTUALBASEPOINTEROFFSET,               // 17
		TI_GET_CLASSPARENTID,                          // 18
		TI_GET_NESTED,                                 // 19
		TI_GET_SYMINDEX,                               // 20
		TI_GET_LEXICALPARENT,                          // 21
		TI_GET_ADDRESS,                                // 22
		TI_GET_THISADJUST,                             // 23
		TI_GET_UDTKIND,                                // 24
		TI_IS_EQUIV_TO,                                // 25
		TI_GET_CALLING_CONVENTION,                     // 26
		TI_IS_CLOSE_EQUIV_TO,                          // 27
		TI_GTIEX_REQS_VALID,                           // 28
		TI_GET_VIRTUALBASEOFFSET,                      // 29
		TI_GET_VIRTUALBASEDISPINDEX,                   // 30
	};
#	define GetStrOff(strucname, membername) ((int8 *)&strucname->membername - (int8 *)strucname)
	static const ULONG_PTR ReqOffsets[] = {
		GetStrOff(typinfo, SymTag),                    //  1
		GetStrOff(typinfo, Name),                      //  2
		GetStrOff(typinfo, Length),                    //  3
		GetStrOff(typinfo, Type),                      //  4
		GetStrOff(typinfo, TypeId),                    //  5
		GetStrOff(typinfo, BaseType),                  //  6
		GetStrOff(typinfo, ArrayIndexTypeId),          //  7
		GetStrOff(typinfo, DataKind),                  //  8
		GetStrOff(typinfo, AddressOffset),             //  9
		GetStrOff(typinfo, Offset),                    // 10
		GetStrOff(typinfo, Value),                     // 11
		GetStrOff(typinfo, Count),                     // 12
		GetStrOff(typinfo, ChildrenCount),             // 13
		GetStrOff(typinfo, BitPosition),               // 14
		GetStrOff(typinfo, VirtualBaseClass),          // 15
		GetStrOff(typinfo, VirtualTableShapeId),       // 16
		GetStrOff(typinfo, VirtualBasePointerOffset),  // 17
		GetStrOff(typinfo, ClassParentId),             // 18
		GetStrOff(typinfo, Nested),                    // 19
		GetStrOff(typinfo, SymIndex),                  // 20
		GetStrOff(typinfo, LexicalParent),             // 21
		GetStrOff(typinfo, Address),                   // 22
		GetStrOff(typinfo, ThisAdjust),                // 23
		GetStrOff(typinfo, UDTKind),                   // 24
		GetStrOff(typinfo, IsEquivTo),                 // 25
		GetStrOff(typinfo, CallConv),                  // 26
		GetStrOff(typinfo, IsCloseEquivTo),            // 27
		GetStrOff(typinfo, ReqsValid),                 // 28
		GetStrOff(typinfo, VirtualBaseOffset),         // 29
		GetStrOff(typinfo, VirtualBaseDispIndex),      // 30
	};
#	undef GetStrOff
	static const ULONG ReqSizes[] = {
		sizeof(typinfo->SymTag),                       //  1
		sizeof(typinfo->Name),                         //  2
		sizeof(typinfo->Length),                       //  3
		sizeof(typinfo->Type),                         //  4
		sizeof(typinfo->TypeId),                       //  5
		sizeof(typinfo->BaseType),                     //  6
		sizeof(typinfo->ArrayIndexTypeId),             //  7
		sizeof(typinfo->DataKind),                     //  8
		sizeof(typinfo->AddressOffset),                //  9
		sizeof(typinfo->Offset),                       // 10
		sizeof(typinfo->Value),                        // 11
		sizeof(typinfo->Count),                        // 12
		sizeof(typinfo->ChildrenCount),                // 13
		sizeof(typinfo->BitPosition),                  // 14
		sizeof(typinfo->VirtualBaseClass),             // 15
		sizeof(typinfo->VirtualTableShapeId),          // 16
		sizeof(typinfo->VirtualBasePointerOffset),     // 17
		sizeof(typinfo->ClassParentId),                // 18
		sizeof(typinfo->Nested),                       // 19
		sizeof(typinfo->SymIndex),                     // 20
		sizeof(typinfo->LexicalParent),                // 21
		sizeof(typinfo->Address),                      // 22
		sizeof(typinfo->ThisAdjust),                   // 23
		sizeof(typinfo->UDTKind),                      // 24
		sizeof(typinfo->IsEquivTo),                    // 25
		sizeof(typinfo->CallConv),                     // 26
		sizeof(typinfo->IsCloseEquivTo),               // 27
		sizeof(typinfo->ReqsValid),                    // 28
		sizeof(typinfo->VirtualBaseOffset),            // 29
		sizeof(typinfo->VirtualBaseDispIndex),         // 30
	};
	//ULONG64 ReqsValid;
	IMAGEHLP_GET_TYPE_INFO_PARAMS gtip;
	try {
		memset(&gtip, 0, sizeof gtip);
		gtip.SizeOfStruct = sizeof gtip;
		gtip.Flags = 0; //IMAGEHLP_GET_TYPE_INFO_UNCACHED
		gtip.NumIds = NumIds;
		gtip.TypeIds = TypeIds;
		gtip.TagFilter = ((ULONG64)1 << SymTagMax) - 1;
		gtip.NumReqs = qnumber(ReqKinds);
		gtip.ReqKinds = (IMAGEHLP_SYMBOL_TYPE_INFO *)ReqKinds;
		gtip.ReqOffsets = (PULONG_PTR)ReqOffsets;
		gtip.ReqSizes = (PULONG)ReqSizes;
		gtip.ReqStride = sizeof typeinfoex_t;
		gtip.BufferSize = sizeof(typeinfoex_t) * NumIds;
		gtip.Buffer = typinfo;
		//gtip.ReqsValid = &ReqsValid;
		//gtip.NumReqsValid = sizeof ReqsValid;
		pSymGetTypeInfoEx(hProcess, SymBase, &gtip);
	} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
			"%s(..., %lu, ...): %s in %s::SymGetTypeInfoEx(...) diagnostics info: TypeIds={%s} NumIds=%lu\n",
				__FUNCTION__, NumIds, e.what(), DBGHELP_DLL, TokenizeTypeIds(TypeIds, NumIds).c_str(), NumIds, typeid(e).name());
#endif // _DEBUG
	}
	if (lpgtip != NULL) *lpgtip = gtip;
#ifdef _DEBUG
// 	if (gtip.EntriesFilled == 0)
// 		_RPT4(_CRT_WARN, "%s(..., %lu, ...): %s::SymGetTypeInfoEx(...) returned 0 (TypeIds={%s})\n",
// 			__FUNCTION__, NumIds, DBGHELP_DLL, TokenizeTypeIds(TypeIds, NumIds).c_str());
// 	else if (gtip.EntriesFilled < NumIds)
// 		_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
// 			"%s(..., %lu, ...): %s::SymGetTypeInfoEx(...) returned %i (TypeIds={%s})\n",
// 			__FUNCTION__, NumIds, DBGHELP_DLL, gtip.EntriesFilled, TokenizeTypeIds(TypeIds, NumIds).c_str());
#endif // _DEBUG
	return gtip.EntriesFilled;
}

class childrenex_t : public boost::scoped_array<typeinfoex_t> {
public:
	childrenex_t(const typeinfoex_t &typinfo,
		IMAGEHLP_GET_TYPE_INFO_PARAMS *pgtip = NULL) { load(typinfo, pgtip); }

	bool load(const typeinfoex_t &typinfo,
		IMAGEHLP_GET_TYPE_INFO_PARAMS *pgtip = NULL) throw(exception) {
		reset();
		_ASSERTE(typinfo.SymIndex != 0);
		_ASSERTE(typinfo.ChildrenCount > 0);
		if (typinfo.SymIndex == 0 || typinfo.ChildrenCount == 0) return false;
		const size_t sz = sizeof TI_FINDCHILDREN_PARAMS +
			(typinfo.ChildrenCount - 1) * sizeof(ULONG);
		boost::shared_crtptr<TI_FINDCHILDREN_PARAMS> fchp(sz);
		if (!fchp)  {
			_RPT2(_CRT_ERROR, "%s(...): malloc(0x%IX) returned NULL\n", __FUNCTION__, sz);
			throw bad_alloc(); //return;
		}
		memset(fchp.get(), 0, sz);
		fchp->Count = typinfo.ChildrenCount;
		fchp->Start = 0;
		if (pSymGetTypeInfo(hProcess, SymBase, typinfo.SymIndex, TI_FINDCHILDREN, fchp.get()) == FALSE) {
			_RPT2(_CRT_WARN, "%s(...): SymGetTypeInfo(..., 0x%lX, TI_FINDCHILDREN, ...) returned FALSE\n",
				__FUNCTION__, typinfo.SymIndex);
			return false;
		}
		reset(new typeinfoex_t[typinfo.ChildrenCount]);
		if (operator !()) {
			_RPT2(_CRT_ERROR, "%s(...): new typeinfoex_t[%lu] returned NULL\n",
				__FUNCTION__, typinfo.ChildrenCount);
			throw bad_alloc(); //return;
		}
		ULONG count = SymGetTypeInfoEx(fchp->ChildId, fchp->Count, get(), pgtip);
		if (count <= 0) reset();
		return operator unspecified_bool_type();
	}
};

#ifdef _DEBUG

#define IS_BOOL_PRESENT(x) if (typinfo.x != FALSE) oss << " " #x;
#define IS_INT_PRESENT(x) if (typinfo.x != 0) oss << " " #x "=" << ashex(typinfo.x);

static void PrintTypeInfoEx(const typeinfoex_t &typinfo,
	const IMAGEHLP_GET_TYPE_INFO_PARAMS *pgtip, uint indent,
	bool recursive, hash_set<DWORD> &path) {
	_ASSERTE(typinfo.SymIndex != 0);
	if (typinfo.SymIndex == 0) return; // invalid
	ostringstream oss;
	if (indent > 0) oss << string(indent << 1, ' ');
	oss << "SymId " << ashex(typinfo.SymIndex) << ": SymTag=" << typinfo.TokenizeSymTag();
	if (typinfo.Name) oss << " Name=\"" << (PCWSTR)typinfo.Name << '\"';
	IS_INT_PRESENT(Type)
	IS_INT_PRESENT(TypeId)
	//if (typinfo.LocationType != LocIsNull) oss << " LocationType=" << typinfo.TokenizeLocationType();
	if (/*typinfo.SymTag == SymTagFunction || typinfo.SymTag == SymTagBlock
		|| typinfo.SymTag == SymTagData || typinfo.SymTag == SymTagFuncDebugStart
		|| typinfo.SymTag == SymTagFuncDebugEnd || typinfo.SymTag == SymTagLabel
		|| typinfo.SymTag == SymTagPublicSymbol || typinfo.SymTag == SymTagThunk/*
		|| typinfo.LocationType == LocIsStatic || typinfo.LocationType == LocIsTLS
		|| */typinfo.AddressOffset != 0 || typinfo.hasAddressOffset())
		oss << " AddressOffset=" << ashex(typinfo.AddressOffset, (streamsize)8);
	if (/*typinfo.SymTag == SymTagFunction || typinfo.SymTag == SymTagBlock
		|| typinfo.SymTag == SymTagData || typinfo.SymTag == SymTagFuncDebugStart
		|| typinfo.SymTag == SymTagFuncDebugEnd || typinfo.SymTag == SymTagLabel
		|| typinfo.SymTag == SymTagPublicSymbol || typinfo.SymTag == SymTagThunk
		|| */typinfo.Address != 0 || typinfo.hasAddress())
		oss << " Address=" << ashex(typinfo.Address, (streamsize)16);
	if (/*typinfo.SymTag == SymTagBlock || typinfo.SymTag == SymTagFunction
		|| typinfo.SymTag == SymTagThunk || typinfo.SymTag == SymTagArrayType
		|| typinfo.SymTag == SymTagBaseType || typinfo.SymTag == SymTagPointerType
		|| typinfo.SymTag == SymTagUDT || */typinfo.Length > 0
		|| typinfo.hasLength()) oss << " Length=" << ashex(typinfo.Length);
	if (typinfo.SymTag == SymTagData || typinfo.DataKind != DataIsUnknown)
		oss << " DataKind=" << typinfo.TokenizeDataKind();
	if (typinfo.SymTag == SymTagBaseType || typinfo.BaseType != btNoType)
		oss << " BaseType=" << typinfo.TokenizeBasicType();
	if (/*typinfo.SymTag == SymTagUDT || typinfo.SymTag == SymTagEnum
		|| typinfo.SymTag == SymTagFunctionType || */typinfo.ChildrenCount > 0
		|| typinfo.hasChildrenCount()) oss << " ChildrenCount=" << dec << typinfo.ChildrenCount;
	if (typinfo.SymTag == SymTagUDT) oss << " UDTKind=" << typinfo.TokenizeUDTKind();
	if (typinfo.SymTag == SymTagFunctionType) oss << " CallingConvention=" << typinfo.TokenizeCallConv();
	if (/*typinfo.SymTag == SymTagArrayType || typinfo.SymTag == SymTagFunctionType
		|| typinfo.SymTag == SymTagVTableShape || */typinfo.Count > 0
		|| typinfo.hasCount()) oss << " Count=" << dec << typinfo.Count;
	if (typinfo.SymTag == SymTagArrayType || typinfo.ArrayIndexTypeId != 0)
		oss << " ArrayIndexTypeId=" << ashex(typinfo.ArrayIndexTypeId);
	if (/*typinfo.SymTag == SymTagBaseClass || */typinfo.Offset != 0
		|| typinfo.hasOffset()) oss << " Offset=" << ashex(typinfo.Offset);
	if (typinfo.SymTag == SymTagData && typinfo.DataKind == DataIsConstant
		|| /*typinfo.SymTag == SymTagCompilandEnv
		|| */typinfo.hasValue()) oss << " Value=" << TokenizeVariant(typinfo.Value);
	if (/*typinfo.SymTag == SymTagData || */typinfo.BitPosition != 0
		|| typinfo.hasBitPosition()) oss << " BitPosition=" << dec << typinfo.BitPosition;
	IS_BOOL_PRESENT(VirtualBaseClass)
	if (typinfo.VirtualBaseOffset != 0 || typinfo.hasVirtualBaseOffset())
		oss << " VirtualBaseOffset=" << ashex(typinfo.VirtualBaseOffset);
	if (typinfo.VirtualTableShapeId != 0 || typinfo.hasVirtualTableShapeId())
		oss << " VirtualTableShapeId=" << ashex(typinfo.VirtualTableShapeId);
	if (/*typinfo.SymTag == SymTagBaseClass || */typinfo.VirtualBaseDispIndex != 0
		|| typinfo.hasVirtualBaseDispIndex())
		oss << " VirtualBaseDispIndex=" << ashex(typinfo.VirtualBaseDispIndex);
	if (/*typinfo.SymTag == SymTagBaseClass || */typinfo.VirtualBasePointerOffset != 0
		|| typinfo.hasVirtualBasePointerOffset())
		oss << " VirtualBasePointerOffset=" << asshex(typinfo.VirtualBasePointerOffset);
	if (typinfo.ClassParentId != 0 || typinfo.hasClassParentId())
		oss << " ClassParentId=" << ashex(typinfo.ClassParentId);
	IS_BOOL_PRESENT(Nested)
	if (typinfo.LexicalParent != 0 || typinfo.hasLexicalParent())
		oss << " LexicalParent=" << ashex(typinfo.LexicalParent);
	if (/*typinfo.SymTag == SymTagFunctionType || */typinfo.ThisAdjust != 0
		|| typinfo.hasThisAdjust()) oss << " ThisAdjust=" << asshex(typinfo.ThisAdjust);
	if (typinfo.hasIsEquivTo())
		if (typinfo.IsEquivTo == S_OK)
			oss << " IsEquivTo=" << "S_OK";
		else if (typinfo.IsEquivTo == S_FALSE)
			oss << " IsEquivTo=" << "S_FALSE";
	if (typinfo.hasIsCloseEquivTo())
		if (typinfo.IsCloseEquivTo == S_OK)
			oss << " IsCloseEquivTo=" << "S_OK";
		else if (typinfo.IsCloseEquivTo == S_FALSE)
			oss << " IsCloseEquivTo=" << "S_FALSE";
	oss << " ReqsValid=" << ashex(typinfo.ReqsValid, (streamsize)16);
	if (pgtip != 0) {
		oss << " EntriesMatched=" << ashex(pgtip->EntriesMatched, (streamsize)8);
		oss << " EntriesFilled=" << ashex(pgtip->EntriesFilled, (streamsize)8);
		oss << " TagsFound=" << ashex(pgtip->TagsFound, (streamsize)16);
		oss << " AllReqsValid=" << ashex(pgtip->AllReqsValid, (streamsize)16);
		oss << " NumReqsValid=" << dec << pgtip->NumReqsValid;
		//oss << " ReqsValid=" << ashex(pgtip->ReqsValid, (streamsize)16);
	}
	oss << endl;
	OutputDebugStringA(oss.str().c_str());
	if (!recursive || path.find(typinfo.SymIndex) != path.end()) return;
	/*hash_set<DWORD>::iterator iter(*/path.insert(typinfo.SymIndex).first/*)*/;
	typeinfoex_t basetype;
	IMAGEHLP_GET_TYPE_INFO_PARAMS gtip;
	// print sub-types
	if (typinfo.TypeId != 0
		&& SymGetTypeInfoEx(typinfo.TypeId, &basetype, pgtip != NULL ? &gtip : NULL)) {
		PrintTypeInfoEx(basetype, pgtip != NULL ? &gtip : NULL, indent + 1, true, path);
		basetype.Name.Empty();
	}
	if (typinfo.SymTag == SymTagArrayType && typinfo.ArrayIndexTypeId != 0
		&& SymGetTypeInfoEx(typinfo.ArrayIndexTypeId, &basetype, pgtip != NULL ? &gtip : NULL)) {
		PrintTypeInfoEx(basetype, pgtip != NULL ? &gtip : NULL, indent + 1, true, path);
		basetype.Name.Empty();
	}
	// print children
	if (typinfo.ChildrenCount > 0) try {
		childrenex_t children(typinfo, pgtip != NULL ? &gtip : NULL);
		if (children) for (ULONG index = 0; index < typinfo.ChildrenCount; ++index) {
			if (children[index].SymIndex != 0)
				PrintTypeInfoEx(children[index], pgtip != NULL ? &gtip : NULL, indent + 1, true, path);
			//children[index].Name.Empty();
		}
	} catch (GENERAL_CATCH_FILTER) {
		_RPTF2(_CRT_ERROR, "%s(...): %s\n", __FUNCTION__, e.what());
	}
	//path.erase(iter);
}
static void PrintTypeInfoEx(const typeinfoex_t &typinfo,
	const IMAGEHLP_GET_TYPE_INFO_PARAMS *pgtip = NULL,
	uint indent = 1, bool recursive = true) {
	PrintTypeInfoEx(typinfo, pgtip, indent, recursive,
#ifdef PRINT_TYPE_ONCE
		printed_types
#else
		hash_set<DWORD>()
#endif
	);
}

#else // !_DEBUG
#define PrintTypeInfoEx __noop
#endif // _DEBUG

static flags_t getFlags(const typeinfoex_t &typinfo) {
	_ASSERTE(typinfo.SymIndex != 0);
	if (typinfo.SymIndex == 0) return 0; // not valid typeinfo
	flags_t flags(0);
	typeinfoex_t basetype;
	switch (typinfo.SymTag) {
		case SymTagBaseType:
			switch (typinfo.BaseType) {
				case btNoType:
				case btVoid:
					break;
				case btChar:
				case btWChar:
					flags = getDataFlagsByLength(typinfo.Length) | charflag();
					break;
				case btInt:
				case btUInt:
				case btLong:
				case btULong:
				case btBit: // ???
					flags = getDataFlagsByLength(typinfo.Length) | numflag();
					break;
				case btFloat:
					flags = fltflag();
					switch (typinfo.Length) {
						case 4: flags |= floatflag(); break;
						case 8: flags |= doubleflag(); break;
						default:
							if (typinfo.Length == ph.tbyte_size) {
								flags |= tbytflag()/*packrealflag()??*/; // should best correspond to ida's BTMT_LNGDBL type
								break;
							}
							flags |= getDataFlagsByLength(typinfo.Length);
							_RPTF2(_CRT_WARN, "%s(...): unexpected size for btFloat base type (0x%I64X), defaulting to general float type\n",
								__FUNCTION__, typinfo.Length);
					}
					break;
				case btBool:
				default:
					flags = getDataFlagsByLength(typinfo.Length);
			}
			_ASSERTE(typinfo.TypeId == 0); // base type cannot have supertypes
			return flags;
		case SymTagPointerType:
			return ptrflag();
		case SymTagArrayType:
			_ASSERTE(typinfo.TypeId != 0);
			if (typinfo.TypeId != 0 && basetype(typinfo.TypeId)) {
				if (basetype.SymTag == SymTagBaseType && (basetype.BaseType == btChar
					|| basetype.BaseType == btWChar/* || basetype.BaseType == btInt
					&& (basetype.Length == 1 || basetype.Length == 2)*/)) return asciflag();
				basetype.Name.Empty();
			}
			break;
		case SymTagEnum:
			return getDataFlagsByLength(typinfo.Length) | enumflag();
		case SymTagUDT:
			return struflag();
		case SymTagFunction:
			return FF_CODE | FF_FUNC;
		case SymTagFunctionType:
			return 0;
	}
	if (typinfo.TypeId != 0 && basetype(typinfo.TypeId)) {
		flags |= getFlags(basetype);
		basetype.Name.Empty();
	}
	return flags;
}

static typeinfo_t *get_typeinfo(const typeinfoex_t &typinfo,
	typeinfo_t &ti, ea_t ea = BADADDR) {
	if (is_extern(ea)) { // externs are always pointers
		ti.ri.target = BADADDR;
		ti.ri.base = 0;
		ti.ri.tdelta = 0;
#if IDP_INTERFACE_VERSION < 76
		ti.ri.type = get_default_reftype(ea != BADADDR ? ea : inf.minEA);
		ti.ri.target_present = false;
#else // IDP_INTERFACE_VERSION >= 76
		ti.ri.set_type(get_default_reftype(ea != BADADDR ? ea : inf.minEA));
#endif
		return &ti;
	}
	_ASSERTE(typinfo.SymIndex != 0);
	if (typinfo.SymIndex == 0) return 0;
	typeinfoex_t basetype;
	switch (typinfo.SymTag) {
#ifdef _DEBUG
		case SymTagBaseType:
			_ASSERTE(typinfo.TypeId == 0); // base type cannot have supertype
			break;
#endif // _DEBUG
		case SymTagPointerType:
			//if (ea == BADADDR) return 0;
			ti.ri.target = BADADDR;
			ti.ri.base = 0;
			ti.ri.tdelta = 0;
#if IDP_INTERFACE_VERSION < 76
			ti.ri.type = get_default_reftype(ea != BADADDR ? ea : inf.minEA);
			ti.ri.target_present = false;
#else // IDP_INTERFACE_VERSION >= 76
			ti.ri.set_type(get_default_reftype(ea != BADADDR ? ea : inf.minEA));
#endif
			return &ti;
		case SymTagEnum:
			if ((ti.ec.tid = CreateTypeFromPDB(typinfo, 0, true)) != BADNODE) {
				if (ti.ec.tid == 0) ti.ec.tid = BADNODE;
				ti.ec.serial = 0;
				return &ti;
			}
			_RPTF4(_CRT_WARN, "%s(...): cannot get %s of %s %-.3840ls, returning NULL\n",
				__FUNCTION__, "enum_t", "enum", static_cast<PCWSTR>(typinfo.Name));
			return 0;
		case SymTagUDT:
			if ((ti.tid = CreateTypeFromPDB(typinfo, 0, true)) != BADNODE) {
				if (ti.tid == 0) ti.tid = BADNODE;
				return &ti;
			}
			_RPTF4(_CRT_WARN, "%s(...): cannot get %s of %s %-.3840ls, returning NULL\n",
				__FUNCTION__, "tid_t", "struct", static_cast<PCWSTR>(typinfo.Name));
			return 0;
		case SymTagArrayType:
			_ASSERTE(typinfo.TypeId != 0);
			if (typinfo.TypeId != 0 && basetype(typinfo.TypeId)) {
				if (basetype.SymTag == SymTagBaseType) switch (basetype.BaseType) {
					case btChar:
						ti.strtype = ASCSTR_C;
						return &ti;
					case btWChar:
						ti.strtype = ASCSTR_UNICODE;
						return &ti;
					/*
					// unsure when real c-string and when binary byte array
					case btInt:
						if (basetype.Length == 1) {
							ti.strtype = ASCSTR_C;
							return &ti;
						}
						if (basetype.Length == 2) {
							ti.strtype = ASCSTR_UNICODE;
							return &ti;
						}
						break;
					*/
				}
			}
			break;
		//case SymTagData: break;
		case SymTagFunction:
		case SymTagFunctionType:
		case SymTagFunctionArgType:
			return 0;
	}
	return typinfo.TypeId != 0 && basetype(typinfo.TypeId) ?
		get_typeinfo(basetype, ti, ea) : 0;
}

// doubtful usage
static ULONG64 get_type_size(const typeinfoex_t &typinfo) {
	_ASSERTE(typinfo.SymIndex != 0);
	if (typinfo.SymIndex == 0) return 0;
	if (typinfo.Length > 0 && !typinfo.hasBitPosition()
		&& typinfo.BitPosition == 0) return typinfo.Length;
	typeinfoex_t basetype;
	for (ULONG TypeId = typinfo.TypeId; TypeId != 0 && basetype(TypeId); TypeId = basetype.TypeId)
		if (basetype.Length > 0 && !basetype.hasBitPosition()
			&& basetype.BitPosition == 0) return basetype.Length;
	//_RPTF1(_CRT_WARN, "%s(...): couldnot reach subtype with valid size\n", __FUNCTION__);
	return 0;
}

// translate typeinfo from PDB -> type_t[] string
// this function may produce not_convertible exception when type can't be
// exactly translated to type_t[] chain, however no validity checks on referred
// subtypes presence are performed, thus result may be claimed as invalid by IDA
// returns true if some typeinfo was generated
static bool get_ti(const typeinfoex_t &typinfo, typestring &type,
	plist *pfnames = 0, loc_p plocals = 0, bool accept_incomplete = false) throw(not_convertible) {
	type.clear();
	if (pfnames != 0) pfnames->clear();
	_ASSERTE(typinfo.SymIndex != 0);
	if (typinfo.SymIndex == 0) return false;
	try {
		typestring loctype;
		typestring::value_type t;
		typeinfoex_t basetype;
		string fullname; //char name[MAXSTR/*MAXNAMESIZE*/]; // care size !!
		bool use_accept_incomplete(false);
		switch (typinfo.SymTag) {
			case SymTagNull:
				return false;
			case SymTagBaseType:
				switch (typinfo.BaseType) {
					case btNoType:
						//type << BT_UNK;
						break;
					case btVoid:
						_ASSERTE(typinfo.Length == 0);
						type << BTF_VOID;
						break;
					case btChar:
						_ASSERTE(typinfo.Length == 1);
						type << (BT_INT8 | BTMT_CHAR);
						break;
					case btWChar:
						_ASSERTE(typinfo.Length == 2);
						type << (BT_INT16/* | BTMT_CHAR*/);
						break;
					case btUInt:
						type << (BTMT_USIGNED | get_int_type_bit(typinfo.Length));
// 						switch (typinfo.Length) {
// 							case 1: type << (BT_INT8 | BTMT_USIGNED/* | BTMT_CHAR*/); break;
// 							case 2: type << (BT_INT16 | BTMT_USIGNED); break;
// 							case 4: type << (BT_INT32 | BTMT_USIGNED); break;
// 							case 8: type << (BT_INT64 | BTMT_USIGNED); break;
// 							case 16: type << (BT_INT128 | BTMT_USIGNED); break;
// 							default:
// 								type << (BT_INT | BTMT_USIGNED);
// #ifdef _DEBUG
// 								_RPTF2(_CRT_WARN, "%s(...): unexpected uint type size (0x%I64X)\n",
// 									__FUNCTION__, typinfo.Length);
// 								PrintTypeInfoEx(typinfo);
// #endif // _DEBUG
// 						}
						break;
					case btInt:
						type << (/*BTMT_SIGNED | */get_int_type_bit(typinfo.Length));
						/*
						switch (typinfo.Length) {
							case 1: type << (BT_INT8 | BTMT_CHAR); break;
							case 2: type << BT_INT16; break;
							case 4: type << BT_INT32; break;
							case 8: type << BT_INT64; break;
							case 16: type << BT_INT128; break;
							default:
								type << BT_INT;
								_RPTF2(_CRT_WARN, "%s(...): unexpected int type size (0x%I64X)\n",
									__FUNCTION__, typinfo.Length);
								PrintTypeInfoEx(typinfo);
						}
						*/
						break;
					case btLong:
						_ASSERTE(typinfo.Length == 4);
						type << BT_INT32;
						break;
					case btULong:
						_ASSERTE(typinfo.Length == 4);
						type << (BT_INT32 | BTMT_USIGNED);
						break;
					case btFloat:
						t = BT_FLOAT;
						switch (typinfo.Length) {
							case 2: t |= BTMT_SHRTFLT; break;
							case 4: t |= BTMT_FLOAT; break;
							case 8: t |= BTMT_DOUBLE; break;
							default:
								if (typinfo.Length == ph.tbyte_size) {
									t |= BTMT_LNGDBL;
									break;
								}
#ifdef _DEBUG
								_RPTF2(_CRT_WARN, "%s(...): unexpected float type size (0x%I64X)\n",
									__FUNCTION__, typinfo.Length);
								PrintTypeInfoEx(typinfo);
#endif // _DEBUG
						}
						type << t;
						break;
					case btBool:
						t = BT_BOOL;
						switch (typinfo.Length) {
							case 1: t |= BTMT_BOOL1; break;
							case 2: t |= BTMT_BOOL2; break;
							case 4: t |= BTMT_BOOL4; break;
							default:
								t |= BTMT_DEFBOOL;
								_RPTF2(_CRT_WARN, "%s(...): unexpected bool type size (0x%I64X)\n",
									__FUNCTION__, typinfo.Length);
								PrintTypeInfoEx(typinfo);
						}
						type << t;
						break;
					case btBCD: // ???
						type << tdef("BCD");
						break;
					case btCurrency: // ?
						CreateCURRENCY();
						type << tdef("CURRENCY");
						break;
					case btDate: // ?
						CreateDATE();
						type << tdef("DATE");
						break;
					case btVariant:
						type << tdef("VARIANT");
						break;
					case btComplex: // ??
						type << tdef("_complex");
						break;
					case btBit: // bitfield ??
						type << BT_BITFIELD << (2 & BTE_SIZE_MASK | BTE_HEX & BTE_OUT_MASK); // !!!!
						break;
					case btBSTR:
						CreateBSTR();
						type << tdef("BSTR");
						break;
					case btHresult:
						CreateHRESULT();
						type << tdef("HRESULT");
						break;
#ifdef _DEBUG
					default:
						_RPTF2(_CRT_WARN, "%s(...): unexpected BaseType value: 0x%lX\n",
							__FUNCTION__, typinfo.BaseType);
						PrintTypeInfoEx(typinfo);
#endif // _DEBUG
				} // switch typinfo.BaseType
				_ASSERTE(typinfo.TypeId == 0);
				return !type.empty();
			case SymTagArrayType:
				if (typinfo.Count <= MAX_DT)
					type << (BT_ARRAY | BTMT_NONBASED) << dt(typinfo.Count);
				else
					type << BT_ARRAY << da(typinfo.Count);
				break;
			case SymTagPointerType:
				type << (BT_PTR | BTMT_DEFPTR);
				use_accept_incomplete = true;
				break;
			case SymTagUDT:
				_ASSERTE(typinfo.hasName());
				if (typinfo.hasName() && !fullname.assign(typinfo.getAnsiName()).empty()) {
					if (CreateTypeFromPDB(typinfo, 0, accept_incomplete) == BADNODE)
						throw fmt_exception("%s \"%s\" couldnot be created", "UDT", fullname.c_str());
					if (!is_named_type(fullname.c_str())) {
						//_RPTF3(_CRT_WARN, "%s(...): %s(\"%s\") returned false\n",
						//	__FUNCTION__, "is_named_type", fullname.c_str());
						throw fmt_exception("%s \"%s\" not accessible by true name", "UDT", fullname.c_str());
					}
					switch (typinfo.UDTKind) {
						case UdtStruct:
							t = BTF_STRUCT;
							break;
						case UdtUnion:
							t = BTF_UNION;
							break;
						default:
							t = BT_COMPLEX; // class or unknown
							_RPTF2(_CRT_WARN, "%s(...): unsupported UDT type by ida typeinfo: %s\n",
								__FUNCTION__, typinfo.TokenizeUDTKind().c_str());
							//throw fmt_exception("unsupported UDT type by ida typeinfo: %s",
							//	typinfo.TokenizeUDTKind().c_str());
					}
					type << t << dt(0) << pstring(fullname);
				} else
					__stl_throw_invalid_argument("cannot get UDT name: name is missing, too long, or cannot be converted to ansi");
				return !type.empty();
			case SymTagEnum:
				_ASSERTE(typinfo.hasName());
				if (typinfo.hasName() && !fullname.assign(typinfo.getAnsiName()).empty()) {
					if (CreateTypeFromPDB(typinfo, 0, accept_incomplete) == BADNODE)
						throw fmt_exception("%s \"%s\" couldnot be created", "enum", fullname.c_str());
					if (!is_named_type(fullname.c_str())) {
						//_RPTF3(_CRT_WARN, "%s(...): %s(\"%s\") returned false\n",
						//	__FUNCTION__, "is_named_type", fullname.c_str());
						throw fmt_exception("%s \"%s\" not accessible by true name", "enum", fullname.c_str());
					}
					type << BTF_ENUM << dt(0) << pstring(fullname);
				} else
					__stl_throw_invalid_argument("cannot get enum name: name is missing, too long, or cannot be converted to ansi");
				return !type.empty();
			case SymTagTypedef:
				_ASSERTE(typinfo.hasName());
				if (typinfo.hasName() && !fullname.assign(typinfo.getAnsiName()).empty()) {
					if (CreateTypeFromPDB(typinfo, 0, accept_incomplete) == BADNODE)
						throw fmt_exception("%s \"%s\" couldnot be created", "typedef", fullname.c_str());
					if (!is_named_type(fullname.c_str())) {
						//_RPTF3(_CRT_WARN, "%s(...): %s(\"%s\") returned false\n",
						//	__FUNCTION__, "is_named_type", fullname.c_str());
						throw fmt_exception("%s \"%s\" not accessible by true name", "typedef", fullname.c_str());
					}
					type << tdef(fullname);
				} else
					__stl_throw_invalid_argument("cannot get typedef name: name is missing, too long, or cannot be converted to ansi");
				return !type.empty();
			case SymTagFunctionType: {
				// _PVFV: Index=0x107 TypeIndex=0x107 Value=0x0 Tag=Typedef ModBase=0000000000400000
				//   SymId 0x107: Tag=Typedef Name=_PVFV Type=0x10 TypeId=0x10 Offset=0x0 SymIndex=0x107 LexicalParent=0x5 ReqsValid=000000000018001B
				//     SymId 0x10: Tag=PointerType Length=0x4 Type=0xA TypeId=0xA Offset=0x0 SymIndex=0x10 LexicalParent=0x5 ReqsValid=000000000018101D
				//       SymId 0xA: Tag=FunctionType Type=0xB TypeId=0xB Offset=0x0 SymIndex=0xA LexicalParent=0x5 CallConv=CDeclNear ReqsValid=0000000002181819
				//         SymId 0xB: Tag=BaseType BaseType=Void Offset=0x0 SymIndex=0xB LexicalParent=0x5 ReqsValid=0000000000181025
				t = BT_FUNC;
				switch (typinfo.CallConv) {
					case CV_CALL_NEAR_C:
					case CV_CALL_NEAR_STD:
					case CV_CALL_NEAR_FAST:
					case CV_CALL_NEAR_PASCAL:
					case CV_CALL_NEAR_SYS:
						t |= BTMT_NEARCALL;
						break;
					case CV_CALL_FAR_C:
					case CV_CALL_FAR_STD:
					case CV_CALL_FAR_FAST:
					case CV_CALL_FAR_PASCAL:
					case CV_CALL_FAR_SYS:
						t |= BTMT_FARCALL;
						break;
				}
				cm_t cm;
				switch (typinfo.CallConv) {
					case CV_CALL_NEAR_C:
					case CV_CALL_FAR_C:
						cm = CM_CC_CDECL;
						break;
					case CV_CALL_NEAR_STD:
					case CV_CALL_FAR_STD:
						cm = CM_CC_STDCALL;
						break;
					case CV_CALL_NEAR_FAST:
					case CV_CALL_FAR_FAST:
						cm = CM_CC_FASTCALL;
						break;
					case CV_CALL_NEAR_SYS:
					case CV_CALL_FAR_SYS:
						cm = CM_CC_STDCALL; // care!!
						break;
					case CV_CALL_NEAR_PASCAL:
					case CV_CALL_FAR_PASCAL:
						cm = CM_CC_PASCAL;
						break;
					case CV_CALL_THISCALL:
						cm = CM_CC_THISCALL;
						break;
					case CV_CALL_GENERIC:
						cm = get_cc(inf.cc.cm);
						break;
					/*
					case CV_CALL_MIPSCALL:
					case CV_CALL_ALPHACALL:
					case CV_CALL_PPCCALL:
					case CV_CALL_SHCALL:
					case CV_CALL_ARMCALL:
					case CV_CALL_AM33CALL:
					case CV_CALL_TRICALL:
					case CV_CALL_SH5CALL:
					case CV_CALL_M32RCALL:
					*/
					default:
						cm = CM_CC_UNKNOWN;
						_RPTF2(_CRT_WARN, "%s(...): unhandled calling convention: %s, defaulting to CM_CC_UNKNOWN\n",
							__FUNCTION__, typinfo.TokenizeCallConv());
				}
				elem_t rtype;
				_ASSERTE(typinfo.TypeId != 0);
				if (typinfo.TypeId != 0 && basetype(typinfo.TypeId)) {
					if (!get_ti(basetype, rtype.type, 0, plocals)) {
						//rtype.type << BT_UNKNOWN;
						_RPTF1(_CRT_WARN, "%s(...): couldnot build result type\n", __FUNCTION__);
						PrintTypeInfoEx(basetype);
						throw logic_error("no type for result or unknown type");
					}
					basetype.Name.Empty();
				} else {
					//rtype.type << BT_UNKNOWN;
					_RPTF2(_CRT_WARN, "%s(...): no typeinfo or SymGetTypeInfoEx(0x%lX, ...) returned FALSE for function result\n",
						__FUNCTION__, typinfo.TypeId);
					throw logic_error("no typeinfo for function result");
				}
				rtype.loc = R_ax; // EAX by default???
				queue<elem_t> argtypes;
				uint16 argcount;
				if (get_cc(cm) != CM_CC_VOIDARG) {
					if ((argcount = typinfo.ChildrenCount) > 0) { // have children
						//static const elem_t unkntype = { BT_UNKNOWN, 0 };
						ULONG index;
						childrenex_t params(typinfo);
						if (params) {
							loc_t loc;
							if (plocals != 0)
								for (loc_t::const_iterator i = plocals->begin(); i != plocals->end(); ++i)
									if (i->first.Tag == SymTagData && (i->first.Flags & SYMFLAG_PARAMETER) != 0)
										loc.push_back(*i);
								/*
								for_each(plocals->begin(), plocals->end(),
									if_(LL_MEMBER(loc_t::value_type::first_type::Tag) == SymTagData
										&& (LL_MEMBER(loc_t::value_type::first_type::Flags) & SYMFLAG_PARAMETER) != 0)
											[bind(&loc_t::push_back, var(loc), _1)]);
								*/
							for (index = 0; index < typinfo.ChildrenCount; ++index) {
								if (get_cc(cm) == CM_CC_ELLIPSIS) {
									_RPTF2(_CRT_ASSERT, "%s(...): unexpected argument[%lu] when get_cc(cm)==CM_CC_ELLIPSIS (arglist continuing after ellipsis is ignored)\n",
										__FUNCTION__, index);
									break;
								}
								if (params[index].SymIndex != 0) {
									if (params[index].SymTag != SymTagFunctionArgType) {
										_RPTF4(_CRT_ASSERT, "%s(...): params[%lu].SymTag != SymTagFunctionArgType (params[%lu].SymTag=%s)\n",
											__FUNCTION__, index, index, params[index].TokenizeSymTag().c_str());
										throw logic_error("unhandled argument type"); //continue;
									}
									_ASSERTE(params[index].TypeId != 0);
									if (params[index].TypeId != 0 && basetype(params[index].TypeId)) {
										if (basetype.SymTag == SymTagBaseType && basetype.BaseType == btNoType) {
#ifdef _DEBUG
											if (is_user_cc(cm))
												_RPTF1(_CRT_WARN, "%s(...): overriding CM_CC_SPECIAL function model by CM_CC_ELLIPSIS\n",
													__FUNCTION__);
#endif // _DEBUG
											cm = CM_CC_ELLIPSIS;
											argcount = index;
											_ASSERTE(index == typinfo.ChildrenCount - 1); // must be last parameter
										} else { // regular argument
											elem_t arg;
											// care arg type
											if (!get_ti(basetype, arg.type)) {
												//arg.type << BT_UNKNOWN;
												_RPTF2(_CRT_WARN, "%s(...): couldnot build argument[%lu] type\n",
													__FUNCTION__, index);
												PrintTypeInfoEx(basetype);
												throw logic_error("no type for argument or unknown type");
											}
											// care arg location
											if (!loc.empty())
												if ((loc.front().first.Flags & SYMFLAG_REGISTER) != 0) {
													const ULONG Register(loc.front().first.Register);
													arg.loc = Register == CV_REG_EDXEAX ? argloc(R_ax, R_dx) :
														ix86_getReg((CV_HREG_e)Register);
													//if (arg.loc > 0) cm = CM_CC_SPECIAL;
												}
#ifdef _DEBUG
												else if ((loc.front().first.Flags & SYMFLAG_REGREL) == 0)
													_RPTF3(_CRT_WARN, "%s(...): argument[%lu] of unknown location (Flags=%s)\n",
														__FUNCTION__, index, TokenizeSymFlag(loc.front().first.Flags).c_str());
#endif // _DEBUG
											argtypes.push(arg);
										} // !VARARG
										basetype.Name.Empty();
									} else {
										_RPTF2(_CRT_WARN, "%s(...): SymGetTypeInfoEx(0x%lX, ...) returned FALSE for function argument base type\n",
											__FUNCTION__, params[index].TypeId);
										throw logic_error("no typeinfo for argument base type");
									}
								} else {
									_RPTF2(_CRT_WARN, "%s(...): SymIndex==0 for arg[%lu]\n",
										__FUNCTION__, index);
									throw logic_error("no typeinfo for argument");
								}
								if (!loc.empty()) {
									if (pfnames != 0) pfnames->append(loc.front().second);
									loc.pop_front();
								}
							} // enumerate params
						} else {
							//for (index = 0; index < typinfo.ChildrenCount; ++index) argtypes.push(unkntype);
							_RPTF2(_CRT_WARN, "%s(...): SymGetChildrenTypeInfoEx(typinfo) returned NULL\n",
								__FUNCTION__, typinfo.ChildrenCount);
							throw logic_error("typeinfo for function arguments not available");
						}
					}/* else
						cm = CM_CC_VOIDARG;*/
				} // not voidarg
				type << t << (cm = get_cc(cm) | inf.cc.cm & (CM_MASK | CM_M_MASK));
				if (is_user_cc(cm) && is_resolved_type_void(rtype.type)) {
					rtype.type.clear();
					rtype.type << BT_UNKNOWN;
				}
				type << rtype.type;
				if (is_user_cc(cm)/* && !is_resolved_type_void(rtype.type)*/)
					type << rtype.loc;
				if (get_cc(cm) != CM_CC_VOIDARG) {
					type << dt(argcount);
					while (!argtypes.empty()) {
						if (is_user_cc(cm) && is_resolved_type_void(argtypes.front().type)) {
							argtypes.front().type.clear();
							argtypes.front().type << BT_UNKNOWN;
							_RPTF1(_CRT_WARN, "%s(...): void type argument\n", __FUNCTION__);
						}
						type << argtypes.front().type;
						if (is_user_cc(cm)/*&& !is_resolved_type_void(argtypes.front().type)*/)
							type << argtypes.front().loc;
						argtypes.pop();
					}
				}
				return !type.empty();
			} // SymTagFunctionType
			case SymTagVTableShape:
				type << (BT_ARRAY | BTMT_NONBASED | BTM_CONST) << dt(typinfo.Count) <<
					(BT_PTR | BTMT_DEFPTR | BTM_CONST) << (BT_FUNC | BTMT_NEARCALL) <<
					(get_cc(CM_CC_THISCALL) | inf.cc.cm & (CM_MASK | CM_M_MASK)) <<
					BT_VOID/*rettype*/ << dt(0/*argcount*/);
				_ASSERTE(typinfo.TypeId == 0);
				break; //return !type.empty();
			// bypassable types (expectional)
			case SymTagVTable:
			case SymTagData:
			case SymTagFunction:
				break;
			// doubtful candidates:
			//case SymTagBaseClass:
			//case SymTagBlock:
			//case SymTagCustom:
			//case SymTagCustomType:
			//case SymTagNull:
			default: // everything else too exotic for ida
				throw fmt_exception("data type %s unknown to IDA", typinfo.TokenizeSymTag().c_str());
		} // switch typinfo.SymTag
		if (typinfo.TypeId != 0 && basetype(typinfo.TypeId)) {
			plist locfnames;
			if (get_ti(basetype, loctype, pfnames != 0 ? &locfnames : 0, plocals, use_accept_incomplete)) {
				type << loctype;
				if (pfnames != 0) pfnames->append(locfnames);
			}
			basetype.Name.Empty();
		}
	} catch (GENERAL_CATCH_FILTER) {
		type.clear();
		if (pfnames != 0) pfnames->clear();
#ifdef _DEBUG
		if (typeid(e) != typeid(not_convertible)) {
			_RPTF3(_CRT_WARN, "%s(...) caught exception: %-.3840s (%s)\n",
				__FUNCTION__, e.what(), typeid(e).name());
			PrintTypeInfoEx(typinfo);
		}
#endif // _DEBUG
		throw not_convertible();
	}
	return !type.empty();
}

// set type_t[] typeinfo for address from PDB typeinfo (not for struct members)
static bool set_ti(ea_t ea, const typeinfoex_t &typinfo, loc_p plocals = 0) {
	_ASSERTE(typinfo.SymIndex != 0);
	if (typinfo.SymIndex != 0) try {
		typestring type;
		plist fnames;
		if (get_ti(typinfo, type, &fnames, plocals)) {
			if (is_extern(ea)) type.before(BT_PTR | BTMT_DEFPTR);
#ifdef _DEBUG
			if (type.length() >= MAXSPECSIZE) _RPTF4(_CRT_WARN, "%s(%08IX, ...): long %s (%Iu)\n",
				__FUNCTION__, ea, "typeinfo", type.length());
			if (fnames.length() >= MAXSPECSIZE) _RPTF4(_CRT_WARN, "%s(%08IX, ...): long %s (%Iu)\n",
				__FUNCTION__, ea, "fnames", fnames.length());
#endif // _DEBUG
			//type.truncate();
			//fnames.truncate();
			return ::set_ti(ea, type, fnames);
		}
	} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
		_RPTF4(_CRT_WARN, "%s(%08IX, ...): %s\n", __FUNCTION__, ea, e.what(), typeid(e).name());
		if (typeid(e) != typeid(not_convertible)) PrintTypeInfoEx(typinfo);
#endif // _DEBUG
	}
	return false;
}

// set type_t[] typeinfo for structure member from PDB typeinfo
static bool set_member_ti(struc_t *sptr, member_t *mptr,
	const typeinfoex_t &typinfo, bool may_destroy_other_members) {
	_ASSERTE(sptr != 0);
	//_ASSERTE(mptr != 0);
	_ASSERTE(typinfo.SymIndex != 0);
	if (sptr != 0 && mptr != 0 && typinfo.SymIndex != 0) try {
		typestring type;
		plist fnames;
		if (get_ti(typinfo, type, &fnames)) {
#ifdef _DEBUG
			if (type.length() >= MAXSPECSIZE) _RPTF3(_CRT_WARN, "%s(...): long %s (%Iu)\n",
				__FUNCTION__, "typeinfo", type.length());
#endif // _DEBUG
			//type.truncate();
			if (!::set_member_ti(sptr, mptr, type, may_destroy_other_members))
				return false;
			netnode namenode(mptr->id);
			if (!fnames.empty())
				namenode.supset(NSUP_TYPEINFO + 1, fnames.c_str(), fnames.size() + 1);
			else
				namenode.supdel(NSUP_TYPEINFO + 1);
			return true;
		}
	} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
		_RPTF3(_CRT_WARN, "%s(...): %s\n", __FUNCTION__, e.what(), typeid(e).name());
		if (typeid(e) != typeid(not_convertible)) PrintTypeInfoEx(typinfo);
#endif // _DEBUG
	}
	return false;
}

// convert one type from PDB to type_t[] sequence and store as named typedef
// returns: BADNODE if failed, 0 if OK (saved as typeinfo),
//          otherwise tid_t of existing idb type (struct or enum) - not created
static tid_t set_named_type(const char *name, const typeinfoex_t &typinfo,
	int ntf_flags = DEF_NTF_FLAGS, const sclass_t *sclass = NULL,
	const char *cmt = NULL, const ulong *value = NULL) {
	tid_t tid(BADNODE);
	//_ASSERTE(name != 0 && *name != 0);
	_ASSERTE(typinfo.SymIndex != 0);
	if (name != 0 && *name != 0 && typinfo.SymIndex != 0) try {
		typestring type;
		plist fnames;
		if (get_ti(typinfo, type, &fnames)) {
#ifdef _DEBUG
			if (strlen(name) >= MAXNAMESIZE) _RPTF4(_CRT_WARN, "%s(..., \"%-.1023s\", ...): long %s (%Iu)\n",
				__FUNCTION__, name, "typename", strlen(name));
			if (type.length() >= MAXSPECSIZE) _RPTF4(_CRT_WARN, "%s(..., \"%-.1023s\", ...): long %s (%Iu)\n",
				__FUNCTION__, name, "typeinfo", type.length());
			if (fnames.length() >= MAXSPECSIZE) _RPTF4(_CRT_WARN, "%s(..., \"%-.1023s\", ...): long %s (%Iu)\n",
				__FUNCTION__, name, "fnames", fnames.length());
#endif // _DEBUG
			//type.truncate();
			//fnames.truncate();
			tid = ::set_named_type(name, type, fnames,
				ntf_flags, sclass, cmt, NULL/*fieldcmts*/, value);
		}
	} catch (GENERAL_CATCH_FILTER) {
		tid = BADNODE;
#ifdef _DEBUG
		_RPTF4(_CRT_WARN, "%s(..., \"%-.1023s\", ...): %s\n", __FUNCTION__, name,
			e.what(), typeid(e).name());
		if (typeid(e) != typeid(not_convertible)) PrintTypeInfoEx(typinfo);
#endif // _DEBUG
	}
	return tid;
}

// for structs: load struct members from pdb typeinfo
static bool LoadMembersFromPDB(const typeinfoex_t &typinfo, struc_t *struc,
	DWORD BaseOffset = 0, const char *parentname = 0) {
	_ASSERTE(typinfo.SymIndex != 0);
	_ASSERTE(typinfo.SymTag == SymTagUDT);
	_ASSERTE(struc != 0);
	if (typinfo.SymIndex == 0 || typinfo.SymTag != SymTagUDT || struc == 0)
		return false;
	if (typinfo.ChildrenCount <= 0) return true; // nothing to add but success
	if (inheritance_path.find(typinfo.SymIndex) != inheritance_path.end())
		return false;
	const hash_set<DWORD>::iterator
		iter(inheritance_path.insert(typinfo.SymIndex).first);
	_ASSERTE(iter != inheritance_path.end());
	childrenex_t members(typinfo);
	if (!members) {
		set_struc_cmt(struc->id, "incomplete", false);
		_RPTF2(_CRT_ASSERT, "%s(...): SymGetChildrenTypeInfoEx(typinfo) returned NULL\n",
			__FUNCTION__, typinfo.ChildrenCount);
		return false;
	}
	bool result(false), incomplete(false);
	string fullname;
	typestring type;
	plist fnames;
	typeinfoex_t basetype;
	for (ULONG index = 0; index < typinfo.ChildrenCount; ++index) try {
		if (members[index].SymIndex == 0) throw logic_error("SymIndex == 0");
		ea_t ea;
		asize_t size;
		flags_t flags;
		typeinfo_t ti, *pti;
		char cmt[MAXSTR];
		member_t *member;
		switch (members[index].SymTag) {
			case SymTagData:
				switch (members[index].DataKind) {
					case DataIsMember:
						// cannot recognize bitfield start
						if (members[index].BitPosition > 0)
							throw fmt_exception("cannot add bit field member due to IDA limitation (BitPosition=%lu Length=%I64u)",
								members[index].BitPosition, members[index].Length);
						_ASSERTE(typinfo.UDTKind != UdtUnion || members[index].Offset == 0);
						_ASSERTE(members[index].TypeId != 0);
						if (members[index].TypeId == 0 || !basetype(members[index].TypeId))
							throw logic_error("no type for member (Data/Member)");
						//_ASSERTE(members[index].hasName());
						if (members[index].hasName()) {
							if (parentname != 0 && *parentname != 0)
								fullname.assign(parentname).append(SCOPE_DELIMITER);
							fullname.append(members[index].getAnsiName());
						}
						size = static_cast<asize_t>(get_type_size(!typinfo.hasBitPosition() ? members[index] : basetype));
						flags = getFlags(basetype);
						pti = get_typeinfo(basetype, ti);
#ifdef _DEBUG
						if (!isData(flags) || size <= 0) {
							_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
								"%s(...): %s(%-.2000ls).member[%lu] name=%-.2000ls without type or zero size: flags=%s size=0x%IX has_typeinfo?%s",
								__FUNCTION__, "struct", static_cast<PCWSTR>(typinfo.Name), index,
								static_cast<PCWSTR>(members[index].Name), flags2str(flags).c_str(),
								size, pti != 0 ? "yes":"no");
							PrintTypeInfoEx(basetype);
						}
#endif // _DEBUG
						if (add_struc_member_anyway(struc,
							members[index].hasName() ? fullname.c_str() : NULL,
							BaseOffset + members[index].Offset, flags, pti, size) == 0)
							result = true;
						else if (add_struc_member_anyway(struc,
							members[index].hasName() ? fullname.c_str() : NULL,
							BaseOffset + members[index].Offset,
							flags = byteflag(), pti = 0, size) != 0)
							incomplete = true;
						member = struc->is_union() ?
							get_member_by_name(struc, members[index].hasName() ? fullname.c_str() : NULL) :
							get_member(struc, BaseOffset + members[index].Offset);
						if (member != 0)
							if (set_member_ti(struc, member, basetype, true))
								++totaltypeinfos;
							else try {
								if (get_ti(basetype, type) && print_type_to_one_line(cmt,
									qnumber(cmt), idati, type) == T_NORMAL)
									set_member_cmt(member, cmt, true);
							} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
								_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
									"%s(...): %s (%s(%-.2000ls).member[%lu] name=%-.2000ls)\n",
									__FUNCTION__, e.what(), "struct", static_cast<PCWSTR>(typinfo.Name),
									index, static_cast<PCWSTR>(members[index].Name));
								if (typeid(e) != typeid(not_convertible)) PrintTypeInfoEx(basetype);
#endif // _DEBUG
							}
						break;
					case DataIsStaticMember:
					case DataIsGlobal:
						ea = (ea_t)members[index].Address + Delta;
						if (isEnabled(ea)) {
							if (basetype(members[index].TypeId)) {
								if (isData(flags = is_extern(ea) ? ptrflag() : getFlags(basetype))) {
#ifdef _DEBUG
									size = is_extern(ea) ? get_ptr_size(FF_DATA) :
										static_cast<asize_t>(get_type_size(members[index]));
									pti = get_typeinfo(basetype, ti, ea);
									typeinfo_t oldti, *poldti(get_typeinfo(ea, 0, flags, &oldti));
									OutputDebugString("%08IX: idabase flags=%s has_typeinfo?%s size=0x%IX\n", ea, flags2str(::getFlags(ea)).c_str(), poldti != 0 ? "yes":"no", get_item_size(ea));
									OutputDebugString("          pdb flags=%s has_typeinfo?%s size=0x%IX\n", flags2str(flags).c_str(), pti != 0 ? "yes":"no", size);
									if (do_data_ex(ea, flags, pti, size)) ++totaldata;
#else // !_DEBUG
									if (do_data_ex(ea, flags, get_typeinfo(basetype, ti, ea),
										static_cast<asize_t>(get_type_size(members[index])))) ++totaldata;
#endif // _DEBUG
								}
#ifdef _DEBUG
								else
									_RPTF3(_CRT_WARN, "%s(...): no data type from typeinfoex_t at %08IX: %-.3840ls\n",
										__FUNCTION__, ea, static_cast<PCWSTR>(members[index].Name));
#endif // _DEBUG
								if (set_ti(ea, basetype)) ++totaltypeinfos;
							} // got type
							if (members[index].hasName()
								&& apply_static_name(ea, members[index].getAnsiName().c_str()))
								++totalnames;
						}
						break;
					default:
						throw fmt_exception("unhandled data kind: %s",
							members[index].TokenizeDataKind().c_str());
				} // switch DataKind
				break;
			case SymTagBaseClass: {
				_ASSERTE(members[index].TypeId != 0);
				if (members[index].TypeId == 0 || !basetype(members[index].TypeId))
					throw logic_error("no type for member (BaseClass)");
				_ASSERTE(basetype.hasName());
				_ASSERTE(basetype.SymTag == SymTagUDT);
				//_ASSERTE(basetype.UDTKind == typinfo.UDTKind);
				// care! too deep nesting may(or not) introduce temporary struc buffer recycling
				// in case of problems by creating structs try to remove following line
				/*if (*/CreateTypeFromPDB(basetype)/* == BADNODE)
					throw logic_error("base class couldnot be created")*/;
				if (parentname != 0 && *parentname != 0) fullname.assign(parentname);
				_ASSERTE(basetype.hasName());
				if (basetype.hasName()) {
					if (parentname != 0 && *parentname != 0) fullname.append(SCOPE_DELIMITER);
					fullname.append(basetype.getAnsiName());
					//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
				}
				if (LoadMembersFromPDB(basetype, struc,
					BaseOffset + members[index].Offset, fullname.c_str())) result = true;
				break;
			}
			// weightless members
			case SymTagUDT:
			case SymTagEnum:
			case SymTagTypedef:
				_ASSERTE(typinfo.hasName());
				if (CreateTypeFromPDB(members[index], typinfo.getAnsiName().c_str()) != BADNODE)
					result = true;
				break;
			// class-specific members (weightless)
			case SymTagFunction:
				// TypeId 0x2A5: Tag=Function Name=MoveElementTo VirtualBaseOffset=0x20
				//_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
				//	"%s(...): %s cannot be stored in ida struct: class(%-.2000ls) member[%lu] name=%-.2000ls\n",
				//	__FUNCTION__, "struct/class methods", static_cast<PCWSTR>(typinfo.Name),
				//	index, static_cast<PCWSTR>(members[index].Name));
				//PrintTypeInfoEx(members[index]);
				// VirtualBaseOffset
				break;
			case SymTagVTable:
				// TypeId 0x78: Tag=VTable Type=0x7E TypeId=0x7E
				//   TypeId 0x7E: Tag=PointerType Length=0x4 Type=0x77 TypeId=0x77
				//     TypeId 0x77: Tag=VTableShape Count=0x3
				//_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
				//	"%s(...): %s cannot be stored in ida struct: class(%-.2000ls) member[%lu] name=%-.2000ls\n",
				//	__FUNCTION__, "class vf tables", static_cast<PCWSTR>(typinfo.Name),
				//	index, static_cast<PCWSTR>(members[index].Name));
				//PrintTypeInfoEx(members[index]);
				_ASSERTE(members[index].BitPosition == 0);
				if (members[index].BitPosition > 0)
					throw fmt_exception("cannot add bit field member due to IDA limitation (BitPosition=%lu Length=%I64u)",
						members[index].BitPosition, members[index].Length);
				_ASSERTE(typinfo.UDTKind != UdtUnion/* || members[index].Offset == 0*/);
				_ASSERTE(members[index].TypeId != 0);
				if (members[index].TypeId == 0 || !basetype(members[index].TypeId))
					throw logic_error("no type for member (VTable)");
				if (members[index].hasName()) {
					if (parentname != 0 && *parentname != 0)
						fullname.assign(parentname).append(SCOPE_DELIMITER);
					fullname.append(members[index].getAnsiName());
				} else
					fullname.assign(VTABLE_NAME);
				//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
				size = (asize_t)get_type_size(members[index]);
				flags = getFlags(basetype);
				pti = get_typeinfo(basetype, ti);
#ifdef _DEBUG
				if (!isData(flags) || size == 0) {
					_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
						"%s(...): %s(%-.2000ls).member[%lu] name=%-.2000ls VTable without type or zero size: flags=%s size=0x%IX has_typeinfo?%s",
						__FUNCTION__, "struct", static_cast<PCWSTR>(typinfo.Name), index,
						static_cast<PCWSTR>(members[index].Name), flags2str(flags).c_str(),
						size, pti != 0 ? "yes":"no");
					PrintTypeInfoEx(basetype);
				}
#endif // _DEBUG
				// ????? platí Offset u vtable nebo vtable offset == 0?
				if (add_struc_member_anyway(struc, fullname.c_str(),
					BaseOffset + /*???*/members[index].Offset, flags, pti, size) == 0)
					result = true;
				else if (add_struc_member_anyway(struc, fullname.c_str(),
					BaseOffset + members[index].Offset, flags = byteflag(), pti = 0, size) != 0)
					incomplete = true;
				if ((member = get_member(struc, BaseOffset + members[index].Offset)) != 0)
					if (set_member_ti(struc, member, basetype, true))
						++totaltypeinfos;
					else try {
						if (get_ti(basetype, type) && print_type_to_one_line(cmt,
							qnumber(cmt), idati, type) == T_NORMAL)
							set_member_cmt(member, cmt, true);
					} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
						_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
							"%s(...): %s (%s(%-.2000ls).member[%lu] name=%-.2000ls %s)\n",
							__FUNCTION__, e.what(), "struct", static_cast<PCWSTR>(typinfo.Name),
							index, static_cast<PCWSTR>(members[index].Name), "VTable");
						if (typeid(e) != typeid(not_convertible)) PrintTypeInfoEx(basetype);
#endif // _DEBUG
					}
				break;
			case SymTagVTableShape:
				break; // ok - just vtable size
			case SymTagThunk:
				// TypeId 0x6FE: Tag=Thunk Name=exception::exception Length=0x6 AddressOffset=0x1B06C LexicalParent=0x706 Address=000000001201C06C
				ea = (ea_t)members[index].Address + Delta;
				if (isEnabled(ea) && !is_spec_ea(ea)) {
					func_t *func(get_func(ea));
					if (func == 0 || func->startEA != ea) {
						del_func(ea);
						if (add_func(ea, BADADDR)) ++totalfuncs;
					}
					if ((func = get_func(ea)) != 0) {
						func->flags |= FUNC_THUNK;
						update_func(func);
					}
					if (basetype(members[index].TypeId)) {
						loc_t locals;
						if (GetLocalsFor(members[index].Address, locals)
							&& set_ti(ea, basetype, &locals)) ++totaltypeinfos;
					}
					if (members[index].hasName()
						&& apply_static_name(ea, members[index].getAnsiName().c_str()))
						++totalnames;
				}
				//PrintTypeInfoEx(members[index]);
				break;
			default: // if unsure, consider weight loose
				throw fmt_exception("unhandled member type: %s",
					members[index].TokenizeSymTag().c_str());
		} // switch SymTag
	} catch (GENERAL_CATCH_FILTER) {
		incomplete = true;
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
			"%s(...): %s (%s=%-.2000ls index=%lu name=%-.2000ls typeid=%s)\n",
			__FUNCTION__, e.what(), "struct", static_cast<PCWSTR>(typinfo.Name),
			index, static_cast<PCWSTR>(members[index].Name), typeid(e).name());
		if (members[index].SymIndex != 0) PrintTypeInfoEx(members[index]);
#endif // _DEBUG
	}
	if (incomplete) set_struc_cmt(struc->id, "incomplete", false);
	/*if (iter != inheritance_path.end()) */inheritance_path.erase(iter);
	return result;
}

static LONG LoadMembersFromPDB(const typeinfoex_t &typinfo,
	typestring &type, plist &fnames, uint8 &Align, const char *parentname = 0) {
	type.clear(); fnames.clear();
	Align = 0; // default
	_ASSERTE(typinfo.SymIndex != 0);
	_ASSERTE(typinfo.SymTag == SymTagUDT);
	if (typinfo.SymIndex == 0 || typinfo.SymTag != SymTagUDT) return -1;
	if (typinfo.ChildrenCount <= 0) return 0; // nothing to add but success
	if (inheritance_path.find(typinfo.SymIndex) != inheritance_path.end())
		return -1;
	const hash_set<DWORD>::iterator
		iter(inheritance_path.insert(typinfo.SymIndex).first);
	_ASSERTE(iter != inheritance_path.end());
	childrenex_t members(typinfo);
	if (!members) {
		_RPTF2(_CRT_ASSERT, "%s(...): SymGetChildrenTypeInfoEx(typinfo) returned NULL\n",
			__FUNCTION__, typinfo.ChildrenCount);
		return -1;
	}
	LONG result(0);
	ULONG index;
	try {
		DWORD LastOffset(0);
		typeinfoex_t basetype;
		string fullname;
		typestring loctype;
		plist locfnames;
		for (index = 0; index < typinfo.ChildrenCount; ++index) {
			if (members[index].SymIndex == 0) throw logic_error("SymIndex == 0");
			fullname.clear();
			ea_t ea;
			asize_t size;
			flags_t flags;
			typeinfo_t ti, *pti;
			member_t *member;
			uint8 tmpAlign;
			LONG Delta;
			ULONG64 Size;
			switch (members[index].SymTag) {
				case SymTagData:
					switch (members[index].DataKind) {
						case DataIsMember:
							if (members[index].BitPosition > 0)
								throw fmt_exception("cannot add bit field member due to IDA limitation (BitPosition=%lu Length=%I64u)",
									members[index].BitPosition, members[index].Length);
							_ASSERTE(typinfo.UDTKind != UdtUnion || members[index].Offset == 0);
							if (members[index].Offset < LastOffset) throw
								fmt_exception("UDT member in descending offset order (LastOffset=%lu)", LastOffset);
							_ASSERTE(members[index].TypeId != 0);
							if (members[index].TypeId == 0 || !basetype(members[index].TypeId))
								throw logic_error("no type for member (Data/Member)");
							if (members[index].hasBitPosition()
								|| members[index].BitPosition != 0) { // is bitfield
								if (basetype.SymTag != SymTagBaseType)
									throw logic_error("bitfield type not basic type");
								switch (basetype.BaseType) {
									case btInt:
									case btUInt:
										switch (basetype.Length) {
											case 1: type << (BT_BITFIELD | BTMT_BFLDCHAR); break;
											case 2: type << (BT_BITFIELD | BTMT_BFLDSHORT); break;
											//case 4: type << (BT_BITFIELD | BTMT_BFLDINT); break;
											default:
												if (basetype.Length != inf.cc.size_i)
													throw logic_error("unexpected bitfield type size");
												type << (BT_BITFIELD | BTMT_BFLDINT);
										}
										break;
									case btLong:
									case btULong:
										if (basetype.Length != 4)
											throw logic_error("unexpected bitfield type size");
										type << (BT_BITFIELD | BTMT_BFLDLONG);
										break;
									case btWChar: // ???
										type << (BT_BITFIELD | BTMT_BFLDSHORT);
										break;
									case btChar:
										type << (BT_BITFIELD | BTMT_BFLDCHAR);
										break;
									default:
										throw logic_error("unexpected bitfield type");
								}
								type << dt(members[index].Length << 1 | (basetype.BaseType == btUInt
									|| basetype.BaseType == btULong ? 1 : 0));
							} else { // normal member
								if (!get_ti(basetype, loctype, &locfnames))
									throw logic_error("no typeinfo for struct member");
								_ASSERTE(!loctype.empty());
								type << loctype;
								//if (!locfnames.empty()) fnames << locfnames;
								//_ASSERTE(members[index].hasName());
							}
							if (members[index].hasName()) {
								if (parentname != 0 && *parentname != 0)
									fullname.assign(parentname).append(SCOPE_DELIMITER);
								fullname.append(members[index].getAnsiName());
								//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
							}
							fnames << fullname;
							_ASSERTE(!fnames.empty());
							++result;
							if (typinfo.UDTKind == UdtUnion || basetype.SymTag == SymTagUDT
								|| members[index].hasBitPosition()
								|| members[index].BitPosition != 0) {
								LastOffset = members[index].Offset;
								break;
							}
							// alignment calculation
							Size = get_type_size(members[index]);
							Delta = members[index].Offset - LastOffset;
							_ASSERTE(Delta >= 0);
							// todo: alignment calculation is very uncertain
							tmpAlign = 1;
							if (Delta > 0) tmpAlign += log2_64(rounduppow2_64(max<ULONG64>(Size, Delta)));
							//if (tmpAlign > Align) Align = tmpAlign;
							LastOffset = members[index].Offset + Size;
							break;
						case DataIsStaticMember:
						case DataIsGlobal:
							ea = (ea_t)members[index].Address + Delta;
							if (isEnabled(ea)) {
								if (basetype(members[index].TypeId)) {
									if (isData(flags = is_extern(ea) ? ptrflag() : getFlags(basetype))) {
#ifdef _DEBUG
										size = is_extern(ea) ? get_ptr_size(FF_DATA) :
											static_cast<asize_t>(get_type_size(members[index]));
										pti = get_typeinfo(basetype, ti, ea);
										typeinfo_t oldti, *poldti(get_typeinfo(ea, 0, flags, &oldti));
										OutputDebugString("%08IX: idabase flags=%s has_typeinfo?%s size=0x%IX\n", ea, flags2str(::getFlags(ea)).c_str(), poldti != 0 ? "yes":"no", get_item_size(ea));
										OutputDebugString("          pdb flags=%s has_typeinfo?%s size=0x%IX\n", flags2str(flags).c_str(), pti != 0 ? "yes":"no", size);
										if (do_data_ex(ea, flags, pti, size)) ++totaldata;
#else // !_DEBUG
										if (do_data_ex(ea, flags, get_typeinfo(basetype, ti, ea),
											static_cast<asize_t>(get_type_size(members[index])))) ++totaldata;
#endif // _DEBUG
									}
#ifdef _DEBUG
									else
										_RPTF3(_CRT_WARN, "%s(...): no data type from typeinfoex_t at %08IX: %-.3840ls\n",
											__FUNCTION__, ea, static_cast<PCWSTR>(members[index].Name));
#endif // _DEBUG
									if (set_ti(ea, basetype)) ++totaltypeinfos;
								} // got type
								if (members[index].hasName()
									&& apply_static_name(ea, members[index].getAnsiName().c_str()))
									++totalnames;
							}
							break;
						default:
							throw fmt_exception("unhandled data kind: %s",
								members[index].TokenizeDataKind().c_str());
					} // switch DataKind
					break;
				case SymTagBaseClass: {
					_ASSERTE(typinfo.UDTKind != UdtUnion || members[index].Offset == 0);
					if (members[index].Offset < LastOffset) throw // ???
						fmt_exception("UDT member in descending offset order (LastOffset=%li)", LastOffset);
					_ASSERTE(members[index].TypeId != 0);
					if (members[index].TypeId == 0 || !basetype(members[index].TypeId))
						throw logic_error("no type for member (BaseClass)");
					_ASSERTE(basetype.SymTag == SymTagUDT);
					//_ASSERTE(basetype.UDTKind == typinfo.UDTKind);
					// care! too deep nesting may(or not) introduce temporary struc buffer recycling
					// in case of problems by creating structs try to remove following line
					/*if (*/CreateTypeFromPDB(basetype)/* == BADNODE)
						throw logic_error("base class couldnot be created")*/;
					if (parentname != 0 && *parentname != 0) fullname.assign(parentname);
					_ASSERTE(basetype.hasName());
					if (basetype.hasName()) {
						if (parentname != 0 && *parentname != 0) fullname.append(SCOPE_DELIMITER);
						fullname.append(basetype.getAnsiName());
						//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
					}
					Delta = LoadMembersFromPDB(basetype, loctype, locfnames, tmpAlign, fullname.c_str());
					if (Delta < 0) throw fmt_exception("couldnot inherit from %s", fullname.c_str());
					_ASSERTE(Delta == 0 || !loctype.empty());
					type << loctype;
					_ASSERTE(Delta == 0 || !locfnames.empty());
					fnames << locfnames;
					result += Delta;
					if (tmpAlign > Align) Align = tmpAlign;
					LastOffset = members[index].Offset;
					if (members[index].UDTKind == UdtUnion) break;
					if ((Size = get_type_size(members[index])) > 0)
						if (Delta > 0)
							LastOffset += Size;
#ifdef _DEBUG
						else
							_RPT3(_CRT_WARN, "%s(...): Empty UDT %s of non-zero size(%I64i):\n",
							__FUNCTION__, fullname.c_str(), Size);
#endif // _DEBUG
					break;
				}
				// weightless members
				case SymTagUDT:
				case SymTagEnum:
				case SymTagTypedef:
					_ASSERTE(typinfo.hasName());
					CreateTypeFromPDB(members[index], typinfo.getAnsiName().c_str());
					break;
				// class-specific members (weightless)
				case SymTagFunction:
					//PrintTypeInfoEx(members[index]);
					// VirtualBaseOffset
					break;
				case SymTagVTable:
					//PrintTypeInfoEx(members[index]);
					_ASSERTE(members[index].BitPosition == 0);
					if (members[index].BitPosition > 0)
						throw fmt_exception("cannot add bit field member due to IDA limitation (BitPosition=%lu Length=%I64u)",
							members[index].BitPosition, members[index].Length);
					_ASSERTE(typinfo.UDTKind != UdtUnion/* || members[index].Offset == 0*/);
					if (members[index].Offset < LastOffset) throw
						fmt_exception("UDT member in descending offset order (LastOffset=%li)", LastOffset);
					_ASSERTE(members[index].TypeId != 0);
					if (members[index].TypeId == 0 || !basetype(members[index].TypeId))
						throw logic_error("no type for member (VTable)");
					if (!get_ti(basetype, loctype, &locfnames))
						throw logic_error("no typeinfo for struct member");
					_ASSERTE(!loctype.empty());
					type << loctype;
					//if (!locfnames.empty()) fnames << locfnames;
					if (members[index].hasName()) {
						if (parentname != 0 && *parentname != 0)
							fullname.assign(parentname).append(SCOPE_DELIMITER);
						fullname.append(members[index].getAnsiName());
					} else
						fullname.assign(VTABLE_NAME);
					//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
					fnames << fullname;
					_ASSERTE(!fnames.empty());
					++result;
					if (typinfo.UDTKind == UdtUnion || basetype.SymTag == SymTagUDT) break;
					Size = get_type_size(members[index]);
					// ????? platí Offset u vtable nebo vtable offset == 0?
					Delta = members[index].Offset - LastOffset;
					_ASSERTE(Delta >= 0);
					// todo: alignment calculation is very uncertain
					tmpAlign = 1;
					if (Delta > 0) tmpAlign += log2_64(rounduppow2_64(max<ULONG64>(Size, Delta)));
					//if (tmpAlign > Align) Align = tmpAlign;
					LastOffset = members[index].Offset + Size;
					break;
				case SymTagVTableShape:
					break; // ok - just vtable size
				case SymTagThunk:
					// TypeId 0x6FE: Tag=Thunk Name=exception::exception Length=0x6 AddressOffset=0x1B06C LexicalParent=0x706 Address=000000001201C06C
					ea = static_cast<ea_t>(members[index].Address) + Delta;
					if (isEnabled(ea) && !is_spec_ea(ea)) {
						func_t *func(get_func(ea));
						if (func == 0 || func->startEA != ea) {
							del_func(ea);
							if (add_func(ea, BADADDR)) ++totalfuncs;
						}
						if ((func = get_func(ea)) != 0) {
							func->flags |= FUNC_THUNK;
							update_func(func);
						}
						if (basetype(members[index].TypeId)) {
							loc_t locals;
							if (GetLocalsFor(members[index].Address, locals)
								&& set_ti(ea, basetype, &locals)) ++totaltypeinfos;
						}
						if (members[index].hasName()
							&& apply_static_name(ea, members[index].getAnsiName().c_str()))
							++totalnames;
					}
					//PrintTypeInfoEx(members[index]);
					break;
				default: // if unsure, consider weight loose
					throw fmt_exception("unhandled member type: %s",
						members[index].TokenizeSymTag().c_str());
			} // switch SymTag
		} // iterate through members
	} catch (GENERAL_CATCH_FILTER) {
		result = -1;
		type.clear(); fnames.clear();
		Align = 0;
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
			"%s(...): %s (%s=%-.2000ls index=%lu name=%-.2000ls typeid=%s)\n",
			__FUNCTION__, e.what(), "struct", static_cast<PCWSTR>(typinfo.Name),
			index, static_cast<PCWSTR>(members[index].Name), typeid(e).name());
		if (members[index].SymIndex != 0 && typeid(e) != typeid(not_convertible))
			PrintTypeInfoEx(members[index]);
#endif // _DEBUG
	}
	/*if (iter != inheritance_path.end()) */inheritance_path.erase(iter);
	return result;
}

// for enums: load constants from pdb typeinfo
static bool LoadConstsFromPDB(const typeinfoex_t &typinfo, enum_t enu) {
	_ASSERTE(typinfo.SymIndex != 0);
	_ASSERTE(typinfo.SymTag == SymTagEnum);
	_ASSERTE(enu != BADNODE);
	if (typinfo.SymIndex == 0 || typinfo.SymTag != SymTagEnum || enu == BADNODE)
		return false;
	if (typinfo.ChildrenCount <= 0) return true; // nothing to add but success
	childrenex_t members(typinfo);
	if (!members) {
 		set_enum_cmt(enu, "incomplete", false);
#ifdef _DEBUG
		char enum_name[MAXNAMESIZE];
		get_enum_name(enu, CPY(enum_name));
		_RPTF3(_CRT_WARN, "%s(...): SymGetChildrenTypeInfoEx(...) returned NULL (enum=%s TypeId=0x%lX)\n",
			__FUNCTION__, enum_name, typinfo.SymIndex);
#endif // _DEBUG
		return false;
	}
	bool incomplete(false);
	for (ULONG index = 0; index < typinfo.ChildrenCount; ++index) try {
		if (members[index].SymIndex == 0) throw logic_error("SymIndex == 0");
		_ASSERTE(members[index].hasName());
		string fullname; //char name[MAXNAMESIZE];
		if (!members[index].hasName()
			|| fullname.assign(members[index].getAnsiName()).empty())
			throw logic_error("name is missing");
		_ASSERTE(members[index].SymIndex != 0);
		_ASSERTE(members[index].DataKind == DataIsConstant);
		if (members[index].DataKind != DataIsConstant)
			throw fmt_exception("DataKind=%s",
				members[index].TokenizeDataKind().c_str());
		const uval_t value = static_cast<uval_t>(VarToUI64(members[index].Value));
		int err(add_const(enu, fullname.c_str(), value));
		if (err == CONST_ERROR_NAME) { // dupe const name try resolve
			// is global enum present? (resolve unwanted enums globalization)
			const enum_t globenu(get_const_enum(get_const_by_name(fullname.c_str())));
			char enum_name[MAXNAMESIZE];
			if (globenu != BADNODE && get_enum_name(globenu, CPY(enum_name)) > 0
				&& typinfo.getAnsiName().compare(0, MAXNAMESIZE - 1, enum_name) == 0) {
				OutputDebugString("deleting false global enum %s (%08IX)\n", enum_name, globenu);
				del_enum(globenu);
				// 2-nd service
				if (add_const(enu, fullname.c_str(), value) != 0)
					throw logic_error("add_const(...) both attempts failed");
			}
		} else if (err != 0)
			throw fmt_exception("add_const(...) returned %i", err);
	} catch (GENERAL_CATCH_FILTER) {
		incomplete = true;
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
			"%s(...): %s (%s=%-.2000ls index=%lu name=%-.2000ls typeid=%s)\n",
			__FUNCTION__, e.what(), "enum", static_cast<PCWSTR>(typinfo.Name),
			index, static_cast<PCWSTR>(members[index].Name), typeid(e).name());
		if (members[index].SymIndex != 0) PrintTypeInfoEx(members[index]);
#endif // _DEBUG
	}
	if (incomplete) set_enum_cmt(enu, "incomplete", false);
	return true;
}

static LONG LoadConstsFromPDB(const typeinfoex_t &typinfo,
	typestring &type, plist &fnames) {
	type.clear(); fnames.clear();
	_ASSERTE(typinfo.SymIndex != 0);
	_ASSERTE(typinfo.SymTag == SymTagEnum);
	if (typinfo.SymIndex == 0 || typinfo.SymTag != SymTagEnum) return -1;
	if (typinfo.ChildrenCount <= 0) return 0; // nothing to add but success
	childrenex_t members(typinfo);
	_ASSERTE(members);
	if (!members) {
		_RPTF2(_CRT_WARN, "%s(...): SymGetChildrenTypeInfoEx(...) returned NULL (TypeId=0x%lX)\n",
			__FUNCTION__, typinfo.SymIndex);
		return -1;
	}
	LONG result(0);
	uval_t level(0);
	for (ULONG index = 0; index < typinfo.ChildrenCount; ++index) try {
		_ASSERTE(members[index].SymIndex != 0);
		if (members[index].SymIndex == 0) throw logic_error("SymIndex == 0");
		//_ASSERTE(Const.SymTag == SymTagData);
		//if (Const.SymTag != SymTagData) throw fmt_exception("SymTag=%s", Const.TokenizeSymTag().c_str());
		//_ASSERTE(Const.LocationType == LocIsConstant);
		//if (Const.LocationType != LocIsConstant) throw fmt_exception("Location=%s", Const.TokenizeLocationType().c_str());
		_ASSERTE(members[index].DataKind == DataIsConstant);
		if (members[index].DataKind != DataIsConstant) throw
			fmt_exception("DataKind=%s", members[index].TokenizeDataKind().c_str());
		_ASSERTE(members[index].hasName());
		if (!members[index].hasName()) throw logic_error("name is missing");
		const uval_t value = static_cast<uval_t>(VarToUI64(members[index].Value));
		type << de(/*delta*/value - level);
		level = value;
		fnames << members[index].getAnsiName();
		++result;
	} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
			"%s(...): %s (%s=%-.2000ls index=%lu name=%-.2000ls typeid=%s)\n",
			__FUNCTION__, e.what(), "enum", static_cast<PCWSTR>(typinfo.Name),
			index, static_cast<PCWSTR>(members[index].Name), typeid(e).name());
		if (members[index].SymIndex != 0) PrintTypeInfoEx(members[index]);
#endif // _DEBUG
	}
	return result;
}

static tid_t CreateTypeFromPDB(const typeinfoex_t &typinfo,
	const char *parentname, bool accept_incomplete) {
	tid_t tid(BADNODE), tmptid;
	_ASSERTE(typinfo.SymIndex != 0);
	if (typinfo.SymIndex == 0) return tid;
	string fullname;
	if (parentname != 0 && *parentname != 0)
		fullname.assign(parentname).append(SCOPE_DELIMITER);
	typeinfoex_t basetype;
	const type_t *type;
	typestring tinfo;
	plist fnames;
	LONG Count;
	hash_set<DWORD>::iterator iter_id;
	hash_set<string>::iterator iter_name;
	uint8 Align;
	string validated_name;
	switch (typinfo.SymTag) {
		case SymTagUDT: {
			// _GUID: Index=0x122 TypeIndex=0x122 Value=0x0 Tag=UDT ModBase=0000000000400000
			// 	SymId 0x122: Tag=UDT Name=_GUID Length=0x10 Offset=0x0 ChildrenCount=0x4 VirtualTableShapeId=0x26 SymIndex=0x122 UDTKind=Struct ReqsValid=00000000009C9007 EntriesMatched=1 EntriesFilled=1 TagsFound=0000000000000800 AllReqsValid=00000000009C9007
			// 		SymId 0x123: Tag=Data Name=Data1 Type=0x4C TypeId=0x4C DataKind=Member Offset=0x0 SymIndex=0x123 ReqsValid=000000000018129B EntriesMatched=4 EntriesFilled=4 TagsFound=0000000000000080 AllReqsValid=000000000018129B
			// 			SymId 0x4C: Tag=BaseType Length=0x4 BaseType=ULong Offset=0x0 SymIndex=0x4C ReqsValid=0000000000181025 EntriesMatched=1 EntriesFilled=1 TagsFound=0000000000010000 AllReqsValid=0000000000181025
			// 		SymId 0x124: Tag=Data Name=Data2 Type=0x4D TypeId=0x4D DataKind=Member Offset=0x4 SymIndex=0x124 ReqsValid=000000000018129B EntriesMatched=4 EntriesFilled=4 TagsFound=0000000000000080 AllReqsValid=000000000018129B
			// 			SymId 0x4D: Tag=BaseType Length=0x2 BaseType=UInt Offset=0x0 SymIndex=0x4D ReqsValid=0000000000181025 EntriesMatched=1 EntriesFilled=1 TagsFound=0000000000010000 AllReqsValid=0000000000181025
			// 		SymId 0x125: Tag=Data Name=Data3 Type=0x4D TypeId=0x4D DataKind=Member Offset=0x6 SymIndex=0x125 ReqsValid=000000000018129B EntriesMatched=4 EntriesFilled=4 TagsFound=0000000000000080 AllReqsValid=000000000018129B
			// 			SymId 0x4D: Tag=BaseType Length=0x2 BaseType=UInt Offset=0x0 SymIndex=0x4D ReqsValid=0000000000181025 EntriesMatched=1 EntriesFilled=1 TagsFound=0000000000010000 AllReqsValid=0000000000181025
			// 		SymId 0x126: Tag=Data Name=Data4 Type=0x127 TypeId=0x127 DataKind=Member Offset=0x8 SymIndex=0x126 ReqsValid=000000000018129B EntriesMatched=4 EntriesFilled=4 TagsFound=0000000000000080 AllReqsValid=000000000018129B
			// 			SymId 0x127: Tag=ArrayType Length=0x8 Type=0x16 TypeId=0x16 ArrayIndexTypeId=0x9 Offset=0x0 Count=0x8 SymIndex=0x127 ReqsValid=000000000018185D EntriesMatched=1 EntriesFilled=1 TagsFound=0000000000008000 AllReqsValid=000000000018185D
			// 				SymId 0x16: Tag=BaseType Length=0x1 BaseType=UInt Offset=0x0 SymIndex=0x16 ReqsValid=0000000000181025 EntriesMatched=1 EntriesFilled=1 TagsFound=0000000000010000 AllReqsValid=0000000000181025
			if (typinfo.hasName()) {
				fullname.append(typinfo.getAnsiName());
				//truncate(fullname, MAXNAMESIZE - 1);
				_ASSERTE(!fullname.empty());
			}
			if (types_created.by_id.find(typinfo.SymIndex) != types_created.by_id.end()
				|| !fullname.empty() && types_created.by_name.find(fullname) != types_created.by_name.end()) {
				if (accept_incomplete
					&& (tid = get_struc_id_anyway(fullname.c_str())) == BADNODE) tid = 0;
					break;
			}
			if (!fullname.empty() && (tid = get_struc_id(fullname.c_str())) != BADNODE)
				break;
			iter_id = types_created.by_id.insert(typinfo.SymIndex).first;
			_ASSERTE(iter_id != types_created.by_id.end());
			iter_name = !fullname.empty() ?
				types_created.by_name.insert(fullname).first : types_created.by_name.end();
			struc_t *struc = get_struc(add_struc(BADADDR, typinfo.hasName() ?
				fullname.c_str() : NULL, typinfo.UDTKind == UdtUnion));
			if (struc != 0) {
				tid = struc->id;
				LoadMembersFromPDB(typinfo, struc);
				++totalstructs;
				struc->props |= SF_HIDDEN;
				save_struc(struc);
			} else if (typinfo.hasName()) {
				if ((tid = get_struc_id_anyway(fullname.c_str())) == BADNODE) {
					if (get_validated_name(fullname.c_str(), validated_name)
						&& (struc = get_struc(add_struc(BADADDR, validated_name.c_str(),
						typinfo.UDTKind == UdtUnion))) != 0) {
						tid = struc->id;
						LoadMembersFromPDB(typinfo, struc);
						++totalstructs;
						struc->props |= SF_HIDDEN;
						save_struc(struc);
					}
				}
				tmptid = BADNODE;
				if (get_named_type(idati, fullname.c_str(), DEF_NTF_FLAGS, &type) > 0) {
					if (is_resolved_type_struni(type))
						tmptid = 0;
					/*else
						cmsg << log_prefix << "WARNING: couldnot create " << "struct" <<
							' ' << fullname << " (name conflict with different type)" << endl;*/
#ifdef _DEBUG
					else
						_RPT3(_CRT_WARN, "%s(...): Couldnot create %s %s (name conflict with diferrent type\n",
							__FUNCTION__, typinfo.UDTKind == UdtUnion ? "union" : "struct", fullname.c_str());
#endif // _DEBUG
				} else if ((Count = LoadMembersFromPDB(typinfo, tinfo, fnames, Align)) >= 0) {
					if (Count == 0) {
						// this is probably invalid!
						_ASSERTE(fnames.empty());
						_ASSERTE(tinfo.empty());
						//tinfo << pstring(); ???
						_RPT3(_CRT_WARN, "%s(...): Saving empty %s to til (\"%s\")\n",
							__FUNCTION__, typinfo.UDTKind == UdtUnion ? "union" : "struct",
							fullname.c_str());
					}
					// alignment calculation is very experimental and uncertain yet
					//Align = 0; //log2_64(get_default_align(inf.cc.cm)) + 1;
					tinfo.before(dt(Count << 3 | Align & 7));
					tinfo.before(BT_COMPLEX |
						(typinfo.UDTKind == UdtUnion ? BTMT_UNION : BTMT_STRUCT));
#ifdef _DEBUG
					OutputDebugString("%s(...): Saving %s %s to til: %li members, alignment=%u\n",
						__FUNCTION__, typinfo.UDTKind == UdtUnion ? "union" : "struct",
						fullname.c_str(), Count, Align);
					print_type_to_many_lines(dbg_printer, __FUNCTION__, "    ", 2, 30,
						idati, tinfo, fullname.c_str(), NULL, !fnames.empty() ? fnames.c_str() : NULL);
#endif // _DEBUG
					if ((tmptid = ::set_named_type(fullname.c_str(), tinfo, fnames)) == 0) {
						++totalstructs;
						// structs stored to til are most probably not accessible via
						// get_struc/get_struc_id API - they must be synchronized to idb
						// first, unfortunatelly I found no exported API to do this
						if ((tmptid = get_struc_id(fullname.c_str())) == BADNODE) tmptid = 0;
						OutputDebugString("%s(...): %s %s stored successfully to til (%li members, tid=%08lX)\n",
							__FUNCTION__, typinfo.UDTKind == UdtUnion ? "Union" : "Struct",
							fullname.c_str(), Count, tmptid);
					}
				} // LoadMembers... ok
				if (tid == BADNODE) tid = tmptid;
			} // has name
			if (iter_name != types_created.by_name.end()) types_created.by_name.erase(iter_name);
			/*if (iter_id != types_created.by_id.end()) */types_created.by_id.erase(iter_id);
			break;
		} // SymTagUDT
		case SymTagEnum:
			// myenum: Index=0x36 TypeIndex=0x36 Value=0x0 Tag=Enum ModBase=0000000000400000
			//   SymId 0x36: Tag=Enum Name=myenum Length=0x4 Type=0x4 TypeId=0x4 BaseType=Int Offset=0x0 ChildrenCount=0x4 SymIndex=0x36 LexicalParent=0x5 ReqsValid=00000000001C103F
			//     SymId 0x4: Tag=BaseType Length=0x4 BaseType=Int Offset=0x0 SymIndex=0x4 LexicalParent=0x5 ReqsValid=0000000000181025
			//     SymId 0x37: Tag=Data Name=enumember1 DataKind=Constant Offset=0x0 SymIndex=0x37 LexicalParent=0x5 ReqsValid=0000000000181483
			//     SymId 0x38: Tag=Data Name=enumember2 DataKind=Constant Offset=0x0 SymIndex=0x38 LexicalParent=0x5 ReqsValid=0000000000181483
			//     SymId 0x39: Tag=Data Name=enumember3 DataKind=Constant Offset=0x0 SymIndex=0x39 LexicalParent=0x5 ReqsValid=0000000000181483
			//     SymId 0x3A: Tag=Data Name=enumember4 DataKind=Constant Offset=0x0 SymIndex=0x3A LexicalParent=0x5 ReqsValid=0000000000181483
			_ASSERTE(typinfo.hasName());
			if (typinfo.hasName()) {
				fullname.append(typinfo.getAnsiName());
				//truncate(fullname, MAXNAMESIZE - 1);
				_ASSERTE(!fullname.empty());
			}
			if (types_created.by_id.find(typinfo.SymIndex) != types_created.by_id.end()
				|| !fullname.empty() && types_created.by_name.find(fullname) != types_created.by_name.end()) {
				if (accept_incomplete
					&& (tid = (tid_t)get_enum_anyway(fullname.c_str())) == BADNODE) tid = 0;
				break;
			}
			if (!fullname.empty() && (tid = (tid_t)get_enum(fullname.c_str())) != BADNODE)
				break;
			_ASSERTE(typinfo.TypeId != 0);
			if (typinfo.TypeId == 0 || !basetype(typinfo.TypeId)) break;
#ifdef _DEBUG
			if (basetype.SymIndex != 0) {
				if (typinfo.BaseType != basetype.BaseType) _RPTF3(_CRT_ASSERT,
					"%s(...): typinfo.BaseType != basetype.BaseType (0x%lX != 0x%lX)\n",
					__FUNCTION__, typinfo.BaseType, basetype.BaseType);
				if (typinfo.Length != basetype.Length) _RPTF3(_CRT_ASSERT,
					"%s(...): typinfo.Length != basetype.Length (0x%I64X != 0x%I64X)\n",
					__FUNCTION__, typinfo.Length, basetype.Length);
			}
#endif // _DEBUG
			iter_id = types_created.by_id.insert(typinfo.SymIndex).first;
			_ASSERTE(iter_id != types_created.by_id.end());
			iter_name = !fullname.empty() ?
				types_created.by_name.insert(fullname).first : types_created.by_name.end();
			if ((tid = (tid_t)add_enum(BADADDR, typinfo.hasName() ?
				fullname.c_str() : NULL,
				getFlags(basetype.SymIndex != 0 ? basetype : typinfo))) != BADNODE) {
				//set_enum_flag((enum_t)tid, getFlags(basetype.SymIndex != 0 ? basetype : typinfo));
				set_ti(tid, basetype.SymIndex != 0 ? basetype : typinfo);
				LoadConstsFromPDB(typinfo, (enum_t)tid);
				++totalenums;
				set_enum_hidden((enum_t)tid, true);
			} else if (typinfo.hasName()) {
				if ((tid = (enum_t)get_enum_anyway(fullname.c_str())) == BADNODE) {
					if (get_validated_name(fullname.c_str(), validated_name)
						&& (tmptid = (tid_t)add_enum(BADADDR, validated_name.c_str(),
						getFlags(basetype.SymIndex != 0 ? basetype : typinfo))) != BADNODE) {
						tid = tmptid;
						//set_enum_flag((enum_t)tid, getFlags(basetype.SymIndex != 0 ? basetype : typinfo));
						set_ti(tid, basetype.SymIndex != 0 ? basetype : typinfo);
						LoadConstsFromPDB(typinfo, (enum_t)tid);
						++totalenums;
						set_enum_hidden((enum_t)tid, true);
					}
				}
				tmptid = BADNODE;
				if (get_named_type(idati, fullname.c_str(), DEF_NTF_FLAGS, &type) > 0) {
					if (is_resolved_type_enum(type))
						tmptid = 0;
					/*else
						cmsg << log_prefix << "WARNING: couldnot create " << "enum" <<
							' ' << fullname << " (name conflict with different type)" << endl;*/
#ifdef _DEBUG
					else
						_RPT3(_CRT_WARN, "%s(...): Couldnot create %s %s (name conflict with diferrent type\n",
							__FUNCTION__, "enum", fullname.c_str());
#endif // _DEBUG
				} else if ((Count = LoadConstsFromPDB(typinfo, tinfo, fnames)) >= 0) {
#ifdef _DEBUG
					if (Count == 0) _RPT3(_CRT_WARN, "%s(...): Saving empty %s to til (\"%s\")\n",
						__FUNCTION__, "enum", fullname.c_str());
#endif // _DEBUG
					Align = 0;
					const ULONG64 Size = get_type_size(typinfo);
					if (Size > 0 && (Align = log2_64(Size)) < BTE_SIZE_MASK)
						if (Size == 1ULL << Align) ++Align; else Align = 0;
					tinfo.before(BTE_ALWAYS | Align & BTE_SIZE_MASK);
					tinfo.before(dt(Count));
					tinfo.before(BTF_ENUM);
#ifdef _DEBUG
					OutputDebugString("%s(...): Saving %s %s to til:\n", __FUNCTION__, "enum", fullname.c_str());
					print_type_to_many_lines(dbg_printer, __FUNCTION__, "    ", 2, 30,
						idati, tinfo, fullname.c_str(), NULL, !fnames.empty() ? fnames.c_str() : NULL);
#endif // _DEBUG
					if ((tmptid = ::set_named_type(fullname.c_str(), tinfo, fnames)) == 0) {
						++totalenums;
						// enums stored to til are most probably not accessible via
						// get_enum API - they must be synchronized to idb first,
						// unfortunatelly I found no exported API to do this
						if ((tmptid = (tid_t)get_enum(fullname.c_str())) == BADNODE) tmptid = 0;
						OutputDebugString("%s(...): %s %s stored successfully to til (%li members, tid=%08lX)\n",
							__FUNCTION__, "Enum", fullname.c_str(), Count, tmptid);
					}
				} // LoadConsts... ok
				if (tid == BADNODE) tid = tmptid;
			} // has name
			if (iter_name != types_created.by_name.end()) types_created.by_name.erase(iter_name);
			/*if (iter_id != types_created.by_id.end()) */types_created.by_id.erase(iter_id);
			break;
		case SymTagTypedef:
			// DWORD: Index=0xF7 TypeIndex=0xF7 Value=0x0 Tag=Typedef ModBase=0000000000400000
			//   SymId 0xF7: Tag=Typedef Name=DWORD Type=0x52 TypeId=0x52 SymIndex=0xF7
			//     SymId 0x52: Tag=BaseType Length=0x4 BaseType=ULong SymIndex=0x52
			_ASSERTE(typinfo.hasName());
			if (!typinfo.hasName()) break;
			fullname.append(typinfo.getAnsiName());
			//truncate(fullname, MAXSTR/*MAXNAMESIZE*/ - 1); // is typename len limited?
			_ASSERTE(!fullname.empty());
			//if (fullname.empty()) break;
			if (types_created.by_id.find(typinfo.SymIndex) != types_created.by_id.end()
				|| types_created.by_name.find(fullname) != types_created.by_name.end()) {
				if (accept_incomplete && (tid = get_named_type(fullname.c_str())) == BADNODE)
					tid = 0;
				break;
			}
			if ((tid = get_named_type(fullname.c_str())) != BADNODE) break;
			_ASSERTE(typinfo.TypeId != 0);
			if (typinfo.TypeId == 0 || !basetype(typinfo.TypeId)) break;
			iter_id = types_created.by_id.insert(typinfo.SymIndex).first;
			_ASSERTE(iter_id != types_created.by_id.end());
			iter_name = types_created.by_name.insert(fullname).first;
			_ASSERTE(iter_name != types_created.by_name.end());
			if ((tid = set_named_type(fullname.c_str(), basetype,
				DEF_NTF_FLAGS, &sc_tdef)) == 0) ++totaltypedefs;
			basetype.Name.Empty();
			/*if (iter_name != types_created.by_name.end()) */types_created.by_name.erase(iter_name);
			/*if (iter_id != types_created.by_id.end()) */types_created.by_id.erase(iter_id);
			break;
#ifdef _DEBUG
		case SymTagBaseType:
		case SymTagPointerType:
		case SymTagFunction:
			break;
		default:
			_RPTF2(_CRT_WARN, "%s(...): Unhandled type %s\n", __FUNCTION__,
				typinfo.TokenizeSymTag().c_str());
#endif // _DEBUG
	}
	return tid;
}

static void SymResetContext() {
	if (pSymSetContext != NULL) {
		IMAGEHLP_STACK_FRAME stack_frame;
		memset(&stack_frame, 0, sizeof stack_frame);
		pSymSetContext(hProcess, &stack_frame, NULL);
	}
}

static BOOL CALLBACK SymEnumFrameProc(PSYMBOL_INFO pSymInfo, ULONG SymbolSize,
	PVOID UserContext) {
	_ASSERTE(pSymInfo != 0);
	_ASSERTE(UserContext != NULL);
	if (pSymInfo == 0 || wasBreak() || UserContext == NULL) return FALSE;
	/*
	OutputDebugString("  @@%c%08I64X: %s Tag=%s Size=0x%lX SymbolSize=0x%lX Flags=%s Index=0x%lX TypeIndex=0x%lX Value=0x%I64X Register=%s Scope=0x%lX NameLen=0x%lX ModBase=%016I64X\n",
		SIGNED_PAIR(static_cast<int64>(pSymInfo->Address)),
		pSymInfo->Name, TokenizeSymTag((enum SymTagEnum)pSymInfo->Tag).c_str(),
		pSymInfo->Size, SymbolSize, TokenizeSymFlag(pSymInfo->Flags).c_str(),
		pSymInfo->Index, pSymInfo->TypeIndex, pSymInfo->Value,
		ix86_getRegCanon((CV_HREG_e)pSymInfo->Register), pSymInfo->Scope,
		pSymInfo->NameLen, pSymInfo->ModBase);
	*/
	if (pSymInfo->Size == 0) pSymInfo->Size = SymbolSize;
	//static_cast<loc_p>(UserContext)->push_back(loc_t::value_type(*pSymInfo, pSymInfo->Name));
	SYMBOL_INFO SymInfo(*pSymInfo);
	const string Name(pSymInfo->Name);
	SymInfo.Name[0] = 0;
	if (pSymGetScope != NULL && pSymGetScope(hProcess, SymBase, pSymInfo->Index, pSymInfo))
		SymInfo.Scope = pSymInfo->Scope;
	OutputDebugString("  @@%c%08I64X: %s Tag=%s Size=0x%lX SymbolSize=0x%lX Flags=%s Index=0x%lX TypeIndex=0x%lX Value=0x%I64X Register=%s Scope=0x%lX NameLen=0x%lX ModBase=%016I64X\n",
		SIGNED_PAIR(static_cast<int64>(SymInfo.Address)),
		Name.c_str(), TokenizeSymTag((enum SymTagEnum)SymInfo.Tag).c_str(),
		SymInfo.Size, SymbolSize, TokenizeSymFlag(SymInfo.Flags).c_str(),
		SymInfo.Index, SymInfo.TypeIndex, SymInfo.Value,
		ix86_getRegCanon((CV_HREG_e)SymInfo.Register), SymInfo.Scope,
		SymInfo.NameLen, SymInfo.ModBase);
	static_cast<loc_p>(UserContext)->push_back(loc_t::value_type(SymInfo, Name));
	return TRUE;
}

// care: SYMBOL_INFO* buffer reused
static bool GetLocalsFor(ULONG64 Address, loc_t &locals) {
	_ASSERTE(Address != 0);
	if (pSymSetContext == NULL || Address == 0) return false;
	locals.clear();
	IMAGEHLP_STACK_FRAME stack_frame;
	memset(&stack_frame, 0, sizeof stack_frame);
	stack_frame.InstructionOffset = Address;
	//stack_frame.FuncTableEntry = pSymFunctionTableAccess64 != NULL ?
	//	(ULONG64)pSymFunctionTableAccess64(hProcess, Address) : 0;
	if (pSymSetContext(hProcess, &stack_frame, NULL) != FALSE
		&& pSymEnumSymbols(hProcess, NULL, NULL, SymEnumFrameProc, &locals) != FALSE) {
		if (!locals.empty()) {
			//stable_sort(CONTAINER_RANGE(locals), loc_t::less);
			return true;
		}
	}
	return false;
}

static BOOL CALLBACK SymEnumSymbolsProc(PSYMBOL_INFO pSymInfo, ULONG SymbolSize,
	PVOID UserContext = NULL) {
	_ASSERTE(pSymInfo != 0);
	if (pSymInfo == 0) return FALSE;
	const ea_t ea = static_cast<ea_t>(pSymInfo->Address) + Delta;
	_ASSERTE(isEnabled(ea));
	if (!isEnabled(ea)) return TRUE;
	showAddr(ea);
	if (wasBreak()) return FALSE;
	OutputDebugString("%08IX: %-.1023s Tag=%s Size=0x%lX SymbolSize=0x%lX Flags=%s Index=0x%lX TypeIndex=0x%lX Value=0x%I64X Register=%s Scope=0x%lX NameLen=0x%lX ModBase=%016I64X\n",
		ea/*pSymInfo->Address*/, pSymInfo->Name,
		TokenizeSymTag((enum SymTagEnum)pSymInfo->Tag).c_str(), pSymInfo->Size,
		SymbolSize, TokenizeSymFlag(pSymInfo->Flags).c_str(), pSymInfo->Index,
		pSymInfo->TypeIndex, pSymInfo->Value,
		ix86_getRegCanon((CV_HREG_e)pSymInfo->Register), pSymInfo->Scope,
		pSymInfo->NameLen, pSymInfo->ModBase);
	if (UserContext != NULL) {
		const sym_t::iterator i(static_cast<sym_p>(UserContext)->find(ea));
		if (i == static_cast<sym_p>(UserContext)->end())
			static_cast<sym_p>(UserContext)->insert(sym_t::value_type(ea, pSymInfo->Name));
		else if (pSymInfo->Tag == SymTagPublicSymbol)
			i->second.assign(pSymInfo->Name);
#ifdef _DEBUG
		else
			_RPTF4(_CRT_WARN, "%s(...): second SymbolInfo entry not of type PublicSymbol (Tag=%s ea=%08IX Name=%s)\n",
				__FUNCTION__, TokenizeSymTag((enum SymTagEnum)pSymInfo->Tag).c_str(),
				ea, pSymInfo->Name);
#endif // _DEBUG
	}
	ULONG64 size = is_extern(ea) ? get_ptr_size(FF_DATA) : pSymInfo->Size; // unreliable for functions
	if (size == 0) size = SymbolSize;
	const SYMBOL_INFO SymInfo(*pSymInfo);
#ifdef _DEBUG
	const string Name(pSymInfo->Name);
#endif // _DEBUG
	if (SymInfo.TypeIndex != 0) {
		const typeinfoex_t typinfo(SymInfo);
		_ASSERTE(typinfo.SymIndex != 0);
		if (size <= 0) size = get_type_size(typinfo);
		if ((SymInfo.Tag == SymTagFunction || SymInfo.Tag == SymTagThunk
			/*|| (SymInfo.Flags & SYMFLAG_FUNCTION) != 0*/) && !is_spec_ea(ea)) {
			loc_t locals;
			if (GetLocalsFor(SymInfo.Address, locals)
				&& set_ti(ea, typinfo, &locals)) ++totaltypeinfos;
		} else if (SymInfo.Tag == SymTagData || is_extern(ea)) {
			const flags_t flags(is_extern(ea) ? ptrflag() : getFlags(typinfo));
			if (isData(flags)) {
				const typeinfo_t ri =
#if IDP_INTERFACE_VERSION < 76
					{ get_default_reftype(ea), 0, BADADDR, 0, 0 };
#else // IDP_INTERFACE_VERSION >= 76
					{ BADADDR, 0, 0, get_default_reftype(ea) };
#endif
				typeinfo_t ti;
				const typeinfo_t *const pti(is_extern(ea) ? &ri : get_typeinfo(typinfo, ti, ea));
#ifdef _DEBUG
				typeinfo_t oldti, *const poldti(get_typeinfo(ea, 0, flags, &oldti));
				OutputDebugString("%08IX: idabase flags=%s has_typeinfo?%s size=0x%IX\n", ea, flags2str(::getFlags(ea)).c_str(), poldti != 0 ? "yes":"no", get_item_size(ea));
				OutputDebugString("                  pdb flags=%s has_typeinfo?%s size=0x%I64X\n", flags2str(flags).c_str(), pti != 0 ? "yes":"no", size);
#endif // _DEBUG
				if (do_data_ex(ea, flags, pti, static_cast<asize_t>(size))) ++totaldata;
			}
#ifdef _DEBUG
			else
				_RPT3(_CRT_WARN, "%s(...): no data type from typeinfoex_t at %08IX: %-.3840s\n",
					__FUNCTION__, ea, Name.c_str());
#endif // _DEBUG
			if (set_ti(ea, typinfo)) ++totaltypeinfos;
		}
#ifdef _DEBUG
		else
			_RPT3(_CRT_WARN, "%s(...): %08IX: item of unknown type (%s)\n", __FUNCTION__,
				ea, TokenizeSymTag((enum SymTagEnum)SymInfo.Tag).c_str());
#endif // _DEBUG
	} // got typeinfo
	// create function?
	if ((SymInfo.Tag == SymTagFunction || SymInfo.Tag == SymTagThunk)
		&& !is_spec_ea(ea)) {
		ea_t endEA = size != 0 ? ea + size : BADADDR;
		func_t *func = get_func(ea);
		if (func == 0 || func->startEA != ea/* || endEA != BADADDR && func->endEA != endEA*/) {
			del_func(ea);
			if (size != 0) {
				do_unknown_range(ea, size, false);
				for (ea_t ip = ea; ip < endEA; ip = next_not_tail(ip))
					if (ua_code(ip) == 0) break;
			}
			if (add_func(ea, BADADDR/*endEA*/)) ++totalfuncs; // endEA may nonsense
		}
		if ((func = get_func(ea)) != 0) {
			const ushort flags = func->flags;
			//if (Symbol.Virtual) func->flags |= FUNC_VIRTUAL;
			//if (Symbol.Pure) func->flags |= FUNC_PUREVIRTUAL;
			if (SymInfo.Tag == SymTagThunk) func->flags |= FUNC_THUNK; // ???
			if (SymInfo.TypeIndex != 0) {
				typeinfoex_t typinfo(SymInfo);
				if ((typinfo.SymTag == SymTagFunction || typinfo.SymTag == SymTagThunk)
					&& typinfo.TypeId != 0 && typinfo(typinfo.TypeId)
					&& typinfo.SymTag == SymTagFunctionType && is_far_call(typinfo.CallConv))
						func->flags |= FUNC_FAR;
			}
			if (func->flags != flags) update_func(func);
		}
	} // create func
	return TRUE;
}

static BOOL CALLBACK SymEnumLocalsProc(PSYMBOL_INFO pSymInfo, ULONG SymbolSize,
	PVOID UserContext) {
	_ASSERTE(pSymInfo != 0);
	if (pSymInfo == 0) return FALSE;
	const ea_t ea((ea_t)pSymInfo->Address + Delta);
	showAddr(ea); // keep user alive
	if (wasBreak()) return FALSE;
	if (pSymInfo->Tag == SymTagFunction && isFunc(get_flags_novalue(ea)) && !is_spec_ea(ea)) {
		OutputDebugString("%08IX: %-.1023s Tag=%s Size=0x%lX SymbolSize=0x%lX Flags=%s Index=0x%lX TypeIndex=0x%lX Value=0x%I64X Register=%s Scope=0x%lX NameLen=0x%lX ModBase=%016I64X\n",
			ea/*pSymInfo->Address*/, pSymInfo->Name,
			TokenizeSymTag((enum SymTagEnum)pSymInfo->Tag).c_str(), pSymInfo->Size,
			SymbolSize, TokenizeSymFlag(pSymInfo->Flags).c_str(), pSymInfo->Index,
			pSymInfo->TypeIndex, pSymInfo->Value,
			ix86_getRegCanon((CV_HREG_e)pSymInfo->Register), pSymInfo->Scope,
			pSymInfo->NameLen, pSymInfo->ModBase);
		func_t *const func(get_func(ea));
		_ASSERTE(func != 0);
		if (func != 0) try {
			const asize_t retsize(get_frame_retsize(func));
			_ASSERTE(func->frsize + func->frregs + retsize + func->argsize ==
				get_frame_size(func)); // get_struc_size(frame) may be bigger!
			adiff_t frame_sp_delta(func->frsize - ix86_get_frame_locals(func));
			if (frame_sp_delta < 0) {
				frame_sp_delta = 0;
				_RPT1(_CRT_WARN, "%s(...): suspicious frame_sp_delta (<0)\n", __FUNCTION__);
			}
			bool func_changed(false);
			ULONG64 func_size(pSymInfo->Size);
			if (func_size == 0) func_size = SymbolSize;
			const ea_t endEA(func_size > 0 ? ea + func_size : BADADDR);
			/*
			if (endEA != BADADDR && func->endEA != endEA) {
				if (!func_setend(func->startEA, endEA))
					func->endEA = endEA; // force
				else
					analyze_area(*func);
				func_changed = true;
			}
			*/
			struc_t *const frame(get_frame(func));
			if (frame != 0) {
				loc_t locals;
				if (GetLocalsFor(pSymInfo->Address, locals)) {
					ostringstream cmts;
					for (loc_t::const_iterator i = locals.begin(); i != locals.end(); ++i) {
						_ASSERTE(i->first.TypeIndex != 0);
						if (i->first.Tag != SymTagData) {
							_RPTF2(_CRT_WARN, "%s(...): unhandled type %s\n", __FUNCTION__,
								TokenizeSymTag((enum SymTagEnum)i->first.Tag));
							continue;
						}
						typeinfoex_t typinfo(i->first);
						ea_t frame_offset;
						member_t *stkvar;
						flags_t flags;
						char mnem[16];
						switch (i->first.Flags & (SYMFLAG_LOCAL | SYMFLAG_PARAMETER | SYMFLAG_REGREL | SYMFLAG_REGISTER)) {
							case SYMFLAG_LOCAL | SYMFLAG_REGREL:
							case SYMFLAG_LOCAL | SYMFLAG_REGREL | SYMFLAG_PARAMETER: {
								if ((func->flags & FUNC_FRAME) != 0
									&& (i->first.Register == CV_REG_EBP || i->first.Register == CV_REG_BP))
									frame_offset = ((func->flags & FUNC_BOTTOMBP) == 0 ?
										func->frsize : frame_sp_delta) + (ea_t)i->first.Address;
								else if (i->first.Register == CV_REG_ESP || i->first.Register == CV_REG_SP)
									frame_offset = frame_sp_delta + (ea_t)i->first.Address;
								else {
									_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
										"%s(...): local symbol '%s' unknown location: flags=%s address=%016I64X register=%s bp_frame?%s\n",
										__FUNCTION__, i->second.c_str(), TokenizeSymFlag(i->first.Flags).c_str(),
										i->first.Address, ix86_getRegCanon((CV_HREG_e)i->first.Register),
										(func->flags & FUNC_FRAME) != 0 ? "yes":"no");
									break;
								}
							dolocal:
								asize_t arg_size(i->first.Size);
								if (arg_size == 0) arg_size = get_type_size(typinfo);
								stkvar = get_member_by_name(frame, i->second.c_str());
								ea_t dupeoff;
								char newname[MAXNAMESIZE];
								uint suffix;
								if (stkvar != 0 && (dupeoff = stkvar->get_soff()) != frame_offset) {
									_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
										"%s(...): @@%c%08IX[%08IX]=%-.1023s (size=0x%IX) name conflict: old member at %08IX (size=0x%IX)\n",
										__FUNCTION__, i->first.Address >> 63 == 0 ? '+':'-',
										i->first.Address >> 63 == 0 ? (ea_t)i->first.Address : -(ea_t)i->first.Address,
										frame_offset, i->second.c_str(), arg_size, stkvar->get_soff(),
										get_member_size(stkvar));
									suffix = 1;
									do
										qsnprintf(CPY(newname), "%s_%u", i->second.c_str(), ++suffix);
									while (get_member_by_name(frame, newname) != 0);
									if (get_member_by_name(frame, newname) == 0)
										set_member_name(frame, dupeoff, newname);
#ifdef _DEBUG
									else
										_RPT1(_CRT_WARN, "%s(...): name conflict above not resolved\n",
											__FUNCTION__);
#endif // _DEBUG
								} // name conflict
								flags = 0;
								if (typinfo.SymIndex != 0) {
									flags = getFlags(typinfo);
									typeinfo_t ti, *pti(get_typeinfo(typinfo, ti, ea));
									if (isData(flags)) {
										del_struc_members(frame, frame_offset, frame_offset + arg_size);
										func_changed = true;
										int err(add_struc_member_anyway(frame, i->second.c_str(),
											frame_offset, flags, pti, arg_size));
										if (err == 0 || (err = add_struc_member_anyway(frame,
											i->second.c_str(), frame_offset, flags = byteflag(),
											pti = 0, arg_size)) == 0) {
											++totalnames;
											++totaldata;
											OutputDebugString("  @@%c%08IX[%08IX]=%-.1023s (flags=%s has_typeinfo?%s size=0x%IX)\n",
												i->first.Address >> 63 == 0 ? '+':'-', i->first.Address >> 63 == 0 ? (ea_t)i->first.Address : -(ea_t)i->first.Address,
												frame_offset, i->second.c_str(), flags2str(flags).c_str(),
												pti != 0 ? "yes":"no", arg_size);
										}
									}
#ifdef _DEBUG
									else
										_RPTF4(_CRT_WARN, "%s(...): not data type for arguemnt though typeinfo present for %08IX:%08IX (flags=%08lX)\n",
											__FUNCTION__, ea, (ea_t)i->first.Address, flags);
#endif // _DEBUG
									if ((stkvar = get_member(frame, frame_offset)) != 0)
										if (set_member_ti(frame, stkvar, typinfo, true)) {
											++totaltypeinfos;
											func_changed = true;
										} else try {
											typestring type;
											char cmt[MAXSTR];
											if (get_ti(typinfo, type)
												&& print_type_to_one_line(CPY(cmt), idati, type) == T_NORMAL)
												set_member_cmt(stkvar, cmt, true);
										} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
											_RPT2(_CRT_WARN, "%s(...): %s\n", __FUNCTION__, e.what());
											if (typeid(e) != typeid(not_convertible)) PrintTypeInfoEx(typinfo);
#endif // _DEBUG
										}
								} // have typeinfo
								if (!isData(flags) // don't touch the stkvar, rename only
									&& set_member_name(frame, frame_offset, i->second.c_str())) {
									++totalnames;
									func_changed = true;
								}
								break;
							} // SYMFLAG_LOCAL | SYMFLAG_REGREL
							case SYMFLAG_LOCAL | SYMFLAG_REGISTER: // local register variable
							case SYMFLAG_LOCAL | SYMFLAG_REGISTER | SYMFLAG_PARAMETER: {
								const RegNo reg = ix86_getReg((CV_HREG_e)i->first.Register);
								const asize_t regbits = ix86_getRegBitness((CV_HREG_e)i->first.Register) >> 3;
								// TODO: find safely load point (if any) for register parameters/local variables
								// (no hints from PDB except register name cause ambiguous assignments very often)
								/*
								if ((i->first.Flags & SYMFLAG_PARAMETER) == 0) {
									if (add_regvar(func, scan, func->endEA, ix86_getRegCanon((CV_HREG_e)i->first.Register),
										i->second.c_str(), NULL) == REGVAR_ERROR_OK) {
										++totalnames; // ???
										func_changed = true;
										_RPT3(_CRT_WARN, "%s(...): register variable created: %s=%s (no stack storage)\n",
											__FUNCTION__, ix86_getRegCanon((CV_HREG_e)i->first.Register), i->second.c_str());
									}
								} else { // very experimental
									typestring type;
									if (typinfo.SymIndex != 0) try {
										get_ti(typinfo, type);
									} catch (const not_convertible &e) {
										_RPT2(_CRT_WARN, "%s(...): %s\n", __FUNCTION__, e.what());
										if (typeid(e) != typeid(not_convertible)) PrintTypeInfoEx(typinfo);
									}
									add_regarg(func, ix86_getReg((CV_HREG_e)i->first.Register), type, i->second.c_str());
									++totalnames; // ???
								}
								*/
								cmts << ix86_getRegCanon((CV_HREG_e)i->first.Register) <<
									'=' << i->second << " (" << TokenizeSymFlag(i->first.Flags) << ')' << endl;
								break;
							} // SYMFLAG_LOCAL | SYMFLAG_REGISTER
							case 0: // local static variable??
							case SYMFLAG_LOCAL: // local static variable??
								if (!i->second.empty() && apply_static_name((ea_t)i->first.Address + Delta, i->second.c_str()))
									++totalnames;
								SymEnumSymbolsProc((PSYMBOL_INFO)&i->first, i->first.Size);
								break;
#ifdef _DEBUG
							default:
								_RPTF3(_CRT_WARN, "%s(...): unhandled arg[%Iu] (SYBOL_INFO.Flags=%s)\n",
									__FUNCTION__, distance((loc_t::const_iterator)locals.begin(), i),
									TokenizeSymFlag(i->first.Flags).c_str());
								PrintTypeInfoEx(typinfo);
#endif // _DEBUG
						} // switch flags
						typinfo.Name.Empty();
					} // iterate local names
					string cmt(cmts.str());
					if (!cmt.empty()) {
						cmt.erase(back_pos(cmt)); // cut last eoln
						_ASSERTE(!cmt.empty());
						set_func_cmt(func, cmt.c_str(), false);
					}
					if (func_changed) save_struc(frame);
				} // have locals
			} // got frame
#ifdef _DEBUG
			else
				_RPT1(_CRT_WARN, "%s(...): get_frame(func) returned NULL\n", __FUNCTION__);
#endif // _DEBUG
			if (func_changed) reanalyze_function(func, func->startEA, func->endEA, true);
		} catch (GENERAL_CATCH_FILTER) {
			_RPT3(_CRT_WARN, "%s(...): %s (%s)\n", __FUNCTION__, e.what(), typeid(e).name());
		} // got func
#ifdef _DEBUG
		else
			_RPT2(_CRT_WARN, "%s(...): get_func(%08IX) returned NULL\n", __FUNCTION__, ea);
#endif // _DEBUG
	}
	return TRUE;
}

static BOOL CALLBACK SymEnumTypesProc(PSYMBOL_INFO pSymInfo, ULONG SymbolSize,
	PVOID UserContext) {
	_ASSERTE(pSymInfo != NULL);
	if (pSymInfo == NULL || wasBreak()) return FALSE;
	/*
	OutputDebugString("%-.1023s: Flags=%s Index=0x%lX TypeIndex=0x%lX Value=0x%I64X Register=%s Scope=0x%lX Tag=%s Address=%016I64X ModBase=%016I64X\n",
		pSymInfo->Name, TokenizeSymFlag(pSymInfo->Flags).c_str(), pSymInfo->Index,
		pSymInfo->TypeIndex, pSymInfo->Value,
		ix86_getRegCanon((CV_HREG_e)pSymInfo->Register), pSymInfo->Scope,
		TokenizeSymTag((enum SymTagEnum)pSymInfo->Tag).c_str(), pSymInfo->Address,
		pSymInfo->ModBase);
	*/
	if (pSymInfo->TypeIndex != 0) {
		const typeinfoex_t typinfo(pSymInfo);
		if (typinfo() && (typinfo.SymTag == SymTagUDT || typinfo.SymTag == SymTagEnum
			|| typinfo.SymTag == SymTagTypedef) && typinfo.ClassParentId == 0
			/*&& typinfo.Nested == 0 ???*/)
			if (UserContext != NULL) {
				static_cast<types_p>(UserContext)->Add(typinfo);
			} else
				CreateTypeFromPDB(typinfo);
	}
	return TRUE; // continue
}

static BOOL CALLBACK SymEnumLinesProc(PSRCCODEINFO LineInfo, PVOID UserContext) {
	_ASSERTE(LineInfo != NULL);
	_ASSERTE(UserContext != NULL);
	if (LineInfo == NULL || wasBreak() || UserContext == NULL) return FALSE;
	SRCCODEINFO lineinfo(*LineInfo);
	lineinfo.Address += Delta;
	showAddr(static_cast<ea_t>(lineinfo.Address)); // keep user alive
	_ASSERTE(LineInfo->FileName[0] != 0);
	if (LineInfo->FileName[0] != 0) static_cast<ln_p>(UserContext)->
		operator [](LineInfo->FileName)[lineinfo.LineNumber].insert(lineinfo);
	return TRUE;
}

static bool ProcessSymbols() {
	cmsg << log_prefix << "Loading symbols...";
	totalnames = 0;
	totaltypedefs = 0;
	totaltypeinfos = 0;
	totaldata = 0;
	totalfuncs = 0;
	pSymSetOptions(SYMOPT_LOAD_LINES);
	sym_t symbols;
	SymResetContext();
	BOOL ok(pSymEnumSymbols(hProcess, (DWORD)SymBase, NULL, SymEnumSymbolsProc, &symbols));
	if (ok == FALSE) error_msg("SymEnumSymbols");
	pSymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_PUBLICS_ONLY);
	SymResetContext();
	ok = pSymEnumSymbols(hProcess, (DWORD)SymBase, NULL, SymEnumSymbolsProc, &symbols);
	if (ok == FALSE) error_msg("SymEnumSymbols");
	cmsg << "done: " << dec << symbols.size() << " symbols" << endl;
	if (!symbols.empty())
		for (sym_t::const_iterator i = symbols.begin(); i != symbols.end(); ++i)
			if (apply_static_name(i->first, i->second.c_str())) ++totalnames;
		/*
		for_each(CONTAINER_RANGE(symbols),
			if_(bind(apply_static_name(bind(&sym_t::value_type::first, _1),
				bind(&sym_t::value_type::second::c_str, _1))))[++var(totalnames)]);
		*/
	msg("%sTotal %u symbol%s named, %u data type%s created, %u function%s created, %u typeinfo%s set\n",
		log_prefix, totalnames, totalnames != 1 ? "s" : "",
		totaldata, totaldata != 1 ? "s" : "",
		totalfuncs, totalfuncs != 1 ? "s" : "",
		totaltypeinfos, totaltypeinfos != 1 ? "s" : "");
#ifdef _DEBUG
	if (totaltypedefs > 0) _RPT2(_CRT_WARN, "%s(): totaltypedefs=%u\n", __FUNCTION__, totaltypedefs);
#endif // _DEBUG
	return ok != FALSE;
}

static bool ProcessTypes() {
	pSymSetOptions(SYMOPT_LOAD_LINES);
	SymResetContext();
	types_t types;
	totalstructs = 0;
	totalenums = 0;
	totaltypedefs = 0;
	totaltypeinfos = 0;
	totaldata = 0;
	totalfuncs = 0;
	cmsg << log_prefix << "Loading types...";
	const BOOL ok(pSymEnumTypes(hProcess, (DWORD)SymBase, SymEnumTypesProc, &types));
	cmsg << "done" << endl;
	if (ok == FALSE) error_msg("SymEnumTypes");
	if (!types.empty()) {
		types.SaveTypes();
		types.clear();
	}
	msg("%sTotal %u struct%s, %u enum%s, %u typedef%s, %u typeinfo%s set, %u data type%s created, %u function%s created\n",
		log_prefix, totalstructs, totalstructs != 1 ? "s" : "",
		totalenums, totalenums != 1 ? "s" : "",
		totaltypedefs, totaltypedefs != 1 ? "s" : "",
		totaltypeinfos, totaltypeinfos != 1 ? "s" : "",
		totaldata, totaldata != 1 ? "s" : "",
		totalfuncs, totalfuncs != 1 ? "s" : "");
	return ok != FALSE;
}

static bool ProcessLines() {
	if (pSymEnumLines == NULL) return true;
	cmsg << log_prefix << "Loading source lines...";
	SymResetContext();
	ln_t sourcelines;
	BOOL ok = pSymEnumLines(hProcess, static_cast<ULONG64>(SymBase),
		NULL, NULL, SymEnumLinesProc, &sourcelines);
	cmsg << "done" << endl;
	if (ok == FALSE) return false;
	if (!sourcelines.empty()) {
		uint totallines(0);
		//init_sourcefiles();
		for (ln_t::const_iterator file = sourcelines.begin(); file != sourcelines.end(); ++file) {
			ifstream is(file->first.c_str());
			uint index(0);
			for (ln_t::mapped_type::const_iterator j = file->second.begin(); j != file->second.end(); ++j) {
				ln_t::mapped_type::mapped_type::const_iterator k;
				if (is.is_open()) {
					string line;
					while (is.good() && index < j->first) {
						getline(is, line);
						if (is.fail()) break;
						++index;
						boost::trim_if(line, boost::is_space());
						if (line.empty()) continue;
						for (k = j->second.begin(); k != j->second.end(); ++k)
							if (isEnabled(static_cast<ea_t>(k->Address))
								&& get_source_linnum(static_cast<ea_t>(k->Address)) == BADADDR)
									add_long_cmt(static_cast<ea_t>(k->Address),
										true, "%-.*s", MAXSTR - 1, line.c_str());
					}
				}
				for (k = j->second.begin(); k != j->second.end(); ++k) {
					if (isEnabled(static_cast<ea_t>(k->Address))) {
						if (get_source_linnum(static_cast<ea_t>(k->Address)) == BADADDR) {
							++totallines;
							showAddr(static_cast<ea_t>(k->Address));
						}
						add_sourcefile(static_cast<ea_t>(k->Address),
							next_not_tail(static_cast<ea_t>(k->Address)), file->first.c_str());
						set_source_linnum(static_cast<ea_t>(k->Address), j->first);
					}
				}
			} // iterate lines
		} // iterate files
		save_sourcefiles();
		//term_sourcefiles();
		msg("%sTotal %u line%s attached\n", log_prefix, totallines,
			totallines != 1 ? "s" : "");
	} // have source lines
	return true;
}

static bool ProcessLocals() {
	if (!ix86_fix_stkframes()) return false;
	wait_box.change("PDB plugin is waiting");
	if (!autoWait()) return false;
	wait_box.change("PDB plugin is running");
	cmsg << log_prefix << "Loading function frames...";
	totalnames = 0;
	totaltypeinfos = 0;
	totaldata = 0;
	totalfuncs = 0;
	totaltypedefs = 0;
	pSymSetOptions(SYMOPT_LOAD_LINES);
	SymResetContext();
	BOOL ok = pSymEnumSymbols(hProcess, (DWORD)SymBase, NULL, SymEnumLocalsProc, NULL);
	cmsg << "done" << endl;
	msg("%sTotal %u local name%s set, %u data type%s created, %u function%s created, %u typeinfo%s set\n",
		log_prefix, totalnames, totalnames != 1 ? "s" : "",
		totaldata, totaldata != 1 ? "s" : "",
		totalfuncs, totalfuncs != 1 ? "s" : "",
		totaltypeinfos, totaltypeinfos != 1 ? "s" : "");
#ifdef _DEBUG
	if (totaltypedefs > 0) _RPT2(_CRT_WARN, "%s(): totaltypedefs=%u\n", __FUNCTION__, totaltypedefs);
#endif // _DEBUG
	//if (ok != FALSE) propagate_stkargs(); // ???
	return ok != FALSE;
}

//----------------------------------------------------------------------
// Support of old debug interface
//----------------------------------------------------------------------
namespace old { // DEPRECATED

typedef BOOL (WINAPI *SymLoadModule_t)(IN HANDLE hProcess, IN HANDLE hFile, IN PSTR ImageName, IN  PSTR ModuleName, IN DWORD BaseOfDll, IN DWORD SizeOfDll);
typedef BOOL (WINAPI *SymEnumerateSymbols_t)(IN HANDLE hProcess, IN DWORD BaseOfDll, IN PSYM_ENUMSYMBOLS_CALLBACK EnumSymbolsCallback, IN PVOID UserContext);
typedef BOOL (WINAPI *SymGetModuleInfo_t)(IN  HANDLE hProcess, IN  DWORD dwAddr, OUT PIMAGEHLP_MODULE ModuleInfo);
typedef BOOL (WINAPI *SymInitialize_t)(IN HANDLE hProcess, IN LPSTR UserSearchPath, IN BOOL fInvadeProcess);
typedef DWORD (WINAPI *SymSetOptions_t)(IN DWORD SymOptions);
typedef BOOL (WINAPI *SymUnloadModule_t)(IN  HANDLE hProcess, IN DWORD64 BaseOfDll);
typedef BOOL (WINAPI *SymCleanup_t)(IN HANDLE hProcess);

DECL_DYNPROC_PTR(SymLoadModule)
DECL_DYNPROC_PTR(SymEnumerateSymbols)
DECL_DYNPROC_PTR(SymGetModuleInfo)
DECL_DYNPROC_PTR(SymInitialize)
DECL_DYNPROC_PTR(SymSetOptions)
DECL_DYNPROC_PTR(SymUnloadModule)
DECL_DYNPROC_PTR(SymCleanup)

static bool setup_pointers() {
	// Since there could be no IMAGEHLP.DLL on the system, we link to
	// the functions at run-time. Usually this is not necessary.
	if ((hImageHlp = LoadLibrary(IMAGEHLP_DLL)) == NULL) {
		_RPT2(_CRT_WARN, "%s(): cannot load %s\n", __FUNCTION__, IMAGEHLP_DLL);
		return false; // There is no imagehlp.dll in this system...
	}
	SET_DYNPROC_PTR(hImageHlp, SymLoadModule)
	SET_DYNPROC_PTR(hImageHlp, SymEnumerateSymbols)
	SET_DYNPROC_PTR(hImageHlp, SymGetModuleInfo)
	SET_DYNPROC_PTR(hImageHlp, SymInitialize)
	SET_DYNPROC_PTR(hImageHlp, SymSetOptions)
	SET_DYNPROC_PTR(hImageHlp, SymUnloadModule)
	SET_DYNPROC_PTR(hImageHlp, SymCleanup)
	if (pSymLoadModule != NULL && pSymEnumerateSymbols != NULL
		&& pSymGetModuleInfo != NULL && pSymInitialize != NULL
		&& pSymSetOptions != NULL && pSymUnloadModule != NULL && pSymCleanup != NULL) {
		use_old = true;
		return true;
	}
	_RPT2(_CRT_WARN, "%s(): essential %s functions are missing\n", __FUNCTION__, IMAGEHLP_DLL);
	FreeLibrary(hImageHlp);
	hImageHlp = NULL;
	return false;
}

static BOOL CALLBACK SymEnumSymbolsProc(PCSTR szName, ULONG ulAddr, ULONG ulSize, PVOID ud) {
	const ea_t ea = static_cast<ea_t>(ulAddr) + Delta;
	if (isEnabled(ea) && szName != NULL && *szName != 0) {
		if (apply_static_name(ea, szName)) ++totalnames;
		const int stype(segtype(ea));
		if (!isFunc(get_flags_novalue(ea)) && (stype == SEG_NORM || stype == SEG_CODE)) {
			char idaname[MAXNAMESIZE];
			if (get_mangled_name_type(qstrcpy(idaname, szName)) != MANGLED_DATA
				&& add_func(ea, BADADDR)) ++totalfuncs;
		}
	}
	return TRUE;
}

} // namespace old

//----------------------------------------------------------------------
// Dynamically load and link to DBGHELP or IMAGEHLP libraries
// Return: success
static bool setup_pointers() {
	if ((hDbgHelp = LoadLibrary(DBGHELP_DLL)) == NULL) {
		_RPT2(_CRT_WARN, "%s(): cannot load %s\n", __FUNCTION__, DBGHELP_DLL);
		return old::setup_pointers();
	}
	SET_DYNPROC_PTR(hDbgHelp, SymSetOptions)
	SET_DYNPROC_PTR(hDbgHelp, SymInitialize)
	SET_DYNPROC_PTR(hDbgHelp, SymLoadModule64)
	SET_DYNPROC_PTR(hDbgHelp, SymEnumSymbols)
	SET_DYNPROC_PTR(hDbgHelp, SymEnumTypes)
	SET_DYNPROC_PTR(hDbgHelp, SymUnloadModule64)
	SET_DYNPROC_PTR(hDbgHelp, SymCleanup)
	SET_DYNPROC_PTR(hDbgHelp, SymGetTypeInfo)
	SET_DYNPROC_PTR(hDbgHelp, SymGetTypeInfoEx)
	SET_DYNPROC_PTR(hDbgHelp, SymEnumLines)
	SET_DYNPROC_PTR(hDbgHelp, SymSetContext)
	SET_DYNPROC_PTR(hDbgHelp, SymFunctionTableAccess64)
	SET_DYNPROC_PTR(hDbgHelp, SymFromName)
	SET_DYNPROC_PTR(hDbgHelp, SymEnumSymbolsForAddr)
	SET_DYNPROC_PTR(hDbgHelp, SymGetScope)
	//SET_DYNPROC_PTR(hDbgHelp, SymEnumSourceFiles)
	//SET_DYNPROC_PTR(hDbgHelp, SymEnumerateSymbols64)
	if (pSymSetOptions != NULL && pSymInitialize != NULL
		&& pSymLoadModule64 != NULL && pSymUnloadModule64 != NULL
		&& pSymCleanup != NULL && pSymEnumSymbols != NULL && pSymEnumTypes != NULL) {
		use_old = false;
		return true;
	}
	_RPT2(_CRT_WARN, "%s(): essential %s functions are missing\n", __FUNCTION__, DBGHELP_DLL);
	FreeLibrary(hDbgHelp);
	hDbgHelp = NULL;
	return old::setup_pointers();
}

void Unload() {
	if (hDbgHelp != NULL) { FreeLibrary(hDbgHelp); hDbgHelp = NULL; }
	if (hImageHlp != NULL) { FreeLibrary(hImageHlp); hImageHlp = NULL; }
}

void ShoutImageHlpVersion() {
	VS_FIXEDFILEINFO fixednfo;
	GetFixedFileInfo(hDbgHelp, fixednfo);
	cmsg << log_prefix << DBGHELP_DLL << " version " << dec <<
		HIWORD(fixednfo.dwFileVersionMS) << '.' <<
		LOWORD(fixednfo.dwFileVersionMS) << '.' <<
		HIWORD(fixednfo.dwFileVersionLS) << '.' <<
		LOWORD(fixednfo.dwFileVersionLS) << " is loaded";
	DYNPROC_TYPE(ImagehlpApiVersion) DYNPROC_PTR(ImagehlpApiVersion);
	SET_DYNPROC_PTR(hDbgHelp, ImagehlpApiVersion)
	if (DYNPROC_PTR(ImagehlpApiVersion) != NULL) {
		const LPAPI_VERSION version = DYNPROC_PTR(ImagehlpApiVersion)();
		if (version != NULL) cmsg << " (ImageHlp API " << dec <<
			version->MajorVersion << '.' << version->MinorVersion << '.' <<
			version->Revision << ')';
	}
	cmsg << endl;
}

// returns:
// -7: SymInitialize failed
// -6: no parsing library is avasilable
// -5: source file not detected
// -4: SymLoadModule failed/PDB not available
// -3: refused to load PDB from MS
// -1: unexpected exception
//  0: OK
//  1: user cancel
static int LoadOwn(bool invoked_by_loader) {
	// since the module has been unloaded, reinitialize
	if (!setup_pointers()) return -6;
	int exit_code(1);
	__try {
		__try {
			if (invoked_by_loader && askyn_c(1, "AUTOHIDE REGISTRY\nHIDECANCEL\n"
				"IDA Pro has determined that the input file was linked with debug information.\n"
				"Do you want to look for the corresponding PDB file at the local symbol store\n"
				"and the Microsoft Symbol Server?\n") <= 0) return 2;
			// Get the input file name and try to guess the PDB file locaton
			char input[QMAXPATH];
			// If failed, ask the user
			if (get_input_file_path(CPY(input)) <= 0 || !qfileexist(input)) {
				const char *ans = askfile_c(false, input, "Please specify the input file");
				if (ans == 0) return -5;
				qstrcpy(input, ans);
			}
			_ASSERTE(qfileexist(input));
			foreign_pdb = false;
			const DWORD ImageBase(static_cast<DWORD>(netnode("$ PE header").altval(-2)));
			if (use_old) {
				old::pSymSetOptions(SYMOPT_LOAD_LINES);
				if (!old::pSymInitialize(hProcess, NULL, FALSE)) {
					error_msg("SymInitialize");
					return -7;
				}
				__try {
					SymBase = old::pSymLoadModule(hProcess, 0, input, NULL, ImageBase, 0);
					if (SymBase == 0) {
						error_msg("SymLoadModule");
						return -4;
					}
					__try {
						load_vc_til();
						reset_globals(true);
						Delta = ImageBase - SymBase;
						totalnames = 0;
						if (!old::pSymEnumerateSymbols(hProcess, ImageBase, old::SymEnumSymbolsProc, NULL)) {
							error_msg("SymEnumerateSymbols");
							return 1;
						}
						msg("%sTotal %u symbol%s loaded\n", log_prefix, totalnames,
							totalnames > 1 ? "s" : "");
					} __finally {
						reset_globals();
						if (!old::pSymUnloadModule(hProcess, SymBase)) error_msg("SymUnloadModule");
					}
				} __finally {
					if (!old::pSymCleanup(hProcess)) error_msg("SymCleanup");
				}
				return 0;
			} // use_old
			download_path[0] = 0;
#if IDP_INTERFACE_VERSION >= 76
			read_user_config_file("pdb", parse_options);
#endif
			if (download_path[0] == 0 && GetTempPath(qnumber(download_path), download_path))
				qstrcat(download_path, "ida");
			char tmp[512];
			qstrncat(qstrncat(qstrcpy(tmp, "srv*"), download_path, qnumber(tmp)),
				"*http://msdl.microsoft.com/download/symbols", qnumber(tmp));
			if (!pSymInitialize(hProcess, tmp, FALSE)) {
				error_msg("SymInitialize");
				return -7;
			}
			__try {
				SymBase = pSymLoadModule64(hProcess, NULL, input, NULL, ImageBase, 0);
				if (SymBase == 0) return -4; // DbgHelp failed to load module
				__try {
					ShoutImageHlpVersion();
					Delta = ImageBase - SymBase;
					if (load_plugin("comhelper2") == 0) load_plugin("comhelper");
					wait_box.open("PDB plugin is running");
					load_vc_til();
					reset_globals(true);
					if (!ProcessTypes() || !ProcessSymbols()
						|| pSymEnumLines != NULL && !ProcessLines()) return 1;
					wait_box.change("PDB plugin is waiting");
					if (!autoWait()) return 1;
					wait_box.change("PDB plugin is running");
					if (!ProcessLocals()) return 1;
					beep();
					exit_code = 0;
				} __finally {
					reset_globals();
					wait_box.close_all();
					if (!pSymUnloadModule64(hProcess, SymBase)) error_msg("SymUnloadModule64:");
				}
			} __finally {
				if (!pSymCleanup(hProcess)) error_msg("SymCleanup");
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			exit_code = -1;
			warning("%sdirty exception in %s(...)", log_prefix, __FUNCTION__);
		}
	} __finally {
		Unload();
	}
	return exit_code;
}

typedef class typesview_t : public ::typesview_t<types_t> {
protected:
	bool IsTypeEmpty(const_reference item) const {
		switch (item.SymTag) {
			case SymTagUDT:
			case SymTagEnum:
				return item.ChildrenCount <= 0;
			case SymTagTypedef:
				return item.TypeId == 0 ? true : value_type(item.TypeId).SymTag == SymTagNull;
		}
		_RPT2(_CRT_WARN, "%s(...): unexpected SymTag value: %s\n",
			__FUNCTION__, item.TokenizeSymTag().c_str());
		return false;
	}
} *typesview_p;

static typesview_p new_typesview_t() {
	const typesview_p ptr = new typesview_t;
	if (ptr == 0) {
		_RPT1(_CRT_ERROR, "%s(...): new typesview_t failed\n", __FUNCTION__);
		cmsg << log_prefix << "Failed to allocate new types container" << endl;
		throw bad_alloc(); // ?
	}
	return ptr;
}

// LoadForeign() tries to load foreign PDB file and import meaningful information
// to local idabase (this concerns everything not directly writable to
// disassembly - typeinfo, structs and enums)
static int LoadForeign() {
	// since the module has been unloaded, reinitialize
	if (!setup_pointers()) return -6;
	if (use_old) return -8; // types enumeration not supported by old interface
	int exit_code(1);
	__try {
		__try {
			// Get the input file name and try to guess the PDB file locaton
			char input[QMAXPATH];
			get_input_file_path(CPY(input));
			char drive[_MAX_DRIVE], path[_MAX_PATH], fname[_MAX_FNAME], pdb[_MAX_PATH];
			_splitpath(input, drive, path, fname, 0);
			_makepath(pdb, drive, path, fname, "pdb");
			do {
				const char *ans = askfile_c(false, pdb, "Please specify the PDB file");
				if (ans == 0) return -5;
				qstrcpy(pdb, ans);
			} while (!qfileexist(pdb));
			if (!pSymInitialize(hProcess, "srv**http://msdl.microsoft.com/download/symbols", FALSE)) {
				error_msg("SymInitialize");
				return -7;
			}
			__try {
				foreign_pdb = true;
				const DWORD ImageBase(static_cast<DWORD>(netnode("$ PE header").altval(-2)));
				if ((SymBase = pSymLoadModule64(hProcess, NULL, pdb, NULL, ImageBase, 0)) == 0) {
					_splitpath(pdb, drive, path, fname, 0);
					_makepath(input, drive, path, fname, "exe");
					if ((SymBase = pSymLoadModule64(hProcess, NULL, input, NULL, ImageBase, 0)) == 0)
						return -4;
				}
				__try {
					ShoutImageHlpVersion();
					wait_box.open("PDB plugin is running");
					SymResetContext();
					typesview_p ptypes = new_typesview_t();
					if (ptypes != 0) __try {
#ifdef _DEBUG
						totalnames = 0;
						totaldata = 0;
						totalfuncs = 0;
#endif // _DEBUG
						totaltypedefs = 0;
						totalstructs = 0;
						totalenums = 0;
						totaltypeinfos = 0;
						reset_globals(true);
						cmsg << log_prefix << "Loading types...";
						const BOOL ok =
							pSymEnumTypes(hProcess, (DWORD)SymBase, SymEnumTypesProc, ptypes);
						cmsg << "done" << endl;
						if (ok == FALSE) error_msg("SymEnumTypes");
						wait_box.close();
						if (!ptypes->empty()) {
							if (ptypes->Open() && !ptypes->empty()) {
								load_vc_til();
								wait_box.open("Storing types to idabase...");
								ptypes->SaveTypes();
								wait_box.close();
							}
							ptypes->clear();
						}
						_ASSERTE(totalnames <= 0);
						_ASSERTE(totaldata <= 0);
						_ASSERTE(totalfuncs <= 0);
						msg("%sTotal %u struct%s, %u enum%s, %u typedef%s, %u typeinfo%s set\n",
							log_prefix, totalstructs, totalstructs != 1 ? "s" : "",
							totalenums, totalenums != 1 ? "s" : "",
							totaltypedefs, totaltypedefs != 1 ? "s" : "",
							totaltypeinfos, totaltypeinfos != 1 ? "s" : "");
						exit_code = 0;
						beep();
					} __finally {
						delete ptypes;
						reset_globals();
					}
				} __finally {
					wait_box.close_all();
					if (!pSymUnloadModule64(hProcess, SymBase)) error_msg("SymUnloadModule64:");
				}
			} __finally {
				if (!pSymCleanup(hProcess)) error_msg("SymCleanup");
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			exit_code = -1;
			warning("%sDirty exception in %s(...)", log_prefix, __FUNCTION__);
		}
	} __finally {
		Unload();
	}
	return exit_code;
}

} // namespace ImageHlp

// parser using DIA SDK
namespace DIA {

static CComPtr<IDiaSession> pSession;

static inline void COM_Error(const char *apiname, HRESULT hr)
	{ if (hr != S_OK) error_msg_base(hr, apiname); }

class CDiaBSTR : public CComBSTR {
public:
	inline CDiaBSTR& operator=(const CComBSTR& src) {
		CComBSTR::operator=(src);
		return *this;
	}
	inline CDiaBSTR& operator=(LPCOLESTR pSrc) {
		CComBSTR::operator=(pSrc);
		return *this;
	}
#ifndef OLE2ANSI
	inline CDiaBSTR& operator=(LPCSTR pSrc) {
		CComBSTR::operator=(pSrc);
		return *this;
	}
#endif

	inline operator bool() const { return operator BSTR() != NULL; }
	/*
	bool operator ==(const CComBSTR &rhs) const {
		return operator !() && !rhs ? true : VarBstrCmp(operator BSTR(), rhs,
			LOCALE_USER_DEFAULT, 0) == VARCMP_EQ;
	}
	inline bool operator !=(const CComBSTR &rhs) const { return !operator ==(rhs); }
	bool operator <(const CComBSTR &rhs) const {
		return operator !() && rhs.operator BSTR() != NULL ? true : !rhs ? false :
			VarBstrCmp(operator BSTR(), rhs, LOCALE_USER_DEFAULT, 0) == VARCMP_LT;
	}
	*/

	int toAnsi(char *buf, size_t bufsize) const {
		_ASSERTE(buf != 0 && bufsize > 0);
		if (buf == 0 || bufsize == 0) return -1;
		*buf = 0;
		if (m_str == NULL) return 0;
		_wcstombs(buf, m_str, bufsize);
		return strlen(buf);
	}
	string toAnsi() const {
		string result;
		if (m_str != NULL) {
			const size_t sz(Length() + 1);
			boost::scoped_array<char> buf(new char[sz]);
			if (!buf) {
				_RPT2(_CRT_ERROR, "%s(...): failed to allocate new string of size 0x%IX\n",
					__FUNCTION__, sz);
				throw bad_alloc();
			}
			if (_wcstombs(buf.get(), m_str, sz) > 0) result.assign(buf.get());
		}
		return result;
	}
}; // CDiaBSTR

static const CComPtr<IDiaSymbol> symbolById(DWORD SymIndexId) {
	_ASSERTE(SymIndexId != 0);
	_ASSERTE(pSession != NULL);
	CComPtr<IDiaSymbol> pSymbol;
	_ASSERTE(!pSymbol);
	if (SymIndexId != 0 && pSession != NULL) try {
		HRESULT hr(pSession->symbolById(SymIndexId, &pSymbol));
		if (FAILED(hr)) COM_Error("IDiaSession::symbolById", hr);
		if (hr != S_OK) throw fmt_exception("%s(...) no match(%08lX)",
			"IDiaSession::symbolById", hr);
		_ASSERTE(pSymbol != NULL);
	} catch (GENERAL_CATCH_FILTER) {
		pSymbol.Release();
		_RPT3(_CRT_WARN, "%s(0x%lX, ...): %s\n", __FUNCTION__, SymIndexId, e.what());
	}
	return pSymbol;
}

struct DiaSymbol;
static bool TypesAreEquiv(const DiaSymbol &, const DiaSymbol &);

#ifdef _DEBUG

#define GUARDED_GETX(W, p, n, m, r) try { \
		W(p, n, m, r) \
	} catch (const exception &e) { \
		/*m(E_UNEXPECTED);*/ \
		ReqsValid.reset(r); \
		_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__, \
			"%s(...): %s->get_%s(%s) produced %s\n", __FUNCTION__, #p, #n, #m, e.what()); \
	}

#else // !_DEBUG

#define GUARDED_GETX(W, p, n, m, r) try { \
		W(p, n, m, r) \
	} catch (...) { \
		/*m(E_UNEXPECTED);*/ \
		ReqsValid.reset(r); \
	}

#endif // _DEBUG

#define UNGUARDED_GET(p, n, m, r) \
	if (FAILED(hr = p->get_##n(&m))) { \
		/*m(hr);*/ \
		_RPTF4(_CRT_WARN, "%s(...): %s->get_%s(...) returned %08lX\n", \
			__FUNCTION__, #p, #n, hr); \
		/*COM_Error(#p "->get_" #n, hr);*/ \
	} \
	ReqsValid.set(r, hr == S_OK);

#define UNGUARDED_GETBYTES(p, n, m, r) { \
	DWORD cbData; \
	if ((hr = p->get_##n(0, &cbData, NULL)) == S_OK && cbData > 0) { \
		m.reset(cbData); \
		if ((bool)m && (hr = p->get_##n(cbData, &cbData, m.get())) != S_OK) { \
			m.reset(); \
			_RPTF4(_CRT_ERROR, "%s(...): %s->get_%s(...) returned %08lX\n", \
				__FUNCTION__, #p, #n, hr); \
			/*COM_Error(#p "->get_" #n, hr);*/ \
		} \
	} \
	ReqsValid.set(r, hr == S_OK/* && (bool)m*/); \
}

#define GUARDED_GET(p, n, m, r) GUARDED_GETX(UNGUARDED_GET, p, n, m, r)
#define GUARDED_GETBYTES(p, n, m, r) GUARDED_GETX(UNGUARDED_GETBYTES, p, n, m, r)

#define TEST_BIT_IMPL(Name, Bit) \
	inline bool has##Name() const { return ReqsValid.test(Bit); }
#define TEST_STRING_BIT_IMPL(Name, Bit) \
	bool has##Name() const { return ReqsValid.test(Bit) && Name.Length() > 0; }
#define TEST_BYTES_BIT_IMPL(Name, Bit) \
	bool has##Name() const { return ReqsValid.test(Bit) && static_cast<bool>(Name); }

__declspec(align(4)) struct DiaSymbol {
private:
	bitset<94> ReqsValid;
public:
	DWORD SymIndexId, SymTag, LocationType; // 2
	ULONGLONG Length; // 3
	CDiaBSTR Name; // 4
	DWORD AddressSection, AddressOffset, RVA; // 7
	ULONGLONG VA; // 8
	LONG Offset; // 9
	DWORD DataKind, BaseType, Count, RegisterId; // 13
	CComVariant Value; // 14
	DWORD BitPosition, TypeId, UDTKind; // 17
	CComPtr<IDiaSymbol> Type, LexicalParent, ClassParent; // 20
	DWORD Slot; // 21
	BOOL VolatileType, ConstType, UnalignedType; // 24
	DWORD Access; // 25
	CDiaBSTR LibraryName; // 26
	DWORD Platform, Language; // 28
	BOOL EditAndContinueEnabled; // 29
	DWORD FrontEndMajor, FrontEndMinor, FrontEndBuild, // 32
		BackEndMajor, BackEndMinor, BackEndBuild; // 35
	CDiaBSTR SourceFileName, Unused, ObjectFileName; // 38
	DWORD ThunkOrdinal; // 39
	LONG ThisAdjust; // 40
	BOOL Virtual, Intro, Pure; // 43
	DWORD CallingConvention, Token, TimeStamp; // 46
	GUID Guid; // 47
	CDiaBSTR SymbolsFileName; // 48
	BOOL Reference; // 49
	CComPtr<IDiaSymbol> ArrayIndexType; // 50
	BOOL Packed, Constructor, OverloadedOperator, Nested, HasNestedTypes, // 55
		HasAssignmentOperator, HasCastOperator, Scoped, VirtualBaseClass, // 59
		IndirectVirtualBaseClass; // 60
	CComPtr<IDiaSymbol> VirtualTableShape; // 61
	DWORD LexicalParentId, ClassParentId, ArrayIndexTypeId, VirtualTableShapeId; // 65
	BOOL Code, Function, Managed, MSIL; // 69
	LONG VirtualBasePointerOffset; // 70
	DWORD VirtualBaseOffset, VirtualBaseDispIndex; // 72
	CDiaBSTR UndecoratedName; // 73
	DWORD Age, Signature; // 75
	BOOL CompilerGenerated, AddressTaken; // 77
	DWORD Rank; // 78
	CComPtr<IDiaSymbol> LowerBound, UpperBound; // 80
	DWORD LowerBoundId, UpperBoundId; // 82
	boost::shared_localptr<BYTE, NONZEROLPTR> DataBytes; // 83
	DWORD TargetSection, TargetOffset, TargetRVA; // 86
	ULONGLONG TargetVA; // 87
	DWORD MachineType, OemId, OemSymbolId; // 90
	CComPtr<IDiaSymbol> ObjectPointerType; // 91
	//CAtlArray<DWORD> TypeIds; // 92
	//CInterfaceArray<IDiaSymbol> Types; // 93

	DiaSymbol() { Reset(); }
	DiaSymbol(const CComPtr<IDiaSymbol> &pSymbol) { operator ()(pSymbol); }

	bool operator ()(const CComPtr<IDiaSymbol> &pSymbol) {
		Reset();
		//_ASSERTE(pSymbol != NULL);
		if (!pSymbol) return false;
		HRESULT hr;
		UNGUARDED_GET(pSymbol, symIndexId, SymIndexId, 0) // Retrieves the unique symbol identifier.
		UNGUARDED_GET(pSymbol, symTag, SymTag, 1) // Retrieves the symbol type classifier.
		UNGUARDED_GET(pSymbol, locationType, LocationType, 2) // Retrieves the location type of a data symbol.
		UNGUARDED_GET(pSymbol, length, Length, 3) // Retrieves the number of bytes of memory used by the object represented by this symbol.
		UNGUARDED_GET(pSymbol, name, Name, 4) // Retrieves the name of the symbol.
		UNGUARDED_GET(pSymbol, addressSection, AddressSection, 5) // Retrieves the section part of an address location.
		UNGUARDED_GET(pSymbol, addressOffset, AddressOffset, 6) // Retrieves the offset part of an address location.
		UNGUARDED_GET(pSymbol, relativeVirtualAddress, RVA, 7) // Retrieves the relative virtual address (RVA) of the location.
		UNGUARDED_GET(pSymbol, virtualAddress, VA, 8) // Retrieves the virtual address (VA) of the location.
		UNGUARDED_GET(pSymbol, offset, Offset, 9) // Retrieves the offset of the symbol location.
		UNGUARDED_GET(pSymbol, dataKind, DataKind, 10) // Retrieves the variable classification of a data symbol.
		UNGUARDED_GET(pSymbol, baseType, BaseType, 11) // Retrieves the type tag of a simple type.
		UNGUARDED_GET(pSymbol, count, Count, 12) // Retrieves the number of items in a list or array.
		UNGUARDED_GET(pSymbol, registerId, RegisterId, 13) // Retrieves the register designator of the location.
		UNGUARDED_GET(pSymbol, value, Value, 14) // Retrieves the value of a constant.
		UNGUARDED_GET(pSymbol, bitPosition, BitPosition, 15) // Retrieves the bit position of a location.
		UNGUARDED_GET(pSymbol, typeId, TypeId, 16) // Retrieves the type identifier of the symbol.
		UNGUARDED_GET(pSymbol, udtKind, UDTKind, 17) // Retrieves the variety of a user-defined type (UDT).
		GUARDED_GET(pSymbol, type, Type, 18) // Retrieves a reference to the function signature.
		GUARDED_GET(pSymbol, lexicalParent, LexicalParent, 19) // Retrieves a reference to the lexical parent of the symbol.
		GUARDED_GET(pSymbol, classParent, ClassParent, 20) // Retrieves a reference to the class parent of the symbol.
		UNGUARDED_GET(pSymbol, slot, Slot, 21) // Retrieves the slot number of the location.
		UNGUARDED_GET(pSymbol, volatileType, VolatileType, 22) // Retrieves a flag that specifies whether the user-defined data type is volatile.
		UNGUARDED_GET(pSymbol, constType, ConstType, 23) // Retrieves a flag that specifies whether the user-defined data type is constant.
		UNGUARDED_GET(pSymbol, unalignedType, UnalignedType, 24) // Retrieves a flag that specifies whether the user-defined data type is unaligned.
		UNGUARDED_GET(pSymbol, access, Access, 25) // Retrieves the access modifier of a class member.
		UNGUARDED_GET(pSymbol, libraryName, LibraryName, 26) // Retrieves the file name of the library or object file from which the object was loaded.
		UNGUARDED_GET(pSymbol, platform, Platform, 27) // Retrieves the platform type for which the program or compiland was compiled.
		UNGUARDED_GET(pSymbol, language, Language, 28) // Retrieves the language of the source.
		UNGUARDED_GET(pSymbol, editAndContinueEnabled, EditAndContinueEnabled, 29) // Retrieves the flag describing the edit and continue features of the compiled program or unit.
		UNGUARDED_GET(pSymbol, frontEndMajor, FrontEndMajor, 30) // Retrieves the front-end major version number.
		UNGUARDED_GET(pSymbol, frontEndMinor, FrontEndMinor, 31) // Retrieves the front-end minor version number.
		UNGUARDED_GET(pSymbol, frontEndBuild, FrontEndBuild, 32) // Retrieves the front-end build number.
		UNGUARDED_GET(pSymbol, backEndMajor, BackEndMajor, 33) // Retrieves the back-end major version number.
		UNGUARDED_GET(pSymbol, backEndMinor, BackEndMinor, 34) // Retrieves the back-end minor version number.
		UNGUARDED_GET(pSymbol, backEndBuild, BackEndBuild, 35) // Retrieves the back-end build number.
		UNGUARDED_GET(pSymbol, sourceFileName, SourceFileName, 36) // Retrieves the file name of the source file.
		//UNGUARDED_GET(pSymbol, unused, Unused, 37)
		//UNGUARDED_GET(pSymbol, objectFileName, ObjectFileName, 38) // Retrieves the file name of the compiland object file.
		UNGUARDED_GET(pSymbol, thunkOrdinal, ThunkOrdinal, 39) // Retrieves the thunk type of a function.
		UNGUARDED_GET(pSymbol, thisAdjust, ThisAdjust, 40) // Retrieves the logical this adjustor for the method.
		UNGUARDED_GET(pSymbol, virtual, Virtual, 41) // Retrieves a flag that specifies whether the function is virtual.
		UNGUARDED_GET(pSymbol, intro, Intro, 42) // Retrieves a flag that specifies whether the function is an introducing virtual function.
		UNGUARDED_GET(pSymbol, pure, Pure, 43) // Retrieves a flag that specifies whether the function is pure virtual.
		UNGUARDED_GET(pSymbol, callingConvention, CallingConvention, 44) // Returns an indicator of a methods calling convention.
		UNGUARDED_GET(pSymbol, token, Token, 45) // Retrieves the metadata token of a managed function or variable.
		UNGUARDED_GET(pSymbol, timeStamp, TimeStamp, 46) // Retrieves the timestamp of the underlying executable file.
		UNGUARDED_GET(pSymbol, guid, Guid, 47) // Retrieves the symbol's GUID.
		UNGUARDED_GET(pSymbol, symbolsFileName, SymbolsFileName, 48) // Retrieves the name of the file from which the symbols were loaded.
		UNGUARDED_GET(pSymbol, reference, Reference, 49) // Retrieves a flag that specifies whether a pointer type is a reference.
		GUARDED_GET(pSymbol, arrayIndexType, ArrayIndexType, 50) // Retrieves the symbol identifier of the array index type.
		UNGUARDED_GET(pSymbol, packed, Packed, 51) // Retrieves a flag that specifies whether the user-defined data type is packed.
		UNGUARDED_GET(pSymbol, constructor, Constructor, 52) // Retrieves a flag that specifies whether the user-defined data type has a constructor.
		UNGUARDED_GET(pSymbol, overloadedOperator, OverloadedOperator, 53) // Retrieves a flag that specifies whether the user-defined data type has overloaded operators.
		UNGUARDED_GET(pSymbol, hasNestedTypes, HasNestedTypes, 55) // Retrieves a flag that specifies whether the user-defined data type has nested type definitions.
		UNGUARDED_GET(pSymbol, nested, Nested, 54) // Retrieves a flag that specifies whether the user-defined data type is nested.
		UNGUARDED_GET(pSymbol, hasAssignmentOperator, HasAssignmentOperator, 56) // Retrieves a flag that specifies whether the user-defined data type has any assignment operators defined.
		UNGUARDED_GET(pSymbol, hasCastOperator, HasCastOperator, 57) // Retrieves a flag that specifies whether the user-defined data type has any cast operators defined.
		UNGUARDED_GET(pSymbol, scoped, Scoped, 58) // Retrieves a flag that specifies whether the user-defined data type appears in a non-global lexical scope.
		UNGUARDED_GET(pSymbol, virtualBaseClass, VirtualBaseClass, 59) // Retrieves a flag that specifies whether the user-defined data type is a virtual base class.
		UNGUARDED_GET(pSymbol, indirectVirtualBaseClass, IndirectVirtualBaseClass, 60) // Retrieves a flag that specifies whether the user-defined data type is an indirect virtual base class.
		GUARDED_GET(pSymbol, virtualTableShape, VirtualTableShape, 61) // Retrieves the symbol interface of the type of the virtual table for a user-defined type.
		UNGUARDED_GET(pSymbol, lexicalParentId, LexicalParentId, 62) // Retrieves the lexical parent identifier of the symbol.
		UNGUARDED_GET(pSymbol, classParentId, ClassParentId, 63) // Retrieves the class parent identifier of the symbol.
		UNGUARDED_GET(pSymbol, arrayIndexTypeId, ArrayIndexTypeId, 64) // Retrieves the array index type identifier of the symbol.
		UNGUARDED_GET(pSymbol, virtualTableShapeId, VirtualTableShapeId, 65) // Retrieves the virtual table shape identifier of the symbol.
		UNGUARDED_GET(pSymbol, code, Code, 66) // Retrieves a flag that specifies whether the symbol refers to a code address.
		UNGUARDED_GET(pSymbol, function, Function, 67) // Retrieves a flag that specifies whether the public symbol refers to a function.
		UNGUARDED_GET(pSymbol, managed, Managed, 68) // Retrieves a flag that specifies whether the symbol refers to managed code.
		UNGUARDED_GET(pSymbol, msil, MSIL, 69) // Retrieves a flag that specifies whether the symbol refers to Microsoft Intermediate Language (MSIL) code.
		UNGUARDED_GET(pSymbol, virtualBasePointerOffset, VirtualBasePointerOffset, 70) // Retrieves the offset of the virtual base pointer.
		UNGUARDED_GET(pSymbol, virtualBaseOffset, VirtualBaseOffset, 71) // Retrieves the offset in the virtual function table of a virtual function.
		UNGUARDED_GET(pSymbol, virtualBaseDispIndex, VirtualBaseDispIndex, 72) // Retrieves the index into the virtual base displacement table.
		UNGUARDED_GET(pSymbol, undecoratedName, UndecoratedName, 73) // Retrieves the undecorated name for a C++ decorated, or linkage, name.
		UNGUARDED_GET(pSymbol, age, Age, 74) // Retrieves the age value of a program database.
		UNGUARDED_GET(pSymbol, signature, Signature, 75) // Retrieves the symbol's signature value.
		UNGUARDED_GET(pSymbol, compilerGenerated, CompilerGenerated, 76) // Retrieves a flag that indicates whether the symbol was compiler generated.
		UNGUARDED_GET(pSymbol, addressTaken, AddressTaken, 77) // Retrieves a flag that indicates whether another symbol references this address.
		UNGUARDED_GET(pSymbol, rank, Rank, 78) // Retrieves the rank of a FORTRAN multi-dimensional array.
		GUARDED_GET(pSymbol, lowerBound, LowerBound, 79) // Retrieves the lower bound of a FORTRAN array dimension.
		GUARDED_GET(pSymbol, upperBound, UpperBound, 80) // Retrieves the upper bound of a FORTRAN array dimension.
		UNGUARDED_GET(pSymbol, lowerBoundId, LowerBoundId, 81) // Retrieves the symbol identifier of lower bound of a FORTRAN array dimension.
		UNGUARDED_GET(pSymbol, upperBoundId, UpperBoundId, 82) // Retrieves the symbol identifier of upper bound of a FORTRAN array dimension.
		GUARDED_GETBYTES(pSymbol, dataBytes, DataBytes, 83) // Retrieves the data bytes of an OEM symbol.
		UNGUARDED_GET(pSymbol, targetSection, TargetSection, 84) // Retrieves the address section of a thunk target.
		UNGUARDED_GET(pSymbol, targetOffset, TargetOffset, 85) // Retrieves the offset section of a thunk target.
		UNGUARDED_GET(pSymbol, targetRelativeVirtualAddress, TargetRVA, 86) // Retrieves the relative virtual address (RVA) of a thunk target.
		UNGUARDED_GET(pSymbol, targetVirtualAddress, TargetVA, 87) // Retrieves the virtual address (VA) of a thunk target.
		UNGUARDED_GET(pSymbol, machineType, MachineType, 88) // Retrieves the type of the target CPU.
		UNGUARDED_GET(pSymbol, oemId, OemId, 89) // Retrieves the symbol's oemId value.
		UNGUARDED_GET(pSymbol, oemSymbolId, OemSymbolId, 90) // Retrieves the symbol's oemSymbolId value.
		GUARDED_GET(pSymbol, objectPointerType, ObjectPointerType, 91) // Retrieves the type of the object pointer for a class method.
		/*
		//GUARDED_GET(pSymbol, typeIds, TypeIds, 92) // Retrieves an array of compiler-specific type identifier values for this symbol.
		DWORD count;
		if (!FAILED(hr = pSymbol->get_typeIds(0, &count, NULL)) && count > 0) {
			boost::scoped_array<DWORD> pTypeIds(new DWORD[count]);
			if ((bool)pTypeIds
				&& !FAILED(hr = pSymbol->get_typeIds(count, &count, pTypeIds.get())))
				for (const DWORD *it = pTypeIds.get(); it != pTypeIds.get() + count; ++it)
					TypeIds.Add(*it);
		}
		ReqsValid.set(92, hr == S_OK);
		//GUARDED_GET(pSymbol, types, Types, 93) // Retrieves an array of compiler-specific type values for this symbol.
		if (!FAILED(hr = pSymbol->get_types(0, &count, NULL)) && count > 0) {
			boost::scoped_array<IDiaSymbol> pTypes(new IDiaSymbol[count]);
			if ((bool)pTypes
				&& !FAILED(hr = pSymbol->get_types(count, &count, pTypes.get())))
				for (const IDiaSymbol *it = pTypes.get(); it != pTypes.get() + count; ++it)
					Types.Add(*it);
		}
		ReqsValid.set(93, hr == S_OK);
		*/
		return true;
	}
	inline bool operator ()() const { return SymIndexId != 0; }
	inline bool operator !() const { return SymIndexId == 0; }
	inline bool operator ==(const DiaSymbol &r) const {
		//_ASSERTE(pSession != NULL);
		return SymIndexId == r.SymIndexId/*pSession->symsAreEquiv(*this, r)*/;
	}
	inline bool operator <(const DiaSymbol &r) const
		{ return SymIndexId < r.SymIndexId; }
	operator const CComPtr<IDiaSymbol>() const
		{ return symbolById(SymIndexId); }

	TEST_BIT_IMPL(SymIndexId, 0)
	TEST_BIT_IMPL(SymTag, 1)
	TEST_BIT_IMPL(LocationType, 2)
	TEST_BIT_IMPL(Length, 3)
	TEST_STRING_BIT_IMPL(Name, 4)
	TEST_BIT_IMPL(AddressSection, 5)
	TEST_BIT_IMPL(AddressOffset, 6)
	TEST_BIT_IMPL(RVA, 7)
	TEST_BIT_IMPL(VA, 8)
	TEST_BIT_IMPL(Offset, 9)
	TEST_BIT_IMPL(DataKind, 10)
	TEST_BIT_IMPL(BaseType, 11)
	TEST_BIT_IMPL(Count, 12)
	TEST_BIT_IMPL(RegisterId, 13)
	TEST_BIT_IMPL(Value, 14)
	TEST_BIT_IMPL(BitPosition, 15)
	TEST_BIT_IMPL(TypeId, 16)
	TEST_BIT_IMPL(UDTKind, 17)
	TEST_BIT_IMPL(Type, 18)
	TEST_BIT_IMPL(LexicalParent, 19)
	TEST_BIT_IMPL(ClassParent, 20)
	TEST_BIT_IMPL(Slot, 21)
	TEST_BIT_IMPL(VolatileType, 22)
	TEST_BIT_IMPL(ConstType, 23)
	TEST_BIT_IMPL(UnalignedType, 24)
	TEST_BIT_IMPL(Access, 25)
	TEST_STRING_BIT_IMPL(LibraryName, 26)
	TEST_BIT_IMPL(Platform, 27)
	TEST_BIT_IMPL(Language, 28)
	TEST_BIT_IMPL(EditAndContinueEnabled, 29)
	TEST_BIT_IMPL(FrontEndMajor, 30)
	TEST_BIT_IMPL(FrontEndMinor, 31)
	TEST_BIT_IMPL(FrontEndBuild, 32)
	TEST_BIT_IMPL(BackEndMajor, 33)
	TEST_BIT_IMPL(BackEndMinor, 34)
	TEST_BIT_IMPL(BackEndBuild, 35)
	TEST_STRING_BIT_IMPL(SourceFileName, 36)
	//TEST_STRING_BIT_IMPL(Unused, 37)
	TEST_STRING_BIT_IMPL(ObjectFileName, 38)
	TEST_BIT_IMPL(ThunkOrdinal, 39)
	TEST_BIT_IMPL(ThisAdjust, 40)
	TEST_BIT_IMPL(Virtual, 41)
	TEST_BIT_IMPL(Intro, 42)
	TEST_BIT_IMPL(Pure, 43)
	TEST_BIT_IMPL(CallingConvention, 44)
	TEST_BIT_IMPL(Token, 45)
	TEST_BIT_IMPL(TimeStamp, 46)
	TEST_BIT_IMPL(Guid, 47)
	TEST_STRING_BIT_IMPL(SymbolsFileName, 48)
	TEST_BIT_IMPL(Reference, 49)
	TEST_BIT_IMPL(ArrayIndexType, 50)
	TEST_BIT_IMPL(Packed, 51)
	TEST_BIT_IMPL(Constructor, 52)
	TEST_BIT_IMPL(OverloadedOperator, 53)
	TEST_BIT_IMPL(HasNestedTypes, 55)
	TEST_BIT_IMPL(Nested, 54)
	TEST_BIT_IMPL(HasAssignmentOperator, 56)
	TEST_BIT_IMPL(HasCastOperator, 57)
	TEST_BIT_IMPL(Scoped, 58)
	TEST_BIT_IMPL(VirtualBaseClass, 59)
	TEST_BIT_IMPL(IndirectVirtualBaseClass, 60)
	TEST_BIT_IMPL(VirtualTableShape, 61)
	TEST_BIT_IMPL(LexicalParentId, 62)
	TEST_BIT_IMPL(ClassParentId, 63)
	TEST_BIT_IMPL(ArrayIndexTypeId, 64)
	TEST_BIT_IMPL(VirtualTableShapeId, 65)
	TEST_BIT_IMPL(Code, 66)
	TEST_BIT_IMPL(Function, 67)
	TEST_BIT_IMPL(Managed, 68)
	TEST_BIT_IMPL(MSIL, 69)
	TEST_BIT_IMPL(VirtualBasePointerOffset, 70)
	TEST_BIT_IMPL(VirtualBaseOffset, 71)
	TEST_BIT_IMPL(VirtualBaseDispIndex, 72)
	TEST_STRING_BIT_IMPL(UndecoratedName, 73)
	TEST_BIT_IMPL(Age, 74)
	TEST_BIT_IMPL(Signature, 75)
	TEST_BIT_IMPL(CompilerGenerated, 76)
	TEST_BIT_IMPL(AddressTaken, 77)
	TEST_BIT_IMPL(Rank, 78)
	TEST_BIT_IMPL(LowerBound, 79)
	TEST_BIT_IMPL(UpperBound, 80)
	TEST_BIT_IMPL(LowerBoundId, 81)
	TEST_BIT_IMPL(UpperBoundId, 82)
	TEST_BYTES_BIT_IMPL(DataBytes, 83)
	TEST_BIT_IMPL(TargetSection, 84)
	TEST_BIT_IMPL(TargetOffset, 85)
	TEST_BIT_IMPL(TargetRVA, 86)
	TEST_BIT_IMPL(TargetVA, 87)
	TEST_BIT_IMPL(MachineType, 88)
	TEST_BIT_IMPL(OemId, 89)
	TEST_BIT_IMPL(OemSymbolId, 90)
	TEST_BIT_IMPL(ObjectPointerType, 91)
	TEST_BIT_IMPL(TypeIds, 92)
	TEST_BIT_IMPL(Types, 93)

	int getAnsiName(char *buf, size_t bufsize) const {
		_ASSERTE(buf != 0 && bufsize > 0);
		if (buf == 0 || bufsize == 0) return -1;
		*buf = 0;
		return !Name ? 0 :
			Name == UNNAMED_NAME ? qsnprintf(buf, bufsize, UNNAMED_FMT, (BSTR)Name, SymIndexId) :
			Name == FORMAL_NAME ? qsnprintf(buf, bufsize, FORMAL_FMT, (BSTR)Name, SymIndexId) :
			Name.toAnsi(buf, bufsize);
	}
	string getAnsiName() const {
		return !Name ? string() :
			Name == UNNAMED_NAME ? _sprintf(UNNAMED_FMT, (BSTR)Name, SymIndexId) :
			Name == FORMAL_NAME ? _sprintf(FORMAL_FMT, (BSTR)Name, SymIndexId) :
			Name.toAnsi();
	}
	inline bool TypeIsEquivTo(const DiaSymbol &other) const
		{ return DIA::TypesAreEquiv(*this, other); }

	void Reset() {
		ReqsValid.reset();
		SymIndexId = 0;
		Name.Empty();
		SymTag = SymTagNull; LocationType = 0; Length = 0; AddressSection = 0;
		AddressOffset = 0; RVA = 0; VA = 0; Offset = 0; DataKind = DataIsUnknown;
		BaseType = btNoType; Count = 0; RegisterId = 0; Value.Clear();
		BitPosition = 0; TypeId = 0; UDTKind = 0;
		Type.Release(); LexicalParent.Release(); ClassParent.Release();
		Slot = 0;
		VolatileType = FALSE; ConstType = FALSE; UnalignedType = FALSE;
		Access = 0;
		LibraryName.Empty();
		Platform = 0; Language = 0;
		EditAndContinueEnabled = FALSE;
		FrontEndMajor = 0; FrontEndMinor = 0; FrontEndBuild = 0;
		BackEndMajor = 0; BackEndMinor = 0; BackEndBuild = 0;
		SourceFileName.Empty(); Unused.Empty(); ObjectFileName.Empty();
		ThunkOrdinal = 0; ThisAdjust = 0; VirtualBaseOffset = 0;
		Virtual = FALSE; Intro = FALSE; Pure = FALSE;
		CallingConvention = 0; Token = 0; TimeStamp = 0;
		memset(&Guid, 0, sizeof Guid);
		SymbolsFileName.Empty();
		Reference = FALSE;
		ArrayIndexType.Release();
		Packed = FALSE; Constructor = FALSE; OverloadedOperator = FALSE;
		Nested = FALSE; HasNestedTypes = FALSE; HasAssignmentOperator = FALSE;
		HasCastOperator = FALSE; Scoped = FALSE; VirtualBaseClass = FALSE;
		IndirectVirtualBaseClass = FALSE;
		VirtualBasePointerOffset = 0;
		VirtualTableShape.Release();
		LexicalParentId = 0; ClassParentId = 0; ArrayIndexTypeId = 0;
		VirtualTableShapeId = 0;
		Code = FALSE; Function = FALSE; Managed = FALSE; MSIL = FALSE;
		VirtualBaseDispIndex = 0;
		UndecoratedName.Empty();
		Age = 0; Signature = 0;
		CompilerGenerated = FALSE; AddressTaken = FALSE;
		Rank = 0;
		LowerBound.Release(); UpperBound.Release();
		LowerBoundId = 0; UpperBoundId = 0;
		DataBytes.reset();
		TargetSection = 0; TargetOffset = 0; TargetRVA = 0;
		TargetVA = 0;
		MachineType = IMAGE_FILE_MACHINE_UNKNOWN; OemId = 0; OemSymbolId = 0;
		ObjectPointerType.Release();
		//TypeIds.RemoveAll(); Types.RemoveAll();
	}

	inline string TokenizeSymTag() const
		{ return ::TokenizeSymTag(static_cast<enum SymTagEnum>(SymTag)); }
	inline string TokenizeBasicType() const
		{ return ::TokenizeBasicType(static_cast<enum BasicType>(BaseType)); }
	inline const char *TokenizeCallConv() const
		{ return ::TokenizeCallConv(static_cast<enum CV_call_e>(CallingConvention)); }
	inline string TokenizeDataKind() const
		{ return ::TokenizeDataKind(static_cast<enum DataKind>(DataKind)); }
	string TokenizeUDTKind() const {
		return SymTag == SymTagUDT ?
			::TokenizeUDTKind(static_cast<enum UdtKind>(UDTKind)) : "<none>";
	}
	inline string TokenizeLocationType() const
		{ return ::TokenizeLocationType(static_cast<enum LocationType>(LocationType)); }
	inline wstring TokenizeValue() const
		{ return Value.vt != VT_EMPTY ? TokenizeVariant(Value) : L"<none>"; }
	inline const char *TokenizeRegisterId() const {
		// TODO: platform distinct!
		return ix86_getRegCanon(static_cast<enum CV_HREG_e>(RegisterId));
	}
	inline string TokenizeSymFlag() const
		{ return ::TokenizeSymFlag(getFlag()); }
	DWORD getFlag() const {
		DWORD flag(0);
		switch (SymTag) {
			case SymTagFunction:
				flag |= SYMFLAG_FUNCTION;
				break;
			case SymTagData:
				if (LexicalParent != NULL) {
					DWORD SymTag;
					if (LexicalParent->get_symTag(&SymTag) == S_OK
						&& SymTag == SymTagFunction) flag |= SYMFLAG_LOCAL;
				}
				break;
		} // switch SymTag
		switch (LocationType) {
			case LocIsEnregistered: flag |= SYMFLAG_REGISTER; break;
			case LocIsRegRel: flag |= SYMFLAG_REGREL; break;
			case LocIsSlot: flag |= SYMFLAG_SLOT; break;
			case LocIsTLS: flag |= SYMFLAG_TLSREL; break;
			case LocInMetaData: flag |= SYMFLAG_METADATA; break;
			case LocIsIlRel: flag |= SYMFLAG_ILREL; break;
		} // switch LocationType
		switch (DataKind) {
			case DataIsLocal: flag |= SYMFLAG_LOCAL; break;
			case DataIsParam: flag |= SYMFLAG_PARAMETER; break;
			case DataIsConstant: flag |= SYMFLAG_CONSTANT; break;
		} // switch DataKind
		//if (Value.vt != VT_EMPTY) flag |= SYMFLAG_VALUEPRESENT; break;
		return flag;
	}
	string TokenizeAccess() const {
		switch (Access) {
			case CV_private: return "private";
			case CV_protected: return "protected";
			case CV_public: return "public";
		}
		//_RPT2(_CRT_WARN, "%s(): unexpected Access value (0x%lX)\n", __FUNCTION__, Access);
		return _sprintf("0x%lX", Access);
	}
	string TokenizeLanguage() const {
		switch (Language) {
			case CV_CFL_C: return "C";
			case CV_CFL_CXX: return "C++";
			case CV_CFL_FORTRAN: return "Fortran";
			case CV_CFL_MASM: return "MASM";
			case CV_CFL_PASCAL: return "Pascal";
			case CV_CFL_BASIC: return "Basic";
			case CV_CFL_COBOL: return "Cobol";
			case CV_CFL_LINK: return "Link";
			case CV_CFL_CVTRES: return "CvtRes";
			case CV_CFL_CVTPGD: return "CvtPgd";
		}
		_RPT2(_CRT_WARN, "%s(): unexpected Language value (0x%lX)\n", __FUNCTION__, Language);
		return _sprintf("0x%lX", Language);
	}
	const char *TokenizePlatform() const {
		switch (Platform) {
			case CV_CFL_8080: return "8080";
			case CV_CFL_8086: return "8086";
			case CV_CFL_80286: return "80286";
			case CV_CFL_80386: return "80386";
			case CV_CFL_80486: return "80486";
			case CV_CFL_PENTIUM: return "Pentium";
			case CV_CFL_PENTIUMII/*CV_CFL_PENTIUMPRO*/: return "Pentium II";
			case CV_CFL_PENTIUMIII: return "Pentium III";
			case CV_CFL_MIPS/*CV_CFL_MIPSR4000*/: return "MIPS";
			case CV_CFL_MIPS16: return "MIPS 16";
			case CV_CFL_MIPS32: return "MIPS 32";
			case CV_CFL_MIPS64: return "MIPS 64";
			case CV_CFL_MIPSI: return "MIPS I";
			case CV_CFL_MIPSII: return "MIPS II";
			case CV_CFL_MIPSIII: return "MIPS III";
			case CV_CFL_MIPSIV: return "MIPS IV";
			case CV_CFL_MIPSV: return "MIPS V";
			case CV_CFL_M68000: return "M68000";
			case CV_CFL_M68010: return "M68010";
			case CV_CFL_M68020: return "M68020";
			case CV_CFL_M68030: return "M68030";
			case CV_CFL_M68040: return "M68040";
			case CV_CFL_ALPHA/*CV_CFL_ALPHA_21064*/: return "Alpha";
			case CV_CFL_ALPHA_21164: return "Alpha 21164";
			case CV_CFL_ALPHA_21164A: return "Alpha 21164A";
			case CV_CFL_ALPHA_21264: return "Alpha 21264";
			case CV_CFL_ALPHA_21364: return "Alpha 21364";
			case CV_CFL_PPC601: return "PPC601";
			case CV_CFL_PPC603: return "PPC603";
			case CV_CFL_PPC604: return "PPC604";
			case CV_CFL_PPC620: return "PPC620";
			case CV_CFL_PPCFP: return "PPCFP";
			case CV_CFL_SH3: return "SH3";
			case CV_CFL_SH3E: return "SH3E";
			case CV_CFL_SH3DSP: return "SH3DSP";
			case CV_CFL_SH4: return "SH4";
			case CV_CFL_SHMEDIA: return "SHMEDIA";
			case CV_CFL_ARM3: return "ARM3";
			case CV_CFL_ARM4: return "ARM4";
			case CV_CFL_ARM4T: return "ARM4T";
			case CV_CFL_ARM5: return "ARM5";
			case CV_CFL_ARM5T: return "ARM5T";
			case CV_CFL_OMNI: return "OMNI";
			case CV_CFL_IA64/*CV_CFL_IA64_1*/: return "IA64";
			case CV_CFL_IA64_2: return "IA64 2";
			case CV_CFL_CEE: return "CEE";
			case CV_CFL_AM33: return "AM33";
			case CV_CFL_M32R: return "M32R";
			case CV_CFL_TRICORE: return "TriCore";
			case CV_CFL_AMD64/*CV_CFL_X8664*/: return "AMD64";
			case CV_CFL_EBC: return "EBC";
			case CV_CFL_THUMB: return "Thumb";
		}
		_RPT2(_CRT_WARN, "%s(): unexpected Platform value (0x%lX)\n", __FUNCTION__, Platform);
		return "<unknown>";
	}
	string TokenizeThunkOrdinal() const {
		switch (ThunkOrdinal) {
			case THUNK_ORDINAL_NOTYPE: return "NoType";
			case THUNK_ORDINAL_ADJUSTOR: return "Adjustor";
			case THUNK_ORDINAL_VCALL: return "VCall";
			case THUNK_ORDINAL_PCODE: return "PCode";
			case THUNK_ORDINAL_LOAD: return "Load";
			case THUNK_ORDINAL_TRAMP_INCREMENTAL: return "TrampolineIncremental";
			case THUNK_ORDINAL_TRAMP_BRANCHISLAND: return "TrampolineBranchIsland";
		}
		_RPT2(_CRT_WARN, "%s(): unexpected ThunkOrdinal value (0x%lX)\n", __FUNCTION__, ThunkOrdinal);
		return _sprintf("0x%lX", ThunkOrdinal);
	}
	const char *TokenizeMachineType() const {
		switch (MachineType) {
			case IMAGE_FILE_MACHINE_UNKNOWN: return "Unknown";
			case IMAGE_FILE_MACHINE_I386: return "I386";
			case IMAGE_FILE_MACHINE_R3000: return "R3000";
			case IMAGE_FILE_MACHINE_R4000: return "R4000";
			case IMAGE_FILE_MACHINE_R10000: return "R10000";
			case IMAGE_FILE_MACHINE_WCEMIPSV2: return "WCEMIPSV2";
			case IMAGE_FILE_MACHINE_ALPHA: return "Alpha";
			case IMAGE_FILE_MACHINE_SH3: return "SH3";
			case IMAGE_FILE_MACHINE_SH3DSP: return "SH3 DSP";
			case IMAGE_FILE_MACHINE_SH3E: return "SH3 E";
			case IMAGE_FILE_MACHINE_SH4: return "SH4";
			case IMAGE_FILE_MACHINE_SH5: return "SH5";
			case IMAGE_FILE_MACHINE_ARM: return "ARM";
			case IMAGE_FILE_MACHINE_THUMB: return "THUMB";
			case IMAGE_FILE_MACHINE_AM33: return "AM33";
			case IMAGE_FILE_MACHINE_POWERPC: return "PowerPC";
			case IMAGE_FILE_MACHINE_POWERPCFP: return "PowerPC FP";
			case IMAGE_FILE_MACHINE_IA64: return "IA64";
			case IMAGE_FILE_MACHINE_MIPS16: return "MIPS16";
			case IMAGE_FILE_MACHINE_ALPHA64/*IMAGE_FILE_MACHINE_AXP64*/: return "Alpha64";
			case IMAGE_FILE_MACHINE_MIPSFPU: return "MIPS FPU";
			case IMAGE_FILE_MACHINE_MIPSFPU16: return "MIPS FPU16";
			case IMAGE_FILE_MACHINE_TRICORE: return "TriCore";
			case IMAGE_FILE_MACHINE_CEF: return "CEF";
			case IMAGE_FILE_MACHINE_EBC: return "EBC";
			case IMAGE_FILE_MACHINE_AMD64: return "AMD64";
			case IMAGE_FILE_MACHINE_M32R: return "M32R";
			case IMAGE_FILE_MACHINE_CEE: return "CEE";
		}
		_RPT2(_CRT_WARN, "%s(%hu): unexpected machine id\n", __FUNCTION__, MachineType);
		return "<unknown>";
	}

	struct hash {
		inline size_t operator ()(const DiaSymbol &__x) const throw()
			{ return static_cast<size_t>(__x.SymIndexId); }
	};
	struct hash_by_rva {
		inline size_t operator ()(const DiaSymbol &__x) const
			{ return static_cast<size_t>(__x.RVA & (1 << 26) - 1 | __x.SymTag << 26); }
	};
	friend inline std::size_t hash_value(const DiaSymbol &__x)
		{ return boost::hash_value(__x.SymIndexId); }
	struct sort_by_name : public binary_function<DiaSymbol, DiaSymbol, bool> {
		bool operator ()(const DiaSymbol &lhs, const DiaSymbol &rhs) const {
			const HRESULT cmp(lhs.Name != NULL && lhs.Name != NULL ?
				VarBstrCmp(lhs.Name, rhs.Name, LOCALE_USER_DEFAULT, 0) :
				!lhs.Name && rhs.Name != NULL ? VARCMP_LT :
				lhs.Name != NULL && !rhs.Name ? VARCMP_GT : VARCMP_EQ);
			_ASSERTE(cmp != VARCMP_NULL);
			return cmp == VARCMP_LT || cmp == VARCMP_EQ && lhs.SymTag < rhs.SymTag;
		}
	};
	struct equal_to_by_rva : public binary_function<DiaSymbol, DiaSymbol, bool> {
		inline bool operator ()(const DiaSymbol &lhs, const DiaSymbol &rhs) const
			{ return lhs.RVA == rhs.RVA && lhs.SymTag == rhs.SymTag; }
	};
}; // DiaSymbol

__declspec(align(4)) struct DiaLineNumber {
private:
	bitset<14> ReqsValid;
public:
	CComPtr<IDiaSymbol> Compiland; // 0
	CComPtr<IDiaSourceFile> SourceFile; // 1
	DWORD LineNumber, LineNumberEnd, ColumnNumber, ColumnNumberEnd, // 5
		AddressSection, AddressOffset, RVA; // 8
	ULONGLONG VA; // 9
	DWORD Length, SourceFileId; // 11
	BOOL Statement; // 12
	DWORD CompilandId; // 13

	DiaLineNumber() { Reset(); }
	DiaLineNumber(const CComPtr<IDiaLineNumber> &pLineNumber)
		{ operator ()(pLineNumber); }

	inline bool operator ==(const DiaLineNumber &r) const { return RVA == r.RVA; }
	inline bool operator <(const DiaLineNumber &r) const { return RVA < r.RVA; }

	TEST_BIT_IMPL(Compiland, 0)
	TEST_BIT_IMPL(SourceFile, 1)
	TEST_BIT_IMPL(LineNumber, 2)
	TEST_BIT_IMPL(LineNumberEnd, 3)
	TEST_BIT_IMPL(ColumnNumber, 4)
	TEST_BIT_IMPL(ColumnNumberEnd, 5)
	TEST_BIT_IMPL(AddressSection, 6)
	TEST_BIT_IMPL(AddressOffset, 7)
	TEST_BIT_IMPL(RVA, 8)
	TEST_BIT_IMPL(VA, 9)
	TEST_BIT_IMPL(Length, 10)
	TEST_BIT_IMPL(SourceFileId, 11)
	TEST_BIT_IMPL(Statement, 12)
	TEST_BIT_IMPL(CompilandId, 13)

	bool operator ()(const CComPtr<IDiaLineNumber> &pLineNumber) {
		Reset();
		//_ASSERTE(pLineNumber != NULL);
		if (!pLineNumber) return false;
		HRESULT hr;
		GUARDED_GET(pLineNumber, compiland, Compiland, 0)
		GUARDED_GET(pLineNumber, sourceFile, SourceFile, 1)
		UNGUARDED_GET(pLineNumber, lineNumber, LineNumber, 2)
		UNGUARDED_GET(pLineNumber, lineNumberEnd, LineNumberEnd, 3)
		UNGUARDED_GET(pLineNumber, columnNumber, ColumnNumber, 4)
		UNGUARDED_GET(pLineNumber, columnNumberEnd, ColumnNumberEnd, 5)
		UNGUARDED_GET(pLineNumber, addressSection, AddressSection, 6)
		UNGUARDED_GET(pLineNumber, addressOffset, AddressOffset, 7)
		UNGUARDED_GET(pLineNumber, relativeVirtualAddress, RVA, 8)
		UNGUARDED_GET(pLineNumber, virtualAddress, VA, 9)
		UNGUARDED_GET(pLineNumber, length, Length, 10)
		UNGUARDED_GET(pLineNumber, sourceFileId, SourceFileId, 11)
		UNGUARDED_GET(pLineNumber, statement, Statement, 12)
		UNGUARDED_GET(pLineNumber, compilandId, CompilandId, 13)
		_ASSERTE(LineNumberEnd >= LineNumber); // ???
		if (LineNumberEnd < LineNumber) LineNumberEnd = LineNumber;
		return true;
	}

	void Reset() {
		ReqsValid.reset();
		Compiland.Release(); SourceFile.Release();
		LineNumber = 0; LineNumberEnd = 0; ColumnNumber = 0; ColumnNumberEnd = 0;
		AddressSection = 0; AddressOffset = 0; RVA = 0; VA = 0; Length = 0;
		SourceFileId = 0;
		Statement = FALSE;
		CompilandId = 0;
	}

	struct hash {
		inline size_t operator ()(const DiaLineNumber&__x) const throw()
			{ return static_cast<size_t>(__x.RVA); }
	};
	friend inline std::size_t hash_value(const DiaLineNumber &__x)
		{ return boost::hash_value(__x.RVA); }
}; // DiaLineNumber

__declspec(align(4)) struct DiaSourceFile {
private:
	bitset<5> ReqsValid;
public:
	DWORD UniqueId; // 0
	CDiaBSTR FileName; // 1
	DWORD ChecksumType; // 2
	hash_set<DiaSymbol, DiaSymbol::hash/*boost::hash<DiaSymbol>*/> Compilands; // 3
	boost::shared_localptr<BYTE, NONZEROLPTR> Checksum; // 4

	DiaSourceFile() { Reset(); }
	DiaSourceFile(const CComPtr<IDiaSourceFile> &pSourceFile)
		{ operator()(pSourceFile); }

	inline bool operator ==(const DiaSourceFile &rhs) const
		{ return UniqueId == rhs.UniqueId; }
	inline bool operator <(const DiaSourceFile &rhs) const
		{ return UniqueId < rhs.UniqueId; }

	TEST_BIT_IMPL(UniqueId, 0)
	TEST_STRING_BIT_IMPL(FileName, 1)
	TEST_BIT_IMPL(ChecksumType, 2)
	TEST_BIT_IMPL(Compilands, 3)
	TEST_BYTES_BIT_IMPL(Checksum, 4)

	bool operator ()(const CComPtr<IDiaSourceFile> &pSourceFile) {
		Reset();
		//_ASSERTE(pSourceFile != NULL);
		if (!pSourceFile) return false;
		HRESULT hr;
		UNGUARDED_GET(pSourceFile, uniqueId, UniqueId, 0)
		UNGUARDED_GET(pSourceFile, fileName, FileName, 1)
		UNGUARDED_GET(pSourceFile, checksumType, ChecksumType, 2)
		CComPtr<IDiaEnumSymbols> pCompilands;
		if ((hr = pSourceFile->get_compilands(&pCompilands)) == S_OK) {
			_ASSERTE(pCompilands != NULL);
			ReqsValid.set(3);
			CComPtr<IDiaSymbol> pSymbol;
			ULONG celt;
			while (pCompilands->Next(1, &pSymbol, &celt) == S_OK) {
				_ASSERTE(celt >= 1);
				_ASSERTE(pSymbol != NULL);
				Compilands.insert(pSymbol);
				pSymbol.Release();
			}
		}
		GUARDED_GETBYTES(pSourceFile, checksum, Checksum, 3)
		return true;
	}

	void Reset() {
		ReqsValid.reset();
		UniqueId = 0;
		FileName.Empty();
		ChecksumType = 0;
		Compilands.clear();
		Checksum.reset();
	}

	struct hash {
		inline size_t operator ()(const DiaSourceFile &__x) const throw()
			{ return static_cast<size_t>(__x.UniqueId); }
	};
	friend inline std::size_t hash_value(const DiaSourceFile &__x)
		{ return boost::hash_value(__x.UniqueId); }
}; // DiaSourceFile

__declspec(align(4)) struct DiaFrame {
private:
	bitset<17> ReqsValid;
public:
	DWORD AddressSection, AddressOffset, RVA; // 2
	ULONGLONG VA; // 3
	DWORD LengthBlock, LengthLocals, LengthParams, MaxStack, // 7
		LengthProlog, LengthSavedRegisters; // 9
	CDiaBSTR Program; // 10
	BOOL SystemExceptionHandling, CplusplusExceptionHandling, // 12
		FunctionStart, AllocatesBasePointer; // 14
	DWORD Type; // 15
	CComPtr<IDiaFrameData> FunctionParent; // 16

	DiaFrame() { Reset(); }
	DiaFrame(const CComPtr<IDiaFrameData> &pFrame) { operator ()(pFrame); }

	inline bool operator ==(const DiaFrame &rhs) const { return RVA == rhs.RVA; }
	inline bool operator <(const DiaFrame &rhs) const { return RVA < rhs.RVA; }

	TEST_BIT_IMPL(AddressSection, 0)
	TEST_BIT_IMPL(AddressOffset, 1)
	TEST_BIT_IMPL(RVA, 2)
	TEST_BIT_IMPL(VA, 3)
	TEST_BIT_IMPL(LengthBlock, 4)
	TEST_BIT_IMPL(LengthLocals, 5)
	TEST_BIT_IMPL(LengthParams, 6)
	TEST_BIT_IMPL(MaxStack, 7)
	TEST_BIT_IMPL(LengthProlog, 8)
	TEST_BIT_IMPL(LengthSavedRegisters, 9)
	TEST_STRING_BIT_IMPL(Program, 10)
	TEST_BIT_IMPL(SystemExceptionHandling, 11)
	TEST_BIT_IMPL(CplusplusExceptionHandling, 12)
	TEST_BIT_IMPL(FunctionStart, 13)
	TEST_BIT_IMPL(AllocatesBasePointer, 14)
	TEST_BIT_IMPL(Type, 15)
	TEST_BIT_IMPL(FunctionParent, 16)

	bool operator ()(const CComPtr<IDiaFrameData> &pFrame) {
		Reset();
		//_ASSERTE(pFrame != NULL);
		if (!pFrame) return false;
		HRESULT hr;
		UNGUARDED_GET(pFrame, addressSection, AddressSection, 0)
		UNGUARDED_GET(pFrame, addressOffset, AddressOffset, 1)
		UNGUARDED_GET(pFrame, relativeVirtualAddress, RVA, 2)
		UNGUARDED_GET(pFrame, virtualAddress, VA, 3)
		UNGUARDED_GET(pFrame, lengthBlock, LengthBlock, 4)
		UNGUARDED_GET(pFrame, lengthLocals, LengthLocals, 5)
		UNGUARDED_GET(pFrame, lengthParams, LengthParams, 6)
		UNGUARDED_GET(pFrame, maxStack, MaxStack, 7)
		UNGUARDED_GET(pFrame, lengthProlog, LengthProlog, 8)
		UNGUARDED_GET(pFrame, lengthSavedRegisters, LengthSavedRegisters, 9)
		UNGUARDED_GET(pFrame, program, Program, 10)
		UNGUARDED_GET(pFrame, systemExceptionHandling, SystemExceptionHandling, 11)
		UNGUARDED_GET(pFrame, cplusplusExceptionHandling, CplusplusExceptionHandling, 12)
		UNGUARDED_GET(pFrame, functionStart, FunctionStart, 13)
		UNGUARDED_GET(pFrame, allocatesBasePointer, AllocatesBasePointer, 14)
		UNGUARDED_GET(pFrame, type, Type, 15)
		GUARDED_GET(pFrame, functionParent, FunctionParent, 16)
		return true;
	}

	void Reset() {
		ReqsValid.reset();
		AddressSection = 0; AddressOffset = 0; RVA = 0; VA = 0; LengthBlock = 0;
		LengthLocals = 0; LengthParams = 0; MaxStack = 0; LengthProlog = 0;
		LengthSavedRegisters = 0;
		Program.Empty();
		SystemExceptionHandling = FALSE; CplusplusExceptionHandling = FALSE;
		FunctionStart = FALSE; AllocatesBasePointer = FALSE;
		Type = 0;
		FunctionParent.Release();
	}

	struct hash {
		inline size_t operator ()(const DiaFrame &__x) const throw()
			{ return static_cast<size_t>(__x.RVA); }
	};
	friend inline std::size_t hash_value(const DiaFrame &__x)
		{ return boost::hash_value(__x.RVA); }
}; // DiaFrame

__declspec(align(4)) struct DiaSegment {
private:
	bitset<9> ReqsValid;
public:
	DWORD Frame, Offset, Length; // 2
	BOOL Read, Write, Execute; // 5
	DWORD AddressSection, RVA; // 7
	ULONGLONG VA; // 8

	DiaSegment() { Reset(); }
	DiaSegment(const CComPtr<IDiaSegment> &pSegment) { operator ()(pSegment); }

	inline bool operator ==(const DiaSegment &rhs) const { return RVA == rhs.RVA; }
	inline bool operator <(const DiaSegment &rhs) const { return RVA < rhs.RVA; }

	TEST_BIT_IMPL(Frame, 0)
	TEST_BIT_IMPL(Offset, 1)
	TEST_BIT_IMPL(Length, 2)
	TEST_BIT_IMPL(Read, 3)
	TEST_BIT_IMPL(Write, 4)
	TEST_BIT_IMPL(Execute, 5)
	TEST_BIT_IMPL(AddressSection, 6)
	TEST_BIT_IMPL(RVA, 7)
	TEST_BIT_IMPL(VA, 8)

	bool operator ()(const CComPtr<IDiaSegment> &pSegment) {
		Reset();
		//_ASSERTE(pSegment != NULL);
		if (!pSegment) return false;
		HRESULT hr;
		UNGUARDED_GET(pSegment, frame, Frame, 0)
		UNGUARDED_GET(pSegment, offset, Offset, 1)
		UNGUARDED_GET(pSegment, length, Length, 2)
		UNGUARDED_GET(pSegment, read, Read, 3)
		UNGUARDED_GET(pSegment, write, Write, 4)
		UNGUARDED_GET(pSegment, execute, Execute, 5)
		UNGUARDED_GET(pSegment, addressSection, AddressSection, 6)
		UNGUARDED_GET(pSegment, relativeVirtualAddress, RVA, 7)
		UNGUARDED_GET(pSegment, virtualAddress, VA, 8)
		return true;
	}

	void Reset() {
		ReqsValid.reset();
		Frame = 0; Offset = 0; Length = 0;
		Read = FALSE; Write = FALSE; Execute = FALSE;
		AddressSection = 0; RVA = 0; VA = 0;
	}

	struct hash {
		inline size_t operator ()(const DiaSegment &__x) const throw()
			{ return static_cast<size_t>(__x.RVA); }
	};
	friend inline std::size_t hash_value(const DiaSegment &__x)
		{ return boost::hash_value(__x.RVA); }
}; // DiaSegment

__declspec(align(4)) struct DiaSectionContrib {
private:
	bitset<21> ReqsValid;
public:
	CComPtr<IDiaSymbol> Compiland; // 0
	DWORD AddressSection, AddressOffset, RVA; // 3
	ULONGLONG VA; // 4
	DWORD Length; // 5
	BOOL NotPaged, Code, InitializedData, UninitializedData, Remove, // 10
		Comdat, Discardable, NotCached, Share, Execute, Read, Write; // 17
	DWORD DataCrc, RelocationsCrc, CompilandId; // 20

	DiaSectionContrib() { Reset(); }
	DiaSectionContrib(const CComPtr<IDiaSectionContrib> &pSectionContrib) { operator ()(pSectionContrib); }

	inline bool operator ==(const DiaSectionContrib &rhs) const { return RVA == rhs.RVA; }
	inline bool operator <(const DiaSectionContrib &rhs) const { return RVA < rhs.RVA; }

	TEST_BIT_IMPL(AddressSection, 1)
	TEST_BIT_IMPL(AddressOffset, 2)
	TEST_BIT_IMPL(RVA, 3)
	TEST_BIT_IMPL(VA, 4)
	TEST_BIT_IMPL(Length, 5)
	TEST_BIT_IMPL(NotPaged, 6)
	TEST_BIT_IMPL(Code, 7)
	TEST_BIT_IMPL(InitializedData, 8)
	TEST_BIT_IMPL(UninitializedData, 9)
	TEST_BIT_IMPL(Remove, 10)
	TEST_BIT_IMPL(Comdat, 11)
	TEST_BIT_IMPL(Discardable, 12)
	TEST_BIT_IMPL(NotCached, 13)
	TEST_BIT_IMPL(Share, 14)
	TEST_BIT_IMPL(Execute, 15)
	TEST_BIT_IMPL(Read, 16)
	TEST_BIT_IMPL(Write, 17)
	TEST_BIT_IMPL(DataCrc, 18)
	TEST_BIT_IMPL(RelocationsCrc, 19)
	TEST_BIT_IMPL(CompilandId, 20)

	bool operator ()(const CComPtr<IDiaSectionContrib> &pSectionContrib) {
		Reset();
		//_ASSERTE(pSectionContrib != NULL);
		if (!pSectionContrib) return false;
		HRESULT hr;
		GUARDED_GET(pSectionContrib, compiland, Compiland, 0)
		UNGUARDED_GET(pSectionContrib, addressSection, AddressSection, 1)
		UNGUARDED_GET(pSectionContrib, addressOffset, AddressOffset, 2)
		UNGUARDED_GET(pSectionContrib, relativeVirtualAddress, RVA, 3)
		UNGUARDED_GET(pSectionContrib, virtualAddress, VA, 4)
		UNGUARDED_GET(pSectionContrib, length, Length, 5)
		UNGUARDED_GET(pSectionContrib, notPaged, NotPaged, 6)
		UNGUARDED_GET(pSectionContrib, code, Code, 7)
		UNGUARDED_GET(pSectionContrib, initializedData, InitializedData, 8)
		UNGUARDED_GET(pSectionContrib, uninitializedData, UninitializedData, 9)
		UNGUARDED_GET(pSectionContrib, remove, Remove, 10)
		UNGUARDED_GET(pSectionContrib, comdat, Comdat, 11)
		UNGUARDED_GET(pSectionContrib, discardable, Discardable, 12)
		UNGUARDED_GET(pSectionContrib, notCached, NotCached, 13)
		UNGUARDED_GET(pSectionContrib, share, Share, 14)
		UNGUARDED_GET(pSectionContrib, execute, Execute, 15)
		UNGUARDED_GET(pSectionContrib, read, Read, 16)
		UNGUARDED_GET(pSectionContrib, write, Write, 17)
		UNGUARDED_GET(pSectionContrib, dataCrc, DataCrc, 18)
		UNGUARDED_GET(pSectionContrib, relocationsCrc, RelocationsCrc, 19)
		UNGUARDED_GET(pSectionContrib, compilandId, CompilandId, 20)
		return true;
	}

	void Reset() {
		ReqsValid.reset();
		Compiland.Release();
		AddressSection = 0; AddressOffset = 0; RVA = 0; VA = 0; Length = 0;
		NotPaged = FALSE; Code = FALSE; InitializedData = FALSE;
		UninitializedData = FALSE; Remove = FALSE; Comdat = FALSE;
		Discardable = FALSE; NotCached = FALSE; Share = FALSE; Execute = FALSE;
		Read = FALSE; Write = FALSE;
		DataCrc = 0; RelocationsCrc = 0; CompilandId = 0;
	}

	struct hash {
		inline size_t operator ()(const DiaSectionContrib &__x) const throw()
			{ return static_cast<size_t>(__x.RVA); }
	};
	friend inline std::size_t hash_value(const DiaSectionContrib &__x)
		{ return boost::hash_value(__x.RVA); }
}; // DiaSectionContrib

__declspec(align(4)) struct DiaInjectedSource {
private:
	bitset<7> ReqsValid;
public:
	DWORD Crc; // 0
	ULONGLONG Length; // 1
	CDiaBSTR Filename, ObjectFilename, VirtualFilename; // 4
	DWORD SourceCompression; // 5
	boost::shared_localptr<BYTE, NONZEROLPTR> Source; // 6

	DiaInjectedSource() { Reset(); }
	DiaInjectedSource(const CComPtr<IDiaInjectedSource> &pInjectedSource)
		{ operator ()(pInjectedSource); }

	inline bool operator <(const DiaInjectedSource &rhs) const {
		return VarBstrCmp(Filename, rhs.Filename, LOCALE_USER_DEFAULT, NORM_IGNORECASE) == VARCMP_LT;
		//return _wcsicmp(Filename, rhs.Filename) < 0;
		//return boost::ilexicographical_compare(Filename, rhs.Filename);
	}

	TEST_BIT_IMPL(Crc, 0)
	TEST_BIT_IMPL(Length, 1)
	TEST_STRING_BIT_IMPL(Filename, 2)
	TEST_STRING_BIT_IMPL(ObjectFilename, 3)
	TEST_STRING_BIT_IMPL(VirtualFilename, 4)
	TEST_BIT_IMPL(SourceCompression, 5)
	TEST_BYTES_BIT_IMPL(Source, 6)

	bool operator ()(const CComPtr<IDiaInjectedSource> &pInjectedSource) {
		Reset();
		//_ASSERTE(pInjectedSource != NULL);
		if (!pInjectedSource) return false;
		HRESULT hr;
		UNGUARDED_GET(pInjectedSource, crc, Crc, 0)
		UNGUARDED_GET(pInjectedSource, length, Length, 1)
		UNGUARDED_GET(pInjectedSource, filename, Filename, 2)
		UNGUARDED_GET(pInjectedSource, objectFilename, ObjectFilename, 3)
		UNGUARDED_GET(pInjectedSource, virtualFilename, VirtualFilename, 4)
		UNGUARDED_GET(pInjectedSource, sourceCompression, SourceCompression, 5)
		GUARDED_GETBYTES(pInjectedSource, source, Source, 6)
		return true;
	}

	void Reset() {
		ReqsValid.reset();
		Crc = 0; Length = 0;
		Filename.Empty(); ObjectFilename.Empty(); VirtualFilename.Empty();
		SourceCompression = 0;
		Source.reset();
	}
}; // DiaInjectedSource

#undef GUARDED_GETX
#undef GUARDED_GET
#undef GUARDED_GETBYTES
#undef UNGUARDED_GET
#undef UNGUARDED_GETBYTES
#undef TEST_BIT_IMPL
#undef TEST_STRING_BIT_IMPL
#undef TEST_BYTES_BIT_IMPL

class DiaSymChildren : public CComPtr<IDiaEnumSymbols> {
private:
	LONG Count;

public:
	DiaSymChildren() : Count(0) { }
	DiaSymChildren(const CComPtr<IDiaEnumSymbols> &pEnumSymbols) : Count(0),
		CComPtr<IDiaEnumSymbols>(pEnumSymbols) {
		if (p == NULL) return;
		HRESULT hr(p->get_Count(&Count));
		if (FAILED(hr)) {
			_RPT3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n",
				__FUNCTION__, "IDiaEnumSymbols::get_Count", hr);
			COM_Error("IDiaEnumSymbols::get_Count", hr);
		}
		if (hr != S_OK) Count = -1;
	}
	DiaSymChildren(const CComPtr<IDiaSymbol> &pSymbol, enum SymTagEnum SymTag = SymTagNull,
		LPCOLESTR name = NULL, DWORD compareFlags = nsNone)
			{ operator ()(pSymbol, SymTag, name, compareFlags); }
	DiaSymChildren(DWORD const SymIndexId, enum SymTagEnum SymTag = SymTagNull,
		LPCOLESTR name = NULL, DWORD compareFlags = nsNone)
			{ operator ()(SymIndexId, SymTag, name, compareFlags); }
	DiaSymChildren(const DiaSymbol &Symbol, enum SymTagEnum SymTag = SymTagNull,
		LPCOLESTR name = NULL, DWORD compareFlags = nsNone)
			{ operator ()(Symbol, SymTag, name, compareFlags); }

	bool operator ()(const CComPtr<IDiaSymbol> &pSymbol, enum SymTagEnum SymTag = SymTagNull,
		LPCOLESTR name = NULL, DWORD compareFlags = nsNone) {
		Release();
		_ASSERTE(pSymbol != NULL);
		if (pSymbol != NULL) try {
			HRESULT hr(pSymbol->findChildren(SymTag, name, compareFlags, operator &()));
			if (FAILED(hr)) {
				COM_Error("IDiaSymbol::findChildren", hr);
				throw fmt_exception("%s(...) returned %08lX", "IDiaSymbol::findChildren", hr);
			}
			if (hr != S_OK) { // no match
				_ASSERTE(p == NULL);
				return false;
			}
			_ASSERTE(p != NULL);
			if (FAILED(hr = p->get_Count(&Count))) {
				_RPT3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n",
					__FUNCTION__, "IDiaEnumSymbols::get_Count", hr);
				COM_Error("IDiaEnumSymbols::get_Count", hr);
			}
			if (hr != S_OK) Count = -1;
		} catch (GENERAL_CATCH_FILTER) {
			Release();
			_RPTF2(_CRT_WARN, "%s(...): %s\n", __FUNCTION__, e.what());
		}
		return p != NULL;
	}
	bool operator ()(DWORD SymIndexId, enum SymTagEnum SymTag = SymTagNull,
		LPCOLESTR name = NULL, DWORD compareFlags = nsNone) {
		Release();
		_ASSERTE(SymIndexId != 0);
		if (SymIndexId == 0) return false;
		const CComPtr<IDiaSymbol> pSymbol(symbolById(SymIndexId));
		return pSymbol != NULL ?
			operator ()(pSymbol, SymTag, name, compareFlags) : false;
	}
	inline bool operator ()(const DiaSymbol &Symbol, enum SymTagEnum SymTag = SymTagNull,
		LPCOLESTR name = NULL, DWORD compareFlags = nsNone)
			{ return operator ()(Symbol.SymIndexId, SymTag, name, compareFlags); }

	inline bool operator ()() const { return p != NULL; }
	inline operator LONG() const { return Count; }

	bool Next(CComPtr<IDiaSymbol> &pSymbol) const {
		pSymbol.Release();
		_ASSERTE(p != NULL);
		if (p == NULL) return false;
		HRESULT hr;
		ULONG celt;
		if ((hr = p->Next(1, &pSymbol, &celt)) != S_OK) return false;
		_ASSERTE(celt >= 1);
		_ASSERTE(pSymbol != NULL);
		return true;
	}
	inline void Reset() const {
		_ASSERTE(p != NULL);
		if (p != NULL) p->Reset();
	}
	inline void Release() {
		__super::Release();
		Count = 0;
	}
}; // DiaSymChildren

static tid_t CreateTypeFromPDB(const CComPtr<IDiaSymbol> &, const DiaSymbol &,
	bool accept_incomplete = false);

class types_t : public boost::multi_index::multi_index_container<DiaSymbol, boost::multi_index::indexed_by<
	/*0*/boost::multi_index::ordered_non_unique<boost::multi_index::identity<DiaSymbol>, DiaSymbol::sort_by_name>,
	/*1*/boost::multi_index::sequenced<>,
	/*2*/boost::multi_index::hashed_unique<boost::multi_index::identity<DiaSymbol>, DiaSymbol::hash>
> > {
public:
	bool Add(const_reference val) {
		_ASSERTE(static_cast<bool>(val));
		if (!val) return false;
		/*
		pair<iterator, iterator> dupes(equal_range(val));
		iterator tmp;
		while (dupes.first != dupes.second)
			if (val.Age > dupes.first->Age)
				erase(tmp = dupes.first++);
			else {
				if (dupes.first->Age > val.Age || dupes.first->TypeIsEquivTo(val))
					return false;
				++dupes.first;
			}
		*/
		if (val.hasName()
			&& wcscmp(val.Name, UNNAMED_NAME) != 0/*!boost::equals(static_cast<BSTR>(val.Name), UNNAMED_NAME)*/
			&& wcscmp(val.Name, FORMAL_NAME) != 0/*!boost::equals(static_cast<BSTR>(val.Name), FORMAL_NAME)*/) {
			const iterator dupe(find(val));
			if (dupe != end()) return replace(dupe, val); // replace old versions
		}
		return get<2>().insert(val).second;
	}
	void SaveTypes() const {
		cmsg << log_prefix << "Creating types...";
		// pass in sequenced order
		for (nth_index_const_iterator<1>::type i = get<1>().begin(); i != get<1>().end(); ++i) {
			if (wasBreak()) throw 1;
			CreateTypeFromPDB(*i, *i);
		}
		cmsg << "done" << endl;
	}
}; // types_t

class statics_t : public boost::multi_index::multi_index_container<DiaSymbol, boost::multi_index::indexed_by<
	/*0*/boost::multi_index::hashed_unique<boost::multi_index::identity<DiaSymbol>, DiaSymbol::hash_by_rva, DiaSymbol::equal_to_by_rva>,
	/*1*/boost::multi_index::sequenced<>
> > {
public:
	bool Add(const_reference val) {
		_ASSERTE(static_cast<bool>(val) && val.LocationType == LocIsStatic/*
			&& isEnabled(static_cast<ea_t>(SymBase) + val.RVA)
			&& !is_spec_ea(static_cast<ea_t>(SymBase) + val.RVA)*/);
		if (!val || val.LocationType != LocIsStatic/*
			|| !isEnabled(static_cast<ea_t>(SymBase) + val.RVA)
			|| is_spec_ea(static_cast<ea_t>(SymBase) + val.RVA)*/) return false;
		/*
		pair<iterator, iterator> dupes(equal_range(val));
		iterator tmp;
		while (dupes.first != dupes.second)
			if (val.Age > dupes.first->Age)
				erase(tmp = dupes.first++);
			else {
				if (dupes.first->Age > val.Age || dupes.first->TypeIsEquivTo(val))
					return false;
				++dupes.first;
			}
		*/
		const iterator dupe(find(val));
		return dupe != end() ? replace(dupe, val) : insert(val).second;
	}
}; // statics_t

static bool TypesAreEquiv(const CComPtr<IDiaSymbol> &pSym1, const CComPtr<IDiaSymbol> &pSym2) {
	return !pSym1 && !pSym2 ? true :
		!pSym1 && pSym2 != NULL || pSym1 != NULL && !pSym2 ? false :
		TypesAreEquiv(DiaSymbol(pSym1), DiaSymbol(pSym2));
}
static bool TypesAreEquiv(const DiaSymbol &Sym1, const DiaSymbol &Sym2) {
	if (Sym1.SymTag != Sym2.SymTag || Sym1.Length != Sym2.Length
		|| Sym1.LocationType != Sym2.LocationType
		|| Sym1.RVA != Sym2.RVA/* || Sym1.Age != Sym2.Age*/
		|| !Sym1.Name && (bool)Sym2.Name || (bool)Sym1.Name && !Sym2.Name
		|| (bool)Sym1.Name && (bool)Sym2.Name && VarBstrCmp(Sym1.Name, Sym2.Name,
			LOCALE_USER_DEFAULT, 0) != VARCMP_EQ) return false;
	switch (Sym1.SymTag) {
		case SymTagDimension:
			if (Sym1.Rank != Sym2.Rank || !TypesAreEquiv(Sym1.LowerBound, Sym2.LowerBound)
				|| !TypesAreEquiv(Sym1.UpperBound, Sym2.UpperBound)) return false;
			break;
		case SymTagArrayType:
			if (Sym1.Rank != Sym2.Rank || Sym1.Count != Sym2.Count
				|| !TypesAreEquiv(Sym1.ArrayIndexType, Sym2.ArrayIndexType)) return false;
			break;
		case SymTagBaseClass:
			if (Sym1.IndirectVirtualBaseClass != Sym2.IndirectVirtualBaseClass
				|| Sym1.Offset != Sym2.Offset
				|| Sym1.VirtualBaseClass != Sym2.VirtualBaseClass
				|| Sym1.VirtualBaseDispIndex != Sym2.VirtualBaseDispIndex
				|| Sym1.VirtualBasePointerOffset != Sym2.VirtualBasePointerOffset)
				return false;
			break;
		case SymTagFunctionType:
			if (Sym1.CallingConvention != Sym2.CallingConvention
				|| Sym1.ThisAdjust != Sym2.ThisAdjust
				|| !TypesAreEquiv(Sym1.ObjectPointerType, Sym2.ObjectPointerType))
				return false;
		case SymTagPointerType:
			if (Sym1.Reference != Sym2.Reference) return false;
		case SymTagVTableShape:
			if (Sym1.Count != Sym2.Count) return false;
			break;
		case SymTagBaseType:
			if (Sym1.BaseType != Sym2.BaseType) return false;
			break;
		case SymTagData:
			if (Sym1.DataKind != Sym2.DataKind) return false;
			break;
		case SymTagUDT:
			if (Sym1.UDTKind != Sym2.UDTKind || Sym1.Constructor != Sym2.Constructor
				|| Sym1.HasAssignmentOperator != Sym2.HasAssignmentOperator
				|| Sym1.HasCastOperator != Sym2.HasCastOperator
				|| Sym1.HasNestedTypes != Sym2.HasNestedTypes
				|| Sym1.OverloadedOperator != Sym2.OverloadedOperator
				|| Sym1.Packed != Sym2.Packed) return false;
		case SymTagEnum:
			if (Sym1.Nested != Sym2.Nested || Sym1.Scoped != Sym2.Scoped)
				return false;
			break;
		case SymTagCompiland:
			if (Sym1.EditAndContinueEnabled != Sym2.EditAndContinueEnabled
				|| !Sym1.LibraryName.operator ==(Sym2.LibraryName)
				|| !Sym1.SourceFileName.operator ==(Sym2.SourceFileName)) return false;
			break;
		case SymTagCompilandDetails:
			if (Sym1.BackEndMajor != Sym2.BackEndMajor || Sym1.BackEndMinor != Sym2.BackEndMinor || Sym1.BackEndBuild != Sym2.BackEndBuild
				|| Sym1.FrontEndMajor != Sym2.FrontEndMajor || Sym1.FrontEndMinor != Sym2.FrontEndMinor || Sym1.FrontEndBuild != Sym2.FrontEndBuild
				|| Sym1.EditAndContinueEnabled != Sym2.EditAndContinueEnabled
				|| Sym1.Language != Sym2.Language || Sym1.Platform != Sym2.Platform)
				return false;
			break;
		case SymTagCustomType:
			if (Sym1.OemId != Sym2.OemId || Sym1.OemSymbolId != Sym2.OemSymbolId)
				return false;
		case SymTagCustom:
			if (!IsEqualGUID(Sym1.Guid, Sym2.Guid)/*
				|| Sym1.DataBytes != Sym2.DataBytes*/) return false;
			break;
	}
	switch (Sym1.LocationType) {
		case LocIsBitField:
			if (Sym1.BitPosition != Sym2.BitPosition) return false;
			break;
		case LocIsThisRel:
		case LocIsIlRel:
			if (Sym1.Offset != Sym2.Offset) return false;
			break;
		case LocIsRegRel:
			if (Sym1.Offset != Sym2.Offset) return false;
		case LocIsEnregistered:
			if (Sym1.RegisterId != Sym2.RegisterId) return false;
			break;
		case LocIsSlot:
			if (Sym1.Slot != Sym2.Slot) return false;
			break;
		case LocInMetaData:
			if (Sym1.Token != Sym2.Token) return false;
			break;
		case LocIsStatic:
			if (Sym1.VA != Sym2.VA || Sym1.RVA != Sym2.RVA) return false;
		case LocIsTLS:
			if (Sym1.AddressSection != Sym2.AddressSection
				|| Sym1.AddressOffset != Sym2.AddressOffset) return false;
	}
	return TypesAreEquiv(Sym1.LexicalParent, Sym2.LexicalParent)
		&& TypesAreEquiv(Sym1.Type, Sym2.Type);
}

#ifdef _DEBUG

#define IS_BOOL_PRESENT(str, x) if (str.x != FALSE) oss << " " #x;
#define IS_TYPE_PRESENT(str, x) if (str.x##Id != 0) { \
		oss << " " #x "Id=" << ashex(str.x##Id); \
		if (str.x == NULL) oss << " (" #x "=NULL)"; \
	} else if (str.x != NULL) \
		oss << " " #x "!=NULL (" #x "Id=0)";
#define IS_STRING_PRESENT(str, x) if (/*str.has##x() || */str.x) \
	oss << " " #x "=\"" << (BSTR)str.x << '\"';
#define IS_INT_PRESENT(str, x) if (/*str.has##x() || */str.x != 0) \
	oss << " " #x "=" << ashex(str.x);

static void PrintSymbol(const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Symbol, uint indent, hash_set<DWORD> &path) {
	_ASSERTE(Symbol());
	ostringstream oss;
	if (indent > 0) oss << string(indent << 1, ' '); // indention
	oss << "SymId " << ashex(Symbol.SymIndexId) << ": SymTag=" << Symbol.TokenizeSymTag();
	IS_STRING_PRESENT(Symbol, Name)
	if (Symbol.LocationType != LocIsNull) oss << " LocationType=" << Symbol.TokenizeLocationType();
	if (/*Symbol.SymTag == SymTagFunction || Symbol.SymTag == SymTagBlock
		|| Symbol.SymTag == SymTagData || Symbol.SymTag == SymTagFuncDebugStart
		|| Symbol.SymTag == SymTagFuncDebugEnd || Symbol.SymTag == SymTagLabel
		|| Symbol.SymTag == SymTagPublicSymbol || Symbol.SymTag == SymTagThunk
		|| */Symbol.LocationType == LocIsStatic || Symbol.LocationType == LocIsTLS
		|| Symbol.AddressSection != 0 || Symbol.AddressOffset != 0)
		oss << " Address=" << ashex(Symbol.AddressSection, (streamsize)8) << ':' <<
		ashex(Symbol.AddressOffset, (streamsize)8);
	if (Symbol.LocationType == LocIsStatic || Symbol.RVA != 0)
		oss << " RVA=" << ashex(Symbol.RVA, (streamsize)8);
	if (Symbol.LocationType == LocIsStatic || Symbol.VA != 0)
		oss << " VA=" << ashex(Symbol.VA, (streamsize)16);
	if (Symbol.SymTag == SymTagBlock || Symbol.SymTag == SymTagFunction
		|| Symbol.SymTag == SymTagThunk || Symbol.SymTag == SymTagArrayType
		|| Symbol.SymTag == SymTagBaseType || Symbol.SymTag == SymTagPointerType
		|| Symbol.SymTag == SymTagUDT || Symbol.LocationType == LocIsBitField
		|| Symbol.Length > 0) oss << " Length=" << ashex(Symbol.Length);
	if (Symbol.SymTag == SymTagData || Symbol.DataKind != DataIsUnknown)
		oss << " DataKind=" << Symbol.TokenizeDataKind();
	if (Symbol.SymTag == SymTagBaseType || Symbol.BaseType != btNoType)
		oss << " BaseType=" << Symbol.TokenizeBasicType();
	if (Symbol.SymTag == SymTagUDT) oss << " UDTKind=" << Symbol.TokenizeUDTKind();
	if (Symbol.SymTag == SymTagFunctionType) oss << " CallingConvention=" << Symbol.TokenizeCallConv();
	if (Symbol.SymTag == SymTagArrayType || Symbol.SymTag == SymTagFunctionType
		|| Symbol.SymTag == SymTagVTableShape || Symbol.Count > 0)
		oss << " Count=" << dec << Symbol.Count;
	if (Symbol.SymTag == SymTagArrayType || Symbol.SymTag == SymTagDimension
		|| Symbol.Rank != 0) oss << " Rank=" << ashex(Symbol.Rank);
	IS_TYPE_PRESENT(Symbol, LowerBound)
	IS_TYPE_PRESENT(Symbol, UpperBound)
	if (Symbol.LocationType == LocIsRegRel || Symbol.LocationType == LocIsEnregistered)
		oss << " RegisterId=" << Symbol.TokenizeRegisterId();
	if (Symbol.SymTag == SymTagBaseClass || Symbol.LocationType == LocIsRegRel
		|| Symbol.LocationType == LocIsThisRel || Symbol.LocationType == LocIsBitField
		|| Symbol.LocationType == LocIsIlRel || Symbol.Offset != 0)
		oss << " Offset=" << asshex(Symbol.Offset);
	if (Symbol.SymTag == SymTagData && Symbol.DataKind == DataIsConstant
		//&& Symbol.LocationType == LocIsConstant || Symbol.Value.vt != VT_EMPTY
		|| Symbol.SymTag == SymTagCompilandEnv)
		oss << " Value=" << Symbol.TokenizeValue();
	if (/*Symbol.SymTag == SymTagData || */Symbol.LocationType == LocIsBitField
		|| Symbol.BitPosition != 0) oss << " BitPosition=" << dec << Symbol.BitPosition;
	IS_TYPE_PRESENT(Symbol, Type)
	IS_BOOL_PRESENT(Symbol, Reference)
	IS_TYPE_PRESENT(Symbol, ClassParent)
	IS_BOOL_PRESENT(Symbol, VolatileType)
	IS_BOOL_PRESENT(Symbol, ConstType)
	IS_BOOL_PRESENT(Symbol, UnalignedType)
	if (/*Symbol.SymTag == SymTagFunction || Symbol.ClassParentId != 0
		|| Symbol.ClassParent != NULL || */Symbol.Access != 0)
		oss << " Access=" << Symbol.TokenizeAccess();
	if (Symbol.SymTag == SymTagThunk) oss << " ThunkOrdinal=" << Symbol.TokenizeThunkOrdinal();
	if (Symbol.SymTag == SymTagFunction && Symbol.Virtual != FALSE
		|| Symbol.VirtualBaseOffset != 0)
		oss << " VirtualBaseOffset=" << ashex(Symbol.VirtualBaseOffset);
	if (Symbol.SymTag == SymTagFunctionType || Symbol.ThisAdjust != 0)
		oss << " ThisAdjust=" << asshex(Symbol.ThisAdjust);
	if (Symbol.SymTag == SymTagBaseClass || Symbol.VirtualBaseDispIndex != 0)
		oss << " VirtualBaseDispIndex=" << ashex(Symbol.VirtualBaseDispIndex);
	if (Symbol.SymTag == SymTagBaseClass || Symbol.VirtualBasePointerOffset != 0)
		oss << " VirtualBasePointerOffset=" << asshex(Symbol.VirtualBasePointerOffset);
	if (Symbol.SymTag == SymTagFunctionType || Symbol.ObjectPointerType != NULL)
		oss << " ObjectPointerType=" << boolalpha << bool(Symbol.ObjectPointerType != NULL);
	IS_BOOL_PRESENT(Symbol, Virtual)
	IS_BOOL_PRESENT(Symbol, Intro)
	IS_BOOL_PRESENT(Symbol, Pure)
	if (Symbol.LocationType == LocIsSlot || Symbol.Slot != 0)
		oss << " Slot=" << ashex(Symbol.Slot);
	if (Symbol.TimeStamp != 0) oss << " TimeStamp=" << ashex(Symbol.TimeStamp);
	/*if (Symbol.SymTag == SymTagArrayType) */IS_TYPE_PRESENT(Symbol, ArrayIndexType)
	IS_BOOL_PRESENT(Symbol, Packed)
	IS_BOOL_PRESENT(Symbol, Constructor)
	IS_BOOL_PRESENT(Symbol, OverloadedOperator)
	IS_BOOL_PRESENT(Symbol, Nested)
	IS_BOOL_PRESENT(Symbol, HasNestedTypes)
	IS_BOOL_PRESENT(Symbol, HasAssignmentOperator)
	IS_BOOL_PRESENT(Symbol, HasCastOperator)
	IS_BOOL_PRESENT(Symbol, Scoped)
	IS_BOOL_PRESENT(Symbol, VirtualBaseClass)
	IS_BOOL_PRESENT(Symbol, IndirectVirtualBaseClass)
	IS_TYPE_PRESENT(Symbol, VirtualTableShape)
	IS_BOOL_PRESENT(Symbol, Code)
	IS_BOOL_PRESENT(Symbol, Function)
	IS_BOOL_PRESENT(Symbol, Managed)
	IS_BOOL_PRESENT(Symbol, MSIL)
	IS_INT_PRESENT(Symbol, Age)
	IS_STRING_PRESENT(Symbol, UndecoratedName)
	IS_INT_PRESENT(Symbol, Signature)
	IS_BOOL_PRESENT(Symbol, CompilerGenerated)
	IS_BOOL_PRESENT(Symbol, AddressTaken)
	if (Symbol.Managed/* && Symbol.SymTag == SymTagFunction*/
		|| Symbol.LocationType == LocInMetaData || Symbol.Token != 0)
		oss << " Token=" << ashex(Symbol.Token);
	IS_STRING_PRESENT(Symbol, SourceFileName)
	//IS_STRING_PRESENT(Symbol, ObjectFileName)
	IS_STRING_PRESENT(Symbol, LibraryName)
	IS_STRING_PRESENT(Symbol, SymbolsFileName)
	if (Symbol.SymTag == SymTagThunk || Symbol.TargetSection != 0
		|| Symbol.TargetOffset != 0) oss << " Target=" <<
		ashex(Symbol.TargetSection, (streamsize)8) << ':' <<
		ashex(Symbol.TargetOffset, (streamsize)8);
	if (Symbol.SymTag == SymTagThunk || Symbol.TargetRVA != 0)
		oss << " TargetRVA=" << ashex(Symbol.TargetRVA, (streamsize)8);
	if (Symbol.SymTag == SymTagThunk || Symbol.TargetVA != 0)
		oss << " TargetVA=" << ashex(Symbol.TargetVA, (streamsize)16);
	if (Symbol.SymTag == SymTagCompilandDetails) oss << " Platform=" <<
		Symbol.TokenizePlatform() << " Language=" << Symbol.TokenizeLanguage();
	IS_BOOL_PRESENT(Symbol, EditAndContinueEnabled)
	if (Symbol.SymTag == SymTagCompilandDetails || Symbol.FrontEndMajor != 0 || Symbol.FrontEndMinor != 0 || Symbol.FrontEndBuild != 0)
		oss << " FrontEnd=" << dec << Symbol.FrontEndMajor << '.' << Symbol.FrontEndMinor << '.' << Symbol.FrontEndBuild;
	if (Symbol.SymTag == SymTagCompilandDetails || Symbol.BackEndMajor != 0 || Symbol.BackEndMinor != 0 || Symbol.BackEndBuild != 0)
		oss << " BackEnd=" << dec << Symbol.BackEndMajor << '.' << Symbol.BackEndMinor << '.' << Symbol.BackEndBuild;
	//IS_STRING_PRESENT(Symbol, Unused)
	if (Symbol.SymTag == SymTagCustom || Symbol.SymTag == SymTagCustomType)
		oss << " Guid={" << hex << setfill('0') << nouppercase << setw(8) <<
			Symbol.Guid.Data1 << '-' << setw(4) << Symbol.Guid.Data2 << '-' <<
			setw(4) << Symbol.Guid.Data3 << '-' <<
			setw(2) << Symbol.Guid.Data4[0] << setw(2) << Symbol.Guid.Data4[1] << '-' <<
			setw(2) << Symbol.Guid.Data4[2] << setw(2) << Symbol.Guid.Data4[3] <<
			setw(2) << Symbol.Guid.Data4[4] << setw(2) << Symbol.Guid.Data4[5] <<
			setw(2) << Symbol.Guid.Data4[6] << setw(2) << Symbol.Guid.Data4[7] << '}';
	if (Symbol.SymTag == SymTagCustom || Symbol.SymTag == SymTagCustomType
		|| Symbol.DataBytes) oss << " DataBytes=" << boolalpha << (bool)Symbol.DataBytes;
	if (Symbol.MachineType != IMAGE_FILE_MACHINE_UNKNOWN)
		oss << " MachineType=" << Symbol.TokenizeMachineType();
	if (Symbol.SymTag == SymTagCustomType || Symbol.OemId != 0)
		oss << " OemId=" << ashex(Symbol.OemId);
	if (Symbol.SymTag == SymTagCustomType || Symbol.OemSymbolId != 0)
		oss << " OemSymbolId=" << ashex(Symbol.OemSymbolId);
	IS_INT_PRESENT(Symbol, LexicalParentId) //IS_TYPE_PRESENT(Symbol, LexicalParent)
	oss << endl;
	OutputDebugStringA(oss.str().c_str());
	// care sub-types
	if (path.find(Symbol.SymIndexId) != path.end()) return;
	/*hash_set<DWORD>::iterator iter(*/path.insert(Symbol.SymIndexId).first/*)*/;
	//_ASSERTE(iter != path.end());
	++indent;
	DiaSymbol basetype;
	// print sub-type
	if (Symbol.Type != NULL && basetype(Symbol.Type))
		PrintSymbol(Symbol.Type, basetype, indent, path);
	if (Symbol.ArrayIndexType != NULL && basetype(Symbol.ArrayIndexType))
		PrintSymbol(Symbol.ArrayIndexType, basetype, indent, path);
	// print children
	const DiaSymChildren Children(pSymbol);
	if (Children > 0) {
		CComPtr<IDiaSymbol> pSymbol;
		while (Children.Next(pSymbol)) if (basetype(pSymbol))
			PrintSymbol(pSymbol, basetype, indent, path);
	}
	//path.erase(iter);
}
static void PrintSymbol(const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Symbol, uint indent = 1) {
	//_ASSERTE(pSymbol != NULL); // may be NULL as result of failed conversion
	if (pSymbol != NULL) PrintSymbol(pSymbol, Symbol, indent,
#ifdef PRINT_TYPE_ONCE
		printed_types
#else
		hash_set<DWORD>()
#endif
	);
}
static void PrintSymbol(const CComPtr<IDiaSymbol> &pSymbol, uint indent = 1) {
	//_ASSERTE(pSymbol != NULL); // may be NULL as result of failed conversion
	if (pSymbol != NULL) PrintSymbol(pSymbol, pSymbol, indent);
}

static void PrintLine(const CComPtr<IDiaLineNumber> &pLineNumber,
	const DiaLineNumber &Line, uint indent = 1) {
	//_ASSERTE(pLineNumber != NULL);
	if (!pLineNumber) return;
	ostringstream oss;
	oss << string(indent << 1, ' ') << '#' << dec << Line.LineNumber << '(' <<
		Line.LineNumberEnd << "):" << Line.ColumnNumber << '(' <<
		Line.ColumnNumberEnd  << ") :";
	oss << " Length=" << ashex(Line.Length);
	IS_BOOL_PRESENT(Line, Statement)
	oss << " Address=" << ashex(Line.AddressSection, (streamsize)8) << ':' <<
		ashex(Line.AddressOffset, (streamsize)8) << " RVA=" <<
		ashex(Line.RVA, (streamsize)8) << " VA=" << ashex(Line.VA, (streamsize)16);
	IS_TYPE_PRESENT(Line, SourceFile)
	IS_TYPE_PRESENT(Line, Compiland)
	oss << endl;
	OutputDebugStringA(oss.str().c_str());
}
static void PrintLine(const CComPtr<IDiaLineNumber> &pLineNumber,
	uint indent = 1) {
	//_ASSERTE(pLineNumber != NULL);
	if (pLineNumber != NULL) PrintLine(pLineNumber, pLineNumber, indent);
}

static void PrintFrame(const CComPtr<IDiaFrameData> &pFrame,
	const DiaFrame &Frame, uint indent = 1) {
	//_ASSERTE(pFrame != NULL);
	if (!pFrame) return;
	ostringstream oss;
	if (indent != 0) oss << string(indent << 1, ' ');
	if (Frame.AddressSection != 0 || Frame.AddressOffset != 0)
		oss << "Address=" << ashex(Frame.AddressSection, (streamsize)8) << ':' <<
			ashex(Frame.AddressOffset, (streamsize)8);
	if (Frame.RVA != 0) oss << " RVA=" << ashex(Frame.RVA, (streamsize)8);
	if (Frame.VA != 0) oss << " VA=" << ashex(Frame.VA, (streamsize)16);
	/*if (Frame.LengthBlock != 0) */oss << " LengthBlock=" << ashex(Frame.LengthBlock);
	/*if (Frame.LengthLocals != 0) */oss << " LengthLocals=" << ashex(Frame.LengthLocals);
	/*if (Frame.LengthParams != 0) */oss << " LengthParams=" << ashex(Frame.LengthParams);
	/*if (Frame.LengthSavedRegisters != 0) */oss << " LengthSavedRegisters=" << ashex(Frame.LengthSavedRegisters);
	/*if (Frame.LengthProlog != 0) */oss << " LengthProlog=" << ashex(Frame.LengthProlog);
	/*if (Frame.MaxStack != 0) */oss << " MaxStack=" << ashex(Frame.MaxStack);
	IS_STRING_PRESENT(Frame, Program)
	IS_BOOL_PRESENT(Frame, SystemExceptionHandling)
	IS_BOOL_PRESENT(Frame, CplusplusExceptionHandling)
	IS_BOOL_PRESENT(Frame, FunctionStart)
	IS_BOOL_PRESENT(Frame, AllocatesBasePointer)
	IS_INT_PRESENT(Frame, Type)
	oss << " FunctionParent=" << (Frame.FunctionParent != NULL ? "present" : "missing");
	oss << endl;
	OutputDebugStringA(oss.str().c_str());
}
static void PrintFrame(const CComPtr<IDiaFrameData> &pFrame, uint indent = 1) {
	//_ASSERTE(pFrame != NULL);
	if (pFrame != NULL) PrintFrame(pFrame, pFrame, indent);
}

static void PrintSegment(const CComPtr<IDiaSegment> &pSegment, uint indent = 1) {
	//_ASSERTE(pSegment != NULL);
	if (!pSegment) return;
	const DiaSegment Segment(pSegment);
	ostringstream oss;
	if (indent != 0) oss << string(indent << 1, ' ');
	oss << "Segment " << dec << Segment.Frame << ':';
	IS_INT_PRESENT(Segment, Offset)
	IS_INT_PRESENT(Segment, Length)
	IS_BOOL_PRESENT(Segment, Read)
	IS_BOOL_PRESENT(Segment, Write)
	IS_BOOL_PRESENT(Segment, Execute)
	if (Segment.AddressSection != 0) oss << " AddressSection=" <<
		ashex(Segment.AddressSection, (streamsize)8);
	if (Segment.RVA != 0) oss << " RVA=" << ashex(Segment.RVA, (streamsize)8);
	if (Segment.VA != 0) oss << " VA=" << ashex(Segment.VA, (streamsize)16);
	oss << endl;
	OutputDebugStringA(oss.str().c_str());
}

static void PrintSectionContrib(const CComPtr<IDiaSectionContrib> &pSectionContrib,
	uint indent = 1) {
	//_ASSERTE(pSectionContrib != NULL);
	if (!pSectionContrib) return;
	const DiaSectionContrib SectionContrib(pSectionContrib);
	ostringstream oss;
	if (indent != 0) oss << string(indent << 1, ' ');
	IS_TYPE_PRESENT(SectionContrib, Compiland)
	if (SectionContrib.AddressSection != 0 || SectionContrib.AddressOffset != 0)
		oss << " Address=" << ashex(SectionContrib.AddressSection, (streamsize)8) << ':' <<
			ashex(SectionContrib.AddressOffset, (streamsize)8);
	if (SectionContrib.RVA != 0) oss << " RVA=" << ashex(SectionContrib.RVA, (streamsize)8);
	if (SectionContrib.VA != 0) oss << " VA=" << ashex(SectionContrib.VA, (streamsize)16);
	IS_INT_PRESENT(SectionContrib, Length)
	IS_BOOL_PRESENT(SectionContrib, NotPaged)
	IS_BOOL_PRESENT(SectionContrib, Code)
	IS_BOOL_PRESENT(SectionContrib, InitializedData)
	IS_BOOL_PRESENT(SectionContrib, UninitializedData)
	IS_BOOL_PRESENT(SectionContrib, Remove)
	IS_BOOL_PRESENT(SectionContrib, Comdat)
	IS_BOOL_PRESENT(SectionContrib, Discardable)
	IS_BOOL_PRESENT(SectionContrib, NotCached)
	IS_BOOL_PRESENT(SectionContrib, Share)
	IS_BOOL_PRESENT(SectionContrib, Execute)
	IS_BOOL_PRESENT(SectionContrib, Read)
	IS_BOOL_PRESENT(SectionContrib, Write)
	IS_INT_PRESENT(SectionContrib, DataCrc)
	IS_INT_PRESENT(SectionContrib, RelocationsCrc)
	oss << endl;
	OutputDebugStringA(oss.str().c_str());
}

static void PrintInjectedSource(const CComPtr<IDiaInjectedSource> &pInjectedSource,
	uint indent = 1) {
	//_ASSERTE(pInjectedSource != NULL);
	if (!pInjectedSource) return;
	const DiaInjectedSource InjectedSource(pInjectedSource);
	ostringstream oss;
	if (indent != 0) oss << string(indent << 1, ' ');
	IS_INT_PRESENT(InjectedSource, Crc)
	IS_INT_PRESENT(InjectedSource, Length)
	IS_STRING_PRESENT(InjectedSource, Filename)
	IS_STRING_PRESENT(InjectedSource, ObjectFilename)
	IS_STRING_PRESENT(InjectedSource, VirtualFilename)
	IS_INT_PRESENT(InjectedSource, SourceCompression)
	oss << " Source=" << boolalpha << (bool)InjectedSource.Source;
	oss << endl;
	OutputDebugStringA(oss.str().c_str());
}

#undef IS_BOOL_PRESENT
#undef IS_TYPE_PRESENT
#undef IS_STRING_PRESENT
#undef IS_INT_PRESENT

#else // !_DEBUG

#define PrintSymbol         __noop
#define PrintFrame          __noop
#define PrintLine           __noop
#define PrintSegment        __noop
#define PrintSectionContrib __noop
#define PrintInjectedSource __noop

#endif // _DEBUG

struct local_desc {
	DiaSymbol Block, Data;
	explicit local_desc(const CComPtr<IDiaSymbol> &pBlock) : Block(pBlock) { }
	inline bool operator ==(const local_desc &r) const
		{ return /*Block == r.Block && */Data == r.Data; }
};

typedef hash_map<DiaSourceFile, map<DWORD/*LineNumber*/, hash_set<DiaLineNumber,
	DiaLineNumber::hash> >, DiaSourceFile::hash> ln_t, *ln_p;
typedef deque<local_desc> loc_t, *loc_p;

static void GetLocalsFromBlock(const CComPtr<IDiaSymbol> &pBlock, loc_t &locals) {
	_ASSERTE(pBlock != NULL);
	if (pBlock == NULL) return;
	local_desc item(pBlock);
	_ASSERTE(item.Block());
	CComPtr<IDiaSymbol> pSymbol;
	DiaSymChildren Locals(pBlock, SymTagData);
	if (Locals > 0) while (Locals.Next(pSymbol)) {
		item.Data(pSymbol);
		_ASSERTE(item.Data.SymTag == SymTagData);
		if (find(CONTAINER_RANGE(locals), item) == locals.end())
			locals.push_back(item);
	}
	// take locals of nested blocks too
	if (Locals(pBlock, SymTagBlock) && Locals > 0)
		while (Locals.Next(pSymbol)) GetLocalsFromBlock(pSymbol, locals);
}

static bool GetLocalsFor(DWORD RVA, loc_t &locals) {
	locals.clear();
	_ASSERTE(pSession != NULL);
	if (!pSession) return false;
	HRESULT hr;
	CComPtr<IDiaSymbol> pBlock;
	if (FAILED(hr = pSession->findSymbolByRVA(RVA, SymTagBlock, &pBlock)))
		COM_Error("IDiaSession::findSymbolByRVA", hr);
	if (hr != S_OK) return false;
	_ASSERTE(pBlock != NULL);
	GetLocalsFromBlock(pBlock, locals);
	return !locals.empty();
}

// doubtful sense
static string getTypeFullName(const CComPtr<IDiaSymbol> &pSymbol) {
	string fullname;
	_ASSERTE(pSymbol != NULL);
	if (pSymbol != NULL) {
		CComPtr<IDiaSymbol> pIter(pSymbol), pParent;
		_ASSERTE(pIter != NULL);
		CDiaBSTR name;
		while (pIter->get_name(&name) == S_OK && name.Length() > 0) {
			if (!fullname.empty()) fullname.insert(0, SCOPE_DELIMITER);
			if (name == UNNAMED_NAME/* || name == FORMAL_NAME*/) {
				DWORD SymIndexId;
				HRESULT hr = pIter->get_symIndexId(&SymIndexId);
				if (hr != S_OK) {
					SymIndexId = 0;
					_RPT3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n", __FUNCTION__,
						"IDiaSymbol::get_symIndexId", hr);
					COM_Error("IDiaSymbol::get_symIndexId", hr);
				}
				fullname.insert(0, _sprintf(/*name != UNNAMED_NAME ?
					FORMAL_FMT : */UNNAMED_FMT, (BSTR)name, SymIndexId));
			} else
				fullname.insert(0, name.toAnsi());
			name.Empty();
			if (pIter->get_classParent(&pParent) != S_OK) break;
			pIter.Attach(pParent.Detach());
			_ASSERTE(pIter != NULL);
		}
		_ASSERTE(!pParent);
	}
	return fullname;
}

// doubtful usage
static ULONGLONG get_type_size(const CComPtr<IDiaSymbol> &pSymbol) {
	_ASSERTE(pSymbol != NULL);
	if (!pSymbol) return 0;
	ULONGLONG Length;
	DWORD LocationType;
	CComPtr<IDiaSymbol> pIter(pSymbol), pParent;
loop:
	_ASSERTE(pIter != NULL);
	if (pIter->get_length(&Length) == S_OK && Length > 0
		&& (pIter->get_locationType(&LocationType) != S_OK
			|| LocationType != LocIsBitField)) return Length;
	if (pIter->get_type(&pParent) != S_OK) return 0;
	_ASSERTE(pParent != NULL);
	pIter.Attach(pParent.Detach());
	goto loop;
}

static flags_t getFlags(const DiaSymbol &Symbol) {
	_ASSERTE(Symbol());
	if (!Symbol) return 0;
	flags_t flags(0);
	switch (Symbol.SymTag) {
		case SymTagBaseType:
			switch (Symbol.BaseType) {
				case btNoType:
				case btVoid:
					break;
				case btChar:
				case btWChar:
					flags = getDataFlagsByLength(Symbol.Length) | charflag();
					break;
				case btInt:
				case btUInt:
				case btLong:
				case btULong:
				case btBit: // ???
					flags = getDataFlagsByLength(Symbol.Length) | numflag();
					break;
				case btFloat:
					flags = fltflag();
					switch (Symbol.Length) {
						case 4: flags |= floatflag(); break;
						case 8: flags |= doubleflag(); break;
						default:
							if (Symbol.Length == ph.tbyte_size) {
								flags |= tbytflag()/*packrealflag()??*/; // should best correspond to ida's BTMT_LNGDBL type
								break;
							}
							flags |= getDataFlagsByLength(Symbol.Length);
							_RPTF2(_CRT_WARN, "%s(...): unexpected size for btFloat base type (0x%I64X), defaulting to general float type\n",
								__FUNCTION__, Symbol.Length);
					}
					break;
				case btBool:
				default:
					flags = getDataFlagsByLength(Symbol.Length);
			} // switch Symbol.BaseType
			_ASSERTE(Symbol.TypeId == 0); // base type cannot have supertypes
			return flags;
		case SymTagPointerType:
			return ptrflag();
		case SymTagArrayType: {
			const DiaSymbol basetype(Symbol.Type);
			if (basetype() && basetype.SymTag == SymTagBaseType
					&& (basetype.BaseType == btChar || basetype.BaseType == btWChar
					/*|| basetype.BaseType == btInt && (basetype.Length == 1
					|| basetype.Length == 2)*/)) return asciflag();
			break;
		}
		case SymTagEnum:
			return getDataFlagsByLength(Symbol.Length) | enumflag();
		case SymTagUDT:
			return struflag();
		case SymTagFunction:
		case SymTagThunk:
			return FF_CODE | FF_FUNC;
		case SymTagBlock:
			return FF_CODE;
		case SymTagBaseClass:
		case SymTagCustom:
		case SymTagData:
		case SymTagFriend:
		case SymTagFunctionArgType:
		case SymTagFunctionType:
		case SymTagTypedef:
		case SymTagVTable:
			break;
		default:
			_RPTF2(_CRT_WARN, "%s(...): data type %s unknown to IDA\n",
				__FUNCTION__, Symbol.TokenizeSymTag().c_str());
			return 0;
	}
	return flags | (Symbol.Type != NULL ? getFlags(Symbol.Type) : 0);
}

static typeinfo_t *get_typeinfo(const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Symbol, typeinfo_t &ti, ea_t ea = BADADDR);
static typeinfo_t *get_typeinfo(const CComPtr<IDiaSymbol> &pSymbol,
	typeinfo_t &ti, ea_t ea = BADADDR) {
	_ASSERTE(pSymbol != NULL);
	return pSymbol != NULL ? get_typeinfo(pSymbol, pSymbol, ti, ea) : 0;
}
static typeinfo_t *get_typeinfo(const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Symbol, typeinfo_t &ti, ea_t ea) {
	if (is_extern(ea)) { // externs are always pointers
		ti.ri.target = BADADDR;
		ti.ri.base = 0;
		ti.ri.tdelta = 0;
#if IDP_INTERFACE_VERSION < 76
		ti.ri.type = get_default_reftype(ea != BADADDR ? ea : inf.minEA);
		ti.ri.target_present = false;
#else // IDP_INTERFACE_VERSION >= 76
		ti.ri.set_type(get_default_reftype(ea != BADADDR ? ea : inf.minEA));
#endif
		return &ti;
	}
	_ASSERTE(pSymbol != NULL);
	if (!pSymbol) return 0;
	_ASSERTE(Symbol());
	switch (Symbol.SymTag) {
		case SymTagPointerType:
			//if (ea == BADADDR) return 0;
			ti.ri.target = BADADDR;
			ti.ri.base = 0;
			ti.ri.tdelta = 0;
#if IDP_INTERFACE_VERSION < 76
			ti.ri.type = get_default_reftype(ea != BADADDR ? ea : inf.minEA);
			ti.ri.target_present = false;
#else // IDP_INTERFACE_VERSION >= 76
			ti.ri.set_type(get_default_reftype(ea != BADADDR ? ea : inf.minEA));
#endif
			return &ti;
		case SymTagEnum: {
			if ((ti.ec.tid = CreateTypeFromPDB(pSymbol, Symbol, true)) != BADNODE) {
				if (ti.ec.tid == 0) ti.ec.tid = BADNODE; // enum can't be accessed directly but via til (type_t *)
				ti.ec.serial = 0;
				return &ti;
			}
			_RPTF4(_CRT_WARN, "%s(...): cannot get %s of %s %-.3840ls, returning NULL\n",
				__FUNCTION__, "enum_t", "enum", static_cast<BSTR>(Symbol.Name));
			return 0;
		}
		case SymTagUDT: {
			if ((ti.tid = CreateTypeFromPDB(pSymbol, Symbol, true)) != BADNODE) {
				if (ti.tid == 0) ti.tid = BADNODE; // struct can't be accessed directly but via til (type_t *)
				return &ti;
			}
			_RPTF4(_CRT_WARN, "%s(...): cannot get %s of %s %-.3840ls, returning NULL\n",
				__FUNCTION__, "tid_t", "struct", static_cast<BSTR>(Symbol.Name));
			return 0;
		}
		case SymTagArrayType: {
			const DiaSymbol basetype(Symbol.Type);
			if (basetype.SymTag == SymTagBaseType) switch (basetype.BaseType) {
				case btChar:
					ti.strtype = ASCSTR_C;
					return &ti;
				case btWChar:
					ti.strtype = ASCSTR_UNICODE;
					return &ti;
				case btInt:
					// unsure when real c-string and when binary byte array
//						if (basetype.Length == 1) {
//							ti.strtype = ASCSTR_C;
//							return &ti;
//						} else if (basetype.Length == 2) {
//							ti.strtype = ASCSTR_UNICODE;
//							return &ti;
//						}
					break;
			} // switch BaseType
			break;
		} // SymTagArrayType
#ifdef _DEBUG
		case SymTagBaseType:
			_ASSERTE(!Symbol.Type);
			break;
#endif // _DEBUG
		case SymTagBaseClass:
		case SymTagCustom:
		case SymTagData:
		case SymTagFriend:
		case SymTagFunctionArgType:
		case SymTagFunctionType:
		case SymTagTypedef:
		case SymTagVTable:
			break;
		default:
			_RPTF2(_CRT_WARN, "%s(...): data type %s unknown to IDA\n",
				__FUNCTION__, Symbol.TokenizeSymTag().c_str());
			return 0;
	}
	return Symbol.Type != NULL ? get_typeinfo(Symbol.Type, ti, ea) : 0;
}

static bool get_ti(const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Symbol, typestring &type, plist *pfnames = 0,
	loc_p plocals = 0, bool accept_incomplete = false) throw(not_convertible);
static bool get_ti(const CComPtr<IDiaSymbol> &pSymbol, typestring &type,
	plist *pfnames = 0, loc_p plocals = 0, bool accept_incomplete = false) throw(not_convertible) {
	_ASSERTE(pSymbol != NULL);
	return pSymbol != NULL ? get_ti(pSymbol, pSymbol, type, pfnames, plocals) : false;
}
static bool get_ti(const CComPtr<IDiaSymbol> &pSymbol, const DiaSymbol &Symbol,
	typestring &type, plist *pfnames, loc_p plocals, bool accept_incomplete) {
	type.clear();
	if (pfnames != 0) pfnames->clear();
	_ASSERTE(pSymbol != NULL);
	if (!pSymbol) return false;
	_ASSERTE(Symbol());
	bool use_accept_incomplete(false);
	try {
		typestring loctype;
		typestring::value_type t(0);
		// append cv-modifiers
		if (Symbol.ConstType) t |= BTM_CONST;
		if (Symbol.VolatileType) t |= BTM_VOLATILE;
		string fullname;
		switch (Symbol.SymTag) {
			case SymTagNull:
				return false;
			case SymTagBaseType:
				switch (Symbol.BaseType) {
					case btNoType: // No basic type is specified.
						//type << BT_UNK;
						break;
					case btVoid: // Basic type is a void.
						_ASSERTE(Symbol.Length == 0);
						type << (t | BTF_VOID);
						break;
					case btChar: // Basic type is a char (C/C++ type).
						_ASSERTE(Symbol.Length == 1);
						type << (t | BT_INT8 | BTMT_CHAR);
						break;
					case btWChar: // Basic type is a wide (Unicode) character (WCHAR).
						_ASSERTE(Symbol.Length == 2);
						type << (t | BT_INT16/* | BTMT_CHAR*/);
						break;
					case btInt: // Basic type is signed char (C/C++ type).
						type << (t |/* BTMT_SIGNED |*/get_int_type_bit(Symbol.Length));
						/*
						switch (Symbol.Length) {
							case 1: t |= BT_INT8 | BTMT_CHAR; break;
							case 2: t |= BT_INT16; break;
							case 4: t |= BT_INT32; break;
							case 8: t |= BT_INT64; break;
							case 16: t |= BT_INT128; break;
							default:
								t |= BT_INT;
								_RPTF2(_CRT_WARN, "%s(...): unexpected int type size (0x%I64X)\n",
									__FUNCTION__, Symbol.Length);
								PrintSymbol(pSymbol, Symbol);
						}
						type << t;
						*/
						break;
					case btUInt: // Basic type is unsigned char (C/C++ type).
						type << (t | BTMT_USIGNED | get_int_type_bit(Symbol.Length));
// 						switch (Symbol.Length) {
// 							case 1: type << (BT_INT8 | BTMT_USIGNED/* | BTMT_CHAR*/); break;
// 							case 2: type << (BT_INT16 | BTMT_USIGNED); break;
// 							case 4: type << (BT_INT32 | BTMT_USIGNED); break;
// 							case 8: type << (BT_INT64 | BTMT_USIGNED); break;
// 							case 16: type << (BT_INT128 | BTMT_USIGNED); break;
// 							default:
// 								type << (BT_INT | BTMT_USIGNED);
// #ifdef _DEBUG
// 								_RPTF2(_CRT_WARN, "%s(...): unexpected uint type size (0x%I64X)\n",
// 									__FUNCTION__, Symbol.Length);
// 								PrintSymbol(pSymbol, Symbol);
// #endif // _DEBUG
// 						}
						break;
					case btLong: // Basic type is a long int (C/C++ type).
						_ASSERTE(Symbol.Length == 4);
						type << (t | BT_INT32);
						break;
					case btULong: // Basic type is an unsigned long int (C/C++ type).
						_ASSERTE(Symbol.Length == 4);
						type << (t | BT_INT32 | BTMT_USIGNED);
						break;
					case btFloat: // Basic type is a floating-point number (FLOAT).
						t |= BT_FLOAT;
						switch (Symbol.Length) {
							case 2: t |= BTMT_SHRTFLT; break;
							case 4: t |= BTMT_FLOAT; break;
							case 8: t |= BTMT_DOUBLE; break;
							default:
								if (Symbol.Length == ph.tbyte_size) {
									t |= BTMT_LNGDBL;
									break;
								}
#ifdef _DEBUG
								_RPTF2(_CRT_WARN, "%s(...): unexpected float type size (0x%I64X)\n",
									__FUNCTION__, Symbol.Length);
								PrintSymbol(pSymbol, Symbol);
#endif // _DEBUG
						}
						type << t;
						break;
					case btBool: // Basic type is a Boolean (BOOL).
						t |= BT_BOOL;
						switch (Symbol.Length) {
							case 1: t |= BTMT_BOOL1; break;
							case 2: t |= BTMT_BOOL2; break;
							case 4: t |= BTMT_BOOL4; break;
							default:
								t |= BTMT_DEFBOOL;
								_RPTF2(_CRT_WARN, "%s(...): unexpected bool type size (0x%I64X)\n",
									__FUNCTION__, Symbol.Length);
								PrintSymbol(pSymbol, Symbol);
						}
						type << t;
						break;
					case btBCD: // Basic type is a binary-coded decimal (BCD).
						type << tdef("BCD");
						OutputDebugString("%s(...): %s basic type found\n", __FUNCTION__,
							Symbol.TokenizeBasicType().c_str());
						PrintSymbol(pSymbol, Symbol);
						break;
					case btCurrency: // Basic type is currency.
						CreateCURRENCY();
						type << tdef("CURRENCY");
						OutputDebugString("%s(...): %s basic type found\n", __FUNCTION__,
							Symbol.TokenizeBasicType().c_str());
						PrintSymbol(pSymbol, Symbol);
						break;
					case btDate: // Basic type is date/time (DATE).
						CreateDATE();
						type << tdef("DATE");
						OutputDebugString("%s(...): %s basic type found\n", __FUNCTION__,
							Symbol.TokenizeBasicType().c_str());
						PrintSymbol(pSymbol, Symbol);
						break;
					case btVariant: // Basic type is a variable type structure (VARIANT).
						type << tdef("VARIANT");
						OutputDebugString("%s(...): %s basic type found\n", __FUNCTION__,
							Symbol.TokenizeBasicType().c_str());
						PrintSymbol(pSymbol, Symbol);
						break;
					case btComplex: // Basic type is a complex number.
						type << tdef("_complex"); // ???
						OutputDebugString("%s(...): %s basic type found\n", __FUNCTION__,
							Symbol.TokenizeBasicType().c_str());
						PrintSymbol(pSymbol, Symbol);
						break;
					case btBit: // Basic type is a bit.
						type << (t | BT_BITFIELD) << (2 & BTE_SIZE_MASK | BTE_HEX & BTE_OUT_MASK); // !!!!
						OutputDebugString("%s(...): %s basic type found\n", __FUNCTION__,
							Symbol.TokenizeBasicType().c_str());
						PrintSymbol(pSymbol, Symbol);
						break;
					case btBSTR: // Basic type is a basic or binary string (BSTR).
						CreateBSTR();
						type << tdef("BSTR");
						OutputDebugString("%s(...): %s basic type found\n", __FUNCTION__,
							Symbol.TokenizeBasicType().c_str());
						PrintSymbol(pSymbol, Symbol);
						break;
					case btHresult: // Basic type is an HRESULT.
						CreateHRESULT();
						type << tdef("HRESULT");
						OutputDebugString("%s(...): %s basic type found\n", __FUNCTION__,
							Symbol.TokenizeBasicType().c_str());
						PrintSymbol(pSymbol, Symbol);
						break;
#ifdef _DEBUG
					default:
						_RPTF2(_CRT_WARN, "%s(...): unexpected BaseType value: 0x%lX\n",
							__FUNCTION__, Symbol.BaseType);
						PrintSymbol(pSymbol, Symbol);
#endif // _DEBUG
				} // switch Symbol.BaseType
				_ASSERTE(!Symbol.Type);
				return !type.empty();
			case SymTagArrayType: {
				// must adapt cv-modifiers of nearest underlying non-array child
				// otherwise typeinfo claimed invalid
				CComPtr<IDiaSymbol> pChild(pSymbol), pTmp;
				while (pChild != NULL && pChild->get_type(&pTmp) == S_OK) {
					_ASSERTE(pTmp != NULL);
					pChild.Attach(pTmp.Detach());
					_ASSERTE(!pTmp);
					const DiaSymbol Child(pChild);
					_ASSERTE(Child());
					if (Child.SymTag != SymTagArrayType) {
						if (Child.ConstType) t |= BTM_CONST;
						if (Child.VolatileType) t |= BTM_VOLATILE;
						break;
					}
				}
				pChild.Release();
				if (Symbol.Count <= MAX_DT)
					type << (t | BT_ARRAY | BTMT_NONBASED) << dt(Symbol.Count);
				else
					type << (t | BT_ARRAY) << da(Symbol.Count);
				break;
			} // SymTagArrayType
			case SymTagPointerType:
				type << (t | BT_PTR | BTMT_DEFPTR);
				use_accept_incomplete = true;
				break;
			case SymTagUDT:
				fullname.assign(getTypeFullName(pSymbol));
				//truncate(fullname, MAXSTR - 1); // safety is boring ;)
				if (!fullname.empty()) {
					if (CreateTypeFromPDB(pSymbol, Symbol, accept_incomplete) == BADNODE)
						throw fmt_exception("%s \"%s\" couldnot be created", "UDT", fullname.c_str());
					if (!is_named_type(fullname.c_str())) {
						//_RPTF3(_CRT_WARN, "%s(...): %s(\"%s\") returned false\n",
						//	__FUNCTION__, "is_named_type", fullname.c_str());
						throw fmt_exception("%s \"%s\" not accessible by true name", "UDT", fullname.c_str());
					}
					switch (Symbol.UDTKind) {
						case UdtStruct: t |= BTF_STRUCT; break;
						case UdtUnion: t |= BTF_UNION; break;
						default: // class or unknown
							t |= BT_COMPLEX;
							_RPTF2(_CRT_WARN, "%s(...): unsupported UDT type by ida typeinfo: %s\n",
								__FUNCTION__, Symbol.TokenizeUDTKind().c_str());
							//throw fmt_exception("unsupported UDT type by ida typeinfo: %s",
							//	Symbol.TokenizeUDTKind().c_str());
					}
					type << t << dt(0) << pstring(fullname);
				} else
					__stl_throw_invalid_argument("cannot get struct/union/class name: name is missing, too long, or cannot be converted to ansi");
				return !type.empty();
			case SymTagEnum:
				fullname.assign(getTypeFullName(pSymbol));
				//truncate(fullname, MAXSTR - 1); // safety is boring ;)
				if (!fullname.empty()) {
					if (CreateTypeFromPDB(pSymbol, Symbol, accept_incomplete) == BADNODE)
						throw fmt_exception("%s \"%s\" couldnot be created", "enum", fullname.c_str());
					if (!is_named_type(fullname.c_str())) {
						//_RPTF3(_CRT_WARN, "%s(...): %s(\"%s\") returned false\n",
						//	__FUNCTION__, "is_named_type", fullname.c_str());
						throw fmt_exception("%s \"%s\" not accessible by true name", "enum", fullname.c_str());
					}
					type << (t | BTF_ENUM) << dt(0) << pstring(fullname);
				} else
					__stl_throw_invalid_argument("cannot get enum name: name is missing, too long, or cannot be converted to ansi");
				return !type.empty();
			case SymTagTypedef:
				fullname.assign(getTypeFullName(pSymbol));
				//truncate(fullname, MAXSTR - 1); // safety is boring ;)
				if (!fullname.empty()) {
					if (CreateTypeFromPDB(pSymbol, Symbol, accept_incomplete) == BADNODE)
						throw fmt_exception("%s \"%s\" couldnot be created", "typedef", fullname.c_str());
					if (!is_named_type(fullname.c_str())) {
						//_RPTF3(_CRT_WARN, "%s(...): %s(\"%s\") returned false\n",
						//	__FUNCTION__, "is_named_type", fullname.c_str());
						throw fmt_exception("%s \"%s\" not accessible by true name", "typedef", fullname.c_str());
					}
					type << tdef(fullname);
				} else
					__stl_throw_invalid_argument("cannot get named type: name is missing, too long, or cannot be converted to ansi");
				return !type.empty();
			case SymTagFunctionType: {
				// _PVFV: Index=0x107 TypeIndex=0x107 Value=0x0 Tag=Typedef ModBase=0000000000400000
				//   SymId 0x107: Tag=Typedef Name=_PVFV Type=0x10 TypeId=0x10 Offset=0x0 SymIndex=0x107 LexicalParent=0x5 ReqsValid=000000000018001B
				//     SymId 0x10: Tag=PointerType Length=0x4 Type=0xA TypeId=0xA Offset=0x0 SymIndex=0x10 LexicalParent=0x5 ReqsValid=000000000018101D
				//       SymId 0xA: Tag=FunctionType Type=0xB TypeId=0xB Offset=0x0 SymIndex=0xA LexicalParent=0x5 CallConv=CDeclNear ReqsValid=0000000002181819
				//         SymId 0xB: Tag=BaseType BaseType=Void Offset=0x0 SymIndex=0xB LexicalParent=0x5 ReqsValid=0000000000181025
				t |= BT_FUNC;
				switch (Symbol.CallingConvention) {
					case CV_CALL_NEAR_C:
					case CV_CALL_NEAR_STD:
					case CV_CALL_NEAR_FAST:
					case CV_CALL_NEAR_PASCAL:
					case CV_CALL_NEAR_SYS:
						t |= BTMT_NEARCALL;
						break;
					case CV_CALL_FAR_C:
					case CV_CALL_FAR_STD:
					case CV_CALL_FAR_FAST:
					case CV_CALL_FAR_PASCAL:
					case CV_CALL_FAR_SYS:
						t |= BTMT_FARCALL;
						break;
				}
				cm_t cm;
				switch (Symbol.CallingConvention) {
					case CV_CALL_NEAR_C:
					case CV_CALL_FAR_C:
						cm = CM_CC_CDECL;
						break;
					case CV_CALL_NEAR_STD:
					case CV_CALL_FAR_STD:
						cm = CM_CC_STDCALL;
						break;
					case CV_CALL_NEAR_FAST:
					case CV_CALL_FAR_FAST:
						cm = CM_CC_FASTCALL;
						break;
					case CV_CALL_NEAR_SYS:
					case CV_CALL_FAR_SYS:
						cm = CM_CC_STDCALL; // care!!
						break;
					case CV_CALL_NEAR_PASCAL:
					case CV_CALL_FAR_PASCAL:
						cm = CM_CC_PASCAL;
						break;
					case CV_CALL_THISCALL:
						cm = CM_CC_THISCALL;
						break;
					case CV_CALL_GENERIC:
						cm = get_cc(inf.cc.cm); // ??
						break;
					//case CV_CALL_MIPSCALL:
					//case CV_CALL_ALPHACALL:
					//case CV_CALL_PPCCALL:
					//case CV_CALL_SHCALL:
					//case CV_CALL_ARMCALL:
					//case CV_CALL_AM33CALL:
					//case CV_CALL_TRICALL:
					//case CV_CALL_SH5CALL:
					//case CV_CALL_M32RCALL:
					default:
						cm = CM_CC_UNKNOWN; //get_cc(inf.cc.cm)?
						_RPTF2(_CRT_WARN, "%s(...): unhandled calling convention: %s, defaulting to CM_CC_UNKNOWN\n",
							__FUNCTION__, Symbol.TokenizeCallConv());
				}
				bool result_via_stack(false);
				elem_t rtype;
				if (Symbol.Type != NULL) {
					// functions returning UDT formal argument list mismatch with actual argument list
					// (prepended by pointer to returned object)
					// typeinfo not set
					DWORD SymTag;
					if (Symbol.Type->get_symTag(&SymTag) == S_OK && SymTag == SymTagUDT)
						result_via_stack = true;
					if (!get_ti(Symbol.Type, rtype.type, 0, plocals)) {
						//rtype.type << BT_UNKNOWN;
						_RPTF1(_CRT_WARN, "%s(...): couldnot build result type\n", __FUNCTION__);
						throw logic_error("no type for result or unknown type");
					}
				} else {
					//rtype.type << BT_UNKNOWN;
					_RPTF1(_CRT_WARN, "%s(...): no typeinfo for function result\n", __FUNCTION__);
					throw logic_error("no typeinfo for function result");
				}
				rtype.loc = R_ax; // EAX by default???
				queue<elem_t> argtypes;
				ULONG argcount(0);
				if (get_cc(cm) != CM_CC_VOIDARG) {
					const DiaSymChildren params(pSymbol, SymTagFunctionArgType);
					if (params > 0) {
						loc_t loc;
						if (plocals != 0)
							for (loc_t::const_iterator i = plocals->begin(); i != plocals->end(); ++i)
								if (i->Data.SymTag == SymTagData && i->Data.DataKind == DataIsParam)
									loc.push_back(*i);
						CComPtr<IDiaSymbol> pParam;
						while (params.Next(pParam)) {
							const DiaSymbol Param(pParam);
							_ASSERTE(Param());
							_ASSERTE(Param.SymTag == SymTagFunctionArgType);
							_ASSERTE(Param.Type != NULL);
							if (get_cc(cm) == CM_CC_ELLIPSIS) {
								_RPTF2(_CRT_ASSERT, "%s(...): unexpected argument[%lu] when get_cc(cm)==CM_CC_ELLIPSIS (arglist continuing after ellipsis is ignored)\n",
									__FUNCTION__, argcount + 1);
								break;
							}
							DWORD Val;
							if (!Param.Type ||
								((Param.Type->get_symTag(&Val) != S_OK || Val == SymTagBaseType)
								&& (Param.Type->get_baseType(&Val) != S_OK || Val == btNoType))) {
#ifdef _DEBUG
								if (is_user_cc(cm))
									_RPTF1(_CRT_WARN, "%s(...): overriding CM_CC_SPECIAL function model by CM_CC_ELLIPSIS\n",
										__FUNCTION__);
#endif // _DEBUG
								cm = CM_CC_ELLIPSIS;
								//_ASSERTE(argcount == (LONG)params - 1); // must be last parameter
							} else { // regular argument
								++argcount;
								// care arg type
								elem_t arg;
								if (!get_ti(Param.Type, arg.type)) {
									//arg.type << BT_UNKNOWN;
									_RPTF2(_CRT_WARN, "%s(...): couldnot build argument[%lu] type\n", __FUNCTION__, argcount);
									throw logic_error("no type for argument or unknown type");
								}
								// care arg location
								if (!loc.empty()) {
									const DiaSymbol &Local(loc.front().Data);
									if (!TypesAreEquiv(Local.Type, Param.Type)) { // type match assertion
										_RPTF3(_CRT_WARN, "%s(...): %s(...) returned false for argument[%lu]:\n",
											__FUNCTION__, "TypesAreEquiv", argcount);
										PrintSymbol(pSymbol, Symbol);
										OutputDebugString("  Paired actual parameter:\n");
										PrintSymbol(Local, Local);
										throw not_convertible();
									}
									switch (Local.LocationType) {
										case LocIsEnregistered:
											arg.loc = Local.RegisterId == CV_REG_EDXEAX ?
												argloc(R_ax, R_dx) : ix86_getReg((CV_HREG_e)Local.RegisterId);
											//if (arg.loc > 0) cm = CM_CC_SPECIAL;
											break;
#ifdef _DEBUG
										case LocIsRegRel:
											break;
										default:
											_RPTF3(_CRT_WARN, "%s(...): unexpected argument[%lu] location: %s\n",
												__FUNCTION__, argcount, Local.TokenizeLocationType().c_str());
#endif // _DEBUG
									} // switch LocationType
								} // !loc.empty()
								argtypes.push(arg);
							} // !VARARG
							if (!loc.empty()) {
								if (pfnames != 0) pfnames->append(loc.front().Data.Name.toAnsi());
								loc.pop_front();
							}
						} // enumerate params
					} // params > 0
				} // !CM_CC_VOIDARG
				type << t << (cm = get_cc(cm) | inf.cc.cm & (CM_MASK | CM_M_MASK));
				if (is_user_cc(cm) && is_resolved_type_void(rtype.type)) {
					rtype.type.clear();
					rtype.type << BT_UNKNOWN;
				}
				type << rtype.type;
				if (is_user_cc(cm)/* && !is_resolved_type_void(rtype.type)*/)
					type << rtype.loc;
				if (get_cc(cm) != CM_CC_VOIDARG) {
					type << dt(argcount);
					while (!argtypes.empty()) {
						if (is_user_cc(cm)&& is_resolved_type_void(argtypes.front().type)) {
							argtypes.front().type.clear();
							argtypes.front().type << BT_UNKNOWN;
							_RPTF1(_CRT_WARN, "%s(...): void type argument\n", __FUNCTION__);
						}
						type << argtypes.front().type;
						if (is_user_cc(cm)/*&& !is_resolved_type_void(argtypes.front().type)*/)
							type << argtypes.front().loc;
						argtypes.pop();
					}
				}
				return !type.empty();
			} // SymTagFunctionType
			case SymTagVTableShape:
				type << (BT_ARRAY | BTMT_NONBASED | BTM_CONST) << dt(Symbol.Count) <<
					(BT_PTR | BTMT_DEFPTR | BTM_CONST) << (BT_FUNC | BTMT_NEARCALL) <<
					(get_cc(CM_CC_THISCALL) | inf.cc.cm & (CM_MASK | CM_M_MASK)) <<
					BT_VOID/*rettype*/ << dt(0/*argcount*/);
				_ASSERTE(!Symbol.Type);
				break; //return !type.empty();
			// lexical types
			case SymTagBaseClass:
			case SymTagBlock:
			case SymTagCompiland:
			case SymTagCompilandDetails:
			case SymTagCompilandEnv:
			case SymTagCustom:
			case SymTagData:
			case SymTagFunction:
			case SymTagFunctionArgType:
			case SymTagFuncDebugEnd:
			case SymTagFuncDebugStart:
			case SymTagLabel:
			case SymTagPublicSymbol:
			case SymTagThunk:
			case SymTagUsingNamespace:
			case SymTagVTable:
				break;
			default: // everything else too exotic for ida
				throw fmt_exception("data type %s unknown to IDA",
					Symbol.TokenizeSymTag().c_str());
		} // switch SymTag
		if (Symbol.Type != NULL) {
			plist locfnames;
			if (get_ti(Symbol.Type, loctype, pfnames != 0 ? &locfnames : 0, plocals,
				use_accept_incomplete)) {
				type << loctype;
				if (pfnames != 0) pfnames->append(locfnames);
			}
		}
	} catch (GENERAL_CATCH_FILTER) {
		type.clear();
		if (pfnames != 0) pfnames->clear();
#ifdef _DEBUG
		if (typeid(e) != typeid(not_convertible)) {
			_RPTF3(_CRT_WARN, "%s(...) caught exception: %-.3840s (%s)\n",
				__FUNCTION__, e.what(), typeid(e).name());
			PrintSymbol(pSymbol, Symbol);
		}
#endif // _DEBUG
		throw not_convertible();
	}
	return !type.empty();
}

// set type_t[] typeinfo for address from PDB typeinfo (not for struct members)
static bool set_ti(ea_t ea, const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Symbol, loc_p plocals = 0) {
	_ASSERTE(pSymbol != NULL);
	if (!pSymbol) return false;
	try {
		typestring type;
		plist fnames;
		if (get_ti(pSymbol, Symbol, type, &fnames, plocals)) {
			if (is_extern(ea)) type.before(BT_PTR | BTMT_DEFPTR);
#ifdef _DEBUG
			if (type.length() >= MAXSPECSIZE) _RPTF4(_CRT_WARN, "%s(%08IX, ...): long %s (%Iu)\n",
				__FUNCTION__, ea, "typeinfo", type.length());
			if (fnames.length() >= MAXSPECSIZE) _RPTF4(_CRT_WARN, "%s(%08IX, ...): long %s (%Iu)\n",
				__FUNCTION__, ea, "fnames", fnames.length());
#endif // _DEBUG
			//type.truncate();
			//fnames.truncate();
			return ::set_ti(ea, type, fnames);
		}
	} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
		_RPTF4(_CRT_WARN, "%s(%08IX, ...): %s\n", __FUNCTION__, ea, e.what(), typeid(e).name());
// 		if (typeid(e) != typeid(not_convertible) || plocals != 0)
// 			PrintSymbol(pSymbol, Symbol);
// 		if (plocals != 0) {
// 			OutputDebugString("  All actual local symbols:\n");
// 			for (loc_t::const_iterator i = plocals->begin(); i != plocals->end(); ++i)
// 				PrintSymbol(i->Data, i->Data);
// 		}
#endif // _DEBUG
	}
	return false;
}
static bool set_ti(ea_t ea, const CComPtr<IDiaSymbol> &pSymbol, loc_p plocals = 0) {
	_ASSERTE(pSymbol != NULL);
	return pSymbol != NULL ? set_ti(ea, pSymbol, pSymbol, plocals) : false;
}

// set type_t[] typeinfo for structure member from PDB typeinfo
static bool set_member_ti(struc_t *sptr, member_t *mptr,
	const CComPtr<IDiaSymbol> &pSymbol, const DiaSymbol &Symbol,
	bool may_destroy_other_members) {
	_ASSERTE(pSymbol != NULL);
	if (!pSymbol) return false;
	_ASSERTE(sptr != 0);
	//_ASSERTE(mptr != 0);
	if (sptr != 0 && mptr != 0) try {
		typestring type;
		plist fnames;
		if (get_ti(pSymbol, Symbol, type, &fnames)) {
#ifdef _DEBUG
			if (type.length() >= MAXSPECSIZE) _RPTF3(_CRT_WARN, "%s(...): long %s (%Iu)\n",
				__FUNCTION__, "typeinfo", type.length());
#endif // _DEBUG
			//type.truncate();
			if (!::set_member_ti(sptr, mptr, type, may_destroy_other_members))
				return false;
			netnode namenode(mptr->id);
			if (!fnames.empty())
				namenode.supset(NSUP_TYPEINFO + 1, fnames.c_str(), fnames.size() + 1);
			else
				namenode.supdel(NSUP_TYPEINFO + 1);
			return true;
		}
	} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
		_RPTF3(_CRT_WARN, "%s(...): %s\n", __FUNCTION__, e.what(), typeid(e).name());
		if (typeid(e) != typeid(not_convertible)) PrintSymbol(pSymbol, Symbol);
#endif // _DEBUG
	}
	return false;
}
static bool set_member_ti(struc_t *sptr, member_t *mptr,
	const CComPtr<IDiaSymbol> &pSymbol, bool may_destroy_other_members) {
	_ASSERTE(sptr != 0);
	//_ASSERTE(mptr != 0);
	_ASSERTE(pSymbol != NULL);
	return sptr != 0 && mptr != 0 && pSymbol != NULL ?
		set_member_ti(sptr, mptr, pSymbol, pSymbol, may_destroy_other_members) : 0;
}

// convert one type from PDB to type_t[] sequence and store as named typedef
// returns: BADNODE if failed, 0 if OK (saved as typeinfo),
//          otherwise tid_t of existing idb type (struct or enum) - not created
static tid_t set_named_type(const char *name, const CComPtr<IDiaSymbol> &pSymbol,
	int ntf_flags = DEF_NTF_FLAGS, const sclass_t *sclass = NULL,
	const char *cmt = NULL, const ulong *value = NULL) {
	_ASSERTE(pSymbol != NULL);
	if (!pSymbol) return BADNODE;
	tid_t tid(BADNODE);
	//_ASSERTE(name != 0 && *name != 0);
	if (name != 0 && *name != 0) try {
		typestring type;
		plist fnames;
		if (get_ti(pSymbol, type, &fnames)) {
#ifdef _DEBUG
			if (strlen(name) >= MAXNAMESIZE) _RPTF4(_CRT_WARN, "%s(..., \"%-.1023s\", ...): long %s (%Iu)\n",
				__FUNCTION__, name, "typename", strlen(name));
			if (type.length() >= MAXSPECSIZE) _RPTF4(_CRT_WARN, "%s(..., \"%-.1023s\", ...): long %s (%Iu)\n",
				__FUNCTION__, name, "typeinfo", type.length());
			if (fnames.length() >= MAXSPECSIZE) _RPTF4(_CRT_WARN, "%s(..., \"%-.1023s\", ...): long %s (%Iu)\n",
				__FUNCTION__, name, "fnames", fnames.length());
#endif // _DEBUG
			//type.truncate();
			//fnames.truncate();
			tid = ::set_named_type(name, type, fnames, ntf_flags,
				sclass, cmt, NULL/*fieldcmts*/, value);
		}
	} catch (GENERAL_CATCH_FILTER) {
		tid = BADNODE;
#ifdef _DEBUG
		_RPTF4(_CRT_WARN, "%s(..., \"%-.1023s\", ...): %s\n", __FUNCTION__, name,
			e.what(), typeid(e).name());
		if (typeid(e) != typeid(not_convertible)) PrintSymbol(pSymbol);
#endif // _DEBUG
	}
	return tid;
}

static void ProcessStaticSymbol(const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Symbol, sym_p pNames = 0) {
	_ASSERTE(!foreign_pdb);
	if (foreign_pdb) return; // don't touch static data - foreign_pdb should be always false
	// pSymbol may be NULL as result of failed conversion
	// of FunctionDebugStart/FunctionDebugEnd void types
	_ASSERTE(Symbol());
	if (!Symbol || Symbol.LocationType != LocIsStatic) return;
	const ea_t ea = static_cast<ea_t>(SymBase) + Symbol.RVA;
	if (!isEnabled(ea)) return; // ea may be invalid on some symbols (RVA=0)
	showAddr(ea);
	ULONGLONG size;
	// format
	if (is_extern(ea)) {
		const typeinfo_t ri =
#if IDP_INTERFACE_VERSION < 76
			{ get_default_reftype(ea), 0, BADADDR, 0, 0 };
#else // IDP_INTERFACE_VERSION >= 76
			{ BADADDR, 0, 0, get_default_reftype(ea) };
#endif
		if (do_data_ex(ea, ptrflag(), &ri, get_ptr_size(FF_DATA))) ++totaldata;
		if (Symbol.Type != NULL && set_ti(ea, Symbol.Type)) ++totaltypeinfos;
	} else if (pSymbol != NULL) switch (Symbol.SymTag) {
		case SymTagData: {
			_ASSERTE(Symbol.DataKind == DataIsFileStatic
				|| Symbol.DataKind == DataIsGlobal
				|| Symbol.DataKind == DataIsStaticMember
				|| Symbol.DataKind == DataIsStaticLocal);
			if (Symbol.Type == NULL) break;
			const flags_t flags(getFlags(Symbol.Type));
			if (isData(flags)) {
				if ((size = get_type_size(Symbol.Type)) <= 0) size = get_type_size(pSymbol);
				typeinfo_t ti, *const pti(get_typeinfo(Symbol.Type, ti, ea));
#ifdef _DEBUG
				typeinfo_t oldti, *poldti(get_typeinfo(ea, 0, flags, &oldti));
				OutputDebugString("%08IX: idabase flags=%s has_typeinfo?%s size=0x%IX\n", ea, flags2str(::getFlags(ea)).c_str(), poldti != 0 ? "yes":"no", get_item_size(ea));
				OutputDebugString("              pdb flags=%s has_typeinfo?%s size=0x%I64X\n", flags2str(flags).c_str(), pti != 0 ? "yes":"no", size);
#endif // _DEBUG
				if (do_data_ex(ea, flags, pti, static_cast<asize_t>(size))) ++totaldata;
			}
#ifdef _DEBUG
			else
				_RPT3(_CRT_WARN, "%s(...): no data type from IDiaSymbol at %08IX: %-.3840ls\n",
					__FUNCTION__, ea, static_cast<BSTR>(Symbol.Name));
#endif // _DEBUG
			if (set_ti(ea, Symbol.Type)) ++totaltypeinfos;
			break;
		} // SymTagData
		case SymTagFunction:
		case SymTagThunk: {
			if  (is_spec_ea(ea)) break;
			size = get_type_size(pSymbol);
			const ea_t endEA = size > 0 ? ea + size : BADADDR;
			func_t *func = get_func(ea);
			if (func == 0 || func->startEA != ea/* || endEA != BADADDR && func->endEA != endEA*/) {
				del_func(ea);
				if (size > 0) {
					do_unknown_range(ea, static_cast<asize_t>(size), false);
					for (ea_t ip = ea; ip < endEA; ip = next_not_tail(ip))
						if (ua_code(ip) == 0) break;
				}
				if (add_func(ea, BADADDR/*endEA*/)) ++totalfuncs;
			} // create func
			if (Symbol.Type != NULL) {
				loc_t locals;
				if (GetLocalsFor(Symbol.RVA, locals)
#ifdef _DEBUG
					&& set_ti(ea, pSymbol, Symbol, &locals)
#else
					&& set_ti(ea, Symbol.Type, &locals)
#endif
					) ++totaltypeinfos;
			}
			if ((func = get_func(ea)) != 0) {
				const ushort flags = func->flags;
				//if (Symbol.Virtual) func->flags |= FUNC_VIRTUAL;
				//if (Symbol.Pure) func->flags |= FUNC_PUREVIRTUAL;
				if (Symbol.SymTag == SymTagThunk) func->flags |= FUNC_THUNK; // ???
				DWORD value;
				if (Symbol.Type && Symbol.Type->get_symTag(&value) == S_OK
					&& value == SymTagFunctionType
					&& Symbol.Type->get_callingConvention(&value) == S_OK
					&& is_far_call(value)) func->flags |= FUNC_FAR;
				if (func->flags != flags) update_func(func);
			}
			break;
		} // SymTagFunction || SymTagThunk
	} // switch SymTag
	// rename (symbols may be nameless)
	if (Symbol.hasName())
		if (pNames != 0) {
			const sym_t::iterator i(pNames->find(ea));
			if (i == pNames->end())
				pNames->insert(sym_t::value_type(ea, Symbol.getAnsiName()));
			else if (Symbol.SymTag == SymTagPublicSymbol)
				i->second.assign(Symbol.getAnsiName());
		} else
			if (apply_static_name(ea, Symbol.getAnsiName().c_str())) ++totalnames;
}

// for structs: load struct members from pdb typeinfo

static bool LoadMembersFromPDB(const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Struct, struc_t *struc, LONG BaseOffset = 0,
	const char *childrenscope = 0) {
	_ASSERTE(pSymbol != NULL);
	if (!pSymbol) return false;
	_ASSERTE(Struct());
	_ASSERTE(Struct.SymTag == SymTagUDT);
	if (Struct.SymTag != SymTagUDT) return false;
	_ASSERTE(struc != 0);
	if (struc == 0) return false;
	const DiaSymChildren Members(pSymbol);
	_ASSERTE(Members());
	if (!Members()) return false; // error
	if (Members <= 0) return true; // nothing to add but success
	if (inheritance_path.find(Struct.SymIndexId) != inheritance_path.end())
		return false;
	const hash_set<DWORD>::iterator
		iter(inheritance_path.insert(Struct.SymIndexId).first);
	_ASSERTE(iter != inheritance_path.end());
	bool result(false), incomplete(false);
#ifdef _DEBUG
	ULONG index(0);
#endif // _DEBUG
	CComPtr<IDiaSymbol> pMember;
	string fullname;
	DiaSymbol basetype;
	typestring type;
	plist fnames;
	while (Members.Next(pMember)) try {
#ifdef _DEBUG
		++index;
#endif // _DEBUG
		const DiaSymbol Member(pMember);
		_ASSERTE(Member());
		fullname.clear();
		asize_t size;
		flags_t flags;
		typeinfo_t ti, *pti;
		member_t *member;
		char cmt[MAXSTR];
		switch (Member.SymTag) {
			case SymTagData:
				switch (Member.DataKind) {
					case DataIsMember:
						switch (Member.LocationType) {
							case LocIsBitField:
								// ida structs lack support for bitfields
								if (Member.BitPosition > 0)
									throw fmt_exception("cannot add bit field member due to IDA limitation (BitPosition=%lu Length=%I64u)",
										Member.BitPosition, Member.Length);
							case LocIsThisRel:
								_ASSERTE(Struct.UDTKind != UdtUnion || Member.Offset == 0);
								if (!basetype(Member.Type)) throw logic_error("no type for member (Data/Member)");
								size = (asize_t)get_type_size(Member.LocationType != LocIsBitField ?
									pMember : Member.Type);
								flags = getFlags(basetype);
								pti = get_typeinfo(Member.Type, basetype, ti);
#ifdef _DEBUG
								if (!isData(flags) || size == 0) {
									_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
										"%s(...): %s(%ls).member[%-.2000lu] name=%-.2000ls without type or zero size: flags=%s size=0x%IX has_typeinfo?%s",
										__FUNCTION__, "struct", static_cast<BSTR>(Struct.Name),
										index, static_cast<BSTR>(Member.Name),
										flags2str(flags).c_str(), size, pti != 0 ? "yes":"no");
									PrintSymbol(Member.Type, basetype);
								}
#endif // _DEBUG
								//_ASSERTE(Member.hasName());
								if (Member.hasName()) {
									if (childrenscope != 0 && *childrenscope != 0)
										fullname.assign(childrenscope).append(SCOPE_DELIMITER);
									fullname.append(Member.getAnsiName());
									//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
								}
								if (add_struc_member_anyway(struc,
									Member.hasName() ? fullname.c_str() : NULL,
									BaseOffset + Member.Offset, flags, pti, size) == 0)
									result = true;
								else if (add_struc_member_anyway(struc,
									Member.hasName() ? fullname.c_str() : NULL,
									BaseOffset + Member.Offset, flags = byteflag(), pti = 0, size) != 0)
									incomplete = true;
								if ((member = struc->is_union() ?
									get_member_by_name(struc, Member.hasName() ? fullname.c_str() : NULL) :
									get_member(struc, BaseOffset + Member.Offset)) != 0)
									if (set_member_ti(struc, member, Member.Type, basetype, true))
										++totaltypeinfos;
									else try {
										if (get_ti(Member.Type, basetype, type, &fnames)
											&& print_type_to_one_line(CPY(cmt), idati, type,
												NULL, NULL, !fnames.empty() ? fnames.c_str() : NULL) == T_NORMAL)
											set_member_cmt(member, cmt, true);
									} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
										_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
											"%s(...): %s (%s(%-.2000ls).member[%lu] name=%-.2000ls)\n",
											__FUNCTION__, e.what(), "struct", static_cast<BSTR>(Struct.Name),
											index, static_cast<BSTR>(Member.Name));
										if (typeid(e) != typeid(not_convertible)) PrintSymbol(Member.Type, basetype);
#endif // _DEBUG
									}
								break;
							default:
								throw fmt_exception("unhandled member location type(SymTagData/DataIsMember): %s",
									Member.TokenizeLocationType().c_str());
						} // switch LocationType
						break;
					case DataIsStaticMember:
					case DataIsGlobal:
						_ASSERTE(Member.LocationType == LocIsStatic);
						// handled by ProcessStaticSymbol
						break;
					default:
						throw fmt_exception("unhandled member data kind(SymTagData): %s",
							Member.TokenizeDataKind().c_str());
				} // switch DataKind
				break;
			case SymTagBaseClass:
				_ASSERTE(Member.LocationType == LocIsNull);
				_ASSERTE(Struct.UDTKind != UdtUnion || Member.Offset == 0);
				_ASSERTE(Member.Type != NULL);
				if (!basetype(Member.Type)) throw logic_error("no type for member (BaseClass)");
				_ASSERTE(basetype.SymTag == SymTagUDT);
				//_ASSERTE(basetype.UDTKind == Struct.UDTKind);
				// care! too deep nesting may(or not) introduce temporary struc buffer recycling
				// in case of problems by creating structs try to remove following line
				/*if (*/CreateTypeFromPDB(Member.Type, basetype)/* == BADNODE)
					throw logic_error("base class couldnot be created")*/;
				if (childrenscope != 0 && *childrenscope != 0) fullname.assign(childrenscope);
				_ASSERTE(basetype.hasName());
				if (basetype.hasName()) {
					if (childrenscope != 0 && *childrenscope != 0) fullname.append(SCOPE_DELIMITER);
					fullname.append(basetype.getAnsiName());
					//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
				}
				if (LoadMembersFromPDB(Member.Type, basetype, struc,
					BaseOffset + Member.Offset, fullname.c_str())) result = true;
				break;
			// weightless members
			case SymTagUDT:
			case SymTagEnum:
			case SymTagTypedef:
				_ASSERTE(Member.LocationType == LocIsNull);
				if (CreateTypeFromPDB(pMember, Member) != BADNODE) result = true;
				break;
			// class-specific members (weightless)
			case SymTagFunction:
				// TypeId 0x2A5: Tag=Function Name=MoveElementTo VirtualBaseOffset=0x20
				//_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
				//	"%s(...): %s cannot be stored in ida struct: class(%-.2000ls) member[%lu] name=%-.2000ls\n",
				//	__FUNCTION__, "struct/class methods", static_cast<BSTR>(typinfo.Name),
				//	index, static_cast<BSTR>(members[index].Name));
				// VirtualBaseOffset
				_ASSERTE(Member.LocationType == LocIsStatic);
				// handled by ProcessStaticSymbol
				break;
			case SymTagVTable:
				// TypeId 0x78: Tag=VTable Type=0x7E TypeId=0x7E
				//   TypeId 0x7E: Tag=PointerType Length=0x4 Type=0x77 TypeId=0x77
				//     TypeId 0x77: Tag=VTableShape Count=0x3
				_ASSERTE(Member.LocationType == LocIsNull);
				_ASSERTE(Struct.UDTKind != UdtUnion/* || Member.Offset == 0*/);
				if (!basetype(Member.Type)) throw logic_error("no type for member (VTable)");
				size = (asize_t)get_type_size(pMember);
				flags = getFlags(basetype);
				pti = get_typeinfo(Member.Type, basetype, ti);
#ifdef _DEBUG
				if (!isData(flags) || size <= 0) {
					_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
						"%s(...): %s(%-.2000ls).member[%lu] name=%-.2000ls VTable without type or zero size: flags=%s size=0x%IX has_typeinfo?%s",
						__FUNCTION__, "struct", static_cast<BSTR>(Struct.Name), index,
						static_cast<BSTR>(basetype.Name), flags2str(flags).c_str(),
						size, pti != 0 ? "yes":"no");
				}
#endif // _DEBUG
				if (Member.hasName()) {
					if (childrenscope != 0 && *childrenscope != 0)
						fullname.assign(childrenscope).append(SCOPE_DELIMITER);
					fullname.append(Member.getAnsiName());
				} else
					fullname.assign(VTABLE_NAME);
				//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
				// ????? platí Offset u vtable nebo vtable offset == 0?
				if (add_struc_member_anyway(struc, fullname.c_str(),
					/*???*/BaseOffset + Member.Offset, flags, pti, size) == 0)
					result = true;
				else if (add_struc_member_anyway(struc, fullname.c_str(),
					BaseOffset + Member.Offset, flags = byteflag(), pti = 0, size) != 0)
					incomplete = true;
				if ((member = get_member(struc, BaseOffset + Member.Offset)) != 0)
					if (set_member_ti(struc, member, Member.Type, basetype, true))
						++totaltypeinfos;
					else try {
						if (get_ti(Member.Type, basetype, type, &fnames)
							&& print_type_to_one_line(CPY(cmt), idati, type, NULL,
								NULL, !fnames.empty() ? fnames.c_str() : NULL) == T_NORMAL)
							set_member_cmt(member, cmt, true);
					} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
						_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
							"%s(...): %s (%s(%-.2000ls).member[%lu] name=%-.2000ls VTable)\n",
							__FUNCTION__, e.what(), "struct", static_cast<BSTR>(Struct.Name),
							index, static_cast<BSTR>(basetype.Name));
						//if (typeid(e) != typeid(not_convertible)) PrintTypeInfoEx(Member.Type);
#endif // _DEBUG
					}
				break;
			case SymTagVTableShape:
				break; // ok - just vtable size
			case SymTagThunk:
				// TypeId 0x6FE: Tag=Thunk Name=exception::exception Length=0x6 AddressOffset=0x1B06C LexicalParent=0x706 Address=000000001201C06C
				_ASSERTE(Member.LocationType == LocIsStatic);
				// handled by ProcessStaticSymbol
				break;
			default: // if unsure, consider weight loose
				throw fmt_exception("unhandled struct member type %s",
					Member.TokenizeSymTag().c_str());
		} // switch SymTag
		if (!foreign_pdb && Member.LocationType == LocIsStatic)
			ProcessStaticSymbol(pMember, Member);
	} catch (GENERAL_CATCH_FILTER) {
		incomplete = true;
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
			"%s(...): %s (%s=%-.3840ls index=%lu typeid=%s)\n", __FUNCTION__,
			e.what(), "struct", static_cast<BSTR>(Struct.Name), index, typeid(e).name());
		PrintSymbol(pMember);
#endif // _DEBUG
	}
	if (incomplete) set_struc_cmt(struc->id, "incomplete", false);
	/*if (iter != inheritance_path.end()) */inheritance_path.erase(iter);
	return result;
}

// assumption: Members are passed in offset ascending order
static LONG LoadMembersFromPDB(const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Struct, typestring &type, plist &fnames, uint8 &Align,
	/*const char *&cmt, */const char *childrenscope = 0) {
	type.clear(); fnames.clear();
	Align = 0; // default
	_ASSERTE(pSymbol != NULL);
	if (!pSymbol) return -1;
	_ASSERTE(Struct());
	_ASSERTE(Struct.SymTag == SymTagUDT);
	if (Struct.SymTag != SymTagUDT) return -1;
	const DiaSymChildren Members(pSymbol);
	_ASSERTE(Members());
	if (!Members()) return -1; // error
	if (Members <= 0) return 0;
	if (inheritance_path.find(Struct.SymIndexId) != inheritance_path.end())
		return -1;
	const hash_set<DWORD>::iterator
		iter(inheritance_path.insert(Struct.SymIndexId).first);
	_ASSERTE(iter != inheritance_path.end());
	LONG result(0);
#ifdef _DEBUG
	ULONG index(0);
#endif // _DEBUG
	CComPtr<IDiaSymbol> pMember;
	try {
		LONG LastOffset(0);
		string fullname;
		DiaSymbol basetype;
		typestring loctype;
		plist locfnames;
		while (Members.Next(pMember)) {
#ifdef _DEBUG
			++index;
#endif // _DEBUG
			const DiaSymbol Member(pMember);
			_ASSERTE(Member());
			fullname.clear();
			uint8 tmpAlign;
			LONG Delta;
			ULONGLONG Size;
			switch (Member.SymTag) {
				case SymTagData:
					switch (Member.DataKind) {
						case DataIsMember:
							switch (Member.LocationType) {
								case LocIsThisRel:
									_ASSERTE(Struct.UDTKind != UdtUnion || Member.Offset == 0);
									if (Member.Offset < LastOffset) throw
										fmt_exception("UDT member in descending offset order (LastOffset=%li)", LastOffset);
									if (!basetype(Member.Type)) throw logic_error("no type for member (Data/Member)");
									if (!get_ti(Member.Type, basetype, loctype, &locfnames))
										throw logic_error("no typeinfo for struct member");
									_ASSERTE(!loctype.empty());
									type << loctype;
									//if (!locfnames.empty()) fnames << locfnames;
									//_ASSERTE(Member.hasName());
									if (Member.hasName()) {
										if (childrenscope != 0 && *childrenscope != 0)
											fullname.assign(childrenscope).append(SCOPE_DELIMITER);
										fullname.append(Member.getAnsiName());
										//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
									}
									fnames << fullname;
									_ASSERTE(!fnames.empty());
									++result;
									if (Struct.UDTKind == UdtUnion || basetype.SymTag == SymTagUDT) {
										LastOffset = Member.Offset;
										break;
									}
									Size = get_type_size(pMember);
									Delta = Member.Offset - LastOffset;
									_ASSERTE(Delta >= 0);
									// todo: alignment calculation is very uncertain
									tmpAlign = 1;
									if (Delta > 0) tmpAlign += log2_64(rounduppow2_64(max<ULONGLONG>(Size, Delta)));
									//if (tmpAlign > Align) Align = tmpAlign;
									LastOffset = Member.Offset + Size;
									break;
								case LocIsBitField:
									_ASSERTE(Struct.UDTKind != UdtUnion || Member.Offset == 0);
									if (Member.Offset < LastOffset) throw
										fmt_exception("UDT member in descending offset order (LastOffset=%li)", LastOffset);
									if (!basetype(Member.Type)) throw logic_error("no type for member (Data/Member)");
									if (basetype.SymTag != SymTagBaseType)
										throw logic_error("bitfield type not basic type");
									switch (basetype.BaseType) {
										case btInt:
										case btUInt:
											switch (basetype.Length) {
												case 1: type << (BT_BITFIELD | BTMT_BFLDCHAR); break;
												case 2: type << (BT_BITFIELD | BTMT_BFLDSHORT); break;
												//case 4: type << (BT_BITFIELD | BTMT_BFLDINT); break;
												default:
													if (basetype.Length != inf.cc.size_i)
														throw logic_error("unexpected bitfield type size");
													type << (BT_BITFIELD | BTMT_BFLDINT);
											}
											break;
										case btLong:
										case btULong:
											if (basetype.Length != 4)
												throw logic_error("unexpected bitfield type size");
											type << (BT_BITFIELD | BTMT_BFLDLONG);
											break;
										case btWChar: // ???
											type << (BT_BITFIELD | BTMT_BFLDSHORT);
											break;
										case btChar:
											type << (BT_BITFIELD | BTMT_BFLDCHAR);
											break;
										default:
											throw logic_error("unexpected bitfield type");
									}
									type << dt(Member.Length << 1 | (basetype.BaseType == btUInt
										|| basetype.BaseType == btULong ? 1 : 0));
									if (Member.hasName()) {
										if (childrenscope != 0 && *childrenscope != 0)
											fullname.assign(childrenscope).append(SCOPE_DELIMITER);
										fullname.append(Member.getAnsiName());
										//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
									}
									fnames << fullname;
									_ASSERTE(!fnames.empty());
									++result;
									LastOffset = Member.Offset;
									break;
								default:
									throw fmt_exception("unhandled member location type(SymTagData/DataIsMember): %s",
										Member.TokenizeLocationType().c_str());
							} // switch LocationType
							break;
						case DataIsStaticMember:
						case DataIsGlobal:
							_ASSERTE(Member.LocationType == LocIsStatic);
							// handled by ProcessStaticSymbol
							break;
						default:
							throw fmt_exception("unhandled member data kind(SymTagData): %s", Member.TokenizeDataKind().c_str());
					} // switch DataKind
					break;
				case SymTagBaseClass:
					_ASSERTE(Member.LocationType == LocIsNull);
					_ASSERTE(Struct.UDTKind != UdtUnion || Member.Offset == 0);
					_ASSERTE(Member.Type != NULL);
					if (Member.Offset < LastOffset) throw // ???
						fmt_exception("UDT member in descending offset order (LastOffset=%li)", LastOffset);
					if (!basetype(Member.Type)) throw logic_error("no type for member (BaseClass)");
					_ASSERTE(basetype.SymTag == SymTagUDT);
					//_ASSERTE(basetype.UDTKind == Struct.UDTKind);
					/*if (*/CreateTypeFromPDB(Member.Type, basetype)/* == BADNODE)
						throw logic_error("base class couldnot be created")*/;
					if (childrenscope != 0 && *childrenscope != 0) fullname.assign(childrenscope);
					_ASSERTE(basetype.hasName());
					if (basetype.hasName()) {
						if (childrenscope != 0 && *childrenscope != 0)
							fullname.append(SCOPE_DELIMITER);
						fullname.append(basetype.getAnsiName());
						//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
					}
					Delta = LoadMembersFromPDB(Member.Type, basetype, loctype, locfnames,
						tmpAlign, fullname.c_str());
					if (Delta < 0) throw fmt_exception("couldnot inherit from %s", fullname.c_str());
					_ASSERTE(Delta == 0 || !loctype.empty());
					type << loctype;
					_ASSERTE(Delta == 0 || !locfnames.empty());
					fnames << locfnames;
					result += Delta;
					if (tmpAlign > Align) Align = tmpAlign;
					LastOffset = Member.Offset;
					if (Member.UDTKind == UdtUnion) break;
					if ((Size = get_type_size(pMember)) > 0)
						if (Delta > 0)
							LastOffset += Size;
#ifdef _DEBUG
						else
							_RPT3(_CRT_WARN, "%s(...): Empty UDT %s of non-zero size(%I64i):\n",
							__FUNCTION__, fullname.c_str(), Size);
#endif // _DEBUG
					break;
				// weightless members
				case SymTagUDT:
				case SymTagEnum:
				case SymTagTypedef:
					_ASSERTE(Member.LocationType == LocIsNull);
					CreateTypeFromPDB(pMember, Member);
					break;
				// class-specific members (weightless)
				case SymTagFunction:
					_ASSERTE(Member.LocationType == LocIsStatic);
					// handled by ProcessStaticSymbol
					break;
				case SymTagVTable:
					_ASSERTE(Member.LocationType == LocIsNull);
					_ASSERTE(Struct.UDTKind != UdtUnion/* || Member.Offset == 0*/);
					if (Member.Offset < LastOffset) throw
						fmt_exception("UDT member in descending offset order (LastOffset=%li)", LastOffset);
					if (!basetype(Member.Type)) throw logic_error("no type for member (VTable)");
					if (!get_ti(Member.Type, basetype, loctype, &locfnames))
						throw logic_error("no typeinfo for struct member");
					_ASSERTE(!loctype.empty());
					type << loctype;
					//if (!locfnames.empty()) fnames << locfnames;
					if (Member.hasName()) {
						if (childrenscope != 0 && *childrenscope != 0)
							fullname.assign(childrenscope).append(SCOPE_DELIMITER);
						fullname.append(Member.getAnsiName());
					} else
						fullname.assign(VTABLE_NAME);
					//truncate(fullname, MAXNAMESIZE - 1); // IDA safety
					_ASSERTE(!fullname.empty());
					fnames << fullname;
					++result;
					if (Struct.UDTKind == UdtUnion || basetype.SymTag == SymTagUDT) break;
					Size = get_type_size(pMember);
					// ????? platí Offset u vtable nebo vtable offset == 0?
					Delta = Member.Offset - LastOffset;
					_ASSERTE(Delta >= 0);
					// todo: alignment calculation is very uncertain
					tmpAlign = 1;
					if (Delta > 0) tmpAlign += log2_64(rounduppow2_64(max<ULONGLONG>(Size, Delta)));
					//if (tmpAlign > Align) Align = tmpAlign;
					LastOffset = Member.Offset + Size;
					break;
				case SymTagVTableShape:
					break; // ok - just vtable size
				case SymTagThunk:
					_ASSERTE(Member.LocationType == LocIsStatic);
					// handled by ProcessStaticSymbol
					break;
				default: // if unsure, consider weight loose
					throw fmt_exception("unhandled struct member type %s",
						Member.TokenizeSymTag().c_str());
			} // switch SymTag
			if (!foreign_pdb && Member.LocationType == LocIsStatic)
				ProcessStaticSymbol(pMember, Member);
		} // iterate mamber
	} catch (GENERAL_CATCH_FILTER) {
		result = -1;
		type.clear(); fnames.clear();
		Align = 0;
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
			"%s(...): %s (%s=%-.3840ls index=%lu typeid=%s)\n", __FUNCTION__,
			e.what(), "struct", static_cast<BSTR>(Struct.Name), index, typeid(e).name());
		if (typeid(e) != typeid(not_convertible)) PrintSymbol(pMember);
#endif // _DEBUG
	}
	/*if (iter != inheritance_path.end()) */inheritance_path.erase(iter);
	return result;
}

// for enums: load constants from pdb typeinfo

static bool LoadConstsFromPDB(const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Enum, enum_t enu) {
	_ASSERTE(pSymbol != NULL);
	if (!pSymbol) return false;
	_ASSERTE(Enum());
	_ASSERTE(Enum.SymTag == SymTagEnum);
	if (Enum.SymTag != SymTagEnum) return false;
	_ASSERTE(enu != BADNODE);
	if (enu == BADNODE) return false;
	const DiaSymChildren Values(pSymbol, SymTagData);
	if (!Values()) return false; // error
	if (Values <= 0) return true; // nothing to add but success
	bool incomplete(false);
#ifdef _DEBUG
	ULONG index(0);
#endif // _DEBUG
	CComPtr<IDiaSymbol> pConst;
	while (Values.Next(pConst)) try {
#ifdef _DEBUG
		++index;
#endif // _DEBUG
		const DiaSymbol Const(pConst);
		_ASSERTE(Const());
		_ASSERTE(Const.SymTag == SymTagData);
		if (Const.SymTag != SymTagData) throw fmt_exception("SymTag=%s", Const.TokenizeSymTag().c_str());
		_ASSERTE(Const.LocationType == LocIsConstant);
		if (Const.LocationType != LocIsConstant) throw fmt_exception("Location=%s", Const.TokenizeLocationType().c_str());
		_ASSERTE(Const.DataKind == DataIsConstant);
		if (Const.DataKind != DataIsConstant) throw fmt_exception("DatKind=%s", Const.TokenizeDataKind().c_str());
		const uval_t value = static_cast<uval_t>(VarToUI64(Const.Value));
		string fullname; //char name[MAXNAMESIZE];
		if (!Const.Name || fullname.assign(Const.getAnsiName()).empty())
			throw logic_error("name is missing or not convertible");
		int err(add_const(enu, fullname.c_str(), value));
		if (err == CONST_ERROR_NAME) { // dupe const name try resolve
			// is global enum present? (resolve unwanted enums globalization)
			const enum_t globenu(get_const_enum(get_const_by_name(fullname.c_str())));
			char enum_name[MAXNAMESIZE];
			if (globenu != BADNODE && get_enum_name(globenu, CPY(enum_name)) > 0
				&& Enum.getAnsiName().compare(0, MAXNAMESIZE - 1, enum_name) == 0) {
				OutputDebugString("deleting false global enum %s (%08IX)\n", enum_name, globenu);
				del_enum(globenu);
				// 2-nd service
				if (add_const(enu, fullname.c_str(), value) != 0)
					throw logic_error("add_const(...) both attempts failed");
			}
		} else if (err != 0)
			throw fmt_exception("add_const(...) returned %i", err);
	} catch (GENERAL_CATCH_FILTER) {
		incomplete = true;
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
			"%s(...): %s (%s=%-.3840ls index=%lu typeid=%s)\n", __FUNCTION__,
			e.what(), "enum", static_cast<BSTR>(Enum.Name), index, typeid(e).name());
		PrintSymbol(pConst);
#endif // _DEBUG
	}
	if (incomplete) set_enum_cmt(enu, "incomplete", false);
	return true;
}

static LONG LoadConstsFromPDB(const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Enum, typestring &type, plist &fnames) {
	type.clear(); fnames.clear();
	_ASSERTE(pSymbol != NULL);
	if (!pSymbol) return -1;
	_ASSERTE(Enum());
	_ASSERTE(Enum.SymTag == SymTagEnum);
	if (Enum.SymTag != SymTagEnum) return -1;
	const DiaSymChildren Values(pSymbol, SymTagData);
	_ASSERTE(Values());
	if (!Values()) return -1; // error
	if (Values <= 0) return 0; // nothing to add but success
	LONG result(0);
#ifdef _DEBUG
	ULONG index(0);
#endif // _DEBUG
	CComPtr<IDiaSymbol> pConst;
	uval_t level(0);
	while (Values.Next(pConst)) try {
#ifdef _DEBUG
		++index;
#endif // _DEBUG
		const DiaSymbol Const(pConst);
		_ASSERTE(Const());
		_ASSERTE(Const.SymTag == SymTagData);
		if (Const.SymTag != SymTagData) throw fmt_exception("SymTag=%s", Const.TokenizeSymTag().c_str());
		_ASSERTE(Const.LocationType == LocIsConstant);
		if (Const.LocationType != LocIsConstant) throw fmt_exception("Location=%s", Const.TokenizeLocationType().c_str());
		_ASSERTE(Const.DataKind == DataIsConstant);
		if (Const.DataKind != DataIsConstant) throw fmt_exception("DatKind=%s", Const.TokenizeDataKind().c_str());
		if (!Const.Name) throw logic_error("name is missing or not convertible");
		const uval_t value = static_cast<uval_t>(VarToUI64(Const.Value));
		type << de(/*delta*/value - level);
		level = value;
		fnames << Const.getAnsiName();
		++result;
	} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
			"%s(...): %s (%s=%-.3840ls index=%lu typeid=%s)\n", __FUNCTION__,
			e.what(), "enum", static_cast<BSTR>(Enum.Name), index, typeid(e).name());
		PrintSymbol(pConst);
#endif // _DEBUG
	}
	return result;
}

static tid_t CreateTypeFromPDB(const CComPtr<IDiaSymbol> &pSymbol,
	const DiaSymbol &Symbol, bool accept_incomplete) {
	tid_t tid(BADNODE), tmptid;
	_ASSERTE(pSymbol != NULL);
	if (!pSymbol) return tid;
	_ASSERTE(Symbol());
	DiaSymbol basetype;
	string fullname;
	const type_t *type;
	typestring tinfo;
	plist fnames;
	LONG Count;
	hash_set<DWORD>::iterator iter_id;
	hash_set<string>::iterator iter_name;
	uint8 Align;
	type_t cv_qualifier;
	string validated_name;
	switch (Symbol.SymTag) {
		case SymTagUDT: {
			fullname.assign(getTypeFullName(pSymbol));
			//truncate(fullname, MAXSTR/*MAXNAMESIZE*/ - 1); // safety is boring ;)
			_ASSERTE(!fullname.empty());
			if (types_created.by_id.find(Symbol.SymIndexId) != types_created.by_id.end()
				|| !fullname.empty() && types_created.by_name.find(fullname) != types_created.by_name.end()) {
				if (accept_incomplete
					&& (tid = get_struc_id_anyway(fullname.c_str())) == BADNODE) tid = 0;
				break;
			}
			if ((tid = get_struc_id(fullname.c_str())) != BADNODE) break;
			iter_id = types_created.by_id.insert(Symbol.SymIndexId).first;
			_ASSERTE(iter_id != types_created.by_id.end());
			iter_name = !fullname.empty() ?
				types_created.by_name.insert(fullname).first : types_created.by_name.end();
			struc_t *struc = get_struc(add_struc(BADADDR, !fullname.empty() ?
				fullname.c_str() : NULL, Symbol.UDTKind == UdtUnion));
			if (struc != 0) {
				tid = struc->id;
				LoadMembersFromPDB(pSymbol, Symbol, struc);
				++totalstructs;
				struc->props |= SF_HIDDEN;
				save_struc(struc);
			} else if (!fullname.empty()) {
				if ((tid = get_struc_id_anyway(fullname.c_str())) == BADNODE) {
					if (get_validated_name(fullname.c_str(), validated_name)
						&& (struc = get_struc(add_struc(BADADDR, validated_name.c_str(),
						Symbol.UDTKind == UdtUnion))) != 0) {
						tid = struc->id;
						LoadMembersFromPDB(pSymbol, Symbol, struc);
						++totalstructs;
						struc->props |= SF_HIDDEN;
						save_struc(struc);
					}
				}
				tmptid = BADNODE;
				if (get_named_type(idati, fullname.c_str(), DEF_NTF_FLAGS, &type) > 0) {
					if (is_resolved_type_struni(type))
						tmptid = 0;
					/*else
						cmsg << log_prefix << "WARNING: couldnot create " << "struct" <<
							' ' << fullname << " (name conflict with different type)" << endl;*/
#ifdef _DEBUG
					else
						_RPT3(_CRT_WARN, "%s(...): Couldnot create %s %s (name conflict with diferrent type\n",
							__FUNCTION__, Symbol.UDTKind == UdtUnion ? "union" : "struct", fullname.c_str());
#endif // _DEBUG
				} else if ((Count = LoadMembersFromPDB(pSymbol, Symbol, tinfo, fnames, Align)) >= 0) {
					if (Count == 0) {
						_ASSERTE(fnames.empty());
						_ASSERTE(tinfo.empty());
						//tinfo << pstring(); // this is probably invalid!
						_RPT3(_CRT_WARN, "%s(...): Saving empty %s to til (\"%s\")\n",
							__FUNCTION__, Symbol.UDTKind == UdtUnion ? "union" : "struct",
							fullname.c_str());
					}
					// alignment calculation is very experimental and uncertain yet
					//Align = 0; //log2_64(get_default_align(inf.cc.cm)) + 1;
					tinfo.before(dt(Count << 3 | Align & 7));
					cv_qualifier = 0;
					if (Symbol.ConstType) cv_qualifier |= BTM_CONST;
					if (Symbol.VolatileType) cv_qualifier |= BTM_VOLATILE;
					tinfo.before(cv_qualifier | BT_COMPLEX |
						(Symbol.UDTKind == UdtUnion ? BTMT_UNION : BTMT_STRUCT));
#ifdef _DEBUG
					OutputDebugString("%s(...): Saving %s %s to til: %li members, alignment=%u\n",
						__FUNCTION__, Symbol.UDTKind == UdtUnion ? "union" : "struct",
						fullname.c_str(), Count, Align);
					print_type_to_many_lines(dbg_printer, __FUNCTION__, "    ", 2, 30,
						idati, tinfo, fullname.c_str(), NULL, !fnames.empty() ? fnames.c_str() : NULL);
#endif // _DEBUG
					if ((tmptid = ::set_named_type(fullname.c_str(), tinfo, fnames)) == 0) {
						++totalstructs;
						// structs stored to til are most probably not accessible via
						// get_struc/get_struc_id API - they must be synchronized to idb
						// first, unfortunatelly I found no exported API to do this
						if ((tmptid = get_struc_id(fullname.c_str())) == BADNODE) tmptid = 0;
						OutputDebugString("%s(...): %s %s stored successfully to til (%li members, tid=%08lX)\n",
							__FUNCTION__, Symbol.UDTKind == UdtUnion ? "Union" : "Struct",
							fullname.c_str(), Count, tmptid);
					}
				} // LoadMembers... ok
				if (tid == BADNODE) tid = tmptid;
			} // has name
			if (iter_name != types_created.by_name.end()) types_created.by_name.erase(iter_name);
			/*if (iter_id != types_created.by_id.end()) */types_created.by_id.erase(iter_id);
			break;
		} // SymTagUDT
		case SymTagEnum:
			fullname.assign(getTypeFullName(pSymbol));
			//truncate(fullname, MAXSTR/*MAXNAMESIZE*/ - 1); // safety is boring ;)
			//_ASSERTE(!fullname.empty());
			if (types_created.by_id.find(Symbol.SymIndexId) != types_created.by_id.end()
				|| !fullname.empty() && types_created.by_name.find(fullname) != types_created.by_name.end()) {
				if (accept_incomplete
					&& (tid = (tid_t)get_enum_anyway(fullname.c_str())) == BADNODE)
						tid = 0;
				break;
			}
			if ((tid = (tid_t)get_enum(fullname.c_str())) != BADNODE) break;
			_ASSERTE(Symbol.TypeId != 0);
			if (Symbol.Type == NULL || !basetype(Symbol.Type)) break;
#ifdef _DEBUG
			if (Symbol.BaseType != basetype.BaseType) _RPTF3(_CRT_ASSERT,
				"%s(...): typinfo.BaseType != basetype.BaseType (0x%lX != 0x%lX)\n",
				__FUNCTION__, Symbol.BaseType, basetype.BaseType);
			if (Symbol.Length != basetype.Length) _RPTF3(_CRT_ASSERT,
				"%s(...): typinfo.Length != basetype.Length (0x%I64X != 0x%I64X)\n",
				__FUNCTION__, Symbol.Length, basetype.Length);
#endif // _DEBUG
			iter_id = types_created.by_id.insert(Symbol.SymIndexId).first;
			_ASSERTE(iter_id != types_created.by_id.end());
			iter_name = !fullname.empty() ?
				types_created.by_name.insert(fullname).first : types_created.by_name.end();
			if ((tid = (tid_t)add_enum(BADADDR, !fullname.empty() ? fullname.c_str() :
				NULL, getFlags(basetype() ? basetype : pSymbol))) != BADNODE) {
				//set_enum_flag((enum_t)tid, getFlags(basetype() ? basetype : pSymbol));
				set_ti(tid, Symbol.Type != NULL ? Symbol.Type : pSymbol,
					Symbol.Type != NULL ? basetype : Symbol); // experimental
				LoadConstsFromPDB(pSymbol, Symbol, (enum_t)tid);
				++totalenums;
				set_enum_hidden((enum_t)tid, true);
			} else if (!fullname.empty()) {
				if ((tid = (enum_t)get_enum_anyway(fullname.c_str())) == BADNODE) {
					if (get_validated_name(fullname.c_str(), validated_name)
						&& (tmptid = (tid_t)add_enum(BADADDR, validated_name.c_str(),
						getFlags(basetype() ? basetype : pSymbol))) != BADNODE) {
						tid = tmptid;
						//set_enum_flag((enum_t)tid, getFlags(basetype.SymIndex != 0 ? basetype : typinfo));
						set_ti(tid, Symbol.Type != NULL ? Symbol.Type : pSymbol,
							Symbol.Type != NULL ? basetype : Symbol); // experimental
						LoadConstsFromPDB(pSymbol, Symbol, (enum_t)tid);
						++totalenums;
						set_enum_hidden((enum_t)tid, true);
					}
				}
				tmptid = BADNODE;
				if (get_named_type(idati, fullname.c_str(), DEF_NTF_FLAGS, &type) > 0) {
					if (is_resolved_type_enum(type))
						tmptid = 0;
					/*else
						cmsg << log_prefix << "WARNING: couldnot create " << "enum" <<
							' ' << fullname << " (name conflict with different type)" << endl;*/
#ifdef _DEBUG
					else
						_RPT3(_CRT_WARN, "%s(...): Couldnot create %s %s (name conflict with diferrent type\n",
							__FUNCTION__, "enum", fullname.c_str());
#endif // _DEBUG
				} else if ((Count = LoadConstsFromPDB(pSymbol, Symbol, tinfo, fnames)) >= 0) {
#ifdef _DEBUG
					if (Count == 0) _RPT3(_CRT_WARN, "%s(...): Saving empty %s to til (\"%s\")\n",
						__FUNCTION__, "enum", fullname.c_str());
#endif // _DEBUG
					Align = 0;
					const ULONGLONG Size = get_type_size(pSymbol);
					if (Size > 0 && (Align = log2_64(Size)) < BTE_SIZE_MASK)
						if (Size == 1ULL << Align) ++Align; else Align = 0;
					tinfo.before(BTE_ALWAYS | Align & BTE_SIZE_MASK);
					tinfo.before(dt(Count));
					cv_qualifier = 0;
					if (Symbol.ConstType) cv_qualifier |= BTM_CONST;
					if (Symbol.VolatileType) cv_qualifier |= BTM_VOLATILE;
					tinfo.before(cv_qualifier | BTF_ENUM);
#ifdef _DEBUG
					OutputDebugString("%s(...): Saving %s %s to til:\n", __FUNCTION__, "enum", fullname.c_str());
					print_type_to_many_lines(dbg_printer, __FUNCTION__, "    ", 2, 30,
						idati, tinfo, fullname.c_str(), NULL, !fnames.empty() ? fnames.c_str() : NULL);
#endif // _DEBUG
					if ((tid = ::set_named_type(fullname.c_str(), tinfo, fnames)) == 0) {
						++totalenums;
						// enums stored to til are most probably not accessible via
						// get_enum API - they must be synchronized to idb first,
						// unfortunatelly I found no exported API to do this
						if ((tmptid = (tid_t)get_enum(fullname.c_str())) == BADNODE) tmptid = 0;
						OutputDebugString("%s(...): %s %s stored successfully to til (%li members, tid=%08lX)\n",
							__FUNCTION__, "Enum", fullname.c_str(), Count, tmptid);
					}
				} // LoadConsts... ok
				if (tid == BADNODE) tid = tmptid;
			} // has name
			if (iter_name != types_created.by_name.end()) types_created.by_name.erase(iter_name);
			/*if (iter_id != types_created.by_id.end()) */types_created.by_id.erase(iter_id);
			break;
		case SymTagTypedef:
			// DWORD: Index=0xF7 TypeIndex=0xF7 Value=0x0 Tag=Typedef ModBase=0000000000400000
			//   SymId 0xF7: Tag=Typedef Name=DWORD Type=0x52 TypeId=0x52 SymIndex=0xF7
			//     SymId 0x52: Tag=BaseType Length=0x4 BaseType=ULong SymIndex=0x52
			fullname.assign(getTypeFullName(pSymbol));
			//truncate(fullname, MAXSTR/*MAXNAMESIZE*/ - 1); // safety is boring ;)
			_ASSERTE(!fullname.empty());
			if (fullname.empty()) break;
			if (types_created.by_id.find(Symbol.SymIndexId) != types_created.by_id.end()
				|| types_created.by_name.find(fullname) != types_created.by_name.end()) {
				if (accept_incomplete && (tid = get_named_type(fullname.c_str())) == BADNODE)
					tid = 0;
				break;
			}
			if ((tid = get_named_type(fullname.c_str())) != BADNODE) break;
			_ASSERTE(Symbol.Type != NULL);
			if (Symbol.Type == NULL) break;
			//_ASSERTE(types_created.by_id.find(Symbol.SymIndexId) == types_created.by_id.end());
			iter_id = types_created.by_id.insert(Symbol.SymIndexId).first;
			_ASSERTE(iter_id != types_created.by_id.end());
			iter_name = types_created.by_name.insert(fullname).first;
			_ASSERTE(iter_name != types_created.by_name.end());
			if ((tid = set_named_type(fullname.c_str(), Symbol.Type,
				DEF_NTF_FLAGS, &sc_tdef)) == 0) ++totaltypedefs;
			/*if (iter_name != types_created.by_name.end()) */types_created.by_name.erase(iter_name);
			/*if (iter_id != types_created.by_id.end()) */types_created.by_id.erase(iter_id);
			break;
#ifdef _DEBUG
		case SymTagBaseType:
		case SymTagPointerType:
		case SymTagFunction:
			break;
		default:
			_RPTF2(_CRT_WARN, "%s(...): Unhandled type %s\n", __FUNCTION__,
				Symbol.TokenizeSymTag().c_str());
#endif // _DEBUG
	}
	return tid;
}

void LoadGlobalScope(DiaSymbol &GlobalScope) {
	CComPtr<IDiaSymbol> pSymbol;
	HRESULT hr;
	if ((hr = pSession->get_globalScope(&pSymbol)) != S_OK) return;
	_ASSERTE(pSymbol != NULL);
	if (!GlobalScope(pSymbol)) return;
	_ASSERTE(GlobalScope.SymTag == SymTagExe);
	if (phid2mt() != GlobalScope.MachineType && askyn_c(0,
		"AUTOHIDE REGISTRY\nHIDECANCEL\n"
		"PDB architecture(%s) mismatch to IDAbase processor type, are you sure to import?",
		GlobalScope.TokenizeMachineType()) <= 0) throw 1;
	if (GlobalScope.MachineType != IMAGE_FILE_MACHINE_I386
		&& GlobalScope.MachineType != IMAGE_FILE_MACHINE_IA64)
		cmsg << log_prefix << "WARNING: untested program architecture (" <<
			GlobalScope.TokenizeMachineType() << ')' << endl;
	if (GlobalScope.Age > 1)
		cmsg << log_prefix << "WARNING: program database age >1 (" << dec <<
			GlobalScope.Age << ") --> caching of old types probable" << endl;
}

// LoadOwn() tries to apply PDB by Microsoft Debug Information Accessor interface.
// This is preferred method over DbgHelp(ImageHlp) API as DIA is able to
// retrieve much more information from PDB.
// To succeed ensure msdiaXX.dll is properly registered on local machine (run
// regsvr32 msdiaXX.dll) where XX is version suffix of current Visual Studio.
// Returns true if everything essential was proceeded by DIA and no more
// processing is needed (false to signal continuing with conventional method).
static int LoadOwn(bool invoked_by_loader) {
	HRESULT hr = CoInitialize(NULL);
	if (FAILED(hr)) {
		_RPTF3(_CRT_WARN, "%s(...): %s(NULL) returned %08lX\n", __FUNCTION__,
			"CoInitialize", hr);
		return -7;
	}
	int exit_code;
	try {
		// Initialize The Component Object Module Library
		// Obtain Access To The Provider
		CComPtr<IDiaDataSource> pSource;
		if (FAILED(hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER,
			__uuidof(IDiaDataSource), (void **)&pSource))) {
			_RPTF3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n", __FUNCTION__,
				"IDiaDataSource::CoCreateInstance", hr);
			if (!invoked_by_loader) COM_Error("IDiaDataSource::CoCreateInstance", hr);
			throw -6;
		}
		if (hr != S_OK) throw -6; // status unknown
		_ASSERTE(pSource != NULL);
		if (invoked_by_loader && askyn_c(1, "AUTOHIDE REGISTRY\nHIDECANCEL\n"
			"IDA Pro has determined that the input file was linked with debug information.\n"
			"Do you want to look for the corresponding PDB file at the local symbol store?\n") <= 0)
			throw 2;
		foreign_pdb = false;
		char input[QMAXPATH];
		get_input_file_path(CPY(input));
		const char *ans;
		while (!qfileexist(input)) {
			if ((ans = askfile_c(false, input, "Please specify the input executable")) == 0)
				throw -5;
			qstrcpy(input, ans);
		}
		_ASSERTE(qfileexist(input));
		char drive[_MAX_DRIVE], path[_MAX_PATH], fname[_MAX_FNAME], pdb[_MAX_PATH];
		_splitpath(input, drive, path, fname, 0);
		_makepath(pdb, drive, path, fname, "pdb");
		while (!invoked_by_loader && !qfileexist(pdb)) {
			if ((ans = askfile_c(false, pdb, "Please specify the PDB file")) == 0)
				throw -5;
			qstrcpy(pdb, ans);
		}
		wchar_t wszFilename[_MAX_PATH];
		mbstowcs(wszFilename, pdb, qnumber(wszFilename));
		if (FAILED(hr = pSource->loadDataFromPdb(wszFilename))) {
			mbstowcs(wszFilename, input, qnumber(wszFilename));
			if (FAILED(hr = pSource->loadDataForExe(wszFilename, NULL, NULL))) {
				_RPTF3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n", __FUNCTION__,
					"IDiaDataSource::loadDataFrom", hr);
				if (!invoked_by_loader) COM_Error("IDiaDataSource::loadDataFromPdb/IDiaDataSource::loadDataForExe", hr);
				throw -4;
			}
		}
		if (hr != S_OK) throw -4; // status unknown
		if (FAILED(hr = pSource->openSession(&pSession))) {
			_RPTF3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n", __FUNCTION__,
				"IDiaDataSource::openSession", hr);
			COM_Error("IDiaDataSource::openSession", hr);
			throw -3;
		}
		if (hr != S_OK) throw -3;
		_ASSERTE(pSession != NULL);
		CComPtr<IDiaEnumTables> pTables;
		if (FAILED(hr = pSession->getEnumTables(&pTables))) {
			_RPT3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n", __FUNCTION__,
				"IDiaSession::getEnumTables", hr);
			COM_Error("IDiaSession::getEnumTables", hr);
			throw -2;
		}
		if (hr != S_OK) throw -2; // no tables
		_ASSERTE(pTables != NULL);
		cmsg << log_prefix << "MS Debug Information Accessor is ready" << endl;
		wait_box.open("PDB plugin is running");
		load_vc_til();
		reset_globals(true);
		DiaSymbol GlobalScope;
		LoadGlobalScope(GlobalScope);
		ULONGLONG LoadAddress;
		if ((hr = pSession->get_loadAddress(&LoadAddress)) != S_OK) {
			LoadAddress = 0;
			_RPT2(_CRT_WARN, "%s(...): IDiaSession::get_loadAddress(...) returned %08lX\n", __FUNCTION__, hr);
			COM_Error("IDiaSession::get_loadAddress", hr);
		}
		SymBase = static_cast<DWORD64>(netnode("$ PE header").altval(-2)/*LoadAddress?*/);
		totaltypeinfos = 0;
		totaldata = 0;
		totalfuncs = 0;
		totaltypedefs = 0;
		totalstructs = 0;
		totalenums = 0;
		totalnames = 0;
		types_t types;
		statics_t statics, functions;
		sym_t names;
		ln_t lines;
		loc_t locals;
		ifstream is;
		ea_t ea, endEA, ip;
		ULONGLONG size;
		func_t *func;
		ULONG celt;
		CComPtr<IDiaTable> pTable;
		CDiaBSTR TableName;
		CComPtr<IDiaSymbol> pSymbol;
		CComPtr<IDiaEnumSymbols> pSymbols;
		DiaSymbol Symbol;
		cmsg << log_prefix << "Scanning all tables...";
		wait_box.open("Scanning all tables...");
		while ((hr = pTables->Next(1, &pTable, &celt)) == S_OK) {
			_ASSERTE(celt >= 1);
			_ASSERTE(pTable != NULL);
			if (wasBreak()) throw 1;
			pTable->get_name(&TableName);
			_ASSERTE(TableName != NULL);
			if ((hr = pTable->QueryInterface(_uuidof(IDiaEnumSymbols), (void**)&pSymbols)) == S_OK) {
				_ASSERTE(pSymbols != NULL);
				wait_box.open("Loading symbols...");
				while ((hr = pSymbols->Next(1, &pSymbol, &celt)) == S_OK) {
					_ASSERTE(celt >= 1);
					_ASSERTE(pSymbol != NULL);
					if (wasBreak()) throw 1;
					Symbol(pSymbol);
					_ASSERTE(Symbol());
					switch (Symbol.SymTag) {
						case SymTagUDT:
						case SymTagEnum:
						case SymTagTypedef:
							if (Symbol.ClassParentId == 0 && !Symbol.Nested/*???care???*/)
								types.Add(Symbol);
							break;
						case SymTagCompiland:
							if (Symbol.hasLibraryName()) {
								char libname[MAX_PATH];
								Symbol.LibraryName.toAnsi(CPY(libname));
								netnode lnm("$ lnm lastlibs", 0, true);
								char strval[MAXSPECSIZE];
								for (nodeidx_t ndx = lnm.sup1st(); ndx != BADNODE; ndx = lnm.supnxt(ndx))
									if (lnm.supstr(ndx, CPY(strval)) > 0
										&& _stricmp(strval, libname) == 0/*boost::iequals(strval, libname)*/)
											break;
								if (ndx == BADNODE) for (ndx = 0; ndx != BADNODE; ++ndx)
									if (lnm.supstr(ndx, NULL, 0) <= 0) {
										lnm.supset(ndx, libname);
										break;
									}
							}
							break;
						case SymTagFunction:
						case SymTagThunk:
							if (Symbol.LocationType == LocIsStatic
								&& isLoaded(ea = static_cast<ea_t>(SymBase) + Symbol.RVA)
								&& !is_spec_ea(ea)) functions.Add(Symbol);
							break;
					} // switch SymTag
					switch (Symbol.LocationType) {
						case LocIsStatic:
							statics.Add(Symbol);
							break;
					} // switch LocationType
					pSymbol.Release();
				} // enumerate symbols
				pSymbols.Release();
				wait_box.close();
			} // QueryInterface() ok (symbols)
			CComPtr<IDiaEnumSourceFiles> pSourceFiles;
			if ((hr = pTable->QueryInterface(_uuidof(IDiaEnumSourceFiles), (void**)&pSourceFiles)) == S_OK) {
				_ASSERTE(pSourceFiles != NULL);
				wait_box.open("Loading source lines...");
				CComPtr<IDiaSourceFile> pSourceFile;
				while ((hr = pSourceFiles->Next(1, &pSourceFile, &celt)) == S_OK) {
					_ASSERTE(celt >= 1);
					_ASSERTE(pSourceFile != NULL);
					if (wasBreak()) throw 1;
					DiaSourceFile SourceFile(pSourceFile);
					if (SourceFile.hasFileName()
						&& SourceFile.ChecksumType == CHKSUM_TYPE_MD5 && SourceFile.Checksum) try {
						_ASSERTE(SourceFile.Checksum.size() == 0x10);
						is.clear();
						is.open(SourceFile.FileName.toAnsi().c_str(), ios_base::in | ios_base::binary);
						if (is.is_open()) {
							boost::md5 md5(is);
							if (memcmp(SourceFile.Checksum.get(), md5.digest().value(), 0x10) != 0) {
								cmsg << log_prefix << "Source file " << (BSTR)SourceFile.FileName <<
									" MD5 mismatch: " << md5.digest().hex_str_value() <<
									" (no lines will be imported)" << endl;
								SourceFile.Reset();
							} // mismatch
							is.close();
						} // ifstream ok
					} catch (GENERAL_CATCH_FILTER) {
						SourceFile.Reset();
						_RPTF3(_CRT_WARN, "%s(...): %s (%s)\n", __FUNCTION__, e.what(), typeid(e).name());
					}
					if (SourceFile.hasFileName()
						&& (hr = pSourceFile->get_compilands(&pSymbols)) == S_OK) {
						_ASSERTE(pSymbols != NULL);
						while ((hr = pSymbols->Next(1, &pSymbol, &celt)) == S_OK) {
							_ASSERTE(celt >= 1);
							_ASSERTE(pSymbol != NULL);
							if (wasBreak()) throw 1;
							CComPtr<IDiaEnumLineNumbers> pLineNumbers;
							if ((hr = pSession->findLines(pSymbol, pSourceFile, &pLineNumbers)) == S_OK) {
								_ASSERTE(pLineNumbers != NULL);
								CComPtr<IDiaLineNumber> pLineNumber;
								while ((hr = pLineNumbers->Next(1, &pLineNumber, &celt)) == S_OK) {
									_ASSERTE(celt >= 1);
									_ASSERTE(pLineNumber != NULL);
									const DiaLineNumber LineNumber(pLineNumber);
									_ASSERTE(lineNumber.LineNumberEnd == 0
										|| LineNumber.LineNumberEnd >= LineNumber.LineNumber);
									DWORD lineNumber = LineNumber.LineNumberEnd;
									if (lineNumber <= 0) lineNumber = LineNumber.LineNumber;
									_ASSERTE(lineNumber > 0);
									if (lineNumber > 0) lines[SourceFile][lineNumber].insert(LineNumber);
									pLineNumber.Release();
								} // iterate lines
								pLineNumbers.Release();
							} // findLines() ok
							pSymbol.Release();
						} // iterate compilands
						pSymbols.Release();
					} // get_compilands() ok
					pSourceFile.Release();
				} // iterate source files
				pSourceFiles.Release();
				wait_box.close();
			} // QueryInterface() ok (sourcefiles)
			CComPtr<IDiaEnumFrameData> pFrames;
			/*
			if ((hr = pTable->QueryInterface(_uuidof(IDiaEnumFrameData), (void**)&pFrames) == S_OK)) {
				_ASSERTE(pFrames != NULL);
				wait_box.open("Loading frames...");
				while ((hr = pFrames->Next(1, &pFrame, &celt)) == S_OK) {
					_ASSERTE(celt >= 1);
					_ASSERTE(pFrame != NULL);
					//const DiaFrame Frame(pFrame);
					//PrintFrame(pFrame, Frame, 1);
					// TODO: process
					pFrame.Release();
				}
				pFrames.Release();
				wait_box.close();
			} // QueryInterface() ok (sourcefiles)
			*/
			CComPtr<IDiaEnumSegments> pSegments;
			if ((hr = pTable->QueryInterface(_uuidof(IDiaEnumSegments), (void**)&pSegments) == S_OK)) {
				_ASSERTE(pSegments != NULL);
				wait_box.open("Loading segments...");
				CComPtr<IDiaSegment> pSegment;
				while ((hr = pSegments->Next(1, &pSegment, &celt)) == S_OK) {
					_ASSERTE(celt >= 1);
					_ASSERTE(pSegment != NULL);
					if (wasBreak()) throw 1;
					//PrintSegment(pSegment, 1);
					//const DiaSegment Segment(pSegment);
					// TODO: process
					pSegment.Release();
				}
				pSegments.Release();
				wait_box.close();
			} // QueryInterface() ok (segments)
			CComPtr<IDiaEnumSectionContribs> pSectionContribs;
			if ((hr = pTable->QueryInterface(_uuidof(IDiaEnumSectionContribs), (void**)&pSectionContribs) == S_OK)) {
				_ASSERTE(pSectionContribs != NULL);
				wait_box.open("Loading section contribs...");
				CComPtr<IDiaSectionContrib> pSectionContrib;
				while ((hr = pSectionContribs->Next(1, &pSectionContrib, &celt)) == S_OK) {
					_ASSERTE(celt >= 1);
					_ASSERTE(pSectionContrib != NULL);
					if (wasBreak()) throw 1;
					//PrintSectionContrib(pSectionContrib, 1);
					//const DiaSectionContrib SectionContrib(pSectionContrib);
					// TODO: process
					pSectionContrib.Release();
				}
				pSectionContribs.Release();
				wait_box.close();
			} // QueryInterface() ok (section contribs)
			CComPtr<IDiaEnumInjectedSources> pInjectedSources;
			if ((hr = pTable->QueryInterface(_uuidof(IDiaEnumInjectedSources), (void**)&pInjectedSources) == S_OK)) {
				_ASSERTE(pInjectedSources != NULL);
				wait_box.open("Loading injected sources...");
				CComPtr<IDiaInjectedSource> pInjectedSource;
				while ((hr = pInjectedSources->Next(1, &pInjectedSource, &celt)) == S_OK) {
					_ASSERTE(celt >= 1);
					_ASSERTE(pInjectedSource != NULL);
					if (wasBreak()) throw 1;
					//PrintInjectedSource(pInjectedSource, 1);
					//const DiaInjectedSource InjectedSource(pInjectedSource);
					// TODO: process
					pInjectedSource.Release();
				}
				pInjectedSources.Release();
				wait_box.close();
			} // QueryInterface() ok (injected sources)
			TableName.Empty();
			pTable.Release();
		} // iterate tables
		wait_box.close(); /* "Scanning all tables..." */
		cmsg << "done" << endl;
		if (load_plugin("comhelper2") == 0) load_plugin("comhelper");
		if (!types.empty()) {
			wait_box.open("Storing types to idabase...");
			types.SaveTypes();
			types.clear();
			wait_box.close();
		}
		if (!statics.empty()) {
			wait_box.open("Creating static symbols...");
			cmsg << log_prefix << "Creating static symbols...";
			for (statics_t::nth_index_const_iterator<0>::type i = statics.get<0>().begin();
				i != statics.get<0>().end(); ++i) {
				if (wasBreak()) throw 1;
				ProcessStaticSymbol(*i, *i, &names);
			}
			statics.clear();
			cmsg << "done" << endl;
			wait_box.close();
		}
		msg("%sTotal %u struct%s, %u enum%s, %u typedef%s, %u typeinfo%s set, %u data type%s created, %u function%s created, %u symbol%s named\n",
			log_prefix, totalstructs, totalstructs != 1 ? "s" : "",
			totalenums, totalenums != 1 ? "s" : "",
			totaltypedefs, totaltypedefs != 1 ? "s" : "",
			totaltypeinfos, totaltypeinfos != 1 ? "s" : "",
			totaldata, totaldata != 1 ? "s" : "",
			totalfuncs, totalfuncs != 1 ? "s" : "",
			totalnames, totalnames != 1 ? "s" : "");
		if (!lines.empty()) {
			wait_box.open("Importing source lines...");
			cmsg << log_prefix << "Attaching source lines...";
			uint totallines(0);
			for (ln_t::const_iterator file = lines.begin(); file != lines.end(); ++file) {
				if (wasBreak()) throw 1;
				/*
				_ASSERTE(pSession != NULL);
				if ((hr = pSession->findFileById(file->first, &pSourceFile)) != S_OK) {
					_RPTF3(_CRT_WARN, "%s(...): %s(0x%lX, ...) returned %08lX\n",
						__FUNCTION__, "IDiaSession::findFileById", file->first, hr);
					COM_Error("IDiaSession::findFileById", hr);
					continue;
				}
				_ASSERTE(pSourceFile != NULL);
				if ((hr = pSourceFile->get_fileName(&FileName)) != S_OK) {
					_RPTF3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n",
						__FUNCTION__, "IDiaSourceFile::get_fileName", hr);
					COM_Error("IDiaSourceFile::get_fileName", hr);
					continue;
				}
				*/
				static const char fmt[] = "HIDECANCEL\nImporting source lines...\n(%ls)";
				wait_box.open(/*kernel_version >= 5.2 ? fmt : */fmt + 11,
					(BSTR)file->first.FileName);
				is.clear();
				_ASSERTE(file->first.hasFileName());
				is.open(file->first.FileName.toAnsi().c_str());
				DWORD index(0);
				for (ln_t::mapped_type::const_iterator j = file->second.begin(); j != file->second.end(); ++j) {
					ea_t ea;
					ln_t::mapped_type::mapped_type::const_iterator k;
					if (is.is_open()) {
						string line;
						while (is.good() && index < j->first) {
							getline(is, line);
							if (is.fail()) break;
							++index;
							boost::trim_if(line, boost::is_space());
							if (line.empty()) continue;
							for (k = j->second.begin(); k != j->second.end(); ++k) {
								ea = static_cast<ea_t>(SymBase) + k->RVA;
								if (isEnabled(ea) && get_source_linnum(ea) == BADADDR)
									add_long_cmt(ea, true, "%-.*s", MAXSTR - 1, line.c_str());
							}
						} // scan forward
					}
					for (k = j->second.begin(); k != j->second.end(); ++k) {
						if (isEnabled(ea = static_cast<ea_t>(SymBase) + k->RVA)) {
							if (get_source_linnum(ea) == BADADDR) {
								++totallines;
								showAddr(ea);
							}
							add_sourcefile(ea, static_cast<LONG>(k->Length) > 0 ? ea + k->Length :
								next_not_tail(ea), file->first.FileName.toAnsi().c_str());
							set_source_linnum(ea, j->first);
						}
					}
				} // iterate lines
				if (is.is_open()) is.close();
				wait_box.close();
			} // iterate sources
			lines.clear();
			//pSourceFile.Release();
			msg("done: total %u line%s attached\n", totallines, totallines != 1 ? "s" : "");
			wait_box.close(); /* "Importing source lines" */
		} // !lines.empty()
		/*
		CComPtr<IDiaEnumDebugStreams> pEnumDebugStreams;
		if (SUCCEEDED(hr = pSession->getEnumDebugStreams(&pEnumDebugStreams))) {
			_ASSERTE(pEnumDebugStreams != NULL);
			if (pEnumDebugStreams != NULL) {
				// TODO: IDiaEnumDebugStreams, k èemu je to dobrý?
				pEnumDebugStreams.Release();
			}
		}
		*/
		wait_box.change("PDB plugin is waiting");
		if (!autoWait()) throw 2;
		wait_box.change("PDB plugin is running");
		if (!ix86_fix_stkframes()) throw 1;
		wait_box.change("PDB plugin is waiting");
		if (!autoWait()) throw 2;
		wait_box.change("PDB plugin is running");
		if (!functions.empty()) {
			wait_box.open("Applying function frames...");
			cmsg << log_prefix << "Loading function frames...";
			totalnames = 0;
			totaltypeinfos = 0;
			totaldata = 0;
			totalfuncs = 0;
			totaltypedefs = 0;
			CComPtr<IDiaEnumFrameData> pFrames;
			if ((hr = pTables->Item(CComVariant(L"FrameData"), &pTable)) == S_OK) {
				_ASSERTE(pTable != NULL);
#ifdef _DEBUG
				if ((hr = pTable->QueryInterface(_uuidof(IDiaEnumFrameData), (void**)&pFrames)) != S_OK) {
					_ASSERTE(!pFrames);
					pFrames = NULL;
				}
#else // _DEBUG
				hr = pTable->QueryInterface(_uuidof(IDiaEnumFrameData), (void**)&pFrames);
#endif // _DEBUG
				pTable.Release();
			}
			for (statics_t::nth_index_const_iterator<0>::type j = functions.get<0>().begin();
				j != functions.get<0>().end(); ++j) {
				if (wasBreak()) throw 1;
				ea = static_cast<ea_t>(SymBase) + j->RVA;
				if (isFunc(get_flags_novalue(ea)) && (func = get_func(ea)) != 0
					&& j->Type != NULL && GetLocalsFor(j->RVA, locals)) try {
					showAddr(ea);
					OutputDebugString("===== Setting locals for %08IX (%ls):\n",
						ea, static_cast<BSTR>(j->Name));
					CComPtr<IDiaFrameData> pFrame;
					if (pFrames != NULL) hr = pFrames->frameByRVA(j->RVA, &pFrame);
					const DiaFrame Frame(pFrame);
#ifdef _DEBUG
					if (pFrame != NULL) {
						PrintFrame(pFrame, Frame);
						const asize_t length_locals(ix86_get_frame_locals(func));
						OutputDebugString("  Frame.LengthLocals %c= ix86_get_frame_locals(...): 0x%IX %c= 0x%lX\n",
							length_locals == Frame.LengthLocals ? '=':'!', length_locals,
							length_locals == Frame.LengthLocals ? '=':'!', Frame.LengthLocals);
					}
#endif // _DEBUG
					endEA = j->Length > 0 ? ea + j->Length : BADADDR;
					const asize_t retsize = get_frame_retsize(func);
					_ASSERTE(func->frsize + func->frregs + retsize + func->argsize ==
						get_frame_size(func)); // get_struc_size(frame) may be bigger!
					adiff_t frame_sp_delta = func->frsize - (pFrame != NULL ?
						Frame.LengthLocals : ix86_get_frame_locals(func));
					if (frame_sp_delta < 0) {
						frame_sp_delta = 0;
						_RPT1(_CRT_WARN, "%s(...): suspicious frame_sp_delta (<0)\n", __FUNCTION__);
					}
					bool func_changed(false);
					/*
					if (endEA != BADADDR && func->endEA != endEA) {
						if (!func_setend(func->startEA, endEA))
							func->endEA = endEA; // force
						else
							analyze_area(*func);
						func_changed = true;
					}
					*/
					struc_t *const frame(get_frame(func));
					if (frame != 0) {
						ostringstream cmts;
						for (loc_t::const_iterator i = locals.begin(); i != locals.end(); ++i) {
							_ASSERTE(isLoaded((ea_t)SymBase + i->Block.RVA));
							if (!isLoaded((ea_t)SymBase + i->Block.RVA)) continue;
#ifdef _DEBUG
							_ASSERTE(i->Data.SymTag == SymTagData);
							OutputDebugString("  Assigning %s @@%ls [%s %s%c%IX]\n",
								i->Data.TokenizeDataKind().c_str(), static_cast<BSTR>(i->Data.Name),
								i->Data.TokenizeLocationType().c_str(), i->Data.TokenizeRegisterId(),
								SIGNED_PAIR(i->Data.Offset));
							_ASSERTE(i->Data.Type != NULL);
							if ((ea_t)SymBase + i->Block.RVA < func->startEA
								|| (ea_t)SymBase + i->Block.RVA + i->Block.Length > func->endEA) {
								_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
									"%s(...): local symbol bounding block <%08IX-%08IX> partly or fully outside function frame <%08IX-%08IX>\n",
									__FUNCTION__, (ea_t)(SymBase + i->Block.RVA), (ea_t)(SymBase + i->Block.RVA + i->Block.Length),
									func->startEA, func->endEA);
								//PrintSymbol(i->Data, i->Data);
							}
#endif // _DEBUG
							ea_t frame_offset;
							member_t *stkvar;
							flags_t flags;
							char mnem[16]; //idaname[MAXNAMESIZE];
							string idaname(i->Data.getAnsiName());
							/*
							switch (i->Data.DataKind) {
								case DataIsLocal: break;
								case DataIsParam: break;
								case DataIsObjectPtr: break;
							}
							*/
							switch (i->Data.LocationType) {
								case LocIsRegRel: {
									if ((func->flags & FUNC_FRAME) != 0
										&& (i->Data.RegisterId == CV_REG_EBP || i->Data.RegisterId == CV_REG_BP))
										frame_offset = ((func->flags & FUNC_BOTTOMBP) == 0 ?
											func->frsize : frame_sp_delta) + (ea_t)i->Data.Offset;
									else if (i->Data.RegisterId == CV_REG_ESP || i->Data.RegisterId == CV_REG_SP)
										frame_offset = frame_sp_delta + (ea_t)i->Data.Offset;
									else {
#ifdef _DEBUG
										_RPTF2(_CRT_WARN, "%s(...): local name unknown location (bp_frame?%s)\n",
											__FUNCTION__, (func->flags & FUNC_FRAME) != 0 ? "yes":"no");
#endif // _DEBUG
										break;
									}
								dolocal:
									asize_t arg_size(i->Data.Length);
									if (arg_size == 0) arg_size = get_type_size(i->Data.Type/*!!!!*/);
									stkvar = get_member_by_name(frame, idaname.c_str());
									ea_t dupeoff;
									string newname; //char newname[MAXNAMESIZE];
									uint suffix;
									if (stkvar != 0 && (dupeoff = stkvar->get_soff()) != frame_offset) {
										_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
											"%s(...): local name at %08IX conflict (size=0x%IX): old member at %08IX (size=0x%IX)\n",
											__FUNCTION__, frame_offset, arg_size, stkvar->get_soff(), get_member_size(stkvar));
										suffix = 1;
										do
											_sprintf(newname, "%s_%u", idaname.c_str(), ++suffix);
										while (get_member_by_name(frame, newname.c_str()) != 0);
										if (get_member_by_name(frame, newname.c_str()) == 0)
											set_member_name(frame, dupeoff, newname.c_str());
#ifdef _DEBUG
										else
											_RPTF1(_CRT_WARN, "%s(...): name conflict not resolved\n", __FUNCTION__);
#endif // _DEBUG
									} // name conflict
									flags = 0;
									if (i->Data.Type != NULL) {
										flags = getFlags(i->Data.Type);
										typeinfo_t ti, *pti(get_typeinfo(i->Data.Type, ti, ea));
										if (isData(flags)) {
											del_struc_members(frame, frame_offset, frame_offset + arg_size);
											func_changed = true;
											int err(add_struc_member_anyway(frame, idaname.c_str(),
												frame_offset, flags, pti, arg_size));
											if (err == 0 || (err = add_struc_member_anyway(frame,
												idaname.c_str(), frame_offset, flags = byteflag(), pti = 0, arg_size)) == 0) {
												++totalnames;
												++totaldata;
												OutputDebugString("  @@%c%08IX[%08IX]=%ls (flags=%s has_typeinfo?%s size=0x%IX)\n",
													SIGNED_PAIR(i->Data.Offset), frame_offset,
													(BSTR)i->Data.Name, flags2str(flags).c_str(),
													pti != 0 ? "yes":"no", arg_size);
											}
										}
#ifdef _DEBUG
										else
											_RPTF2(_CRT_WARN, "%s(...): not data type for arguemnt though typeinfo present (flags=%s)\n",
												__FUNCTION__, flags2str(flags).c_str());
#endif // _DEBUG
										if ((stkvar = get_member(frame, frame_offset)) != 0)
											if (set_member_ti(frame, stkvar, i->Data.Type, true)) {
												++totaltypeinfos;
												func_changed = true;
											} else try {
												typestring type;
												char cmt[MAXSTR];
												if (get_ti(i->Data.Type, type)
													&& print_type_to_one_line(CPY(cmt), idati, type) == T_NORMAL)
													set_member_cmt(stkvar, cmt, true);
											} catch (GENERAL_CATCH_FILTER) {
#ifdef _DEBUG
												_RPT2(_CRT_WARN, "%s(...): %s\n", __FUNCTION__, e.what());
												if (typeid(e) != typeid(not_convertible)) PrintSymbol(i->Data, i->Data);
#endif // _DEBUG
											}
									} // have typeinfo
									if (!isData(flags) && !idaname.empty() // don't touch the stkvar, rename only
										&& set_member_name(frame, frame_offset, idaname.c_str())) {
										++totalnames;
										func_changed = true;
									}
									break;
								} // LocIsRegRel
								case LocIsEnregistered: {
									_ASSERTE(i->Data.Offset == 0);
									if (i->Block.Length <= 0) {
										_RPTF1(_CRT_WARN, "%s(...): register variable probably not used (bounding block of zero size)\n",
											__FUNCTION__);
										break;
									}
									const RegNo reg = ix86_getReg((CV_HREG_e)i->Data.RegisterId);
									const asize_t regbits = ix86_getRegBitness((CV_HREG_e)i->Data.RegisterId) >> 3;
									// TODO: find safely load point (if any) for register parameters/local variables
									// (no hints from PDB except register name cause ambiguous assignments very often)
									/*
									if (i->Data.DataKind != DataIsParam) {
										if (add_regvar(func, (ea_t)SymBase + i->Block.RVA,
											(ea_t)SymBase + i->Block.RVA + i->Block.Length,
											i->Data.TokenizeRegisterId(), idaname.c_str(), NULL) == REGVAR_ERROR_OK) {
											++totalnames; // ???
											func_changed = true;
											_RPT3(_CRT_WARN, "%s(...): regvar created: %s=%-.3840ls (no stack storage)\n",
												__FUNCTION__, i->Data.TokenizeRegisterId(), static_cast<BSTR>(i->Data.Name));
										}
									} else { // very experimental
										typestring type;
										if (i->Data.Type != NULL) try {
											get_ti(i->Data.Type, type);
										} catch (const not_convertible &e) {
											_RPT2(_CRT_WARN, "%s(...): %s\n", __FUNCTION__, e.what());
											//PrintSymbol(i->Data, i->Data);
										}
										add_regarg(func, ix86_getReg((enum CV_HREG_e)i->Data.RegisterId), type, idaname.c_str());
										++totalnames; // ???
										_RPT4(_CRT_WARN, "%s(...): regarg created for %08IX: %s=%-.3840ls (no stack storage)\n",
											__FUNCTION__, func->startEA, i->Data.TokenizeRegisterId(), static_cast<BSTR>(i->Data.Name));
									}
									*/
									cmts << i->Data.TokenizeLocationType() << ' ' <<
										i->Data.TokenizeDataKind() << ' ' << i->Data.TokenizeRegisterId() <<
										'=' << (BSTR)i->Data.Name << " <" <<
										asea((ea_t)(SymBase + i->Block.RVA)) << '-' <<
										asea((ea_t)(SymBase + i->Block.RVA + i->Block.Length)) << '>' << endl;
									break;
								} // LocIsEnregistered
								case LocIsStatic:
									_ASSERTE(i->Data.DataKind == DataIsStaticLocal);
									ProcessStaticSymbol(i->Data, i->Data, &names);
									break;
#ifdef _DEBUG
								default:
									_RPTF3(_CRT_WARN, "%s(...): unhandled arg[%Iu] LocationType(%s)\n",
										__FUNCTION__, distance((loc_t::const_iterator)locals.begin(), i),
										i->Data.TokenizeLocationType().c_str());
									PrintSymbol(i->Data, i->Data);
#endif // _DEBUG
							} // switch LocationType
						} // enumerate local names
						if (func_changed) save_struc(frame);
						string cmt(cmts.str());
						if (!cmt.empty()) {
							cmt.erase(back_pos(cmt)); // cut last eoln
							_ASSERTE(!cmt.empty());
							set_func_cmt(func, cmt.c_str(), false);
						}
					} // got frame
#ifdef _DEBUG
					else
						_RPT2(_CRT_WARN, "%s(...): %s(func) returned NULL\n", __FUNCTION__, "get_frame");
#endif // _DEBUG
					if (j->SymTag == SymTagThunk && (func->flags & FUNC_THUNK) == 0) {
						func->flags |= FUNC_THUNK;
						update_func(func);
					}
					if (func_changed) reanalyze_function(func, func->startEA, func->endEA, true);
				} catch (GENERAL_CATCH_FILTER) {
					_RPT3(_CRT_WARN, "%s(...): %s (%s)\n", __FUNCTION__, e.what(), typeid(e).name());
				}
			} // iterate over functions
			functions.clear();
			cmsg << "done" << endl;
			msg("%sTotal %u local name%s set, %u data type%s created, %u function%s created, %u typeinfo%s set\n",
				log_prefix, totalnames, totalnames != 1 ? "s" : "",
				totaldata, totaldata != 1 ? "s" : "",
				totalfuncs, totalfuncs != 1 ? "s" : "",
				totaltypeinfos, totaltypeinfos != 1 ? "s" : "");
			wait_box.close(); /* "Applying function frames" */
		} // !functions.empty()
		pTables.Release();
#ifdef _DEBUG
		if (totaltypedefs > 0) _RPT2(_CRT_WARN, "%s(...): totaltypedefs=%u\n", __FUNCTION__, totaltypedefs);
#endif // _DEBUG
		totalnames = 0;
		if (!names.empty()) {
			wait_box.open("Applying static names...");
			cmsg << log_prefix << "Applying static names..." << endl;
			for (sym_t::const_iterator i = names.begin(); i != names.end(); ++i) {
				_ASSERTE(!i->second.empty());
				if (wasBreak()) throw 1;
				if (apply_static_name(i->first, i->second.c_str())) ++totalnames;
			}
			names.clear();
			msg("%sTotal %u global name%s set\n", log_prefix, totalnames, totalnames != 1 ? "s" : "");
			wait_box.close();
		}
		wait_box.close(); /* "PDB plugin is running" */
		exit_code = 0;
		beep();
	} catch (const int i) {
		exit_code = i;
		_RPT2(_CRT_WARN, "%s(...): integral exception %i\n", __FUNCTION__, i);
	} catch (GENERAL_CATCH_FILTER) {
		exit_code = -1;
		_RPT3(_CRT_ERROR, "%s(...): %s (%s)\n", __FUNCTION__, e.what(), typeid(e).name());
	}
	if (pSession != NULL) pSession.Release();
	reset_globals();
	wait_box.close_all();
	CoUninitialize();
	return exit_code;
} // LoadOwn()

// LoadForeign() tries to load foreign PDB file and import meaningful information
// to local idabase (this concerns everything not directly writable to
// disassembly - typeinfo, structs and enums)
static int LoadForeign() {
	HRESULT hr = CoInitialize(NULL);
	if (FAILED(hr)) {
		_RPTF3(_CRT_WARN, "%s(...): %s(NULL) returned %08lX\n", __FUNCTION__,
			"CoInitialize", hr);
		return -7;
	}
	int exit_code;
	try {
		// Initialize The Component Object Module Library
		// Obtain Access To The Provider
		CComPtr<IDiaDataSource> pSource;
		if (FAILED(hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER,
			__uuidof(IDiaDataSource), (void **)&pSource))) {
			_RPTF3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n", __FUNCTION__,
				"CoCreateInstance", hr);
			COM_Error("CoCreateInstance", hr);
			throw -6;
		}
		if (hr != S_OK) throw -6; // status unknown
		_ASSERTE(pSource != NULL);
		foreign_pdb = true;
		char input[QMAXPATH];
		get_input_file_path(CPY(input));
		char drive[_MAX_DRIVE], path[_MAX_PATH], fname[_MAX_FNAME], pdb[_MAX_PATH];
		_splitpath(input, drive, path, fname, 0);
		_makepath(pdb, drive, path, fname, "pdb");
		do {
			const char *ans = askfile_c(false, pdb, "Please specify the PDB file");
			if (ans == 0) throw -5;
			qstrcpy(pdb, ans);
		} while (!qfileexist(pdb));
		wchar_t wszFilename[_MAX_PATH];
		mbstowcs(wszFilename, pdb, qnumber(wszFilename));
		if (FAILED(hr = pSource->loadDataFromPdb(wszFilename))) {
			_RPTF3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n", __FUNCTION__,
				"IDiaDataSource::loadDataFromPdb", hr);
			COM_Error("IDiaDataSource::loadDataFromPdb", hr);
			throw -4;
		}
		if (hr != S_OK) throw -4; // status unknown
		if (FAILED(hr = pSource->openSession(&pSession))) {
			_RPTF3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n", __FUNCTION__,
				"IDiaDataSource::openSession", hr);
			COM_Error("IDiaDataSource::openSession", hr);
			throw -3;
		}
		if (hr != S_OK) throw -3;
		_ASSERTE(pSession != NULL);
		CComPtr<IDiaEnumTables> pTables;
		if (FAILED(hr = pSession->getEnumTables(&pTables))) {
			_RPT3(_CRT_WARN, "%s(...): %s(...) returned %08lX\n", __FUNCTION__,
				"IDiaSession::getEnumTables", hr);
			COM_Error("IDiaSession::getEnumTables", hr);
			throw -2;
		}
		if (hr != S_OK) throw -2; // no tables
		_ASSERTE(pTables != NULL);
		cmsg << log_prefix << "MS Debug Information Accessor is ready" << endl;
		wait_box.open("PDB plugin is running");
		load_vc_til();
		reset_globals(true);
		DiaSymbol GlobalScope;
		LoadGlobalScope(GlobalScope);
		class typesview_t : public ::typesview_t<DIA::types_t> {
		protected:
			bool IsTypeEmpty(const_reference item) const {
				switch (item.SymTag) {
					case SymTagUDT:
					case SymTagEnum:
						return DiaSymChildren(item) <= 0;
					case SymTagTypedef:
						return item.TypeId == 0 ? true : value_type(item.Type).SymTag == SymTagNull;
				}
				_RPT2(_CRT_WARN, "%s(...): unexpected SymTag value: %s\n",
					__FUNCTION__, item.TokenizeSymTag().c_str());
				return false;
			}
		} types;
		_ASSERTE(types.empty());
		ULONG celt;
		CComPtr<IDiaTable> pTable;
		CComPtr<IDiaSymbol> pSymbol;
		DiaSymbol Symbol;
		cmsg << log_prefix << "Scanning all tables...";
		wait_box.open("Scanning all tables...");
		while ((hr = pTables->Next(1, &pTable, &celt)) == S_OK) {
			_ASSERTE(celt >= 1);
			_ASSERTE(pTable != NULL);
			if (wasBreak()) throw 1;
			CDiaBSTR TableName;
			pTable->get_name(&TableName);
			_ASSERTE(TableName != NULL);
			CComPtr<IDiaEnumSymbols> pSymbols;
			if ((hr = pTable->QueryInterface(_uuidof(IDiaEnumSymbols), (void**)&pSymbols)) == S_OK) {
				_ASSERTE(pSymbols != NULL);
				wait_box.open("Loading symbols...");
				while ((hr = pSymbols->Next(1, &pSymbol, &celt)) == S_OK) {
					_ASSERTE(celt >= 1);
					_ASSERTE(pSymbol != NULL);
					if (wasBreak()) throw 1;
					Symbol(pSymbol);
					_ASSERTE(Symbol());
					if ((Symbol.SymTag == SymTagUDT || Symbol.SymTag == SymTagEnum
						|| Symbol.SymTag == SymTagTypedef) && Symbol.ClassParentId == 0)
						types.Add(Symbol);
					pSymbol.Release();
				} // enumerate symbols
				pSymbols.Release();
				wait_box.close();
			} // QueryInterface() ok (symbols)
			pTable.Release();
		} // iterate tables
		wait_box.close(); /* "Scanning all tables..." */
		cmsg << "done" << endl;
		pTables.Release();
		wait_box.close(); /* "PDB plugin is running" */
#ifdef _DEBUG
		totalnames = 0;
		totaldata = 0;
		totalfuncs = 0;
#endif // _DEBUG
		totaltypedefs = 0;
		totalstructs = 0;
		totalenums = 0;
		totaltypeinfos = 0;
		if (!types.empty()) {
			if (types.Open() && !types.empty()) {
				wait_box.open("Storing types to idabase...");
				types.SaveTypes();
				wait_box.close();
			}
			types.clear();
		}
		_ASSERTE(totalnames <= 0);
		_ASSERTE(totaldata <= 0);
		_ASSERTE(totalfuncs <= 0);
		msg("%sTotal %u struct%s, %u enum%s, %u typedef%s, %u typeinfo%s set\n",
			log_prefix, totalstructs, totalstructs != 1 ? "s" : "",
			totalenums, totalenums != 1 ? "s" : "",
			totaltypedefs, totaltypedefs != 1 ? "s" : "",
			totaltypeinfos, totaltypeinfos != 1 ? "s" : "");
		exit_code = 0;
		beep();
	} catch (const int i) {
		exit_code = i;
		_RPT2(_CRT_WARN, "%s(...): integral exception %i\n", __FUNCTION__, i);
	} catch (GENERAL_CATCH_FILTER) {
		exit_code = -1;
		_RPT3(_CRT_ERROR, "%s(...): %s (%s)\n", __FUNCTION__, e.what(), typeid(e).name());
	}
	if (pSession != NULL) pSession.Release();
	reset_globals();
	wait_box.close_all();
	CoUninitialize();
	return exit_code;
} // LoadForeign()

} // namespace DIA

#ifdef PDB_RUN_WATCHER_THREAD

static atomic_integer<BOOL> plugin_running(TRUE);

static void watchdog() {
	while (plugin_running) {
		HWND hWnd = FindWindowEx(NULL, NULL, "TMsgForm", "Warning");
		if (hWnd != NULL) SendMessage(hWnd, WM_CLOSE, 0, 0);
		_sleep(5000);
	}
}

#endif // PDB_RUN_WATCHER_THREAD

//----------------------------------------------------------------------
// Main function: do the real job here
// param==1: ida decided to call the plugin itself
// param==2: import types from foreign pdb
static void idaapi plugin_main(int param) {
	BPX;
#ifdef PDB_RUN_WATCHER_THREAD
	boost::scoped_ptr<boost::thread> watcher_thread;
	try { watcher_thread.reset(new boost::thread(watchdog)); }
		catch (GENERAL_CATCH_FILTER) { watcher_thread.reset(); }
#endif
	/*
	try {
	*/
		switch (param) {
			case 0:
			case 1:
				if (DIA::LoadOwn(param == 1) < 0/*error*/)
					ImageHlp::LoadOwn(param == 1);
				break;
			case 2:
				if (DIA::LoadForeign() < 0/*error*/) ImageHlp::LoadForeign();
				break;
			default:
				warning("%s%i: unsupported parameter", log_prefix, param);
		}
	/*
	} catch (const exception &e) {
		cmsg << log_prefix << "too bad: uncaught exception (" << e.what() << ") at " <<
			__FUNCTION__ << ": lame stoopid servil" << endl;
		warning("too bad: uncaught exception (%s) at %s: lame stoopid servil",
			e.what(), __FUNCTION__);
	} catch(...) {
		cmsg << log_prefix << "too bad: uncaught unknown exception at " <<
			__FUNCTION__ << ": lame stoopid servil" << endl;
		warning("too bad: uncaught unknown exception at %s: lame stoopid servil",
			__FUNCTION__);
	}
	*/
#ifdef PDB_RUN_WATCHER_THREAD
	plugin_running = FALSE;
	if (watcher_thread) watcher_thread->join();
#endif
}

static int idaapi init(void) {
  const char *opts = get_plugin_options("pdb");
  if ( opts != NULL && _stricmp(opts, "off") == 0 ) return PLUGIN_SKIP;
	// only accept if current processor can be found within Windows machine types
	// if you are using an exotic archiecture, update phid2mt with
	// IMAGE_FILE_MACHINE_XXX equivalent to your processor
	return phid2mt() != IMAGE_FILE_MACHINE_UNKNOWN ? PLUGIN_OK : PLUGIN_SKIP;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		hInstance = hinstDLL;
		DisableThreadLibraryCalls((HMODULE)hinstDLL);
		se_exception::_set_se_translator();
		_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
		_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#if defined(_DEBUG) && defined(NMBC)
		NMMemMark();
	} else if (fdwReason == DLL_PROCESS_DETACH) {
		NMMemSave(__FILE__ ".leaks", "BoundsChecker", 0);
		NMMemPopup();
#endif // _DEBUG && NMBC
	}
	return TRUE;
}

static bool is_far_call(DWORD CallConv) {
	return CallConv == CV_CALL_FAR_C || CallConv == CV_CALL_FAR_STD
		|| CallConv == CV_CALL_FAR_FAST || CallConv == CV_CALL_FAR_PASCAL
		|| CallConv == CV_CALL_FAR_SYS;
}

static string TokenizeSymTag(enum SymTagEnum SymTag) {
	switch (SymTag) {
#define TOKENIZE(x) case SymTag##x: return #x;
		TOKENIZE(Null)
		TOKENIZE(Exe)
		TOKENIZE(Compiland)
		TOKENIZE(CompilandDetails)
		TOKENIZE(CompilandEnv)
		TOKENIZE(Function)
		TOKENIZE(Block)
		TOKENIZE(Data)
		TOKENIZE(Annotation)
		TOKENIZE(Label)
		TOKENIZE(PublicSymbol)
		TOKENIZE(UDT)
		TOKENIZE(Enum)
		TOKENIZE(FunctionType)
		TOKENIZE(PointerType)
		TOKENIZE(ArrayType)
		TOKENIZE(BaseType)
		TOKENIZE(Typedef)
		TOKENIZE(BaseClass)
		TOKENIZE(Friend)
		TOKENIZE(FunctionArgType)
		TOKENIZE(FuncDebugStart)
		TOKENIZE(FuncDebugEnd)
		TOKENIZE(UsingNamespace)
		TOKENIZE(VTableShape)
		TOKENIZE(VTable)
		TOKENIZE(Custom)
		TOKENIZE(Thunk)
		TOKENIZE(CustomType)
		TOKENIZE(ManagedType)
		TOKENIZE(Dimension)
	}
	return _sprintf("0x%X", SymTag);
}

static string TokenizeSymFlag(ULONG Flags) {
	string result;
	if ((Flags & SYMFLAG_VALUEPRESENT) != 0) result += "VALUEPRESENT|";
	if ((Flags & SYMFLAG_REGISTER) != 0) result += "REGISTER|";
	if ((Flags & SYMFLAG_REGREL) != 0) result += "REGREL|";
	if ((Flags & SYMFLAG_FRAMEREL) != 0) result += "FRAMEREL|";
	if ((Flags & SYMFLAG_PARAMETER) != 0) result += "PARAMETER|";
	if ((Flags & SYMFLAG_LOCAL) != 0) result += "LOCAL|";
	if ((Flags & SYMFLAG_CONSTANT) != 0) result += "CONSTANT|";
	if ((Flags & SYMFLAG_EXPORT) != 0) result += "EXPORT|";
	if ((Flags & SYMFLAG_FORWARDER) != 0) result += "FORWARDER|";
	if ((Flags & SYMFLAG_FUNCTION) != 0) result += "FUNCTION|";
	if ((Flags & SYMFLAG_VIRTUAL) != 0) result += "VIRTUAL|";
	if ((Flags & SYMFLAG_THUNK) != 0) result += "THUNK|";
	if ((Flags & SYMFLAG_TLSREL) != 0) result += "TLSREL|";
	if ((Flags & SYMFLAG_SLOT) != 0) result += "SLOT|";
	if ((Flags & SYMFLAG_ILREL) != 0) result += "ILREL|";
	if ((Flags & SYMFLAG_METADATA) != 0) result += "METADATA|";
	if ((Flags & SYMFLAG_CLR_TOKEN) != 0) result += "CLR_TOKEN|";
	if (!result.empty()) result.erase(back_pos(result));
	return result;
}

static WORD phid2mt() {
	switch (ph.id) {
		case PLFM_386: return IMAGE_FILE_MACHINE_I386; // Intel 80x86
		case PLFM_IA64: return IMAGE_FILE_MACHINE_IA64; // Intel Itanium IA64
// 			IMAGE_FILE_MACHINE_AMD64        // AMD64 (K8)
		case PLFM_ALPHA: return IMAGE_FILE_MACHINE_ALPHA; // DEC Alpha
// 			IMAGE_FILE_MACHINE_ALPHA64      // ALPHA64
		case PLFM_ARM: return IMAGE_FILE_MACHINE_ARM; // Advanced RISC Machines
		case PLFM_M32R: return IMAGE_FILE_MACHINE_M32R; // Mitsubishi 32bit RISC little-endian
		case PLFM_MIPS: return IMAGE_FILE_MACHINE_MIPS16/*???*/; // MIPS
// 			IMAGE_FILE_MACHINE_MIPSFPU      // MIPS
// 			IMAGE_FILE_MACHINE_MIPSFPU16    // MIPS
// 			IMAGE_FILE_MACHINE_R10000       // MIPS little-endian
// 			IMAGE_FILE_MACHINE_R3000        // MIPS little-endian, 0x160 big-endian
// 			IMAGE_FILE_MACHINE_R4000        // MIPS little-endian
		case PLFM_PPC: return IMAGE_FILE_MACHINE_POWERPC; // IBM PowerPC Little-Endian
// 			IMAGE_FILE_MACHINE_POWERPCFP
		case PLFM_TRICORE: return IMAGE_FILE_MACHINE_TRICORE; // Tasking Tricore (Infineon?)
    case PLFM_SH/*Hitachi SH*/: return IMAGE_FILE_MACHINE_SH3/*SH3 little-endian*/;
// 			IMAGE_FILE_MACHINE_SH3DSP
// 			IMAGE_FILE_MACHINE_SH3E         // SH3E little-endian
// 			IMAGE_FILE_MACHINE_SH4          // SH4 little-endian
// 			IMAGE_FILE_MACHINE_SH5          // SH5
		/*
    case PLFM_6502: return IMAGE_FILE_MACHINE_6502; // 6502
    case PLFM_6800: return IMAGE_FILE_MACHINE_6800; // Motorola 68xx
    case PLFM_68K: return IMAGE_FILE_MACHINE_68K; // Motorola 680x0
    case PLFM_80196: return IMAGE_FILE_MACHINE_80196; // Intel 80196
    case PLFM_8051: return IMAGE_FILE_MACHINE_8051; // 8051
    case PLFM_AD218X: return IMAGE_FILE_MACHINE_AD218X; // Analog Devices ADSP 218X
    case PLFM_AVR: return IMAGE_FILE_MACHINE_AVR; // Atmel 8-bit RISC processor(s)
    case PLFM_C166: return IMAGE_FILE_MACHINE_C166; // Siemens C166 family
    case PLFM_C39: return IMAGE_FILE_MACHINE_C39; // Rockwell C39
    case PLFM_CR16: return IMAGE_FILE_MACHINE_CR16; // NSC CR16
    case PLFM_DSP56K: return IMAGE_FILE_MACHINE_DSP56K; // Motorola DSP5600x
    case PLFM_F2MC: return IMAGE_FILE_MACHINE_F2MC; // Fujistu F2MC-16
    case PLFM_FR: return IMAGE_FILE_MACHINE_FR; // Fujitsu FR Family
    case PLFM_H8500: return IMAGE_FILE_MACHINE_H8500; // Hitachi H8/500
    case PLFM_H8: return IMAGE_FILE_MACHINE_H8; // Hitachi H8/300, H8/2000
    case PLFM_HPPA: return IMAGE_FILE_MACHINE_HPPA; // Hewlett-Packard PA-RISC
    case PLFM_I860: return IMAGE_FILE_MACHINE_I860; // Intel 860
    case PLFM_I960: return IMAGE_FILE_MACHINE_I960; // Intel 960
    case PLFM_JAVA: return IMAGE_FILE_MACHINE_JAVA; // Java
    case PLFM_KR1878: return IMAGE_FILE_MACHINE_KR1878; // Angstrem KR1878
    case PLFM_M740: return IMAGE_FILE_MACHINE_M740; // Mitsubishi 8bit
    case PLFM_M7700: return IMAGE_FILE_MACHINE_M7700; // Mitsubishi 16bit
    case PLFM_M7900: return IMAGE_FILE_MACHINE_M7900; // Mitsubishi 7900
    case PLFM_MC6812: return IMAGE_FILE_MACHINE_MC6812; // Motorola 68HC12
    case PLFM_MC6816: return IMAGE_FILE_MACHINE_MC6816; // Motorola 68HC16
    case PLFM_MN102L00: return IMAGE_FILE_MACHINE_MN102L00; // Panasonic MN10200
    case PLFM_NEC_78K0: return IMAGE_FILE_MACHINE_NEC_78K0; // NEC 78K0
    case PLFM_NEC_78K0S: return IMAGE_FILE_MACHINE_NEC_78K0S; // NEC 78K0S
    case PLFM_NET: return IMAGE_FILE_MACHINE_NET; // Microsoft Visual Studio.Net
    case PLFM_OAKDSP: return IMAGE_FILE_MACHINE_OAKDSP; // Atmel OAK DSP
    case PLFM_PDP: return IMAGE_FILE_MACHINE_PDP; // PDP11
    case PLFM_PIC: return IMAGE_FILE_MACHINE_PIC; // Microchip's PIC
    case PLFM_SPARC: return IMAGE_FILE_MACHINE_SPARC; // SPARC
    case PLFM_ST20: return IMAGE_FILE_MACHINE_ST20; // SGS-Thomson ST20
    case PLFM_ST7: return IMAGE_FILE_MACHINE_ST7; // SGS-Thomson ST7
    case PLFM_ST9: return IMAGE_FILE_MACHINE_ST9; // ST9+
    case PLFM_TLCS900: return IMAGE_FILE_MACHINE_TLCS900; // Toshiba TLCS-900
    case PLFM_TMS320C1X: return IMAGE_FILE_MACHINE_TMS320C1X; // Texas Instruments TMS320C1x
    case PLFM_TMS320C3: return IMAGE_FILE_MACHINE_TMS320C3; // Texas Instruments TMS320C3
    case PLFM_TMS320C54: return IMAGE_FILE_MACHINE_TMS320C54; // Texas Instruments TMS320C54xx
    case PLFM_TMS320C55: return IMAGE_FILE_MACHINE_TMS320C55; // Texas Instruments TMS320C55xx
    case PLFM_TMS: return IMAGE_FILE_MACHINE_TMS; // Texas Instruments TMS320C5x
    case PLFM_TMSC6: return IMAGE_FILE_MACHINE_TMSC6; // Texas Instruments TMS320C6x
    case PLFM_TRIMEDIA: return IMAGE_FILE_MACHINE_TRIMEDIA; // Trimedia
    case PLFM_Z80: return IMAGE_FILE_MACHINE_Z80; // 8085, Z80
    case PLFM_Z8: return IMAGE_FILE_MACHINE_Z8; // Z8
    */
	} // switch id
	return IMAGE_FILE_MACHINE_UNKNOWN;
}

static ULONGLONG VarToUI64(const VARIANT &var) {
	switch (var.vt) {
		case VT_I1: return var.cVal;
		case VT_I2: return var.iVal;
		case VT_I4: return var.lVal;
		case VT_I8: return var.llVal;
		case VT_INT: return var.intVal;
		case VT_UI1: return var.bVal;
		case VT_UI2: return var.uiVal;
		case VT_UI4: return var.ulVal;
		case VT_UI8: return var.ullVal;
		case VT_UINT: return var.uintVal;
	} // main switch
	_RPT3(_CRT_WARN, "%s(...): variant type %u(%s) not convertible to integral type\n",
		__FUNCTION__, var.vt, TokenizeVarType(var.vt));
	return 0;
}

// map CV_HREG_e to IDA pc.w32 representation (ix86 only)
static RegNo ix86_getReg(CV_HREG_e Register) {
	if (ph.id == PLFM_386) switch (Register) {
		// 8-bit
		case CV_REG_AL: return R_al;
		case CV_REG_CL: return R_cl;
		case CV_REG_DL: return R_dl;
		case CV_REG_BL: return R_bl;
		case CV_REG_AH: return R_ah;
		case CV_REG_CH: return R_ch;
		case CV_REG_DH: return R_dh;
		case CV_REG_BH: return R_bh;
		// 16-bit
		case CV_REG_AX: case CV_REG_EAX: return R_ax;
		case CV_REG_CX: case CV_REG_ECX: return R_cx;
		case CV_REG_DX: case CV_REG_EDX: return R_dx;
		case CV_REG_BX: case CV_REG_EBX: return R_bx;
		case CV_REG_SP: case CV_REG_ESP: return R_sp;
		case CV_REG_BP: case CV_REG_EBP: return R_bp;
		case CV_REG_SI: case CV_REG_ESI: return R_si;
		case CV_REG_DI: case CV_REG_EDI: return R_di;
		// segment registers
		case CV_REG_ES: return R_es;
		case CV_REG_CS: return R_cs;
		case CV_REG_DS: return R_ds;
		case CV_REG_SS: return R_ss;
		case CV_REG_FS: return R_fs;
		case CV_REG_GS: return R_gs;
		// instruction pointer
		case CV_REG_IP: case CV_REG_EIP: return R_ip;
		// AMD 64-bit
		case CV_AMD64_SIL: return R_sil;
		case CV_AMD64_DIL: return R_dil;
		case CV_AMD64_BPL: return R_bpl;
		case CV_AMD64_SPL: return R_spl;
		// AMD 64-bit
		case CV_AMD64_R8: return R_r8;
		case CV_AMD64_R9: return R_r9;
		case CV_AMD64_R10: return R_r10;
		case CV_AMD64_R11: return R_r11;
		case CV_AMD64_R12: return R_r12;
		case CV_AMD64_R13: return R_r13;
		case CV_AMD64_R14: return R_r14;
		case CV_AMD64_R15: return R_r15;
#ifdef _DEBUG
		case CV_REG_NONE: break;
		default:
			_RPT2(_CRT_WARN, "%s(...): cannot map nonstandard register id=%d\n",
				__FUNCTION__, Register);
#endif // _DEBUG
	} // switch
	return R_none;
}

static size_t ix86_getRegBitness(CV_HREG_e Register) {
	switch (ph.id) {
		case PLFM_386:
			if (Register >= CV_REG_AL && Register <= CV_REG_BH
				|| Register >= CV_AMD64_R8B && Register <= CV_AMD64_R15B)
				return 8;
			else if (Register >= CV_REG_AX && Register <= CV_REG_DI
				|| Register >= CV_REG_ES && Register <= CV_REG_IP
				|| Register >= CV_AMD64_R8W && Register <= CV_AMD64_R15W)
				return 16;
			else if (Register >= CV_REG_EAX && Register <= CV_REG_EDI
				|| Register == CV_REG_EIP || Register == CV_REG_FLAGS || Register == CV_REG_EFLAGS
				|| Register >= CV_REG_CR0 && Register <= CV_REG_DR7
				|| Register >= CV_AMD64_R8D && Register <= CV_AMD64_R15D)
				return 32;
			else if (Register >= CV_AMD64_RAX && Register <= CV_AMD64_RSP
				|| Register >= CV_AMD64_R8 && Register <= CV_AMD64_R15)
				return 64;
#ifdef _DEBUG
			else
				_RPT2(_CRT_WARN, "%s(...): cannot determine size of register id=%d\n",
					__FUNCTION__, Register);
#endif // _DEBUG
			break;
#ifdef _DEBUG
		default:
			_RPT2(_CRT_WARN, "%s(...): unsupported processor id=%i\n", __FUNCTION__, ph.id);
#endif // _DEBUG
	}
	return 0;
}

static string TokenizeLocationType(enum LocationType LocType) {
	switch (LocType) {
#define TOKENIZE(x) case LocIs##x: return #x;
		TOKENIZE(Null)
		TOKENIZE(Static)
		TOKENIZE(TLS)
		TOKENIZE(RegRel)
		TOKENIZE(ThisRel)
		TOKENIZE(Enregistered)
		TOKENIZE(BitField)
		TOKENIZE(Slot)
		TOKENIZE(IlRel)
		case LocInMetaData: return "InMetaData";
		TOKENIZE(Constant)
	}
	return _sprintf("0x%X", LocType);
}

static const char *ix86_getRegCanon(enum CV_HREG_e Register) {
	switch (Register) {
		case CV_REG_NONE: return "<none>";
		case CV_REG_AL: return "al";
		case CV_REG_CL: return "cl";
		case CV_REG_DL: return "dl";
		case CV_REG_BL: return "bl";
		case CV_REG_AH: return "ah";
		case CV_REG_CH: return "ch";
		case CV_REG_DH: return "dh";
		case CV_REG_BH: return "bh";
		case CV_REG_AX: return "ax";
		case CV_REG_CX: return "cx";
		case CV_REG_DX: return "dx";
		case CV_REG_BX: return "bx";
		case CV_REG_SP: return "sp";
		case CV_REG_BP: return "bp";
		case CV_REG_SI: return "si";
		case CV_REG_DI: return "di";
		case CV_REG_EAX: return "eax";
		case CV_REG_ECX: return "ecx";
		case CV_REG_EDX: return "edx";
		case CV_REG_EBX: return "ebx";
		case CV_REG_ESP: return "esp";
		case CV_REG_EBP: return "ebp";
		case CV_REG_ESI: return "esi";
		case CV_REG_EDI: return "edi";
		case CV_REG_ES: return "es";
		case CV_REG_CS: return "cs";
		case CV_REG_SS: return "ss";
		case CV_REG_DS: return "ds";
		case CV_REG_FS: return "fs";
		case CV_REG_GS: return "gs";
		case CV_REG_IP: return "ip";
		case CV_REG_FLAGS: return "flags";
		case CV_REG_EIP: return "eip";
		case CV_REG_EFLAGS: return "eflags";
		case CV_REG_TEMP: return "temp";
		case CV_REG_TEMPH: return "temph";
		case CV_REG_QUOTE: return "quote";
		case CV_REG_PCDR3: return "pcdr(3)";
		case CV_REG_PCDR4: return "pcdr(4)";
		case CV_REG_PCDR5: return "pcdr(5)";
		case CV_REG_PCDR6: return "pcdr(6)";
		case CV_REG_PCDR7: return "pcdr(7)";
		case CV_REG_CR0: return "cr(0)";
		case CV_REG_CR1: return "cr(1)";
		case CV_REG_CR2: return "cr(2)";
		case CV_REG_CR3: return "cr(3)";
		case CV_REG_CR4: return "cr(4)";
		case CV_REG_DR0: return "dr(0)";
		case CV_REG_DR1: return "dr(1)";
		case CV_REG_DR2: return "dr(2)";
		case CV_REG_DR3: return "dr(3)";
		case CV_REG_DR4: return "dr(4)";
		case CV_REG_DR5: return "dr(5)";
		case CV_REG_DR6: return "dr(6)";
		case CV_REG_DR7: return "dr(7)";
		case CV_AMD64_DR8: return "dr(8)";
		case CV_AMD64_DR9: return "dr(9)";
		case CV_AMD64_DR10: return "dr(10)";
		case CV_AMD64_DR11: return "dr(11)";
		case CV_AMD64_DR12: return "dr(12)";
		case CV_AMD64_DR13: return "dr(13)";
		case CV_AMD64_DR14: return "dr(14)";
		case CV_AMD64_DR15: return "dr(15)";
		case CV_REG_GDTR: return "gdtr";
		case CV_REG_GDTL: return "gdtl";
		case CV_REG_IDTR: return "idtr";
		case CV_REG_IDTL: return "idtl";
		case CV_REG_LDTR: return "ldtr";
		case CV_REG_TR: return "tr";
		case CV_REG_PSEUDO1: return "pseudo(1)";
		case CV_REG_PSEUDO2: return "pseudo(2)";
		case CV_REG_PSEUDO3: return "pseudo(3)";
		case CV_REG_PSEUDO4: return "pseudo(4)";
		case CV_REG_PSEUDO5: return "pseudo(5)";
		case CV_REG_PSEUDO6: return "pseudo(6)";
		case CV_REG_PSEUDO7: return "pseudo(7)";
		case CV_REG_PSEUDO8: return "pseudo(8)";
		case CV_REG_PSEUDO9: return "pseudo(9)";
		case CV_REG_ST0: return "st(0)";
		case CV_REG_ST1: return "st(1)";
		case CV_REG_ST2: return "st(2)";
		case CV_REG_ST3: return "st(3)";
		case CV_REG_ST4: return "st(4)";
		case CV_REG_ST5: return "st(5)";
		case CV_REG_ST6: return "st(6)";
		case CV_REG_ST7: return "st(7)";
		case CV_REG_CTRL: return "ctrl";
		case CV_REG_STAT: return "stat";
		case CV_REG_TAG: return "tag";
		case CV_REG_FPIP: return "fpip";
		case CV_REG_FPCS: return "fpcs";
		case CV_REG_FPDO: return "fpdo";
		case CV_REG_FPDS: return "fpds";
		case CV_REG_ISEM: return "isem";
		case CV_REG_FPEIP: return "fpeip";
		case CV_REG_FPEDO: return "fpedo";
		case CV_REG_MM0: return "mm(0)";
		case CV_REG_MM1: return "mm(1)";
		case CV_REG_MM2: return "mm(2)";
		case CV_REG_MM3: return "mm(3)";
		case CV_REG_MM4: return "mm(4)";
		case CV_REG_MM5: return "mm(5)";
		case CV_REG_MM6: return "mm(6)";
		case CV_REG_MM7: return "mm(7)";
		case CV_REG_XMM0: return "xmm(0)";
		case CV_REG_XMM1: return "xmm(1)";
		case CV_REG_XMM2: return "xmm(2)";
		case CV_REG_XMM3: return "xmm(3)";
		case CV_REG_XMM4: return "xmm(4)";
		case CV_REG_XMM5: return "xmm(5)";
		case CV_REG_XMM6: return "xmm(6)";
		case CV_REG_XMM7: return "xmm(7)";
		case CV_REG_XMM00: return "xmm(0)";
		case CV_REG_XMM01: return "xmm(1)";
		case CV_REG_XMM02: return "xmm(2)";
		case CV_REG_XMM03: return "xmm(3)";
		case CV_REG_XMM10: return "xmm(10)";
		case CV_REG_XMM11: return "xmm(11)";
		case CV_REG_XMM12: return "xmm(12)";
		case CV_REG_XMM13: return "xmm(13)";
		case CV_REG_XMM20: return "xmm(20)";
		case CV_REG_XMM21: return "xmm(21)";
		case CV_REG_XMM22: return "xmm(22)";
		case CV_REG_XMM23: return "xmm(23)";
		case CV_REG_XMM30: return "xmm(30)";
		case CV_REG_XMM31: return "xmm(31)";
		case CV_REG_XMM32: return "xmm(32)";
		case CV_REG_XMM33: return "xmm(33)";
		case CV_REG_XMM40: return "xmm(40)";
		case CV_REG_XMM41: return "xmm(41)";
		case CV_REG_XMM42: return "xmm(42)";
		case CV_REG_XMM43: return "xmm(43)";
		case CV_REG_XMM50: return "xmm(50)";
		case CV_REG_XMM51: return "xmm(51)";
		case CV_REG_XMM52: return "xmm(52)";
		case CV_REG_XMM53: return "xmm(53)";
		case CV_REG_XMM60: return "xmm(60)";
		case CV_REG_XMM61: return "xmm(61)";
		case CV_REG_XMM62: return "xmm(62)";
		case CV_REG_XMM63: return "xmm(63)";
		case CV_REG_XMM70: return "xmm(70)";
		case CV_REG_XMM71: return "xmm(71)";
		case CV_REG_XMM72: return "xmm(72)";
		case CV_REG_XMM73: return "xmm(73)";
		case CV_REG_XMM0L: return "xmm(0l)";
		case CV_REG_XMM1L: return "xmm(1l)";
		case CV_REG_XMM2L: return "xmm(2l)";
		case CV_REG_XMM3L: return "xmm(3l)";
		case CV_REG_XMM4L: return "xmm(4l)";
		case CV_REG_XMM5L: return "xmm(5l)";
		case CV_REG_XMM6L: return "xmm(6l)";
		case CV_REG_XMM7L: return "xmm(7l)";
		case CV_REG_XMM0H: return "xmm(0h)";
		case CV_REG_XMM1H: return "xmm(1h)";
		case CV_REG_XMM2H: return "xmm(2h)";
		case CV_REG_XMM3H: return "xmm(3h)";
		case CV_REG_XMM4H: return "xmm(4h)";
		case CV_REG_XMM5H: return "xmm(5h)";
		case CV_REG_XMM6H: return "xmm(6h)";
		case CV_REG_XMM7H: return "xmm(7h)";
		case CV_REG_MXCSR: return "mxcsr";
		case CV_REG_EDXEAX: return "edx:eax"; // ???
		case CV_REG_EMM0L: return "emm(0l)";
		case CV_REG_EMM1L: return "emm(1l)";
		case CV_REG_EMM2L: return "emm(2l)";
		case CV_REG_EMM3L: return "emm(3l)";
		case CV_REG_EMM4L: return "emm(4l)";
		case CV_REG_EMM5L: return "emm(5l)";
		case CV_REG_EMM6L: return "emm(6l)";
		case CV_REG_EMM7L: return "emm(7l)";
		case CV_REG_EMM0H: return "emm(0h)";
		case CV_REG_EMM1H: return "emm(1h)";
		case CV_REG_EMM2H: return "emm(2h)";
		case CV_REG_EMM3H: return "emm(3h)";
		case CV_REG_EMM4H: return "emm(4h)";
		case CV_REG_EMM5H: return "emm(5h)";
		case CV_REG_EMM6H: return "emm(6h)";
		case CV_REG_EMM7H: return "emm(7h)";
		case CV_REG_MM00: return "mm(0)";
		case CV_REG_MM01: return "mm(1)";
		case CV_REG_MM10: return "mm(10)";
		case CV_REG_MM11: return "mm(11)";
		case CV_REG_MM20: return "mm(20)";
		case CV_REG_MM21: return "mm(21)";
		case CV_REG_MM30: return "mm(30)";
		case CV_REG_MM31: return "mm(31)";
		case CV_REG_MM40: return "mm(40)";
		case CV_REG_MM41: return "mm(41)";
		case CV_REG_MM50: return "mm(50)";
		case CV_REG_MM51: return "mm(51)";
		case CV_REG_MM60: return "mm(60)";
		case CV_REG_MM61: return "mm(61)";
		case CV_REG_MM70: return "mm(70)";
		case CV_REG_MM71: return "mm(71)";
		// Extended KATMAI registers
		case CV_AMD64_XMM8: return "xmm(8)";
		case CV_AMD64_XMM9: return "xmm(9)";
		case CV_AMD64_XMM10: return "xmm(10)";
		case CV_AMD64_XMM11: return "xmm(11)";
		case CV_AMD64_XMM12: return "xmm(12)";
		case CV_AMD64_XMM13: return "xmm(13)";
		case CV_AMD64_XMM14: return "xmm(14)";
		case CV_AMD64_XMM15: return "xmm(15)";
		case CV_AMD64_XMM8_0: return "xmm(8_0)";
		case CV_AMD64_XMM8_1: return "xmm(8_1)";
		case CV_AMD64_XMM8_2: return "xmm(8_2)";
		case CV_AMD64_XMM8_3: return "xmm(8_3)";
		case CV_AMD64_XMM9_0: return "xmm(9_0)";
		case CV_AMD64_XMM9_1: return "xmm(9_1)";
		case CV_AMD64_XMM9_2: return "xmm(9_2)";
		case CV_AMD64_XMM9_3: return "xmm(9_3)";
		case CV_AMD64_XMM10_0: return "xmm(10_0)";
		case CV_AMD64_XMM10_1: return "xmm(10_1)";
		case CV_AMD64_XMM10_2: return "xmm(10_2)";
		case CV_AMD64_XMM10_3: return "xmm(10_3)";
		case CV_AMD64_XMM11_0: return "xmm(11_0)";
		case CV_AMD64_XMM11_1: return "xmm(11_1)";
		case CV_AMD64_XMM11_2: return "xmm(11_2)";
		case CV_AMD64_XMM11_3: return "xmm(11_3)";
		case CV_AMD64_XMM12_0: return "xmm(12_0)";
		case CV_AMD64_XMM12_1: return "xmm(12_1)";
		case CV_AMD64_XMM12_2: return "xmm(12_2)";
		case CV_AMD64_XMM12_3: return "xmm(12_3)";
		case CV_AMD64_XMM13_0: return "xmm(13_0)";
		case CV_AMD64_XMM13_1: return "xmm(13_1)";
		case CV_AMD64_XMM13_2: return "xmm(13_2)";
		case CV_AMD64_XMM13_3: return "xmm(13_3)";
		case CV_AMD64_XMM14_0: return "xmm(14_0)";
		case CV_AMD64_XMM14_1: return "xmm(14_1)";
		case CV_AMD64_XMM14_2: return "xmm(14_2)";
		case CV_AMD64_XMM14_3: return "xmm(14_3)";
		case CV_AMD64_XMM15_0: return "xmm(15_0)";
		case CV_AMD64_XMM15_1: return "xmm(15_1)";
		case CV_AMD64_XMM15_2: return "xmm(15_2)";
		case CV_AMD64_XMM15_3: return "xmm(15_3)";
		case CV_AMD64_XMM8L: return "xmm(8l)";
		case CV_AMD64_XMM9L: return "xmm(9l)";
		case CV_AMD64_XMM10L: return "xmm(10l)";
		case CV_AMD64_XMM11L: return "xmm(11l)";
		case CV_AMD64_XMM12L: return "xmm(12l)";
		case CV_AMD64_XMM13L: return "xmm(13l)";
		case CV_AMD64_XMM14L: return "xmm(14l)";
		case CV_AMD64_XMM15L: return "xmm(15l)";
		case CV_AMD64_XMM8H: return "xmm(8h)";
		case CV_AMD64_XMM9H: return "xmm(9h)";
		//case CV_AMD64_XMM10H: return "xmm(10h)";
		case CV_AMD64_XMM11H: return "xmm(11h)";
		case CV_AMD64_XMM12H: return "xmm(12h)";
		case CV_AMD64_XMM13H: return "xmm(13h)";
		case CV_AMD64_XMM14H: return "xmm(14h)";
		case CV_AMD64_XMM15H: return "xmm(15h)";
		case CV_AMD64_EMM8L: return "emm(8l)";
		case CV_AMD64_EMM9L: return "emm(9l)";
		case CV_AMD64_EMM10L: return "emm(10l)";
		case CV_AMD64_EMM11L: return "emm(11l)";
		case CV_AMD64_EMM12L: return "emm(12l)";
		case CV_AMD64_EMM13L: return "emm(13l)";
		case CV_AMD64_EMM14L: return "emm(14l)";
		case CV_AMD64_EMM15L: return "emm(15l)";
		case CV_AMD64_EMM8H: return "emm(8h)";
		case CV_AMD64_EMM9H: return "emm(9h)";
		case CV_AMD64_EMM10H: return "emm(10h)";
		case CV_AMD64_EMM11H: return "emm(11h)";
		case CV_AMD64_EMM12H: return "emm(12h)";
		case CV_AMD64_EMM13H: return "emm(13h)";
		case CV_AMD64_EMM14H: return "emm(14h)";
		case CV_AMD64_EMM15H: return "emm(15h)";
		case CV_AMD64_SIL: return "sil";
		case CV_AMD64_DIL: return "dil";
		case CV_AMD64_BPL: return "bpl";
		case CV_AMD64_SPL: return "spl";
		case CV_AMD64_RAX: return "rax";
		case CV_AMD64_RBX: return "rbx";
		case CV_AMD64_RCX: return "rcx";
		case CV_AMD64_RDX: return "rdx";
		case CV_AMD64_RSI: return "rsi";
		case CV_AMD64_RDI: return "rdi";
		case CV_AMD64_RBP: return "rbp";
		case CV_AMD64_RSP: return "rsp";
		case CV_AMD64_R8: return "r(8)";
		case CV_AMD64_R9: return "r(9)";
		case CV_AMD64_R10: return "r(10)";
		case CV_AMD64_R11: return "r(11)";
		case CV_AMD64_R12: return "r(12)";
		case CV_AMD64_R13: return "r(13)";
		case CV_AMD64_R14: return "r(14)";
		case CV_AMD64_R15: return "r(15)";
		case CV_AMD64_R8B: return "r(8b)";
		case CV_AMD64_R9B: return "r(9b)";
		case CV_AMD64_R10B: return "r(10b)";
		case CV_AMD64_R11B: return "r(11b)";
		case CV_AMD64_R12B: return "r(12b)";
		case CV_AMD64_R13B: return "r(13b)";
		case CV_AMD64_R14B: return "r(14b)";
		case CV_AMD64_R15B: return "r(15b)";
		case CV_AMD64_R8W: return "r(8w)";
		case CV_AMD64_R9W: return "r(9w)";
		case CV_AMD64_R10W: return "r(10w)";
		case CV_AMD64_R11W: return "r(11w)";
		case CV_AMD64_R12W: return "r(12w)";
		case CV_AMD64_R13W: return "r(13w)";
		case CV_AMD64_R14W: return "r(14w)";
		case CV_AMD64_R15W: return "r(15w)";
		case CV_AMD64_R8D: return "r(8d)";
		case CV_AMD64_R9D: return "r(9d)";
		case CV_AMD64_R10D: return "r(10d)";
		case CV_AMD64_R11D: return "r(11d)";
		case CV_AMD64_R12D: return "r(12d)";
		case CV_AMD64_R13D: return "r(13d)";
		case CV_AMD64_R14D: return "r(14d)";
		case CV_AMD64_R15D: return "r(15d)";
#ifdef _DEBUG
		default:
			_RPT2(_CRT_WARN, "%s(...): cannot canonize nonstandard register id=%d\n",
				__FUNCTION__, Register);
#endif // _DEBUG
	}
	return 0;
}

static string TokenizeDataKind(enum DataKind DataKind) {
	switch (DataKind) {
#define TOKENIZE(x) case DataIs##x: return #x;
		TOKENIZE(Unknown)
		TOKENIZE(Local)
		TOKENIZE(StaticLocal)
		TOKENIZE(Param)
		TOKENIZE(ObjectPtr)
		TOKENIZE(FileStatic)
		TOKENIZE(Global)
		TOKENIZE(Member)
		TOKENIZE(StaticMember)
		TOKENIZE(Constant)
	}
	return _sprintf("0x%X", DataKind);
}

static string TokenizeBasicType(enum BasicType BaseType) {
	switch (BaseType) {
#define TOKENIZE(x) case bt##x: return #x;
		TOKENIZE(NoType)
		TOKENIZE(Void)
		TOKENIZE(Int) TOKENIZE(UInt)
		TOKENIZE(Long) TOKENIZE(ULong)
		TOKENIZE(Float)
		TOKENIZE(Char) TOKENIZE(WChar)
		TOKENIZE(Bool)
		TOKENIZE(BCD) TOKENIZE(Currency) TOKENIZE(Date) TOKENIZE(Variant)
		TOKENIZE(Complex) TOKENIZE(Bit) TOKENIZE(BSTR)
		case btHresult: return "HRESULT";
	}
	return _sprintf("0x%X", BaseType);
}

static string TokenizeUDTKind(enum UdtKind UDTKind) {
	switch (UDTKind) {
#define TOKENIZE(x) case Udt##x: return #x;
		TOKENIZE(Struct) TOKENIZE(Class) TOKENIZE(Union)
	}
	return _sprintf("0x%X", UDTKind);
}

static const char *TokenizeCallConv(enum CV_call_e CallConv) {
	switch (CallConv) {
		case CV_CALL_NEAR_C: return "CDeclNear";
		case CV_CALL_FAR_C: return "CDeclFar";
		case CV_CALL_NEAR_PASCAL: return "PascalNear";
		case CV_CALL_FAR_PASCAL: return "PascalFar";
		case CV_CALL_NEAR_FAST: return "FastCallNear";
		case CV_CALL_FAR_FAST: return "FastCallFar";
		case CV_CALL_SKIPPED: return "Skipped";
		case CV_CALL_NEAR_STD: return "StdCallNear";
		case CV_CALL_FAR_STD: return "StdCallFar";
		case CV_CALL_NEAR_SYS: return "SysCallNear";
		case CV_CALL_FAR_SYS: return "SysCallFar";
		case CV_CALL_THISCALL: return "ThisCall";
		case CV_CALL_MIPSCALL: return "MipsCall";
		case CV_CALL_GENERIC: return "Generic";
		case CV_CALL_ALPHACALL: return "AlphaCall";
		case CV_CALL_PPCCALL: return "PPCCall";
		case CV_CALL_SHCALL: return "HitachiSuperHCall";
		case CV_CALL_ARMCALL: return "ARMCall";
		case CV_CALL_AM33CALL: return "AM33Call";
		case CV_CALL_TRICALL: return "TriCoreCall";
		case CV_CALL_SH5CALL: return "HitachiSuperH-5Call";
		case CV_CALL_M32RCALL: return "M32RCall";
	}
	return "<none>";
}

#undef TOKENIZE

static tid_t CreateStructCY() {
	tid_t tid = get_struc_id("CY");
	if (tid == BADNODE) {
		typeinfo_t ti;
		ti.tid = add_struc(BADADDR, NULL, false);
		struc_t *struc(get_struc(ti.tid));
		if (struc == 0) return BADNODE;
		add_struc_member(struc, "Lo", BADADDR, dwrdflag() | numflag(), 0, sizeof(ulong));
		add_struc_member(struc, "Hi", BADADDR, dwrdflag() | numflag(), 0, sizeof(long));
		struc->props |= SF_HIDDEN;
		save_struc(struc);
		tid = add_struc(BADADDR, "CY", true);
		struc = get_struc(tid);
		if (struc == 0) return BADNODE;
		add_struc_member(struc, NULL, 0, struflag(), &ti, get_struc_size(ti.tid));
		add_struc_member(struc, "int64", 1, qwrdflag() | numflag(), 0, sizeof(LONGLONG));
		struc->props |= SF_HIDDEN;
		save_struc(struc);
	}
	return tid;
}

static bool CreateBSTR() throw() {
	typestring loctype;
	try {
		if (!is_named_type("BSTR")) {
			if (!is_named_type("OLECHAR")) {
				if (!is_named_type("WCHAR")) {
					if (!is_named_type("wchar_t")) {
						loctype.clear();
						loctype << (BTMT_USIGNED | BT_INT16);
						if (::set_named_type(idati, "wchar_t", DEF_NTF_FLAGS, loctype,
							NULL, NULL, NULL, &sc_tdef)) ++totaltypedefs;
						loctype.clear();
					}
					loctype << tdef("wchar_t");
					if (::set_named_type(idati, "WCHAR", DEF_NTF_FLAGS, loctype,
						NULL, NULL, NULL, &sc_tdef)) ++totaltypedefs;
					loctype.clear();
				}
				loctype << tdef("WCHAR");
				if (::set_named_type(idati, "OLECHAR", DEF_NTF_FLAGS, loctype,
					NULL, NULL, NULL, &sc_tdef)) ++totaltypedefs;
				loctype.clear();
			}
			loctype << (BT_PTR | BTMT_DEFPTR) << tdef("OLECHAR");
			if (!::set_named_type(idati, "BSTR", DEF_NTF_FLAGS, loctype,
				NULL, NULL, NULL, &sc_tdef)) throw logic_error("failed to store BSTR");
			++totaltypedefs;
		}
		return true;
	} catch (GENERAL_CATCH_FILTER) {
		_RPT4(_CRT_WARN, "%s(): kernel raised %s during set_named_type(\"%s\") chain\n",
			__FUNCTION__, e.what(), "wchar_t/WCHAR/OLECHAR/BSTR", typeid(e).name());
		try {
			loctype.clear();
			loctype << (BT_PTR | BTMT_DEFPTR) << (BTMT_USIGNED | BT_INT16);
			if (!::set_named_type(idati, "BSTR", DEF_NTF_FLAGS, loctype,
				NULL, NULL, NULL, &sc_tdef)) throw logic_error("failed to store BSTR");
			++totaltypedefs;
			return true;
		} catch (GENERAL_CATCH_FILTER) {
			_RPT4(_CRT_WARN, "%s(): kernel raised %s during set_named_type(\"%s\") chain\n",
				__FUNCTION__, e.what(), "BSTR", typeid(e).name());
		}
	}
	return false;
}

static bool CreateHRESULT() throw() {
	typestring loctype;
	try {
		if (!is_named_type("HRESULT")) {
			if (!is_named_type("LONG")) {
				loctype << BT_INT32;
				if (::set_named_type(idati, "LONG", DEF_NTF_FLAGS, loctype,
					NULL, NULL, NULL, &sc_tdef)) ++totaltypedefs;
				loctype.clear();
			}
			loctype << tdef("LONG");
			if (!::set_named_type(idati, "HRESULT", DEF_NTF_FLAGS, loctype,
				NULL, NULL, NULL, &sc_tdef)) throw logic_error("failed to store HRESULT");
			++totaltypedefs;
		}
		return true;
	} catch (GENERAL_CATCH_FILTER) {
		_RPT4(_CRT_WARN, "%s(): kernel raised %s during set_named_type(\"%s\") chain\n",
			__FUNCTION__, e.what(), "LONG/HRESULT", typeid(e).name());
		try {
			loctype.clear();
			loctype << BT_INT32;
			if (!::set_named_type(idati, "HRESULT", DEF_NTF_FLAGS, loctype,
				NULL, NULL, NULL, &sc_tdef)) throw logic_error("failed to store HRESULT");
			++totaltypedefs;
			return true;
		} catch (GENERAL_CATCH_FILTER) {
			_RPT4(_CRT_WARN, "%s(): kernel raised %s during set_named_type(\"%s\") chain\n",
				__FUNCTION__, e.what(), "HRESULT", typeid(e).name());
		}
	}
	return false;
}

static bool CreateDATE() throw() {
	try {
		if (!is_named_type("DATE")) {
			typestring loctype;
			loctype << (BT_FLOAT | BTMT_DOUBLE);
			if (!::set_named_type(idati, "DATE", DEF_NTF_FLAGS, loctype,
				NULL, NULL, NULL, &sc_tdef)) throw logic_error("failed to store DATE");
			++totaltypedefs;
		}
		return true;
	} catch (GENERAL_CATCH_FILTER) {
		_RPT4(_CRT_WARN, "%s(): kernel raised %s during set_named_type(\"%s\") chain\n",
			__FUNCTION__, e.what(), "DATE", typeid(e).name());
	}
	return false;
}

static bool CreateCURRENCY() throw() {
	try {
		if (!is_named_type("CURRENCY")) {
			CreateStructCY();
			typestring loctype;
			loctype << tdef("CY");
			if (!::set_named_type(idati, "CURRENCY", DEF_NTF_FLAGS, loctype,
				NULL, NULL, NULL, &sc_tdef)) throw logic_error("failed to store CURRENCY");
			++totaltypedefs;
		}
		return true;
	} catch (GENERAL_CATCH_FILTER) {
		_RPT4(_CRT_WARN, "%s(): kernel raised %s during set_named_type(\"%s\") chain\n",
			__FUNCTION__, e.what(), "CURRENCY", typeid(e).name());
	}
	return false;
}

// plugin description block
static const char help[] =
	"PDB file loader\n"
	"\n"
	"This module allows you to load debug information about function names\n"
	"from a PDB file.\n"
	"\n"
	"The PDB file should be in the same directory as the input file\n";

plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION, PLUGIN_UNL | PLUGIN_MOD | PLUGIN_HIDE,
	init, 0/*term*/, plugin_main,
	"Load debug information from a PDB file", const_cast<char *>(help),
	"Load PDB file (DbgHelp 4.1+)", 0/*hotkey*/
};
