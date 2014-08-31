
/*****************************************************************************
 *                                                                           *
 *  csc.cpp: Code snippet creator: plugin for IDA Pro                        *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include <ctime>
#include <vector>
#include <list>
#include <hash_map>
#include <fstream>
#include <iomanip>
#include <valarray>
#include <utility>
#include <bitset>
#include <boost/mem_fn.hpp>
#include <boost/bind.hpp>
#include <boost/variant.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/optional.hpp>
//#include <boost/lambda/lambda.hpp>
//#include <boost/lambda/bind.hpp>
//#define PERL_NO_SHORT_NAMES        1
//#include <EXTERN.h>               /* from the Perl distribution     */
//#include <perl.h>                 /* from the Perl distribution     */
//#include <PerlEz.h>
//#ifdef CONTEXT
//#undef CONTEXT
//#endif // CONTEXT
#include "debugger.hpp"
#include "fixdcstr.hpp"
#include "pcre.hpp"
#include "pcre_replacer.hpp"
#ifdef GetModuleBaseName
#undef GetModuleBaseName
#endif
#include "plugida.hpp"
#include "rtrlist.hpp"
#include "xtrnresolver.h"
#include "flirtmatch.h"
#include "undbgnew.h"
#include "batchres.hpp"
#include "warnlist.hpp"
#include "graphvwr.hpp"
#include "plug_abt.ipp"  // about box common handler

#define _SHOWADDRESS               1          // display progress (costs time)
//#define _DEBUG_VERBOSE             1        // more diagnostic messages

CRTRList rtrlist;

/*****************************************************************************
 *  *
 *  C0MPONENT 1: THE CODE RIPPER  *
 *  *
 *****************************************************************************/

namespace CSC {

//template<class T>std::size_t hash_value(const T &);
//namespace boost { using ::CSC::hash_value; }

// flags for sections
#define FF_CONST (FF_DATA | 0x80000000)
#define FF_BSS   (FF_DATA | 0x81000000)
#define FF_XTRN  (FF_DATA | 0x82000000)
#define FF_DYN   (FF_DATA | 0x83000000)

enum asm_model_t { asm_none = 0, asm_masm, asm_ideal, asm_nasm, asm_fasm, };
enum string_t { nostr = 0, cstr, pstr, lstr, ucstr, upstr, ulstr, };

static uint total_arrays, total_vars, total_offsets, total_funcs,
	total_virtual_ranges, fatals;
static int total_ranges, tabs_current;
static size_t offset_boundary;
static areaex_t last;
static time_t start/*, lastrefresh*/;
static valarray<asize_t> total_bytes(5);
static hash_set<RegNo, hash<int> > segs_used;
static bool have_unc;
static layered_wait_box wait_box;
static const char node_name[] = "$ csc";
static const char emu_procname[] = "csc_project_rtdata"; // virtual ranges emulator name
static const char trn_procname[] = "csc_translate_externals"; // rt translator name
static const char trn_tablename[] = "csc_imports_translation_table"; // translation table name
static const char libname_prefix[] = "csc_libname";
static const char clonedname_prefix[] = "csc_data";
static const char rte_warning[] = "<<<--- csc warning: runtime-evaluated destination";
static const char cfgsection[] = "CSC";
static const char prefix[] = "[csc] ";
static const char deflt_wait_banner[] = "please wait, snippet creator is working...";
static const char *options, *code_sec, *data_sec, *const_sec, *bss_sec,
	*proc_start, *proc_end;
static CBatchResults *pBatchResults; // hook to fubar's report list
static hash_set<ea_t> dummy_labels, log_addresses;
#define PREFS_VERSION 0x0105
static struct __declspec(align(1)) prefs_t {
	uint16 version;
	bool include_libitems, do_wipeout, exec_flt, code2code, makealigns,
		code2data, data2code, dbg_resolve, dbg_savedata, data2data, createoffsets,
		offtohead, offtodefhead, crefs, drefs, cmtrta, include_thunkfuncs,
		include_hidden, destroyenums, addref, destroy_structs, circulated_resolving,
		keep_saved_data, externdefs, anchorstroffs, resolve_names, dbg_exploreheaps,
		reloc_extfn_offs, dyndataxplorer_carenames, dyndataxplorer_carerefs,
		dyndataxplorer_carefuncs, suppress_nags[2], dyndataxplorer_enablevalloc,
		include_typedefs, suddendeath_on_fatal, reloc_extvar_offs,
		dyndataxplorer_honouroffsets, unattended, dyndataxplorer_map_imps_dir,
		create_graph;
	uint8 verbosity, reporting_verbosity, dyndataxplorer_offtostat,
		dyndataxplorer_offtodyn;
	size_t dyndataxplorer_maxclonable, dyndataxplorer_maxoffsetable,
		dyndataxplorer_minvallocblk;
	uint dyndataxplorer_maxrecursion, max_ranges;
	time_t maxruntime;
	asm_model_t asm_model;
	char fltcommand[0x200];
} prefs;

static bool isExcludedExternal(ea_t const ea);

namespace CTab1
	{ static INT_PTR CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM); }
namespace CTab2
	{ static INT_PTR CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM); }
static tabdef_t tabs[] = {
	"General settings", MAKEINTRESOURCE(IDD_CSC_TAB1), CTab1::DialogProc, NULL,
	"Runtime features", MAKEINTRESOURCE(IDD_CSC_TAB2), CTab2::DialogProc, NULL,
};

//  breakpoints manager implementation (for tracer) 

static class breakpoints_t : public hash_map<ea_t, uint8> {
public:
	bool set(key_type ea, mapped_type type) {
		if (type == 0) return false; // no flag bit
		const iterator i(find(ea));
		if (i != end()) {
			_RPT4(_CRT_WARN, "%s(%08IX, %u): setting multiple breakpoints (existing=%u)\n",
				__FUNCTION__, ea, type, i->second);
			if ((i->second & type) == type) return false; // no bits to add
			i->second |= type;
			return true;
		}
		return insert(value_type(ea, type)).second;
	}
} breakpoints;

//  static ranges manager implementation 

struct range_t : public areaex_t {
	flags_t type;
	uint level;
	vector<string> comments;
	int graph_node;

	range_t(ea_t startEA, ea_t endEA, flags_t type, uint level = 0) throw() :
		areaex_t(startEA, endEA), type(type), level(level), graph_node(-1) { }
	range_t(const area_t &area, flags_t type, uint level = 0) throw() :
		areaex_t(area), type(type), level(level), graph_node(-1) { }

	inline operator ea_t() const throw() { return startEA; }
	// for sorted containers...
	inline bool operator <(const range_t &rhs) const throw() {
		return /*level < rhs.level || level == rhs.level && */startEA < rhs.startEA;
	}

	inline bool is_of_type(flags_t type) const throw()
		{ return this->type == type; }
	inline bool isData() const throw() {
		return is_of_type(FF_DATA) || is_of_type(FF_CONST)
			|| is_of_type(FF_BSS) || is_of_type(FF_XTRN);
	}
	inline bool isCode() const throw() { return is_of_type(FF_CODE); }
	asize_t rawsize() const {
		ea_t rawstart(startEA);
		while (isAlign(get_flags_novalue(rawstart))) rawstart = next_not_tail(rawstart);
		ea_t rawend(safeEndEA()), ea;
		while (isAlign(get_flags_novalue(ea = prev_not_tail(rawend)))) rawend = ea;
		return rawend > rawstart ? rawend - rawstart : 0;
	}
	asize_t plus(asize_t accumulated, flags_t type = 0) const throw() {
		if (type == 0 || this->type == type) accumulated += rawsize();
		return accumulated;
	}
	bool GetLabel(char *buf, size_t bufsize, ea_t target = BADADDR) const;
}; // range_t
static class ranges_t : public list<range_t>/*hash_set<range_t, areaex_t::hash> ???*/ {
public:
	inline const_iterator operator [](ea_t ea) const
		{ return const_cast<ranges_t *>(this)->find(ea); }

	iterator find(ea_t ea, bool exact = false) {
		return find_if(begin(), end(), boost::bind2nd(boost::mem_fun_ref(exact ?
			areaex_t::start_at : areaex_t::has_address), ea));
	}
	bool has_address(ea_t ea) const
		{ return const_cast<ranges_t *>(this)->find(ea, false) != end(); }
	bool add(const range_t &range, const char *const comment = 0);
	bool add_comment(ea_t ea, const string &comment) {
		_ASSERTE(!comment.empty());
		if (comment.empty()) return false;
		const iterator tmp(find(ea));
		if (tmp == end() || std::find(tmp->comments.begin(), tmp->comments.end(),
			comment) != tmp->comments.end()) return false; // no dupes!
		tmp->comments.push_back(comment);
		return true;
	}
	asize_t accumulate(flags_t type = 0) const {
		return std::accumulate(begin(), end(), 0,
			boost::bind(&range_t::plus, _2, _1, type));
	}
} static_ranges;

//  imports manager implementation 

struct import_t {
	typedef boost::variant<
		string, // by name
		WORD,   // by ordinal
		DWORD   // by RVA from module base
	> anchor_t;

	LPCVOID Address;
	fixed_path_t DllName;
	anchor_t anchor;
	string comment;

	import_t(LPCVOID Address, LPCSTR lpDllName, const anchor_t &anchor,
		const char *comment = 0) throw(exception) :
		Address(Address), DllName(lpDllName), anchor(anchor) {
		_ASSERTE(!anchor.empty());
		if (anchor.empty()) __stl_throw_invalid_argument("either anchor method must be given");
		if (comment != 0 && *comment != 0) this->comment.assign(comment);
	}

	inline bool operator ==(const import_t &rhs) const throw()
		{ return operator LPCVOID() == rhs.operator LPCVOID(); }
	inline operator LPCVOID() const throw() { return Address; }

	inline bool hasDllName() const throw() { return DllName[0] != 0; }

	struct hash {
		inline size_t operator ()(const import_t &__x) const throw()
			{ return hash_value(__x); }
	};
	friend inline std::size_t hash_value(const import_t &__x)
		{ return boost::hash_value(__x.operator LPCVOID()); }
//private:
	class print_anchor : public boost::static_visitor<void> {
	private:
		ostream &__os;
	public:
		print_anchor(ostream &__os) : __os(__os) { }

		void operator ()(const string &s) const { __os << s; }
		void operator ()(WORD w) const { __os << __os.widen('#') << dec << w; }
		void operator ()(DWORD dw) const { __os << __os.widen('+') << ashex(dw); }
	};
}; // import_t
ostream &operator<<(ostream &__os, const import_t::anchor_t &rhs) {
	boost::apply_visitor(import_t::print_anchor(__os), rhs);
	return __os;
}
typedef hash_set<import_t, import_t::hash/*boost::hash<import_t>*/> imports_t;
static imports_t imports;

//  cloned ranges manager implementation 

struct clonedblock_t/* : public CDebugger::memblock_t*/ {
	struct referrer_t {
		DWORD offset; // offset from clonedblock_t start
		LPVOID BaseAddress; // base address of referrer block
		DWORD BaseOffset; // offset from refblock base address
		string comment;

		referrer_t(DWORD offset, LPCVOID BaseAddress = NULL, DWORD dwBaseOffset = 0,
			const char *comment = 0) : offset(offset),
			BaseAddress(const_cast<LPVOID>(BaseAddress)), BaseOffset(dwBaseOffset)
				{ if (comment != 0 && *comment != 0) this->comment.assign(comment); }

		inline operator LPVOID() const throw()
			{ return (LPBYTE)BaseAddress + BaseOffset; }

		inline bool start_at(LPCVOID addr) const throw()
			{ return BaseAddress == addr; }

		struct hash {
			inline size_t operator ()(const referrer_t &__x) const throw()
				{ return reinterpret_cast<size_t>(__x.operator LPVOID()); }
		};
		friend inline std::size_t hash_value(const referrer_t &__x) {
			return boost::hash_value(__x.operator LPVOID());
		}
	};
	typedef hash_set<referrer_t, referrer_t::hash/*boost::hash<referrer_t>*/>
		referrers_t;

	LPCVOID BaseAddress;
	SIZE_T size;
	boost::shared_crtptr<void> dump;
	referrers_t referrers;
	string label, comment;
	hash_map<size_t, imports_t::const_iterator> imprefs;
	int graph_node;

	clonedblock_t(LPCVOID BaseAddress, SIZE_T size = (SIZE_T)-1, const char *label = 0,
		const char *comment = 0, const void *dump = 0) throw(exception) :
		BaseAddress(BaseAddress), size(size), graph_node(-1) {
		if (label != 0 && *label != 0) this->label.assign(label);
		if (comment != 0 && *comment != 0) this->comment.assign(comment);
		if (dump != 0 && size != (SIZE_T)-1 && size > 0) {
			this->dump.reset(malloc(size));
			if (!this->dump) {
				_RPT2(_CRT_ERROR, "%s(...): failed to allocate new block of size 0x%IX\n",
					__FUNCTION__, size);
				throw bad_alloc();
			}
			memcpy(this->dump.get(), dump, size);
		}
	}

	inline operator LPCVOID() const throw()
		{ return BaseAddress; }
	inline operator bool() const throw()
		{ return BaseAddress != NULL && size != (SIZE_T)-1; }
	inline bool operator <(const clonedblock_t &rhs) const throw()
		{ return operator LPCVOID() < rhs.operator LPCVOID(); }
	inline bool operator ==(const clonedblock_t &rhs) const throw()
		{ return operator LPCVOID() == rhs.operator LPCVOID(); }

	inline bool start_at(LPCVOID Address) const throw()
		{ return BaseAddress == Address; }
	inline bool has_address(LPCVOID Address) const throw()
		{ return Address >= BaseAddress && (LPBYTE)Address < (LPBYTE)EndAddress(); }
	size_t offset(LPCVOID addr) const {
		_ASSERTE(has_address(addr));
		if (!has_address(addr)) __stl_throw_out_of_range("address invalid (not owned by dynamic block)");
		return static_cast<size_t>((LPBYTE)addr - (LPBYTE)BaseAddress);
	}
	inline LPCVOID EndAddress() const throw()
		{ return operator bool() ? (LPBYTE)BaseAddress + size : NULL; }
	inline SIZE_T plus(SIZE_T accumulated) const throw()
		{ return accumulated + size; }
	bool GetLabel(char *buf, size_t bufsize, DWORD dwOffset = 0) const;
	bool GetLabel(char *buf, size_t bufsize, LPCVOID address) const {
		_ASSERTE(has_address(address));
		return GetLabel(buf, bufsize, address == NULL || address == (LPCVOID)-1L ?
			0 : (LPBYTE)address - (LPBYTE)BaseAddress);
	}

	struct hash {
		inline size_t operator ()(const clonedblock_t &__x) const throw()
			{ return reinterpret_cast<size_t>(__x.operator LPCVOID()); }
	};
	friend inline std::size_t hash_value(const clonedblock_t &__x)
		{ return boost::hash_value(__x.operator LPCVOID()); }
}; // clonedblock_t
static class clonedblocks_t :
	public hash_set<clonedblock_t, clonedblock_t::hash/*boost::hash<clonedblock_t>*/> {
public:
	inline const_iterator operator [](LPCVOID address) const { return find(address); }

	const_iterator find(LPCVOID address, bool exact = true) const {
		return exact ? __super::find(address) : find_if(begin(), end(),
			boost::bind2nd(boost::mem_fun_ref(clonedblock_t::has_address), address));
	}
	bool has_address(LPCVOID address) const { return find(address, false) != end(); }
	SIZE_T accumulate() const {
		return std::accumulate(begin(), end(), 0,
			boost::bind(&clonedblock_t::plus, _2, _1));
	}
} cloned_blocks;

//  exclusions 

static class exclusions_t : public hash_map<ea_t, size_t> {
public:
	bool have(ea_t ea) const { return find(ea) == end(); }
	inline bool have(LPCVOID addr) const { return have(reinterpret_cast<ea_t>(addr)); }
} excluded_symbols;


//  graph nodes container 

struct graph_node_t {
	string name;
	flags_t type;
	hash_set<int> refs;
	string hint; // ??
	ea_t ea;

	graph_node_t(const char *name, flags_t type, ea_t ea = BADADDR,
		asize_t size = 0, const char *hint = 0) : type(type), ea(ea) {
		set_name(name, type, size);
		if (hint != 0 && *hint != 0) this->hint.assign(hint);
	}

	void set_name(const char *name, flags_t type, asize_t size = 0) {
		_ASSERTE(name != 0 && *name != 0);
		char colname;
		switch (type) {
			case FF_CODE : colname = COLOR_CNAME;   break;
			case FF_DATA : colname = COLOR_DNAME;   break;
			case FF_CONST: colname = COLOR_DNAME;   break;
			case FF_BSS  : colname = COLOR_DNAME;   break;
			case FF_XTRN : colname = COLOR_IMPNAME; break;
			case FF_DYN  : colname = COLOR_DATNAME; break;
			default      : colname = COLOR_DEFAULT;
		}
		_sprintf(this->name, "\n %c%c%s%c%c \n ", COLOR_ON, colname,
			name != 0 && *name != 0 ? name : "?????", COLOR_OFF, colname);
		if (size > 0) _sprintf_append(this->name, "%c%csize=0x%X%c%c \n ",
			COLOR_ON, COLOR_REGCMT, size, COLOR_OFF, COLOR_REGCMT);
	}
}; // graph_node_t

static class CGraphForm : public vector<graph_node_t>
#if IDA_SDK_VERSION >= 510
	, public ::CGraphForm
#endif
{
#if IDA_SDK_VERSION >= 510
	// internal graph
private:
	// bit mapping:
	//  1 <-> FF_CODE
	//  2 <-> FF_DATA
	//  4 <-> FF_CONST
	//  8 <-> FF_BSS
	// 16 <-> FF_XTRN
	// 32 <-> FF_DYN
	uint16 filter;
	vector<size_t> node2ndx_mapper;
	hash_map<size_t, int> ndx2node_mapper;

private:
	// IDA graphing interface
	bool dblclicked(graph_viewer_t *gv, const selection_item_t *current_item) const {
		__super::dblclicked(gv, current_item);
		if (current_item != 0 && current_item->is_node) {
			_ASSERTE(current_item->node != -1 && node2ndx(current_item->node) <= size());
			const ea_t &ea(at(node2ndx(current_item->node)).ea);
			if (isEnabled(ea)) jumpto(ea); else MessageBeep(MB_ICONWARNING);
		}
		return true;
	}
	void user_refresh(mutable_graph_t *g) const {
		__super::user_refresh(g);
		if (g == 0 || !grentry(grcode_empty, g)) return;
		const_iterator x;
		hash_set<int>::const_iterator y;
		edge_info_t ei;
		if (node2ndx_mapper.empty()) {
			// no filter
			g->resize(size());
			for (x = begin(); x != end(); ++x)
				for (y = x->refs.begin(); y != x->refs.end(); ++y) {
					_ASSERTE(*y >= 0 && *y < size());
					g->add_edge(distance(begin(), x), *y, calc_edge(ei, *x, at(*y)));
				}
		} else {
			// filtering active
			g->resize(node2ndx_mapper.size());
			for (x = begin(); x != end(); ++x) if (show_type(x->type))
				for (y = x->refs.begin(); y != x->refs.end(); ++y) {
					_ASSERTE(*y >= 0 && *y < size());
					if (show_type(at(*y).type)) g->add_edge(ndx2node(distance(begin(), x)),
						ndx2node(*y), calc_edge(ei, *x, at(*y)));
				}
		}
	}
	void user_text(mutable_graph_t *g, int node, const char **result, bgcolor_t *bg_color) const {
		__super::user_text(g, node, result, bg_color);
		//if (/*g == 0 || */node2ndx(node) >= size()) return;
		const graph_node_t &grn(at(node2ndx(node)));
		if (result != 0) *result = grn.name.empty() ? 0 : grn.name.c_str();
		if (bg_color != 0) *bg_color = DEFCOLOR;
	}
	bool user_hint(mutable_graph_t *g, int node, const edge_t &edge, char **hint) const {
		__super::user_hint(g, node, edge, hint);
		if (hint == 0) return false;
		*hint = 0;
		if (node != -1) {
			_ASSERTE(node2ndx(node) < size());
			const graph_node_t &grn(at(node2ndx(node)));
			if (!grn.hint.empty()) {
				*hint = qstrdup(grn.hint.c_str());
				return true;
			}
		} else if (edge.src != -1 && edge.dst != -1) {
			_ASSERTE(node2ndx(edge.src) < size());
			_ASSERTE(node2ndx(edge.dst) < size());
			//const graph_node_t &src(at(node2ndx(edge.src)));
			//const graph_node_t &dst(at(node2ndx(edge.dst)));
			// todo: fill hint
			//return true;
		}
		return false;
	}
	void destroyed(mutable_graph_t *g) {
		__super::destroyed(g);
		apply_filter(); //Reset();
	}
	bool created() {
		if (empty()) return false;
		__super::created();
		add_menu_item("Locate node by name", find_node, "F");
		add_menu_item("Node type filtering", filtering, "Ctrl-L");
		return true;
	}

	// menu events
	static bool idaapi find_node(void *ud) {
		_ASSERTE(ud != 0);
		if (ud == 0 || !static_cast<CGraphForm *>(ud)->IsOpen()
			|| static_cast<CGraphForm *>(ud)->empty()) return false;
		const char *str = askstr(HIST_IDENT, NULL, "Enter name or part (case sensitive)\nor regexp as /<regex>/[<options>]");
		if (str == 0 || *str == 0) return false;
		PCRE::regexp regex;
		const PCRE::regexp::result
			match(PCRE::regexp("^m?\\/(.*)\\/\\s*([[:lower:]\\s]+)?$"), str);
		if (match >= 2) {
			int options(0);
			if (match >= 3) {
#define TestReOption(letter, value) if (strchr(match[2], #@letter) != 0) options |= value;
				TestReOption(i, PCRE_CASELESS)
				TestReOption(m, PCRE_MULTILINE)
				TestReOption(s, PCRE_DOTALL)
				TestReOption(x, PCRE_EXTENDED)
				// pcre-specific
				TestReOption(A, PCRE_ANCHORED)
				TestReOption(C, PCRE_AUTO_CALLOUT)
				TestReOption(E, PCRE_DOLLAR_ENDONLY)
				TestReOption(f, PCRE_FIRSTLINE)
				TestReOption(N, PCRE_NO_AUTO_CAPTURE)
				TestReOption(U, PCRE_UNGREEDY)
				TestReOption(X, PCRE_EXTRA)
#undef TestReOption
			}
			const char *errptr;
			int erroffset, errorcode(regex.compile(match[1], options, errptr, erroffset));
			if (errorcode != 0) {
				_ASSERTE(errptr != 0);
				cmsg << prefix << "regexp pattern '" << match[1] << "'[" << dec <<
					erroffset << "] compile error " << dec << errorcode << ": " << errptr << endl;
			}
		}
		for (CGraphForm::const_iterator i = static_cast<CGraphForm *>(ud)->begin();
			i != static_cast<CGraphForm *>(ud)->end(); ++i)
			if (static_cast<CGraphForm *>(ud)->show_type(i->type) && (regex ?
				regex.match(i->name) : i->name.find(str) != (string::size_type)string::npos)) {
				static_cast<CGraphForm *>(ud)->center_on(static_cast<CGraphForm *>(ud)->
					ndx2node(distance((CGraphForm::const_iterator)
						static_cast<CGraphForm *>(ud)->begin(), i)));
				return true;
			}
		warning("no match");
		return false;
	}
	static bool idaapi filtering(void *ud) {
		_ASSERTE(ud != 0);
		if (ud == 0 || !static_cast<CGraphForm *>(ud)->IsOpen()
			|| static_cast<CGraphForm *>(ud)->empty()) return false;
		uint16 tmp(static_cast<CGraphForm *>(ud)->filter);
		if (AskUsingForm_c("\nChoose block types to show\n"
				"<~C~ode:c>\n"
				"<~D~ata (mutable):c>\n"
				"<C~o~nst data:c>\n"
				"<~U~ninitialized data:c>\n"
				"<E~x~ternal symbols:c>\n"
				"<C~l~oned blocks:c>>\n\n", &tmp) != 1
			|| (tmp & 0x3F) <= 0
			|| (tmp & 0x3F) == (static_cast<CGraphForm *>(ud)->filter & 0x3F))
			return false;
		static_cast<CGraphForm *>(ud)->apply_filter(tmp);
		static_cast<CGraphForm *>(ud)->full_refresh();
		return true;
	}

	bool show_type(flags_t type) const {
		switch (type) {
			case FF_CODE : return (filter &  1) != 0;
			case FF_DATA : return (filter &  2) != 0;
			case FF_CONST: return (filter &  4) != 0;
			case FF_BSS  : return (filter &  8) != 0;
			case FF_XTRN : return (filter & 16) != 0;
			case FF_DYN  : return (filter & 32) != 0;
#ifdef _DEBUG
			default: _RPT2(_CRT_ASSERT, "%s(0x%08X): unexpected type value\n",
				__FUNCTION__, type);
#endif
		}
		return false;
	}
	void apply_filter(uint16 filter = ~0) {
		this->filter = filter;
		node2ndx_mapper.clear();
		ndx2node_mapper.clear();
		if (filter >= 0x3F) return;
		for (const_iterator x = begin(); x != end(); ++x) if (show_type(x->type)) {
			const size_type index = distance((const_iterator)begin(), x);
			node2ndx_mapper.push_back(index);
			ndx2node_mapper[index] = node2ndx_mapper.size() - 1;
		}
		_ASSERTE(ndx2node_mapper.size() == node2ndx_mapper.size());
	}
	size_t node2ndx(int node) const {
		if (node == -1) __stl_throw_invalid_argument(__FUNCTION__ "(-1): invalid node");
		node = abs_node(node);
		if (!node2ndx_mapper.empty()) {
			_ASSERTE(static_cast<size_t>(node) < node2ndx_mapper.size());
			node = node2ndx_mapper.at(static_cast<size_t>(node));
		}
#ifdef _DEBUG
		else
			_ASSERTE(static_cast<size_t>(node) < size());
#endif
		return node;
	}
	int ndx2node(size_t index) const {
		_ASSERTE(index < size());
		if (ndx2node_mapper.empty()) return static_cast<int>(index);
		const hash_map<size_t, int>::const_iterator it = ndx2node_mapper.find(index);
		_ASSERTE(it != ndx2node_mapper.end());
		return it != ndx2node_mapper.end() ? it->second : -1;
	}
	static edge_info_t *calc_edge(edge_info_t &ei, const graph_node_t &from,
		const graph_node_t &to) {
		if (from.type == FF_CODE && to.type == FF_CODE) {
			ei.color = RGB(0, 160, 0);
			ei.width = 4;
		} else if (from.type == FF_DYN || to.type == FF_DYN) {
			ei.color = RGB(160, 0, 160);
			ei.width = 1;
		} else if (from.type == FF_CODE) {
			ei.color = RGB(0, 128, 160);
			ei.width = 3;
		} else {
			ei.color = RGB(0, 0, 192);
			ei.width = 2;
		}
		return &ei;
	}
#endif // IDA_SDK_VERSION >= 510

private:
	// GDL graph helper functions
	enum gdl_color_type {
		gdl_background = 0,
		gdl_text = 1,
		gdl_border = 2,
	};
	static uint8 gdl_get_colorentry(uint index, gdl_color_type coltype)
		{ return 32 + index * 3 + static_cast<int>(coltype); }
	static uint8 gdl_get_color(flags_t type, gdl_color_type coltype) {
		switch (type) {
			case FF_CODE: return gdl_get_colorentry(0, coltype);
			case FF_DATA: return gdl_get_colorentry(1, coltype);
			case FF_CONST: return gdl_get_colorentry(2, coltype);
			case FF_BSS: return gdl_get_colorentry(3, coltype);
			case FF_XTRN: return gdl_get_colorentry(4, coltype);
			case FF_DYN: return gdl_get_colorentry(5, coltype);
		}
		_RPT2(_CRT_WARN, "%s(%u): unexpected block type\n", __FUNCTION__, type);
		return 0;
	}
	static uint8 gdl_get_edge_color(flags_t fromtype, flags_t totype) {
		uint8 r;
		if (fromtype == FF_CODE && totype == FF_CODE)
			r = 0;
		else if (fromtype == FF_DYN || totype == FF_DYN)
			r = 1;
		else if (fromtype == FF_CODE)
			r = 2;
		else
			r = 3;
		return 32 + 6 * 3 + r;
	}

public:
	// kernel`s gen_gdl(...) not implemented, let`s generate on our own
	bool gen_gdl(const char *filename) const {
		_ASSERTE(filename != 0 && *filename != 0);
		if (filename == 0 || *filename == 0) return false;
		ofstream os(filename, ios_base::out | ios_base::trunc);
		if (!os.good()) return false;
		dec(os);
		os << "graph: {" << endl;
		os << "title: \"" << "CSC ref-graph review" << "\"" << endl;
		os << "manhattan_edges: yes" << endl;
		//os << "layoutalgorithm: " << "mindepth" << endl;
		os << "finetuning: yes" << endl;
		//os << "layout_downfactor: " << 100 << endl;
		//os << "layout_upfactor: " << 0 << endl;
		//os << "layout_nearfactor: " << 0 << endl;
		//os << "xlspace: " << 12 << endl;
		//os << "yspace: " << 30 << endl;
		os << "// Palette" << endl;
		static const uint8 colortable[][3] = {
			// draw nodes
			0, 0, 0, // 32 (code bgcolor)
			255, 255, 255, // 33 (code textcolor)
			128, 128, 128, // 34 (code bordercolor)
			0, 0, 0, // 35 (data bgcolor)
			240, 189, 15, // 36 (data textcolor)
			128, 128, 128, // 37 (data bordercolor)
			0, 0, 0, // 38 (const bgcolor)
			242, 200, 55, // 39 (const textcolor)
			128, 128, 128, // 40 (const bordercolor)
			0, 0, 0, // 41 (bss bgcolor)
			220, 173, 14, // 42 (bss textcolor)
			128, 128, 128, // 43 (bss bordercolor)
			0, 0, 0, // 44 (extern bgcolor)
			206, 253, 213, // 45 (extern textcolor)
			128, 128, 128, // 46 (extern bordercolor)
			0, 0, 0, // 47 (dynblock bgcolor)
			201, 87, 210, // 48 (dynblock textcolor)
			128, 128, 128, // 49 (dynblock bordercolor)
			// edge colors
			0, 160, 0, // 50 (code -> code)
			160, 0, 160, // 51 (from/to dyn)
			0, 128, 160, // 52 (from code)
			0, 0, 192, // 53 (everything else)
		}; // colortable
		for (const uint8 (*i)[3] = colortable; i != colortable +
			sizeof(colortable) / sizeof(uint8[3]); ++i) os <<
				"colorentry " << (32 + (i - colortable)) << ": " <<
					static_cast<uint>((*i)[0]) << ' ' <<
					static_cast<uint>((*i)[1]) << ' ' <<
					static_cast<uint>((*i)[2]) << endl;
		os << "// Nodes" << endl;
		for (const_iterator x = begin(); x != end(); ++x) {
			const size_t sz = x->name.length() + 1;
			boost::scoped_array<char> uncolored(new char[sz]);
			tag_remove(x->name.c_str(), uncolored.get(), sz);
			os << "node: { title: \"" << /*hex << x->ea*/distance(begin(), x) <<
				/*dec << */"\" label: \"" << uncolored.get() << "\" color: " <<
				static_cast<uint>(gdl_get_color(x->type, gdl_background)) <<
				" textcolor: " <<
				static_cast<uint>(gdl_get_color(x->type, gdl_text)) <<
				" bordercolor: " <<
				static_cast<uint>(gdl_get_color(x->type, gdl_border)) << " }" << endl;
		}
		os << "// Edges" << endl;
		for (x = begin(); x != end(); ++x) {
			os << "// node " << /*dec << */distance(begin(), x) << endl/* << hex*/;
			for (hash_set<int>::const_iterator y = x->refs.begin(); y != x->refs.end(); ++y) {
				_ASSERTE(*y >= 0 && *y < size());
				// todo: use edge labels?
				os << "edge: { sourcename: \"" << /*x->ea*/distance(begin(), x) <<
					"\" targetname: \"" << /*at(*y).ea*/*y << "\" color: " <<
					static_cast<uint>(gdl_get_edge_color(x->type, at(*y).type)) <<
					" }" << endl;
			}
		}
		os << '}' << endl;
		os.close();
		return true;
	}

public:
	// open either call graph, return true on success
	bool Open() {
#if IDA_SDK_VERSION >= 510
		if (!IsAvail())
#endif
		return OpenGdl();
#if IDA_SDK_VERSION >= 510
		apply_filter();
		if (!IsOpen()) return __super::Open("CSC ref-graph") || OpenGdl();
		__super::Refresh();
		return true;
#endif // IDA_SDK_VERSION
	}
	void Reset() {
		clear();
		excluded_symbols.clear();
#if IDA_SDK_VERSION >= 510
		apply_filter();
#endif
	}
	// open GDL graph in external viewer (wingraph32)
	// this is not the preferred method due to lacking interaction with idabase,
	// custom commands and pure bitmap mode (unusable for complex graphs)
	// (only performed for kernel 5.0 and older)
	bool OpenGdl(const char *fname = 0) const {
		char tmp_fname[QMAXPATH];
		if (fname != 0 && *fname != 0)
			qstrcpy(tmp_fname, fname);
		else {
			GetTempPath(QMAXPATH, tmp_fname);
			qsnprintf(CAT(tmp_fname), "\\~csc_refgraph_%x.gdl", GetTickCount() * time(0));
		}
		return gen_gdl(tmp_fname) && display_gdl(tmp_fname) == 0;
	}
	// feed the database
	int AddNode(const char *name, flags_t type, ea_t ea = BADADDR,
		asize_t size = 0, const char *hint = 0) {
		push_back(graph_node_t(name, type, ea, size, hint));
		return static_cast<int>(this->size() - 1);
	}
	template<class F, class T>bool AddRef(F from, T to) {
		const int ndxf = find_source(from);
		if (ndxf == -1) return false;
		const int ndxt = find_target(to);
		// never should throw !
		return ndxt != -1 && ndxf != ndxt && at(ndxf).refs.insert(ndxt).second;
	}

private:
	template<class F>static int find_source(F from) {
		if ((ea_t)from != BADADDR)
			if (isEnabled((ea_t)from)) {
				const ranges_t::const_iterator it(static_ranges.find((ea_t)from, false));
				if (it != static_ranges.end()) return it->graph_node;
			} else if (prefs.dbg_savedata && prefs.dbg_exploreheaps) {
				const clonedblocks_t::const_iterator it(cloned_blocks.find((LPCVOID)from, false));
				if (it != cloned_blocks.end()) return it->graph_node;
			}
		return -1;
	}
	template<class T>int find_target(T to) {
		if (isEnabled((ea_t)to)) {
			const ranges_t::const_iterator it = static_ranges.find((ea_t)to, false);
			if (it != static_ranges.end()) return it->graph_node;
		} else if (prefs.dbg_savedata && prefs.dbg_exploreheaps) {
			const clonedblocks_t::const_iterator it =
				cloned_blocks.find((LPCVOID)to, false);
			if (it != cloned_blocks.end()) return it->graph_node;
		}
		const exclusions_t::const_iterator it = excluded_symbols.find((ea_t)to);
		if (it != excluded_symbols.end()) return it->second;
		char name[MAXNAMESIZE];
		return isExcludedExternal((ea_t)to) && GetLabel((ea_t)to, CPY(name)) ?
			(excluded_symbols[(ea_t)to] = AddNode(name, FF_XTRN, (ea_t)to)) : -1;
	}
} graph;

//  translation points manager implementation 

struct remappoint_t {
	ea_t BaseAddress;
	asize_t BaseOffset;
	string comment;

	remappoint_t(ea_t BaseAddress, asize_t BaseOffset = 0, const char *comment = 0) :
		BaseAddress(BaseAddress), BaseOffset(BaseOffset)
			{ if (comment != 0) this->comment.assign(comment); }

	inline operator ea_t() const throw() { return BaseAddress + BaseOffset; }
	inline bool operator ==(const remappoint_t &rhs) const throw()
		{ return operator ea_t() == rhs.operator ea_t(); }

	struct hash {
		inline size_t operator ()(const remappoint_t &__x) const throw()
			{ return static_cast<size_t>(__x.operator ea_t()); }
	};
	friend inline std::size_t hash_value(const remappoint_t &__x)
		{ return boost::hash_value(__x.operator ea_t()); }
};
typedef hash_set<remappoint_t, remappoint_t::hash/*boost::hash<remappoint_t>*/>
	remappoints_t;
static remappoints_t externals;

//  report list implementation 

static class CReport : public CWarningList {
public:
	bool Open() {
		if (items.empty()) return false;
		//Sort();
		static int const widths[] = { 9, 14, 77, };
		choose2(0, -1, -1, -1, -1, this, qnumber(widths), widths, sizer, getl,
			GetTitle(), GetIcon(0), 1, 0, 0, 0, 0, enter, destroy, 0, get_icon);
		PLUGIN.flags &= ~PLUGIN_UNL;
		return true;
	}

protected:
	const char *GetTitle() const { return "CSC report"; }
	// IDA callback overrides
	void GetLine(ulong n, char * const *arrptr) const {
		if (n == 0) { // header
			static const char *const headers[] = { "address", "classification", "description", };
			for (uint i = 0; i < qnumber(headers); ++i)
				qstrncpy(arrptr[i], headers[i], MAXSTR);
		} else { // regular item
			if (n > operator size_t()) return; //_ASSERTE(n <= operator size_t());
			const item_t &item(items.at(n - 1));
			qsnprintf(arrptr[0], MAXSTR, "%08a", item.ea); //ea2str(item.ea, arrptr[0], MAXSTR);
			switch (item.type) { // category
				case 0x0001: // ignored function / operand untyped
				case 0x000A: // inaccessible label possibly referred (keep raw)
				case 0x000B: // dummy name set
				case 0x000D: // range cloned but not explored
				case 0x004A: // function head having detached chunks
				case 0x0118: // argvalue known
				case 0x0209: // heap block dumped & replicated
				case 0x0219: // mapped import
				case 0x0229: // mapped import
				case 0x0301: // ignored function / operand untyped
				case 0x0004: // special segment
					qstrncpy(arrptr[1], "INFO", MAXSTR);
					break;
				case 0x0008: // ref to tail
				case 0x0021: // ref to align
				case 0x0031: // ref to tail
				case 0x0032: // dword unaligned
				case 0x0200: // access violation? from static data
				case 0x0501: // possible offset in non-dummy region
				case 0x0502: // displacement (indexed array) to single data type
				case 0x0042: // possible offset (not created due to existing type)
				case 0x0043: // possible offset to dynamic data
					qstrncpy(arrptr[1], "DOUBTFUL OFFSET", MAXSTR);
					break;
				case 0x0005: // variable overhang
				case 0x0010: // auto-align?
				//case 0x0105: // variable expansion
				case 0x0205: // variable truncated?
					qstrncpy(arrptr[1], "DATA BOUNDS", MAXSTR);
					break;
				case 0x0002: // indirect but known
				case 0x0003: // indirect but known (address from rti)
				case 0x00FF: // indirect unknown (address from rti)
				case 0x0100: // indirect unknown
				case 0x0006: // formatted data inside function
				case 0x0009: // virgin data inside function
				case 0x0020: // align inside function
				case 0x0029: // unexpected flow after function end, resolver: unexpected function exit
				case 0x0049: // fchunk doesnot return
					qstrncpy(arrptr[1], "CODE CONTINUITY", MAXSTR);
					break;
				case 0x0007: // unexpected code
				case 0x0417: // hole inside variable
				case 0x0517: // unexpected alignment
					qstrncpy(arrptr[1], "DATA CONTINUITY", MAXSTR);
					break;
				case 0x0030: // local struct
				case 0x0039: // enum
				case 0x0601: // unc string
					qstrncpy(arrptr[1], "COMPATIBILITY", MAXSTR);
					break;
				case 0x0041: // patched
					qstrncpy(arrptr[1], "DATA INIT", MAXSTR);
					break;
				case 0x0FFF:
					qstrncpy(arrptr[1], "PROBLEM", MAXSTR);
					break;
				case 0xFFFF:
					qstrncpy(arrptr[1], "CATASTROPHIC", MAXSTR);
					break;
				default:
					qsnprintf(arrptr[1], MAXSTR, "%04hX", item.type);
			}
			if (!item.text.empty())
				qstrncpy(arrptr[2], item.text.c_str(), MAXSTR);
			else
				*arrptr[2] = 0;
		} // regular item
	}
	int GetIcon(ulong n) const {
		if (n == 0) return 38; // list head icon
		if (n > operator size_t()) return -1; //_ASSERTE(n <= operator size_t());
		switch (items.at(n - 1).type) {
			case 0x0001: return  42; // info - ignored function / operand untyped
			case 0x0002: return  84; // known variable flow
			case 0x0003: return  88; // known variable flow (address from rti)
			case 0x0004: return  46; // special segment
			case 0x0006: return   3; // data inside function
			case 0x0009: return  32; // virgin area inside func
			case 0x000A: return  98; // inaccessible label possibly referred (keep raw)
			case 0x000B: return  19; // dummy name set
			case 0x000D: return  30; // range cloned but not explored
			case 0x0020: return  72; // align inside func
			case 0x0029: return  13; // flow continues after func end, resolver: unexpected function exit
			case 0x0030: return  52; // local struct
			case 0x0039: return  63; // local enum
			case 0x0041: return  38; // data different
			case 0x0042: return  20; // possible offset: not created due to existing type
			case 0x0043: return 120; // possible offset: variable points to allocated memory
			case 0x0049: return  86; // fchunk no return
			case 0x004A: return  90; // func head having detached chunks
			case 0x0100: return  78; // unknown flow
			case 0x00FF: return  88; // unknown flow (address from rti)
			//case 0x0105: return  79; // variable expansion
			case 0x0118: return  25; // argvalue known
			case 0x0209: return  47; // heap block dumped & replicated ok
			case 0x0219: return 136; // virtual addr mapped as import
			case 0x0229: return 109; // runtim offset relocated to default image base
			case 0x0301: return  15; // stack variable renamed
			case 0x0501: return  21; // possible offset at non-dummy range
			case 0x0502: return 100; // displacement (indexed array) to single data type
			case 0x0601: return  28; // unicode string warning
			case 0x0FFF: return  60; // problem (generic)
		}
		return __super::GetIcon(n);
	}
} report;

#ifdef _DEBUG

//  data report implementation (debug only) 

static class CStaticDataList : public CIdaChooser {
protected:
	struct item_t : areaex_t {
		string name;

		item_t(const areaex_t &area, const char *name = 0) : areaex_t(area)
			{ if (name != 0) this->name.assign(name); }

		inline operator ea_t() const throw() { return startEA; }
	};

	set<item_t> items;

public:
	operator size_t() const { return items.size(); }

	bool Add(const area_t &area, asize_t size = 0, const char *name = 0)
		{ return items.insert(item_t(area, name)).second; }
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
		static const int widths[] = { 13, 13, 9, 64, };
		choose2(0, -1, -1, -1, -1, this, qnumber(widths), widths, sizer, getl,
			GetTitle(), 111, 1, 0, 0, 0, 0, enter, destroy, 0, 0);
		PLUGIN.flags &= ~PLUGIN_UNL;
		return true;
	}
	void Clear() { items.clear(); }

protected:
	const char *GetTitle() const { return "CSC: variables"; }
	// IDA callback overrides
	void GetLine(ulong n, char * const *arrptr) const {
		if (n == 0) { // header
			static const char *const headers[] = { "start", "end", "size", "name", };
			for (uint i = 0; i < qnumber(headers); ++i)
				qstrncpy(arrptr[i], headers[i], MAXSTR);
		} else { // regular item
			if (n > operator size_t()) return; //_ASSERTE(n <= operator size_t());
			const item_t &item(at(items, n - 1));
			ea2str(item.startEA, arrptr[0], MAXSTR); //qsnprintf(arrptr[0], MAXSTR, "%08a", item.startEA);
			ea2str(item.safeEndEA(), arrptr[1], MAXSTR); //qsnprintf(arrptr[1], MAXSTR, "%08a", item.safeEndEA());
			qsnprintf(arrptr[2], MAXSTR, "%08IX", item.size());
			if (!item.name.empty())
				qstrncpy(arrptr[3], item.name.c_str(), MAXSTR);
			else
				*arrptr[3] = 0;
		} // regular item
	}
	void Enter(ulong n) const {
		_ASSERTE(n > 0);
		//_ASSERTE(n <= operator size_t());
		if (n > operator size_t()) return;
		const item_t &item(at(items, n - 1));
		if (isEnabled(item)) {
			jumpto(item); // TODO: select area
		} else
			MessageBeep(MB_ICONWARNING);
	}
} data_list;

#endif // _DEBUG

//  GLOBAL FUNCTIONS 

class user_abort : public exception {
public:
	const char *what() const throw() { return "user cancel"; }
};

static void Destroy(bool failed = true);
static int ExploreCREF(ea_t caller, ea_t callee, uint level = 0) throw(exception);
static int ExploreDREF(ea_t caller, ea_t callee, uint level = 0) throw(exception);
static int ProcessRange(const area_t &area, uint level) throw(exception);
static uint ResolveNameConflicts();
static void ExplodeExpandedStructs();
static int ExportCustomSection(FILE *, flags_t, const char * = 0) throw(exception);
static uint CleanUp(const char *filename);
static flags_t GetSegment(ea_t);
static void ProcessNewOffset(ea_t from, ea_t to = BADADDR);
static ea_t GetItemStart(ea_t ea);
static string_t GetStringType(const void *buf, size_t bufsize);
static bool GenStringTokens(char *buf, size_t bufsize,
	const void *dump, size_t dumpsize);
static bool GenWStringTokens(wchar_t *buf, size_t bufsize,
	const void *dump, size_t dumpsize);
static void ash_set_masm() throw();
static void ash_set_tasm() throw();
static void ash_set_nasm() throw();
static void ash_set_fasm() throw();
static uint EmuRuntimeData(FILE *);
static uint TransleteExternals(FILE *);
static uint GenWarnings(FILE *);
static INT_PTR CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);

static bool is_thunk_library_func(const func_t *func) {
	return func != 0 && has_name(get_flags_novalue(func->startEA))
		&& func->tailqty == 0 && next_not_tail(func->startEA) == func->endEA
		&& isCode(get_flags_novalue(func->startEA)) && ua_ana0(func->startEA) > 0
		&& is_jump_insn(cmd.itype) && is_libfuncname(calc_reference_target(cmd, 0));
}
static inline bool is_thunk_library_func(ea_t ea)
	{ return is_thunk_library_func(get_func(ea)); }
static bool is_visible_func(const func_t *pfn) {
	segment_t *seg;
	return pfn != 0 && (pfn->flags & FUNC_HIDDEN) == 0
		&& (seg = getseg(pfn->startEA)) != 0 && seg->is_visible_segm();
}
static bool is_hidden_item(ea_t ea) {
	segment_t *seg;
	return (get_aflags(ea) & AFL_HIDDEN) != 0 || (seg = getseg(ea)) != 0
		&& !seg->is_visible_segm();
}
static bool isExcludedExternal(ea_t ea) {
	return isEnabled(ea)
		&& (!prefs.include_thunkfuncs && isFunc(get_flags_novalue(ea))
			&& (is_pure_import_func(ea)
			|| !prefs.include_libitems && is_thunk_library_func(ea))
		|| !prefs.include_libitems && is_libname(ea));
}
static bool IsAddrOffsetable(ea_t ea, bool directly = false) {
	if (!directly) ea = GetItemStart(ea);
	return isEnabled(ea)
		&& (static_ranges.has_address(ea) || isExcludedExternal(ea));
}
static bool CanIncludeFunction(const func_t *func) {
	return func != 0 && (prefs.include_libitems || !is_true_libfunc(func)
		/*|| get_supressed_library_flag(func->startEA) == 1*/)
		&& (prefs.include_thunkfuncs || !is_pure_import_func(func)
			&& (prefs.include_libitems || !is_thunk_library_func(func)))
		&& (prefs.include_hidden || CSC::is_visible_func(func));
}
static bool CanIncludeVariable(ea_t ea) {
	return (prefs.include_libitems || !is_libitem(ea)
		|| get_supressed_library_flag(ea) == 1)
		&& (prefs.include_hidden || !is_hidden_item(ea));
}
static bool Off2Stat(ea_t ea) {
	return isEnabled(ea) && (!prefs.offtohead || points_to_meaningful_head(ea))
		&& (!prefs.offtodefhead || points_to_defitem(ea)) && !is_in_rsrc(ea);
}
static bool Dyn2Stat(ea_t ea) {
	if (!Off2Stat(ea)) return false;
	const flags_t flags(get_flags_novalue(ea));
	return (!prefs.dyndataxplorer_carerefs || hasRef(flags)/* || can_ref_ea(ea)
		&& hasRef(get_flags_novalue(get_item_head(ea)))*/)
		&& (!prefs.dyndataxplorer_carenames || has_any_name(flags) || can_ref_ea(ea)
			&& has_any_name(flags))
		&& (!prefs.dyndataxplorer_carefuncs || get_func(ea) == 0 || isFunc(flags));
}
static bool CanOffFromDyn(ea_t ea) {
	_ASSERTE(prefs.dbg_savedata && prefs.dbg_exploreheaps);
	return prefs.dbg_savedata && prefs.dbg_exploreheaps
		&& prefs.dyndataxplorer_offtostat >= 1 && isEnabled(ea)
		&& (prefs.dyndataxplorer_offtostat >= 2 && static_ranges.has_address(ea)
			|| isExcludedExternal(ea));
}
static bool OffAtBound(ea_t ea) {
	return ea == BADADDR || offset_boundary == 0
		|| (ea & offset_boundary - 1) == 0;
}

static ea_t GetItemStart(ea_t ea) {
	if (!isEnabled(ea)) return BADADDR;
	const ranges_t::const_iterator tmp(static_ranges[ea]);
	if (tmp != static_ranges.end()) return tmp->startEA;
	ea_t item_start;
	func_t *func(get_func(ea));
	if (func != 0)
		item_start = func->startEA;
	else {
		item_start = isVariableEnd(get_flags_novalue(ea)) ?
			ea : prevthat(ea, inf.minEA, isVariableEnd);
		if (item_start == BADADDR) item_start = get_item_head(ea);
		if (func = get_func(item_start)) item_start = func->endEA;
	}
	return item_start;
}

bool range_t::GetLabel(char *buf, size_t bufsize, ea_t target) const {
	_ASSERTE(buf != 0 && bufsize > 0);
	if (buf == 0 || bufsize <= 0) return false;
	for (ea_t ea = startEA; ea < safeEndEA(); ea = nextthat(ea, safeEndEA(),
		TESTFUNC(has_any_name))) if (get_name(BADADDR, ea, buf, bufsize) != 0) {
			if (target == 0) target = startEA;
			if (target != BADADDR && contains(target) && target != ea)
				qsnprintf(tail(buf), bufsize - strlen(buf), "%c0%IXh",
					SIGNED_PAIR(static_cast<adiff_t>(target - ea)));
			return true;
		}
	*buf = 0; //qstrncpy(buf, "<unnamed>", bufsize);
	_RPT4(_CRT_WARN, "%s(..., %08IX): no name within range <%08IX-%08IX>\n",
		__FUNCTION__, target, startEA, safeEndEA());
	return false;
}

bool clonedblock_t::GetLabel(char *buf, size_t bufsize, DWORD dwOffset) const {
	_ASSERTE(buf != 0 && bufsize > 0);
	if (buf == 0 || bufsize <= 0) return false;
	*buf = 0;
	if (dwOffset >= size) {
		_RPT4(_CRT_ASSERT, "%s(..., 0x%lX): offset out of size for %08X (0x%IX)\n",
			__FUNCTION__, dwOffset, BaseAddress, size);
		return false;
	}
	if (!label.empty())
		qstrncpy(buf, label.c_str(), bufsize);
	else
		qsnprintf(buf, bufsize, "%s_%X", clonedname_prefix, BaseAddress);
	make_ident_name(buf, bufsize);
	if (dwOffset > 0)
		qsnprintf(tail(buf), bufsize - strlen(buf), "+0%lXh", dwOffset);
	return true;
}

static bool GetLabel(ea_t ea, char *buf, size_t bufsize) {
	_ASSERTE(buf != 0 && bufsize > 0);
	if (buf == 0 || bufsize <= 0) return false;
	if (isEnabled(ea)) {
		for (ea_t nameea = get_item_head(ea); isEnabled(nameea);
			nameea = prevthat(nameea, inf.minEA, hasAnyName)) {
			if (hasAnyName(get_flags_novalue(nameea)) && IsAddrOffsetable(nameea, true)
				&& get_name(BADADDR, nameea, buf, bufsize) != 0) {
				if (ea > nameea) qsnprintf(tail(buf), bufsize - strlen(buf),
					"+0%IXh", ea - nameea);
				return true;
			} // has name
			if (!IsAddrOffsetable(nameea)) break;
		} // loop
		_RPT3(_CRT_WARN, "%s(%08IX, ...): name not found (nameEA=%08IX)\n",
			__FUNCTION__, ea, nameea);
	} else { // !isEnabled(ea)
		const clonedblocks_t::const_iterator
			bar(cloned_blocks.find(reinterpret_cast<LPCVOID>(ea), false));
		if (bar != cloned_blocks.end()) {
			const bool ok(bar->GetLabel(buf, bufsize, reinterpret_cast<LPCVOID>(ea)));
			_ASSERTE(ok);
			if (ok) return true;
		}
		_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
			"%s(%08IX, ...): ea not found within cloned ranges or %s(...) returned false (range %s found: BaseAddress=%08X)\n",
			__FUNCTION__, ea, "CSC::clonedblock_t::GetLabel",
			bar != cloned_blocks.end() ? "was" : "was not",
			bar != cloned_blocks.end() ? bar->BaseAddress : NULL);
	}
	*buf = 0;
	return false;
}

class exit_scope : public exception {
private:
	string _m_what;
public:
	exit_scope(const char *what = 0) { if (what != 0) _m_what.assign(what); }
	const char *what() const { return _m_what.c_str(); }
};

//  tracer classes declaration 

class CTracer : public CDebugger {
protected:
	mutable uint run_counter;
	mutable modules_t::const_iterator module;

	virtual void OnModuleAvailable() const = 0;

	// overrides
	void OnCreateProcess() const;
	void OnLoadDll(const module_t &) const;
	void OnUnloadDll(const module_t &module) const {
		__super::OnUnloadDll(module);
		if (is_dll && isLoaded() && module == *this->module) {
			this->module = modules.end();
			Terminate();
		}
	}
	void OnExitProcess() const {
		__super::OnExitProcess();
		module = modules.end();
	}

public:
	mutable int total_ranges;
	mutable bool is_dll;

	// construction
	CTracer() : CDebugger(TRUE/*bQuiet*/), module(modules.end()) {
		bIgnoreExternalExceptions = TRUE;
		//bUseDbgHelp = FALSE;
	}

	bool isLoaded() const { return module != modules.end(); }
	virtual void Reset() { // called before 1st usage for each dump
		_ASSERTE(module == modules.end()); //module = modules.end(); // should always be set by constructor and EXIT_PROCESS_DEBUG_EVENT
		run_counter = 0;
		is_dll = false;
		total_ranges = 0;
	}
};

static class CResolver : public CTracer {
	friend int CSC::ExploreCREF(ea_t , ea_t, uint); // set SW breakpoint
private:
	mutable ea_t caller_ea, exit_ea;
	mutable bool resolving_active;
public:
	bool single_range;

private:
	static cref_t GetCRefType(const insn_t &cmd);
	void NameAnonOffsets(ea_t to, const char *tgtname, const char *cmt = 0) const;
protected:
	// overloads
	void OnModuleAvailable() const;
	DWORD OnBreakpoint(breakpoint_type_t, LPVOID) const;
	DWORD OnSingleStep() const;
	void OnCrash() const;
} resolver;

static class CDumper : public CTracer {
private:
	mutable DWORD root_stack, root_bp;
	mutable struc_t root_frame;
	mutable asize_t root_arglist;
	mutable LPCVOID lpStackTop;
	mutable bool have_patched;
	mutable boost::scoped_ptr<heapmgr> winheap;
	mutable const range_t *range;
	mutable boost::optional<refinfo_t> refinfo;
	// compiler-specific specialisations of heap structure lists
	mutable class customheapmgr : public hash_set<memblock_t, memblock_t::hash/*boost::hash<memblock_t>*/> {
	public:
		const_iterator find(LPCVOID address, bool exact = false) const {
			return exact ? __super::find(address) : find_if(begin(), end(),
				boost::bind2nd(boost::mem_fun_ref(memblock_t::has_address), address));
		}
	} VCLheap, BCCheap, GNUheap, VCSBheap;
	mutable hash_set<LPCVOID, boost::hash<LPCVOID> > refused_for_address;
	mutable string cmt;
	mutable char tmpstr[MAXSTR], name[MAXNAMESIZE], basename[_MAX_FNAME];
	mutable uint8 buf[0x10];
	bool hasVCLMemFunction;
public:
	mutable bool used_translation;

private:
	ea_t TryOffset(void *buffer, size_t referreroffset, ea_t referrer = BADADDR,
#ifdef _DEBUG
		asize_t = 0,
#endif // _DEBUG
		uint level = 0) const throw(exception);
	pair<clonedblocks_t::iterator, bool> AddClonedRange(LPCVOID BaseAddress,
		SIZE_T dwSize, DWORD dwBaseOffset, LPCVOID referrer = (LPCVOID)BADADDR,
		DWORD referrer_offset = 0, const char *label = 0, const char *comment = 0) const throw(exception);
	// Virtual memory and heap parsers
	memblock_t FindVCLBlock(LPCVOID Address, bool bExactMatch = false) const;
	memblock_t FindBCCBlock(LPCVOID Address, bool bExactMatch = false) const;
	memblock_t FindGNUCBlock(LPCVOID Address, bool bExactMatch = false) const;
	memblock_t FindVcSbhBlock(LPCVOID Address, bool bExactMatch = false) const;
	memblock_t FindVirtAllocBlock(LPCVOID Address, bool bExactMatch = false) const;
	memblock_t FindStkVar(LPCVOID Address, DWORD caller_stack,
		asize_t caller_arglist, struc_t *caller_frame, const member_t *&,
		DWORD caller_bp = 0, bool bExactMatch = false) const;
	void ShoutEAVWarning(ea_t referrer, const char *format, const char *object,
		LPCVOID baseaddr, SIZE_T size = 0) const;
	bool MakeStaticOffset(ea_t ea, struc_t *struc, member_t *member) const;
	uint8 getStrucRefType(struc_t *&struc, ea_t stroff, member_t *&member) const;
	uint8 getStatRefType(ea_t ea, struc_t *&struc, member_t *&member) const;

protected:
	// overloads
	void OnModuleAvailable() const;
	DWORD OnBreakpoint(breakpoint_type_t, LPVOID) const;

public:
	//CDumper() : winheap(heapmgr(*this)) { }

	void Reset() {
		__super::Reset();
		have_patched = false;
		total_virtual_ranges = 0;
	}
	void RestorePatchedAreas() const;
	static uint RestorePatchedBytes(nodeidx_t ea);
} dumper;

bool Execute() {
	ea_t scan;
	areaex_t area;
	if (!read_selection(area)) {
		area.startEA = get_screen_ea();
		area.endEA = next_not_tail(area.startEA);
		if (area.endEA == BADADDR) area.endEA = inf.maxEA;
	}
	func_t *topfunc;
	if ((topfunc = get_func(area.startEA))) area.startEA = topfunc->startEA;
	if ((topfunc = get_func(prev_not_tail(area.endEA))))
		area.endEA = topfunc->endEA;
	if ((bool)last && area != last && MessageBox(get_ida_hwnd(),
		"csc was aborted last run, use previous selection?",
		PLUGINNAME " v" PLUGINVERSIONTEXT, MB_ICONQUESTION | MB_YESNO) == IDYES) {
		area = last;
	}
	if (DialogBox(hInstance, MAKEINTRESOURCE(IDD_CSC), get_ida_hwnd(), DialogProc) != IDOK) return false;
	if (prefs.dbg_savedata && prefs.dbg_exploreheaps && default_compiler() == COMP_UNK
		&& MessageBox(get_ida_hwnd(),
		"cloning of process virtual data was selected despite unknown\n"
		"compiler is set: correct heap structure may not be correctly\n"
		"identified thus heap virtual data won't be available.\n\n"
		"run snippet creator anyway?", PLUGINNAME " v" PLUGINVERSIONTEXT,
		MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
		MessageBeep(MB_ICONEXCLAMATION);
		return false;
	}
	if (!decide_ida_bizy("code snippet creator")) {
		// Let the analysis make all data references to avoid variables merging.
		if (prefs.verbosity >= 1) cmsg << prefix << "autoanalysis is running now. call me again when finished" << endl;
		MessageBeep(MB_ICONEXCLAMATION);
		return false;
	}
	options = get_plugin_options("csc");
	scan = area.startEA;
	while (scan < area.endEA) { // has root selection any acceptable function?
		if ((topfunc = get_func(scan)) != 0) {
			if (CanIncludeFunction(topfunc)) break;
			scan = get_fchunk(scan)->endEA;
		}
		scan = next_not_tail(scan);
	} // has root eslection any acceptable function?
	if (scan >= area.endEA) {
		warning("aborted: selection has no valid function(s), change the selection so\n"
			"it contains at least one function passing the function filters in\n"
			"start dialog, or redefine function filters");
		return false;
	}
	wait_box.open("%s", deflt_wait_banner);
	_ASSERTE(static_ranges.empty());
	_ASSERTE(cloned_blocks.empty());
	_ASSERTE(breakpoints.empty());
	_ASSERTE(externals.empty());
	_ASSERTE(imports.empty());
	_ASSERTE(dummy_labels.empty());
	_ASSERTE(log_addresses.empty());
	_ASSERTE(segs_used.empty());
	_ASSERTE(excluded_symbols.empty());
	// initialize everything
	/*lastrefresh = */start = time(0);
	have_unc = false;
	total_ranges = 0;
	total_arrays = 0;
	total_offsets = 0;
	total_funcs = 0;
	total_vars = 0;
	fatals = 0;
	last = area;
	total_bytes = 0;
	pBatchResults = (CBatchResults *)GetProcAddress(GetModuleHandle("fubar.plw"),
		"?batchlist@@3VCBatchResults@@A");
	if (pBatchResults != 0 && *pBatchResults <= 0) pBatchResults = 0; // only add to existing list
	bool rtrlistwasopen, reportwasopen(report > 0);
	report.Clear();
	_ASSERTE(!resolver.isLoaded());
	_ASSERTE(!dumper.isLoaded());
	if (prefs.dbg_resolve) rtrlistwasopen = rtrlist > 0;
#ifdef _DEBUG
	bool datalistwasopen(data_list > 0);
	data_list.Clear();
#endif
	if (prefs.verbosity >= 1) cmsg << prefix <<
		"code snippet creator starting at " << asea(area.startEA);
	graph.Reset();
	// construct output files names
	char outputfn[QMAXPATH];
	if (get_func_name(area.startEA, CPY(outputfn)) != 0) {
		if (prefs.verbosity >= 1) cmsg << " (" << outputfn << ')';
	} else
		qsnprintf(CPY(outputfn), "sub_%08a", area.startEA);
	if (prefs.verbosity >= 1) cmsg << endl;
	func_t funcbuf;
	try { // walk the selection
		wait_box.open("%s\n(gathering static ranges)", deflt_wait_banner);
		scan = area.startEA;
		while (scan < area.endEA) {
			if ((topfunc = get_func(scan)) != 0) { // regular function
				scan = topfunc->endEA;
				if (CanIncludeFunction(topfunc)) {
					func_tail_iterator_t fti(&(funcbuf = *topfunc));
					for (bool ok = fti.main(); ok; ok = fti.next())
						total_ranges += ExploreCREF(BADADDR, fti.chunk().startEA);
				} else
					if (prefs.verbosity >= 3) cmsg << prefix <<
						"  info: ignoring disabled function at " <<
						asea(topfunc->startEA) << " on request" << endl;
				continue;
			} // is function
			const flags_t flags(get_flags_novalue(scan));
			if (!isCode(flags) && (flags & MS_COMM & FF_BOUNDARY) != 0
				&& !isAlign(flags) && !isCode(flags))
				total_ranges += ExploreDREF(BADADDR, scan); // orphan DATA
			scan = next_not_tail(scan);
		} // selection walk
	} catch (const exception &e) {
		total_ranges = -1;
		if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " <<
			e.what() << ", aborting" << endl;
	}
	wait_box.close();
	OPENFILENAME ofn;
	memset(&ofn, 0, sizeof OPENFILENAME);
	ofn.lStructSize = sizeof OPENFILENAME;
	ofn.hwndOwner = get_ida_hwnd();
	ofn.hInstance = hInstance;
	ofn.nFilterIndex = 1;
	ofn.nMaxFile = QMAXPATH;
	time_t duration(0);
	if (total_ranges > 0 && fatals <= 0) try {
		if (prefs.verbosity >= 1) cmsg << prefix <<
			"deadcode traversal finished, total " << dec << total_ranges <<
			" known ranges" << endl;
		if (prefs.dbg_resolve && breakpoints.empty()) prefs.dbg_resolve = false;
		// dbg_savedata executed unconditionally: always examine param values
		char exepath[QMAXPATH];
		if (prefs.dbg_resolve || prefs.dbg_savedata) {
			if (prefs.dbg_resolve) resolver.Reset();
			if (prefs.dbg_savedata) dumper.Reset();
			const ssize_t s = netnode("$ loader").valstr(CPY(exepath));
			if (s > 0) {
				resolver.is_dll = true;
				dumper.is_dll = true;
			} else
				get_input_file_path(CPY(exepath));
			if (!qfileexist(exepath))
				if (!prefs.unattended) {
					ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
						OFN_LONGNAMES | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
						OFN_HIDEREADONLY;
					ofn.lpstrFile = exepath;
					ofn.lpstrFilter = "Win32 applications\0*.exe\0all files\0*.*\0";
					ofn.lpstrTitle = s <= 0 ? "host application not found, locate it..." :
						"disassemblee is a dll, please locate a host loader first (must be directly executable)...";
					ofn.lpstrDefExt = "exe";
					char drive[_MAX_DRIVE], dir[_MAX_DIR], path[QMAXPATH];
					get_input_file_path(CPY(path));
					_splitpath(path, drive, dir, 0, 0);
					_makepath(path, drive, dir, 0, 0);
					ofn.lpstrInitialDir = path;
					duration = time(0) - start;
					wait_box.close_all();
					if (!GetOpenFileName(&ofn)) {
						wait_box.open("%s", deflt_wait_banner);
						start = time(0);
						if (prefs.verbosity >= 1) cmsg << prefix << "runtime features skipped" << endl;
						throw exit_scope("no related executable available");
					}
					start = time(0);
					if (s > 0)
						netnode("$ loader", 0, true).set(exepath);
					else if (MessageBox(get_ida_hwnd(),
						"remember new root?", PLUGINNAME " v" PLUGINVERSIONTEXT,
						MB_ICONQUESTION | MB_YESNO) == IDYES)
						change_root(exepath);
					wait_box.open("%s", deflt_wait_banner);
				} else {
					if (prefs.verbosity >= 1) cmsg << prefix << "target is missing, cannot execute in unattended mode" << endl;
					throw exit_scope("no related executable available");
				}
		} // verify exename
		do { // resolve indirect references
			if (prefs.dbg_resolve) {
				ea_t lastfuncEA(BADADDR);
				resolver.single_range = true;
				scan = area.startEA;
				while (scan < area.endEA) {
					if ((topfunc = get_func(scan)) != 0) {
						scan = topfunc->endEA;
						if (CanIncludeFunction(topfunc)) {
							func_tail_iterator_t fti(&(funcbuf = *topfunc));
							for (bool ok = fti.main(); ok; ok = fti.next()) {
								breakpoints.set(fti.chunk().startEA, 2);
								const ea_t lastinsn(prev_head(fti.chunk().endEA, fti.chunk().startEA));
								if (lastinsn > fti.chunk().startEA) breakpoints.set(lastinsn, 4);
								for (ea_t ea = next_head(fti.chunk().startEA, fti.chunk().endEA);
									ea < fti.chunk().endEA; ea = next_head(ea, fti.chunk().endEA))
									if (is_flowchange_insn(ea)) breakpoints.set(ea, 4);
							}
						} // function match rules
						if (lastfuncEA != BADADDR && lastfuncEA != topfunc->startEA)
							resolver.single_range = false;
						lastfuncEA = topfunc->startEA;
						continue;
					} // is function
					scan = next_not_tail(scan);
				} // selection walk
			resolveagain:
				wait_box.open("%s\n(indirect flow resolving)", deflt_wait_banner);
				switch (resolver.DebugProcess(exepath)) {
					//case (DWORD)-1L: if (prefs.verbosity >= 1) cmsg << prefix << "the app crushed!" << endl; break;
					case (DWORD)-2L:
						if (prefs.verbosity >= 1) cmsg << prefix << "programfile not found!" << endl;
						_RPTF3(_CRT_ASSERT, "%s(): %s(\"%s\"): file doesnot exist\n",
							__FUNCTION__, "CDebugger::DebugProcess", exepath);
						break;
					case (DWORD)-3L: if (prefs.verbosity >= 1) cmsg << prefix << "target not a valid pe file!" << endl; break;
					case (DWORD)-4L: if (prefs.verbosity >= 1) cmsg << prefix << "the app failed to start!" << endl; break;
					case (DWORD)-5L:
						if (!prefs.unattended) {
							wait_box.close();
							ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
								OFN_LONGNAMES | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
								OFN_HIDEREADONLY;
							ofn.lpstrFile = exepath;
							ofn.lpstrFilter = "Win32 applications\0*.exe\0all files\0*.*\0";
							ofn.lpstrTitle = "disassemblee is a dll, please locate a host loader first (must be directly executable)...";
							ofn.lpstrDefExt = "exe";
							char drive[_MAX_DRIVE], dir[_MAX_DIR], path[QMAXPATH];
							get_input_file_path(CPY(path));
							_splitpath(path, drive, dir, 0, 0);
							_makepath(path, drive, dir, 0, 0);
							ofn.lpstrInitialDir = path;
							duration = time(0) - start;
							wait_box.close_all();
							if (!GetOpenFileName(&ofn)) {
								start = time(0);
								wait_box.open("%s", deflt_wait_banner);
								if (prefs.verbosity >= 1) cmsg << prefix << "debugger parts skipped" << endl;
								throw exit_scope("no loader for dll");
							}
							start = time(0);
							wait_box.open("%s", deflt_wait_banner);
							resolver.is_dll = true;
							dumper.is_dll = true;
							netnode("$ loader", 0, true).set(exepath);
							goto resolveagain;
						} else
							if (prefs.verbosity >= 1) cmsg << prefix <<
								"target is a dll, cannot execute in unattended mode" << endl;
						break;
				} // switch
				wait_box.close();
				_ASSERTE(!resolver.isLoaded());
				if (resolver.total_ranges == -1) total_ranges = -1;
				if (fatals > 0 || resolver.total_ranges == -1
					|| dumper.total_ranges > 0 && resolver.total_ranges == 0) break;
				if (resolver.total_ranges > 0) {
					if (prefs.verbosity >= 1) cmsg << prefix << "another " << dec <<
						resolver.total_ranges << " areas were found by runtime check" << endl;
					total_ranges += resolver.total_ranges;
				}
			} // prefs.dbg_resolve
			if (prefs.dbg_savedata) {
				scan = area.startEA;
				while (scan < area.endEA) {
					if ((topfunc = get_func(scan)) != 0) {
						scan = topfunc->endEA;
						if (CanIncludeFunction(topfunc)) {
							func_tail_iterator_t fti(&(funcbuf = *topfunc));
							for (bool ok = fti.main(); ok; ok = fti.next())
								breakpoints.set(fti.chunk().startEA, 2);
						}
						continue;
					} // function
					scan = next_not_tail(scan);
				} // selection walk
			dumpagain:
				wait_box.open("%s\n(gathering process data)", deflt_wait_banner);
				switch (dumper.DebugProcess(exepath)) {
					//case (DWORD)-1L: if (prefs.verbosity >= 1) cmsg << prefix << "the app crushed!" << endl; break;
					case (DWORD)-2L:
						if (prefs.verbosity >= 1) cmsg << prefix << "programfile not found!" << endl;
						_RPTF3(_CRT_ASSERT, "%s(): %s(\"%s\"): file doesnot exist\n",
							__FUNCTION__, "CDebugger::DebugProcess", exepath);
						break;
					case (DWORD)-3L: if (prefs.verbosity >= 1) cmsg << prefix << "target not a valid pe file!" << endl; break;
					case (DWORD)-4L: if (prefs.verbosity >= 1) cmsg << prefix << "the app failed to start!" << endl; break;
					case (DWORD)-5L:
						if (!prefs.unattended) {
							wait_box.close();
							ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
								OFN_LONGNAMES | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
								OFN_HIDEREADONLY;
							ofn.lpstrFile = exepath;
							ofn.lpstrFilter = "Win32 applications\0*.exe\0all files\0*.*\0";
							ofn.lpstrTitle = "disassemblee is a dll, please locate a host loader first (must be directly executable)...";
							ofn.lpstrDefExt = "exe";
							char drive[_MAX_DRIVE], dir[_MAX_DIR], path[QMAXPATH];
							get_input_file_path(CPY(path));
							_splitpath(path, drive, dir, 0, 0);
							_makepath(path, drive, dir, 0, 0);
							ofn.lpstrInitialDir = path;
							duration = time(0) - start;
							wait_box.close_all();
							if (!GetOpenFileName(&ofn)) {
								start = time(0);
								wait_box.open("%s", deflt_wait_banner);
								if (prefs.verbosity >= 1) cmsg << prefix << "debugger parts skipped" << endl;
								throw exit_scope("no loader for dll");
							}
							start = time(0);
							wait_box.open("%s", deflt_wait_banner);
							resolver.is_dll = true;
							dumper.is_dll = true;
							netnode("$ loader", 0, true).set(exepath);
							goto dumpagain;
						} else
							if (prefs.verbosity >= 1) cmsg << prefix <<
								"target is a dll, cannot execute in unattended mode" << endl;
						break;
				} // switch
				wait_box.close();
				_ASSERTE(!dumper.isLoaded());
				if (dumper.total_ranges == -1) total_ranges = -1;
				if (dumper.total_ranges > 0 && fatals <= 0) {
					if (prefs.verbosity >= 1) cmsg << prefix << "another " << dec <<
						dumper.total_ranges << " areas were found by offsets in runtime data" << endl;
					total_ranges += dumper.total_ranges;
				} // dumper ok
			} // initializing variables
		} while (prefs.circulated_resolving && prefs.dbg_resolve
			&& prefs.dbg_savedata && fatals <= 0 && dumper.total_ranges > 0);
	} catch (const exit_scope &e) { /* normal */ }
	if (report > 0)
		if (!reportwasopen)
			report.Open();
#if IDA_SDK_VERSION >= 520
		else
			report.Refresh();
#endif
#if IDP_INTERFACE_VERSION >= 76
	else
		report.Close();
#endif
	if (prefs.dbg_resolve && rtrlist > 0)
		if (!rtrlistwasopen)
			rtrlist.Open();
#if IDA_SDK_VERSION >= 520
		else
			rtrlist.Refresh();
#endif
#if IDP_INTERFACE_VERSION >= 76
// 	else
// 		rtrlist.Close();
#endif
#ifdef _DEBUG
	if (data_list > 0)
		if (!datalistwasopen)
			data_list.Open();
#if IDA_SDK_VERSION >= 520
		else
			data_list.Refresh();
#endif
#if IDP_INTERFACE_VERSION >= 76
	else
		data_list.Close();
#endif
#endif // _DEBUG
	if (total_ranges >= 0 && fatals > 0) {
		if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " << dec << fatals <<
			" integrity error(s) on code or data traversal (see report for details)" << endl;
		total_ranges = -1;
	}
	if (total_ranges <= 0) {
		Destroy();
		MessageBeep(MB_ICONEXCLAMATION);
		if (total_ranges == 0) {
			if (prefs.verbosity >= 1) cmsg << prefix <<
				"no exportable snippets found within selection" << ", giving up" << endl;
			last.clear();
		}
		return false;
	}
	if (prefs.verbosity >= 1) {
		cmsg << prefix << "code snippet creator finished with " << dec;
		if (prefs.dbg_savedata && prefs.dbg_exploreheaps) {
			cmsg << total_ranges + total_virtual_ranges << " areas collected (" <<
				total_virtual_ranges << " emulated)" << endl;
		} else
			cmsg << total_ranges << " areas collected" << endl;
	}
	validate_filename(outputfn); // replace non-os compliant characters
	char drive[_MAX_DRIVE], dir[_MAX_DIR], path[QMAXPATH];
	_splitpath(database_idb, drive, dir, 0, 0);
	if (prefs.unattended) {
		_makepath(path, drive, dir, outputfn, "asm");
		qstrcpy(outputfn, path);
	} else { // ask for savename
		ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
			OFN_LONGNAMES | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST |
			OFN_HIDEREADONLY;
		qstrcat(outputfn, ".asm");
		ofn.lpstrFile = outputfn;
		ofn.lpstrFilter = "assembler sources (*.asm)\0*.asm;*.S\0all files\0*.*\0";
		ofn.lpstrTitle = "select destination file name";
		ofn.lpstrDefExt = "asm";
		_makepath(path, drive, dir, 0, 0);
		ofn.lpstrInitialDir = path;
		duration += time(0) - start;
		wait_box.close_all();
		if (!GetSaveFileName(&ofn)) {
			Destroy();
			if (prefs.verbosity >= 1) cmsg << prefix << "user cancel" << endl;
			return false;
		}
		wait_box.open("%s", deflt_wait_banner);
		start = time(0);
	}
	wait_box.open("%s\n(finalization)", deflt_wait_banner);
	if (prefs.destroy_structs) {
		ExplodeExpandedStructs();
		if (wasBreak()) {
			Destroy();
			if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " <<
				user_abort().what() << ", aborting" << endl;
			clearBreak();
			return false;
		}
	}
	uint names_resolved(0);
	if (prefs.resolve_names) {
		names_resolved = ResolveNameConflicts();
		if (wasBreak()) {
			Destroy();
			if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " <<
				user_abort().what() << ", aborting" << endl;
			clearBreak();
			return false;
		}
	}
#ifdef _DEBUG
	for (ranges_t::iterator tmp = static_ranges.begin();
		(tmp = find_if(tmp, static_ranges.end(),
		boost::mem_fun_ref(range_t::isData))) != static_ranges.end(); ++tmp) {
		const ea_t lastea(prev_not_tail(tmp->endEA));
		_ASSERTE(lastea >= tmp->startEA);
		char s[MAXNAMESIZE];
		if (!GetLabel(lastea, CPY(s)))
			_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
				"%s(): %s(%08IX, ...) returns false for range <%08IX-%08IX>\n",
				__FUNCTION__, "CSC::GetLabel", lastea, tmp->startEA, tmp->endEA);
		if (!tmp->GetLabel(CPY(s)))
			_RPT4(_CRT_WARN, "%s(): %s(...) returns false for range <%08IX-%08IX>\n",
				__FUNCTION__, "CSC::range_t::GetLabel", tmp->startEA, tmp->endEA);
	}
#endif // _DEBUG
	if (total_offsets > 0 || total_arrays > 0 || names_resolved > 0) {
		if (prefs.verbosity >= 1) cmsg << prefix << "total " << dec <<
			total_offsets << " new offsets recognized, total " <<
			total_arrays << " variables packaged, total " <<
			names_resolved << " name conflicts resolved" << endl;
	}
	/*for (ranges_t::const_iterator range = static_ranges.begin(); range != static_ranges.end(); ++range)
		if (net_patch.altval(range->startEA, 'p') > 0) break;
	if (range != static_ranges.end()) {
		if (prefs.verbosity >= 1) cmsg << prefix <<
			"moving all data to same section due to initialization...";
		for (range = static_ranges.begin(); range != static_ranges.end(); ++range)
			if (range->type == FF_CONST || range->type == FF_BSS) range->type = FF_DATA;
		if (prefs.verbosity >= 1) cmsg << "done" << endl;
	} else */if (!prefs.include_libitems && (prefs.reloc_extfn_offs || prefs.reloc_extvar_offs)) {
		for (remappoints_t::const_iterator iter = externals.begin(); iter != externals.end(); ++iter) {
			if (wasBreak()) break;
			ranges_t::iterator range(static_ranges.find(*iter));
			if (range != static_ranges.end() && range->type == FF_CONST) {
				if (prefs.verbosity >= 1) cmsg << prefix <<
					"moving const data to writable section due to runtime extarnals translation...";
				for (range = static_ranges.begin(); (range = find_if(range, static_ranges.end(),
					boost::bind2nd(boost::mem_fun_ref(range_t::is_of_type), FF_CONST))) != static_ranges.end(); ++range)
					range->type = FF_DATA;
				if (prefs.verbosity >= 1) cmsg << "done" << endl;
				break;
			}
		}
	}
	if (wasBreak()) {
		Destroy();
		if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " <<
			user_abort().what() << ", aborting" << endl;
		clearBreak();
		return false;
	}
	wait_box.change("%s\n(output writing)", deflt_wait_banner);
	boost::scoped_ptr<asm_t> ash_backup;
	if (prefs.asm_model != asm_none) {
		ash_backup.reset(new asm_t);
		if (!ash_backup) {
			_RPT2(_CRT_ERROR, "%s(...): failed to allocate new object (%s)\n",
				__FUNCTION__, "asm_t");
			throw bad_alloc();
		}
		*ash_backup = ash;
	}
	switch (prefs.asm_model) { // define target assembler model if specified
		case asm_masm: ash_set_masm(); break;
		case asm_ideal: ash_set_tasm(); break;
		case asm_nasm: ash_set_nasm(); break;
		case asm_fasm: ash_set_fasm(); break;
		default:
			code_sec = ".code";
			data_sec = ".data";
			const_sec = ".const";
			bss_sec = ".data?";
			proc_start = "%s proc near";
			proc_end = "%s endp";
	}
	if (prefs.asm_model != asm_none && prefs.verbosity >= 1) cmsg << prefix <<
		"target assembler set to " << ash.name << endl;
	if (prefs.verbosity >= 1) cmsg << prefix << "writing static ranges...";
	FILE *outfile(fopenWT(outputfn));
	string assm;
	// prologue
	get_input_file_path(CPY(path));
	_sprintf(assm, "\n%s\n%s Generated by Code snippet creator IDA Pro plugin v" PLUGINVERSIONTEXT "\n"
		"%s (c) 2003-2008 servil, semteksoft corporation, inc.\n%s Host module: %s\n%s\n",
		ash.cmnt, ash.cmnt, ash.cmnt, ash.cmnt, path, ash.cmnt);
	ewrite(outfile, assm.data(), assm.length());
	int totallines(5);
	switch (prefs.asm_model) {
		case asm_masm: {
			char proc_name[9];
			inf.get_proc_name(proc_name);
			uint16 intel_family;
			char pmode;
			if (qsscanf(proc_name, "80%hu%c", &intel_family, &pmode) < 1) {
				intel_family = 686;
				pmode = 'p';
				_RPT2(_CRT_WARN, "%s(...): processor name not of known ix86 type (%s)\n",
					__FUNCTION__, proc_name);
			}
			_sprintf(assm, "\n.%hu%s\n", intel_family, pmode == 'p' ? "p" : "");
			ewrite(outfile, assm.data(), assm.length());
			totallines += 2;
			if (intel_family >= 586/* && pmode == 'p'*/) {
				ewrite(outfile, SIZEDTEXT(".mmx\n.xmm\n"));
				totallines += 2;
			}
			if (intel_family >= 686 && pmode == 'p') {
				ewrite(outfile, SIZEDTEXT(".k3d\n"));
				++totallines;
			}
			_sprintf(assm, ".model flat, %s\n",
				get_cc(inf.cc.cm) == CM_CC_CDECL ? "C" :
				get_cc(inf.cc.cm) == CM_CC_PASCAL ? "pascal" : "stdcall");
			assm.append("option casemap: none\n");
			ewrite(outfile, assm.data(), assm.length());
			totallines += 2;
			totallines += GenWarnings(outfile);
			assm.clear();
			if (segs_used.count(R_es) > 0) assm.append("es: nothing, ");
			//if (segs_used.count(R_cs) > 0) assm.append("cs: _text, ");
			//if (segs_used.count(R_ds) > 0) assm.append("ds: _data, ");
			//if (segs_used.count(R_ss) > 0) assm.append("ss: nothing, ");
			if (segs_used.count(R_fs) > 0) assm.append("fs: nothing, ");
			if (segs_used.count(R_gs) > 0) assm.append("gs: nothing, ");
			if (!assm.empty()) {
				assm.insert(0, "\nassume ");
				assm.replace(assm.length() - 2,
					static_cast<string::size_type>(string::npos), "\n");
				ewrite(outfile, assm.data(), assm.length());
				totallines += 2;
			}
			if (have_unc) {
				_sprintf(assm, "\nunicode macro page,string,zero\n"
					"\tirpc c,<string>\n"
					"\t%s %c&c%c, page\n"
					"\tendm\n"
					"\tifnb <zero>\n"
					"\tdw zero\n"
					"\tendif\n"
					"endm\n", ash.a_byte, ash.accsep, ash.accsep);
				ewrite(outfile, assm.data(), assm.length());
				totallines += 9;
			}
			break;
		} // asm_masm
		case asm_ideal:
			// TODO: prologue for TASM
			totallines += GenWarnings(outfile);
			break;
		case asm_fasm:
			// TODO: prologue for FASM
			totallines += GenWarnings(outfile);
			break;
		case asm_nasm:
			// TODO: prologue for NASM
			totallines += GenWarnings(outfile);
			break;
		default:
			totallines += GenWarnings(outfile);
	} // asm model switch
	// static sections
	uint8 s_cmtflg;
	try {
		// force show anything hidden to ensure full listing
		if (prefs.include_hidden) {
			s_cmtflg = inf.s_cmtflg; // backup current
			inf.s_cmtflg |= SW_SHHID_ITEM | SW_SHHID_FUNC | SW_SHHID_SEGM;
		}
		// typeinfo
		if (prefs.include_typedefs) {
			const int tmp(gen_file(OFILE_ASM, outfile,
				BADADDR, BADADDR, GENFLG_ASMTYPE | GENFLG_ASMINC));
			if (tmp == -1) throw runtime_error("gen_file(OFILE_ASM, ..., BADADDR, BADADDR, GENFLG_ASMTYPE|GENFLG_ASMINC): error");
			totallines += tmp;
		}
		// flush sections to file
		totallines += ExportCustomSection(outfile, FF_XTRN) +
			ExportCustomSection(outfile, FF_CODE, code_sec);
		static_ranges.sort(); // all data blocks in same order as in host
		_sprintf(assm, "%s %s initialised", data_sec, ash.cmnt);
		totallines += ExportCustomSection(outfile, FF_DATA, assm.c_str());
		_sprintf(assm, "%s %s read/only", const_sec, ash.cmnt);
		totallines += ExportCustomSection(outfile, FF_CONST, assm.c_str());
		_sprintf(assm, "%s %s uninitialised", bss_sec, ash.cmnt);
		totallines += ExportCustomSection(outfile, FF_BSS, assm.c_str());
	} catch (const exception &e) {
		Destroy();
		if (prefs.include_hidden) inf.s_cmtflg = s_cmtflg;
		if (ash_backup) ash = *ash_backup;
		if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " << e.what() <<
			", giving up" << endl;
		return false;
	}
	if (prefs.include_hidden) inf.s_cmtflg = s_cmtflg;
	if (prefs.verbosity >= 1) cmsg << "done" << endl;
	// virtual sections
	if (!cloned_blocks.empty() || !imports.empty())
		totallines += EmuRuntimeData(outfile);
	if (wasBreak()) {
		if (ash_backup) ash = *ash_backup;
		Destroy();
		eclose(outfile);
		if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " <<
			user_abort().what() << ", giving up" << endl;
		clearBreak();
		return false;
	}
	if (/*!prefs.include_libitems && (prefs.reloc_extfn_offs
		|| prefs.reloc_extvar_offs)*/!externals.empty())
		totallines += TransleteExternals(outfile);
	if (wasBreak()) {
		if (ash_backup) ash = *ash_backup;
		Destroy();
		eclose(outfile);
		if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " <<
			user_abort().what() << ", giving up" << endl;
		clearBreak();
		return false;
	}
	// epilogue
	_sprintf(assm, "\n%s\n", ash.end);
	ewrite(outfile, assm.data(), assm.length());
	totallines += 2;
	eclose(outfile);
	if (ash_backup) {
		ash = *ash_backup;
		ash_backup.reset();
	}
	if (prefs.verbosity >= 1) cmsg << prefix << "output file `" << outputfn <<
		"` successfully generated, " << dec << totallines << " lines written" << endl;
	// cleanup
	if (prefs.do_wipeout) CleanUp(outputfn);
	if (wasBreak()) {
		Destroy();
		if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " <<
			user_abort().what() << ", giving up" << endl;
		clearBreak();
		return false;
	}
	wait_box.close_all();
	if (prefs.create_graph) {
		graph.Open();
#if defined(_DEBUG) && IDA_SDK_VERSION >= 510
		if (graph.IsAvail()) graph.OpenGdl();
#endif
	}
#if IDA_SDK_VERSION >= 510
	else
		graph.Close();
#endif
	// external filter
	if (prefs.exec_flt && prefs.fltcommand[0] != 0) {
		assm.assign(prefs.fltcommand);
		if (boost::icontains(assm, "%l")) {
			string tmp(outputfn);
			if (boost::find_token(tmp, boost::is_space()))
				tmp.insert((string::size_type)0, 1, '\"').push_back('\"');
			boost::ireplace_all(assm, "%l", tmp);
		}
		if (boost::icontains(assm, "%s")) {
			char shortname[QMAXPATH];
			GetShortPathName(outputfn, CPY(shortname));
			boost::ireplace_all(assm, "%s", shortname);
		}
		if (prefs.verbosity >= 1) cmsg << prefix <<
			"running external filter on output:" << endl << prefix << "  " << assm << endl;
		STARTUPINFO si;
		GetStartupInfo(&si);
		si.lpTitle = "Code snippet creator";
		si.wShowWindow = SW_SHOWMINIMIZED;
		PROCESS_INFORMATION pi;
		CreateProcess(NULL, (LPSTR)assm.c_str(), NULL, NULL, NULL,
			CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &si, &pi);
	}
	// get totals
	total_bytes[0] += static_ranges.accumulate(FF_CODE);
	total_bytes[1] += static_ranges.accumulate(FF_DATA) + cloned_blocks.accumulate();
	total_bytes[2] += static_ranges.accumulate(FF_CONST);
	total_bytes[3] += static_ranges.accumulate(FF_BSS);
	total_bytes[4] += static_ranges.accumulate(FF_XTRN);
	// export breakpoints for Olly... (deprecated)
	if (prefs.dbg_resolve && !breakpoints.empty()) {
		if (prefs.verbosity >= 1) cmsg << prefix << "exporting breakpoints...";
		ea_t imagebase;
		IMAGE_NT_HEADERS pehdr;
		if (netnode("$ PE header").valobj(&pehdr, sizeof pehdr) >= sizeof pehdr)
			imagebase = pehdr.OptionalHeader.ImageBase;
		else
			if (prefs.verbosity >= 1) cmsg << prefix <<
				"failed to read pe header, assuming imagebase at " << hex << uppercase <<
				setw(sizeof(PVOID) << 1) << setfill('0') << (imagebase = 0x00400000) << endl;
		char drive[_MAX_DRIVE], dir[_MAX_DIR], fname[_MAX_FNAME], bpxfile[QMAXPATH];
		_splitpath(outputfn, drive, dir, fname, 0);
		_makepath(bpxfile, drive, dir, fname, "bpx");
		ofstream os(bpxfile, ios_base::out | ios_base::binary | ios_base::trunc);
		if (!os) {
			if (prefs.verbosity >= 1) cmsg << prefix << "failed to create file (" <<
				bpxfile << ')' << endl;
		} else try {
			if (!os.write(SIZEDTEXT("bpx")).write((char *)&imagebase, sizeof imagebase))
				throw runtime_error("write error");
			char rootname[QMAXPATH];
			get_root_filename(CPY(rootname));
			if (!os.write(rootname, strlen(rootname) + 1))
				throw runtime_error("write error");
			totallines = 0;
			//remove_if(breakpoints.begin(), .end(),
			//	boost::not1(boost::bind2nd(boost::mem_fun_ref(breakpoint_t::type_has_bit), 0)));
			for (breakpoints_t::const_iterator i = breakpoints.begin(); i != breakpoints.end(); ++i)
				if ((i->second & 1) != 0) {
					const ea_t ea(i->first - imagebase);
					if (!os.write((char *)&ea, sizeof ea)) throw runtime_error("write error");
					++totallines;
				}
			if (prefs.verbosity >= 1) cmsg << "done: " << dec << totallines << " breakpoints" << endl;
		} catch (const exception &e) {
			if (prefs.verbosity >= 1) cmsg << "failed: " << e.what() << endl;
		}
	}
	// finalization
	Destroy(false);
	last.startEA = BADADDR;
	last.endEA = BADADDR;
	if (prefs.verbosity >= 1) {
		cmsg << prefix << "export completed: " << dec << total_funcs <<
			" functions saved, " << total_vars << " continuous data blocks saved" << endl;
		cmsg << prefix << "  image preview (estimation): code(" << total_bytes[0] <<
			") data(" << total_bytes[1] << ") rdata(" << total_bytes[2] << ") bss(" <<
			total_bytes[3] << ") idata(" << total_bytes[4] << ") total:" <<
			total_bytes.sum() << endl;
		duration += time(0) - start;
		cmsg << prefix << "  time elapsed: ";
		static const char fmt[] = "%H:%M:%S";
		use_facet<time_put<char> >(locale("")).put(ostreambuf_iterator<char>(cmsg.rdbuf()),
			cmsg, ' ', gmtime(&duration), ARRAY_RANGE(fmt));
		cmsg << endl;
	}
	return true;
} // Execute()

static void Destroy(bool failed) { // exit clean-up everything
	if (prefs.dbg_savedata && !prefs.keep_saved_data) dumper.RestorePatchedAreas();
	static_ranges.clear();
	cloned_blocks.clear();
	breakpoints.clear();
	externals.clear();
	imports.clear();
	hash_set<ea_t>::iterator dummy;
	while ((dummy = dummy_labels.begin()) != dummy_labels.end()) {
		del_global_name(*dummy);
		dummy_labels.erase(dummy);
	}
	_ASSERTE(dummy_labels.empty());
	log_addresses.clear();
	segs_used.clear();
	excluded_symbols.clear();
	wait_box.close_all();
	if (failed) {
#if IDA_SDK_VERSION >= 510
		if (graph.IsOpen()) graph.Close();
#endif
		if (prefs.create_graph) graph.Reset();
	}
}

/*
static DWORD WINAPI ThreadProc(LPVOID lpParameter) {
	DWORD exit_code;
	try {
		exit_code = Execute() ? 0 : 1;
	} catch (const exception &e) {
		if (prefs.verbosity >= 1) cmsg << e.what() <<
			", aborting (lame stupid servil ;p)" << endl;
		MessageBeep(MB_ICONERROR);
		warning("%s, lame stoopid servil ;p", e.what());
		exit_code = (DWORD)-1;
	} catch (...) {
		if (prefs.verbosity >= 1) cmsg << "unknown exception" <<
			", aborting (lame stupid servil ;p)" << endl;
		MessageBeep(MB_ICONERROR);
		warning("%s, lame stoopid servil ;p", "unknown exception");
		exit_code = (DWORD)-1;
	}
	return exit_code;
}
*/

static int ExploreCREF(ea_t caller, ea_t callee, uint level) {
	callee = get_item_head(callee);
	segment_t *seg;
	if (!isEnabled(callee) || (seg = getseg(callee)) == 0/*
		|| is_spec_segm(seg>type) */) return 0;
	if (static_ranges.has_address(callee)) { // no dupe processing
		if (prefs.create_graph && caller != BADADDR) graph.AddRef(caller, callee);
		return 0;
	}
	segment_t segment(*seg);
#ifdef _DEBUG_VERBOSE
	OutputDebugString("%s%s(%08a, %08a)\n", prefix, __FUNCTION__, caller, callee);
#endif // _DEBUG_VERBOSE
	flags_t flags(get_flags_novalue(callee));
	char dassm[MAXSTR], tmpstr[MAXNAMESIZE + 80];
	/*
	if (!isCode(flags)) {
		qsnprintf(CPY(tmpstr), "code at %08a was referred from %08a, but"
			"the address contains no valid instructions", callee, caller);
		if (prefs.verbosity >= 1) cmsg << prefix << "error: " << tmpstr << endl;
		char mnem[MAXSTR];
		qsnprintf(CPY(tmpstr), "%s to unknown instructions from %08a (mnemonics: %s)",
			ua_mnem(caller, CPY(mnem)), caller, get_disasm(callee, CPY(dassm)));
		if (prefs.reporting_verbosity >= 1) report.Add(callee, 0xFFFF, tmpstr);
		++fatals;
		MessageBeep(MB_ICONERROR);
		if (prefs.suddendeath_on_fatal) {
			jumpto(callee);
			throw logic_error("code referred contains no valid instructions");
		} else
			wait_box.change("%s\n%u catastrophic error(s), abort scheduled",
				deflt_wait_banner, fatals);
		return 0;
	} // !code
	*/
	flags_t caller_flags(get_flags_novalue(caller));
	char funcname[MAXNAMESIZE];
	if (get_func(callee) == 0) {
		if (isCode(caller_flags) && is_call_insn(caller)) {
			// ref'd by callxx insn - probably this is a regular function start
			if (prefs.verbosity >= 2) cmsg << prefix << "warning: it seems code at " <<
				asea(callee) << " isn't inside any function, but is" << endl << prefix <<
				"  referred by call insn --> trying to declare a function starting here...";
			if (add_func(callee, BADADDR) == 0 || get_func(callee) == 0) {
				if (prefs.verbosity >= 2)
					cmsg << "failed: define a function here, then run the plugin again" << endl;
				else if (prefs.verbosity >= 1)
					cmsg << "error: failed to declare function at " << asea(callee) << endl;
				if (prefs.reporting_verbosity >= 1) report.Add(callee, 0xFFFF,
					"failed to declare function");
				++fatals;
				MessageBeep(MB_ICONERROR);
				if (prefs.suddendeath_on_fatal) {
					jumpto(callee);
					qsnprintf(CPY(tmpstr), "failed to declare function at %08a", callee);
					throw logic_error(tmpstr);
				} else
					wait_box.change("%s\n%u catastrophic error(s), abort scheduled",
						deflt_wait_banner, fatals);
				return 0;
			}
#ifdef _DEBUG
			char *ok =
#endif
			get_func_name(callee, CPY(funcname));
			_ASSERTE(ok == funcname);
			if (prefs.verbosity >= 2) cmsg << "success: " << funcname << endl;
			func_t *const func(get_fchunk(callee));
			if (func != 0) analyze_area(*func);
			if (pBatchResults != 0) pBatchResults->Add(callee, 0x0003,
				_sprintf("%sfunc `%s` created", prefix, funcname).c_str());
		} else { // not ref'd by call insn - declare func manually
			if (prefs.verbosity >= 1) cmsg << prefix << "error: code address " <<
				asea(callee) << " doesn't belong to any function (not ref'd by regular call insn)" <<
				endl << prefix << "  define a function here, then run the plugin again" << endl;
			if (prefs.reporting_verbosity >= 1) report.Add(callee, 0xFFFF,
				_sprintf("%s to unknown area", ua_mnem(caller, CPY(dassm))).c_str());
			++fatals;
			MessageBeep(MB_ICONERROR);
			if (prefs.suddendeath_on_fatal) {
				jumpto(callee);
				qsnprintf(CPY(tmpstr), "jump to unknown area (%08a)", callee);
				throw logic_error(tmpstr);
			} else
				wait_box.change("%s\n%u catastrophic error(s), abort scheduled",
					deflt_wait_banner, fatals);
			return 0;
		} // !call
	} // !func
	// have function frame
	func_t subfunc(*get_func(callee));
	get_func_name(&subfunc, CPY(funcname));
	if (!CanIncludeFunction(&subfunc)) { // quick pass test
		qsnprintf(CPY(tmpstr), "ignoring %s%s%sfunction %s",
			!CSC::is_visible_func(&subfunc) ? "hidden " : "",
			is_pure_import_func(&subfunc) || is_thunk_library_func(&subfunc) ? "forwarder " : "",
			is_true_libfunc(&subfunc) ? "library " : "", funcname);
		if (prefs.reporting_verbosity >= 2) report.Add(subfunc.startEA, 0x0001, tmpstr);
		if (prefs.verbosity >= 3 && log_addresses.insert(subfunc.startEA).second)
			cmsg << prefix << "  info: " << tmpstr << " on request" << endl;
		if (callee != subfunc.startEA
			&& (!is_libitem(callee) || get_supressed_library_flag(callee) == 1)) {
			// jump/call to middle of ignored function
			char label[MAXNAMESIZE];
			if (get_name(caller, get_item_head(callee), CPY(label)) == 0)
				qsnprintf(CPY(label), isCode(flags) ? "loc_%IX" : "unk_%IX", callee);
			bool fatal(isEnabled(caller));
			if (fatal) {
				if (prefs.verbosity >= 1 && log_addresses.insert(callee).second)
					cmsg << prefix << "error: label " << label <<
						" of excluded function is referred from " << asea(caller) <<
						": relax code filtering or change target function" << endl;
				qsnprintf(CPY(tmpstr), "label %s of excluded function %s referred",
					label, funcname);
			} else {
				if (prefs.verbosity >= 2 && log_addresses.insert(callee).second)
					cmsg << prefix << "warning: label " << label <<
						" of excluded function is possibly referred from " << asea(caller) <<
						": keeping referrer value raw" << endl;
				qsnprintf(CPY(tmpstr), "label %s of excluded function %s possibly referred: keeping referrer value raw",
					label, funcname);
			}
			if (prefs.reporting_verbosity >= 1) report.Add(caller/*callee*/,
				fatal ? 0xFFFF : 0x000A, tmpstr);
			if (fatal) {
				++fatals;
				MessageBeep(MB_ICONERROR);
				if (prefs.suddendeath_on_fatal) {
					jumpto(callee);
					qsnprintf(CPY(tmpstr), "inaccessible name %s(%s) at %08a referred",
						label, funcname, caller);
					throw logic_error(tmpstr);
				} else
					wait_box.change("%s\n%u catastrophic error(s), abort scheduled",
						deflt_wait_banner, fatals);
			} // caller in static code
		} else
			if (prefs.create_graph && caller != BADADDR) graph.AddRef(caller, callee);
		return 0;
	}
	_ASSERTE(is_func_entry(&subfunc));
	if (is_spec_segm(segment.type)) {
		if (prefs.verbosity >= 2) cmsg << prefix << "warning: included function " <<
			funcname << " in special segment" << endl;
		if (prefs.reporting_verbosity >= 1) report.Add(subfunc.startEA, 0x0004,
			_sprintf("including function %s in special segment", funcname).c_str());
	}
	if (/*is_func_entry(get_fchunk(callee)) && */isCode(caller_flags)
		&& is_call_insn(caller) && !isFunc(flags)) {
		if (prefs.verbosity >= 3) cmsg << prefix << "  info: address " <<
			asea(callee) << " is called but not func " << funcname << " true start" << endl;
		if (prefs.reporting_verbosity >= 2) report.Add(callee, 0x0020,
			_sprintf("called address not true start of func %s", funcname).c_str());
	}
	if (subfunc.tailqty > 0) {
		if (prefs.verbosity >= 3) cmsg << prefix << "  info: func " << funcname <<
			" (" << asea(callee) << ") having detached chunks" << endl;
		if (prefs.reporting_verbosity >= 2) report.Add(callee, 0x004A,
			_sprintf("func %s having one or more detached chunks", funcname).c_str());
	}
	// detect & remove local structures (compatibility issue)
	struc_t *frame;
	if (prefs.destroy_structs && (frame = get_frame(&subfunc)) != 0) {
		for (ea_t offset = get_struc_first_offset(frame);
			offset != BADADDR/* < subfunc.frsize;*/;
			offset = get_struc_next_offset(frame, offset)) {
			const member_t *const stkvar = get_member(frame, offset);
			if (stkvar == 0) continue;
			if (isStruct(stkvar->flag)) { // local structure
				_ASSERTE(stkvar->get_soff() == offset);
				const struc_t *const sptr = get_sptr(stkvar);
				_ASSERTE(sptr != 0);
				if (sptr == 0) continue;
				char struname[MAXSPECSIZE];
				ssize_t s = get_struc_name(sptr->id, CPY(struname));
				_ASSERTE(s > 0);
				const adiff_t frdelta = offset - subfunc.frsize;
				if (prefs.verbosity >= 3) cmsg << prefix << "  info: local structure [" <<
					asshex(frdelta, static_cast<streamsize>(4)) << "]=" <<
					(s > 0 ? struname : "<?>") << " at " << asea(subfunc.startEA) <<
					" (func " << funcname << ')';
				qsnprintf(CPY(tmpstr), "local structure: [%c%04IX]=%s (func %s)",
					SIGNED_PAIR(frdelta), struname, funcname);
				s = get_member_name(stkvar->id, CPY(struname));
				_ASSERTE(s > 0);
				if (s <= 0) struname[0] = 0;
				const asize_t varsize = get_member_size(stkvar);
#ifdef _DEBUG
				_ASSERTE(varsize % get_struc_size(sptr) == 0);
				typeinfo_t ti, *pti(retrieve_member_info(stkvar, &ti));
				_ASSERTE(pti != 0);
				_ASSERTE(sptr->id == ti.tid);
#endif // _DEBUG
				uint16 iconid;
				if (del_struc_member(frame, offset)) {
					if (prefs.verbosity >= 3) cmsg << " (undefined)";
					qstrcat(tmpstr, " undefined");
					iconid = 0x0030;
					add_local_struct_member(frame, offset, struname, sptr, varsize);
				} else {
					if (prefs.verbosity >= 3) cmsg << " (failed to undefine)";
					qstrcat(tmpstr, " failed to undefine");
					iconid = 0x0FFF;
				}
				if (prefs.verbosity >= 3) cmsg << endl;
				if (prefs.reporting_verbosity >= 2 || prefs.reporting_verbosity >= 1
					&& iconid == 0x0FFF) report.Add(subfunc.startEA, iconid, tmpstr);
			} // local structure
		} // scan frame offsets
	}
	int result(0);
	// enumerate all function chunks
	func_tail_iterator_t fti(&subfunc);
	for (bool ok = fti.main(); ok; ok = fti.next()) {
		const area_t &area(fti.chunk());
		func_t *fchunk(get_fchunk(area.startEA));
		_ASSERTE(fchunk != 0);
		ea_t scan;
		// try to create offsets from raw operands where possible
		if (prefs.createoffsets)
			for (scan = area.startEA; scan < area.endEA; scan = next_head(scan, area.endEA))
				if (isCode(get_flags_novalue(scan)) && ua_ana0(scan) > 0) {
					ea_t tgt;
					for (uint cntr = 0; cmd.Operands[cntr].type != o_last
						&& cntr < UA_MAXOP; ++cntr)
						if (cmd.Operands[cntr].type == o_imm
							&& !isDefArg(get_flags_novalue(scan), cntr)
							&& isEnabled(tgt = cmd.Operands[cntr].value/*raw!!*/)
							&& Off2Stat(tgt) && !is_in_rsrc(tgt)
							&& op_offset(scan, cntr, get_default_reftype(scan)) != 0)
							ProcessNewOffset(scan, tgt);
				} // dassm ok
		// check for fishy places
		flags_t lastFlags(get_flags_novalue(area.endEA));
		if (isCode(lastFlags) && isFlow(lastFlags)) {
			if (prefs.verbosity >= 2) cmsg << prefix << "warning: chunk of " <<
				funcname << ':' << asea(area.startEA) << " supposedly continuing at " <<
				asea(area.endEA) << endl;
			qsnprintf(CPY(tmpstr), "chunk of %s:%08a supposedly continuing after end (last instruction: %s)",
				funcname, area.startEA, get_disasm(prev_head(area.endEA, area.startEA), CPY(dassm)));
			if (prefs.reporting_verbosity >= 1) report.Add(area.endEA, 0x0029, tmpstr);
		} else if (decode_prev_insn(area.endEA) != BADADDR && !is_ret_insn(cmd.itype)
			&& (fchunk->flags & FUNC_NORET) == 0) {
			if (prefs.verbosity >= 2) cmsg << prefix << "warning: chunk of " <<
				funcname << ':' << asea(area.startEA) << " doesnot return" << endl;
			qsnprintf(CPY(tmpstr), "chunk of %s:%08a doesnot return (last instruction: %s)",
				funcname, area.startEA, get_disasm(cmd.ea, CPY(dassm)));
			if (prefs.reporting_verbosity >= 1) report.Add(cmd.ea, 0x0049, tmpstr);
		}
		lastFlags = flags;
		bool jumptable;
		for (scan = area.startEA; scan < area.endEA; scan = next_not_tail(scan)) {
#ifdef _SHOWADDRESS
			showAddr(scan);
#endif
			flags = get_flags_novalue(scan);
			if (isUnknown(flags) && !isUnknown(lastFlags)) {
				if (prefs.verbosity >= 2) cmsg << prefix <<
					"warning: undefined area inside function at " << asea(scan) << endl;
				if (prefs.reporting_verbosity >= 1) report.Add(scan, 0x0009,
					_sprintf("undefined area inside function (%s)",
						get_disasm(scan, CPY(dassm))).c_str());
			}
			// detect runtime-evaluated addressing
			if (isCode(flags)) {
#ifdef _DEBUG
				int ok =
#endif
				ua_ana0(scan);
				_ASSERTE(ok > 0);
				// find used segments
				hash_set<RegNo, hash<int> > seg_sels(get_segs_used(scan));
				if (!seg_sels.empty()) segs_used.insert(CONTAINER_RANGE(seg_sels));
				// detect indirect flow
				if (seg_sels.count(R_es) <= 0 && seg_sels.count(R_fs) <= 0
					&& seg_sels.count(R_gs) <= 0 && is_indirectflow_insn(cmd.itype)
					&& ((flags & MS_CODE) & FF_JUMP) == 0 // ignore jumptables
					&& !does_ref_extern(scan)) { // rt-evaluated call or jump
					func_t *func;
					xrefblk_t xref;
					for (bool isresolved = xref.first_from(scan, XREF_FAR); isresolved; isresolved = xref.next_from())
						if (xref.iscode && ((func = get_func(xref.to)) == 0
							|| func->startEA != subfunc.startEA)) break;
					if (cmd.Op1.type == o_mem
						&& isEnabled(calc_reference_target(calc_reference_target(cmd, 0)))) { // known offset
						// log window
						if (prefs.verbosity >= 2) cmsg << prefix <<
							"warning: runtime-evaluated address to known but variable offset at " <<
							asea(scan) << " (target" <<
							(isresolved ? "(s) known from run trace" : " unknown") <<  ')' << endl;
						// warning list
						qsnprintf(CPY(tmpstr), "runtime-evaluated address known but variable (%s insn.) - target",
							ua_mnem(scan, CPY(dassm)));
						qstrcat(tmpstr, isresolved ? "(s) known from run trace" : " unknown");
						if (prefs.reporting_verbosity >= 1) report.Add(scan,
							0x0002 + isresolved, tmpstr);
						goto lbl2;
					} else {
						// unknown offset and not impdef
						// log window
						if (prefs.verbosity >= 2) cmsg << prefix <<
							"warning: runtime-evaluated address detected at " <<
							asea(scan) << " (target" <<
							(isresolved ? "(s) known from run trace" : " unknown") << ')' << endl;
						// warning list
						if (prefs.reporting_verbosity >= 1) report.Add(scan, 0x0100 - isresolved,
							_sprintf("runtime-evaluated address (%s insn.) - target%s",
							ua_mnem(scan, CPY(dassm)), isresolved ? "(s) known from run trace" : " unknown").c_str());
					lbl2:
						// comment
						append_unique_cmt(scan, rte_warning);
						breakpoints.set(scan, 1);
						if (resolver.isLoaded()) resolver.SetSwBreakpoint(
							reinterpret_cast<LPCVOID>(scan + resolver.module->getBaseOffset()));
					} // unknown offset and not impdef
				} // rt-evaluated call or jump
				ea_t xrefea;
				for (int iter = 0; iter < UA_MAXOP; ++iter) // detect possible array base index shifts
					if (cmd.Operands[iter].type == o_displ
						&& isEnabled(xrefea = calc_reference_target(cmd, iter))
						&& !isArray(xrefea)) {
						if (prefs.verbosity >= 2) cmsg << prefix << "warning: target at " <<
							asea(xrefea) << " handled as indexed array, though single item" << endl;
						qsnprintf(CPY(tmpstr), "indexed array by insn at %08a, though not array (possible base index delta for %s)",
							xrefea, get_disasm(scan, CPY(dassm), true));
						if (prefs.reporting_verbosity >= 1) report.Add(scan, 0x0502, tmpstr);
					}
			} // code
			for (int iter = 0; iter < UA_MAXOP; ++iter) {
				// destroy offsets to .rsrc section
				if (isOff(flags, iter) && cmd.Operands[iter].type == o_imm
					&& is_in_rsrc(calc_reference_target(cmd, iter)))
					if (op_hex(scan, iter)) {
						if (prefs.verbosity >= 3) cmsg << prefix <<
							"  info: false offset to .rsrc section removed at " <<
								asea(scan) << " (operand " << dec << iter + 1 << ')' << endl;
						if (prefs.reporting_verbosity >= 2) report.Add(scan, 0x0200,
							"false offset to .rsrc section undefined");
						analyze_area(scan, scan + cmd.size);
					} else {
						if (prefs.verbosity >= 2) cmsg << prefix <<
							"warning: couldnot remove false offset at " << asea(scan) <<
							" (operand " << dec << iter + 1 << ')' << endl;
						if (prefs.reporting_verbosity >= 1) report.Add(scan, 0x0FFF,
							"couldnot undefine false offset");
					}
				// remove enums if disabled
				if (prefs.destroyenums && isEnum(flags, iter))
					if (noType(scan, iter)) {
						if (prefs.verbosity >= 3) cmsg << prefix <<
							"  info: typeinfo removed at " << asea(scan) <<
								" on request (enum operand " << dec << iter + 1 << ')' << endl;
						if (prefs.reporting_verbosity >= 2) report.Add(scan, 0x0039,
							"typeinfo (enum) removed from operand");
					} else {
						if (prefs.verbosity >= 2) cmsg << prefix <<
							"warning: couldnot remove typeinfo at " << asea(scan) <<
								" (enum operand " << dec << iter + 1 << ')' << endl;
						if (prefs.reporting_verbosity >= 1) report.Add(scan, 0x0FFF,
							"couldnot remove typeinfo (enum)");
					}
			} // iterate operands
			if (isData(flags)) {
				if ((flags & DT_TYPE) == FF_ALIGN && !isAlign(lastFlags)) {
					if (decode_prev_insn(scan) != BADADDR && is_ret_insn(cmd.itype)) {
						if (prefs.verbosity >= 2) cmsg << prefix <<
							"warning: align directive found inside function " << funcname <<
								" at " << asea(scan) << ", possible function end?" << endl;
					} else
						if (prefs.verbosity >= 2) cmsg << prefix <<
							"warning: align directive found in function " <<
								funcname << " at " << asea(scan) << endl;
					if (prefs.reporting_verbosity >= 1) report.Add(scan, 0x0020,
						_sprintf("unexpected align directive inside function (next instruction: %s)",
							get_disasm(next_not_tail(scan), CPY(dassm))).c_str());
				} else if (!isData(lastFlags)) {
					jumptable = false;
					if (hasRef(flags)) { // detect jumptables
						xrefblk_t xref;
						for (bool ok = xref.first_to(scan, XREF_DATA); ok; ok = xref.next_to()) {
							if (xref.iscode) continue;
							flags_t flags(get_flags_novalue(xref.from));
							if (isCode(flags) && ((flags & MS_CODE) & FF_JUMP) != 0)
								jumptable = true;
							else {
								jumptable = false;
								break;
							}
						} // evaluate xrefs to
					} // hasRef(flags)
					if (jumptable)
						flags = FF_TAIL;
					else { // defined data - make warning
						const char *type;
						switch (flags & DT_TYPE) {
							case FF_BYTE: type = "byte"; break;
							case FF_WORD: type = "word"; break;
							case FF_DWRD: type = "dword"; break;
							case FF_QWRD: type = "qword"; break;
							case FF_TBYT: type = "tbyte"; break;
							case FF_ASCI: type = "string"; break;
							case FF_STRU: type = "struct"; break;
							case FF_OWRD: type = "octaword"; break;
							case FF_FLOAT: type = "float"; break;
							case FF_DOUBLE: type = "double"; break;
							case FF_PACKREAL: type = "packed decimal real"; break;
							//case FF_ALIGN: type = "align"; break;
							default: type = "unknown";
						} // switch statement
						if (prefs.verbosity >= 2) cmsg << prefix << "warning: data type " <<
							type << " found inside function " << funcname << " (" <<
								asea(scan) << ')' << endl;
						qsnprintf(CPY(tmpstr),
							"unexpected data type (%s) inside function", type);
						if (isArray(scan)) {
							asize_t array_size(get_array_size(scan));
							array_parameters_t arrayinfo;
							if (get_array_parameters(scan, &arrayinfo, sizeof arrayinfo) >= sizeof arrayinfo) {
								string flags;
								if ((arrayinfo.flags & AP_SIGNED) != 0) flags.append("signed ");
								if ((arrayinfo.flags & AP_INDEX) != 0) flags.append("indexed ");
								qsnprintf(CAT(tmpstr), " (%s%Iu-element array %li\x9E%li)",
									flags.c_str(), array_size, arrayinfo.lineitems, arrayinfo.alignment);
							}
							else
								qsnprintf(CAT(tmpstr), " (%Iu-element array)", array_size);
						} // isArray(scan)
						if (prefs.reporting_verbosity >= 1) report.Add(scan, 0x0006, tmpstr);
					} // !jumptable
				} // !isData(lastFlags)
			} // data
			lastFlags = flags;
		} // walk the function
		result += ProcessRange(area, level);
	} // fchunk iterator
	if (prefs.create_graph && caller != BADADDR && result > 0)
		graph.AddRef(caller, callee);
	return result;
}

static int ExploreDREF(ea_t caller, ea_t callee, uint level) {
	segment_t *seg, segment;
	if (!isEnabled(callee) || (seg = getseg(callee)) == 0
		/*|| is_spec_segm(seg->type)*/) return 0;
	segment = *seg;
#ifdef _DEBUG_VERBOSE
	OutputDebugString("%s%s(%08IX, %08IX)\n", prefix, __FUNCTION__, caller, callee);
#endif
	ea_t const item_head(get_item_head(callee));
	flags_t flags(get_flags_novalue(item_head));
	if (isCode(flags)) {
		_RPT3(_CRT_WARN, "%s(%08IX, %08IX) called for code area: forwarding to ExploreCREF(...)\n",
			__FUNCTION__, caller, callee);
		return ExploreCREF(caller, callee, level); //return 0; ?
	}
	char dassm[MAXSTR], tmpstr[512];
	if (prefs.anchorstroffs && isStruct(flags) && callee > item_head && isEnabled(caller)) {
		clr_zstroff(item_head);
		clr_zstroff(caller);
		flags_t const caller_flags(get_flags_novalue(get_item_head(caller)));
		typeinfo_t ti;
		if (isCode(caller_flags))
			if (ua_ana0(caller) > 0) {
				for (int iter = 0; iter < UA_MAXOP && cmd.Operands[iter].type != o_last; ++iter)
					if (isOff(caller_flags, iter) && calc_reference_target(cmd, iter) == callee
						&& get_refinfo(caller, iter, &ti.ri) != 0) {
						_ASSERTE(ti.ri.tdelta == 0);
						ti.ri.tdelta = callee - item_head;
						if (op_offset_ex(caller, iter, &ti.ri) != 0) {
							if (prefs.verbosity >= 3/* && log_addresses.insert(caller).second*/)
								cmsg << prefix << "  info: offset at " <<
									asea(caller) << " was anchored to static struct base" << endl;
							qsnprintf(CPY(tmpstr), "offset was anchored to static struct base (%08a)",
								item_head);
							if (prefs.reporting_verbosity >= 2) report.Add(caller, 0x0030/*0x0001*/, tmpstr);
						} else
							goto general_anchor_fail;
					}
			} else { // disassm failed
				if (prefs.verbosity >= 2/* && log_addresses.insert(caller).second*/)
					cmsg << prefix << "warning: disassembly failed at " << asea(caller) << endl;
				if (prefs.reporting_verbosity >= 1) report.Add(caller, 0x0FFF,
					_sprintf("disassembly failed (%s)", get_disasm(caller, CPY(dassm))).c_str());
			}
		else if (isStruct(caller_flags)) {
			struc_t *struc;
			if (get_typeinfo(item_head, 0, flags, &ti) != 0
				&& (struc = get_struc(ti.tid)) != 0
				|| (struc = get_struc(get_strid(item_head))) != 0) {
				char strucname[MAXNAMESIZE];
				if (get_struc_name(ti.tid, CPY(strucname)) <= 0) strucname[0] = 0;
				asize_t const strucsize(get_struc_size(struc));
				uint ndx(0);
				do {
					for (ea_t offset = get_struc_first_offset(struc);
						offset != BADADDR;
						offset = get_struc_next_offset(struc, offset)) {
						const member_t *const member = get_member(struc, offset);
						if (member == 0) continue;
						if (isOff0(member->flag)
							&& calc_reference_target(caller + ndx * strucsize, member) == callee
							&& retrieve_member_info(member, &ti) != 0) {
							char tmp[MAXNAMESIZE], memname[MAXSPECSIZE];
							if (get_member_fullname(member->id, CPY(memname)) <= 0) {
								qsnprintf(CPY(tmp), "%s:%04IX", strucname, offset);
								qstrcpy(memname, tmp);
							}
							_ASSERTE(ti.ri.tdelta == 0);
							ti.ri.tdelta = callee - item_head;
							if (set_member_type(struc, offset, member->flag, &ti, get_member_size(member))) {
								if (prefs.verbosity >= 3) cmsg << prefix << "  info: offset of " <<
									memname << " was anchored to static struct base" << endl;
								if (prefs.reporting_verbosity >= 2) report.Add(caller +
									ndx * strucsize + member->get_soff(), 0x0030/*0x0001*/,
									_sprintf("offset of %s was anchored to static struct base",
									memname).c_str());
							} else {
								if (prefs.verbosity >= 2) cmsg << prefix <<
									"warning: couldnot anchor offset to static struct member to struct base (" << memname << ')' << endl;
								if (prefs.reporting_verbosity >= 1) report.Add(caller +
									ndx * strucsize + member->get_soff(), 0x0FFF,
									_sprintf("failed anchor offset to static struct member to struct base (%s)",
									memname).c_str());
							} // problem
						} // found struct member pointing to target
					} // iterate struct offsets
				} while (!struc->is_varstr() && ++ndx * strucsize < get_item_size(caller));
			} else { // cant get struct
				if (prefs.verbosity >= 2/* && log_addresses.insert(item_head).second*/)
					cmsg << prefix << "warning: couldnot get struct at " << asea(item_head) << endl;
				if (prefs.reporting_verbosity >= 1) report.Add(item_head, 0x0FFF,
					"couldnot get struct info");
			}
		} else if (isData(caller_flags) && calc_reference_target(caller) == callee
			&& get_typeinfo(caller, 0, caller_flags, &ti) != 0) {
			_ASSERTE(ti.ri.tdelta == 0);
			ti.ri.tdelta = callee - item_head;
			if (op_offset_ex(caller, 0, &ti.ri) != 0) {
				if (prefs.verbosity >= 3/* && log_addresses.insert(caller).second*/)
					cmsg << prefix << "  info: offset at " << asea(caller) <<
						" was anchored to static struct base" << endl;
				qsnprintf(CPY(tmpstr), "offset was anchored to static struct base (%08a)",
					item_head);
				if (prefs.reporting_verbosity >= 2) report.Add(caller, 0x0030/*0x0001*/, tmpstr);
			} else
				goto general_anchor_fail;
		} else {
		general_anchor_fail:
			if (prefs.verbosity >= 2/* && log_addresses.insert(caller).second*/)
				cmsg << prefix << "warning: couldnot anchor offset at " <<
					asea(caller) << " to static struct member to struct base" << endl;
			qsnprintf(CPY(tmpstr), "failed anchor offset at %08a to static struct member to struct base",
				caller);
			if (prefs.reporting_verbosity >= 1) report.Add(caller, 0x0FFF, tmpstr);
		}
	} // offset to static struct member
	if (static_ranges.has_address(callee)) { // no dupe processing
		if (prefs.create_graph && caller != BADADDR) graph.AddRef(caller, callee);
		return 0;
	}
	bool const fatal(isEnabled(caller));
	char name[MAXNAMESIZE];
	if (get_true_name(BADADDR, item_head, CPY(name)) == 0)
		qsnprintf(CPY(name), isCode(flags) ? "loc_%IX" : "unk_%IX", item_head);
	if (!CanIncludeVariable(item_head)) {
		if (prefs.verbosity >= 3 && log_addresses.insert(item_head).second)
			cmsg << prefix << "  info: ignoring " <<
				(is_hidden_item(item_head) ? "hidden " : "") <<
				(is_libitem(item_head) ? "library " : "") << "variable " << name <<
				" on request" << endl;
		if (prefs.reporting_verbosity >= 2) report.Add(callee, 0x0001,
			_sprintf("ignoring %s%svariable %s", is_hidden_item(item_head) ?
			"hidden " : "", is_libitem(item_head) ? "library " : "", name).c_str());
		if (callee > item_head && hasRef(get_flags_novalue(callee))
			&& CanIncludeVariable(callee)) { // offset to middle of ignored variable or excluded function
			char label[MAXNAMESIZE];
			if (get_name(caller, callee, CPY(label)) == 0)
				qsnprintf(CPY(label), isCode(get_flags_novalue(callee)) ?
					"loc_%IX" : "unk_%IX", callee);
			if (fatal) {
				if (prefs.verbosity >= 1 && log_addresses.insert(callee).second)
					cmsg << prefix << "error: label " << label <<
						" of excluded variable " << name << " is referred from " << asea(caller) <<
						": relax code filtering or unlib(unhide) target variable" << endl;
				qsnprintf(CPY(tmpstr), "label %s of excluded variable %s is referred from %08a",
					label, name, caller);
			} else {
				if (prefs.verbosity >= 2 && log_addresses.insert(callee).second)
					cmsg << prefix << "warning: label " <<
						label << " of excluded variable " << name << " possibly referred from " <<
						asea(caller) << ": keeping the referrer raw" << endl;
				qsnprintf(CPY(tmpstr), "label %s of excluded variable %s is possibly referred from %08a, keeping the referrer raw",
					label, name, caller);
			}
		lbl1:
			if (prefs.reporting_verbosity >= 1) report.Add(callee,
				fatal ? 0xFFFF : 0x000A, tmpstr);
			if (fatal) {
				++fatals;
				MessageBeep(MB_ICONERROR);
				if (prefs.suddendeath_on_fatal) {
					jumpto(callee);
					qsnprintf(CPY(tmpstr), "inaccessible item at %08a referred", callee);
					throw logic_error(tmpstr);
				} else
					wait_box.change("%s\n%u catastrophic error(s), abort scheduled",
						deflt_wait_banner, fatals);
			} // isEnabled(caller)
		} else
			if (prefs.create_graph && caller != BADADDR) graph.AddRef(caller, callee);
		return 0;
	} else if (isAlign(flags)) {
		if (prefs.verbosity >= 2 && log_addresses.insert(callee).second)
			cmsg << prefix << "warning: dref to alignment directive at " <<
				asea(callee) << endl;
		if (prefs.reporting_verbosity >= 1) report.Add(callee, 0x0FFF,
			"dref to alignment directive");
		return 0;
	} else if (!prefs.externdefs && segment.type == SEG_XTRN) {
		if (prefs.verbosity >= 3 && log_addresses.insert(callee).second)
			cmsg << prefix << "  info: ignoring externdef " << name << " on request" << endl;
		if (prefs.reporting_verbosity >= 2) report.Add(callee, 0x0001,
			_sprintf("ignoring externdef %s", name).c_str());
		return 0;
	} else if (is_spec_segm(segment.type)) {
		if (prefs.verbosity >= 2) cmsg << prefix << "warning: included variable " <<
			name << " in special segment"<< endl;
		if (prefs.reporting_verbosity >= 1) report.Add(callee, 0x0004,
			_sprintf("including variable %s in special segment", name).c_str());
	}
	area_t area;
	area.startEA = callee;
	area.endEA = format_data_area(area.startEA, prefs.createoffsets, offset_boundary,
		prefs.offtohead ? 1 + prefs.offtodefhead ? 1 : 0 : 0, prefs.makealigns,
		total_arrays, total_offsets, &report, pBatchResults, prefs.verbosity, prefix);
	if (area.endEA <= area.startEA) return 0;
	//bool nmmm = false;
	for (ea_t scan = area.startEA; scan < area.endEA; scan = next_not_tail(scan)) {
#ifdef _SHOWADDRESS
		//showAddr(scan);
#endif
		flags = get_flags_novalue(scan);
		if (prefs.destroyenums && isEnum0(flags) && noType(scan, 0)) {
			if (prefs.verbosity >= 3) cmsg << prefix <<
				"  info: typeinfo (enum) removed from data at " << asea(scan) <<
				" on request" << endl;
			if (prefs.reporting_verbosity >= 2) report.Add(scan, 0x0001,
				"typeinfo (enum) removed from data on request");
		}
		uval_t val;
		if (isOff0(flags) && get_data_value(scan, &val, 0) != 0 && is_in_rsrc(val))
			if (op_num(scan, 0)) {
				if (prefs.verbosity >= 3) cmsg << prefix <<
					"  info: false offset to .rsrc section removed at " << asea(scan) << endl;
				if (prefs.reporting_verbosity >= 2) report.Add(scan, 0x0200,
					"false offset to .rsrc section undefined");
				analyze_area(scan, scan + get_item_size(scan));
			} else {
				if (prefs.verbosity >= 2) cmsg << prefix <<
					"warning: couldnot remove false offset at " << asea(scan) << endl;
				if (prefs.reporting_verbosity >= 1) report.Add(scan, 0x0FFF,
					"couldnot undefine false offset");
			}
		if (isASCII(flags) && is_unicode(get_str_type_code(get_string_type(scan)))) {
			if (prefs.verbosity >= 2) cmsg << prefix << "warning: unicode string at " <<
				asea(scan) << " possible compatibility issue" << endl;
			if (prefs.reporting_verbosity >= 1) report.Add(scan, 0x0601,
				"unicode string possible compatibility issue");
			have_unc = true;
		}
		if (has_user_name(flags) && !prefs.include_libitems && is_libname(scan)) {
			area.endEA = scan;
			if (does_prefix_lstring(area.endEA - 4)) area.endEA -= 4;
		}
	} // walk area
	if (area.endEA <= area.startEA) return 0;
	// expand structs
	//if (isStruct(flags) && is_terse_struc(item_head)) clr_terse_struc(item_head);
	// cover alignment directive where present
	ea_t previnsn(prev_not_tail(area.startEA));
	if (previnsn != BADADDR && previnsn >= segment.startEA
		&& isAlign(get_flags_novalue(previnsn))) area.startEA = previnsn;
	if (!hasAnyName(get_flags_novalue(item_head)) && (item_head == area.startEA
		|| prevthat(item_head, area.startEA, hasAnyName) == BADADDR)
		&& set_dummy_name(caller, item_head)
		&& get_true_name(caller, item_head, CPY(name)) != 0) { // ensure range is named
		if (prefs.verbosity >= 3) cmsg << prefix << "  info: dummy data at " <<
			asea(item_head) << " named as " << name << endl;
		if (prefs.reporting_verbosity >= 2) report.Add(item_head, 0x000B,
			_sprintf("dummy name set at range start to %s", name).c_str());
	}
	const int result = ProcessRange(area, level);
	if (prefs.create_graph && caller != BADADDR && result > 0)
		graph.AddRef(caller, callee);
	return result;
}

static int ProcessRange(const area_t &area, uint level) {
	if (prefs.maxruntime != 0 && time(0) - start > prefs.maxruntime)
		__stl_throw_overflow_error("running time over limit");
	if (prefs.max_ranges != 0 && total_funcs + total_vars >= prefs.max_ranges)
		__stl_throw_overflow_error("range quantity over limit");
	if (wasBreak()) throw user_abort();
#ifdef _SHOWADDRESS
	//showAddr(area.startEA);
#endif
	const flags_t fType(GetSegment(area.startEA));
	if (fType == 0) {
		if (prefs.verbosity >= 2) cmsg << prefix << "warning: range <" << asea(area.startEA) <<
			'-' << asea(area.endEA) << "> couldnot be added (segment type not deduced)" << endl;
		if (prefs.reporting_verbosity >= 1) report.Add(area.startEA, 0x0FFF,
			"address not added (couldnot deduce segment type)");
		return 0; //throw logic_error("couldnot add static range for cloning (segment type not deduced)");
	}
	const range_t range(area, fType, level);
	if (!static_ranges.add(range)) {
		if (prefs.verbosity >= 2) cmsg << prefix << "warning: range <" << asea(area.startEA) <<
			'-' << asea(area.endEA) << "> couldnot be added (dupe or insert failed)" << endl;
		if (prefs.reporting_verbosity >= 1) report.Add(area.startEA, 0x0FFF,
			"address not added (duper or insert failed)");
		return 0; //throw logic_error("couldnot add static range for cloning (dupe or insert failed)");
	}
	if (prefs.verbosity >= 2) {
		char tmpstr[MAXNAMESIZE + 80];
		qsnprintf(CPY(tmpstr), "%srange <%08a-%08a> successfully added", prefix,
			range.startEA, range.safeEndEA());
		char name[MAXNAMESIZE];
		if (get_func(range.startEA) != 0 && get_func_name(range.startEA, CPY(name)) != 0)
			qsnprintf(CAT(tmpstr), " (func %s)", name);
		else {
			range.GetLabel(CPY(name));
			qsnprintf(CAT(tmpstr), " (%s: %s)", fType == FF_DATA ? "data" :
				fType == FF_CONST ? "rdata" : fType == FF_BSS ? "bss" :
				fType == FF_XTRN ? "idata" : fType == FF_CODE ? "code" :
				"unknown area", name);
		}
#ifdef _DEBUG
		//if (type != FF_CODE) data_list.Add(range, name);
#endif
		cmsg << tmpstr << endl;
	} // do message
	if (fType == FF_CODE && is_func_entry(get_fchunk(range.startEA))) ++total_funcs;
	if (fType == FF_DATA || fType == FF_CONST || fType == FF_BSS
		/*|| fType == FF_XTRN*/) ++total_vars;
#ifdef _DEBUG_VERBOSE
	OutputDebugString("%s%s(%08IX, %08IX, ...)\n", prefix, __FUNCTION__,
		range.startEA, range.safeEndEA());
#endif
	int result(1);
	for (ea_t ea = range.startEA; ea < range.safeEndEA(); ea = next_not_tail(ea)) {
#ifdef _SHOWADDRESS
		showAddr(ea);
#endif
		const flags_t flags(get_flags_novalue(ea));
		// enumerate references from EA
		hash_set<RegNo, hash<int> > seg_sels;
		if (!isCode(flags) || (seg_sels = get_segs_used(ea)).count(R_es) <= 0
			&& seg_sels.count(R_fs) <= 0 && seg_sels.count(R_gs) <= 0) {
			typeinfo_t ti, *pti(0);
			tid_t strid;
			if (isData(flags)) {
				pti = get_typeinfo(ea, 0, flags, &ti);
				strid = (flags & DT_TYPE) == FF_STRU ? get_strid(ea) : BADNODE;
#ifdef _DEBUG
				if ((flags & DT_TYPE) == FF_STRU) {
					_ASSERTE(pti != 0);
					_ASSERTE(strid != BADNODE);
					if (pti != 0 && ti.tid != strid) _RPT4(_CRT_WARN,
						"%s(...): struct ids mismatch at %08IX: ti.tid=%08IX get_strid(...)=%08IX\n",
						__FUNCTION__, ea, ti.tid, strid);
				}
#endif // _DEBUG
			}
			xrefblk_t xref;
			for (bool ok = xref.first_from(ea, XREF_FAR); ok; ok = xref.next_from()) { // is code not included yet
				if (isStruct(flags) && (pti != 0 && xref.to == ti.tid || xref.to == strid)
					|| get_func(ea) != 0 && get_func(xref.to) != 0
					&& get_func(xref.to)->startEA == get_func(ea)->startEA) continue;
#ifdef _DEBUG_VERBOSE
				OutputDebugString("%sxref iterator %08a: (%08a) -> %08a\n", prefix,
					ea, xref.from, xref.to);
#endif
				char tmpstr[MAXSTR];
				if (!isEnabled(xref.to)) {
					if (prefs.verbosity >= 2) cmsg << prefix << "warning: invalid address " <<
						asea(xref.to) << " referred from " << asea(ea) << ", this target will be ignored" << endl;
					qsnprintf(CPY(tmpstr), "target not explored (invalid address %08a)", xref.to);
					if (prefs.reporting_verbosity >= 1) report.Add(ea, 0x0200, tmpstr);
					continue; // don't bother about .to anymore
				} else if (is_in_rsrc(xref.to)) {
					if (xref.user == 1) continue; // ignore nonstd. refs made by fubar plugin
					if (prefs.verbosity >= 2) cmsg << prefix <<
						"warning: .rsrc section referred from " << asea(ea) << endl;
					qsnprintf(CPY(tmpstr), "resource section referred (%08a)", xref.to);
					if (prefs.reporting_verbosity >= 1) report.Add(ea, 0x0200, tmpstr);
					/*
					++fatals;
					MessageBeep(MB_ICONERROR);
					if (prefs.suddendeath_on_fatal) {
						throw logic_error("xref to resource section");
					} else
						wait_box.change("%s\n%u catastrophic error(s), abort scheduled",
							deflt_wait_banner, fatals);
					return result;
					*/
				}
				flags_t const tgtFlags(get_flags_novalue(xref.to));
				if (!prefs.include_libitems && (prefs.reloc_extfn_offs
					&& is_libfuncname(xref.to) || prefs.reloc_extvar_offs && is_libvarname(xref.to)))
					for (ea_t scan = ea; scan + sizeof DWORD <= get_item_end(ea); ++scan)
						if (/*calc_reference_target*/can_be_off32(scan) == xref.to) {
							if (isCode(flags) && !has_any_name(flags)
								&& set_dummy_name(BADADDR, ea)) dummy_labels.insert(ea);
							if (!externals.insert(remappoint_t(range.startEA,
								scan - range.startEA)).second) {
								if (prefs.verbosity >= 2) cmsg << prefix << "warning: failed to add address " <<
									asea(scan) << " to external translation table" << endl;
								if (prefs.reporting_verbosity >= 1) report.Add(scan, 0x0FFF,
									"failed to add offset to translation table");
							}
						}
				if ((prefs.crefs && xref.iscode || prefs.drefs && !xref.iscode)
					&& (!isCode(flags) && (prefs.data2code && isCode(tgtFlags) || prefs.data2data
					&& !isCode(tgtFlags)) || isCode(flags) && (prefs.code2code
					&& isCode(tgtFlags) || prefs.code2data && !isCode(tgtFlags)))) {
					if (isCode(tgtFlags))
						result += ExploreCREF(ea, xref.to, range.level + 1);
					else if (points_to_meaningful_head(xref.to))
						result += ExploreDREF(ea, xref.to, range.level + 1);
					else { // invalid reference - STOP!
						++fatals;
						if (prefs.verbosity >= 1) cmsg << prefix <<
							"error: unaligned reference to " << asea(xref.to) <<
							" was found - try to redefine" << endl << prefix <<
							"  target area or revise the offset at " << asea(ea) << endl;
						char dassm[MAXSTR];
						qsnprintf(CPY(tmpstr), "unaligned reference from %08a (%s)", ea,
							get_disasm(ea, CPY(dassm)));
						if (prefs.reporting_verbosity >= 1) report.Add(xref.to, 0xFFFF, tmpstr);
						MessageBeep(MB_ICONERROR);
						if (prefs.suddendeath_on_fatal) {
							jumpto(isEnabled(xref.to) ? xref.to : ea);
							qsnprintf(CPY(tmpstr), "unaligned reference to %08a", xref.to);
							throw logic_error(tmpstr);
						} else
							wait_box.change("%s\n%u catastrophic error(s), abort scheduled",
								deflt_wait_banner, fatals);
						break;
					} // invalid reference - STOP!
				} // reference allowed by user filters
			} // enum refs from ea
		} // not special segment from instruction
	} // iterate through range
	return result;
}

static flags_t GetSegment(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	if (!isEnabled(ea)) return 0;
	if (isCode(get_flags_novalue(ea)))
		return FF_CODE;
	else if (!isLoaded(ea))
		return FF_BSS;
	else if (is_extern(ea))
		return FF_XTRN;
	netnode penode("$ PE header");
	if (penode != BADNODE) {
		IMAGE_NT_HEADERS pehdr;
		if (penode.valobj(&pehdr, sizeof pehdr) >= sizeof pehdr) {
			const ea_t imagebase = pehdr.OptionalHeader.ImageBase;
			for (nodeidx_t ndx = penode.sup1st(); ndx != BADNODE; ndx = penode.supnxt(ndx)) try {
				IMAGE_SECTION_HEADER sechdr;
				if (penode.supval(ndx, &sechdr, sizeof sechdr) >= sizeof sechdr
					&& ea >= imagebase + sechdr.VirtualAddress
					&& ea < imagebase + sechdr.VirtualAddress + sechdr.Misc.VirtualSize)
					return (sechdr.Characteristics & IMAGE_SCN_MEM_WRITE) != 0 ?
						FF_DATA : FF_CONST;
			} catch (const exception &e) {
				_RPTF3(_CRT_ERROR, "%s(...): %s on iterating sections: index=0x%IX\n",
					__FUNCTION__, e.what(), ndx);
				return FF_DATA;
			}
			return FF_BSS; // address not loaded?
		}
	}
	_RPTF1(_CRT_ASSERT, "%s(...): failed to get PE header from netnode\n", __FUNCTION__);
	return FF_DATA;
}

static uint ResolveNameConflicts() {
	if (prefs.verbosity >= 1) cmsg << prefix << "resolving local<->global names conflicts..." << endl;
	uint result(0);
	for (ranges_t::iterator range = static_ranges.begin();
		(range = find_if(range, static_ranges.end(),
		boost::mem_fun_ref(range_t::isCode))) != static_ranges.end(); ++range) {
		if (wasBreak()) break;
		func_t *func(get_func(range->startEA));
		_ASSERTE(func != 0);
		struc_t *frame;
		if (is_func_entry(func) && (frame = get_frame(func)) != 0) {
#ifdef _SHOWADDRESS
			showAddr(range->startEA);
#endif
			char funcname[MAXNAMESIZE];
			if (get_func_name(func, CPY(funcname)) == 0)
				qsnprintf(CPY(funcname), "<%08a>", func->startEA);
			char name[MAXSPECSIZE];
			for (ea_t stroff = get_struc_first_offset(frame);
				stroff != BADADDR;
				stroff = get_struc_next_offset(frame, stroff)) {
				const member_t *const member = get_member(frame, stroff);
				if (member == 0) continue;
				if (get_member_name(member->id, CPY(name)) > 0
					&& static_ranges.has_address(get_name_ea(BADADDR, name))) {
					string newname(name);
					while (newname.length() < MAXNAMESIZE) {
						newname.insert(newname.begin(), '_');
						if (!static_ranges.has_address(get_name_ea(BADADDR, newname.c_str()))
							&& set_member_name(frame, stroff, newname.c_str())) {
							++result;
							if (prefs.verbosity >= 3) cmsg << prefix << "  info: local at " <<
								funcname << ':' << ashex(stroff, (streamsize)4) <<
								" renamed to " << newname << " to prevent global conflict" << endl;
							if (prefs.reporting_verbosity >= 2) report.Add(range->startEA,
								0x0301, _sprintf("local at %s:%04IX renamed to %s to prevent global conflict",
								funcname, stroff, newname.c_str()).c_str());
							break;
						}
					}
				} // member with dupe name
			} // iterate offsets
		} // head function frame is present
	} // iterate members
	return result;
}

static void declare_struc_members(ea_t ea, const char *basename,
	struc_t *struc, asize_t size = 0) {
	_ASSERTE(isEnabled(ea) && struc != 0);
	if (!isEnabled(ea) || struc == 0) return;
	asize_t strucsize(get_struc_size(struc));
	if (size <= 0) size = strucsize;
	if (struc->is_varstr()) strucsize = size;
	_ASSERTE(size % strucsize == 0);
	//do_unknown_range(ea, size, true);
	for (uint index = 0; index * strucsize < size; ++index)
		for (ea_t offset = get_struc_first_offset(struc);
			offset != BADADDR;
			offset = get_struc_next_offset(struc, offset)) {
			member_t *const member = get_member(struc, offset);
			if (member == 0) continue;
			char name[MAXNAMESIZE], memname[MAXSPECSIZE];
			if (basename != 0 && *basename != 0
				&& get_member_name(member->id, CPY(memname)) > 0
				&& !is_anonymous_member_name(memname)) {
				qsnprintf(CPY(name), "%s_%s", basename, memname);
				//make_unique_name(CPY(name));
			} else
				name[0] = 0;
			asize_t memsize = get_member_size(member);
			const ea_t ea2(ea + index * strucsize + offset);
			if (isStruct(member->flag))
				declare_struc_members(ea2, name, get_sptr(member), memsize);
			else {
				typeinfo_t ti, *pti(retrieve_member_info(member, &ti));
				if (memsize <= 0) memsize = strucsize - offset;
				type_t typinfo[MAXSPECSIZE];
				if (!get_member_ti(member, CPY(typinfo))) typinfo[0] = 0;
				p_list fnames[MAXSPECSIZE];
				char cmt[2][MAXSPECSIZE];
				const ssize_t s[3] = {
					netnode(member->id).supval(NSUP_TYPEINFO + 1, &fnames, sizeof(fnames)),
					get_member_cmt(member->id, false, CPY(cmt[0])),
					get_member_cmt(member->id, true, CPY(cmt[1])),
				};
				array_parameters_t array_parm;
				const bool has_array_parameters = get_array_parameters(member->id,
					&array_parm, sizeof array_parameters_t) >= sizeof array_parm;
				do_data_ex(ea2, member->flag, pti, memsize);
				if (name[0] != 0) do_name_anyway(ea, CPY(name));
				if (typinfo[0] != 0) set_ti(ea2, typinfo, fnames);
				if (typinfo[0] != 0) set_ti(ea2, typinfo, s[0] > 0 ? fnames : 0);
				if (s[1] > 0) append_unique_cmt(ea2, cmt[0], false);
				if (s[2] > 0) append_unique_cmt(ea2, cmt[1], true);
				if (has_array_parameters) set_array_parameters(ea2, &array_parm);
			} // not struct (regular member)
		} // iterate offsets
}

static void ExplodeExpandedStructs() {
	if (prefs.verbosity >= 1) cmsg << prefix << "exploding global expanded structs..." << endl;
	for (ranges_t::iterator range = static_ranges.begin();
		(range = find_if(range, static_ranges.end(),
		boost::mem_fun_ref(range_t::isCode))) != static_ranges.end(); ++range) {
		if (wasBreak()) break;
#ifdef _SHOWADDRESS
		showAddr(range->startEA);
#endif
		ea_t item_head;
		flags_t tgtFlags;
		typeinfo_t ti;
		struc_t *struc;
		for (ea_t scan = range->startEA; scan < range->endEA; scan = next_head(scan, range->endEA))
			if (isCode(get_flags_novalue(scan)) && ua_ana0(scan) > 0)
				for (int iter = 0; iter < UA_MAXOP
					&& cmd.Operands[iter].type != o_last; ++iter)
					if (cmd.Operands[iter].type == o_mem
						&& isStruct(tgtFlags = get_flags_novalue(item_head = get_item_head(calc_reference_target(cmd, iter)))
						&& !is_terse_struc(item_head)
						&& get_typeinfo(item_head, 0, tgtFlags, &ti) != 0
						&& (struc = get_struc(ti.tid)) != 0
						|| (struc = get_struc(get_strid(item_head))) != 0)) {
						char basename[MAXNAMESIZE];
#ifdef _DEBUG
						_ASSERTE(get_name(BADADDR, item_head, CPY(basename)) == basename);
#else // _DEBUG
						get_name(BADADDR, item_head, CPY(basename));
#endif // _DEBUG
						char strucname[MAXNAMESIZE];
#ifdef _DEBUG
						_ASSERTE(get_struc_name(struc->id, CPY(strucname)) > 0);
#else // !_DEBUG
						get_struc_name(struc->id, CPY(strucname));
#endif // _DEBUG
						if (!is_uname(basename)) qstrcpy(basename, strucname);
						const asize_t item_size(get_item_size(item_head));
						_ASSERTE(item_size % get_struc_size(struc) == 0);
						do_unknown(item_head, true);
						if (!has_any_name(get_flags_novalue(item_head)))
							set_dummy_name(BADADDR, item_head); // ensure struct members will be referrable
						declare_struc_members(item_head, basename, struc, item_size);
						if (prefs.verbosity >= 3) cmsg << prefix << "  info: structure " <<
							strucname << " at " << asea(item_head) << " exploded to basic types" << endl;
						if (prefs.reporting_verbosity >= 2) report.Add(item_head, 0x0030,
							_sprintf("structure %s exploded to basic types", strucname).c_str());
						break; // next instruction
					}
	}
}

static int ExportCustomSection(FILE *file, flags_t iType, const char *sectionhdr) {
	int result(0);
	bool sectionwritten(false);
	for (ranges_t::iterator range = static_ranges.begin();
		(range = find_if(range, static_ranges.end(),
		boost::bind2nd(boost::mem_fun_ref(range_t::is_of_type), iType))) != static_ranges.end(); ++range) {
		if (wasBreak()) throw user_abort();
		if (!sectionwritten) {
			if (sectionhdr != 0 && *sectionhdr != 0) {
				ewrite(file, SIZEDTEXT("\n"));
				ewrite(file, sectionhdr, strlen(sectionhdr));
				ewrite(file, SIZEDTEXT("\n"));
				result += 2;
			}
			ewrite(file, SIZEDTEXT("\n"));
			++result;
			sectionwritten = true;
		}
		char name[MAXNAMESIZE];
#ifdef _DEBUG
		qsnprintf(CPY(name), "%s recursion depth: %u\n", ash.cmnt, range->level);
		ewrite(file, name, strlen(name));
		++result;
#endif // _DEBUG
		for (vector<string>::const_iterator i = range->comments.begin();
			i != range->comments.end(); ++i) if (!i->empty()) {
			string line;
			if (range->GetLabel(CPY(name)))
				_sprintf(line, "%s %s: %s\n", ash.cmnt, name, i->c_str());
			else
				_sprintf(line, "%s %s\n", ash.cmnt, i->c_str());
			ewrite(file, line.data(), line.length());
		}
		const int tmp(gen_file(OFILE_ASM, file, *range, 0));
		if (tmp == -1) {
			char tmpstr[80];
			qsnprintf(CPY(tmpstr), "gen_file(OFILE_ASM, ..., %08a, %08a, 0): error",
				range->startEA, range->endEA);
			throw runtime_error(tmpstr);
		}
		result += tmp;
	}
	return result;
}

// many replacements are masm specific, executing basic code cleanup not
// recommended if exporting for another compiler
static uint CleanUp(const char *filename) {
	_ASSERTE(filename != 0 && *filename != 0);
	if (filename == 0 || *filename == 0) return 0;
	fstream fs(filename, ios_base::in);
	if (!fs) return 0;
	if (prefs.verbosity >= 1) cmsg << prefix << "performing basic code cleanup..."/*, pcre_version()*/;
	wait_box.change("%s\n(output clean-up)", deflt_wait_banner);
	const PCRE::tables tables;
	// TODO: user-default locale independent OEM charset translation
	const struct deleter_t {
		PCRE::regexp regexp; // matching pattern
		uint count;  // count of lines incl. matching to be deleted
	} deleters[] = {
		/*
		; File Name   :	H:\Program Files\VSO\CopyToDVD\C2CTuner.exe
		; Format      :	Portable executable for	80386 (PE)
		; Imagebase   :	400000
		*/
		PCRE::regexp("\\;\\sFile\\sName\\s{3}\\:\\s", 0/*PCRE_CASELESS*/, true, tables), 3,
		/*
		; Section 2. (virtual address 000D6000)
		; Virtual size                  : 0000A188 (  41352.)
		; Section size in file          : 0000A200 (  41472.)
		; Offset to raw data for section: 000D4E00
		; Flags 60000020: Text Executable Readable
		; Alignment     : default
		*/
		PCRE::regexp("^\\;\\sSection\\s\\d+\\.\\s\\(virtual\\saddress\\s[[:xdigit:]]+\\)", 0/*PCRE_CASELESS*/, true, tables), 6,
		// ; Segment type:	Pure code
		PCRE::regexp("^;\\sSegment\\stype:\\s", 0/*PCRE_CASELESS*/, true, tables), 1/*6 ne vdy!*/,
		// ; Segment permissions: Read/Execute
		PCRE::regexp("^;\\sSegment\\spermissions:\\s", 0/*PCRE_CASELESS*/, true, tables), 1,
		// CODE segment para public 'CODE' use32
		// _text segment para public 'CODE' use32
		/*care!!*/PCRE::regexp("^\\w+\\ssegment\\b", 0, true, tables), 1,
		//     ;org 401000h
		// 		;org 12601000h
		PCRE::regexp("^\\s+(?:;\\s*)?org\\s+[[:xdigit:]]+h\\b", PCRE_CASELESS, true, tables), 1,
		// 		assume cs:_text
		//     assume es:nothing, ss:nothing, ds:CODE, fs:nothing,	gs:nothing
		PCRE::regexp("^\\s+assume\\s+[cdsefg]s\\s*:", 0/*PCRE_CASELESS*/, true, tables), 1,
		// ; อออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออ
		PCRE::regexp("^;\\s*(?:\\ฤ*|\\อ*|\\-*|\\=*)\\s*$", 0, true, tables), 1,
		/*
		;
		; ษอออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออป
		; บ	This file is generated by The Interactive Disassembler (IDA)	    บ
		; บ	Copyright (c) 2005 by DataRescue sa/nv,	<ida@datarescue.com>	    บ
		; บ		Licensed to: Lennart Reus, 1 user, std,	07/2003		    บ
		; ศอออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออผ
		;
		*/
		PCRE::regexp("^;\\s*(?:ษอ+ป|ศอ+ผ|\\+\\-+\\+)\\s*$", 0, true, tables), 1,
		PCRE::regexp("^;\\s*[บ\\|]\\s*This\\s+file\\s+is\\s+generated\\s+by\\s+The\\s+Interactive\\s+Disassembler\\s+\\(IDA\\)\\s*[บ\\|]\\s*$", PCRE_CASELESS, true, tables), 1,
		PCRE::regexp("^;\\s*[บ\\|]\\s*Copyright\\s+\\(c\\)\\s+\\d+\\s+by\\s+DataRescue\\s+sa\\/nv\\,\\s+\\<ida\\@datarescue\\.com\\>\\s*[บ\\|]\\s*$", PCRE_CASELESS, true, tables), 1,
		PCRE::regexp("^;\\s*[บ\\|]\\s*Licensed\\s+to:\\s+.*,\\s+\\d+\\s+users?,\\s+.*\\s*[บ\\|]\\s*$", 0/*PCRE_CASELESS*/, true, tables), 1,
		// ; Input MD5   : 7C87CFB760AB3650C25AF3EEB8CF103C
		PCRE::regexp("^;\\sInput\\s+MD5\\s*\\:\\s*[[:xdigit:]]{32}\\s*$", 0/*PCRE_CASELESS*/, true, tables), 1,
		// ; ÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛ S U B	R O U T	I N E ÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛÛ
		//PCRE::regexp("^\\;\\s+[Û\\=]+\\s+S\\s*U\\s*B\\s*R\\s*O\\s*U\\s*T\\s*I\\s*N\\s*E\\s+[Û\\=]+\\s*$", 0/*PCRE_CASELESS*/, true, tables), 1,
		//     .686p
		PCRE::regexp("^\\s+\\.\\d86p?\\s*$", 0/*PCRE_CASELESS*/, true, tables), 1,
		//     .mmx
		PCRE::regexp("^\\s+\\.(?:mmx|k3d|xmm)\\s*$", 0/*PCRE_CASELESS*/, true, tables), 1,
		//     .model flat
		PCRE::regexp("^\\s+\\.model\\s\\w+\\s*$", 0/*PCRE_CASELESS*/, true, tables), 1,
		// option casemap:none
		PCRE::regexp("^\\s+option\\s+(?:casemap|dotname|emulator|expr16|language|ljmp|nokeyword|nosignextend|offset|proc|prologue|readonly|scoped|segment)\\b", PCRE_CASELESS, true, tables), 1,
		//     include uni.inc ; see unicode subdir of ida for info on unicode
		PCRE::regexp("^\\s*include\\s+uni\\.inc\\b", PCRE_CASELESS, true, tables), 1,
		// ; OS type   :  MS Windows
		PCRE::regexp("^;\\sOS\\stype\\s{3}:\\s{2}[\\w\\s]+$", 0/*PCRE_CASELESS*/, true, tables), 1,
		// ; Application type:  DLL 32bit
		PCRE::regexp("^;\\sApplication\\stype:\\s{2}[\\w\\s]+$", 0/*PCRE_CASELESS*/, true, tables), 1,
	}; // deleters
	const PCRE::regexp
		// _text ends
		is_segment_end("^\\s*[_[:alpha:]\\@\\$\\?][\\w\\@\\$\\?]*\\s+ends\\s*(?:;.*)?$", PCRE_CASELESS, true, tables), // care!
		// "quoted quotes" issue should be avoided by setting assembler grammar
		//is_quoted_singlequotes("^(\\s*)([a-z_\\@\\$\\?][a-z\\d_\\@\\$\\?]*\\s+)?db\\s*\\'([^\\\"]*\\'[^\\\"]*)\\'", PCRE_CASELESS, true),
		//is_quoted_doublequotes("^(\\s*)([a-z_\\@\\$\\?][a-z\\d_\\@\\$\\?]*\\s+)?db\\s*\\\"([^\\']*\\\"[^\\']*)\\\"", PCRE_CASELESS, true),
		is_spare_line("^\\s*$", 0, true, tables);
	const locale loc("");
	PCRE::replacer adjusters[] = {
#define DECL_ADJUSTER(s, r, flags) PCRE::replacer(PCRE::regexp(s, flags, true, tables), r, loc),
#define JMP_INSN "j(?:mp|n?(?:[cos]|(?:e?cx|[abgl])?[ez]?|p[oe]?))"
#define GRP_PROLOGUE "(?:\\s*\\[\\s*|\\s+)"
#define CALL_JMP_PREFIX "^(\\s*(?:call|" JMP_INSN ")\\b)(?:\\s+short\\b)?(" \
	"(?:" GRP_PROLOGUE "(?:near|far)(?:16|32|64)?)?" \
	"(?:" GRP_PROLOGUE "(?:byte|[dq]?word)\\s+ptr)?" \
	GRP_PROLOGUE "(?:[c-gs]s\\s*\\:(?:\\s*\\[)?\\s*)?)"
#define STDCALL_IMPORT FUNC_IMPORT_PREFIX "(\\w+)(?:\\@\\d+)?\\b"
		// convert leading spaces onto tabs
		DECL_ADJUSTER("^(\\t*) {4}", "$1\\t", 0)
		// convert tabs to spaces
		DECL_ADJUSTER("(\\S *)\\t", "$1 ", 0)
		// remove x-refs
		DECL_ADJUSTER("\\s*\\;.*[\\x18\\x19].*$", "", 0)
		// ensure MASM compatibility
		DECL_ADJUSTER("\\brepn?[ez]\\s+((?:in|out|sto|lod|mov)s[bwdq]?)\\b", "rep $1", PCRE_CASELESS)
		DECL_ADJUSTER("\\brep\\s+((?:cmp|sca)s[bwdq]?)\\b", "repe $1", PCRE_CASELESS)
		DECL_ADJUSTER("^(\\s*)fcompp\\s+st\\s*\\(1\\)\\s*,\\s*st\\b", "$1fcompp", PCRE_CASELESS)
		// adjust MMX register naming convention to MASM
		DECL_ADJUSTER("\\b([ex]?mm)(\\d+[lh]?)\\b", "$1($2)", PCRE_CASELESS)
		// remove `large` keyword not supported by MASM
		DECL_ADJUSTER("\\blarge\\s+((?:byte|[dq]?word)\\s+ptr\\s+)?([e-g]s)\\s*\\:\\s*([[:xdigit:]]+h?)\\b", "$1$2:$3", PCRE_CASELESS)
		// remove postfix `short` from jumps
		DECL_ADJUSTER("^(\\s*" JMP_INSN ")\\s+short\\b", "$1", PCRE_CASELESS)
		// merge duplicate impdefs
		DECL_ADJUSTER(CALL_JMP_PREFIX "((?-i:[A-Z])\\w*)_\\d+\\b", "$1$2$3", PCRE_CASELESS)
		// remove __imp_ prefix
		DECL_ADJUSTER(CALL_JMP_PREFIX STDCALL_IMPORT, "$1$2$3", PCRE_CASELESS)
		DECL_ADJUSTER("\\b([c-gs]s\\s*\\:\\s*(?:\\[\\s*)?)?" STDCALL_IMPORT, "$1$2", PCRE_CASELESS)
#undef JMP_INSN
#undef STDCALL_IMPORT
#undef CALL_JMP_PREFIX
#undef GRP_PROLOGUE
#undef DECL_ADJUSTER
	}; // adjusters
	stringstream container;
	uint total_deleted(0), skip_lines(0), line_counter(0);
	bool spare_line(false);
	while (fs.good()) /*try */{
		string line;
		getline(fs, line);
		if (fs.fail()) break;
		if (++line_counter % 1000 == 0) {
			if (wasBreak()) {
				if (prefs.verbosity >= 1) cmsg << user_abort().what() << endl;
				return 0;
			}
			wait_box.change("%s\n(output clean-up)\nline:%u deleted:%u replacements:%u",
				deflt_wait_banner, line_counter, total_deleted, accumulate(ARRAY_RANGE(adjusters), 0));
		}
		if (skip_lines > 0) {
			--skip_lines;
			++total_deleted;
			continue;
		}
// 		for_each(ARRAY_RANGE(deleters), boost::lambda::if_then(
// 			(boost::lambda::_1 ->* &deleter_t::count) > 0
// 			&& boost::lambda::bind(&PCRE::regexp::match,
// 				(boost::lambda::_1 ->* &deleter_t::regexp), boost::ref(line)),
// 			(++boost::lambda::var(total_deleted), boost::lambda::var(skip_lines) =
// 				(boost::lambda::_1 ->* &deleter_t::count) - 1, /*throw!!!*/))
// 		);
		for (const deleter_t *iter = deleters; iter != deleters + qnumber(deleters); ++iter)
			if (iter->count > 0 && iter->regexp.match(line)) {
				++total_deleted;
				skip_lines = iter->count - 1;
				break; //throw exit_scope();
			}
		if (iter != deleters + qnumber(deleters)) continue;
		if (!prefs.include_typedefs && is_segment_end.match(line)) {
			++total_deleted;
			continue; //throw exit_scope();
		}
		/*
		//PCRE::regexp::result match;
		if (match(is_quoted_singlequotes, line) >= 0) {
			_sprintf(line, "%s%s%s \"%s\"", match[1], match[2], ash.a_ascii, ash.match[3]);
			++total_deleted; // ???
		}
		if (match(is_quoted_doublequotes, line) >= 0) {
			_sprintf(line, "%s%s%s '%s'", match[1], match[2], ash.a_ascii, match[3]);
			++total_deleted; // ???
		}
		*/
		const bool was_spare(is_spare_line.match(line));
		if (!was_spare) for_each(ARRAY_RANGE(adjusters),
			boost::bind(PCRE::replacer::exec, _1, boost::ref(line)));
		const bool is_spare(was_spare || is_spare_line.match(line));
		if (spare_line && is_spare) { ++total_deleted; continue; }
		if (!was_spare && is_spare) {
			++total_deleted;
			spare_line = true;
			continue;
		}
		container << line << endl;
		spare_line = is_spare;
	}// catch (const exit_scope &) { /*line skipped, continue iteration*/ }
	fs.close();
	const uint total_replaced = accumulate(ARRAY_RANGE(adjusters), 0);
	// flush if changes made
	if (total_deleted > 0 || total_replaced > 0) {
		fs.clear();
		fs.open(filename, ios_base::out | ios_base::trunc);
		if (fs.good()) {
			fs << container.rdbuf();
			fs.close();
			if (prefs.verbosity >= 1) cmsg << "done: " << dec << total_deleted <<
				" line(s) deleted, " << total_replaced << " inline replacement(s) made" << endl;
		} else
			if (prefs.verbosity >= 1) cmsg << "failed" << endl;
	} else
		if (prefs.verbosity >= 1) cmsg << "not needed" << endl;
	return total_deleted;
}

static void ProcessNewOffset(ea_t from, ea_t to) {
#ifdef _SHOWADDRESS
	showAddr(from);
#endif
	_ASSERTE(isEnabled(from));
	if (!isEnabled(from)) return;
	if (to == BADADDR) get_many_bytes(from, &to, sizeof to);
	_ASSERTE(isEnabled(to));
	if (!isEnabled(to)) return;
	++total_offsets;
	analyze_area(from, next_not_tail(from));
	if (pBatchResults != 0) {
		char reft(isCode(get_flags_novalue(from)) && isCode(get_flags_novalue(to)) ?
			'c' : 'd'), name[MAXNAMESIZE], tmpstr[512];
		if (get_true_name(from, to, CPY(name)) != 0)
			qsnprintf(CPY(tmpstr), "ok: %cref to %s", reft, name);
		else
			qsnprintf(CPY(tmpstr), "ok: %cref to %08a", reft, to);
		pBatchResults->Add(from, 0x0005, tmpstr);
	} // list available
	if (prefs.verbosity >= 3) cmsg << prefix << "  info: offset created at " <<
		asea(from) << endl;
	nameanonoffsets_internal(from, prefs.verbosity, prefix, pBatchResults);
}

struct less_nocase : public binary_function<LPCSTR, LPCSTR, bool> {
	inline bool operator ()(LPCSTR s1, LPCSTR s2) const { return _stricmp(s1, s2) < 0; }
};

#define LINESIZE 16384
#define BUFCPY(name, size) name.get(), size
#define BUFCAT(name, size) tail(name.get()), size - strlen(name.get())

static uint EmuRuntimeData(FILE *file) {
	_ASSERTE(file != NULL);
	if (file == NULL || (cloned_blocks.empty() && imports.empty())) return 0;
	if (prefs.verbosity >= 1) cmsg << prefix << "emulating process runtime data: ";
	boost::scoped_array<char> line(new char[LINESIZE]);
	if (!line) {
		if (prefs.verbosity >= 1) cmsg << "failed: " << bad_alloc().what() << endl;
		_RPT2(_CRT_ERROR, "%s(...): failed to allocate new string of size 0x%X\n",
			__FUNCTION__, LINESIZE);
		throw bad_alloc(); //return 0;
	}
	char name[MAXNAMESIZE];
	vector<string> section[3]; // 0:code 1:data 2:const
	clonedblocks_t::const_iterator dynblock, refblock;
	ranges_t::const_iterator range;
	if (!cloned_blocks.empty()) {
		if (prefs.verbosity >= 1) cmsg << "generating virtual blocks...";
		char numprefix[5][0x20];
		const char *const tmp_table[] = {
			ash.a_byte, ash.a_word, ash.a_dword, ash.a_qword, ash.a_oword,
		};
		for (uint i = 0; i < qnumber(numprefix); ++i)
			qsnprintf(CPY(numprefix[i]), "\t%s", tmp_table[i]);
		for (dynblock = cloned_blocks.begin(); dynblock != cloned_blocks.end(); ++dynblock) try {
			if (wasBreak()) break; //throw user_abort();
#ifdef _SHOWADDRESS
			showAddr((ea_t)dynblock->BaseAddress);
#endif
			// code part - bind referrers
			for (clonedblock_t::referrers_t::const_iterator referrer = dynblock->referrers.begin(); referrer != dynblock->referrers.end(); ++referrer) try {
				char refname[MAXNAMESIZE];
				// find referrer owner block
				if ((range = static_ranges.find(reinterpret_cast<ea_t>(referrer->operator LPVOID()), false)) != static_ranges.end()) {
					// referrer from static range must link at runtime
					if (!range->GetLabel(CPY(refname), reinterpret_cast<ea_t>(referrer->operator LPVOID())))
						throw logic_error("cannot get referrer name");
				} else if ((refblock = cloned_blocks[referrer->BaseAddress]) != cloned_blocks.end()) {
					// integrity cross-check
					_ASSERTE(*(LPCVOID *)((LPBYTE)refblock->dump.get() + referrer->BaseOffset)
						== (LPBYTE)dynblock->BaseAddress + referrer->offset);
					if (/* obey size rule */prefs.dyndataxplorer_maxoffsetable != 0
						&& refblock->size > prefs.dyndataxplorer_maxoffsetable
						// referrer from cloned block on even address should be converted
						// to offset directly by cloned blocks generator depending on
						// dyndataxplorer_maxoffsetable value
						|| (reinterpret_cast<ea_t>(referrer->operator LPVOID()) & 3) == 0)
						continue;
					// otherwise must link at runtime
					if (!refblock->GetLabel(CPY(refname), referrer->BaseOffset))
						throw logic_error("cannot get referrer name");
				} else {
					_RPT3(_CRT_ASSERT, "%s(...): cannot get owner block for referrer at %08X+0x%lX (refname undefined)\n",
						__FUNCTION__, referrer->BaseAddress, referrer->BaseOffset);
					throw logic_error("referrer owner block lookup failed");
				}
				if (!dynblock->GetLabel(CPY(name), referrer->offset))
					throw logic_error("cannot get virtual block name");
				qsnprintf(BUFCPY(line, LINESIZE), "\tmov %cword ptr [%s], offset %s",
					ph.use64() ? 'q' : 'd', refname, name);
				if (!referrer->comment.empty()) qsnprintf(BUFCAT(line, LINESIZE),
					" %s %s", ash.cmnt, referrer->comment.c_str());
				section[0].push_back(line.get());
				total_bytes[0] += 2 + 2 * get_ptr_size();
			} catch (const exception &e) {
				dynblock->GetLabel(CPY(name));
				if (prefs.verbosity >= 1) cmsg << e.what() << " with referrer at " <<
					asptr(referrer->BaseAddress) << '+' << ashex(referrer->BaseOffset) <<
					" of block " << asptr(dynblock->BaseAddress) << '+' <<
					ashex(referrer->offset) << '/' << ashex(dynblock->size);
				if (name[0] != 0 && prefs.verbosity >= 1) cmsg << " (" << name << ')';
				if (prefs.verbosity >= 1) cmsg << "...";
			} // walk referrers
			// data part: gen dynamic block
			if (!dynblock->GetLabel(BUFCPY(line, LINESIZE)))
				throw logic_error("cannot get virtual block name");
			section[1].push_back(_sprintf("\t%s %Iu", ash.a_align, ph.use64() ?
				sizeof(DWORDLONG) : sizeof(DWORD)));
			// care comment
			if (!dynblock->comment.empty())
				section[1].push_back(_sprintf("%s %s: %s", ash.cmnt, line.get(),
					dynblock->comment.c_str()));
#ifdef _DEBUG
			if (!dynblock->referrers.empty())
				section[1].push_back(_sprintf("%s %Iu referrer(s)", ash.cmnt, dynblock->referrers.size()));
#endif
			size_t offset;
			uint foo;
			switch (GetStringType(dynblock->dump.get(), dynblock->size)) {
				case cstr:
					offset = strlen(static_cast<const char *>(dynblock->dump.get()));
					qsnprintf(BUFCAT(line, LINESIZE), "\t%s ", ash.a_ascii);
					GenStringTokens(BUFCAT(line, LINESIZE), dynblock->dump.get(), offset++);
					qstrncat(line.get(), ", 0", LINESIZE);
					foo = 1;
					break;
				case pstr:
					offset = *static_cast<uint8 *>(dynblock->dump.get());
					qsnprintf(BUFCAT(line, LINESIZE), "\t%s %Iu, ", ash.a_byte, offset);
					GenStringTokens(BUFCAT(line, LINESIZE),
						(const char *)((LPBYTE)dynblock->dump.get() + 1), offset++);
					foo = 1;
					break;
				case lstr:
					offset = *(static_cast<const uint32 *>(dynblock->dump.get()) + 1);
					_ASSERTE((*static_cast<const int32 *>(dynblock->dump.get()) == -1
						|| *static_cast<const int32 *>(dynblock->dump.get()) == 1
						|| *static_cast<const int32 *>(dynblock->dump.get()) == 2)
						&& *(static_cast<const int8 *>(dynblock->dump.get()) + 8 + offset) == 0);
					qsnprintf(BUFCAT(line, LINESIZE), "%s %I32i, %Iu %s type, len",
						numprefix[2], *static_cast<const int32 *>(dynblock->dump.get()),
						offset, ash.cmnt);
					section[1].push_back(line.get());
					qsnprintf(BUFCPY(line, LINESIZE), "\t%s ", ash.a_ascii);
					GenStringTokens(BUFCAT(line, LINESIZE),
						(const char *)((LPBYTE)dynblock->dump.get() + 8), offset);
					qstrncat(line.get(), ", 0", LINESIZE);
					foo = 1;
					offset += 9;
					break;
				/*
				case ucstr: // not implemented
					offset = wcslen((wchar_t *)dynblock->dump.get()) << 1;
					qstrncat(line.get(), "label word", LINESIZE);
					section[1].push_back(line.get());
					qstrncpy(line.get(), "unicode 0,<", LINESIZE);
					GenWStringTokens(BUFCAT(line, LINESIZE), dynblock->dump.get(), offset);
					qstrncat(line.get(), ">, 0", LINESIZE);
					section[1].push_back(line.get());
					break;
				case upstr: // not implemented
					offset = *(uint8 *)dynblock->dump.get();
					qsnprintf(BUFCAT(line, LINESIZE), "\t%s %Iu, ", ash.a_ascii, offset);
					GenWStringTokens(BUFCAT(line, LINESIZE), (wchar_t *)((int8 *)dynblock->dump.get() + 1), offset);
					break;
				case ulstr: // not implemented
					offset = *(uint32 *)dynblock->dump.get();
					qsnprintf(BUFCAT(line, LINESIZE), "\t%s %09I32X, %09IX", ash.a_dword,
						*(uint32 *)dynblock->dump.get(), offset);
					section[1].push_back(line.get());
					qsnprintf(BUFCPY(line, LINESIZE), "\t%s ", ash.a_ascii);
					GenWStringTokens(BUFCAT(line, LINESIZE), (wchar_t *)((int8 *)dynblock->dump.get() + 8), offset);
					qstrncat(line.get(), ", 0", LINESIZE);
					break;
				*/
				case nostr:
				default:
					foo = 0;
					offset = 0;
			} // data type switch
			size_t lastoffset(offset);
			// flush string first with dword padding bytes
			if (offset > 0) {
				while (offset < dynblock->size && ((offset & 3) != 0
					|| offset + 4 > dynblock->size))
					qsnprintf(BUFCAT(line, LINESIZE), "%s %03Xh", foo > 0 ? "," :
						numprefix[0], *((LPBYTE)dynblock->dump.get() + offset++));
				lastoffset = offset;
				section[1].push_back(line.get());
				line[0] = 0;
				foo = 0;
			}
			class not_offset { };
			hash_map<size_t, imports_t::const_iterator>::const_iterator impref;
			if (ph.use64() && ash.a_qword != NULL) {
				while (offset + sizeof(DWORDLONG) <= dynblock->size) {
					const DWORDLONG bar(*(PDWORDLONG)((PBYTE)dynblock->dump.get() + offset));
					try { // try as offset either to module or known heap block
						if (!prefs.createoffsets || prefs.dyndataxplorer_maxoffsetable != 0
							&& dynblock->size > prefs.dyndataxplorer_maxoffsetable) throw not_offset();
						if (Dyn2Stat(bar)) { // offset to captured static range
							const ea_t off64(netnode("$ offsets").altval(bar));
							if (CanOffFromDyn(off64)) {
								if (!GetLabel(off64, CPY(name))) throw not_offset();
								qsnprintf(BUFCAT(line, LINESIZE), "%s %cword ptr [%s]",
									foo > 0 ? "," : numprefix[3], 'q', name);
							} else if (CanOffFromDyn(bar)) {
#ifdef _DEBUG
								if (off64 != 0) _RPTF4(_CRT_WARN, "%s(...): offset translation not followed due to referrer inaccessibility in output: %08IX -> %08I64X (%s)\n",
									__FUNCTION__, off64, bar, "keeping direct reference");
#endif
								if (!GetLabel(bar, CPY(name))) throw not_offset();
								qsnprintf(BUFCAT(line, LINESIZE), "%s offset %s",
									foo > 0 ? "," : numprefix[3], name);
							} else { // none of above
#ifdef _DEBUG
								if (off64 != 0)
									_RPTF4(_CRT_WARN, "%s(...): offset translation not followed due to both targets inaccessibility in output: %08IX -> %08I64X (%s)\n",
										__FUNCTION__, off64, bar, "going raw");
								else
									_RPTF3(_CRT_WARN, "%s(...): target anchorable but not available in output: %08I64X (%s)\n",
										__FUNCTION__, bar, "going raw");
#endif // _DEBUG
								throw not_offset();
							}
						} else if (prefs.dyndataxplorer_map_imps_dir
							&& prefs.dyndataxplorer_offtodyn >= 1
							&& (impref = dynblock->imprefs.find(offset)) != dynblock->imprefs.end()) {
							_ASSERTE(impref->second->anchor.type() == typeid(string));
							_ASSERTE(!boost::get<string>(impref->second->anchor).empty());
							if (impref->second->DllName[0] != 0) {
								qsnprintf(CPY(name), "%s.%s", impref->second->DllName.c_str(),
									boost::get<string>(impref->second->anchor).c_str());
								if (!externals.insert(remappoint_t(reinterpret_cast<ea_t>(dynblock->BaseAddress),
									offset, name)).second) {
									if (prefs.verbosity >= 2) cmsg << prefix << "warning: failed to add address " <<
										asptr((PBYTE)dynblock->BaseAddress + offset) << " to external translation table" << endl;
									if (prefs.reporting_verbosity >= 1)
										report.Add(reinterpret_cast<ea_t>((PBYTE)dynblock->BaseAddress + offset),
											0x0FFF, "failed to add offset to translation table");
									throw not_offset();
								}
							}
#ifdef _DEBUG
							dynblock->GetLabel(CPY(name), offset);
							OutputDebugString("%s%s(...): address %s(%017I64Xh) mapped to import %s\n",
								prefix, __FUNCTION__, name, bar, boost::get<string>(impref->second->anchor).c_str());
#endif // _DEBUG
							qsnprintf(BUFCAT(line, LINESIZE), "%s offset %s", foo > 0 ? "," :
								numprefix[3], boost::get<string>(impref->second->anchor).c_str());
						} else if (prefs.dyndataxplorer_offtodyn >= 2
							&& (refblock = cloned_blocks.find((LPCVOID)bar, false)) != cloned_blocks.end()) { // offset to captured heap block
#ifdef _DEBUG
							// integrity cross-check
// 							const clonedblock_t::referrer_t R1((LPBYTE)bar - refblock->BaseAddress,
// 								dynblock->BaseAddress, offset);
// 							const clonedblock_t::referrers_t::const_iterator
// 								R2(refblock->referrers.find(R1));
// 							_ASSERTE(R2 != refblock->referrers.end() && R2->offset == R1.offset
// 								&& R2->BaseAddress == R1.BaseAddress && R2->BaseOffset == R1.BaseOffset);
#endif // _DEBUG
							if (!refblock->GetLabel(CPY(name), reinterpret_cast<LPCVOID>(bar)))
								throw not_offset();
							qsnprintf(BUFCAT(line, LINESIZE), "%s offset %s", foo > 0 ? "," :
								numprefix[3], name);
						} else
							throw not_offset();
					} catch (const not_offset &) { // go raw
						qsnprintf(BUFCAT(line, LINESIZE), "%s %017I64Xh",
							foo > 0 ? "," : numprefix[3], bar);
					}
					offset += sizeof DWORDLONG;
					if (++foo >= 2) { // flush line
						if (lastoffset > 0) qsnprintf(BUFCAT(line, LINESIZE), "\t%s +0%IXh",
							ash.cmnt, lastoffset);
						lastoffset = offset;
						section[1].push_back(line.get());
						line[0] = 0;
						foo = 0;
					}
				} // qwords
				if (foo > 0) {
					if (lastoffset > 0) qsnprintf(BUFCAT(line, LINESIZE), "\t%s +0%IXh",
						ash.cmnt, lastoffset);
					lastoffset = offset;
					section[1].push_back(line.get());
					line[0] = 0;
					foo = 0;
				}
			} // use64
			if (ph.use32() && ash.a_dword != NULL) {
				while (offset + sizeof(DWORD) <= dynblock->size) {
					const DWORD bar(*(PDWORD)((PBYTE)dynblock->dump.get() + offset));
					try { // try as offset either to module or known heap block
						if (!prefs.createoffsets || prefs.dyndataxplorer_maxoffsetable != 0
							&& dynblock->size > prefs.dyndataxplorer_maxoffsetable) throw not_offset();
						if (Dyn2Stat(bar)) { // offset to captured static range
							const ea_t off32(netnode("$ offsets").altval(bar));
							if (CanOffFromDyn(off32)) {
								if (!GetLabel(off32, CPY(name))) throw not_offset();
								qsnprintf(BUFCAT(line, LINESIZE), "%s %cword ptr [%s]",
									foo > 0 ? "," : numprefix[2], 'd', name);
							} else if (CanOffFromDyn(bar)) {
#ifdef _DEBUG
								if (off32 != 0) _RPTF4(_CRT_WARN, "%s(...): offset translation not followed due to referrer inaccessibility in output: %08IX -> %08lX (%s)\n",
									__FUNCTION__, off32, bar, "keeping direct reference");
#endif
								if (!GetLabel(bar, CPY(name))) throw not_offset();
								qsnprintf(BUFCAT(line, LINESIZE), "%s offset %s",
									foo > 0 ? "," : numprefix[2], name);
							} else { // none of above
#ifdef _DEBUG
								if (off32 != 0)
									_RPTF4(_CRT_WARN, "%s(...): offset translation not followed due to both targets inaccessibility in output: %08IX -> %08lX (%s)\n",
										__FUNCTION__, off32, bar, "going raw");
								else
									_RPTF3(_CRT_WARN, "%s(...): target anchorable but not available in output: %08lX (%s)\n",
										__FUNCTION__, bar, "going raw");
#endif // _DEBUG
								throw not_offset();
							}
						} else if (prefs.dyndataxplorer_map_imps_dir
							&& prefs.dyndataxplorer_offtodyn >= 1
							&& (impref = dynblock->imprefs.find(offset)) != dynblock->imprefs.end()) {
							_ASSERTE(impref->second->anchor.type() == typeid(string));
							_ASSERTE(!boost::get<string>(impref->second->anchor).empty());
							if (impref->second->DllName[0] != 0) {
								qsnprintf(CPY(name), "%s.%s", impref->second->DllName.c_str(),
									boost::get<string>(impref->second->anchor).c_str());
								if (!externals.insert(remappoint_t(reinterpret_cast<ea_t>(dynblock->BaseAddress),
									offset, name)).second) {
									if (prefs.verbosity >= 2) cmsg << prefix << "warning: failed to add address " <<
										asptr((PBYTE)dynblock->BaseAddress + offset) << " to external translation table" << endl;
									if (prefs.reporting_verbosity >= 1)
										report.Add(reinterpret_cast<ea_t>((PBYTE)dynblock->BaseAddress + offset),
											0x0FFF, "failed to add offset to translation table");
									throw not_offset();
								}
							}
#ifdef _DEBUG
							dynblock->GetLabel(CPY(name), offset);
							OutputDebugString("%s%s(...): address %s(%09IXh) mapped to import %s\n",
								prefix, __FUNCTION__, name, bar, boost::get<string>(impref->second->anchor).c_str());
#endif // _DEBUG
							qsnprintf(BUFCAT(line, LINESIZE), "%s offset %s", foo > 0 ? "," :
								numprefix[2], boost::get<string>(impref->second->anchor).c_str());
						} else if (prefs.dyndataxplorer_offtodyn >= 2
							&& (refblock = cloned_blocks.find((LPCVOID)bar, false)) != cloned_blocks.end()) { // offset to captured heap block
#ifdef _DEBUG
							// integrity cross-check
// 							const clonedblock_t::referrer_t R1((LPBYTE)bar - refblock->BaseAddress,
// 								dynblock->BaseAddress, offset);
// 							const clonedblock_t::referrers_t::const_iterator
// 								R2(refblock->referrers.find(R1));
// 							_ASSERTE(R2 != refblock->referrers.end() && R2->offset == R1.offset
// 								&& R2->BaseAddress == R1.BaseAddress && R2->BaseOffset == R1.BaseOffset);
#endif // _DEBUG
							if (!refblock->GetLabel(CPY(name), reinterpret_cast<LPCVOID>(bar)))
								throw not_offset();
							qsnprintf(BUFCAT(line, LINESIZE), "%s offset %s", foo > 0 ? "," :
								numprefix[2], name);
						} else
							throw not_offset();
					} catch (const not_offset &) { // go raw
						qsnprintf(BUFCAT(line, LINESIZE), "%s %09lXh",
							foo > 0 ? "," : numprefix[2], bar);
					}
					offset += sizeof DWORD;
					if (++foo >= 4) {
						if (lastoffset > 0) qsnprintf(BUFCAT(line, LINESIZE), "\t%s +0%IXh",
							ash.cmnt, lastoffset);
						lastoffset = offset;
						section[1].push_back(line.get());
						line[0] = 0;
						foo = 0;
					}
				} // dwords
				if (foo > 0) {
					if (lastoffset > 0) qsnprintf(BUFCAT(line, LINESIZE), "\t%s +0%IXh",
						ash.cmnt, lastoffset);
					lastoffset = offset;
					section[1].push_back(line.get());
					line[0] = 0;
					foo = 0;
				}
			} // use32
			while (offset + sizeof WORD <= dynblock->size) {
				qsnprintf(BUFCAT(line, LINESIZE), "%s %05lXh", foo > 0 ? "," :
					numprefix[1], *(PWORD)((PBYTE)dynblock->dump.get() + offset));
				offset += sizeof WORD;
				if (++foo >= 8) {
					if (lastoffset > 0) qsnprintf(BUFCAT(line, LINESIZE), "\t%s +0%IXh",
						ash.cmnt, lastoffset);
					lastoffset = offset;
					section[1].push_back(line.get());
					line[0] = 0;
					foo = 0;
				}
			} // words
			if (foo > 0) {
				if (lastoffset > 0) qsnprintf(BUFCAT(line, LINESIZE), "\t%s +0%IXh",
					ash.cmnt, lastoffset);
				lastoffset = offset;
				section[1].push_back(line.get());
				line[0] = 0;
				foo = 0;
			}
			while (offset + sizeof BYTE <= dynblock->size) {
				qsnprintf(BUFCAT(line, LINESIZE), "%s %03Xh", foo > 0 ? "," :
					numprefix[0], *((PBYTE)dynblock->dump.get() + offset));
				offset += sizeof BYTE;
				if (++foo >= 16) {
					if (lastoffset > 0) qsnprintf(BUFCAT(line, LINESIZE), "\t%s +0%IXh",
						ash.cmnt, lastoffset);
					lastoffset = offset;
					section[1].push_back(line.get());
					line[0] = 0;
					foo = 0;
				}
			} // bytes
			if (foo > 0) {
				if (lastoffset > 0) qsnprintf(BUFCAT(line, LINESIZE), "\t%s +0%IXh",
					ash.cmnt, lastoffset);
				section[1].push_back(line.get());
			}
		} catch (const exception &e) {
			if (prefs.verbosity >= 1) {
				dynblock->GetLabel(CPY(name));
				cmsg << e.what() << " with block " << asptr(dynblock->BaseAddress) <<
					'/' << ashex(dynblock->size);
				if (name[0] != 0) cmsg << " (" << name << ')';
				cmsg << "...";
			}
		}
	} // write virtual ranges
	if (!imports.empty()) {
		if (prefs.verbosity >= 1) cmsg << "binding imports...";
		uint label_counter(0);
		typedef map<LPCSTR, uint, less_nocase> libitems_t;
		libitems_t libitems;
		for (imports_t::const_iterator import = imports.begin(); import != imports.end(); ++import) try {
			if (wasBreak()) break; //throw user_abort();
			if (import->anchor.type() == typeid(string)) { // import by name
				_ASSERTE(import->hasDllName());
				if (prefs.dyndataxplorer_map_imps_dir // projected to deadcode directly?
					&& !isEnabled(reinterpret_cast<ea_t>(import->operator LPCVOID()))
					&& (dynblock = cloned_blocks.find(*import, false)) != cloned_blocks.end()
					&& dynblock->offset(*import) % (ph.use64() ?
						sizeof(DWORDLONG) : sizeof(DWORD)) == 0) continue;
				//if (import->hasDllName())
					section[0].push_back(_sprintf("\tmov eax, %cword ptr [%s] %s %s",
						ph.use64() ? 'q' : 'd', boost::get<string>(import->anchor).c_str(),
						ash.cmnt, import->DllName.c_str()));
				//else
				//	section[0].push_back(_sprintf("\tmov eax, offset %s",
				//		boost::get<string>(import->anchor).c_str()));
				total_bytes[0] += 1 + get_ptr_size();
			} else { // anchor to module name
				libitems_t::const_iterator libitem;
				if (import->hasDllName()
					&& (libitem = libitems.find(import->DllName)) == libitems.end()) {
					libitem = libitems.insert(libitems_t::value_type(import->DllName,
						libitems.size() + 1)).first;
					_ASSERTE(libitem != libitems.end());
					section[2].push_back(_sprintf("\t%s%u %s %c%s%c, 0",
						libname_prefix, libitem->second, ash.a_ascii,
						ash.ascsep, libitem->first, ash.ascsep));
					total_bytes[2] += strlen(libitem->first) + 1;
				}
				if (import->anchor.type() == typeid(WORD)) { // import by ordinal
					const WORD &Ordinal(boost::get<WORD>(import->anchor));
					_ASSERTE(import->hasDllName());
					section[0].push_back(_sprintf("\tpush offset %s%u %s %s",
						libname_prefix, libitem->second, ash.cmnt, import->DllName.c_str()));
					section[0].push_back("\tcall GetModuleHandle");
					section[0].push_back("\ttest eax, eax");
					section[0].push_back(_sprintf("\tjz @@lbl_%u", ++label_counter));
					section[0].push_back(_sprintf("\tpush %hu %s by ordinal", Ordinal, ash.cmnt));
					section[0].push_back("\tpush eax");
					section[0].push_back("\tcall GetProcAddress");
					section[0].push_back("\ttest eax, eax");
					section[0].push_back(_sprintf("\tjz @@lbl_%u", label_counter));
					total_bytes[0] += 27 + (Ordinal < 0x80 ? 2 : 5); // 32-bit!!!
				} else { // !hasImport(), anchor to modulebase
					_ASSERTE(import->anchor.type() == typeid(DWORD));
					if (import->hasDllName()) {
						section[0].push_back(_sprintf("\tpush offset %s%u %s %s",
							libname_prefix, libitem->second, ash.cmnt, import->DllName.c_str()));
						total_bytes[0] += 1 + get_ptr_size();
					} else { // !import->hasDllName() -> hInstance
						section[0].push_back("\tpush 0");
						total_bytes[0] += 2;
					}
					section[0].push_back("\tcall GetModuleHandle");
					total_bytes[0] += 6; // 5 if use thunk functions!
					if (import->hasDllName()) {
						section[0].push_back("\ttest eax, eax");
						section[0].push_back(_sprintf("\tjz @@lbl_%u", ++label_counter));
						total_bytes[0] += 4;
					}
					const DWORD &RVA(boost::get<DWORD>(import->anchor));
					if (RVA > 0) {
						section[0].push_back(_sprintf("\tadd eax, 0%lXh", RVA));
						total_bytes[0] += 1 + (RVA < 0x80 ? 2 : 4);
					}
				} // !hasImport(), anchor to modulebase
			} // anchor to module name
			// get the block and it's name
			if ((range = static_ranges.find(reinterpret_cast<ea_t>(import->Address), false)) != static_ranges.end()) {
				if (!range->GetLabel(CPY(name), reinterpret_cast<ea_t>(import->Address)))
					throw logic_error("cannot get static range name");
			} else if ((refblock = cloned_blocks.find(import->Address, false)) != cloned_blocks.end()) {
				if (!refblock->GetLabel(CPY(name), import->Address))
					throw logic_error("cannot get virtual block name");
			} else {
				_RPTF2(_CRT_ASSERT, "%s(...): import offset owner block lookup failed: %08X\n",
					__FUNCTION__, import->Address);
				throw logic_error("import owner block lookup failed");
			}
			_ASSERTE(name[0] != 0);
			qsnprintf(BUFCPY(line, LINESIZE), "\tmov %cword ptr [%s], eax",
				ph.use64() ? 'q' : 'd', name);
			if (!import->comment.empty()) qsnprintf(BUFCAT(line, LINESIZE), " %s %s",
				ash.cmnt, import->comment.c_str());
			section[0].push_back(line.get());
			total_bytes[0] += 1 + get_ptr_size();
			if (import->anchor.type() != typeid(string) && import->hasDllName())
				section[0].push_back(_sprintf("@@lbl_%u:", label_counter));
		} catch (const exception &e) {
			if (prefs.verbosity >= 1) cmsg << e.what() << ": ea=" <<
				asptr(import->Address) << " (" << (import->hasDllName() ?
				import->DllName.c_str() : "NULL") << ':' << import->anchor << ")...";
		}
	} // // map imports
	uint result(0);
	// flush sections to file
	_ASSERTE(!section[0].empty() || !section[1].empty() || !section[2].empty());
	if (!section[0].empty() || !section[1].empty() || !section[2].empty()) {
		if (prefs.verbosity >= 1) cmsg << "flushing to file...";
		const string seglines[3][2] = {
			// .code
			_sprintf("\n%s\n\n"
				"%s ---- process runtime data projection by csc plugin ----\n", code_sec,
				ash.cmnt).append(_sprintf(proc_start, emu_procname)).append(1, '\n'),
			string("\tretn\n").append(_sprintf(proc_end, emu_procname)).append(1, '\n'),
			// .data
			_sprintf("\n%s %s replica of process workspace\n\n", data_sec, ash.cmnt),
			string(),
			// .const
			_sprintf("\n%s\n\n", const_sec),
			string(),
		};
		for (uint index = 0; index < qnumber(section); ++index) try {
			if (wasBreak()) break;
			if (section[index].empty()) continue;
			if (!seglines[index][0].empty()) // write prologue
				ewrite(file, seglines[index][0].data(), seglines[index][0].length());
			for (vector<string>::const_iterator line = section[index].begin();
				line != section[index].end(); ++line) {
				ewrite(file, line->data(), line->length());
				ewrite(file, SIZEDTEXT("\n"));
			}
			if (!seglines[index][1].empty()) // write epilogue
				ewrite(file, seglines[index][1].data(), seglines[index][1].length());
			if (index == 0) ++total_bytes[0]; // retn (0xC3)
			static const uint8 linecounts[] = { 7, 3, 3, };
			result += linecounts[index] + section[index].size();
		} catch (const exception &e) {
			if (prefs.verbosity >= 1) {
				cmsg << e.what() << " writing emu source section ";
				switch (index) {
					case 0: cmsg << "code"; break;
					case 1: cmsg << "data"; break;
					case 2: cmsg << "const"; break;
				}
				cmsg << "...";
			}
		}
		if (!section[0].empty()) ++total_funcs; // proc csc_emu_rtdata
	} // dump sections to file
	_ASSERTE(!cloned_blocks.empty() || !imports.empty());
	if (prefs.verbosity >= 1) cmsg << "done" << endl;
	return result;
}

#undef LINESIZE
#undef BUFCPY
#undef BUFCAT

static uint TransleteExternals(FILE *file) {
	_ASSERTE(file != NULL);
	if (file == NULL || externals.empty()) return 0;
	if (prefs.verbosity >= 1) cmsg << prefix << "generating offset translations...";
	//OutputDebugString("%s%s(...): %Iu offsets to translate\n",
	//	prefix, __FUNCTION__, externals.size());
	uint total(0), foo(0);
	for (remappoints_t::const_iterator iter = externals.begin(); iter != externals.end(); ++iter) {
		if (wasBreak()) break;
#ifdef _SHOWADDRESS
		showAddr(*iter);
#endif
		char name[MAXNAMESIZE];
		if (!GetLabel(*iter, CPY(name))) continue;
		string line;
		if (foo == 0) {
			_sprintf(line, "\n%s\n\n\t%s %Iu\n%s", const_sec, ash.a_align,
				offset_boundary, trn_tablename);
			ewrite(file, line.data(), line.length());
			total = get_ptr_size();
		}
		_sprintf(line, "\t%s offset %s", ph.use64() ? ash.a_qword : ash.a_dword, name);
		ewrite(file, line.data(), line.length());
		total_bytes[2] += get_ptr_size();
		ea_t tgt;
		if (isEnabled(*iter))
			tgt = /*calc_reference_target*/can_be_off32(*iter);
		else {
			const clonedblocks_t::const_iterator
				dyndata(cloned_blocks[(LPCVOID)iter->BaseAddress]);
			if (dyndata != cloned_blocks.end())
				tgt = *(ea_t *)((LPBYTE)dyndata->dump.get() + iter->BaseOffset);
			else {
				tgt = BADADDR; // ooops
				_RPTF3(_CRT_ASSERT, "%s(...): %s(%08X) == cloned_blocks.end()\n",
					__FUNCTION__, "CSC::clonedblocks_t::find", iter->BaseAddress);
			}
		}
		//_ASSERTE(is_libname(tgt));
		char tgtname[MAXNAMESIZE];
		if (get_name(BADADDR, tgt, CPY(tgtname)) != 0) {
			_sprintf(line, " ; %s", tgtname);
			ewrite(file, line.data(), line.length());
		}
// #ifdef _DEBUG
// 		else
// 			_RPTF3(_CRT_ASSERT, "%s(...): %s(BADADDR, %08IX, ...) == 0\n",
// 				__FUNCTION__, "get_name", tgt);
// #endif // _DEBUG
		if (!iter->comment.empty()) {
			_sprintf(line, " %s %s", ash.cmnt, iter->comment.c_str());
			ewrite(file, line.data(), line.length());
		}
		if (foo > 0) {
			_sprintf(line, " %s +0%Xh", ash.cmnt, foo);
			ewrite(file, line.data(), line.length());
		}
		ewrite(file, SIZEDTEXT("\n"));
		++foo;
		++total;
	} // iterate externals
	if (foo > 0) {
		string trn_proc;
		_sprintf(trn_proc, "\n%s\n\n"
			"%s ---- external address translation by csc plugin ----\n", code_sec, ash.cmnt);
		_sprintf_append(trn_proc, proc_start, trn_procname);
		_sprintf_append(trn_proc, "\n"
			"\tpush esi\n"
			"\tmov esi, offset %s\n"
			"\tmov ecx, 0%Xh\n"
			"@@loop:\n"
			"\tlodsd\n"
			"\ttest eax, eax\n"
			"\tjz @@next\n"
			"\tmov edx, [eax]\n"
			"\ttest edx, edx\n"
			"\tjz @@next\n"
			"\tmov edx, [edx]\n"
			"\tmov [eax], edx\n"
			"@@next:\n"
			"\tloop @@loop\n"
			"\tpop esi\n"
			"\tretn\n", trn_tablename, foo);
		_sprintf_append(trn_proc, proc_end, trn_procname);
		trn_proc.push_back('\n');
		ewrite(file, trn_proc.data(), trn_proc.length());
		total += 22;
		total_bytes[0] += 30; // 32-bit!!!
		++total_funcs;
		++total_vars;
	}
	if (prefs.verbosity >= 1) cmsg << "done: " << dec << foo << " extrn offsets" << endl;
	return total;
}

#define RESERVELINE if (!freeline) { \
	ewrite(file, SIZEDTEXT("\n")); \
	freeline = true; ++result; \
}

static uint GenWarnings(FILE *file) {
	_ASSERTE(file != NULL);
	if (file == NULL) return 0;
	string assm;
	uint result(0);
	bool freeline(false);
	if (!prefs.include_thunkfuncs) {
		RESERVELINE
		_sprintf(assm, "%s thunk import functions excluded from export: insert standard header file(s) here\n",
			ash.cmnt);
		ewrite(file, assm.data(), assm.length());
		++result;
	}
	if (!prefs.externdefs) {
		RESERVELINE
		_sprintf(assm, "%s externdefs excluded from export: include all referenced symbols or standard header file(s) here\n",
			ash.cmnt);
		ewrite(file, assm.data(), assm.length());
		++result;
	}
	if (!prefs.include_libitems) {
		RESERVELINE
		_sprintf(assm, "%s library functions excluded from export: insert corresponding header file(s) here\n",
			ash.cmnt);
		ewrite(file, assm.data(), assm.length());
		++result;
	}
	if (!cloned_blocks.empty() || !imports.empty()) {
		RESERVELINE
		_sprintf(assm, "%s call %s before any ripped code is executed!\n",
			ash.cmnt, emu_procname);
		ewrite(file, assm.data(), assm.length());
		++result;
	}
	if (!externals.empty() || prefs.dbg_savedata && prefs.dbg_exploreheaps
		&& prefs.dyndataxplorer_offtodyn >= 1 && prefs.dyndataxplorer_map_imps_dir
		&& dumper.used_translation) {
		RESERVELINE
		_sprintf(assm, "%s call %s before any ripped code is executed!\n",
			ash.cmnt, trn_procname);
		ewrite(file, assm.data(), assm.length());
		++result;
	}
	return result;
}

#undef RESERVELINE

static void AddArgValue(const func_t &func, const char *argname,
	DWORD value, asize_t param_size = sizeof DWORD) {
	char name[MAXNAMESIZE], funcname[MAXNAMESIZE];
	qstrcpy(name, "offset ");
	if (param_size < sizeof DWORD || !GetLabel(static_cast<ea_t>(value), CAT(name)))
		if (param_size >= sizeof(DWORD))
			qsnprintf(CPY(name), "%08lX", value);
		else if (param_size >= sizeof(WORD))
			qsnprintf(CPY(name), "%04lX", value);
		else
			qsnprintf(CPY(name), "%02lX", value);
	get_func_name(&func, CPY(funcname));
	string appendix;
	_sprintf(appendix, "param %s of %s initialized to %s", argname, funcname, name);
	if (prefs.verbosity >= 3) cmsg << prefix << "  info: " << appendix << endl;
	if (prefs.reporting_verbosity >= 2) report.Add(func.startEA, 0x0118, appendix.c_str());
	_sprintf(appendix, "param %s initialized to %s", argname, name);
	static_ranges.add_comment(func.startEA, appendix);
	//append_unique_cmt(func.startEA, appendix.c_str(), true);
}

static string_t GetStringType(const void *buf, size_t bufsize) {
	if (bufsize > 4) {
		size_t size;
		if (*(const int32 *)buf == -1 || *(const int32 *)buf == 1
			|| *(const int32 *)buf == 2) { // try as lstring
			size = *((const uint32 *)buf + 1);
			if (size > 4/* && (size + 12 & ~3) == bufsize*/) {
				for (uint iter = 0; iter < size; ++iter)
					if (_isascii(*((const uchar *)buf + 8 + iter)) == 0)
						break;
				if (iter >= size) {
#ifdef _DEBUG
					if (*(const int32 *)buf == -1)
						_RPT1(_CRT_WARN, "%s(...): lstring of type -1 found on stack\n",
							__FUNCTION__);
#endif // _DEBUG
					return lstr;
				}
			}
		}
		// try as pstring
		size = *((const uint8 *)buf);
		if (size > 4 && (size + 4 & ~3) == bufsize) {
			for (uint iter = 0; iter < size; ++iter)
				if (_isascii(*((const uint8 *)buf + 1 + iter)) == 0) break;
			if (iter >= size) return pstr;
		}
		// try as cstring
		for (const uint8 *ch = (const uint8 *)buf; _isascii(*ch) != 0; ++ch);
		if (*ch == 0 && ch - (const uint8 *)buf < bufsize
			&& ch - (const uint8 *)buf > 4) return cstr;
	}
	return nostr;
}

static bool GenStringTokens(char *buf, size_t bufsize,
	const void *dump, size_t dumpsize) {
	_ASSERTE(buf != 0 && dump != 0 && dumpsize > 0 && bufsize >= dumpsize);
	if (buf == 0 || bufsize <= 0) return false;
	*buf = 0;
	if (dump == 0 || dumpsize <= 0) return false;
	bool quote(false), first(true);
	string tmp;
	for (uint iter = 0; iter < dumpsize; ++iter) {
		const uchar c(*(static_cast<const uchar *>(dump) + iter));
		const bool printable(isprint(c));
		_ASSERTE(printable || isspace(c));
		if (printable) {
			if (!quote) tmp.push_back(ash.ascsep);
			tmp.push_back(c);
			if (c == ash.ascsep) tmp.push_back(ash.ascsep); // double quotes
		} else {
			if (quote && !first) {
				tmp.push_back(ash.ascsep);
				tmp.append(", ");
			}
			_sprintf_append(tmp, "%03Xh, ", c);
		}
		quote = printable;
		first = false;
	}
	if (!first) if (quote)
		tmp.push_back(ash.ascsep);
	else
		tmp.erase(tmp.length() - 2);
	if (tmp.length() >= bufsize) return false;
	qstrncpy(buf, tmp.c_str(), bufsize);
	return !first;
}

void ash_set_masm() {
	ash.flag = AS_OFFST | AS_UDATA | AS_HEXFM & ASH_HEXF0 |
		AS_DECFM & ASD_DECF0 | AS_OCTFM & ASO_OCTF0 | AS_BINFM & ASB_BINF0 |
		AS_UNEQU | AS_NOXRF | AS_XTRNTYPE | AS_RELSUP;
	//ash.uflag = 0;
	ash.name = "MASM 6.0";
	ash.help = 0;
	ash.header = 0;
	ash.origin = "org";
	ash.end = "end";
	ash.cmnt = ";";
	ash.ascsep = '\"';
	ash.accsep = '\'';
	ash.esccodes = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
		"'\"\x7F"
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"
		"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF"
		"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
		"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"
		"\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF"
		"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF"
		"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"
		"\x00";
	ash.a_ascii = "db";
	ash.a_byte = "db";
	ash.a_word = "dw";
	ash.a_dword = "dd";
	ash.a_qword = "dq";
	ash.a_oword = 0;
	ash.a_float = "real4"; // "dd"
	ash.a_double = "real8"; // "dq"
	ash.a_tbyte = "dt";
	ash.a_packreal = 0;
	ash.a_dups = "#d dup(#v)";
	ash.a_bss = "db    ? ;";
	ash.a_equ = "equ";
	ash.a_seg = "seg";
	//ash.checkarg_preline = 0;
	//ash.checkarg_atomprefix = 0;
	//ash.checkarg_operations = 0;
	ash.XlatAsciiOutput = (const uchar *)
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
		" !\"#$%&'()*+,-./0123456789:;<=>?"
		"@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7F"
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"
		"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF"
		"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
		"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"
		"\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF"
		"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF"
		"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF";
	ash.a_curip = "$";
	//ash.func_header = 0;
	//ash.func_footer = 0;
	ash.a_public = "public";
	ash.a_weak = 0;
	ash.a_extrn = "externdef";
	ash.a_comdef = "comm";
	//ash.get_type_name = 0;
	ash.a_align = "align";
	ash.lbrace = '(';
	ash.rbrace = ')';
	ash.a_mod = "mod";
	ash.a_band = "and";
	ash.a_bor = "or";
	ash.a_xor = "xor";
	ash.a_bnot = "not";
	ash.a_shl = "shl";
	ash.a_shr = "shr";
	ash.a_sizeof_fmt = "sizeof %s";
	ash.flag2 = AS2_TERSESTR;
	ash.cmnt2 = 0;
	ash.low8 = 0;
	ash.high8 = 0;
	ash.low16 = "lowword %s";
	ash.high16 = "highword %s";
	ash.a_include_fmt = "include <%s>";
	ash.a_vstruc_fmt = 0;
	// csc specific
	code_sec = ".code";
	data_sec = ".data";
	const_sec = ".const";
	bss_sec = ".data?";
	proc_start = "%s proc near";
	proc_end = "%s endp";
}

// TODO: not fully implemented
void ash_set_tasm() {
	//ash.flag = AS_OFFST | AS_UDATA | AS_HEXFM & ASH_HEXF0 |
	//	AS_DECFM & ASD_DECF0 | AS_OCTFM & ASO_OCTF0 | AS_BINFM & ASB_BINF0 |
	//	AS_UNEQU | AS_NOXRF | AS_XTRNTYPE | AS_RELSUP;
	//ash.uflag = 0;
	ash.name = "TASM 5.0 Ideal";
	ash.help = 0;
	ash.header = 0;
	ash.origin = "org";
	ash.end = "end";
	ash.cmnt = ";";
	ash.ascsep = '\"';
	ash.accsep = '\'';
	ash.esccodes = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
		"'\"\x7F"
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"
		"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF"
		"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
		"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"
		"\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF"
		"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF"
		"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"
		"\x00";
	ash.a_ascii = "db";
	ash.a_byte = "db";
	ash.a_word = "dw";
	ash.a_dword = "dd";
	ash.a_qword = "dq";
	ash.a_oword = 0;
	ash.a_float = "dd";
	ash.a_double = "dq";
	ash.a_tbyte = "dt";
	ash.a_packreal = 0;
	ash.a_dups = "#d dup(#v)";
	ash.a_bss = "db    ? ;";
	ash.a_equ = "equ";
	ash.a_seg = "seg";
	//ash.checkarg_preline = 0;
	//ash.checkarg_atomprefix = 0;
	//ash.checkarg_operations = 0;
	ash.XlatAsciiOutput = (const uchar *)
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
		" !\"#$%&'()*+,-./0123456789:;<=>?"
		"@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7F"
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"
		"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF"
		"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
		"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"
		"\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF"
		"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF"
		"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF";
	ash.a_curip = "$";
	//ash.func_header = 0;
	//ash.func_footer = 0;
	ash.a_public = "public";
	ash.a_weak = 0;
	ash.a_extrn = "extrn";
	ash.a_comdef = "comm";
	//ash.get_type_name = 0;
	ash.a_align = "align";
	ash.lbrace = '(';
	ash.rbrace = ')';
	ash.a_mod = "mod";
	ash.a_band = "and";
	ash.a_bor = "or";
	ash.a_xor = "xor";
	ash.a_bnot = "not";
	ash.a_shl = "shl";
	ash.a_shr = "shr";
	ash.a_sizeof_fmt = "size %s";
	ash.flag2 |= AS2_IDEALDSCR | AS2_TERSESTR;
	ash.cmnt2 = 0;
	ash.low8 = "low %s";
	ash.high8 = "high %s";
	ash.low16 = 0;
	ash.high16 = 0;
	ash.a_include_fmt = "include \"%s\"";
	ash.a_vstruc_fmt = 0;
	// csc specific
	code_sec = ".code";
	data_sec = ".data";
	const_sec = ".const";
	bss_sec = ".data?";
	proc_start = "%s proc near";
	proc_end = "%s endp";
}

// TODO: not fully implemented
void ash_set_nasm() {
	ash.flag = AS_UDATA | AS_1TEXT | AS_HEXFM & ASH_HEXF0 |
		AS_DECFM & ASD_DECF0 | AS_OCTFM & ASO_OCTF0 | AS_BINFM & ASB_BINF0 |
		AS_UNEQU | AS_NOXRF | AS_XTRNTYPE | AS_RELSUP;
	//ash.uflag = 0;
	ash.name = "NASM (The Netwide Assembler)";
	//ash.help = 0;
	//ash.header = 0;
	//ash.origin = "org";
	//ash.end = "end";
	//ash.cmnt = ";";
	//ash.ascsep = '\'';
	//ash.accsep = '\'';
	ash.esccodes = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
		"'\"\x7F"
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"
		"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF"
		"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
		"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"
		"\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF"
		"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF"
		"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"
		"\x00";
	//ash.a_ascii = "db";
	ash.a_byte = "db";
	ash.a_word = "dw";
	ash.a_dword = "dd";
	ash.a_qword = "dq";
	//ash.a_oword = 0;
	//ash.a_float = "real4"; // "dd"
	//ash.a_double = "real8"; // "dq"
	//ash.a_tbyte = "dt";
	//ash.a_packreal = 0;
	//ash.a_dups = "#d dup(#v)";
	//ash.a_bss = "db    ? ;";
	//ash.a_equ = "equ";
	//ash.a_seg = "seg";
	//ash.checkarg_preline = 0;
	//ash.checkarg_atomprefix = 0;
	//ash.checkarg_operations = 0;
	ash.XlatAsciiOutput = (const uchar *)
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
		" !\"#$%&'()*+,-./0123456789:;<=>?"
		"@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7F"
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"
		"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF"
		"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
		"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"
		"\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF"
		"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF"
		"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF";
	//ash.a_curip = "$";
	//ash.func_header = 0;
	//ash.func_footer = 0;
	//ash.a_public = "public";
	//ash.a_weak = 0;
	//ash.a_extrn = "externdef";
	//ash.a_comdef = "comm";
	//ash.get_type_name = 0;
	//ash.a_align = "align";
	//ash.lbrace = '(';
	//ash.rbrace = ')';
	//ash.a_mod = "mod";
	//ash.a_band = "and";
	//ash.a_bor = "or";
	//ash.a_xor = "xor";
	//ash.a_bnot = "not";
	//ash.a_shl = "shl";
	//ash.a_shr = "shr";
	//ash.a_sizeof_fmt = "sizeof %s";
	//ash.flag2 = AS2_TERSESTR;
	//ash.cmnt2 = 0;
	//ash.low8 = 0;
	//ash.high8 = 0;
	//ash.low16 = "lowword %s";
	//ash.high16 = "highword %s";
	//ash.a_include_fmt = "include <%s>";
	//ash.a_vstruc_fmt = 0;
	// csc specific
	code_sec = ".code";
	data_sec = ".data";
	const_sec = ".const";
	bss_sec = ".data?";
	proc_start = "%s proc near";
	proc_end = "endproc";
}

// TODO: not fully implemented
void ash_set_fasm() {
	//ash.flag = AS_OFFST | AS_UDATA | AS_1TEXT | AS_HEXFM & ASH_HEXF0 |
	//	AS_DECFM & ASD_DECF0 | AS_OCTFM & ASO_OCTF0 | AS_BINFM & ASB_BINF0 |
	//	AS_UNEQU | AS_NOXRF | AS_XTRNTYPE | AS_RELSUP;
	//ash.uflag = 0;
	ash.name = "FASM (Flat Assembler) - not implemented yet";
	ash.help = 0;
	ash.header = 0;
	ash.origin = "org";
	ash.end = 0;
	ash.cmnt = ";";
	ash.ascsep = '\'';
	//ash.accsep = '\'';
	ash.esccodes = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
		"'\"\x7F"
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"
		"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF"
		"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
		"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"
		"\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF"
		"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF"
		"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"
		"\x00";
	ash.a_ascii = "db";
	ash.a_byte = "db";
	//ash.a_word = "dw";
	ash.a_dword = "dd";
	//ash.a_qword = "dq";
	//ash.a_oword = 0;
	//ash.a_float = "real4"; // "dd"
	//ash.a_double = "real8"; // "dq"
	//ash.a_tbyte = "dt";
	//ash.a_packreal = 0;
	//ash.a_dups = "#d dup(#v)";
	//ash.a_bss = "db    ? ;";
	ash.a_equ = "equ";
	//ash.a_seg = "seg";
	//ash.checkarg_preline = 0;
	//ash.checkarg_atomprefix = 0;
	//ash.checkarg_operations = 0;
	ash.XlatAsciiOutput = (const uchar *)
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
		" !\"#$%&'()*+,-./0123456789:;<=>?"
		"@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7F"
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"
		"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF"
		"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
		"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF"
		"\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF"
		"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF"
		"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF";
	//ash.a_curip = "$";
	//ash.func_header = 0;
	//ash.func_footer = 0;
	//ash.a_public = "public";
	//ash.a_weak = 0;
	//ash.a_extrn = "externdef";
	//ash.a_comdef = "comm";
	//ash.get_type_name = 0;
	//ash.a_align = "align";
	//ash.lbrace = '(';
	//ash.rbrace = ')';
	//ash.a_mod = "mod";
	//ash.a_band = "and";
	//ash.a_bor = "or";
	//ash.a_xor = "xor";
	//ash.a_bnot = "not";
	//ash.a_shl = "shl";
	//ash.a_shr = "shr";
	//ash.a_sizeof_fmt = "sizeof %s";
	//ash.flag2 = AS2_TERSESTR;
	//ash.cmnt2 = 0;
	//ash.low8 = 0;
	//ash.high8 = 0;
	//ash.low16 = "lowword %s";
	//ash.high16 = "highword %s";
	ash.a_include_fmt = "include \'%s\'";
	//ash.a_vstruc_fmt = 0;
	// csc specific
	code_sec = ".code";
	data_sec = ".data";
	const_sec = ".const";
	bss_sec = ".data?";
	proc_start = "%s proc near";
	proc_end = "%s endp";
}

static INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	netnode node;
	switch (uMsg) {
		case WM_INITDIALOG: {
			netnode csc(node_name);
			if (csc == BADNODE || csc.valobj(&prefs, sizeof prefs_t) < sizeof prefs_t
				|| prefs.version != PREFS_VERSION) {
				// Tab1
				prefs.code2code = GetPrivateProfileInt(cfgsection, "code2code", true, inipath);
				prefs.code2data = GetPrivateProfileInt(cfgsection, "code2data", true, inipath);
				prefs.data2code = GetPrivateProfileInt(cfgsection, "data2code", true, inipath);
				prefs.data2data = GetPrivateProfileInt(cfgsection, "data2data", true, inipath);
				prefs.crefs = GetPrivateProfileInt(cfgsection, "crefs", true, inipath);
				prefs.drefs = GetPrivateProfileInt(cfgsection, "drefs", true, inipath);
				prefs.include_libitems = GetPrivateProfileInt(cfgsection, "includestdlibs", false, inipath);
				prefs.reloc_extfn_offs = GetPrivateProfileInt(cfgsection, "reloc_extfn_offs", true, inipath);
				prefs.reloc_extvar_offs = GetPrivateProfileInt(cfgsection, "reloc_extvar_offs", false, inipath);
				prefs.include_thunkfuncs = GetPrivateProfileInt(cfgsection, "thunkfuncs", false, inipath);
				prefs.include_hidden = GetPrivateProfileInt(cfgsection, "hidden", true, inipath);
				prefs.suddendeath_on_fatal = GetPrivateProfileInt(cfgsection, "suddendeath_on_fatal", true, inipath);
				prefs.verbosity = GetPrivateProfileInt(cfgsection, "verbosity", 2, inipath);
				prefs.reporting_verbosity = GetPrivateProfileInt(cfgsection, "reporting_verbosity", 2, inipath);
				prefs.unattended = GetPrivateProfileInt(cfgsection, "unattended", false, inipath);
				prefs.maxruntime = GetPrivateProfileInt(cfgsection, "maxruntime", 0, inipath);
				prefs.createoffsets = GetPrivateProfileInt(cfgsection, "createoffsets", true, inipath);
				prefs.offtohead = GetPrivateProfileInt(cfgsection, "offtohead", true, inipath);
				prefs.offtodefhead = GetPrivateProfileInt(cfgsection, "offtodefhead", true, inipath);
				prefs.destroyenums = GetPrivateProfileInt(cfgsection, "destroyenums", false, inipath);
				prefs.resolve_names = GetPrivateProfileInt(cfgsection, "resolve_names", true, inipath);
				prefs.asm_model = (asm_model_t)GetPrivateProfileInt(cfgsection, "asm_model", asm_masm, inipath);
				prefs.makealigns = GetPrivateProfileInt(cfgsection, "makealigns", true, inipath);
				prefs.destroy_structs = GetPrivateProfileInt(cfgsection, "destroystructs", false, inipath);
				prefs.do_wipeout = GetPrivateProfileInt(cfgsection, "wipeout", true, inipath);
				prefs.externdefs = GetPrivateProfileInt(cfgsection, "externdefs", true, inipath);
				prefs.anchorstroffs = GetPrivateProfileInt(cfgsection, "anchorstroffs", true, inipath);
				prefs.include_typedefs = GetPrivateProfileInt(cfgsection, "include_typedefs", false, inipath);
				prefs.exec_flt = GetPrivateProfileInt(cfgsection, "extflt", false, inipath);
				prefs.create_graph = GetPrivateProfileInt(cfgsection, "create_graph", true, inipath);
				GetPrivateProfileString(cfgsection, "extcmd",
					/* "perl C:\\Ida\\fmtidasrc.pl --collapsepublics --deleteimports --fixlabelscope --backup \"%1\"", */
					"<info: put external program or script here to perform more "
					"fixups or cleanup to source; recognized macros: "
					"%l expanded to current output full name quoted if spaced; "
					"%s expanded to current output short name>", CPY(prefs.fltcommand), inipath);
				// Tab2
				prefs.dbg_resolve = GetPrivateProfileInt(cfgsection, "dbg_resolve", false, inipath);
				prefs.addref = GetPrivateProfileInt(cfgsection, "addref", true, inipath);
				prefs.cmtrta = GetPrivateProfileInt(cfgsection, "cmtrta", true, inipath);
				prefs.suppress_nags[0] = GetPrivateProfileInt(cfgsection, "dont_show_rtr_nag", false, inipath);
				prefs.dbg_savedata = GetPrivateProfileInt(cfgsection, "dbg_savedata", false, inipath);
				prefs.keep_saved_data = GetPrivateProfileInt(cfgsection, "keep_saved_data", true, inipath);
				prefs.dbg_exploreheaps = GetPrivateProfileInt(cfgsection, "dbg_exploreheaps", false, inipath);
				prefs.dyndataxplorer_offtostat = GetPrivateProfileInt(cfgsection, "dyndataxplorer_offtostat", 3, inipath);
				prefs.dyndataxplorer_offtodyn = GetPrivateProfileInt(cfgsection, "dyndataxplorer_offtodyn", 3, inipath);
				prefs.dyndataxplorer_honouroffsets = GetPrivateProfileInt(cfgsection, "dyndataxplorer_honouroffsets", false, inipath);
				prefs.dyndataxplorer_map_imps_dir = GetPrivateProfileInt(cfgsection, "dyndataxplorer_map_imps_dir", true, inipath);
				prefs.dyndataxplorer_maxclonable = GetPrivateProfileInt(cfgsection, "dyndataxplorer_maxclonable", 0, inipath);
				prefs.dyndataxplorer_maxoffsetable = GetPrivateProfileInt(cfgsection, "dyndataxplorer_maxoffsetable", 0x1000, inipath);
				prefs.dyndataxplorer_enablevalloc = GetPrivateProfileInt(cfgsection, "dyndataxplorer_enablevalloc", false, inipath);
				prefs.dyndataxplorer_minvallocblk = GetPrivateProfileInt(cfgsection, "dyndataxplorer_minvallocblk", 0x100000, inipath);
				prefs.dyndataxplorer_carenames = GetPrivateProfileInt(cfgsection, "dyndataxplorer_carenames", true, inipath);
				prefs.dyndataxplorer_carerefs = GetPrivateProfileInt(cfgsection, "dyndataxplorer_carerefs", true, inipath);
				prefs.dyndataxplorer_carefuncs = GetPrivateProfileInt(cfgsection, "dyndataxplorer_carefuncs", true, inipath);
				prefs.dyndataxplorer_maxrecursion = GetPrivateProfileInt(cfgsection, "dyndataxplorer_maxrecursion", 0, inipath);
				prefs.suppress_nags[1] = GetPrivateProfileInt(cfgsection, "dont_show_dumper_nag", false, inipath);
				prefs.circulated_resolving = GetPrivateProfileInt(cfgsection, "circulated_resolving", false, inipath);
			}
			TCITEM tab;
			tab.mask = TCIF_TEXT;
			for (uint cntr = 0; cntr < qnumber(tabs); ++cntr) {
				tab.pszText = (LPSTR)tabs[cntr].pszTitle;
				TabCtrl_InsertItem(GetDlgItem(hwndDlg, IDC_TABCTL), cntr, &tab);
				tabs[cntr].hWnd = CreateDialog(hInstance, tabs[cntr].lpTemplateName,
					hwndDlg, tabs[cntr].lpDialogFunc);
			}
			ShowWindow(tabs[tabs_current = 0].hWnd, SW_SHOWDEFAULT);
			const HWND hwndTabCtrl(GetDlgItem(hwndDlg, IDC_TABCTL));
			if ((HWND)wParam == hwndTabCtrl) return 1;
			RestoreDialogPos(hwndDlg, cfgsection);
			SetFocus(hwndTabCtrl);
			return 0;
		}
		case WM_DESTROY: {
			for (uint cntr = qnumber(tabs); cntr > 0; --cntr)
				DestroyWindow(tabs[cntr - 1].hWnd);
			SaveDialogPos(hwndDlg, cfgsection);
			SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
			return 1;
		}
		case WM_COMMAND:
			if (HIWORD(wParam) == BN_CLICKED)
				switch (LOWORD(wParam)) {
					case IDOK:
						// Tab1
						save_bool(cfgsection, "code2code", prefs.code2code = IsDlgButtonChecked(tabs[0].hWnd, IDC_CSC_CODE2CODE));
						save_bool(cfgsection, "code2data", prefs.code2data = IsDlgButtonChecked(tabs[0].hWnd, IDC_CSC_CODE2DATA));
						save_bool(cfgsection, "data2code", prefs.data2code = IsDlgButtonChecked(tabs[0].hWnd, IDC_CSC_DATA2CODE));
						save_bool(cfgsection, "data2data", prefs.data2data = IsDlgButtonChecked(tabs[0].hWnd, IDC_CSC_DATA2DATA));
						save_bool(cfgsection, "crefs", prefs.crefs = IsDlgButtonChecked(tabs[0].hWnd, IDC_CREFS));
						save_bool(cfgsection, "drefs", prefs.drefs = IsDlgButtonChecked(tabs[0].hWnd, IDC_DREFS));
						save_bool(cfgsection, "includestdlibs", prefs.include_libitems = IsDlgButtonChecked(tabs[0].hWnd, IDC_CSCLIBSBOX));
						save_bool(cfgsection, "reloc_extfn_offs", prefs.reloc_extfn_offs = IsDlgButtonChecked(tabs[0].hWnd, IDC_RELOCXTRNFUNC));
						save_bool(cfgsection, "reloc_extvar_offs", prefs.reloc_extvar_offs = IsDlgButtonChecked(tabs[0].hWnd, IDC_RELOCXTRNVAR));
						save_bool(cfgsection, "thunkfuncs", prefs.include_thunkfuncs = IsDlgButtonChecked(tabs[0].hWnd, IDC_CSCIMPORTS));
						save_bool(cfgsection, "hidden", prefs.include_hidden = IsDlgButtonChecked(tabs[0].hWnd, IDC_CSCHIDDEN));
						save_bool(cfgsection, "suddendeath_on_fatal", prefs.suddendeath_on_fatal = IsDlgButtonChecked(tabs[0].hWnd, IDC_SUDDENDEATH));
						save_byte(cfgsection, "verbosity", prefs.verbosity = SendDlgItemMessage(tabs[0].hWnd, IDC_VERBOSITY, CB_GETCURSEL, 0, 0));
						//save_byte(cfgsection, "reporting_verbosity", prefs.reporting_verbosity = SendDlgItemMessage(tabs[0].hWnd, IDC_REPORTING_VERBOSITY, CB_GETCURSEL, 0, 0));
						prefs.unattended = IsDlgButtonChecked(tabs[0].hWnd, IDC_UNATTENDED);
#ifdef _DEBUG
						save_byte(cfgsection, "unattended", prefs.unattended);
#endif
						//save_dword(cfgsection, "max_ranges", prefs.max_ranges = GetDlgItemInt(tabs[0].hWnd, IDC_MAX_RANGES, NULL, FALSE));
						//SYSTEMTIME mrt;
						//SendDlgItemMessage(tabs[0].hWnd, IDC_MAXRUNTIME, DTM_GETSYSTEMTIME, NULL, (LPARAM)&mrt);
						//save_dword(cfgsection, "maxruntime", prefs.maxruntime = mrt.wHour * 60 * 60 + mrt.wMinute * 60 + mrt.wSecond);
						netnode("$ offset_boundary", 0, true).altset(0, offset_boundary = rdownpow2(GetDlgItemInt(tabs[0].hWnd, IDC_OFFBOUNDARY, NULL, FALSE)));
						//save_dword(cfgsection, "offset_boundary", offset_boundary);
						save_bool(cfgsection, "createoffsets", prefs.createoffsets = IsDlgButtonChecked(tabs[0].hWnd, IDC_CREATEOFFSETS));
						save_bool(cfgsection, "offtohead", prefs.offtohead = IsDlgButtonChecked(tabs[0].hWnd, IDC_OFFTOHEAD));
						save_bool(cfgsection, "offtodefhead", prefs.offtodefhead = IsDlgButtonChecked(tabs[0].hWnd, IDC_OBEYDEFHEAD));
						save_bool(cfgsection, "resolve_names", prefs.resolve_names = IsDlgButtonChecked(tabs[0].hWnd, IDC_RESOLVENAMES));
						save_bool(cfgsection, "makealigns", prefs.makealigns = IsDlgButtonChecked(tabs[0].hWnd, IDC_MAKEALIGNS));
						save_byte(cfgsection, "asm_model", prefs.asm_model = (asm_model_t)SendDlgItemMessage(tabs[0].hWnd, IDC_ASMMODEL, CB_GETCURSEL, 0, 0));
						save_bool(cfgsection, "include_typedefs", prefs.include_typedefs = IsDlgButtonChecked(tabs[0].hWnd, IDC_TYPEDEFS));
						save_bool(cfgsection, "destroystructs", prefs.destroy_structs = IsDlgButtonChecked(tabs[0].hWnd, IDC_DESTROYSTRUCTS));
						save_bool(cfgsection, "anchorstroffs", prefs.anchorstroffs = IsDlgButtonChecked(tabs[0].hWnd, IDC_ANCHORSTROFFS));
						save_bool(cfgsection, "destroyenums", prefs.destroyenums = IsDlgButtonChecked(tabs[0].hWnd, IDC_KILLENUMS));
						save_bool(cfgsection, "externdefs", prefs.externdefs = !IsDlgButtonChecked(tabs[0].hWnd, IDC_EXTERNDEFS));
						save_bool(cfgsection, "wipeout", prefs.do_wipeout = IsDlgButtonChecked(tabs[0].hWnd, IDC_WIPEOUT));
						save_bool(cfgsection, "extflt", prefs.exec_flt = IsDlgButtonChecked(tabs[0].hWnd, IDC_EXTFILTER));
						save_bool(cfgsection, "create_graph", prefs.create_graph = IsDlgButtonChecked(tabs[0].hWnd, IDC_CREATEGRAPH));
						GetDlgItemText(tabs[0].hWnd, IDC_FLTCOMMAND, prefs.fltcommand, QMAXPATH);
						WritePrivateProfileString(cfgsection, "extcmd", prefs.fltcommand, inipath);
						// Tab2
						save_bool(cfgsection, "dbg_resolve", prefs.dbg_resolve = IsDlgButtonChecked(tabs[1].hWnd, IDC_DBG_RESOLVE_RTA));
						save_bool(cfgsection, "addref", prefs.addref = IsDlgButtonChecked(tabs[1].hWnd, IDC_REFRTI));
						save_bool(cfgsection, "cmtrta", prefs.cmtrta = IsDlgButtonChecked(tabs[1].hWnd, IDC_CMTRTI));
						save_bool(cfgsection, "dont_show_rtr_nag", prefs.suppress_nags[0] = IsDlgButtonChecked(tabs[1].hWnd, IDC_DONT_SHOW_RTR_NAG));
						save_bool(cfgsection, "dbg_savedata", prefs.dbg_savedata = IsDlgButtonChecked(tabs[1].hWnd, IDC_DBG_SAVE_VALUES));
						save_bool(cfgsection, "keep_saved_data", prefs.keep_saved_data = IsDlgButtonChecked(tabs[1].hWnd, IDC_KEEPINITDATA));
						save_bool(cfgsection, "dbg_exploreheaps", prefs.dbg_exploreheaps = IsDlgButtonChecked(tabs[1].hWnd, IDC_EXPLOREHEAPS));
						save_byte(cfgsection, "dyndataxplorer_offtostat", prefs.dyndataxplorer_offtostat = SendDlgItemMessage(tabs[1].hWnd, IDC_OFFTOSTAT, CB_GETCURSEL, 0, 0));
						save_byte(cfgsection, "dyndataxplorer_offtodyn", prefs.dyndataxplorer_offtodyn = SendDlgItemMessage(tabs[1].hWnd, IDC_OFFTODYN, CB_GETCURSEL, 0, 0));
						save_bool(cfgsection, "dyndataxplorer_carenames", prefs.dyndataxplorer_carenames = IsDlgButtonChecked(tabs[1].hWnd, IDC_CARENAMES));
						save_bool(cfgsection, "dyndataxplorer_carerefs", prefs.dyndataxplorer_carerefs = IsDlgButtonChecked(tabs[1].hWnd, IDC_CAREREFS));
						save_bool(cfgsection, "dyndataxplorer_carefuncs", prefs.dyndataxplorer_carefuncs = IsDlgButtonChecked(tabs[1].hWnd, IDC_CAREFUNCS));
						save_dword(cfgsection, "dyndataxplorer_maxoffsetable", prefs.dyndataxplorer_maxoffsetable = GetDlgItemInt(tabs[1].hWnd, IDC_MAXOFFSETABLE, NULL, FALSE));
						save_dword(cfgsection, "dyndataxplorer_maxclonable", prefs.dyndataxplorer_maxclonable = GetDlgItemInt(tabs[1].hWnd, IDC_MAXCLONABLE, NULL, FALSE));
						save_bool(cfgsection, "dyndataxplorer_enablevalloc", prefs.dyndataxplorer_enablevalloc = IsDlgButtonChecked(tabs[1].hWnd, IDC_ENABLEVALLOC));
						save_dword(cfgsection, "dyndataxplorer_minvallocblk", prefs.dyndataxplorer_minvallocblk = GetDlgItemInt(tabs[1].hWnd, IDC_MINVALLOCBLK, NULL, FALSE));
						save_dword(cfgsection, "dyndataxplorer_maxrecursion", prefs.dyndataxplorer_maxrecursion = GetDlgItemInt(tabs[1].hWnd, IDC_MAXRECURSION, NULL, FALSE));
						save_bool(cfgsection, "dyndataxplorer_honouroffsets", prefs.dyndataxplorer_honouroffsets = IsDlgButtonChecked(tabs[1].hWnd, IDC_HONOUROFFSETS));
						save_bool(cfgsection, "dyndataxplorer_map_imps_dir", prefs.dyndataxplorer_map_imps_dir = IsDlgButtonChecked(tabs[1].hWnd, IDC_MAPIMPSDIR));
						save_bool(cfgsection, "dont_show_dumper_nag", prefs.suppress_nags[1] = IsDlgButtonChecked(tabs[1].hWnd, IDC_DONT_SHOW_DUMPER_NAG));
						save_bool(cfgsection, "circulated_resolving", prefs.circulated_resolving = IsDlgButtonChecked(tabs[1].hWnd, IDC_CIRCULRESOLV));
						if (inf.filetype != f_PE) { // runtime features for PE-only
							prefs.dbg_resolve = false;
							prefs.dbg_savedata = false;
						}
						if (GetPrivateProfileInt(cfgsection, "resolver_nag_seen", false, inipath) == 0) prefs.suppress_nags[0] = false;
						if (GetPrivateProfileInt(cfgsection, "dumper_nag_seen", false, inipath) == 0) prefs.suppress_nags[1] = false;
						prefs.version = PREFS_VERSION;
						netnode(node_name, 0, true).set(&prefs, sizeof prefs_t);
					case IDCANCEL:
						EndDialog(hwndDlg, LOWORD(wParam));
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
						break;
					case IDABOUT:
						DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_ABOUT), hwndDlg,
							about_dlgproc, (LPARAM)"by _servil_ v" PLUGINVERSIONTEXT " " __DATE__);
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
						break;
				} // switch WM_COMMAND
			return 1;
		case WM_NOTIFY:
			_ASSERTE(lParam != NULL);
			if (((LPNMHDR)lParam)->idFrom == IDC_TABCTL &&
				((LPNMHDR)lParam)->code == TCN_SELCHANGE) {
				ShowWindow(tabs[tabs_current].hWnd, SW_HIDE);
				tabs_current = TabCtrl_GetCurSel(((LPNMHDR)lParam)->hwndFrom);
				ShowWindow(tabs[tabs_current].hWnd, SW_SHOWDEFAULT);
				SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
			}
			return 1;
		//case WM_CHAR: // TODO: add Ctrl-PgUp/PgDn support
		//	break;
	} // switch
	return FALSE;
}

namespace CTab1 {
INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	BOOL state;
	switch (uMsg) {
		case WM_INITDIALOG: {
			CheckDlgButton(hwndDlg, IDC_CSC_CODE2CODE, prefs.code2code);
			CheckDlgButton(hwndDlg, IDC_CSC_CODE2DATA, prefs.code2data);
			CheckDlgButton(hwndDlg, IDC_CSC_DATA2CODE, prefs.data2code);
			CheckDlgButton(hwndDlg, IDC_CSC_DATA2DATA, prefs.data2data);
			CheckDlgButton(hwndDlg, IDC_CREFS, prefs.crefs);
			CheckDlgButton(hwndDlg, IDC_DREFS, prefs.drefs);
			CheckDlgButton(hwndDlg, IDC_CSCLIBSBOX, prefs.include_libitems);
			CheckDlgButton(hwndDlg, IDC_RELOCXTRNFUNC, prefs.reloc_extfn_offs);
			CheckDlgButton(hwndDlg, IDC_RELOCXTRNVAR, prefs.reloc_extvar_offs);
			CheckDlgButton(hwndDlg, IDC_CSCIMPORTS, prefs.include_thunkfuncs);
			CheckDlgButton(hwndDlg, IDC_CSCHIDDEN, prefs.include_hidden);
			CheckDlgButton(hwndDlg, IDC_SUDDENDEATH, prefs.suddendeath_on_fatal);
			SendDlgItemMessage(hwndDlg, IDC_VERBOSITY, CB_ADDSTRING, 0, (LPARAM)"Quiet");
			SendDlgItemMessage(hwndDlg, IDC_VERBOSITY, CB_ADDSTRING, 0, (LPARAM)"Brief");
			SendDlgItemMessage(hwndDlg, IDC_VERBOSITY, CB_ADDSTRING, 0, (LPARAM)"Normal");
			SendDlgItemMessage(hwndDlg, IDC_VERBOSITY, CB_ADDSTRING, 0, (LPARAM)"Verbose");
			SendDlgItemMessage(hwndDlg, IDC_VERBOSITY, CB_SETMINVISIBLE, (WPARAM)15, 0);
			SendDlgItemMessage(hwndDlg, IDC_VERBOSITY, CB_SETCURSEL, (WPARAM)prefs.verbosity, 0);
// #ifndef _DEBUG
// 			ShowDlgItem(hwndDlg, IDC_UNATTENDED, SW_HIDE);
// 			//EnableDlgItem(hwndDlg, IDC_UNATTENDED, FALSE);
// #else // _DEBUG
			CheckDlgButton(hwndDlg, IDC_UNATTENDED, prefs.unattended);
// #endif // _DEBUG
			/*
			SendDlgItemMessage(hwndDlg, IDC_UPDOWN1, UDM_SETBASE, (WPARAM)10, NULL);
			SendDlgItemMessage(hwndDlg, IDC_UPDOWN1, UDM_SETRANGE32, (WPARAM)0, (LPARAM)0x7FFFFFFF);
			SendDlgItemMessage(hwndDlg, IDC_UPDOWN1, UDM_SETPOS32, NULL, (LPARAM)prefs.max_ranges);
			SYSTEMTIME mrt;
			memset(&mrt, 0, sizeof mrt);
			mrt.wMilliseconds = 0;
			mrt.wHour = prefs.maxruntime / (60*60);
			if (mrt.wHour >= 24) {
				mrt.wHour = 23;
				mrt.wMinute = 59;
				mrt.wSecond = 59;
			} else {
				mrt.wSecond = prefs.maxruntime % 60;
				mrt.wMinute = (prefs.maxruntime / 60) % 60;
			}
			SendDlgItemMessage(hwndDlg, IDC_MAXRUNTIME, DTM_SETSYSTEMTIME, (WPARAM)GDT_VALID, (LPARAM)&mrt);
			memset(&mrt, 0, sizeof mrt);
			SendDlgItemMessage(hwndDlg, IDC_MAXRUNTIME, DTM_SETRANGE, (WPARAM)GDTR_MIN, (LPARAM)&mrt);
			mrt.wHour = 23;
			mrt.wMinute = 59;
			mrt.wSecond = 59;
			SendDlgItemMessage(hwndDlg, IDC_MAXRUNTIME, DTM_SETRANGE, (WPARAM)GDTR_MAX, (LPARAM)&mrt);
			*/
			size_t ptrsize(0);
			netnode node("$ offset_boundary");
			if (node != BADNODE) ptrsize = node.altval(0);
			if (ptrsize <= 0) ptrsize = get_ptr_size();
			if (ptrsize <= 0) ptrsize = get_near_ptr_size();
			ptrsize = rounduppow2(ptrsize);
			SetDlgItemInt(hwndDlg, IDC_OFFBOUNDARY, ptrsize, FALSE);
			SendDlgItemMessage(hwndDlg, IDC_UPDOWN2, UDM_SETRANGE, NULL, (LPARAM)MAKELONG(1, (short)-1));
			CheckDlgButton(hwndDlg, IDC_CREATEOFFSETS, prefs.createoffsets);
			CheckDlgButton(hwndDlg, IDC_OFFTOHEAD, prefs.offtohead);
			CheckDlgButton(hwndDlg, IDC_OBEYDEFHEAD, prefs.offtodefhead);
			CheckDlgButton(hwndDlg, IDC_KILLENUMS, prefs.destroyenums);
			CheckDlgButton(hwndDlg, IDC_RESOLVENAMES, prefs.resolve_names);
			CheckDlgButton(hwndDlg, IDC_MAKEALIGNS, prefs.makealigns);
			SendDlgItemMessage(hwndDlg, IDC_ASMMODEL, CB_ADDSTRING, 0, (LPARAM)"use current");
			SendDlgItemMessage(hwndDlg, IDC_ASMMODEL, CB_ADDSTRING, 0, (LPARAM)"MASM 6.0");
			SendDlgItemMessage(hwndDlg, IDC_ASMMODEL, CB_ADDSTRING, 0, (LPARAM)"TASM 5.0 Ideal");
			SendDlgItemMessage(hwndDlg, IDC_ASMMODEL, CB_ADDSTRING, 0, (LPARAM)"NASM (The Netwide Assembler)");
			SendDlgItemMessage(hwndDlg, IDC_ASMMODEL, CB_ADDSTRING, 0, (LPARAM)"FASM (Flat Assembler)");
			SendDlgItemMessage(hwndDlg, IDC_ASMMODEL, CB_SETMINVISIBLE, (WPARAM)15, 0);
			SendDlgItemMessage(hwndDlg, IDC_ASMMODEL, CB_SETCURSEL, (WPARAM)prefs.asm_model, 0);
			CheckDlgButton(hwndDlg, IDC_DESTROYSTRUCTS, prefs.destroy_structs);
			CheckDlgButton(hwndDlg, IDC_WIPEOUT, prefs.do_wipeout);
			CheckDlgButton(hwndDlg, IDC_EXTERNDEFS, !prefs.externdefs);
			CheckDlgButton(hwndDlg, IDC_ANCHORSTROFFS, prefs.anchorstroffs);
			CheckDlgButton(hwndDlg, IDC_TYPEDEFS, prefs.include_typedefs);
			CheckDlgButton(hwndDlg, IDC_EXTFILTER, prefs.exec_flt);
			CheckDlgButton(hwndDlg, IDC_CREATEGRAPH, prefs.create_graph);
			SetDlgItemText(hwndDlg, IDC_FLTCOMMAND, prefs.fltcommand);
			state = IsDlgButtonChecked(hwndDlg, IDC_CREATEOFFSETS);
			EnableDlgItem(hwndDlg, IDC_OFFTOHEAD, state);
			state = IsDlgButtonChecked(hwndDlg, IDC_OFFTOHEAD);
			if (!state) CheckDlgButton(hwndDlg, IDC_OBEYDEFHEAD, BST_UNCHECKED);
			EnableDlgItem(hwndDlg, IDC_OBEYDEFHEAD, state &
				IsDlgButtonChecked(hwndDlg, IDC_CREATEOFFSETS));
			state = IsDlgButtonChecked(hwndDlg, IDC_EXTFILTER);
			EnableDlgItem(hwndDlg, IDC_FLTCOMMAND, state);
			EnableDlgItem(hwndDlg, IDBROWSE, state);
			state = !IsDlgButtonChecked(hwndDlg, IDC_CSCLIBSBOX);
			EnableDlgItem(hwndDlg, IDC_RELOCXTRNFUNC, state);
			EnableDlgItem(hwndDlg, IDC_RELOCXTRNVAR, state);
			const static tooltip_item_t tooltips[] = {
				IDC_CSCLIBSBOX, "Cover library functions and variables in output. Note: including library code may cause rapid output size growth and is not supported if external libraries are available for used SDK.",
				IDC_RELOCXTRNFUNC, "Translate offsets to imported functions to real address instead of IAT entry. Use only when linking with dynamic runtimes, never use for static link.",
				IDC_RELOCXTRNVAR, "Translate offsets to imported data to real address instead of IAT entry. Use only when linking with dynamic runtimes, never use for static link.",
				IDC_CSCIMPORTS, "Cover forwarder (thunk) functions in output. Thunk functions are simple jump front-ends to externals or real library functions (if excluded). Thunks in most cases can be left out as they are assumed to inherit name of the target.",
				IDC_CSCHIDDEN, "Cover hidden items in output. If this rule is enabled, any visibility restrictions are gracefully ignored for all entry types. If rule is disabled hidden items are stripped according to type: functions are included only if not collapsed and inside visible (expanded) segment, data is included only if not having hidden flag and inside visible (expanded) segment. Data visibility can't be changed nor displayed by ida UI but only via API (see NALT_AFLAGS).",
				IDC_SUDDENDEATH, "Abort on first catastrophic integrity error. Turn off for too exhaustive branch giving too many catastrophic errors.",
				IDC_VERBOSITY, "Logging verbosity level:\n\rquiet = print only progress stages\n\rbrief = print everything except informational messages\n\rnormal = print everything\n\rverbose = yet more log window bloat ;p (not implemented yet)",
				IDC_UNATTENDED, "Run in unattended mode: no dialogs are shown till everything is done (output filename is made out of idabase path and root function name)",
				IDC_CREATEGRAPH, "Create graphic relation graph at finish - internal viewer is preferred on IDA 5.1 and newer, otherwise graph is opened in external viewer (wingraph32)",
				//IDC_MAXRUNTIME, "Max running time for too big branches (0:00:00 = unlimited)",
				//IDC_MAX_RANGES, "Maximum collected ranges (static or dynamic) for too big branches (0 = unlimited)",
				IDC_OFFBOUNDARY, "Bundary is used as required parameter for new offsets recognition and to retest existing offsets (unaligned offsets are not removed but cause warnings). All offsets stored by current compiler should start at address divisible by alignment (most 32-bit compilers align offsets to dword, etc.). If unsure or compiler doesnot align offsets, set to 0 (=don't care). Default boundary value is current compiler pointer size. Values are rounded down to nearest power of 2, if differ.",
				IDC_UPDOWN2, "Bundary is used as required parameter for new offsets recognition and to retest existing offsets (unaligned offsets are not removed but cause warnings). All offsets stored by current compiler should start at address divisible by alignment (most 32-bit compilers align offsets to dword, etc.). If unsure or compiler doesnot align offsets, set to 0 (=don't care). Default boundary value is current compiler pointer size. Values are rounded down to nearest power of 2, if differ.",
				IDC_CREATEOFFSETS, "Create offsets where appliable. Offsets are recognized only inside unexplored or dummy ranges. Dumy range means by default defined byte, word or dword values. New offsets must meet minimum alignment if specified.",
				IDC_OFFTOHEAD, "Only to not middle of instruction/data",
				IDC_OBEYDEFHEAD, "Only to start of defined instruction/data",
				IDC_RESOLVENAMES, "Scan every exported function frame for local <--> global name pairs. Same name for local and global variable is not supported by MASM for IDA's frame design.",
				IDC_KILLENUMS, "Destroy all enums within captured ranges to ensure assembler compatibility. Not necessary for types delivered by standard includes or if `Include typedefs` option is on.",
				IDC_MAKEALIGNS, "Create align directives where possible (only recommended for 32-bit VCL code)",
				IDC_ASMMODEL, "[only MASM6 grammar fully implemented atm.]\nTarget assembler grammar: use current to perform with assembler set selected in options dialog.\nNote: MASM is recommended - although plugin obeys all assembler specific tokens, setting other assembler than MASM may cause compatibility conflicts on helper functions and data structures generated by plugin, also prologue is generated only with MASM.",
				IDC_DESTROYSTRUCTS, "Explode local structs to basic data types. Local structs are not supported by MASM for IDA's frame design.",
				IDC_WIPEOUT, "Strip IDA banners, xrefs, dummy lines, basic compatibility adjustments for MASM assembler",
				IDC_EXTERNDEFS, "Exclude externdefs from output (covers all IAT entries)",
				IDC_ANCHORSTROFFS, "Anchor offsets to global (static) struct members to struct base address + raw member offset rather than referring member directly. Not tersed (expanded) structures only (tersed structures handled correctly). Plugin doesnot care if structures are finally tersed so there still may be members of expanded structures referred. This is MASM specific compatibility fix.",
				IDC_TYPEDEFS, "Include typedefs of complex types (enums, structs) into source. All types are included regardless if used or not within snippet. Including typedefs may resolve complex type references (especially product-specific) but make the output bigger.",
				IDC_EXTFILTER, "Post-process the output (additional code clean-up, compatibility adjustments, or any automated actions)",
				IDC_FLTCOMMAND, "Full path to executable with cmd-line arguments, two macros are supported:\n\r  `%l` is replaced by current output full name including path, quoted if spaced\n\r  `%s` is replaced by current output full short name\n\r\n\rExternal filter must be directly executable by Windows kernel, for any scripts include the interpreter executable first, for ex.\n\rperl.exe C:\\user\\fmtidasrc.pl %l",
			};
			const HWND hwndTT(CreateWindowEx(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL,
				WS_POPUP | TTS_NOPREFIX | TTS_BALLOON | TTS_ALWAYSTIP, CW_USEDEFAULT,
				CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwndDlg, NULL, hInstance, NULL));
			SetWindowPos(hwndTT, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
			SendMessage(hwndTT, TTM_SETMAXTIPWIDTH, 0, (LPARAM)400);
			SendMessage(hwndTT, TTM_SETDELAYTIME, (WPARAM)TTDT_AUTOPOP, (LPARAM)30000);
			TOOLINFO tt;
			memset(&tt, 0, sizeof tt);
			tt.cbSize = sizeof tt;
			tt.uFlags = TTF_SUBCLASS | TTF_IDISHWND | TTF_TRANSPARENT;
			tt.hwnd = hwndDlg;
			tt.hinst = hInstance;
			for (const tooltip_item_t *i = boost::begin(tooltips); i != boost::end(tooltips); ++i) {
				tt.uId = (UINT_PTR)GetDlgItem(hwndDlg, i->uID);
				tt.lpszText = (LPSTR)i->lpText;
				SendMessage(hwndTT, TTM_ADDTOOL, 0, (LPARAM)&tt);
			}
			return 1;
		}
		case WM_COMMAND:
			if (HIWORD(wParam) == BN_CLICKED)
				switch (LOWORD(wParam)) {
					case IDBROWSE: {
						char tmp[512], ext[_MAX_EXT];
						GetDlgItemText(hwndDlg, IDC_FLTCOMMAND, CPY(tmp));
						if (!qfileexist(tmp)) {
							const PCRE::regexp::result match("^\"(.*)\"$", tmp);
							if (match >= 2 && qfileexist(match[1]))
								qstrcpy(tmp, match[1]);
							else
								fill_n(CPY(tmp), 0);
						}
						OPENFILENAME ofn;
						memset(&ofn, 0, sizeof OPENFILENAME);
						ofn.lStructSize = sizeof OPENFILENAME;
						ofn.hwndOwner = hwndDlg;
						ofn.hInstance = hInstance;
						ofn.lpstrFilter =
							"all executables\0*.exe;*.com;*.bat;*.cmd;*.pl;*.py;*.js;*.vbs;*.VBScript\0"
							"binary executables (*.exe;*.com)\0*.exe;*.com\0"
							"DOS commands (*.bat;*.cmd)\0*.bat;*.cmd\0"
							"scripts (*.js;*.vbs;*.pl;*.py)\0*.pl;*.py;*.js;*.vbs;*.VBScript\0"
							"all files\0*.*\0";
						ofn.nFilterIndex = 1;
						ofn.nMaxFile = QMAXPATH;
						ofn.lpstrFile = tmp;
						ofn.lpstrTitle = "browse for external filter";
						ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
							OFN_LONGNAMES | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
							OFN_HIDEREADONLY;
						ofn.lpstrDefExt = "exe";
						if (GetOpenFileName(&ofn)) {
							string edit(tmp);
							if (boost::find_token(tmp, boost::is_space()))
								edit.insert((string::size_type)0, 1, '\"').push_back('\"');
							_splitpath(tmp, 0, 0, 0, ext);
							if (boost::iequals(ext, ".pl"))
								edit.insert(0, "perl.exe ");
							else if (boost::iequals(ext, ".py"))
								edit.insert(0, "python.exe ");
							else if (boost::iequals(ext, ".vbs") || boost::iequals(ext, ".js")
								|| boost::iequals(ext, ".VBScript"))
								edit.insert(0, "cscript.exe ");
							SetDlgItemText(hwndDlg, IDC_FLTCOMMAND, edit.append(" %l").c_str());
						}
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
						break;
					} // IDBROWSE
					case IDC_CSCLIBSBOX:
						state = IsDlgButtonChecked(hwndDlg, IDC_CSCLIBSBOX);
						EnableDlgItem(hwndDlg, IDC_RELOCXTRNFUNC, !state);
						EnableDlgItem(hwndDlg, IDC_RELOCXTRNVAR, !state);
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
						break;
					case IDC_CREATEOFFSETS:
						state = IsDlgButtonChecked(hwndDlg, IDC_CREATEOFFSETS);
						EnableDlgItem(hwndDlg, IDC_OFFTOHEAD, state);
						EnableDlgItem(hwndDlg, IDC_OBEYDEFHEAD, state &
							IsDlgButtonChecked(hwndDlg, IDC_OFFTOHEAD));
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
						break;
					case IDC_OFFTOHEAD:
						state = IsDlgButtonChecked(hwndDlg, IDC_OFFTOHEAD);
						if (!state) CheckDlgButton(hwndDlg, IDC_OBEYDEFHEAD, BST_UNCHECKED);
						EnableDlgItem(hwndDlg, IDC_OBEYDEFHEAD, state);
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
						break;
					case IDC_EXTFILTER:
						state = IsDlgButtonChecked(hwndDlg, IDC_EXTFILTER);
						EnableDlgItem(hwndDlg, IDC_FLTCOMMAND, state);
						EnableDlgItem(hwndDlg, IDBROWSE, state);
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
						break;
				} // switch
			return 1;
		case WM_NOTIFY:
			switch ((int)wParam) {
				case IDC_UPDOWN2: {
					_ASSERTE(lParam != NULL);
					int delta(((LPNMUPDOWN)lParam)->iDelta);
					((LPNMUPDOWN)lParam)->iDelta = 0;
					UINT value(GetDlgItemInt(hwndDlg, IDC_OFFBOUNDARY, NULL, FALSE));
					int8 exp(log2(value));
					if (exp >= 0 && delta < 0 && value > 1 << exp) ++delta;
					exp += delta;
					if (exp >= -1 && exp < 32) SetDlgItemInt(hwndDlg, IDC_OFFBOUNDARY,
						exp < 0 ? 0 : 1 << exp, FALSE);
					SetWindowLong(hwndDlg, DWL_MSGRESULT, 1); // owner update
					break;
				}
			} // switch
			return 1;
		case WM_HELP:
			_ASSERTE(lParam != NULL);
			SendDlgItemMessage(hwndDlg, ((LPHELPINFO)lParam)->iCtrlId, TTM_POPUP, 0, 0);
			SetWindowLong(hwndDlg, DWL_MSGRESULT, 1);
			return 1;
	} // switch statement
	return FALSE;
}
}

namespace CTab2 {
INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	BOOL state[4];
	switch (uMsg) {
		case WM_INITDIALOG: {
			CheckDlgButton(hwndDlg, IDC_DBG_RESOLVE_RTA, prefs.dbg_resolve);
			CheckDlgButton(hwndDlg, IDC_REFRTI, prefs.addref);
			CheckDlgButton(hwndDlg, IDC_CMTRTI, prefs.cmtrta);
			CheckDlgButton(hwndDlg, IDC_DONT_SHOW_RTR_NAG, prefs.suppress_nags[0]);
			CheckDlgButton(hwndDlg, IDC_DBG_SAVE_VALUES, prefs.dbg_savedata);
			CheckDlgButton(hwndDlg, IDC_KEEPINITDATA, prefs.keep_saved_data);
			CheckDlgButton(hwndDlg, IDC_EXPLOREHEAPS, prefs.dbg_exploreheaps);
			CheckDlgButton(hwndDlg, IDC_HONOUROFFSETS, prefs.dyndataxplorer_honouroffsets);
			CheckDlgButton(hwndDlg, IDC_MAPIMPSDIR, prefs.dyndataxplorer_map_imps_dir);
			SetDlgItemInt(hwndDlg, IDC_MAXCLONABLE, prefs.dyndataxplorer_maxclonable, FALSE);
			SetDlgItemInt(hwndDlg, IDC_MAXOFFSETABLE, prefs.dyndataxplorer_maxoffsetable, FALSE);
			CheckDlgButton(hwndDlg, IDC_ENABLEVALLOC, prefs.dyndataxplorer_enablevalloc);
			SetDlgItemInt(hwndDlg, IDC_MINVALLOCBLK, prefs.dyndataxplorer_minvallocblk, FALSE);
			SendDlgItemMessage(hwndDlg, IDC_OFFTOSTAT, CB_ADDSTRING, 0, (LPARAM)"Don't allow");
			SendDlgItemMessage(hwndDlg, IDC_OFFTOSTAT, CB_ADDSTRING, 0, (LPARAM)"Only to externals");
			SendDlgItemMessage(hwndDlg, IDC_OFFTOSTAT, CB_ADDSTRING, 0, (LPARAM)"Only to captured ranges and externals");
			SendDlgItemMessage(hwndDlg, IDC_OFFTOSTAT, CB_ADDSTRING, 0, (LPARAM)"Allow exploring");
			SendDlgItemMessage(hwndDlg, IDC_OFFTOSTAT, CB_SETMINVISIBLE, (WPARAM)15, 0);
			SendDlgItemMessage(hwndDlg, IDC_OFFTOSTAT, CB_SETCURSEL, (WPARAM)prefs.dyndataxplorer_offtostat, 0);
			SendDlgItemMessage(hwndDlg, IDC_OFFTOSTAT, CB_SETDROPPEDWIDTH, (WPARAM)200, 0);
			SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_ADDSTRING, 0, (LPARAM)"Don't allow");
			SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_ADDSTRING, 0, (LPARAM)"Only map imports (anchorable)");
			//SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_ADDSTRING, 0, (LPARAM)"Only map imports and offset to module (not anchorable)");
			SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_ADDSTRING, 0, (LPARAM)"Only to captured ranges and modules");
			SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_ADDSTRING, 0, (LPARAM)"Allow exploring");
			SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_SETMINVISIBLE, (WPARAM)15, 0);
			SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_SETCURSEL, (WPARAM)prefs.dyndataxplorer_offtodyn, 0);
			SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_SETDROPPEDWIDTH, (WPARAM)200, 0);
			CheckDlgButton(hwndDlg, IDC_CARENAMES, prefs.dyndataxplorer_carenames);
			CheckDlgButton(hwndDlg, IDC_CAREREFS, prefs.dyndataxplorer_carerefs);
			CheckDlgButton(hwndDlg, IDC_CAREFUNCS, prefs.dyndataxplorer_carefuncs);
			SendDlgItemMessage(hwndDlg, IDC_UPDOWN1, UDM_SETBASE, (WPARAM)10, NULL);
			SendDlgItemMessage(hwndDlg, IDC_UPDOWN1, UDM_SETRANGE32, (WPARAM)0, (LPARAM)0x7FFFFFFF);
			SendDlgItemMessage(hwndDlg, IDC_UPDOWN1, UDM_SETPOS32, NULL, (LPARAM)prefs.dyndataxplorer_maxrecursion);
			CheckDlgButton(hwndDlg, IDC_DONT_SHOW_DUMPER_NAG, prefs.suppress_nags[1]);
			CheckDlgButton(hwndDlg, IDC_CIRCULRESOLV, prefs.circulated_resolving);
			if (inf.filetype == f_PE) {
				state[0] = IsDlgButtonChecked(hwndDlg, IDC_DBG_RESOLVE_RTA);
				EnableDlgItem(hwndDlg, IDC_REFRTI, state[0]);
				EnableDlgItem(hwndDlg, IDC_CMTRTI, state[0]);
				EnableDlgItem(hwndDlg, IDC_DONT_SHOW_RTR_NAG, state[0]
					&& GetPrivateProfileInt(cfgsection, "resolver_nag_seen", false, inipath));
				state[1] = IsDlgButtonChecked(hwndDlg, IDC_DBG_SAVE_VALUES);
				EnableDlgItem(hwndDlg, IDC_KEEPINITDATA, state[1]);
				state[2] = state[1] && IsDlgButtonChecked(tabs[0].hWnd, IDC_CREATEOFFSETS);
				EnableDlgItem(hwndDlg, IDC_EXPLOREHEAPS, state[2]);
				state[2] = state[2] && IsDlgButtonChecked(hwndDlg, IDC_EXPLOREHEAPS);
				EnableDlgItem(hwndDlg, IDC_HONOUROFFSETS, state[2]);
				EnableDlgItem(hwndDlg, IDC_STATIC3, state[2]);
				EnableDlgItem(hwndDlg, IDC_MAXCLONABLE, state[2]);
				EnableDlgItem(hwndDlg, IDC_STATIC4, state[2]);
				EnableDlgItem(hwndDlg, IDC_MAXOFFSETABLE, state[2]);
				EnableDlgItem(hwndDlg, IDC_ENABLEVALLOC, state[2]);
				state[3] = state[2] && IsDlgButtonChecked(hwndDlg, IDC_ENABLEVALLOC);
				EnableDlgItem(hwndDlg, IDC_STATIC5, state[3]);
				EnableDlgItem(hwndDlg, IDC_MINVALLOCBLK, state[3]);
				EnableDlgItem(hwndDlg, IDC_STATIC1, state[2]);
				EnableDlgItem(hwndDlg, IDC_OFFTOSTAT, state[2]);
				EnableDlgItem(hwndDlg, IDC_STATIC2, state[2]);
				EnableDlgItem(hwndDlg, IDC_OFFTODYN, state[2]);
				state[3] = state[2] && SendDlgItemMessage(hwndDlg, IDC_OFFTOSTAT, CB_GETCURSEL, 0, 0) > 0;
				EnableDlgItem(hwndDlg, IDC_CARENAMES, state[3]);
				EnableDlgItem(hwndDlg, IDC_CAREREFS, state[3]);
				EnableDlgItem(hwndDlg, IDC_CAREFUNCS, state[3]);
				state[3] = state[2] && SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_GETCURSEL, 0, 0) >= 1;
				EnableDlgItem(hwndDlg, IDC_MAPIMPSDIR, state[2]);
				//state[3] = state[3] && SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_GETCURSEL, 0, 0) >= 3;
				EnableDlgItem(hwndDlg, IDC_STATIC6, state[2]);
				EnableDlgItem(hwndDlg, IDC_MAXRECURSION, state[2]);
				EnableDlgItem(hwndDlg, IDC_DONT_SHOW_DUMPER_NAG, state[1]
					&& GetPrivateProfileInt(cfgsection, "dumper_nag_seen", false, inipath));
				EnableDlgItem(hwndDlg, IDC_CIRCULRESOLV, state[0] && state[1]);
				static const tooltip_item_t tooltips[] = {
					IDC_DBG_RESOLVE_RTA, "Resolve indirect calls/jumps by internal tracer engine (original executable is required). Use this feature to resolve OOP virtual calls. Only indirect flow within captured ranges is resolved.",
					IDC_REFRTI, "Add user x-ref for resolved pair caller->callee",
					IDC_CMTRTI, "Put resolved target to comment of caller",
					//IDC_DONT_SHOW_RTR_NAG, "Don't show warning nag before each tracer run",
					IDC_DBG_SAVE_VALUES, "On exported root function entry point compare process static data to dead data in idabase. Patch differing values into idabase and make proper comment. Warn about possible offsets to virtual ranges.",
					IDC_KEEPINITDATA, "Keep patched runtime data in disassembly so they can be revised any later. All patched data by CSC can be restored to original state by running a IDC command `RunPlugin(\"csc\",99);` (IDC console)",
					IDC_EXPLOREHEAPS, "Recognize offsets to virtual data. Only static data found different in current or any previous run are examined. The scanner is capable to determine allocated blocks of several types: malloc(new) of BCC heap, MSVC32 large-block heap, GNU C heap, GetMem of VCL heap, stack variables of any function in call hierarchy with BP-based frame. Scanner is capable to recognize and explore offsets to a static address or to another dynamic block of known type, so that all captured dynamic data are covered in output and replicated at snippet start (helper functions are generated). Offset recognition rules conform to general static offset rules, offset rules from dynamic block conform additionally to rules for dynamic data explorer.",
					IDC_MAXOFFSETABLE, "Max. size of dynamic block scanned for offsets, too big blocks -> too much false offsets (0 = size unlimited)",
					IDC_HONOUROFFSETS, "Force flow from existing offsets despite traversal rules (follow every static offset to any determinable dynamic data unconditionally)",
					IDC_MAPIMPSDIR, "Parameter decides about method used to denote imports references:\n\r"
						"- Direct projection denotes id name right in emited dynamic block, the offset is translated later to point to actual import address\n\r"
						"- Indirect projection leaves actual address in dynamic block raw and import is projected at runtime by import mapping helper",
					IDC_MAXCLONABLE, "Max. size of captured dynamic block (0 = size unlimited)",
					IDC_ENABLEVALLOC, "Allow VirtualAlloc(...) memory blocks to be included into known heap block types if no std. heap block type is found inside (warning: VirtualAlloc blocks are supposed to be quite a big)",
					IDC_MINVALLOCBLK, "Min. size for replicable VirtualAlloc(...) block (0 = size unlimited, 1MB = VC32 default)",
					IDC_OFFTOSTAT, "Allow offset virtual block -> static range:\n\r"
						"Only to externals allows offset to only library names if library functions are excluded\n\r"
						"Only to captured ranges and externals allows offset to only captured static range of any type meeting the rules and excluded libnames\n\r"
						"Allow exploring allows offset to any static range of any type meeting the rules, new ranges are added to output and explored\n\n"
						"Offset recognition conforms to general rules (minimum alignment, heads/tails), plus several additional rules are available to reduce chance of false offsets.",
					IDC_OFFTODYN, "Allow offset virtual block -> virtual block:\n\r"
						"Only map imports allows offset to imported function/data\n\r"
						//"Only map imports and to modules allows offset to any import and to unknown place of mapped image (not export - not anchorable)\n\r"
						"Only to captured range and map imports allows offset to only captured virtual block of any type and imported function/data\n\r"
						"Allow exploring allows offset to any dynamic block of any type or imported function/data, new blocks are added to output and explored",
					IDC_CARENAMES, "Consider offset to only named static address (reduce false offsets)",
					IDC_CAREREFS, "Consider offset to only items being referred from another static address (reduce false offsets)",
					IDC_CAREFUNCS, "Code targets only: consider offset to only function start (reduce false offsets)",
					IDC_MAXRECURSION, "Max nesting level from virtual blocks (0 = unlimited, 1 = don't follow from virtual block)",
					IDC_UPDOWN1, "Max nesting level from virtual blocks (0 = unlimited, 1 = don't follow from virtual block)",
					//IDC_DONT_SHOW_DUMPER_NAG, "Don't show warning nag before each tracer run",
					IDC_CIRCULRESOLV, "Run flow tracer and data dumper in infinite loop till one returns no new areas discovered. Both flow tracer and data dumper may add new static ranges, not yet processed by the another engine, circular resolving should ensure every range was processed.",
				};
				HWND hwndTT(CreateWindowEx(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL,
					WS_POPUP | TTS_NOPREFIX | TTS_BALLOON | TTS_ALWAYSTIP, CW_USEDEFAULT, CW_USEDEFAULT,
					CW_USEDEFAULT, CW_USEDEFAULT, hwndDlg, NULL, hInstance, NULL));
				SetWindowPos(hwndTT, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
				SendMessage(hwndTT, TTM_SETMAXTIPWIDTH, 0, (LPARAM)400);
				SendMessage(hwndTT, TTM_SETDELAYTIME, (WPARAM)TTDT_AUTOPOP, (LPARAM)30000);
				TOOLINFO tt;
				memset(&tt, 0, sizeof tt);
				tt.cbSize = sizeof tt;
				tt.uFlags = TTF_SUBCLASS | TTF_IDISHWND | TTF_TRANSPARENT;
				tt.hwnd = hwndDlg;
				tt.hinst = hInstance;
				for (const tooltip_item_t *i = boost::begin(tooltips); i != boost::end(tooltips); ++i) {
					tt.uId = (UINT_PTR)GetDlgItem(hwndDlg, i->uID);
					tt.lpszText = (LPSTR)i->lpText;
					SendMessage(hwndTT, TTM_ADDTOOL, 0, (LPARAM)&tt);
				}
			} else { // runtime features PE-only
				EnableWindow(hwndDlg, FALSE);
				EnumChildWindows(hwndDlg, enablewndproc, (LPARAM)FALSE);
			}
			return 1;
		}
		case WM_COMMAND:
			switch (HIWORD(wParam)) {
				case BN_CLICKED:
					switch (LOWORD(wParam)) {
						case IDC_DBG_RESOLVE_RTA:
							state[0] = IsDlgButtonChecked(hwndDlg, IDC_DBG_RESOLVE_RTA);
							EnableDlgItem(hwndDlg, IDC_REFRTI, state[0]);
							EnableDlgItem(hwndDlg, IDC_CMTRTI, state[0]);
							EnableDlgItem(hwndDlg, IDC_DONT_SHOW_RTR_NAG, state[0]
								&& GetPrivateProfileInt(cfgsection, "resolver_nag_seen", false, inipath));
							EnableDlgItem(hwndDlg, IDC_CIRCULRESOLV, state[0]
								&& IsDlgButtonChecked(hwndDlg, IDC_DBG_SAVE_VALUES));
							SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
							break;
						case IDC_DBG_SAVE_VALUES:
							state[0] = IsDlgButtonChecked(hwndDlg, IDC_DBG_SAVE_VALUES);
							EnableDlgItem(hwndDlg, IDC_KEEPINITDATA, state[0]);
							state[1] = state[0] && IsDlgButtonChecked(tabs[0].hWnd, IDC_CREATEOFFSETS);
							EnableDlgItem(hwndDlg, IDC_EXPLOREHEAPS, state[1]);
							EnableDlgItem(hwndDlg, IDC_DONT_SHOW_DUMPER_NAG, state[0]
								&& GetPrivateProfileInt(cfgsection, "dumper_nag_seen", false, inipath));
							EnableDlgItem(hwndDlg, IDC_CIRCULRESOLV,
								IsDlgButtonChecked(hwndDlg, IDC_DBG_RESOLVE_RTA) && state[0]);
							state[1] = state[1] && IsDlgButtonChecked(hwndDlg, IDC_EXPLOREHEAPS);
							goto on_xploreheaps_clicked;
						case IDC_EXPLOREHEAPS:
							state[1] = IsDlgButtonChecked(hwndDlg, IDC_EXPLOREHEAPS);
						on_xploreheaps_clicked:
							EnableDlgItem(hwndDlg, IDC_HONOUROFFSETS, state[1]);
							EnableDlgItem(hwndDlg, IDC_STATIC3, state[1]);
							EnableDlgItem(hwndDlg, IDC_MAXOFFSETABLE, state[1]);
							EnableDlgItem(hwndDlg, IDC_STATIC4, state[1]);
							EnableDlgItem(hwndDlg, IDC_MAXCLONABLE, state[1]);
							EnableDlgItem(hwndDlg, IDC_ENABLEVALLOC, state[1]);
							state[2] = state[1] && IsDlgButtonChecked(hwndDlg, IDC_ENABLEVALLOC);
							EnableDlgItem(hwndDlg, IDC_STATIC5, state[2]);
							EnableDlgItem(hwndDlg, IDC_MINVALLOCBLK, state[2]);
							EnableDlgItem(hwndDlg, IDC_STATIC1, state[1]);
							EnableDlgItem(hwndDlg, IDC_OFFTOSTAT, state[1]);
							EnableDlgItem(hwndDlg, IDC_STATIC2, state[1]);
							EnableDlgItem(hwndDlg, IDC_OFFTODYN, state[1]);
							state[2] = state[1] && SendDlgItemMessage(hwndDlg, IDC_OFFTOSTAT, CB_GETCURSEL, 0, 0) >= 1;
							EnableDlgItem(hwndDlg, IDC_CARENAMES, state[2]);
							EnableDlgItem(hwndDlg, IDC_CAREREFS, state[2]);
							EnableDlgItem(hwndDlg, IDC_CAREFUNCS, state[2]);
							state[2] = state[1] && SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_GETCURSEL, 0, 0) >= 1;
							EnableDlgItem(hwndDlg, IDC_MAPIMPSDIR, state[2]);
							EnableDlgItem(hwndDlg, IDC_STATIC6, state[1]);
							EnableDlgItem(hwndDlg, IDC_MAXRECURSION, state[1]);
							SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
							break;
						case IDC_ENABLEVALLOC:
							state[2] = IsDlgButtonChecked(hwndDlg, IDC_ENABLEVALLOC);
							EnableDlgItem(hwndDlg, IDC_STATIC5, state[2]);
							EnableDlgItem(hwndDlg, IDC_MINVALLOCBLK, state[2]);
							SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
							break;
					} // switch
					break;
				case CBN_SELCHANGE:
					switch (LOWORD(wParam)) {
						case IDC_OFFTOSTAT:
							state[2] = SendDlgItemMessage(hwndDlg, IDC_OFFTOSTAT, CB_GETCURSEL, 0, 0) > 0;
							EnableDlgItem(hwndDlg, IDC_CARENAMES, state[2]);
							EnableDlgItem(hwndDlg, IDC_CAREREFS, state[2]);
							EnableDlgItem(hwndDlg, IDC_CAREFUNCS, state[2]);
							SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
							break;
						case IDC_OFFTODYN:
							state[2] = SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_GETCURSEL, 0, 0) >= 1;
							EnableDlgItem(hwndDlg, IDC_MAPIMPSDIR, state[2]);
							/*
							state[2] = state[2] && SendDlgItemMessage(hwndDlg, IDC_OFFTODYN, CB_GETCURSEL, 0, 0) >= 3;
							EnableDlgItem(hwndDlg, IDC_STATIC6, state[2]);
							EnableDlgItem(hwndDlg, IDC_MAXRECURSION, state[2]);
							*/
							SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
							break;
					} // switch
					break;
			} // switch HIWORD(wParam)
			return 1;
		case WM_HELP:
			_ASSERTE(lParam != NULL);
			SendDlgItemMessage(hwndDlg, ((LPHELPINFO)lParam)->iCtrlId, TTM_POPUP, 0, 0);
			SetWindowLong(hwndDlg, DWL_MSGRESULT, 1);
			return 1;
	} //switch statement
	return 0;
}
}

//  class CTracer 

void CTracer::OnCreateProcess() const {
	__super::OnCreateProcess();
	_ASSERTE(!isLoaded());
	HideDebugger();
	if (is_dll) {
		char inpath[QMAXPATH];
		get_input_file_path(CPY(inpath));
		module = modules[inpath]; //modules.find_fullpath(inpath);
		_ASSERTE(!isLoaded() || !isMain(module));
		if (!isLoaded() && prefs.verbosity >= 1) cmsg << prefix <<
			"waiting for the dll to load..." << endl;
	} else { // not dll
		module = mainModule();
		_ASSERTE(isMain(module));
	}
	if (isLoaded()) OnModuleAvailable();
	total_ranges = 0;
}

void CTracer::OnLoadDll(const CDebugger::module_t &module) const {
	__super::OnLoadDll(module);
	if (!isLoaded() && is_dll) {
		_ASSERTE(!isMain(module));
		char inpath[QMAXPATH];
		get_input_file_path(CPY(inpath));
		if (module.has_fname(inpath)) {
			this->module = modules[module];
			_ASSERTE(isLoaded() && !isMain(this->module));
		}
		if (isLoaded()/* || (this->module = modules[inpath]) != modules.end()*/) {
			if (prefs.verbosity >= 1) cmsg << prefix << this->module->getBaseName() <<
				" was loaded at " << asptr(this->module->lpBaseOfImage) << endl;
			OnModuleAvailable();
		}
#ifdef _DEBUG
		else
			_ASSERTE(modules[inpath] == modules.end());
#endif
	}
}

//  class ranges_t 

bool ranges_t::add(const range_t &range, const char *comment) {
	_ASSERTE(isEnabled(range.startEA) && isEnabled(range.endEA));
	if (range.endEA <= range.startEA || !isEnabled(range.startEA)
		|| !isEnabled(range.endEA)) return false; // only valid ranges
	iterator tmp(find_if(begin(), end(),
		boost::bind2nd(boost::mem_fun_ref(areaex_t::intersects), range)));
	bool addition(tmp == end() || tmp->type != range.type);
	char name[MAXNAMESIZE];
	if (addition) {
		push_back(range);
		(tmp = end())--;
		_ASSERTE(*tmp == range);
		if (prefs.create_graph) {
			tmp->GetLabel(CPY(name));
			tmp->graph_node = graph.AddNode(name, tmp->type, tmp->startEA, tmp->size());
		}
	} else if (!tmp->covers(range)) { // expand existing
		tmp->unite(range);
		if (prefs.create_graph && tmp->graph_node != -1) {
			graph_node_t &node(graph.at(tmp->graph_node));
			node.ea = tmp->startEA;
			if (tmp->GetLabel(CPY(name))) node.set_name(name, tmp->type, tmp->size());
		}
		addition = true;
	}
	_ASSERTE(tmp->covers(range) && tmp->is_of_type(range.type));
	if (comment != 0 && *comment != 0) tmp->comments.push_back(comment);
	// cross-check
	if (addition) {
		if (prefs.create_graph && tmp->graph_node != -1 && comment != 0 && *comment != 0)
			graph.at(tmp->graph_node).hint.append(comment);
#ifdef _DEBUG
		for (iterator i = begin(); i != end(); ++i)
			if (i != tmp && tmp->intersects(*i)) {
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
					"%s(%08IX, %08IX, %08lX): (<%08IX-%08IX>, %08lX) overlaps with existing (<%08IX-%08IX>, %08lX)\n",
					__FUNCTION__, range.startEA, range.endEA, range.type, tmp->startEA,
					tmp->endEA, tmp->type, i->startEA, i->endEA, i->type);
			}
#endif // _DEBUG
	}
	return addition;
}

//  class CResolver 

void CResolver::OnModuleAvailable() const {
	_ASSERTE(isLoaded());
	if (isLoaded()) {
		for (CSC::breakpoints_t::const_iterator i = CSC::breakpoints.begin(); i != CSC::breakpoints.end(); ++i)
			if ((i->second & 6) != 0) // start/stop tracing
				SetSwBreakpoint(reinterpret_cast<LPCVOID>(i->first + module->getBaseOffset()));
		if (++run_counter == 1 && !prefs.suppress_nags[0]) {
			// annoy only in first round
			string message("host application is about to start, ");
			message.append(single_range ?
				"to proceed all functions need to be executed\n"
					"fully, if the application will not close afterwards, terminate it manually" :
				"because of many root functions exist its impossible\n"
					"to determine safely when all exported ranges were hit. if no more exported ranges will be\n"
					"executed, klose target manually.");
			message.append("\n\nwarning, the application may run _very_ slow at collected areas, if theres\n"
				"anti-debug traps it may crash even\n\n"
				"another warning: the tracer fully relies on ida's analysis, if theres false code containing\n"
				"indirect calls/jumps at real data area, the application may crash when accessing the\n"
				"data - saving idabase before running resolver not a bad idea.\n\n"
				"another another warning: be sure the disassemblee doesnot contain any malicious or harmful\n"
				"code that can be executed before the root function is called.\n\n"
				"are you sure to run the runtime flow resolver?");
			if (MessageBox(get_ida_hwnd(), message.c_str(), PLUGINNAME " v" PLUGINVERSIONTEXT,
				MB_ICONQUESTION | MB_YESNO) != IDYES) Terminate();
			save_bool(cfgsection, "resolver_nag_seen", true);
		} else if (run_counter == 2)
			if (prefs.verbosity >= 1) cmsg << prefix << "circular resolving in progress..." << endl;
		//bIgnoreExternalExceptions = TRUE;
		//prefs.suddendeath_on_fatal = false;
		rtrlist.Clear();
		caller_ea = BADADDR;
		exit_ea = BADADDR;
		resolving_active = false;
	}
}

void CResolver::OnCrash() const {
	__super::OnCrash();
	const modules_t::const_iterator
		module(modules.find(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, FALSE));
	if (prefs.verbosity >= 2) cmsg << prefix << "warning: application crash with exception " <<
		ashex(DebugEvent.u.Exception.ExceptionRecord.ExceptionCode, (streamsize)sizeof(DebugEvent.u.Exception.ExceptionRecord.ExceptionCode) << 1) <<
		" in " << (module != modules.end() ? module->getBaseName() : "<unknown>") <<
		" at " << asptr((LPBYTE)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress -
		(module != modules.end() ? module->getBaseOffset() : 0)) << endl;
	boost::shared_crtptr<SYMBOL_INFO> pSymInfo(sizeof SYMBOL_INFO + MAX_SYM_NAME - 1);
	if (pSymInfo) {
		pSymInfo->MaxNameLen = MAX_SYM_NAME;
		DWORD64 Displacement;
		if (SymFromAddr(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress,
			&Displacement, pSymInfo.get()) && prefs.verbosity >= 1) {
			cmsg << '(' << pSymInfo->Name;
			if (Displacement > 0) cmsg << '+' << ashex(Displacement);
			cmsg << ')';
		}
		pSymInfo.reset();
	}
	if (prefs.verbosity >= 1) {
		if (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
			cmsg << ": couldnot " << (DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 0 ?
				"read from" : "write to") << ' ' << asptr(DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]);
		cmsg << endl << prefix << "  caller_ea=" << asea(caller_ea) << " exit_ea=" <<
			asea(exit_ea) << " flags=" << ashex(DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags, (streamsize)sizeof(DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags) << 1) << endl;
		CONTEXT Context;
		Context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
		if (GetThreadContext(Context, TRUE)) cmsg << prefix <<
			"  context dump:" <<
			" eax=" << ashex(Context.Eax, (streamsize)sizeof(Context.Eax) << 1) <<
			" ecx=" << ashex(Context.Ecx, (streamsize)sizeof(Context.Ecx) << 1) <<
			" edx=" << ashex(Context.Edx, (streamsize)sizeof(Context.Edx) << 1) <<
			" ebx=" << ashex(Context.Ebx, (streamsize)sizeof(Context.Ebx) << 1) <<
			" ebp=" << ashex(Context.Ebp, (streamsize)sizeof(Context.Ebp) << 1) <<
			" esp=" << ashex(Context.Esp, (streamsize)sizeof(Context.Esp) << 1) <<
			" esi=" << ashex(Context.Esi, (streamsize)sizeof(Context.Esi) << 1) <<
			" edi=" << ashex(Context.Edi, (streamsize)sizeof(Context.Edi) << 1) <<
			" eip=" << ashex(Context.Eip, (streamsize)sizeof(Context.Eip) << 1) << endl;
	}
}

DWORD CResolver::OnBreakpoint(breakpoint_type_t Type, LPVOID Address) const {
	__super::OnBreakpoint(Type, Address);
	if (Type == bpt_sw/* || Type == bpt_hw_exec*/) {
		_ASSERTE(isLoaded());
		ea_t ea(reinterpret_cast<ea_t>(Address));
#ifdef _SHOWADDRESS
		showAddr(ea);
#endif
		ea -= module->getBaseOffset();
		_ASSERTE(::isLoaded(ea));
		CSC::breakpoints_t::const_iterator i(CSC::breakpoints.find(ea));
		_ASSERTE(i != CSC::breakpoints.end() && (i->second & 7) != 0);
		if (i != CSC::breakpoints.end()) {
			if (!resolving_active && (i->second & 2) != 0) { // start tracing
				//DisableBreakpoint(); // once only
				resolving_active = true;
				for (CSC::breakpoints_t::const_iterator i = CSC::breakpoints.begin();
					i != CSC::breakpoints.end(); ++i) if ((i->second & 1) != 0)
						SetSwBreakpoint(reinterpret_cast<LPCVOID>(i->first + module->getBaseOffset()));
				/*
				for_each(CSC::breakpoints.begin(), CSC::breakpoints.end(),
					boost::lambda::if_then((boost::lambda::bind(&breakpoints_t::value_type::second,
						boost::lambda::_1) & 1) != 0, boost::lambda::bind(&CDebugger::SetSwBreakpoint,
							this, reinterpret_cast<LPCVOID>(boost::lambda::bind(&breakpoints_t::value_type::first,
								boost::lambda::_1) + boost::lambda::constant(module->getBaseOffset())))));
				*/
				if (prefs.verbosity >= 1) cmsg << prefix << "resolving started at " <<
					asea(ea + module->getBaseOffset());
				if (prefs.verbosity >= 1) {
					char name[MAXNAMESIZE];
					if (get_true_name(BADADDR, ea, CPY(name)) != 0) cmsg << " (" << name << ')';
					cmsg << endl;
				}
			}
			if (resolving_active) {
				if ((i->second & 1) != 0) { // indirect call/jump
					_ASSERTE(is_indirectflow_insn(ea));
					caller_ea = ea;
				}
				if ((i->second & 4) != 0) exit_ea = ea; // stop tracing?
				if (caller_ea != BADADDR || exit_ea != BADADDR) SingleStep();
			} // resolving_active
		}
	} // own breakpoint
	DWORD dwResult;
	if (wasBreak()) {
		total_ranges = -1;
		Terminate();
		dwResult = DBG_TERMINATE_PROCESS;
		if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " <<
			user_abort().what() << ", aborting" << endl;
	} else
		dwResult = DBG_CONTINUE;
	return dwResult;
}

cref_t CResolver::GetCRefType(const insn_t &cmd) {
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

void CResolver::NameAnonOffsets(ea_t to, const char *tgtname, const char *cmt) const {
	_ASSERTE(isEnabled(caller_ea));
	_ASSERTE(tgtname != 0);
	flags_t flags;
	if (!isEnabled(caller_ea) || tgtname == 0 || *tgtname == 0
		|| !isCode(flags = get_flags_novalue(caller_ea)) || ua_ana0(caller_ea) <= 0)
			return;
	member_t *stkvar;
	char newname[MAXNAMESIZE];
	ea_t tgt;
	sval_t actval;
	if (cmd.Op1.type == o_mem && isEnabled(tgt = calc_reference_target(cmd, 0))
		&& !is_in_rsrc(tgt) && !has_name(get_flags_novalue(tgt))) {
		_ASSERTE(!does_ref_extern(caller_ea));
		qsnprintf(CPY(newname), "lp%s", tgtname);
		newname[2] = static_cast<char>(toupper(static_cast<uchar>(newname[2])));
		if (do_name_anyway(tgt, newname, MAXNAMESIZE - 1)) {
			if (prefs.verbosity >= 3) cmsg << prefix << "  info: offset at " <<
				asea(tgt) << " renamed to " << newname << endl;
			if (cmt != 0 && *cmt != 0) append_unique_cmt(tgt, cmt, true/*repeatable*/);
		}
		if (tgt == get_item_head(tgt) && !isArray(tgt)
			&& op_offset(tgt, 0, get_default_reftype(tgt)) != 0)
			ProcessNewOffset(tgt, to); // offset created
	} else if (isStkvar0(flags) && (stkvar = get_stkvar(cmd.Op1,
			static_cast<sval_t>(cmd.Op1.addr), &actval)) != 0
		&& (get_member_name(stkvar->id, CPY(newname)) <= 0
		|| is_dummy_member_name(newname))) {
		qsnprintf(CPY(newname), "lp%s", tgtname);
		newname[2] = static_cast<char>(toupper(static_cast<uchar>(newname[2])));
		uint suffix(2);
		uval_t discard;
		while (get_name_value(caller_ea, newname, &discard) == NT_STKVAR) {
			qsnprintf(CPY(newname), "lp%s_%u", tgtname, ++suffix);
			newname[2] = static_cast<char>(toupper(static_cast<uchar>(newname[2])));
		}
		if (set_member_name(get_frame(get_func(caller_ea)), stkvar->get_soff(), newname)) {
			if (prefs.verbosity >= 3) cmsg << prefix << "  info: variable at " <<
				asea(caller_ea) << " renamed to " << newname << endl;
			if (cmt != 0 && *cmt != 0) set_member_cmt(stkvar, cmt, true/*repeatable*/);
		}
	} // is stkvar
}

DWORD CResolver::OnSingleStep() const {
	__super::OnSingleStep();
	_ASSERTE(resolving_active);
	_ASSERTE(isLoaded());
#ifdef _DEBUG
	if (!isEnabled(caller_ea) && !isEnabled(exit_ea))
		_RPT3(_CRT_ASSERT, "%s(): single step triggered without backward reference IP=%s:%08X\n",
			__FUNCTION__, module->getBaseName(), DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
#endif
	const modules_t::const_iterator module(modules.find(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, FALSE));
	if (module == modules.end()) {
		_RPT2(_CRT_WARN, "%s(...): module not found for IP=%08X\n", __FUNCTION__, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
		return DBG_CONTINUE;
	}
	func_t *func;
	if (isEnabled(caller_ea)) {
		char name[MAXNAMESIZE], tmpstr[512];
		if (module == this->module) { // same module
			const ea_t to(reinterpret_cast<ea_t>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress) - module->getBaseOffset());
#ifdef _SHOWADDRESS
			showAddr(to);
#endif
			if (isEnabled(to)) {
				if (!rtrlist.Has(caller_ea, to)) { // no dupe processing
					xrefblk_t xref;
					for (bool dupe = xref.first_from(caller_ea, XREF_FAR); dupe;
						dupe = xref.next_from()) if (xref.iscode && xref.to == to) break;
					if (!dupe) {
						uint16 type;
						const flags_t flags(get_flags_novalue(caller_ea));
						// care x-ref
						if (isCode(flags) && ua_ana0(caller_ea) > 0) {
							type = static_cast<uint16>(GetCRefType(cmd));
							if (prefs.addref) add_cref(caller_ea, to, static_cast<cref_t>(type | XREF_USER));
							if (is_call_insn(cmd.itype)) {
								if ((func = get_fchunk(to)) != 0 && func->startEA != to) {
									if (prefs.verbosity >= 2) cmsg << prefix <<
										"warning: function at " << asea(func->startEA) <<
										" start lower than target despite call instruction" << endl;
									if (prefs.reporting_verbosity >= 1) report.Add(to, 0x0FFF,
										"function start lower than resolved call target (doubtful function frame?)");
									// delete improperly starting functions?
									//del_func(func->startEA);
									//func = 0;
								}
								if (func == 0 && add_func(to, BADADDR) != 0) {
									if ((func = get_fchunk(to)) != 0) analyze_area(*func);
									if (get_func_name(to, CPY(name)) == 0) {
										name[0] = 0;
										_RPTF2(_CRT_WARN, "%s(): get_func_name(%08IX, ...) returned NULL\n",
											__FUNCTION__, to);
									}
									if (prefs.verbosity >= 3) cmsg << prefix <<
										"  info: new function at " << asea(to) << " created: " <<
										name << endl;
									if (pBatchResults != 0) pBatchResults->Add(to, 0x0003,
										_sprintf("new function %s created", name).c_str());
								} // new func created
							} // is call
						} else {
							type = static_cast<uint16>(dr_I);
							if (prefs.addref) add_dref(caller_ea, to, static_cast<dref_t>(type | XREF_USER));
						}
						if (get_true_name(BADADDR, to, CPY(name)) == 0) name[0] = 0;
						// care overview list
						qstrcpy(tmpstr, "created ok");
						if (name[0] != 0) qsnprintf(CAT(tmpstr), " (%s)", name);
						rtrlist.Add(caller_ea, to, type, tmpstr);
						// care comment
						if (prefs.cmtrta) {
							qsnprintf(CPY(tmpstr), "evaluated address resolved: %08a", to);
							const ea_t caller_head(get_item_head(caller_ea));
							char cmt[MAXSPECSIZE];
							if (GET_CMT(caller_head, false, CPY(cmt)) <= 0
								|| !boost::contains(cmt, tmpstr)) {
								if (name[0] != 0) qsnprintf(CAT(tmpstr), " (%s)", name);
								append_cmt(caller_head, tmpstr, false);
							}
						}
						// care log window
						if (prefs.verbosity >= 3) {
							cmsg << prefix << "  info: evaluated address resolved: " <<
								asea(caller_ea) << " -> " << asea(to);
							if (name[0] != 0) cmsg << " (" << name << ')';
							cmsg << endl;
						}
						NameAnonOffsets(to, name); // rename if offset by operand and convert to offset
						// explore & add subranges
						try {
							if (!isCode(flags)) {
								do_unknown(to, true);
								if (ua_code(to) == 0) {
									++fatals;
									if (prefs.verbosity >= 1) cmsg << prefix <<
										"error: tracer stopped at " << asea(to) <<
										" defined as data, make code here and run me again" << endl;
									_ASSERTE(isCode(get_flags_novalue(caller_ea)));
									char dassm[MAXSTR], mnem[MAXSTR];
									qsnprintf(CPY(tmpstr), "%s at %08a points to data (runtime check), mnemonics: %s",
										ua_mnem(caller_ea, CPY(mnem)), caller_ea, get_disasm(to, CPY(dassm)));
									if (prefs.reporting_verbosity >= 1) report.Add(to, 0xFFFF, tmpstr);
									if (prefs.suddendeath_on_fatal) {
										qsnprintf(CPY(tmpstr), "tracer landed at non-code area (%08IX)", to);
										throw logic_error(tmpstr);
									}
								}
							}
							if (prefs.code2code && prefs.drefs) {
								const ranges_t::const_iterator range(static_ranges.find(caller_ea));
								_ASSERTE(range != static_ranges.end());
								total_ranges += ExploreCREF(caller_ea, to, range != static_ranges.end()
									&& range->level != (uint)-1 ? range->level + 1 : (uint)-1);
							}
						} catch (const exception &e) {
							total_ranges = -1;
							Terminate();
							if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " <<
								e.what() << ", aborting" << endl;
							return DBG_TERMINATE_PROCESS;
						}
					} // unique
				} // !has item
			} // isEnabled(to)
#ifdef _DEBUG
			else
				_RPT2(_CRT_WARN, "%s(): address %08IX not enabled despite in main module\n",
					__FUNCTION__, to);
#endif // _DEBUG
		} else {
			const module_t::exports_t::const_iterator
				export(module->exports[DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress]);
			if (export != module->exports.end()) {
#ifdef _SHOWADDRESS
				showAddr(reinterpret_cast<ea_t>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress));
#endif
				if (!rtrlist.Has(caller_ea, reinterpret_cast<ea_t>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress))) { // no dupe processing
					if (!export->Name.empty()) // ImpByName
						qsnprintf(CPY(name), "%s (%s)", export->Name.c_str(), module->getBaseName());
					else // ImpByOrd care if not 1-based
						qsnprintf(CPY(name), "%s@%hu", module->getBaseName(), export->Ordinal);
					// care overview list
					rtrlist.Add(caller_ea, reinterpret_cast<ea_t>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress),
						static_cast<uint16>(isCode(get_flags_novalue(caller_ea))
							&& ua_ana0(caller_ea) > 0 ? GetCRefType(cmd) : dr_I), name);
					// care comment
					if (prefs.cmtrta) {
						qsnprintf(CPY(tmpstr), "evaluated address resolved: %s", name);
						append_unique_cmt(get_item_head(caller_ea), tmpstr);
					}
					// care log window
					if (prefs.verbosity >= 3) cmsg << prefix <<
						"  info: evaluated address resolved: " <<
						asea(caller_ea) << " -> " << name << endl;
					// rename if offset by operand and convert to offset
					const char *cmt(0);
					if (!export->Name.empty()) { // ImpByName
						qstrcpy(name, export->Name.c_str());
						if (module->hasName()) cmt = module->getBaseName();
					} else { // ImpByOrd care if not 1-based
						char basename[_MAX_FNAME];
						_splitpath(module->getBaseName(), 0, 0, basename, 0);
						qsnprintf(CPY(name), "%s@%hu", basename, export->Ordinal);
					}
					NameAnonOffsets(reinterpret_cast<ea_t>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress),
						name, cmt);
				} // pair not resolved yet
			} // has export
		}
	} // caller_ea enabled
	// test for exit
	if (isEnabled(exit_ea)) {
		ea_t ea;
		func_t *func0;
		if (module != this->module && (ua_ana0(exit_ea) == 0 || is_ret_insn(cmd.itype))
			|| module == this->module && ((func = get_func(ea =
				reinterpret_cast<ea_t>(DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress) -
				module->getBaseOffset())) == 0
			|| ua_ana0(exit_ea) == 0 || is_ret_insn(cmd.itype)
			&& ((func0 = get_func(exit_ea)) == 0 || func->startEA != func0->startEA)
			|| !static_ranges.has_address(ea) && (prefs.include_libitems || !is_call_insn(cmd.itype)
			|| !is_true_libfunc(func)/* || get_supressed_library_flag(func->startEA) == 1*/)
			&& (prefs.include_thunkfuncs || !is_call_insn(cmd.itype)
				&& !is_jump_insn(cmd.itype) || !is_pure_import_func(func)
				&& (prefs.include_libitems || !is_thunk_library_func(func)))
			&& (prefs.include_hidden || !is_call_insn(cmd.itype)
			|| CSC::is_visible_func(func)))) { // flow outside base scope
			resolving_active = false;
			for (CSC::breakpoints_t::const_iterator i = CSC::breakpoints.begin(); i != CSC::breakpoints.end(); ++i)
				if (i->second == 1) DeleteBreakpoint((LPCVOID)(i->first + this->module->getBaseOffset()));
			_ASSERTE(isCode(get_flags_novalue(exit_ea)));
			if (prefs.verbosity >= 1) cmsg << prefix << "resolving stopped at " << asea(exit_ea);
			char tmp[MAXNAMESIZE];
			if (get_true_name(BADADDR, exit_ea, CPY(tmp)) != 0 && prefs.verbosity >= 1)
				cmsg << " (" << tmp << ')';
			if (get_disasm(exit_ea, CPY(tmp)) != 0 && prefs.verbosity >= 1)
				cmsg << ", last instruction: " << tmp;
			if (single_range) {
				Terminate();
				if (prefs.verbosity >= 1) cmsg << " (terminated)" << endl;
				return DBG_TERMINATE_PROCESS;
			}
			cmsg << endl;
			if (!is_ret_insn(cmd.itype)) {
				if (prefs.verbosity >= 1) cmsg << prefix <<
					"warning: doubtful function exit (see previous line about details)" << endl;
				if (prefs.reporting_verbosity >= 1) report.Add(cmd.ea, 0x0029,
					_sprintf("doubtful function exit (%s)", tmp).c_str());
				_RPT3(_CRT_WARN, "%s(...): doubtful function exit at %08IX (%s)\n",
					__FUNCTION__, cmd.ea, tmp);
			}
		}
		_ASSERTE(module != this->module || isEnabled(ea)); // ok, go on we stay in scope
	} // isEnabled(exit_ea);
	caller_ea = BADADDR;
	exit_ea = BADADDR; // everything handled
	return DBG_CONTINUE;
}

//  class CDumper 

void CDumper::OnModuleAvailable() const {
	_ASSERTE(isLoaded());
	if (isLoaded()) {
		for (CSC::breakpoints_t::const_iterator i = CSC::breakpoints.begin(); i != CSC::breakpoints.end(); ++i)
			if ((i->second & 2) != 0) SetSwBreakpoint((LPCVOID)(i->first + module->getBaseOffset()));
		if (++run_counter == 1 && !prefs.suppress_nags[1]) {
			if (MessageBox(get_ida_hwnd(), "to get initial values of all variables, run the host application\n"
				"the way root function(s) are invoked (applcation will run till the\n"
				"root code is reached).\n\n"
				"be sure the disassemblee doesnot contain any malicious or harmful\n"
				"code that can be executed before the root function is called.\n\n"
				"are you sure to run the process dumper?", PLUGINNAME " v" PLUGINVERSIONTEXT,
				MB_ICONQUESTION | MB_YESNO) != IDYES) Terminate();
			save_bool(cfgsection, "dumper_nag_seen", true);
		}
		//bIgnoreExternalExceptions = TRUE;
		//prefs.suddendeath_on_fatal = false;
	}
}

DWORD CDumper::OnBreakpoint(breakpoint_type_t Type, LPVOID Address) const {
	__super::OnBreakpoint(Type, Address);
	_ASSERTE(isLoaded());
	if (Type != bpt_sw/* && Type != bpt_hw_exec*/) return DBG_CONTINUE; // unexpected!!
	ea_t IP(reinterpret_cast<ea_t>(Address));
#ifdef _SHOWADDRESS
	showAddr(IP);
#endif
	IP -= module->getBaseOffset();
#ifdef _DEBUG
	const CSC::breakpoints_t::const_iterator i(CSC::breakpoints.find(IP));
	_ASSERTE(i != CSC::breakpoints.end() && (i->second & 2) != 0);
	const time_t start(time(0));
#endif
	_ASSERTE(refused_for_address.empty());
	_ASSERTE(!winheap);
	_ASSERTE(VCLheap.empty());
	_ASSERTE(BCCheap.empty());
	_ASSERTE(GNUheap.empty());
	_ASSERTE(VCSBheap.empty());
	try {
		if (prefs.verbosity >= 1) {
			cmsg << prefix << "dumping process data at " << asea(IP);
			if (get_true_name(BADADDR, IP, CPY(name)) != 0) cmsg << " (" << name << ')';
			cmsg << endl;
		}
		root_stack = 0;
		root_bp = 0;
		memset(&root_frame, 0, sizeof root_frame);
		root_frame.id = BADNODE;
		CONTEXT Context;
		struc_t *frame;
		const flags_t ipFlags(get_flags_novalue(IP));
		_ASSERTE(isFunc(ipFlags));
		if ((ipFlags & FF_FUNC) != 0) {
			Context.ContextFlags = CONTEXT_CONTROL;
			if (GetThreadContext(Context, TRUE)) {
				root_stack = Context.Esp;
				root_bp = Context.Ebp;
			}
			func_t *func;
			if (root_stack != 0 && (func = get_func(IP)) != 0
				&& (frame = get_frame(func)) != 0) {
				root_arglist = get_struc_size(frame) -
					get_ptr_size() - func->frregs - func->frsize;
				_ASSERTE((signed)root_arglist >= 0);
				root_frame = *frame;
			} else {
				root_arglist = 0;
				memset(&root_frame, 0, sizeof root_frame);
				root_frame.id = BADNODE;
			}
		} // func at IP present
		if ((lpStackTop = GetThreadStackTop()) == NULL) {
			_RPTF2(_CRT_WARN, "%s(...): %s() returned 0 for this thread\n",
				__FUNCTION__, "CDebugger::GetThreadStackTop");
			const threads_t::const_iterator thread(FindThread());
			if (thread != threads.end()) {
				lpStackTop = thread->GetStackTop();
#ifdef _DEBUG
				if (lpStackTop == NULL)
					_RPTF2(_CRT_WARN, "%s(...): %s() returned 0\n", __FUNCTION__,
						"CDebugger::thread_t::GetStackTop");
#endif // _DEBUG
			}
#ifdef _DEBUG
			else
				_RPTF2(_CRT_WARN, "%s(...): %s() returned 0\n", __FUNCTION__,
					"CDebugger::FindThread");
#endif
		}
#ifdef _DEBUG_VERBOSE
		OutputDebugString("%s%s(...): stack top for current thread=%08X (0x%lX)\n",
			prefix, __FUNCTION__, lpStackTop, DebugEvent.dwThreadId);
#endif
		if (prefs.dbg_exploreheaps && prefs.dyndataxplorer_offtodyn >= 2
			&& (prefs.createoffsets || prefs.dyndataxplorer_honouroffsets)) {
			winheap.reset(NewHeapMgr());
			_ASSERTE(winheap);
			const_cast<bool &>(hasVCLMemFunction) =
				get_name_ea(BADADDR, "@System@SysGetMem$qqri") != BADADDR
				|| get_name_ea(BADADDR, "System.SysGetMem@00DFDAD9") != BADADDR
				|| get_name_ea(BADADDR, "@System@SysFreeMem$qqrpv") != BADADDR
				|| get_name_ea(BADADDR, "System.SysFreeMem@00DFDAD9") != BADADDR
				|| get_name_ea(BADADDR, "@System@SysReallocMem$qqrpvi") != BADADDR
				|| get_name_ea(BADADDR, "System.SysReallocMem@C57859E7") != BADADDR
				|| get_name_ea(BADADDR, "@SysGetMem$qqri") != BADADDR
				|| get_name_ea(BADADDR, "@SysFreeMem$qqrpv") != BADADDR
				|| get_name_ea(BADADDR, "@SysReallocMem$qqrpvi") != BADADDR;
		}
#ifdef _DEBUG
		//MessageBox(get_ida_hwnd(), "Dbg: Time to attach", "Hook notification", MB_ICONINFORMATION);
#endif
		range = 0;
		member_t *member;
		ea_t tgt;
		used_translation = false;
		if (prefs.dbg_exploreheaps && (ipFlags & FF_FUNC) != 0) {
			func_t func(*get_fchunk(IP));
			Context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
			if (is_func_entry(&func) && GetThreadContext(Context, TRUE)) {
				// func frame is valid
				if (prefs.verbosity >= 1) cmsg << prefix << "exploring arg values..." << endl;
				asize_t argsbase;
				if ((frame = get_frame(&func)) != 0
					&& (func.argsize = get_struc_size(frame) -
						(argsbase = func.frsize + func.frregs + get_ptr_size())) > 0) try {
					get_func_name(&func, CPY(name));
					char tmpname[MAXNAMESIZE];
					qsnprintf(CPY(tmpname), "%s_arglist", name);
					clonedblocks_t::iterator foo;
					try {
						foo = AddClonedRange(reinterpret_cast<LPCVOID>(Context.Esp + get_ptr_size()),
							func.argsize, 0, reinterpret_cast<LPCVOID>(BADADDR), 0, tmpname).first;
						_ASSERTE(foo != cloned_blocks.end());
						//if (foo == cloned_blocks.end())
						//	throw runtime_error("stdcall arglist couldnot be cloned");
						foo->GetLabel(CPY(tmpname),
							reinterpret_cast<LPCVOID>(Context.Esp + get_ptr_size()));
						_sprintf(deconst_it(foo).comment,
							"copy of stdcall arglist passed to %s", name);
						static_ranges.add_comment(func.startEA,
							string("arglist saved as ").append(tmpname));
						qsnprintf(CPY(tmpstr), "stdcall arglist passed to %s saved as %s",
							name, tmpname);
						if (prefs.verbosity >= 3) cmsg << prefix << "  info: " << tmpstr << endl;
						if (prefs.reporting_verbosity >= 2) report.Add(func.startEA, 0x0001, tmpstr);
					} catch (const exception &e) {
						if (typeid(e) == typeid(overflow_error)) /*re*/throw; // pass high
						if (prefs.verbosity >= 2) cmsg << prefix << "warning: " << e.what() << endl;
						if (prefs.reporting_verbosity >= 1) report.Add(func.startEA, 0x0FFF, e.what());
						throw exit_scope(e.what());
					}
					for (ea_t offset = argsbase; offset != BADADDR;
						offset = get_struc_next_offset(frame, offset))
						if ((member = get_member(frame, offset)) != 0) {
							const asize_t memsize(get_member_size(member));
							for (asize_t offset = 0; offset < memsize; ++offset) {
								tgt = prefs.createoffsets && offset + get_ptr_size() <= memsize ?
									TryOffset(foo->dump.get(), member->get_soff() + offset - argsbase,
									cloned_blocks[(LPCVOID)(Context.Esp + get_ptr_size())] != cloned_blocks.end() ?
									Context.Esp + get_ptr_size() : BADADDR
#ifdef _DEBUG
									, func.argsize
#endif
									) : BADADDR;
								if (offset == 0) {
									if (tgt == BADADDR) tgt =
										(memsize & 3) == 0 ? *(PDWORD)((PBYTE)foo->dump.get() + member->get_soff() - argsbase) :
										(memsize & 1) == 0 ? *(PWORD)((PBYTE)foo->dump.get() + member->get_soff() - argsbase) :
										/*(memsize & 1) == 1)*/*((PBYTE)foo->dump.get() + member->get_soff() - argsbase);
									if (get_member_name(member->id, CPY(name)) > 0)
										AddArgValue(func, name, tgt, memsize);
								} // argument base
							} // scan member
						} // member at offset valid and available
				} catch (const exit_scope &e) { /*handled*/ }
				if (wasBreak()) throw user_abort();
				// try fastcall arguments
				//if (get_cc(inf.cc.cm) == CM_CC_FASTCALL)
				for (uint16 iter = 0; iter < 3; ++iter) try { // fastcall specific
					for (ea_t scan = func.startEA; scan < func.endEA; scan = next_not_tail(scan)) {
#ifdef _SHOWADDRESS
						showAddr(scan);
#endif
					lbl0:
						if (isCode(get_flags_novalue(scan)) && ua_ana0(scan) > 0) {
							func_t *pfn;
							if ((cmd.itype == NN_jmp || cmd.itype == NN_jmpshort)
								&& calc_reference_target(cmd, 0) > scan
								&& (pfn = get_func(calc_reference_target(cmd, 0))) != 0
								&& pfn->startEA == func.startEA) {
								scan = calc_reference_target(cmd, 0);
								goto lbl0;
							}
							if (is_condflow_insn(cmd.itype) || (is_jump_insn(cmd.itype)
								|| is_loop_insn(cmd.itype))
								&& calc_reference_target(cmd, 0) <= scan
								&& (pfn = get_func(calc_reference_target(cmd, 0))) != 0
								&& pfn->startEA == func.startEA) continue; // local loop
							if (is_flowchange_insn(cmd.itype)) break; // context lost
							for (uint16 n = 0; n < UA_MAXOP; ++n) if (cmd.Operands[n].is_reg(iter)
								&& insn_changes_opnd(cmd.itype, n)) throw exit_scope("context lost");
							for (n = 0; n < UA_MAXOP; ++n)
								if ((cmd.Operands[n].type == o_reg || cmd.Operands[n].type == o_phrase
									|| cmd.Operands[n].type == o_displ) && cmd.Operands[n].reg == iter
									&& insn_uses_opnd(cmd.itype, n)) {
									tgt = prefs.createoffsets ?
										TryOffset(&Context.Edx, 2 - iter << 2) : BADADDR;
									if (tgt == BADADDR) tgt = *((PDWORD)&Context.Eax - iter);
									static const char *const r32_canons[] = { "eax", "ecx", "edx" };
									AddArgValue(func, r32_canons[iter]/*reg2str(iter)*/, tgt);
									throw exit_scope("register value added"); // ok
								} // test if this reg used
						} // valid instruction
					} // walk function
				} catch (const exit_scope &e) { /* constructive exception expected */ }
			} // func is entry and got context
		} // func present
		for (ranges_t::iterator range = static_ranges.begin(); range != static_ranges.end(); ++range) {
			if (total_ranges == -1) break;
			if (wasBreak()) throw user_abort();
			boost::shared_crtptr<void> buf;
			if ((range->type == FF_DATA || range->type == FF_BSS
				/*|| range->type == FF_CONST*/) && buf.reset(range->size())) {
				if (ReadMemory(reinterpret_cast<LPCVOID>(range->startEA +
					module->getBaseOffset()), buf.get(), range->size()) >= range->size()) {
					const bool different(range->type == FF_BSS
						|| !equal_bytes(range->startEA, (const uchar *)buf.get(), 0, range->size(), true));
					if (different) {
						tgt = get_item_head(range->startEA);
						while (isAlign(get_flags_novalue(tgt))) tgt = next_not_tail(tgt);
						// care comment
						append_unique_cmt(tgt, "csc note: runtime data initialized", false);
						range->GetLabel(CPY(name));
						// care log window
						if (prefs.verbosity >= 3) cmsg << prefix << "  info: data at " <<
							asea(tgt) << " initialized (" << name << ')' << endl;
						// care idaview
						if (prefs.reporting_verbosity >= 2) report.Add(tgt, 0x0041,
							_sprintf("data initialized (%s)", name).c_str());
					}
					// detect offsets for dword, struct and undefined types
					if (different || prefs.dbg_exploreheaps
						&& (net_patch.altval(range->startEA, 'p') > 0
						|| net_patch.charval(range->startEA, 'P') == 1)) {
						this->range = &*range;
						for (asize_t offset = 0; offset + get_ptr_size() <= range->size(); ++offset)
							TryOffset(buf.get(), offset, range->startEA
#ifdef _DEBUG
								, range->size()
#endif
								);
					} // explore && (changed || patched)
					if (different) {
						doVar(range->startEA, true);
						patch_many_bytes(range->startEA, buf.get(), range->size());
						net_patch.altset(range->startEA, range->size(), 'p');
						analyze_area(*range);
						have_patched = true;
						if (range->type == FF_BSS) {
							_RPTF3(_CRT_WARN, "%s(...): bss data <%08IX-%08IX> modified during execution, concurrence may get broken\n",
								__FUNCTION__, range->startEA, range->endEA);
							range->type = FF_DATA;
						}
					} // different
				} // data read
#ifdef _DEBUG
				else
					_RPTF4(_CRT_WARN/*_CRT_ERROR*/, "%s(...): %s(%08IX, ..., 0x%IX) failed\n",
						__FUNCTION__, "CDebugger::ReadMemory",
						range->startEA + module->getBaseOffset(), range->size());
#endif // _DEBUG
			} // area vardata and buffer available
		} // iterate ranges
	} catch (const exception &e) {
		total_ranges = -1;
		if (prefs.verbosity >= 1) cmsg << prefix << "catastrophic: " <<
			e.what() << ", aborting" << endl;
	}
	winheap.reset();
	VCLheap.clear();
	BCCheap.clear();
	GNUheap.clear();
	VCSBheap.clear();
	refused_for_address.clear();
#ifdef _DEBUG
	time_t duration(time(0) - start);
	uint s(duration % 60);
	OutputDebugString("%sprocess data dumper duration: %Iu:%02Iu:%02u\n",
		prefix, duration / 60, (duration /= 60) % 60, s);
#endif // _DEBUG
	Terminate();
	return DBG_TERMINATE_PROCESS;
}

typedef flags_t (ida_export *get_flags_by_size_t)(size_t);

flags_t getDefRefFlag(asize_t refsize = 0, flags_t flags = 0) {
	if (refsize <= 0) refsize = get_ptr_size(flags);
	switch (refsize) {
		case sizeof(BYTE): return byteflag();
		case sizeof(WORD): return wordflag();
		case sizeof(DWORD): return dwrdflag();
		case 8/*sizeof(QWORD)*/: return qwrdflag();
		case 16/*sizeof(OWORD)*/: return owrdflag();
#if IDP_INTERFACE_VERSION >= 76
		case 3: return tribyteflag();
#endif
	}
	if (refsize == ph.tbyte_size) return tbytflag();
	_RPT2(_CRT_ASSERT, "%s(): unexpected default pointer size(%u): returning byte\n",
		__FUNCTION__, refsize);
#if IDP_INTERFACE_VERSION >= 76
	if (hIdaWll != NULL) {
		const get_flags_by_size_t pget_flags_by_size =
			(get_flags_by_size_t)GetProcAddress(hIdaWll, "get_flags_by_size");
		if (pget_flags_by_size != NULL) return pget_flags_by_size(refsize);
	}
#endif
	return 0/*FF_DATA?*/;
}

bool CDumper::MakeStaticOffset(ea_t ea, struc_t *struc, member_t *member) const {
	if (struc != 0 && member != 0) {
#if IDP_INTERFACE_VERSION < 76
		typeinfo_t ti_off = { get_default_reftype(ea), 0, BADADDR, 0, 0 };
#else // IDP_INTERFACE_VERSION >= 76
		typeinfo_t ti_off = { BADADDR, 0, 0, get_default_reftype(ea) };
#endif
		if (!set_member_type(struc, member->get_soff(),
			getDefRefFlag() | offflag(), &ti_off, get_member_size(member))) {
			if (prefs.verbosity >= 2) cmsg << prefix << "warning: " <<
				asea(ea) << ": " << "failed to make member offset" << endl;
			if (prefs.reporting_verbosity >= 1) report.Add(ea, 0x0FFF,
				"failed to make member offset");
			if (pBatchResults != 0) pBatchResults->Add(ea, 0xFFFF,
				"failed to make member offset");
			return false;
		}
		++total_offsets; // ???
		analyze_area(get_item_head(ea), get_item_end(ea));
		char memname[MAXNAMESIZE];
		get_member_fullname(member->id, CPY(memname));
		_ASSERTE(memname[0] != 0);
		qsnprintf(CPY(tmpstr), "struct member %s made offset",
			memname[0] != 0 ? memname : "(null)");
		if (prefs.verbosity >= 3) cmsg << prefix << "  info: " << tmpstr <<
			" (" << asea(ea) << ')' << endl;
		if (pBatchResults != 0) pBatchResults->Add(ea, 0x0005, tmpstr);
	} else {
		_ASSERTE(OffAtBound(ea));
		if (!OffAtBound(ea) || !is_dummy_data_range(ea, get_ptr_size())) {
			if (prefs.verbosity >= 3) cmsg << prefix << "  info: " <<
				asea(ea) << ": " << "possible offset in non-dummy region" << endl;
			if (prefs.reporting_verbosity >= 2) report.Add(ea, 0x0042,
				"possible offset in non-dummy region");
// 			if (pBatchResults != 0) pBatchResults->Add(ea,
// 				0x0501, "possible offset in non-dummy region");
			qsnprintf(CPY(tmpstr), "possible offset in non-dummy region (%08a)", ea);
			append_unique_cmt(ea, tmpstr);
			return false;
		}
		do_unknown_range(ea, get_ptr_size(), false);
		if (op_offset(ea, 0, get_default_reftype(ea)) == 0) { // failed
			if (prefs.verbosity >= 2) cmsg << prefix << "warning: " <<
				asea(ea) << ": " << "failed to create offset" << endl;
			if (prefs.reporting_verbosity >= 1) report.Add(ea, 0x0FFF,
				"failed to create offset");
			if (pBatchResults != 0) pBatchResults->Add(ea, 0xFFFF,
				"failed to create offset");
			return false;
		}
		ProcessNewOffset(ea);
	}
	return true;
}

uint8 CDumper::getStrucRefType(struc_t *&struc, ea_t stroff, member_t *&member) const {
	if (struc != 0 && (member = get_best_fit_member(struc, stroff)) != 0
		&& stroff < member->get_soff() + get_member_size(member)) {
		if (isOff0(member->flag)
			&& (stroff - member->get_soff()) % get_data_type_size(member) == 0) {
			refinfo_t ri;
			if (get_refinfo(member->id, 0, &ri) != 0) refinfo = ri;
			return 2;
		} else if (isStruct(member->flag)) {
			return getStrucRefType(struc = get_sptr(member),
				stroff - member->get_soff(), member);
		} else if ((member->flag & DT_TYPE) == (getDefRefFlag() & DT_TYPE)
			&& (!isDefArg0(member->flag) || isNumH0(member->flag)))
			return 1;
	}
	struc = 0;
	member = 0;
	return 0;
}

uint8 CDumper::getStatRefType(ea_t ea, struc_t *&struc, member_t *&member) const {
	uint8 result(0);
	struc = 0;
	member = 0;
	refinfo.reset();
	if (!isEnabled(ea)) return 0;
	ea_t const head = get_item_head(ea);
	flags_t flags = get_flags_novalue(head);
	if (!isCode(flags)) {
// 		if (!isData(flags)) {
// 			/*if (OffAtBound(ea)) */return 1;
// 		} else
		if (isOff0(flags)) {
			if ((ea - head) % get_data_type_size(head, flags) == 0/*
				&& (prefs.dbg_exploreheaps && prefs.dyndataxplorer_honouroffsets
				|| OffAtBound(ea))*/) {
				refinfo_t ri;
				if (get_refinfo(head, 0, &ri) != 0) refinfo = ri;
				return 2;
			}
		} else if (isStruct(flags)) {
			typeinfo_t ti;
			// can`t get struct = can't be offset here
			if (get_typeinfo(head, 0, flags, &ti) != 0
				&& (struc = get_struc(ti.tid)) != 0
				|| (struc = get_struc(get_strid(head))) != 0)
				return getStrucRefType(struc, ea - head, member);
		} else {
			/*if (!OffAtBound(ea)) */return 0;
			for (ea_t offset = 0; offset < get_ptr_size(); ++offset) {
				flags = get_flags_novalue(get_item_head(ea + offset));
				if (isDefArg0(flags) && !isNumH0(flags) && !isOff0(flags) // is forced format
					// not dword and (not byte or is forced format)
					|| ((flags & DT_TYPE) != (getDefRefFlag() & DT_TYPE) || does_prefix_lstring(ea + offset))
					&& ((flags & DT_TYPE) != FF_BYTE || (isDefArg0(flags) && range->type != FF_BSS)))
					return 0;
			}
			return 1;
		}
	}
	return 0;
}

ea_t CDumper::TryOffset(void *buf, size_t referreroffset, ea_t referrer,
#ifdef _DEBUG
	asize_t referrersize,
#endif
	uint level) const {
	_ASSERTE(isLoaded());
	_ASSERTE(static_ranges.has_address(referrer)
		|| cloned_blocks[reinterpret_cast<LPCVOID>(referrer)] != cloned_blocks.end()
		|| referrer == BADADDR);
	const uint8 from(
		isEnabled(referrer) ? 1 : // static
		IsAddressEnabled(reinterpret_cast<LPCVOID>(referrer)) ? 2 : // dynamic
		0 // emulated
	);
	_ASSERTE(from == 1 || prefs.dbg_exploreheaps);
	const ea_t refea(referrer != BADADDR ? referrer + referreroffset : BADADDR);
	// variables for identifying static variable type
	uint8 statRefType;
	struc_t *struc = 0;
	member_t *member = 0;
	// identify referrer type
	bool force;
	switch (from) {
		case 1:
			if ((statRefType = getStatRefType(refea, struc, member)) <= 0
				|| statRefType < 2 && (!prefs.createoffsets
				|| member == 0 && !OffAtBound(refea))) return BADADDR;
			force = prefs.dbg_exploreheaps && statRefType >= 2
				&& prefs.dyndataxplorer_honouroffsets;
			break;
		case 2:
			if (!prefs.createoffsets || !OffAtBound(refea)) return BADADDR;
			force = false;
			break;
		default:
			if (!prefs.createoffsets) return BADADDR;
			force = false;
	} // switch from
	if (prefs.maxruntime != 0 && time(0) - start > prefs.maxruntime)
		__stl_throw_overflow_error("running time over limit");
	if (wasBreak()) throw user_abort();
	const PDWORD offbase((PDWORD)((LPBYTE)buf + referreroffset));
#define lpMem reinterpret_cast<LPCVOID>(*offbase)
	ea_t tgt;
	const uint8 to(
		isEnabled(tgt = from == 1 && refinfo ? calc_reference_target(refea,
			*refinfo, static_cast<ea_t>(*offbase - module->getBaseOffset())) :
			static_cast<ea_t>(*offbase)) ? 1 : // static
		IsAddressEnabled(lpMem) ? 2 : // dynamic
		0 // invalid otherwise
	);
	switch (to) {
		// ============================== to static ===============================
		case 1: {
			bool isExternal;
			if (from == 1) { // is from static
				if (statRefType <= 1/*raw*/) {
					if (!Off2Stat(tgt) || !MakeStaticOffset(refea, struc, member)) break;
					if (is_in_rsrc(tgt)) {
				} else { /* is offset */
						if (prefs.verbosity >= 2 && log_addresses.insert(tgt).second)
							cmsg << prefix << "warning: " <<
								asea(refea) << ": " << "offset to resource section (" <<
								asea(tgt) << ')' << endl;
						qsnprintf(CPY(tmpstr), "offset to resource section (%08a)", tgt);
						append_unique_cmt(get_item_head(refea), tmpstr);
						if (prefs.reporting_verbosity >= 1) report.Add(refea, 0x0FFF,
							"offset to resource section");
						if (!force) break;
					}
				}
			} else { // not from static
				if (!Dyn2Stat(tgt)) break;
				if (prefs.dyndataxplorer_offtostat < 3 && !CanOffFromDyn(tgt)) {
					GetLabel(tgt, CPY(name));
					if (prefs.verbosity >= 3 && log_addresses.insert(refea).second) {
						cmsg << prefix << "  info: " << asea(refea) << ": possible offset to static area (";
						if (name[0] != 0) cmsg << name; else cmsg << asea(tgt);
						cmsg << "), keeping raw (exploral rules)" << endl;
					}
					if (prefs.reporting_verbosity >= 2) {
						if (name[0] != 0)
							qsnprintf(CPY(tmpstr), "possible offset to static area (%s), keeping raw (exploral rules)", name);
						else
							qsnprintf(CPY(tmpstr), "possible offset to static area (%08a), keeping raw (exploral rules)", tgt);
						report.Add(refea, 0x0042, tmpstr);
					}
					break;
				}
			}
			// target acceptable
#ifdef _SHOWADDRESS
			if (from != 0) showAddr(refea);
#endif
			if (from == 2) {
				const ea_t tmp = netnode("$ offsets").altval(tgt);
				if (isEnabled(tmp)) tgt = tmp; // translate
			}
			if (module->getBaseOffset() != 0) {
				qsnprintf(CPY(tmpstr), "offset to %08a relocated to default base", tgt);
				if (prefs.reporting_verbosity >= 2) report.Add(refea, 0x0229, tmpstr);
				if (from == 1) append_unique_cmt(get_item_head(refea), tmpstr);
				*offbase -= module->getBaseOffset();
			}
			if (from != 0 && !prefs.include_libitems
				&& (prefs.reloc_extfn_offs && is_libfuncname(tgt)
				|| prefs.reloc_extvar_offs && is_libvarname(tgt))
				&& !externals.insert(remappoint_t(referrer, referreroffset)).second) {
				if (prefs.verbosity >= 2) cmsg << prefix << "warning: failed to add address " <<
					asea(refea) << " to external translation table" << endl;
				if (prefs.reporting_verbosity >= 1) report.Add(refea, 0x0FFF,
					"failed to add offset to translation table");
			}
			if (from == 1 ? prefs.drefs : prefs.dyndataxplorer_offtostat >= 3) {
				const flags_t flags = get_flags_novalue(tgt);
				if (isCode(flags) && prefs.data2code)
					total_ranges += ExploreCREF(from == 0 ? BADADDR : refea,
						tgt, range != 0 && range->level != (uint)-1 ?
						range->level + level + 1 : (uint)-1);
				else if (!isCode(flags) && prefs.data2data)
					total_ranges += ExploreDREF(from == 0 ? BADADDR : refea,
						tgt, range != 0 && range->level != (uint)-1 ?
						range->level + level + 1 : (uint)-1);
			} else
				if (prefs.create_graph && from != 0) graph.AddRef(refea, tgt);
			return tgt;
		} // to static
		// ============================== to dynamic ==============================
		case 2: {
			if (!force && (!prefs.dbg_exploreheaps
				|| from != 1 && prefs.dyndataxplorer_offtodyn < 1
				|| from != 0 && member == 0 && !OffAtBound(refea))) break;
			const modules_t::const_iterator dll(modules.find(lpMem, FALSE));
			if (dll != modules.end()) { // offset to module image
				_ASSERTE(dll->hasName());
				if (from != 0) {
					module_t::exports_t::const_iterator export(dll->exports[lpMem]);
					_splitpath(dll->getBaseName(), 0, 0, basename, 0);
					name[0] = 0;
					cmt.clear();
					if (export != dll->exports.end()) {
						if (from == 1 && statRefType <= 1/*raw*/) MakeStaticOffset(refea, struc, member);
						if (!export->Name.empty()) { // ImpByName
							const pair<imports_t::const_iterator, bool>
								i(imports.insert(import_t(reinterpret_cast<LPCVOID>(refea),
								dll != module ? dll->getBaseName() : 0, export->Name)));
							if (i.second) {
								if (from == 2 && prefs.dyndataxplorer_map_imps_dir) {
									const clonedblocks_t::const_iterator
										foo(cloned_blocks.find(reinterpret_cast<LPCVOID>(referrer), true));
									if (foo != cloned_blocks.end()) {
										deconst_it(foo).imprefs[referreroffset] = i.first;
										// signal probable external translation helper calling
										used_translation = true;
									}
								}
								if (prefs.verbosity >= 3 && log_addresses.insert(reinterpret_cast<ea_t>(lpMem)).second)
									cmsg << prefix << "  info: address " << asptr(lpMem) <<
										" mapped to import " << basename << '.' << export->Name << endl;
								if (prefs.reporting_verbosity >= 2) report.Add(refea, 0x0219,
									_sprintf("address %08X mapped to import %s.%s",
										lpMem, basename, export->Name.c_str()).c_str());
								if (from == 1)
									if (/*referreroffset == 0 && */get_item_head(refea) == refea
										&& !isArray(refea)) {
										if (!has_name(get_flags_novalue(refea)))
											qsnprintf(CPY(name), "lp%s", export->Name.c_str());
										cmt.assign(dll->getBaseName()).append(1, ':').append(export->Name);
									} else
										_sprintf(cmt, "+0x%IX: offset to import %s.%s",
											refea - get_item_head(refea), basename, export->Name.c_str());
								if (prefs.create_graph && !excluded_symbols.have(lpMem)) {
									qsnprintf(CPY(tmpstr), "%s.%s", dll->getBaseName(),
										export->Name.c_str());
									excluded_symbols[reinterpret_cast<ea_t>(lpMem)] =
										graph.AddNode(tmpstr, FF_XTRN, reinterpret_cast<ea_t>(lpMem));
								}
							} else {
								if (from != 0) ShoutEAVWarning(refea, "%s%s: target=%08X, size=? (cannot add reference - memory full?)",
									dll->getBaseName(), lpMem);
								break;
							}
						} else { // ImpByOrd care if not 1-based
							if (imports.insert(import_t(reinterpret_cast<LPCVOID>(refea),
								dll != module ? dll->getBaseName() : 0, export->Ordinal)).second) {
								if (prefs.verbosity >= 3 && log_addresses.insert(reinterpret_cast<ea_t>(lpMem)).second)
									cmsg << prefix << "  info: address " << asptr(lpMem) <<
										" mapped to import " << basename << '@' << dec << export->Ordinal << endl;
								if (prefs.reporting_verbosity >= 2) report.Add(refea, 0x0219,
									_sprintf("address %08X mapped to import %s@%hu",
									lpMem, basename, export->Ordinal).c_str());
								if (from == 1)
									if (/*referreroffset == 0 && */get_item_head(refea) == refea
										&& !isArray(refea)) {
										if (!has_name(get_flags_novalue(refea)))
											qsnprintf(CPY(name), "lp%s@%hu", basename, export->Ordinal);
										//_sprintf(cmt, "%s:#%hu", dll->getBaseName(), export->Ordinal);
									} else
										_sprintf(cmt, "+0x%IX: offset to %s@%hu import",
											refea - get_item_head(refea), basename, export->Ordinal);
								if (prefs.create_graph && !excluded_symbols.have(lpMem)) {
									qsnprintf(CPY(tmpstr), "%s.@%hu", dll->getBaseName(),
										export->Ordinal);
									excluded_symbols[reinterpret_cast<ea_t>(lpMem)] =
										graph.AddNode(tmpstr, FF_XTRN, reinterpret_cast<ea_t>(lpMem));
								}
							} else {
								if (from != 0) ShoutEAVWarning(refea, "%s%s: target=%08X, size=? (cannot add reference - memory full?)",
									dll->getBaseName(), lpMem);
								break;
							}
						} // ImpByName/Ord?
					} else if (lpMem == dll->lpBaseOfImage || from == 1// && force ??
						|| !prefs.dyndataxplorer_carefuncs
							&& !prefs.dyndataxplorer_carenames
							&& !prefs.dyndataxplorer_carerefs) {
						// not an exported address: anchor address to module base
						if (from == 1 && statRefType <= 1/*raw*/) MakeStaticOffset(refea, struc, member);
						if (imports.insert(import_t(reinterpret_cast<LPCVOID>(refea),
							dll != module ? dll->getBaseName() : 0,
							static_cast<DWORD>((LPBYTE)lpMem - (LPBYTE)dll->lpBaseOfImage))).second) {
							if (lpMem == dll->lpBaseOfImage) { // module address
								if (prefs.verbosity >= 3 && log_addresses.insert(reinterpret_cast<ea_t>(lpMem)).second)
									cmsg << prefix << "  info: address " << asptr(lpMem) <<
										" mapped to " << dll->getBaseName() << " instance" << endl;
								if (prefs.reporting_verbosity >= 2) report.Add(refea, 0x0219,
									_sprintf("address %08X mapped to %s instance",
										lpMem, dll->getBaseName()).c_str());
								if (from == 1) if (/*referreroffset == 0
									&& */get_item_head(refea) == refea && !isArray(refea)) {
										if (!has_name(get_flags_novalue(refea))) {
											qsnprintf(CPY(name), "h%s", dll != module ? basename : "Instance");
											name[1] = static_cast<char>(toupper(static_cast<uchar>(name[1])));
										}
									} else
										_sprintf(cmt, "+0x%IX: offset to %s instance",
											refea - get_item_head(refea), dll->getBaseName());
							} // module load address
							/* senseless?!
							if (prefs.create_graph && !excluded_symbols.have(lpMem)) {
								qsnprintf(CPY(tmpstr), "%s+%08X", dll->getBaseName(),
									((LPBYTE)lpMem - (LPBYTE)dll->lpBaseOfImage));
								excluded_symbols[reinterpret_cast<ea_t>(lpMem)] =
									graph.AddNode(tmpstr, FF_XTRN, reinterpret_cast<ea_t>(lpMem));
							}
							*/
						} else {
							if (from != 0) ShoutEAVWarning(refea, "%s%s: target=%08X, size=? (cannot add reference - memory full?)",
								dll->getBaseName(), lpMem);
							break;
						}
					} else { // anything else consider number
						if (from != 0) ShoutEAVWarning(refea, "%s%s: target=%08X, size=? (address not anchorable)",
							dll->getBaseName(), lpMem);
						break;
					}
					if (from == 1) {
						// give offsets to imports meaningful name
						if (name[0] != 0 && make_unique_name(CPY(name)) != 0
							&& set_name(refea, name, SN_CHECK | SN_NOWARN | SN_NON_WEAK | SN_NON_PUBLIC)) {
							if (prefs.verbosity >= 3) cmsg << prefix << "  info: offset at " <<
								asea(refea) << " renamed to " << name << endl;
							if (pBatchResults != 0) pBatchResults->Add(refea, 0x000C,
								_sprintf("offset renamed to %s", name).c_str());
						}
						// ...and comment
						if (!cmt.empty()) append_unique_cmt(get_item_head(refea), cmt.c_str());
					} // from static range
				} // referrer is present
			} else if (prefs.dyndataxplorer_offtodyn >= 2 || force) {
				// offset to process virtual space?
				memblock_t block;
				const member_t *stkvar = 0;
				bitset<7> is_block;
				if (refused_for_address.find(lpMem) == refused_for_address.end()
					&& ((is_block[0] = (block = FindVcSbhBlock(lpMem, false)))
					|| (is_block[1] = (block = FindVCLBlock(lpMem, false)))
					|| (is_block[2] = (block = FindBCCBlock(lpMem, false)))
					|| (is_block[3] = (block = FindGNUCBlock(lpMem, false)))
					|| (is_block[4] = (block = FindStkVar(lpMem, root_stack, root_arglist,
						&root_frame, stkvar, root_bp, false)))
					|| (is_block[5] = (block = winheap->find(lpMem, FALSE)))
					|| (is_block[6] = (block = FindVirtAllocBlock(lpMem, false))))) { // is any known virtual block type
					_ASSERTE(lpMem >= block.BaseAddress);
					pair<clonedblocks_t::const_iterator, bool> clonedblock;
					if ((clonedblock.first = cloned_blocks.find(lpMem, false)) != cloned_blocks.end()) { // cloned already
						if (from == 1 && statRefType <= 1/*raw*/) MakeStaticOffset(refea, struc, member);
						deconst_it(clonedblock.first).referrers.insert(clonedblock_t::referrer_t(
							(LPBYTE)lpMem - (LPBYTE)clonedblock.first->BaseAddress,
							reinterpret_cast<LPCVOID>(referrer), referreroffset));
					} else if (block.Size > 0 && (force || prefs.data2data
						&& (from == 1 ? prefs.drefs : prefs.dyndataxplorer_offtodyn >= 3
						&& (prefs.dyndataxplorer_maxclonable == 0 || block.Size <= prefs.dyndataxplorer_maxclonable)
						&& (prefs.dyndataxplorer_maxrecursion == 0 || level < prefs.dyndataxplorer_maxrecursion)))) {
						if (stkvar != 0) {
							get_member_fullname(stkvar->id, CPY(name));
							//struc_t *const frame(get_member_struc(name));
						} else
							name[0] = 0;
						const char *hint;
						_ASSERTE(is_block.count() == 1);
						static const char *const block_types[] = {
							"MSVC malloc (smallheap) block",
							"VCL GetMem block",
							"BCC malloc block",
							"GCC malloc block",
							"stack variable/call argument",
							"MSVC malloc (LocalAlloc) block",
							"VirtualAlloc(...) block",
						};
						for (size_t n = 0; n < is_block.size(); ++n)
							if (is_block.test(n)) hint = block_types[n];
						try {
							_ASSERTE(hint != 0);
							clonedblock = AddClonedRange(block.BaseAddress, block.Size,
								(LPBYTE)lpMem - (LPBYTE)block.BaseAddress,
								reinterpret_cast<LPCVOID>(referrer), referreroffset, name, hint);
							_ASSERTE(clonedblock.first != cloned_blocks.end());
							//if (clonedblock.first == cloned_blocks.end())
							//	throw runtime_error("stdcall arglist couldnot be cloned");
							_ASSERTE(clonedblock.second);
						} catch (const exception &e) {
							if (typeid(e) == typeid(overflow_error)) /*re*/throw; // pass high
							if (prefs.verbosity >= 2) cmsg << prefix << "warning: " << e.what() << endl;
							if (prefs.reporting_verbosity >= 1)
								report.Add(reinterpret_cast<ea_t>(block.BaseAddress/*lpMem*/),
									0x0FFF, e.what());
							break;
						}
						if (!clonedblock.second) { // never should trigger
							if (from != 0) ShoutEAVWarning(refea,
								"%s%s: base=%08X, size=0x%IX (failed to add for cloning)",
								"commited page", block.BaseAddress, block.Size);
							break;
						}
						if (from == 1 && statRefType <= 1/*raw*/) MakeStaticOffset(refea, struc, member);
#ifdef _SHOWADDRESS
						if (from != 0) showAddr(refea);
#endif
						if (prefs.verbosity >= 2) cmsg << prefix << "range <" <<
							asptr(block.BaseAddress) << '-' << asptr(block.EndAddress()) <<
							"> added (cloned virtual block)" << endl;
						if (prefs.reporting_verbosity >= 1) report.Add(reinterpret_cast<ea_t>(block.BaseAddress),
							0x0209, _sprintf("virtual data of size 0x%IX added for cloning", block.Size).c_str());
						_ASSERTE(from == 0 || !area_t(referrer, referrer + referrersize).
							contains(reinterpret_cast<ea_t>(lpMem))); // no recursion!
						if (prefs.createoffsets/*redundant but speed-up*/
							&& (prefs.dyndataxplorer_maxoffsetable == 0
								|| block.Size <= prefs.dyndataxplorer_maxoffsetable)) {
							for (size_t offset = 0; offset + get_ptr_size() <= block.Size; ++offset)
								if (OffAtBound(reinterpret_cast<ea_t>(block.BaseAddress) + offset)/*redundand but speed-up*/)
									TryOffset(clonedblock.first->dump.get(), offset,
										reinterpret_cast<ea_t>(block.BaseAddress)
#ifdef _DEBUG
										, block.Size
#endif
										, level + 1);
						} else { // not explored
							if (prefs.verbosity >= 3) cmsg << "  info: range <" <<
								asptr(block.BaseAddress) << '-' << asptr(block.EndAddress()) <<
								"> added for cloning but not explored (" <<
								(prefs.createoffsets ? "size exceeded" : "new offsets disabled") << ')' << endl;
							if (prefs.createoffsets) {
								_ASSERTE(prefs.dyndataxplorer_maxoffsetable > 0);
								if (prefs.reporting_verbosity >= 2) report.Add(reinterpret_cast<ea_t>(block.BaseAddress),
									0x000D, _sprintf("dynamic block cloned but not explored (size exceeded 0x%IX > 0x%IX)",
									block.Size, prefs.dyndataxplorer_maxoffsetable).c_str());
							} else
								if (prefs.reporting_verbosity >= 2) report.Add(reinterpret_cast<ea_t>(block.BaseAddress),
									0x000D, "dynamic block cloned but not explored (creating offsets generally disabled)");
							break;
						}
					} else {
						if (from != 0) ShoutEAVWarning(refea,
							"%s%s: base=%08X, size=0x%IX (not passed cloning rules)",
							"commited page", block.BaseAddress, block.Size);
						break;
					}
				} else { // address enabled but block fake, unknown or cloning disabled
					refused_for_address.insert(lpMem);
					if (from != 0) {
						qstrcpy(name, "%s%s: target=%08X, size=? (type not determined or cloning disabled)");
						if (ReadMemory(lpMem, &this->buf, sizeof this->buf) >= sizeof this->buf) {
							qsnprintf(CAT(name), "; first %Iu bytes:", qnumber(this->buf));
							for (uint index = 0; index < qnumber(this->buf); ++index)
								qsnprintf(CAT(name), " %02X", this->buf[index]);
							qstrcat(name, " ");
							for (index = 0; index < qnumber(this->buf); ++index)
								qsnprintf(CAT(name), "%c", isprint(this->buf[index]) ?
									this->buf[index] : '.');
						} // read ok
#ifdef _DEBUG
						else
							_RPTF4(_CRT_WARN/*_CRT_ERROR*/, "%s(...): %s(%08X, ..., 0x%IX) failed\n",
								__FUNCTION__, "CDebugger::ReadMemory", lpMem, sizeof this->buf);
#endif
						ShoutEAVWarning(refea, name, "commited page", lpMem);
					}
					break;
				} // block fake or unknown
			} else
				// exploring of virtual space not allowed
				break;
			if (prefs.create_graph && from != 0) graph.AddRef(refea, lpMem);
			return reinterpret_cast<ea_t>(lpMem);
		} // to dynamic
	} // switch destination
	return BADADDR;
}

#undef lpMem

pair<clonedblocks_t::iterator, bool> CDumper::AddClonedRange(LPCVOID BaseAddress,
	SIZE_T dwSize, DWORD dwBaseOffset, LPCVOID referrer, DWORD referrer_offset,
	const char *label, const char *comment) const {
	_ASSERTE(dwSize > 0);
	_ASSERTE(!isEnabled(reinterpret_cast<ea_t>(BaseAddress)));
	_ASSERTE(IsAddressEnabled(BaseAddress));
	if (isEnabled(reinterpret_cast<ea_t>(BaseAddress)) || !IsAddressEnabled(BaseAddress))
		throw fmt_exception("address %08X invalid for cloning", BaseAddress);
	if (prefs.max_ranges != 0 && total_funcs + total_vars >= prefs.max_ranges)
		__stl_throw_overflow_error("range quantity over limit");
#ifdef _DEBUG
	const clonedblocks_t::const_iterator dupe(cloned_blocks.find(BaseAddress, false));
	if (dupe != cloned_blocks.end() && BaseAddress > dupe->BaseAddress)
		_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
			"%s(%08X, 0x%IX, ...): overlap with existing <%08X-%08X>\n",
			__FUNCTION__, BaseAddress, dwSize, dupe->BaseAddress, dupe->EndAddress());
#endif // _DEBUG
	const pair<clonedblocks_t::iterator, bool>
		p(cloned_blocks.insert(clonedblock_t(BaseAddress, dwSize, label, comment)));
	if (p.second) {
		if (dwSize > 0) try {
			deconst_it(p.first).dump.reset(dwSize);
			if (!p.first->dump) throw bad_alloc();
			if (ReadMemory(BaseAddress, p.first->dump.get(), dwSize) < dwSize)
				throw fmt_exception("%s(%08X, ..., 0x%IX) failed: this block will not be cloned",
					"CDebugger::ReadMemory", BaseAddress, dwSize);
#ifdef _DEBUG
		} catch (const exception &e) {
#else
		} catch (...) {
#endif
			cloned_blocks.erase(p.first);
#ifdef _DEBUG
			_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "%s(%08X, 0x%X, 0x%X, %08X, 0x%X, \"%s\", \"%s\"): %s (%s)\n",
				__FUNCTION__, BaseAddress, dwSize, dwBaseOffset, referrer, referrer_offset,
				label, comment, e.what(), typeid(e).name());
#endif
			/*re*/throw;
		}
		++total_virtual_ranges;
		++total_vars;
		if (prefs.create_graph/* && referrer != reinterpret_cast<LPCVOID>(BADADDR)
			&& referrer != NULL*/) {
			char name[MAXNAMESIZE];
			p.first->GetLabel(CPY(name));
			deconst_it(p.first).graph_node = graph.AddNode(name, FF_DYN,
				reinterpret_cast<ea_t>(BaseAddress), dwSize, comment);
		}
	}
	if (referrer != reinterpret_cast<LPCVOID>(BADADDR) && referrer != NULL)
		deconst_it(p.first).referrers.insert(clonedblock_t::referrer_t(dwBaseOffset,
			referrer, referrer_offset));
	return p;
}

void CDumper::ShoutEAVWarning(ea_t referrer, const char *format,
	const char *object, LPCVOID baseaddr, SIZE_T size) const {
	static const char malloc_warning[] = "runtime data possible offset to ";
	string msg;
	_sprintf(msg, format, malloc_warning, object, baseaddr, size);
	// care log
	if (prefs.verbosity >= 3 && log_addresses.insert(referrer).second)
		cmsg << prefix << "  info: " << asea(referrer) << ": " << msg << endl;
	// care idaview
	if (prefs.reporting_verbosity >= 2) report.Add(referrer, 0x0043, msg.c_str());
	// care comment
	if (isEnabled(referrer)) {
		const ea_t referrer_head(get_item_head(referrer));
		if (referrer > referrer_head) {
			char tmp[16];
			qsnprintf(CPY(tmp), "+0%IXh: ", referrer - referrer_head);
			msg.insert(0, tmp);
		}
// 		char cmt[MAXSPECSIZE];
// 		if (GET_CMT(referrer_head, false, CPY(cmt)) <= 0
// 			|| !boost::contains(cmt, malloc_warning))
			append_unique_cmt(referrer_head, msg.c_str(), false);
	}
}

void CDumper::RestorePatchedAreas() const {
	if (have_patched) try {
		for (ranges_t::iterator range = static_ranges.begin();
			(range = find_if(range, static_ranges.end(),
			boost::bind2nd(boost::mem_fun_ref(range_t::is_of_type), FF_DATA))) != static_ranges.end(); ++range)
			for (ea_t scan = range->startEA; scan < range->endEA; scan = nextaddr(scan))
				RestorePatchedBytes(scan);
		have_patched = false;
	} catch (const exception &e) {
		if (prefs.verbosity >= 1) cmsg << prefix << e.what() <<
			" on restoring data, aborting" << endl;
	}
}

uint CDumper::RestorePatchedBytes(nodeidx_t ea) {
	uint total(0);
	nodeidx_t size(net_patch.altval(ea, 'p'));
	if (size > 0) {
		for (ea_t scan = ea; scan < ea + size; scan = nextaddr(scan)) {
			if (net_patch.charval(scan, 'P') == 1) { // restore byte and delete patch marks
				put_byte(scan, net_patch.altval(scan));
				net_patch.altdel(scan);
				net_patch.chardel(scan, 'P');
			} else
				delValue(scan);
			++total;
		}
		net_patch.altdel(ea, 'p');
		static const char note[] = "csc note: runtime data initialized";
		char *cut, cmt[MAXSPECSIZE];
		if (GET_CMT(ea, false, CPY(cmt)) > 0 && (cut = strstr(cmt, note)) != 0) {
			*cut = 0;
			set_cmt(ea, cmt, false);
		}
	}
	return total;
}

CDebugger::memblock_t CDumper::FindVCLBlock(LPCVOID Address, bool bExactMatch) const {

#define cAlign         4
#define cThisUsedFlag  2
#define cPrevFreeFlag  1
#define cFillerFlag    0x80000000
#define cFlags         (cThisUsedFlag | cPrevFreeFlag | cFillerFlag)
#define cSmallSize     4*1024
#define cDecommitMin   15*1024

#define F_SIZE         (~cFlags)

	struct TFree;
	typedef struct TFree *PFree;
	__declspec(align(4)) struct TFree {
		PFree prev;
		PFree next;
		size_t size;
	};

	if (default_compiler() == COMP_BP
		|| default_compiler() == COMP_BC && hasVCLMemFunction) try {
#ifdef _DEBUG
		if (default_compiler() == COMP_BP && !hasVCLMemFunction)
			_RPTF2(_CRT_WARN, "%s(%08X, ...): trying as vcl heap region despite no vcl memory function found (relying on compiler type)\n",
				__FUNCTION__, Address);
#endif
		const customheapmgr::const_iterator i(VCLheap.find(Address, bExactMatch));
		if (i != VCLheap.end()) return *i;
		MEMORY_BASIC_INFORMATION MemInfo;
		if (VirtualQuery(Address, MemInfo) > 0
			&& MemInfo.State == MEM_COMMIT && MemInfo.Type == MEM_PRIVATE
			&& VirtualQuery(MemInfo.AllocationBase, MemInfo) > 0) {
			_ASSERTE(MemInfo.AllocationBase == MemInfo.BaseAddress);
			SIZE_T dwSizeField, Size;
			TFree free_space_descriptor;
			uint loopcount(0);
#ifdef _DEBUG
			LPCVOID lpLastFree(reinterpret_cast<LPCVOID>(-1L)),
				lpLastUsed(reinterpret_cast<LPCVOID>(-1L));
			DWORD dwLastSizeField((DWORD)-1L);
#endif
			for (LPCVOID ptr = MemInfo.AllocationBase; ptr <= Address
				&& ReadMemory(ptr, &dwSizeField, sizeof dwSizeField) >= sizeof dwSizeField
				&& (dwSizeField & F_SIZE) > 0; ptr = (LPBYTE)ptr + Size) {
				if ((dwSizeField & cThisUsedFlag) != 0) {
#ifdef _DEBUG
					lpLastUsed = ptr;
					dwLastSizeField = dwSizeField;
#endif
					ptr = (LPBYTE)ptr + sizeof dwSizeField;
					Size = (dwSizeField & F_SIZE) - 4;
#ifdef _DEBUG
					if (Size <= 0) _RPTF2(_CRT_WARN, "%s(...): heap block of zero size at %08X\n",
						__FUNCTION__, (char *)ptr - sizeof dwSizeField);
#endif
					if (/*Size <= 0 || */loopcount < 3 && (LPBYTE)ptr + Size >
						(LPBYTE)MemInfo.BaseAddress + MemInfo.RegionSize) break; // security check
					VCLheap.insert(memblock_t(ptr, Size));
					if (Address == ptr || !bExactMatch && Address > ptr
						&& (LPBYTE)Address < (LPBYTE)ptr + Size) return memblock_t(ptr, Size);
				} else { // free block
#ifdef _DEBUG
					lpLastFree = ptr;
#endif
					if (ReadMemory(ptr, &free_space_descriptor, sizeof free_space_descriptor)
						< sizeof free_space_descriptor
						|| free_space_descriptor.size <= 0
						|| free_space_descriptor.prev != 0 && !IsAddressEnabled(free_space_descriptor.prev)
						|| free_space_descriptor.next != 0 && !IsAddressEnabled(free_space_descriptor.next))
						break;
					Size = free_space_descriptor.size;
				}
				++loopcount;
			} // the loop
#ifdef _DEBUG
			if (loopcount > 4) {
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "%s(%08X, %u, ...): lookup failed\n",
					__FUNCTION__, Address, bExactMatch);
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "  loop_counter=%u allocbase=%08X regionbase=%08X regionsize=%08IX\n",
					loopcount, MemInfo.AllocationBase, MemInfo.BaseAddress, MemInfo.RegionSize);
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "  current loop at %08X blockdescriptor=%08IX\n",
					ptr, dwSizeField);
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "  last loop at %08X blockdescriptor=%08IX\n",
					lpLastUsed, dwLastSizeField);
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "  last free space descriptor at %08X: prev=%08X next=%08X size=%08IX\n",
					lpLastFree, free_space_descriptor.prev, free_space_descriptor.next, free_space_descriptor.size);
			}
#endif // _DEBUG
		} // memory accessible
	} catch (const exception &e) {
		if (prefs.verbosity >= 2) cmsg << prefix << "warning: " << e.what() <<
			" in " << __FUNCTION__ << '(' << asptr(Address) << ", ...)" << endl;
		_RPTF3(_CRT_ERROR, "%s(%08X, ...): %s in main block\n",
			__FUNCTION__, Address, e.what());
	}
	return memblock_t();
}

CDebugger::memblock_t CDumper::FindBCCBlock(LPCVOID Address, bool bExactMatch) const {
/*----------------------------------------------------------------------
 * Knuth's "boundary tag" algorithm is used to manage the heap.
 * Each block in the heap has a tag word before it, which
 * contains the size of the block and two bits:
 *  SIZE f1 f2
 *  block ...
 *  SIZE f1 f2
 *  block ...
 * The size is stored as a long word, and does not include the 4 bytes of
 * overhead that the boundary tag consumes.  Blocks are allocated
 * on LONG word boundaries, so the size is always even.  When the
 * block is allocated, bit 0 (F_FREE) of the size is set to 1.  When a block
 * is freed, it is merged with adjacent free blocks, and bit 0 of the
 * size is set to 0. Bit 1 (F_PFREE) signals that the previous block is free.
 *
 * When a block is on the free list, the first two LONG words of the block
 * contain double links. In addition, there is a tag at the end of the block,
 * which stores the size + 4. These links are not used when the block is
 * allocated, but space needs to be reserved for them.  Thus, the minimum
 * block size (not counting the tag) is 12 bytes.
 *
 * There are separate free lists for blocks smaller than _smalloc_threshold.
 * Each of these lists link free blocks of the same size. There is one list
 * for free blocks > _smalloc_threshold with a roving pointer.
 *
 * When an allocation request comes in for a block >= _smalloc_threshold,
 * the usual 'nextfit' algorithm is used with the rover. Note that the search
 * will only browse the free blocks that are >=_smalloc_threshold.
 *
 * When an allocation request is made for a block <=smalloc_threshold,
 * first we check if we have a free block of that size. Note that this is
 * very fast, since it involves only one indexing. If there is a free
 * block of the requested size, it simply needs to be unlinked from the
 * free list. If there is no such size free block, we will take the rover
 * (>=_smalloc_threshold). If there are no blocks > _smalloc_threshold,
 * we will scan forward in the 'small' list until we find any free
 * blocks.
 *
 * See <heap.h> for the definition and description of the macros
 * and structures used to access heap blocks.
 */

//
// Misc defines
//

#define PAGESIZE        0x1000          // system page size
#define ALIGNMENT       4               // block size alignment
#define MAXSYSBLOCKS    32              // max number of system blocks that can be merged

//
// Useful macros
//

#define ALIGNUPBY(x,a)  (((x)+( (a)-1) )   & (~((a)-1L)))
#define ALIGNDNBY(x,a)  ( (x)              & (~((a)-1L)))

#ifndef MAX
#define MAX(a,b)        ( ((a)>(b)) ? (a) : (b) )
#endif

#ifndef MIN
#define MIN(a,b)        ( ((a)<(b)) ? (a) : (b) )
#endif

//
// Block header
//

#define F_FREE  1                       // block is free
#define F_PFREE 2                       // previous block is free
#define F_BITS  3                       // mask for flags in the blocksize
#define F_SIZE  0xFFFFFFFC              // mask for size in the blocksize

typedef __declspec(align(4)) struct BLOCKHDR {
	size_t  blockSize;   // bit 0 = this block is free. bit 1= prev is free
	// for free blocks:
	struct BLOCKHDR * nextFree;
	struct BLOCKHDR * prevFree;
} BLOCKHDR;

// free blocks also have a terminating 'size_t' of their size+4.

#define MINFREEH      sizeof(BLOCKHDR) + sizeof(size_t)
#define MINFREE       sizeof(BLOCKHDR)
#define MINSIZE       sizeof(BLOCKHDR)
#define PTR2HDR(p)    ((BLOCKHDR*) ((char*) (p) - sizeof(size_t)))
#define HDR2PTR(b)    ((void *) ((char*) &(b)->blockSize + sizeof(size_t)))
#define SIZE(b)       (((b)->blockSize)&F_SIZE)
#define ISFREE(b)     (((b)->blockSize)&F_FREE)
#define ISPFREE(b)    (((b)->blockSize)&F_PFREE)
#define PFREE(b)      ((BLOCKHDR*) ((char *) (b) - *((size_t*) (b) - 1)))
#define NEXT(b)       ((BLOCKHDR*) ((char *) HDR2PTR(b) + SIZE(b)))
#define SETFSIZE(b,s) *((size_t*)((char *)(b) + s)) = s+sizeof(size_t)

//
// Helper macros for the big allocation optimization
//

#define XTRA_SIZE            (sizeof (size_t))
#define BLOCK_SIZE(a)        ((((size_t *)(a))[-1])&F_SIZE)  // block size
#define SET_BLOCK_SIZE(a, n) (((size_t *)(a))[-1] = (n))
#define IS_BIG_SIZE(a)       ((a) >= (PAGESIZE) * 256)       // >= 1meg blocks
#define IS_BIG_BLOCK(a)      (IS_BIG_SIZE (BLOCK_SIZE(a)))

//
// The heap header
//

typedef __declspec(align(4)) struct HEAP {
	size_t  cSize;                  // committed size, 'brklevel'
	size_t  rSize;                  // reserved size
	int     numSysBlocks;           // number of system blocks this heap consists of
	char *  sysBlocks[MAXSYSBLOCKS];// address of system blocks
	struct HEAP     * nextHeap;     // next non-contigous heap
	struct HEAP     * prevHeap;     // previous non-contigous heap
} HEAP;

typedef __declspec(align(4)) struct DLINK {
	BLOCKHDR * nextFree;
	BLOCKHDR * prevFree;
} DLINK;

#define LASTBLOCK(h)       ((BLOCKHDR*) ((char *) (h) + (h)->cSize -sizeof(size_t)))
#define FIRSTBLOCK(h)      ((BLOCKHDR*) ((char *) (h) + sizeof(HEAP)))
#define ADDFREEAFTER(b,f)  b->nextFree = (f)->nextFree;b->prevFree=(f);\
                           b->nextFree->prevFree=b;(f)->nextFree=b;
#define REMOVEFREE(b)      b->nextFree->prevFree = b->prevFree; \
                           b->prevFree->nextFree = b->nextFree;
#define HDR4SIZE(x)        ((BLOCKHDR*) ((char *) _linktable + (x)*(sizeof(DLINK)/ALIGNMENT)-(sizeof(size_t)+sizeof(DLINK))))
#define PTR2ADDR(ptr)      ((LPVOID)((char *)MemInfo.AllocationBase + ((char *)(ptr) - (char *)heap)))
#define ADDR2PTR(addr)     ((LPVOID)((char *)page.get() + ((char *)(addr) - (char *)MemInfo.AllocationBase)))

	if (default_compiler() == COMP_BC) try {
		const customheapmgr::const_iterator i(BCCheap.find(Address, bExactMatch));
		if (i != BCCheap.end()) return *i;
		MEMORY_BASIC_INFORMATION MemInfo;
		if (VirtualQuery(Address, MemInfo) < sizeof MemInfo
			|| MemInfo.State != MEM_COMMIT || MemInfo.Type != MEM_PRIVATE
			|| VirtualQuery(MemInfo.AllocationBase, MemInfo) < sizeof MemInfo
			|| MemInfo.RegionSize < sizeof HEAP + sizeof DWORD/*get_ptr_size()???*/)
			throw logic_error("VirtualQuery(...) failed or examined block othrewise invalid");
		_ASSERTE(MemInfo.AllocationBase == MemInfo.BaseAddress);
		boost::shared_localptr<void, NONZEROLPTR> page(MemInfo.RegionSize);
		if (!page) {
			_RPTF3(_CRT_ERROR, "%s(%08X, ...): LocalAlloc(0x%IX) failed\n",
				__FUNCTION__, Address, MemInfo.RegionSize);
			throw bad_alloc();
		}
		if (ReadMemory(MemInfo.BaseAddress, page.get(), MemInfo.RegionSize) < MemInfo.RegionSize)
			throw fmt_exception("%s(%08X, ..., 0x%IX) failed", "CDebugger::ReadMemory",
				MemInfo.BaseAddress, MemInfo.RegionSize);
		HEAP *heap((HEAP *)MemInfo.BaseAddress); // lets start at page start
		do { // iterate all heaps
			BLOCKHDR *blockhdr(FIRSTBLOCK(heap = (HEAP *)ADDR2PTR(heap)));
			if (SIZE(blockhdr) > 0) continue; // bcc heap first block not of zero size
			uint loopcount(0);
#ifdef _DEBUG
			BLOCKHDR *prevblockhdr(0);
#endif
			while (PTR2ADDR(blockhdr) <= Address && blockhdr <= LASTBLOCK(heap)) {
				if (ISFREE(blockhdr) && SIZE(blockhdr) < MINFREE) {
					_RPTF4(_CRT_WARN, "%s(%08X, ...): too small heap block at %08X (%08X)\n",
						__FUNCTION__, Address, PTR2ADDR(blockhdr),
						SIZE(blockhdr));
					break; // try next heap in chain
				}
				OutputDebugString("%s%s(...) heap scanner: %u. blockhdr=%08X blockSize=0x%IX\n",
					prefix, __FUNCTION__, loopcount, PTR2ADDR(blockhdr),
					blockhdr->blockSize);
				if (SIZE(blockhdr) > 0) {
					if (!ISFREE(blockhdr))
						BCCheap.insert(memblock_t(PTR2ADDR(HDR2PTR(blockhdr)), SIZE(blockhdr)));
					if (Address == PTR2ADDR(HDR2PTR(blockhdr)) || !bExactMatch && Address > PTR2ADDR(HDR2PTR(blockhdr))
						&& (LPBYTE)Address < (LPBYTE)PTR2ADDR(HDR2PTR(blockhdr)) + SIZE(blockhdr))
						if (!ISFREE(blockhdr))
							return memblock_t(PTR2ADDR(HDR2PTR(blockhdr)), SIZE(blockhdr));
#ifdef _DEBUG
						else
							_RPTF4(_CRT_WARN, "%s(%08X, ...): matched free block (%08X/0x%IX)\n",
								__FUNCTION__, Address, PTR2ADDR(HDR2PTR(blockhdr)), SIZE(blockhdr));
#endif
				} // SIZE > 0
#ifdef _DEBUG
				prevblockhdr = blockhdr;
#endif
				blockhdr = NEXT(blockhdr);
				++loopcount;
			} // walk the heap
#ifdef _DEBUG
			if (loopcount > 4) {
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "%s(%08X, %u, ...): lookup failed\n",
					__FUNCTION__, Address, bExactMatch);
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "  loop_counter=%u allocbase=%08X regionbase=%08X regionsize=%08IX heap=%08X\n",
					loopcount, MemInfo.AllocationBase, MemInfo.BaseAddress, MemInfo.RegionSize, PTR2ADDR(heap));
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "  current loop at %08X blockhdr=%08IX %08X %08X\n",
					PTR2ADDR(blockhdr), blockhdr->blockSize, blockhdr->nextFree, blockhdr->prevFree);
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "  last loop at %08X prevblockhdr=%08IX %08X %08X\n",
					prevblockhdr != 0 ? PTR2ADDR(prevblockhdr) : 0, prevblockhdr != 0 ? prevblockhdr->blockSize : 0, prevblockhdr != 0 ? prevblockhdr->nextFree : 0, prevblockhdr != 0 ? prevblockhdr->prevFree : 0);
			}
#endif // _DEBUG
		} while ((heap = heap->nextHeap) != 0 // try next heap in chain
			&& (LPVOID)heap >= MemInfo.BaseAddress // stay within page
			&& (LPBYTE)heap < (LPBYTE)MemInfo.BaseAddress + MemInfo.RegionSize);
	} catch (const exception &e) {
		if (prefs.verbosity >= 1 && typeid(e) == typeid(se_exception))
			cmsg << prefix << "warning: exception in " << __FUNCTION__ <<
				'(' << asptr(Address) << ", ...): " << e.what() << endl;
		_RPTF4(_CRT_WARN, "%s(%08X, ...): exception in main block: %s (%s)\n",
			__FUNCTION__, Address, e.what(), typeid(e).name());
	}
	return memblock_t();
}

CDebugger::memblock_t CDumper::FindGNUCBlock(LPCVOID Address, bool bExactMatch) const {
	if (default_compiler() == COMP_GNU) try {
		const customheapmgr::const_iterator i(GNUheap.find(Address, bExactMatch));
		if (i != GNUheap.end()) return *i;
		MEMORY_BASIC_INFORMATION MemInfo;
		if (VirtualQuery(Address, MemInfo) > 0 && MemInfo.State == MEM_COMMIT
			&& MemInfo.Type == MEM_PRIVATE && VirtualQuery(MemInfo.AllocationBase,
			MemInfo) > 0) {
			_ASSERTE(MemInfo.AllocationBase == MemInfo.BaseAddress);
			uint loopcount = 0;
			__declspec(align(4)) struct tagBlockHeader{
				uint32 dwUnknown;
				size_t Size;                     // size + flags
				inline size_t size() { return Size & ~3L; }
				inline size_t getDataSize() { return size() - sizeof tagBlockHeader; }
				inline bool isBlock() { return (Size & 1) != 0; }
			} BlockHdr;
#ifdef _DEBUG
			tagBlockHeader LastBlockHdr = { (uint32)-1L, (size_t)-1L };
			LPCVOID lpLastUsed(reinterpret_cast<LPCVOID>(-1L));
#endif
			for (LPCVOID ptr = MemInfo.AllocationBase;
				(LPBYTE)ptr <= (LPBYTE)MemInfo.BaseAddress + MemInfo.RegionSize
				&& ReadMemory(ptr, &BlockHdr, sizeof BlockHdr) >= sizeof BlockHdr;
				ptr = (LPBYTE)ptr + BlockHdr.size()) {
				if (!BlockHdr.isBlock()) {
					_RPTF4(_CRT_WARN, "%s(...): not a heap block at %08X blockheader={ %08I32X, %08IX }\n",
						__FUNCTION__, ptr, BlockHdr.dwUnknown, BlockHdr.Size);
					break;
				}
				if (BlockHdr.size() < sizeof tagBlockHeader) {
					_RPT3(_CRT_WARN, "%s(...): too small heap block at %08X (0x%IX)\n",
						__FUNCTION__, ptr, BlockHdr.size());
					break;
				}
				OutputDebugString("%s%s(...) heap scanner: %u. ptr=%08X blockheader={ %08I32X, %08IX }\n",
					prefix, __FUNCTION__, loopcount, ptr, BlockHdr.dwUnknown,
					BlockHdr.Size);
				LPCVOID data((LPBYTE)ptr + sizeof tagBlockHeader);
				GNUheap.insert(memblock_t(data, BlockHdr.getDataSize()));
				if (Address == data || !bExactMatch && Address > data
					&& (LPBYTE)Address < (LPBYTE)ptr + BlockHdr.size())
					return memblock_t(data, BlockHdr.getDataSize());
#ifdef _DEBUG
				lpLastUsed = ptr;
				LastBlockHdr = BlockHdr;
#endif
				++loopcount;
			} // the loop
#ifdef _DEBUG
			if (loopcount > 4) {
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "%s(%08X, %u, ...): lookup failed\n",
					__FUNCTION__, Address, bExactMatch);
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "  loop_counter=%u allocbase=%08X regionbase=%08X regionsize=0x%IX\n",
					loopcount, MemInfo.AllocationBase, MemInfo.BaseAddress, MemInfo.RegionSize);
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "  current loop at %08X blockheader={ %08I32X, %08IX }\n",
					ptr, BlockHdr.dwUnknown, BlockHdr.Size);
				_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "  last loop at %08X blockheader={ %08I32X, %08IX }\n",
					lpLastUsed, LastBlockHdr.dwUnknown, LastBlockHdr.Size);
			}
#endif // _DEBUG
		} // memory accessible
	} catch (const exception &e) {
		if (prefs.verbosity >= 2) cmsg << prefix << "warning: " << e.what() <<
			" in " << __FUNCTION__ << '(' << asptr(Address) << ", ...)" << endl;
		_RPTF3(_CRT_ERROR, "%s(%08X, ...): %s in main block\n",
			__FUNCTION__, Address, e.what());
	}
	return memblock_t();
}

// MS VC32 smallblock heap
CDebugger::memblock_t CDumper::FindVcSbhBlock(LPCVOID Address, bool bExactMatch) const {
	if (default_compiler() == COMP_MS) try {
		const customheapmgr::const_iterator i(VCSBheap.find(Address, bExactMatch));
		if (i != VCSBheap.end()) return *i;
		MEMORY_BASIC_INFORMATION MemInfo;
		if (VirtualQuery(Address, MemInfo) > 0 && MemInfo.State == MEM_COMMIT
			&& MemInfo.Type == MEM_PRIVATE && VirtualQuery(MemInfo.AllocationBase,
			MemInfo) > 0) {
			_ASSERTE(MemInfo.AllocationBase == MemInfo.BaseAddress);
			// TODO: parse structure
			// uint loopcount = 0;
		} // memory accessible
	} catch (const exception &e) {
		if (prefs.verbosity >= 2) cmsg << prefix << "warning: " << e.what() <<
			" in " << __FUNCTION__ << '(' << asptr(Address) << ", ...)" << endl;
		_RPTF3(_CRT_ERROR, "%s(%08X, ...): %s in main block\n",
			__FUNCTION__, Address, e.what());
	}
	return memblock_t();
}

CDebugger::memblock_t CDumper::FindVirtAllocBlock(LPCVOID Address, bool exact) const {
	MEMORY_BASIC_INFORMATION MemInfo;
	return prefs.dyndataxplorer_enablevalloc && VirtualQuery(Address, MemInfo) > 0
		&& MemInfo.State == MEM_COMMIT && MemInfo.Type == MEM_PRIVATE
		&& VirtualQuery(MemInfo.AllocationBase, MemInfo) > 0
		&& (prefs.dyndataxplorer_minvallocblk == 0
		|| MemInfo.RegionSize >= prefs.dyndataxplorer_minvallocblk)
		&& (Address == MemInfo.BaseAddress || !exact && Address > MemInfo.BaseAddress
		&& (LPBYTE)Address < (LPBYTE)MemInfo.BaseAddress + MemInfo.RegionSize) ?
		memblock_t(MemInfo.BaseAddress, (SIZE_T)MemInfo.RegionSize) : memblock_t();
}

CDebugger::memblock_t CDumper::FindStkVar(LPCVOID Address, DWORD caller_stack,
	asize_t caller_arglist, struc_t *caller_frame, const member_t *&member,
	DWORD caller_bp, bool bExactMatch) const {
	member = 0;
	LPCVOID baseaddr;
	if (Address >= reinterpret_cast<LPCVOID>(caller_stack + get_ptr_size())
		&& (LPBYTE)Address < reinterpret_cast<LPBYTE>(caller_stack +
			get_ptr_size() + caller_arglist)) {
		// this is a callee param
		OutputDebugString("%s%s(%08X, %08lX, 0x%IX, ...): address fits this arglist\n",
			prefix, __FUNCTION__, Address, caller_stack, caller_arglist);
		_ASSERTE(caller_frame != 0 && caller_frame->id != BADADDR);
		asize_t framesize(get_struc_size(caller_frame));
		for (ea_t stroff = framesize - caller_arglist; stroff <= framesize;
			stroff = get_struc_next_offset(caller_frame, stroff))
			if (stroff >= framesize || get_member(caller_frame, stroff) != 0) {
				if (member != 0) {
					baseaddr = reinterpret_cast<LPCVOID>(caller_stack + get_ptr_size() +
						member->get_soff() - (framesize - caller_arglist));
#ifdef _DEBUG
					char memname[MAXSPECSIZE];
					get_member_name(member->id, CPY(memname));
					OutputDebugString("%s%s(...): trying member %08X, 0x%IX (%s)\n",
						prefix, __FUNCTION__, baseaddr, stroff - member->get_soff(), memname);
#endif
					if (Address == baseaddr || !bExactMatch
						&& Address > baseaddr
						&& (LPBYTE)Address < reinterpret_cast<LPBYTE>(caller_stack +
						get_ptr_size() + stroff - (framesize - caller_arglist))) {
						// match
#ifdef _DEBUG
						OutputDebugString("%sexact match: %08X/0x%IX (%s)\n", prefix,
							baseaddr, stroff - member->get_soff(), memname);
#endif
						return memblock_t(baseaddr, stroff - member->get_soff());
					}
				}
				member = get_member(caller_frame, stroff);
			}
		_RPTF1(_CRT_ASSERT, "%s(...): param not found despite in this frame\n", __FUNCTION__);
	} // callee param
	DWORD ESP;
	member = 0;
	if (Address >= lpStackTop || (LPBYTE)Address < reinterpret_cast<LPBYTE>(ESP =
		caller_stack + get_ptr_size() + caller_arglist)) return memblock_t(); // not a stack address
	OutputDebugString("%s%s(%08X, %08lX, 0x%IX, ..., %08lX, %u, ...) ESP=%08lX\n",
		prefix, __FUNCTION__, Address, caller_stack, caller_arglist,
		caller_bp, bExactMatch, ESP);
	DWORD call_ea;
	if (ReadMemory(reinterpret_cast<LPCVOID>(caller_stack), &call_ea, sizeof call_ea) >= sizeof call_ea) {
		if (::isLoaded(call_ea)) {
			if (decode_prev_insn(call_ea) != BADADDR) {
				call_ea = cmd.ea;
				_ASSERTE(is_call_insn(cmd.itype));
			} else {
				_RPTF2(_CRT_ASSERT, "%s(...): failed to decode previous insn for %08IX\n",
					__FUNCTION__, call_ea);
				call_ea = prev_head(call_ea, inf.minEA);
				_ASSERTE(call_ea != BADADDR);
			}
			func_t *const func = get_func(call_ea);
			if (func  != 0 && (caller_frame = get_frame(func)) != 0) {
				if (caller_bp != 0 && (func->flags & FUNC_FRAME) != 0) {
					_ASSERTE(func->frregs >= get_ptr_size());
#ifdef _DEBUG
					if (func->frregs > get_ptr_size())
						_RPTF3(_CRT_WARN, "%s(...): %08IX saves many regs (0x%hX)\n",
							__FUNCTION__, func->startEA, func->frregs);
#endif
					ESP = caller_bp - (func->frsize + (func->frregs - get_frame_retsize(func))); // assume ebp was saved first
				}/* else
					ESP = caller_stack + get_frame_retsize(func) - get_spd(func, call_ea) -
						(func->frsize + func->frregs); // bad bad*/
				OutputDebugString("%sfunction frame present for %08IX: 0x%IX, bottom at %08lX\n",
					prefix, func->startEA, func->frsize, ESP);
				if (Address < reinterpret_cast<LPCVOID>(ESP + func->frsize)) { // stkvar of this func
					OutputDebugString("%saddress fits this frame\n", prefix);
					if (Address < reinterpret_cast<LPCVOID>(ESP)) { // unknown - saved register or SEH frame
						_RPTF3(_CRT_WARN, "%s(...): address under base of %08IX's locals, using default (base=%08lX)\n",
							__FUNCTION__, func->startEA, ESP);
						member = 0;
						return memblock_t(Address, get_ptr_size());
					}
// 					const asize_t stroff((LPBYTE)Address - (LPBYTE)ESP);
// 					member = get_best_fit_member(caller_frame, stroff);
// 					if (member != 0 && (stroff == member->get_soff()
// 						|| !bExactMatch && stroff < member->get_soff() + get_member_size(member))) {
// 						_ASSERTE(stroff >= member->get_soff());
// 					}
					for (ea_t stroff = get_struc_first_offset(caller_frame);
						stroff != BADADDR/*<= func->frsize*/;
						stroff = get_struc_next_offset(caller_frame, stroff))
						if (stroff >= func->frsize || get_member(caller_frame, stroff) != 0) {
							if (member != 0) {
								baseaddr = reinterpret_cast<LPCVOID>(ESP + member->get_soff());
#ifdef _DEBUG
								char memname[MAXSPECSIZE];
								get_member_name(member->id, CPY(memname));
								OutputDebugString("%strying member %08X, 0x%IX (%s)\n", prefix,
									baseaddr, stroff - member->get_soff(), memname);
#endif // _DEBUG
								if (Address == baseaddr || !bExactMatch && Address > baseaddr
									&& (LPBYTE)Address < reinterpret_cast<LPBYTE>(ESP + stroff)) {
									// match
#ifdef _DEBUG
									OutputDebugString("%sexact match: %08X/0x%IX (%s)\n", prefix,
										baseaddr, stroff - member->get_soff(), memname);
#endif
									return memblock_t(baseaddr, stroff - member->get_soff());
								}
							} // member != 0
							member = get_member(caller_frame, stroff);
						}
					_RPTF1(_CRT_ASSERT, "%s(...): stack variable not found despite in this frame\n",
						__FUNCTION__);
				} else { // trying higher
					const asize_t stackbase(func->frsize + func->frregs),
						argsize(get_struc_size(caller_frame) - get_frame_retsize(func) - stackbase);
					_ASSERTE((signed)argsize >= 0);
					if (caller_bp != 0 && (func->flags & FUNC_FRAME) != 0
						&& ReadMemory(reinterpret_cast<LPCVOID>(caller_bp), &caller_bp, sizeof caller_bp)
						< sizeof caller_bp) caller_bp = 0; // bp chain discontinued (invalidate)
					OutputDebugString("%s(...): trying caller frame: ESP=%08lX arglist=0x%IX parentEBP=%08lX",
						__FUNCTION__, ESP + stackbase, argsize, caller_bp);
					return FindStkVar(Address, ESP + stackbase, argsize, caller_frame,
						member, caller_bp, bExactMatch);
				}
			} // func frame exist
		} // caller present in idabase
#ifdef _DEBUG
		else {
			const modules_t::const_iterator module(modules.find((LPCVOID)call_ea, FALSE));
			_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
				"%s(...): caller outside of disassemblee (%s:%08lX)\n",
				__FUNCTION__, module != modules.end() && module->hasName() ?
				module->getBaseName() : "<unknown>", call_ea);
		}
#endif // _DEBUG
	} // readprocessmemory ok
#ifdef _DEBUG
	else
		_RPT4(_CRT_WARN/*_CRT_ERROR*/, "%s(...): %s(%08lX, ..., 0x%IX) failed\n",
			__FUNCTION__, "CDebugger::ReadMemory", caller_stack, sizeof call_ea);
#endif
	memblock_t result(Address);
	// heuristic string detection
	try {
		uint8 buf[4];
		if (ReadMemory(Address, buf, sizeof buf) >= sizeof buf
			&& (isEnabled(*reinterpret_cast<ea_t *>(buf))
			|| IsAddressEnabled(*reinterpret_cast<LPCVOID *>(buf))))
			// pointer possible, dont bother with strings
			result.Size = get_ptr_size();
		else {
			result.Size = 0;
			// try as lstring
			if (ReadMemory((LPBYTE)Address - 8, buf, sizeof buf) >= sizeof buf
				&& (*(LPDWORD)buf == -1 || *(LPDWORD)buf == 1 || *(LPDWORD)buf == 2)
				&& ReadMemory((LPBYTE)Address - 4, &result.Size, sizeof result.Size) >= sizeof result.Size
				&& result.Size > 0) {
				boost::scoped_array<uint8> _buf(new uint8[result.Size + 1]);
				if (!_buf) {
					_RPT2(_CRT_ERROR, "%s(...): failed to allocate new block of size 0x%IX\n",
						__FUNCTION__, result.Size + 1);
					throw bad_alloc();
				}
				if (ReadMemory(Address, _buf.get(), result.Size + 1) >= result.Size + 1) {
					for (uint iter = 0; iter < result.Size; ++iter)
						if (_isascii(_buf[iter]) == 0) break;
					if (iter < result.Size || _buf[result.Size] != 0) result.Size = 0;
				} else
					result.Size = 0;
				result.BaseAddress = (LPBYTE)Address - 8;
				if (result.Size > 0) result.Size += 9;
			}
			// try as cstring
			if (result.Size <= 0)
				while (ReadMemory(Address, buf, sizeof buf) >= sizeof buf) {
					for (uint iter = 0; iter < 4; ++iter)
						if (_isascii(buf[iter]) != 0) ++result.Size; else break;
					if (iter < 4) {
						if (buf[iter] == 0 && result.Size >= 4)
							++result.Size;
						else
							result.Size = get_ptr_size();
						break;
					}
					Address = (LPBYTE)Address + get_ptr_size();
				}
			if (result.Size <= 0) throw exit_scope(); // no string recognized, happy with default
		} // not a offset
	} catch (const exception &e) {
		result.Size = get_ptr_size();
#ifdef _DEBUG
		if (typeid(e) != typeid(exit_scope))
			_RPT2(_CRT_ERROR, "%s(...): %s during string detection\n", __FUNCTION__, e.what());
#endif
	}
	_RPT4(_CRT_WARN, "%s(...): address of %08X guessed as stack var though not found in stack frames (size=0x%IX callerstack=%08lX)\n",
		__FUNCTION__, Address, result.Size, caller_stack);
	member = 0;
	return result;
}

} // namespace CSC

// align all data refs to item's tail bytes to the head+offset
static uint align_refs_to_head(ea_t ea) {
	uint res(0);
	const area_t item(get_item_head(ea), get_item_end(ea));
	xrefblk_t xref;
	for (ea = nextaddr(item.startEA); ea < item.endEA; ea = nextaddr(ea))
	redo:
		for (bool ok = xref.first_to(ea, XREF_DATA); ok; ok = xref.next_to()) {
			const flags_t flags = get_flags_novalue(xref.from);
			refinfo_t ri;
			if (isCode(flags) && ua_ana0(xref.from) > 0) {
				for (int n = 0; n < UA_MAXOP; ++n) switch (cmd.Operands[n].type) {
					case o_imm:
						if (isOff(flags, n) && calc_reference_target(cmd, n) == ea) {
							if (!get_refinfo(xref.from, n, &ri))
#if IDP_INTERFACE_VERSION < 76
								ri.type = get_default_reftype(xref.from);
							ri.target_present = 1;
#else // IDP_INTERFACE_VERSION >= 76
								ri.flags = get_default_reftype(xref.from);
#endif // IDP_INTERFACE_VERSION
							ri.target = item.startEA/*BADADDR*/;
							ri.base = 0;
							ri.tdelta = ea - item.startEA;
							if (set_refinfo_ex(xref.from, n, &ri) != 0) {
								++res;
								analyze_area(xref.from, get_item_end(xref.from));
								goto redo;
							}
						}
						break;
					case o_mem:
					case o_displ:
					case o_near: // ???
					case o_far: // ???
						if (cmd.Operands[n].addr == ea) {
							del_dref(xref.from, ea);
							add_dref(xref.from, item.startEA, (dref_t)(xref.type | XREF_USER));
							++res;
							goto redo;
						}
						break;
				}
			} else if (isData(flags) && isOff0(flags)
				&& calc_reference_target(xref.from) == ea) {
				if (!get_refinfo(xref.from, 0, &ri))
#if IDP_INTERFACE_VERSION < 76
					ri.type = get_default_reftype(xref.from);
				ri.target_present = 1;
#else // IDP_INTERFACE_VERSION >= 76
					ri.flags = get_default_reftype(xref.from);
#endif // IDP_INTERFACE_VERSION
				ri.target = item.startEA/*BADADDR*/;
				ri.base = 0;
				ri.tdelta = ea - item.startEA;
				if (set_refinfo_ex(xref.from, 0, &ri) != 0) {
					++res;
					analyze_area(xref.from, get_item_end(xref.from));
					goto redo;
				}
			}
		}
	return res;
}

#include "xrefmgr.hpp" // X-Ref manager

static int idaapi init(void) {
	if (ph.id != PLFM_386) {
		cmsg << "csc plugin is enabled but not tested on this " << "processor" << ": results not guaranteed" << endl;
		//return PLUGIN_SKIP;
	} else if (inf.filetype != f_PE) {
		cmsg << "csc plugin is enabled but not tested on this " << "format" << ": results not guaranteed" << endl;
		//return PLUGIN_SKIP;
	}
	return PLUGIN_OK;
}

static void idaapi run(int arg) {
	BPX;
	try {
		switch (arg) {
			case 0: { // Code snippet creator (main) - host stack!
				if (!CSC::Execute()) return;
				/*
				// nenํ funk่nํ pro่ ?
				HANDLE hThread(CreateThread(NULL, 0x400000, CSC::ThreadProc, NULL, 0, NULL));
				DWORD ExitCode;
				if (hThread == NULL) return;
				if (WaitForSingleObject(hThread, INFINITE) != WAIT_OBJECT_0
					|| !GetExitCodeThread(hThread, &ExitCode)) {
					CloseHandle(hThread);
					return;
				}
				CloseHandle(hThread);
				if (ExitCode != 0) return;
				*/
				break;
			}
			case 1: // external source indirect calls importer
				if (!RTR::Execute()) return;
				break;
			case 2: // Libnames matching
				if (!LNM::Execute()) return;
				break;
			case 3: { // manage xrefs
				const ea_t jump(CXRefManager().Lister(true));
				if (jump != BADADDR)
					if (isEnabled(jump)) jumpto(jump); else MessageBeep(MB_ICONWARNING);
				break;
			}
			case 4: { // align all refs to item tail bytes to head
				const uint tot(align_refs_to_head(get_screen_ea()));
				if (tot <= 0) return;
				cmsg << dec << tot << " references re-based to item head" << endl;
				break;
			}
			case 99: { // revirgin all initialized areas
				uint total(0);
				nodeidx_t ndx;
				while ((ndx = net_patch.alt1st('p')) != BADNODE)
					total += CSC::CDumper::RestorePatchedBytes(ndx);
				if (total <= 0) return;
				cmsg << CSC::prefix << dec << total <<
					" bytes reverted to original state" << endl;
				break;
			}
			case 0xFFFF: // forced unload
			case -1:
#if IDP_INTERFACE_VERSION < 76
				if ((CSC::report > 0 || rtrlist > 0 || LNM::list > 0
#ifdef _DEBUG
					|| CSC::data_list > 0
#endif
#if IDA_SDK_VERSION >= 510
					//|| CSC::graph.IsOpen()
#endif
					) && MessageBox(get_ida_hwnd(),
					"there is one or more viewer tabs hooked to this plugin, "
					"unload anyway? (the viewers will be detached from data store)",
					"csc forced unload", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) return;
#endif
				PLUGIN.flags |= PLUGIN_UNL;
				break;
			default:
				MessageBeep(MB_ICONEXCLAMATION);
				warning("called with incorrect plugin parameter, these are supported:\n\n"
					"    0: code snippet creator (default)\n"
					"    1: runtime addressing resolving (by external debugger): deprecated\n"
					"    2: flirt libnames matching\n"
					"    3: manage xrefs for address at cursor\n"
					"   99: restore all patched areas\n"
					"65535: forced plugin unload (close all views opened by plugin first!)");
				return;
		} // switch
	} catch (const exception &e) {
		CSC::wait_box.close_all();
		cmsg << e.what() << ", aborting (lame stupid servil ;p)" << endl;
		MessageBeep(MB_ICONERROR);
		warning("%s, lame stoopid servil ;p", e.what());
		return;
	} catch (...) {
		CSC::wait_box.close_all();
		cmsg << "unknown exception" << ", aborting (lame stupid servil ;p)" << endl;
		MessageBeep(MB_ICONERROR);
		warning("%s, lame stoopid servil ;p", "unknown exception");
		return;
	}
	MessageBeep(MB_OK);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		hInstance = hinstDLL;
		DisableThreadLibraryCalls(static_cast<HMODULE>(hinstDLL));
#if IDP_INTERFACE_VERSION < 76
		if (ph.version != IDP_INTERFACE_VERSION) {
			char ModuleFileName[QMAXPATH];
			GetModuleFileName(hinstDLL, CPY(ModuleFileName));
			string tmp;
			tmp.assign(ModuleFileName).append(".old");
			MoveFile(ModuleFileName, tmp.c_str());
			_sprintf(tmp, "Cannot load plugin: this plugin is for IDP version %u (%i reported by kernel)\n\n"
				"Update or delete the plugin file", IDP_INTERFACE_VERSION, ph.version);
			MessageBox(get_ida_hwnd(), tmp.c_str(),
				PLUGINNAME " v" PLUGINVERSIONTEXT, MB_ICONEXCLAMATION | MB_OK);
			return FALSE;
		}
#endif // IDP_INTERFACE_VERSION < 76
		ConstructHomeFileName(inipath, 0, "ini");
#ifndef _DEBUG
		DWORD flOldProtect;
		VirtualProtect((PBYTE)hInstance + 0x199000, 0x19E00, PAGE_READONLY, &flOldProtect);
#endif
		se_exception::_set_se_translator();
		_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
		_CrtSetDbgFlag(/*_CRTDBG_CHECK_EVERY_1024_DF | */_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
		// Initialize Common Controls
		INITCOMMONCONTROLSEX iccex;
		iccex.dwSize = sizeof iccex;
		iccex.dwICC = ICC_TAB_CLASSES | ICC_TREEVIEW_CLASSES |
			ICC_UPDOWN_CLASS | ICC_DATE_CLASSES;
		InitCommonControlsEx(&iccex);
	} // DLL_PROCESS_ATTACH
	return TRUE;
}

// ================================ENTRY POINT================================
plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION, PLUGIN_MOD | PLUGIN_DRAW
#ifdef _DEBUG
	| PLUGIN_UNL
#endif
	, init, wait_threads, run,
	PLUGINNAME " v" PLUGINVERSIONTEXT, 0, "Code snippet creator\x085", "Alt-F10"
};
// ================================ENTRY POINT================================
