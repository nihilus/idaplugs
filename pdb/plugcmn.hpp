
/*****************************************************************************
 *                                                                           *
 *  plugcmn.hpp: ida plugins shared code                                     *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef _PLUGCMN_HPP_
#define _PLUGCMN_HPP_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "undbgnew.h"
#include <string>
#include <hash_set>
#define NOMINMAX 1
#include <wtypes.h>
#define BYTES_SOURCE                1
#include "idasdk.hpp"
#include "plugsys.hpp"

// don't get stuck in the queues of unfinished autoanalysis... - experimental
#if IDP_INTERFACE_VERSION < 76
// on old IDA this worked properly even if autoanalysis wasn't finished
#define ANALYZE_AREA analyze_area
#else // IDP_INTERFACE_VERSION >= 76
#define ANALYZE_AREA if (autoIsOk()) analyze_area
#endif // IDP_INTERFACE_VERSION

NALT_UCHAR(get_supressed_library_flag, set_supressed_library_flag, \
	clr_supressed_library_flag, AFL_LIB)

#if IDP_INTERFACE_VERSION < 66
#define dr_USR dr_I
#else
#define dr_USR static_cast<dref_t>(dr_I | XREF_USER)
#endif

#define AUTOFREQ                        0x1000
#define SIG_FLAGS                    (7 << 29)
#define SIG_COUNT                 (~SIG_FLAGS)

#if IDA_SDK_VERSION < 510
#define R_none static_cast<RegNo>(-1)
#endif
#define R_any static_cast<RegNo>(-2)

/*
// ix86 registers representation for pc.w32
enum x86_reg_t {
	// generic
	reg_none = -1, reg_any = -2,
	// 16-bit
	ax = 0x00, cx, dx, bx, sp, bp, si, di,
	// 32-bit (mapped to 16-bit)
	eax = ax, ecx = cx, edx = dx, ebx = bx, esp = sp, ebp = bp, esi = si, edi = di,
	// 64-bit integer registers (AMD64/X8664)
	r8 = 0x08, r9, r10, r11, r12, r13, r14, r15,
	// 8-bit
	al = 0x10, cl, dl, bl, ah, ch, dh, bh,
	// low byte forms of some standard registers (AMD64/X8664)
	spl = 0x18, bpl, sil, dil,
	// instruction pointer
	ip = 0x1C, eip = ip,
	// segment registers should start at ph.regFirstSreg
	es = 0x1D, cs, ds, ss, fs, gs,
	// flag bits?
	cf = 35, zf, sf, of,
};
*/

// nextthat/prevthat helper functions
#define FF_BOUNDARY (FF_REF | FF_ANYNAME)

#if IDP_INTERFACE_VERSION < 76

inline bool idaapi hasNamCmt(flags_t flags) throw()
	{ return (flags & MS_COMM & FF_ANYNAME) != 0 && isNotTail(flags); }
inline bool idaapi hasCmt(flags_t flags) throw()
	{ return has_cmt(flags) && isNotTail(flags); }
inline bool idaapi hasAnyName(flags_t flags) throw()
	{ return has_any_name(flags) && isNotTail(flags); }
inline bool idaapi isBoundary(flags_t flags) throw()
	{ return (flags & MS_COMM & FF_BOUNDARY) != 0 || isAlign(flags) || isFunc(flags); }
inline bool idaapi isVariableEnd(flags_t flags) throw()
	{ return hasRef(flags) || /*has_user_name(flags) || */isFunc(flags); }
inline bool idaapi isVirgin(flags_t flags) throw()
	{ return isUnknown(flags) && !hasRef(flags) && !has_any_name(flags) && !isVar(flags); }
inline bool idaapi isNumH0(flags_t flags) throw()
	{ return get_optype_flags0(flags) == FF_0NUMH; }
inline bool idaapi isNumH1(flags_t flags) throw()
	{ return get_optype_flags1(flags) == FF_1NUMH; }
inline bool idaapi isReal(flags_t flags) throw() {
	return isData(flags) && ((flags &= DT_TYPE) == FF_FLOAT || flags == FF_DOUBLE
		|| flags == FF_PACKREAL);
}

#define TESTFUNC(x) x

// only tests if type is accessed by tail byte in common sense
// to test if a certain tail byte can be accessed, use can_ref_ea(ea)
// returns if specified address can be referred regarding the byte tailness
// and data type
bool idaapi canRefByTail(flags_t flags) throw();

#else // IDP_INTERFACE_VERSION >= 76

inline ea_t nextthat(ea_t ea, ea_t maxea, testf_t *testf)
	{ return nextthat(ea, maxea, testf, 0); }
inline ea_t prevthat(ea_t ea, ea_t minea, testf_t *testf)
	{ return prevthat(ea, minea, testf, 0); }
inline bool idaapi f_has_cmt(flags_t F, void *) { return has_cmt(F); }
inline bool idaapi f_isVar(flags_t F, void *) { return isVar(F); }
inline bool idaapi f_has_any_name(flags_t F, void *) { return has_any_name(F); }
inline bool idaapi f_isFunc(flags_t F, void *) { return isFunc(F); }
inline bool idaapi hasNamCmt(flags_t flags, void *ud = 0)
	{ return (flags & MS_COMM & FF_ANYNAME) != 0 && f_isNotTail(flags, ud); }
inline bool idaapi hasCmt(flags_t flags, void *ud = 0)
	{ return f_has_cmt(flags, ud) && f_isNotTail(flags, ud); }
inline bool idaapi hasAnyName(flags_t flags, void *ud = 0)
	{ return f_has_any_name(flags, ud) && f_isNotTail(flags, ud); }
inline bool idaapi isBoundary(flags_t flags, void *ud = 0) {
	return (flags & MS_COMM & FF_BOUNDARY) != 0 || f_isAlign(flags, ud)
		|| f_isFunc(flags, ud);
}
inline bool idaapi isVariableEnd(flags_t flags, void *ud = 0) {
	return f_hasRef(flags, ud)/* || f_has_user_name(flags, ud)*/
		|| f_isFunc(flags, ud);
}
inline bool idaapi isVirgin(flags_t flags, void *ud = 0) {
	return f_isUnknown(flags, ud) && !f_hasRef(flags, ud)
		&& !f_has_any_name(flags, ud) && !f_isVar(flags, ud);
}
inline bool idaapi isNumH0(flags_t flags, void *ud = 0)
	{ return get_optype_flags0(flags) == FF_0NUMH; }
inline bool idaapi isNumH1(flags_t flags, void *ud = 0)
	{ return get_optype_flags1(flags) == FF_1NUMH; }
inline bool idaapi isReal(flags_t flags, void *ud = 0) {
	return f_isData(flags, ud) && ((flags &= DT_TYPE) == FF_FLOAT
		|| flags == FF_DOUBLE || flags == FF_PACKREAL);
}

#define TESTFUNC(x) f_##x

// only tests if type is accessed by tail byte in common sense
// to test if a certain tail byte can be accessed, use can_ref_ea(ea)
// returns if specified address can be referred regarding the byte tailness
// and data type
bool idaapi canRefByTail(flags_t flags, void *ud = 0);

#endif // IDP_INTERFACE_VERSION

extern const HMODULE hIdaWll;
extern const double kernel_version;

char *get_disasm(ea_t ea, char *buf, size_t bufsize, bool stripcmt = true);
inline bool Wait() {
	while (!autoIsOk()) if (!autoWait()) return false;
	return true;
}
inline HWND get_ida_hwnd() { return static_cast<HWND>(callui(ui_get_hwnd).vptr); }
bool can_ref_ea(ea_t ea);
/*
inline bool isReal(ea_t const ea) {
	return isReal(get_flags_novalue(get_item_head(ea)));
}
*/
char *make_ident_name(char *name, size_t namesize, char substchar = 0/*SubstChar*/);
char *make_unique_name(char *name, size_t namesize);
asize_t get_data_type_size(ea_t ea, flags_t flags);
asize_t get_data_type_size(ea_t ea);
asize_t get_data_type_size(const member_t *member);
asize_t get_array_size(ea_t ea);
asize_t get_array_size(const member_t *member);
inline bool isArray(ea_t ea) { return get_array_size(ea) > 1; }
inline bool isArray(const member_t *member) { return get_array_size(member) > 1; }
inline void set_array_parameters(ea_t ea, long lineitems = 0,
	long alignment = -1, long flags = AP_ALLOWDUPS) {
	const array_parameters_t foo = { flags, lineitems, alignment };
	set_array_parameters(ea, &foo);
}
asize_t doString(ea_t const start, long strtype = -1,
	bool allowzeroterminated = false, int (__cdecl &isstring)(int) = _isascii);
// ea_t get_string_start(ea_t ea);
long get_string_type(ea_t ea);
bool does_prefix_lstring(ea_t ea); // does prefix existing LString?
bool can_prefix_lstring(ea_t ea, int (__cdecl &isstring)(int) = _isascii); // can be prefix for existing or future LString?
bool iscalled(ea_t ea);
bool is_in_rsrc(ea_t ea);
bool points_to_struct_member(ea_t ea);
ssize_t get_member_name(const struc_t *struc, ea_t offset, char *buf, size_t bufsize);
ssize_t get_member_name(const member_t *mptr, ea_t memoff, char *buf, size_t bufsize);
int cat_stkvar_struct_fields(ea_t ea, int opndx, char *buf, size_t bufsize);
inline bool points_to_meaningful_head(ea_t ea)
	{ return can_ref_ea(ea) && !is_in_rsrc(ea); }
bool points_to_defitem(ea_t ea);
// weak tolerates basic numeric formats (hex, dec, octa, bin)
// not weak obeys void type strictly
bool is_dummy_data(ea_t ea, bool weak = false);
bool is_dummy_data_range(ea_t ea, asize_t size, bool weak = false);
inline bool is_dummy_data_range(const area_t &area, bool weak = false)
	{ return is_dummy_data_range(area.startEA, area.size(), weak); }
bool is_fake_code(ea_t ea, ea_t *startEA = 0, ea_t *endEA = 0);
inline bool is_fake_code(ea_t ea, area_t &area)
	{ return is_fake_code(ea, &area.startEA, &area.endEA); }
//bool can_be_off32(ea_t const ea);
// from existing data, not valid on undefined address (use can_be_off... instead)
ea_t calc_reference_target(ea_t ea);
// from operand
ea_t calc_reference_target(ea_t ea, const op_t &op);
// from operand index
inline ea_t calc_reference_target(const insn_t &cmd, int n = 0) {
	_ASSERTE(isLoaded(cmd.ea) && isCode(get_flags_novalue(cmd.ea)));
	return calc_reference_target(cmd.ea, cmd.Operands[n]);
}
inline ea_t calc_reference_target(ea_t ea, int n) {
	_ASSERTE(isLoaded(ea) && isCode(get_flags_novalue(ea)));
	return ua_ana0(ea) > 0 ? calc_reference_target(cmd, n) : BADADDR;
}
// from static struct member, ea points at struct start address
ea_t calc_reference_target(ea_t ea, const member_t *member);
bool does_ref_extern(ea_t ea);
inline bool is_extern(ea_t ea)
	{ return isEnabled(ea) && segtype(ea) == SEG_XTRN; }
int kill_tail_chunks(func_t *func);
inline int kill_tail_chunks(ea_t ea)
	{ return kill_tail_chunks(get_func(ea)); }
bool is_pure_import_func(const func_t *func);
inline bool is_pure_import_func(ea_t ea)
	{ return is_pure_import_func(get_func(ea)); }
inline bool is_true_libfunc(const func_t *func) {
	return func != 0 && (func->flags & FUNC_LIB) != 0
		&& has_name(get_flags_novalue(func->startEA)) && !is_extern(func->startEA);
}
inline bool is_true_libfunc(ea_t ea)
	{ return is_true_libfunc(get_func(ea)); }
bool is_libfuncname(ea_t ea);
bool is_libvarname(ea_t ea);
inline bool is_libname(ea_t ea)
	{ return is_libfuncname(ea) || is_libvarname(ea); }
ulong get_signature_state(const char *signame);
bool can_be_mfc_app();
bool can_be_cbuilder_app();
asize_t get_near_ptr_size() throw();
asize_t get_far_ptr_size() throw();
asize_t get_ptr_size(flags_t type = 0) throw(); // type must be FF_DATA or FF_CODE if pointer size different for code and data
bool has_rsrc();
bool change_root(const char *newroot);
bool has_meaningful_name(ea_t ea);
inline ea_t get_member_off(const struc_t *struc, const char *membername) {
	const member_t *member = get_member_by_name(struc, membername);
	return member != 0 ? member->get_soff() : BADADDR;
}
void add_local_struct_member(struc_t *frame, ea_t offset, const char *varname,
	const struc_t *var, asize_t varsize = 0);
std::hash_set<RegNo, std::hash<int> > get_segs_used(ea_t ea);
inline const char *reg2str(ushort reg) {
	_ASSERTE(reg < ph.regsNum);
	return reg < ph.regsNum ? static_cast<const char *>(ph.regNames[reg]) : 0;
}
bool do_data_ex(ea_t ea, flags_t flags, const typeinfo_t *pti, asize_t size = 0);
inline bool do_data_ex(ea_t ea, flags_t flags, asize_t size = 0)
	{ return do_data_ex(ea, flags, static_cast<const typeinfo_t *>(0), size); }
bool isOffset(ea_t ea);
bool make_off32(ea_t ea, bool force = false);
bool doOff32(ea_t ea, ulong size);
inline asize_t get_align_size(ea_t ea, size_t alignment) {
	_ASSERTE(alignment > 0);
	alignment = rdownpow2(alignment);
	return (alignment - (ea & alignment - 1)) % alignment;
}
asize_t doAlign(ea_t ea, size_t alignment, bool force = false);
inline asize_t doAlignWord(ea_t ea, bool force = false)
	{ return doAlign(ea, 2, force); }
inline asize_t doAlignDword(ea_t ea, bool force = false)
	{ return doAlign(ea, 4, force); }
inline asize_t doAlignQword(ea_t ea, bool force = false)
	{ return doAlign(ea, 8, force); }
inline asize_t doAlign2(ea_t ea, uint8 alignment, bool force = false)
	{ return doAlign(ea, 1 << alignment, force); }
class CBatchResults;
uint find_doubtful_offsets_range(const area_t &area,
	size_t offset_alignment, CBatchResults *list = 0, bool quiet = false,
	const char *prefix = 0) throw(int);
uint find_offsets_range(const area_t &area, size_t offboundary,
	uint8 offtohead, CBatchResults *list, uint8 verbosity = 2,
	const char *prefix = 0);
uint nameanonoffsets_internal(ea_t to, uint8 verbosity = 2,
	const char *prefix = 0, CBatchResults *list = 0);
class CWarningList;
ea_t format_data_area(ea_t &ea, bool createoffsets, size_t offboundary,
	uint8 offtohead, bool makealigns, uint &totalarraya,
	uint &totaloffsets, CWarningList *list = 0,
	CBatchResults *batchresults = 0, uint8 verbosity = 2,
	const char *prefix = 0);
inline bool is_enabled(ea_t ea)
	{ return isEnabled(ea) && ea >= inf.minEA && ea < inf.maxEA; }
inline char *get_func_name(const func_t *pfn, char *buf, size_t bufsize) {
	_ASSERTE(buf != 0 && bufsize > 0);
	if (buf == 0 || bufsize <= 0) return 0;
	*buf = 0;
	_ASSERTE(pfn != 0);
#ifdef _DEBUG
	if (pfn == 0) return 0;
	char *s = get_func_name(pfn->startEA, buf, bufsize);
	_ASSERTE(s == buf);
	return s;
#else // !_DEBUG
	return pfn != 0 ? get_func_name(pfn->startEA, buf, bufsize) : 0;
#endif // _DEBUG
}
bool is_xrefd(ea_t ea);
uint xrefs_to(ea_t ea);
uint xrefs_from(ea_t ea);
uint crefs_to(ea_t ea);
uint crefs_from(ea_t ea);
uint drefs_to(ea_t ea);
uint drefs_from(ea_t ea);
std::string flags2str(flags_t flags);
bool append_unique_cmt(ea_t ea, const char *str, bool rptble = false);
void add_unique_long_cmt(ea_t ea, bool isprev, const char *format, ...);
#if IDP_INTERFACE_VERSION < 76
char *GET_CMT(ea_t ea, bool rptble = false);
ssize_t GET_CMT(ea_t ea, bool rptble, char *buf, size_t bufsize);
#else // IDP_INTERFACE_VERSION >= 76
ssize_t GET_CMT(ea_t ea, bool rptble = false, char *buf = 0, size_t bufsize = 0);
#endif // IDP_INTERFACE_VERSION
// char *GET_ANY_CMT(ea_t ea, color_t *cmttype);
int add_struc_member_ex(struc_t *sptr, const char *fieldname, ea_t offset,
	flags_t flag, const typeinfo_t *mt, asize_t nbytes, const char *cmt = 0,
	bool repeatable = false);
int add_struc_member_ex(struc_t *sptr, const char *fieldname, ea_t offset,
	flags_t flag, const typeinfo_t *mt, asize_t nbytes, long lineitems = 0,
	long alignment = -1, long flags = AP_ALLOWDUPS);
nodeidx_t sup1stfree(const netnode &node, char tag = stag);
nodeidx_t alt1stfree(const netnode &node, char tag = atag);

class layered_wait_box {
private:
	uint __M_layer_counter;
	// non-copyable
	layered_wait_box(const layered_wait_box &);
	layered_wait_box &operator =(const layered_wait_box &);

public:
	inline layered_wait_box() throw() : __M_layer_counter(0) { }
	layered_wait_box(const char *format, ...);
	inline ~layered_wait_box() { if (__M_layer_counter > 0) close_all(); }

	// add new layer
	uint open(const char *format, ...);
	// stay on same level (replace top-most if such)
	uint change(const char *format, ...);
	// remove topmost (if such), returns true on success
	void close() {
		if (__M_layer_counter <= 0) return;
		hide_wait_box();
		--__M_layer_counter;
	}
	// remove all layers above nlayer
	inline void close(uint nlayer) { while (__M_layer_counter > nlayer) close(); }
	// destroy all layers
	inline void close_all() { close(0); }
	inline uint get_layer() const throw() { return __M_layer_counter; }
	inline operator uint() const throw() { return __M_layer_counter; }
	inline bool operator !() const throw() { return __M_layer_counter <= 0; }
}; // layered_wait_box

class simple_hooker {
protected:
	uint count;
	hook_type_t hook_type;
	hook_cb_t *cb;
	void *user_data;

public:
	simple_hooker(hook_type_t hook_type, hook_cb_t *cb, void *user_data = NULL) throw() :
		count(0), hook_type(hook_type), cb(cb), user_data(user_data) { }
	simple_hooker(hook_cb_t *cb, void *user_data = NULL) throw() :
		count(0), hook_type(HT_IDP), cb(cb), user_data(user_data) { }
	inline ~simple_hooker() { if (is_active()) deactivate(); }

	inline bool is_active() const throw() { return count > 0; }
	inline bool is_hooked() const throw() { return is_active(); }
	inline operator bool() const throw() { return is_active(); }
	//inline bool operator !() const throw() { return !operator bool(); }

	bool activate(bool on = true);
	bool activate(void *ud);
	inline bool deactivate() { return activate(false); }

protected:
	bool hook(hook_type_t, hook_cb_t *, void *);
	bool unhook(hook_type_t, hook_cb_t *, void *);
}; // class simple_hooker

class multi_hooker : public simple_hooker {
private:
	std::hash_set<void *> _M_uds;

public:
	multi_hooker(hook_type_t hook_type, hook_cb_t *cb, void *user_data = NULL) :
		simple_hooker(hook_type, cb, user_data) { }
	multi_hooker(hook_cb_t *cb, void *user_data = NULL) :
		simple_hooker(cb, user_data) { }
	~multi_hooker() { unhook_all(); }

	inline uint get_count() const throw() { return count; }
	inline operator uint() const throw() { return get_count(); }

	bool activate(bool on, void *ud);
	inline bool activate(bool on = true) { return activate(on, user_data); }
	inline bool activate(void *ud) { return activate(true, ud); }
	inline bool deactivate(void *ud) { return activate(false, ud); }
	inline bool deactivate() { return activate(false); }
	void deactivate_all();
	inline void unhook_all() { deactivate_all(); }
}; // multi_hooker

class variatic_hooker : public simple_hooker {
private:
	struct hook_descr_t {
		hook_type_t hook_type;
		hook_cb_t *cb;
		void *user_data;

		inline hook_descr_t(hook_type_t hook_type, hook_cb_t cb, void *ud) throw() :
			hook_type(hook_type), cb(cb), user_data(user_data) { }

		inline bool operator ==(const hook_descr_t &rhs) const throw() {
			return hook_type == rhs.hook_type && cb == rhs.cb && user_data == rhs.user_data;
		}
		struct hash {
			inline size_t operator ()(const hook_descr_t &__x) const throw()
				{ return (size_t)__x.cb; }
		};
	};
	std::hash_set<hook_descr_t, hook_descr_t::hash> _M_hooks;

public:
	variatic_hooker(hook_type_t hook_type, void *user_data = NULL) :
		simple_hooker(hook_type, NULL, user_data) { }
	variatic_hooker(void *user_data = NULL) :
		simple_hooker(HT_IDP, NULL, user_data) { }
	~variatic_hooker() { unhook_all(); }

	inline uint get_count() const throw() { return count; }
	inline operator uint() const throw() { return get_count(); }

	bool activate(hook_type_t hook_type, hook_cb_t cb, bool on, void *ud);
	inline bool activate(hook_type_t hook_type, hook_cb_t cb, bool on = true)
		{ return activate(hook_type, cb, on, user_data); }
	inline bool activate(hook_cb_t cb, bool on, void *ud)
		{ return activate(hook_type, cb, on, ud); }
	inline bool activate(hook_cb_t cb, bool on = true)
		{ return activate(hook_type, cb, on, user_data); }
	inline bool deactivate(hook_type_t hook_type, hook_cb_t cb, void *ud)
		{ return activate(hook_type, cb, false, ud); }
	inline bool deactivate(hook_type_t hook_type, hook_cb_t cb)
		{ return activate(hook_type, cb, false); }
	inline bool deactivate(hook_cb_t cb, void *ud)
		{ return activate(cb, false, ud); }
	inline bool deactivate(hook_cb_t cb)
		{ return activate(cb, false); }
	void deactivate_all();
	inline void unhook_all() { deactivate_all(); }
}; // variatic_hooker

// plain enum (mutually exclusive values)
struct enum_entry_t {
	const char *name;
	uval_t value;
};

// plain bitfield
struct bitfield_entry_t {
	const char *name;
	uval_t value;
	bmask_t bmask;
};

// versions with value comments
struct enum_entry_ex_t {
	const char *name;
	uval_t value;
	const char *comment;
};

struct bitfield_entry_ex_t {
	const char *name;
	uval_t value;
	bmask_t bmask;
	const char *comment;
};

// return number of consta added
uint add_consts(enum_t id, const enum_entry_t *consts, size_t count);
uint add_consts(enum_t id, const bitfield_entry_t *consts, size_t count);
uint add_consts(enum_t id, const enum_entry_ex_t *consts, size_t count,
	bool repeatable = true);
uint add_consts(enum_t id, const bitfield_entry_ex_t *consts,
	size_t count, bool repeatable = true);
// return enum id of created (or existing if deleteexisting false) enum
enum_t create_enum(const char *name, flags_t flag,
	const enum_entry_t *consts, size_t count,
	bool deleteexisting = false, const char *cmt = 0, bool repeatable = false);
enum_t create_enum(const char *name, flags_t flag,
	const bitfield_entry_t *consts, size_t count,
	bool deleteexisting = false, const char *cmt = 0, bool repeatable = false);
enum_t create_enum(const char *name, flags_t flag,
	const enum_entry_ex_t *consts, size_t count, bool rptble = true,
	bool deleteexisting = false, const char *cmt = 0, bool repeatable = false);
enum_t create_enum(const char *name, flags_t flag,
	const bitfield_entry_ex_t *consts, size_t count, bool rptble = true,
	bool deleteexisting = false, const char *cmt = 0, bool repeatable = false);

// area_t facets for common functions
inline bool read_selection(area_t &area) { return read_selection(&area.startEA, &area.endEA); }
inline int analyze_area(const area_t &area) { return analyze_area(area.startEA, area.endEA); }
inline void noUsed(const area_t &area) { noUsed(area.startEA, area.endEA); }
inline void autoCancel(const area_t &area) { autoCancel(area.startEA, area.endEA); }
inline error_t FlagsEnable(const area_t &area) { return FlagsEnable(area.startEA, area.endEA); }
inline error_t FlagsDisable(const area_t &area) { return FlagsDisable(area.startEA, area.endEA); }
inline bool add_func(const area_t &area) { return add_func(area.startEA, area.endEA); }
inline int del_struc_members(struc_t *sptr, const area_t &area) { return del_struc_members(sptr, area.startEA, area.endEA); }
inline bool add_hidden_area(const area_t &area, const char *description, const char *header, const char *footer, bgcolor_t color) { return add_hidden_area(area.startEA, area.endEA, description, header, footer, color); }
inline ea_t find_binary(const area_t &area, const char *ubinstr, int radix, int sflag) { return find_binary(area.startEA, area.endEA, ubinstr, radix, sflag); }
inline bool display_flow_graph(const char *title, func_t *pfn, const area_t &area, bool print_names) { return display_flow_graph(title, pfn, area.startEA, area.endEA, print_names); }
inline bool display_complex_call_chart(const char *wait, const char *title, const area_t &area, int flags, long recursion_depth=-1) { return display_complex_call_chart(wait, title, area.startEA, area.endEA, flags, recursion_depth); }
inline int gen_file(ofile_type_t otype, FILE *fp, const area_t &area, int flags) { return gen_file(otype, fp, area.startEA, area.endEA, flags); }
inline int file2base(linput_t *li, long pos, const area_t &area, int patchable) { return file2base(li, pos, area.startEA, area.endEA, patchable); }
inline int mem2base(const void *memptr, const area_t &area, long fpos) { return mem2base(memptr, area.startEA, area.endEA, fpos); }
inline int base2file(FILE *fp, long pos, const area_t &area) { return base2file(fp, pos, area.startEA, area.endEA); }
inline void set_sreg_at_next_code(const area_t &area, int reg, sel_t value) { set_sreg_at_next_code(area.startEA, area.endEA, reg, value); }
inline bool add_sourcefile(const area_t &area,const char *filename) { return add_sourcefile(area.startEA, area.endEA,filename); }
inline bool append_func_tail(func_t *pfn, const area_t &area) { return append_func_tail(pfn, area.startEA, area.endEA); }
inline int add_regvar(func_t *pfn, const area_t &area, const char *canon, const char *user, const char *cmt) { return add_regvar(pfn, area.startEA, area.endEA, canon, user, cmt); }
inline regvar_t *find_regvar(func_t *pfn, const area_t &area, const char *canon, const char *user) { return find_regvar(pfn, area.startEA, area.endEA, canon, user); }
inline int del_regvar(func_t *pfn, const area_t &area, const char *canon) { return del_regvar(pfn, area.startEA, area.endEA, canon); }
inline void auto_mark_range(const area_t &area,atype_t type) { auto_mark_range(area.startEA, area.endEA, type); }
inline void autoUnmark(const area_t &area,atype_t type) { autoUnmark(area.startEA, area.endEA, type); }
inline ea_t auto_get(const area_t &area, atype_t *type) { return auto_get(area.startEA, area.endEA, type); }

#endif // _PLUGCMN_HPP_
