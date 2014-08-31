
/*****************************************************************************
 *                                                                           *
 *  plugcmn.cpp: ida plugins shared code                                     *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#pragma warning(disable: 181)

#include "mscrtdbg.h"
#include <algorithm>
#include <boost/bind.hpp>
#include "plugcmn.hpp"
#include "plughlpr.hpp"
#include "pluginsn.hpp"
#include "areaex.hpp"

static HMODULE __get_hidawll() {
	HMODULE hIdaWll;
#ifdef __X64__ // 64-bit kernel
	if ((hIdaWll = GetModuleHandle("IDA64.WLL")) == NULL)
#endif
	hIdaWll = GetModuleHandle("IDA.WLL");
	_ASSERTE(hIdaWll != NULL);
	return hIdaWll;
}

const HMODULE hIdaWll(__get_hidawll());

static double GetMajorIdaVersion() {
	VS_FIXEDFILEINFO fixednfo;
	if (!GetFixedFileInfo(fixednfo)) return 0;
	char buf[16];
	return qsnprintf(CPY(buf), "%hu.%hu",
		HIWORD(fixednfo.dwFileVersionMS), LOWORD(fixednfo.dwFileVersionMS)) > 0 ?
		atof(buf) : 0;
}

static inline double __get_kernel_version() {
#if IDP_INTERFACE_VERSION >= 76
	const HMODULE hIdaWll = __get_hidawll();
	if (hIdaWll == NULL) return GetMajorIdaVersion();
	if (GetProcAddress(hIdaWll, "add_til2") == NULL) // kernel <5.1
		return GetProcAddress(hIdaWll, "grentry") != NULL ? 5.0 : 4.9;
#if IDA_SDK_VERSION >= 510
	char buf[16];
	if (::get_kernel_version(CPY(buf))) return atof(buf);
	_RPT4(_CRT_ASSERT, "%s(): %s(...) returned false though kernel 5.1 or above (%s is present): returning %f (assumption)\n",
		__FUNCTION__, "::get_kernel_version", "add_til2", 5.1);
#endif
	const double ret = GetMajorIdaVersion();
	return ret > 0 ? ret : 5.1;
#elif IDP_INTERFACE_VERSION >= 75
	return 4.8;
#elif IDP_INTERFACE_VERSION >= 70
	return 4.7;
#elif IDP_INTERFACE_VERSION >= 66
	return 4.6;
#elif IDP_INTERFACE_VERSION >= 63
	return 4.5;
#elif IDP_INTERFACE_VERSION >= 61
	return 4.3;
#else // too old
	return GetMajorIdaVersion();
#endif // IDP_INTERFACE_VERSION
}

const double kernel_version(__get_kernel_version());

char *get_disasm(ea_t ea, char *buf, size_t bufsize, bool stripcmt) {
	_ASSERTE(isEnabled(ea) && buf != 0 && bufsize > 0);
	if (buf != 0 && bufsize > 0) {
		uchar s_cmtflg(inf.s_cmtflg);
		inf.s_cmtflg |= SW_SHHID_ITEM | SW_SHHID_FUNC | SW_SHHID_SEGM;
		if (stripcmt) inf.s_cmtflg |= SW_NOCMT;
		if (isEnabled(ea) && generate_disasm_line(ea, buf, bufsize, 0)) {
			inf.s_cmtflg = s_cmtflg;
			char *cmt1, *cmt2, *cmt3;
			if (stripcmt && ((cmt1 = strstr(buf, SCOLOR_ON SCOLOR_REGCMT)) != 0
				|| (cmt2 = strstr(buf, SCOLOR_ON SCOLOR_RPTCMT)) != 0
				|| (cmt3 = strstr(buf, SCOLOR_ON SCOLOR_AUTOCMT)) != 0)) {
				if (cmt1 == 0 || cmt2 != 0 && cmt2 < cmt1) cmt1 = cmt2;
				if (cmt1 == 0 || cmt3 != 0 && cmt3 < cmt1) cmt1 = cmt3;
				_ASSERTE(cmt1 != 0);
				while (cmt1 > buf && (*(cmt1 - 1) == ' ' || *(cmt1 - 1) == '\t')
					&& (cmt1 < buf + 2 || *(uchar *)(cmt1 - 2) < COLOR_ON
					|| *(uchar *)(cmt1 - 2) > COLOR_INV)) --cmt1;
				*cmt1 = 0;
			}
			if (tag_remove(buf, buf, bufsize) > 0) return buf;
		} else
			inf.s_cmtflg = s_cmtflg;
		*buf = 0;
	}
	return 0;
}

bool idaapi canRefByTail(flags_t flags
#if IDP_INTERFACE_VERSION >= 76
	, void *ud
#endif
) {
	return (flags &= DT_TYPE) == FF_QWRD || flags == FF_OWRD || flags == FF_TBYT
		|| flags == FF_ASCI || flags == FF_STRU  || flags == FF_DOUBLE
		|| flags == FF_PACKREAL;
}

asize_t get_data_type_size(ea_t ea) {
	ea = get_item_head(ea);
	return get_data_type_size(ea, get_flags_novalue(ea));
}

static class API_TRAITS {
#if IDP_INTERFACE_VERSION < 76
#	define TRAITS_CALL static inline
#	define TRAITS_FUNC(x) ::x
#else // IDP_INTERFACE_VERSION >= 76
#	define TRAITS_CALL
#	define TRAITS_FUNC(x) p_##x
private:
	typedef asize_t (idaapi *get_data_type_size_t)(flags_t, const typeinfo_t *);
	get_data_type_size_t p_get_data_type_size;
	typedef bool (idaapi *add_stkvar_t)(const op_t &, sval_t);
	add_stkvar_t p_add_stkvar;
	typedef int (idaapi *add_til_t)(const char *);
	add_til_t p_add_til;
	typedef asize_t (idaapi *get_data_elsize_t)(ea_t, flags_t, const typeinfo_t *);
	get_data_elsize_t p_get_data_elsize;
	typedef bool (idaapi *add_stkvar3_t)(const op_t &, sval_t, int);
	add_stkvar3_t p_add_stkvar3;
	typedef int (idaapi *add_til2_t)(const char *, int);
	add_til2_t p_add_til2;
	typedef bool (idaapi *set_member_tinfo_t)(til_t *, struc_t *, member_t *,
		uval_t, const type_t *, const p_list *, int);
	set_member_tinfo_t p_set_member_tinfo;
	typedef bool (idaapi *set_member_ti_t)(struc_t *, member_t *, const type_t *, int);
	set_member_ti_t p_set_member_ti;
	typedef bool (idaapi *ua_outop_t)(ea_t, char *, size_t, int);
	ua_outop_t p_ua_outop;
	typedef bool (idaapi *ua_outop2_t)(ea_t, char *, size_t, int, int);
	ua_outop2_t p_ua_outop2;
#endif // IDP_INTERFACE_VERSION

public:
#if IDP_INTERFACE_VERSION >= 76
	API_TRAITS() : p_get_data_type_size(NULL), p_add_stkvar(NULL), p_add_til(NULL),
		p_get_data_elsize(NULL), p_add_stkvar3(NULL), p_add_til2(NULL),
		p_set_member_ti(NULL), p_set_member_tinfo(NULL), p_ua_outop(NULL),
		p_ua_outop2(NULL) {
		const HMODULE hIdaWll = __get_hidawll();
		if (hIdaWll == NULL) {
			error("%s(): hIdaWll == NULL!", __FUNCTION__);
			return;
		}
#	define GET_PTR(new, old) \
	if ((p_##new = (new##_t)GetProcAddress(hIdaWll, #new)) == NULL) { \
		p_##old = reinterpret_cast<old##_t>(GetProcAddress(hIdaWll, #old)); \
		_ASSERTE(p_##old != NULL); \
	}
		GET_PTR(get_data_elsize, get_data_type_size)
		GET_PTR(add_stkvar3, add_stkvar)
		GET_PTR(add_til2, add_til)
		GET_PTR(set_member_tinfo, set_member_ti)
		GET_PTR(ua_outop2, ua_outop)
#undef GET_PTR
	}
#endif // IDP_INTERFACE_VERSION >= 76

	TRAITS_CALL asize_t get_data_elsize(ea_t ea, flags_t flags, const typeinfo_t *pti = NULL) {
		typeinfo_t ti;
		return
#if IDP_INTERFACE_VERSION >= 76
			p_get_data_elsize != NULL ? p_get_data_elsize(ea, flags, pti) :
#endif
			TRAITS_FUNC(get_data_type_size)(flags, pti != NULL ? pti : get_typeinfo(ea, 0, flags, &ti));
	}
	TRAITS_CALL bool add_stkvar(const op_t &x, sval_t v, int flags = 0) {
		return
#if IDP_INTERFACE_VERSION >= 76
			p_add_stkvar3 != NULL ? p_add_stkvar3(x, v, flags) :
#endif
			TRAITS_FUNC(add_stkvar)(x, v);
	}
	TRAITS_CALL int add_til(const char *name, int flags = 0) {
		return
#if IDP_INTERFACE_VERSION >= 76
			p_add_til2 != NULL ? p_add_til2(name, flags) :
#endif
			TRAITS_FUNC(add_til)(name);
	}
	TRAITS_CALL bool set_member_tinfo(struc_t *sptr, member_t *mptr,
		const type_t *type, int flags = 0, til_t *til = NULL,
		uval_t memoff = 0, const p_list *fields = NULL) {
		return
#if IDP_INTERFACE_VERSION >= 76
			p_set_member_tinfo != NULL ? p_set_member_tinfo(til != NULL ? til : idati,
				sptr, mptr, memoff, type, fields, flags) :
#endif
			TRAITS_FUNC(set_member_ti)(sptr, mptr, type, flags);
	}
	TRAITS_CALL bool ua_outop(ea_t ea, char *buf, size_t bufsize, int n, int flags=0) {
		return
#if IDP_INTERFACE_VERSION >= 76
			p_ua_outop2 != NULL ? p_ua_outop2(ea, buf, bufsize, n, flags) :
#endif
			TRAITS_FUNC(ua_outop)(ea, buf, bufsize, n);
	}
#	undef TRAITS_FUNC
} API_traits;

asize_t get_data_type_size(ea_t ea, flags_t flags) {
	_ASSERTE(isEnabled(ea));
	if (!isEnabled(ea)) return 0;
	ea = get_item_head(ea);
	typeinfo_t ti, *const pti = get_typeinfo(ea, 0, flags, &ti);
#ifdef _DEBUG
	const asize_t result = API_traits.get_data_elsize(ea, flags, pti);
	if (isStruct(flags) && get_struc(ti.tid) != 0 && result != get_struc_size(ti.tid))
		_CrtDbgReport(_CRT_ASSERT, __FILE__, __LINE__, __FUNCTION__,
			"%s(%08IX, %08lX): result != get_struc_size(%08IX) (0x%IX!=0x%IX)\n",
			__FUNCTION__, ea, flags, ti.tid, result, get_struc_size(ti.tid));
	return result;
#else // !_DEBUG
	return API_traits.get_data_elsize(ea, flags, pti);
#endif // _DEBUG
}

asize_t get_data_type_size(const member_t *member) {
	_ASSERTE(member != 0);
	typeinfo_t ti;
	return member != 0 ? get_data_type_size(member->flag,
		retrieve_member_info(member, &ti)) : 0;
}

asize_t get_array_size(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	ea = get_item_head(ea);
	const flags_t flags(get_flags_novalue(ea));
	if (isStruct(flags)) {
		typeinfo_t ti;
		struc_t *struc;
		if (get_typeinfo(ea, 0, flags, &ti) != 0
			&& (struc = get_struc(ti.tid)) != 0
			|| (struc = get_struc(get_strid(ea))) != 0) {
			_ASSERTE(struc->is_varstr() || get_struc_size(struc) == get_data_type_size(ea));
			return struc->is_varstr() ? 1 : get_item_size(ea) / get_struc_size(struc);
		}
		_CrtDbgReport(_CRT_ERROR, __FILE__, __LINE__, __FUNCTION__,
			"%s(%08IX): couldnot get struct at %08IX: ti.tid=%08IX get_strid(%08IX)=%08IX\n",
			__FUNCTION__, ea, ea, ti.tid, ea, get_strid(ea));
	}
	return get_item_size(ea) / get_data_type_size(ea, flags);
}

asize_t get_array_size(const member_t *member) {
	_ASSERTE(member != 0);
	return member != 0 ? get_member_size(member) / get_data_type_size(member) : 0;
}

// returns true if address at ea can be directly accessed in common sense
bool can_ref_ea(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	flags_t flags;
	if (!isEnabled(ea) || isAlign(flags = get_flags_novalue(ea))) return false;
	if (isNotTail(flags)) return true;
	const ea_t item_head(get_item_head(ea));
	_ASSERTE(ea > item_head);
	flags = get_flags_novalue(item_head);
	_ASSERTE(isNotTail(flags));
	if (isCode(flags) || isByte(flags) || isWord(flags) || isDwrd(flags)
		|| isFloat(flags)) return false;
	if (isASCII(flags)) {
		const long strtype(get_str_type_code(get_string_type(item_head)));
		//_ASSERTE(strtype != -1);
		return strtype == ASCSTR_PASCAL && ea == item_head + 1
			|| (strtype == ASCSTR_LEN2 || strtype == ASCSTR_ULEN2) && ea == item_head + 2
			|| (strtype == ASCSTR_LEN4 || strtype == ASCSTR_ULEN4) && ea == item_head + 4;
	}
	const asize_t item_offset(ea - item_head);
	typeinfo_t ti;
	struc_t *struc;
	if (isStruct(flags)) return (get_typeinfo(item_head, 0, flags, &ti) != 0
		&& get_member(struc = get_struc(ti.tid), item_offset) != 0
		|| get_member(struc = get_struc(get_strid(item_head)), item_offset) != 0)
		&& (struc->is_varstr() || item_offset < get_struc_size(struc)); // points_to_struct_member(ea)
	if (item_offset >= get_data_type_size(item_head, flags)) return false; // array members cannot be accessed directly
	if ((isQwrd(flags) || isOwrd(flags) || isDouble(flags))
		&& (item_offset & 3) == 0 || isTbyt(flags) || isPackReal(flags))
		return true; // common on condition of fixed offset
#ifdef _DEBUG
	_RPTF4(_CRT_WARN, "%s(%08IX): unhandled type at %08IX: flags=%s\n",
		__FUNCTION__, ea, item_head, flags2str(flags).c_str());
#endif // _DEBUG
	return false;
}

bool points_to_struct_member(ea_t ea) {
	//_ASSERTE(isEnabled(ea));
	typeinfo_t ti;
	ea_t itemhead;
	flags_t flags;
	struc_t *struc;
	return isStruct(flags = get_flags_novalue(itemhead = get_item_head(ea)))
		&& (get_typeinfo(itemhead, 0, flags, &ti) != 0
		&& (struc = get_struc(ti.tid)) != 0 && get_member(struc, struc->is_varstr()
			? ea - itemhead : (ea - itemhead) % get_struc_size(struc)) != 0
		|| (struc = get_struc(get_strid(itemhead))) != 0
		&& get_member(struc, struc->is_varstr() ? ea - itemhead :
			(ea - itemhead) % get_struc_size(struc)) != 0);
}

bool points_to_defitem(ea_t ea) {
	return !isUnknown(get_flags_novalue(ea)) && can_ref_ea(ea) && !is_in_rsrc(ea);
}

bool does_ref_extern(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	char name[MAXNAMESIZE];
	return isCode(get_flags_novalue(ea)) && ua_ana0(ea) > 0
		&& InstrIsSet(cmd.itype, CF_JUMP) && cmd.Op1.type == o_mem
		&& (is_extern(calc_reference_target(cmd, 0)/*cmd.Op1.addr*/)
		|| get_true_name(ea, calc_reference_target(cmd, 0)/*cmd.Op1.addr*/, CPY(name)) != 0
		&& strncmp(name, FUNC_IMPORT_PREFIX, sizeof FUNC_IMPORT_PREFIX - 1) == 0);
}

/*
bool can_be_off32(ea_t const ea) {
	_ASSERTE(isEnabled(ea));
	ea_t tgt = get_long(ea);
	return isLoaded(tgt) || get_byte(tgt) != 0xFF;
}
*/

// get target from instruction operand
ea_t calc_reference_target(ea_t ea, const op_t &op) {
	flags_t const flags(getFlags(ea));
	_ASSERTE(hasValue(flags) && isCode(flags));
	if (!hasValue(flags) || !isCode(flags)) return BADADDR;
	adiff_t opval;
	switch (op.type) {
		case o_mem: // jmp off_4AEF50[eax*4]
		case o_displ: // mov dl, ds:byte_4FB2F0[esi]
			opval = static_cast<adiff_t>(op.addr);
			break;
		case o_imm: // push offset loc_4C9AE2
			opval = static_cast<adiff_t>(op.value);
			break;
		case o_far:
			opval = static_cast<adiff_t>(op.addr);
#ifdef _DEBUG
			if (isOff(flags, op.n)) _RPTF4(_CRT_WARN, "%s(%08IX, ...): operand %d target evaluated from ref info though not supported by kernel (op.type=%s)\n",
				__FUNCTION__, ea, op.n/*char*/, "o_far");
#endif // _DEBUG
			break;
		case o_near: // jmp short loc_4C9900
			opval = static_cast<adiff_t>(op.addr);
#ifdef _DEBUG
			if (isOff(flags, op.n)) _RPTF4(_CRT_WARN, "%s(%08IX, ...): operand %d target evaluated from ref info though not supported by kernel (op.type=%s)\n",
				__FUNCTION__, ea, op.n/*char*/, "o_near");
#endif // _DEBUG
			break;
		default:
			_RPTF4(_CRT_WARN, "%s(%08IX, ...): operand %d not of reference kind (op.type=%u)\n",
				__FUNCTION__, ea, op.n/*char*/, op.type/*uchar*/);
			return BADADDR;
	} // switch
	// notice: while calc_reference_target(...) is set to reflect user-defined
	// offsets, these are not reflected in operand value: this may give to
	// encounter discrepancy between generated disassembly targets and internal
	// offset (x-ref) targets for o_mem, o_near and o_far types
	refinfo_t ri;
	ea_t const target(isOff(flags, op.n) && get_refinfo(ea, op.n, &ri) != 0 ?
		calc_reference_target(ea, ri, opval) : static_cast<ea_t>(opval));
	return isEnabled(target) ? target : BADADDR;
}

// get target from data (offset, offset array, or these in struct member)
ea_t calc_reference_target(ea_t ea) {
	//_ASSERTE(isLoaded(ea));
	if (!isLoaded(ea)) return BADADDR;
	ea_t const head(get_item_head(ea));
	flags_t flags = get_flags_novalue/*getFlags*/(head);
	typeinfo_t ti, *pti(get_typeinfo(head, 0, flags, &ti));
	if (pti == 0) return BADADDR;
	if (isStruct(flags)) {
		struc_t *struc(get_struc(ti.tid));
		if (struc == 0) struc = get_struc(get_strid(head)); // alternate
		ea_t offset(ea - head);
		do {
			if (struc == 0) return BADADDR;
			if (!struc->is_varstr()) offset %= get_struc_size(struc);
			member_t *const member(get_best_fit_member(struc, offset));
			if (member == 0 || (pti = retrieve_member_info(member, &ti)) == 0)
				return BADADDR;
			flags = member->flag;
			struc = get_sptr(member);
			offset = member->get_soff();
		} while (isStruct(flags));
	}
	if (!isOff0(flags)) return BADADDR;
	const asize_t size = API_traits.get_data_elsize(ea, flags, pti);
	adiff_t opval;
	if (size <= 0 || size > sizeof(opval)
		|| !get_data_value(ea, (uval_t *)&opval, size)) return BADADDR;
	ea_t const target(calc_reference_target(ea, pti->ri, opval));
	return isEnabled(target) ? target : BADADDR;
}

ea_t calc_reference_target(ea_t ea, const member_t *member) {
	//_ASSERTE(isLoaded(ea));
	_ASSERTE(member != 0);
	if (/*!isStruct(get_flags_novalue(get_item_head(ea))) || */member == 0
		|| !isOff0(member->flag) || isArray(member)
		|| !isLoaded(ea += member->get_soff())) return BADADDR;
	typeinfo_t ti, *const pti(retrieve_member_info(member, &ti));
	if (pti == 0) return BADADDR;
	asize_t const size(get_member_size(member));
	_ASSERTE(size > 0 && size <= sizeof uval_t);
	if (size <= 0 || size > sizeof uval_t) return BADADDR;
	adiff_t opval(0);
	if (!get_data_value(ea, (uval_t *)&opval, size)) return BADADDR;
	ea_t const target(calc_reference_target(ea, pti->ri, opval));
	return isEnabled(target) ? target : BADADDR;
}

// return: string type or -1 if not string
long get_string_type(ea_t ea) {
	//_ASSERTE(isEnabled(ea));
	const flags_t flags(get_flags_novalue(ea = get_item_head(ea)));
	if (!isASCII(flags)) return -1; // not a string there
	typeinfo_t ti = { -1 };
	if (get_typeinfo(ea, 0, flags, &ti) != 0 && ti.strtype >= 0) return ti.strtype; // ok
	_RPT4(_CRT_WARN, "%s(%08IX): cannot get strtype by get_typeinfo despite string by flags (flags=0x%08lX ti.strtype=%li)\n",
		__FUNCTION__, ea, flags, ti.strtype);
#ifdef _DEBUG
	if (get_str_type(ea) == BADNODE) _RPT2(_CRT_WARN, "%s(%08IX): invalid altval(NALT_STRTYPE) despite string by flags\n",
		__FUNCTION__, ea);
#endif // _DEBUG
	return get_str_type(ea);
}

/*
// return: start address of string at ea or BADADDR if ea not pointing to string
ea_t get_string_start(ea_t ea) {
	ea = get_item_head(ea);
	if (isASCII(get_flags_novalue(ea)))
		return ea;
	else if (isASCII(get_flags_novalue(ea - 4)) && get_long(ea - 4) > 0
		&& (get_str_type_code(get_string_type(ea - 4)) == ASCSTR_LEN4
		|| get_str_type_code(get_string_type(ea - 4)) == ASCSTR_ULEN4))
		return ea - 4;
	else if (isASCII(get_flags_novalue(ea - 2)) && get_word(ea - 2) > 0
		&& (get_str_type_code(get_string_type(ea - 2)) == ASCSTR_LEN2
		|| get_str_type_code(get_string_type(ea - 2)) == ASCSTR_ULEN2))
		return ea - 2;
	else if (isASCII(get_flags_novalue(ea - 1)) && get_byte(ea - 1) > 0
		&& get_str_type_code(get_string_type(ea - 1)) == ASCSTR_PASCAL)
		return ea - 1;
	else if (does_prefix_lstring(ea))
		return ea + 4;
	else
		return BADADDR;
}
*/

static bool isStrucOffset(const struc_t *struc, ea_t stroff) {
	if (struc == 0) return false;
	const member_t *const member = get_best_fit_member(struc, stroff);
	return member != 0 && stroff < member->get_soff() + get_member_size(member)
		&& (isOff0(member->flag) ? (stroff - member->get_soff()) % get_data_type_size(member) == 0 :
		isStruct(member->flag) && isStrucOffset(get_sptr(member), stroff - member->get_soff()));
}

ssize_t get_member_name(const struc_t *struc, ea_t offset, char *buf, size_t bufsize) {
	if (buf != 0 && bufsize > 0) *buf = 0;
	if (struc == 0) return -1;
	const member_t *mptr = get_best_fit_member(struc, offset);
	return mptr != 0 ? get_member_name(mptr, offset - mptr->get_soff(),
		buf, bufsize) : -1;
}

ssize_t get_member_name(const member_t *mptr, ea_t offset, char *buf, size_t bufsize) {
	//if (buf == 0 || bufsize <= 0) return -1;
	if (buf != 0 && bufsize > 0) *buf = 0;
	if (mptr == 0) return -1;
	if (get_member_name(mptr->id, buf, bufsize) <= 0) return -1;
	if (isStruct(mptr->flag)) {
		qstrncat(buf, ".", bufsize);
		return get_member_name(get_sptr(mptr), offset, tail(buf),
			bufsize - strlen(buf)) >= 0 ? strlen(buf) : -1;
	}
	if (offset > 0) {
		qstrncat(buf, "+", bufsize);
		btoa(tail(buf), bufsize - strlen(buf), offset);
	}
	return strlen(buf);
}

int cat_stkvar_struct_fields(ea_t ea, int opndx, char *buf, size_t bufsize) {
	_ASSERTE(isEnabled(ea));
	if (!isEnabled(ea)) return -1;
	adiff_t disp;
	strpath_t strpath;
	if ((strpath.len = get_struct_operand(ea, opndx, strpath.ids, &disp,
		&strpath.delta) - 1) >= 0) {
		append_struct_fields(opndx, strpath.ids, strpath.len,
			byteflag(), tail(buf), buf + bufsize, &disp,
			strpath.delta/* + disp???*/, true);
#if IDP_INTERFACE_VERSION < 76
		append_disp(buf, buf + bufsize, disp);
#else // IDP_INTERFACE_VERSION >= 76
		print_disp(tail(buf), buf + bufsize, disp);
#endif
	}
	return strpath.len;
}

bool isOffset(ea_t ea) {
	typeinfo_t ti;
	struc_t *struc;
	if (!isEnabled(ea)) return false;
	ea_t const head = get_item_head(ea);
	const flags_t flags = get_flags_novalue(head);
	return isData(flags) && (isOff0(flags) ?
		(ea - head) % get_data_type_size(head, flags) == 0 :
		isStruct(flags) && ((get_typeinfo(head, 0, flags, &ti) != 0
			&& (struc = get_struc(ti.tid)) != 0
			|| (struc = get_struc(get_strid(head))) != 0)
			&& isStrucOffset(struc, ea - head)));
}

bool does_prefix_lstring(ea_t ea) {
	if (!isLoaded(ea)) return false;
	const comp_t ccid = default_compiler();
	if (ccid != COMP_BP && ccid != COMP_BC) return false;
	const uint32 prefix = get_long(ea);
	if (prefix != (uint32)-1/* && prefix != 1*/) return false;
	const size_t size = (size_t)get_long(ea + 4);
	if (/*size <= 0 || */get_byte(ea + 8 + size) != 0) return false;
	long strtype;
	asize_t sz;
	ea_t endEA;
	sint8 strtype_code;
	if (isASCII(get_flags_novalue(ea + 4))
		&& (strtype_code = get_str_type_code(get_string_type(ea + 4))) == ASCSTR_LEN4
		/* || strtype_code == ASCSTR_ULEN4*/) {
		//sz = get_item_size(ea + 4);
		//if (sz != size + 5 && sz != size + 4/*???*/) return false;
		return true;
	} else if (isASCII(get_flags_novalue(ea + 8))
		&& get_str_type_code(strtype = get_string_type(ea + 8)) == ASCSTR_TERMCHR) {
		//sz = get_item_size(ea + 8);
		//if (sz != size + 1 && sz != size/*???*/) return false;
		//char termchar = get_str_term1(strtype);
		//endEA = find_byte(ea + 8, sz, (uchar)termchar, true);
		//if (endEA != ea + 8 + size) return false;
		//if (termchar != 0) {
		//	termchar = get_str_term2(strtype);
		//	endEA = find_byte(ea + 8, sz, (uchar)termchar, true);
		//	if (endEA != ea + 8 + size + 1) return false;
		//}
		return true;
	}
	return false;
}

bool can_prefix_lstring(ea_t ea, int (__cdecl &isstring)(int)) {
	if (!isLoaded(ea)) return false;
	const comp_t ccid = default_compiler();
	if (ccid != COMP_BP && ccid != COMP_BC || get_long(ea) != ~0) return false;
	const size_t size = get_long(ea + 4);
	if (size <= 0 || get_byte(ea + 8 + size) != 0) return false;
	for (ea_t scan = ea + 8; scan < ea + 8 + size; ++scan)
		if (!isstring(get_byte(scan))) return false; // mistrail
	return true;
}

// strtype if not stated defaults to idabase current type
// isstring can be own or one of std. character classification routines
// defaults to any low ascii or special space character
// return: length of new or existing string or 0 for error
// content scan is not performed on existing strings
asize_t doString(ea_t start, long strtype,
	bool allowzeroterminated, int (__cdecl &isstring)(int)) {
	_ASSERTE(isEnabled(start));
	ea_t scan, foo;
	wchar_t c;
	flags_t flags;
	asize_t sz(0);
	if (get_str_type_code(strtype) < 0 || get_str_type_code(strtype) > ASCSTR_LAST)
		strtype = inf.strtype;
	switch (get_str_type_code(strtype)) {
		case ASCSTR_C:
			if (get_str_type_code(get_string_type(start)) == ASCSTR_C)
				return get_item_size(start) - 1;
			for (scan = start; (c = get_byte(scan)) != get_str_term1(strtype)
				|| get_str_term2(strtype) == 0
				|| get_byte(scan + 1) != get_str_term2(strtype); ++scan)
				if (!isEnabled(scan) || isLoaded(scan) && isstring(c) == 0) return 0;
			if (scan <= start) return 0;
			do_unknown_range(start, sz = scan + 1 - start, false);
			if (!make_ascii_string(start, sz, ASCSTR_C)) return 0;
			if (!hasRef(flags = get_flags_novalue(start)) && has_any_name(flags))
				del_global_name(start);
			return sz - 1;
		case ASCSTR_LEN2:
			if ((sz = get_word(start)) > 0
				&& get_str_type_code(get_string_type(start)) != ASCSTR_LEN2) {
				for (scan = start + 2; scan < start + 2 + sz; ++scan)
					if (!isEnabled(scan) || isLoaded(scan)
						&& isstring(get_byte(scan)) == 0) return 0;
				if (scan <= start + 2) return 0;
				foo = start + 2 + sz;
				allowzeroterminated = allowzeroterminated && get_byte(foo) == 0
					&& !isBoundary(get_flags_novalue(foo));
				do_unknown_range(start, 2 + sz + allowzeroterminated, false);
				if (!make_ascii_string(start, 2 + sz + allowzeroterminated, ASCSTR_LEN2))
					return 0;
#ifdef _DEBUG
				if (sz <= 0) _RPT3(_CRT_WARN, "%s(%08IX, %s, ...): trying to create string of zero size\n",
					__FUNCTION__, start, "ASCSTR_LEN2");
#endif // _DEBUG
				if (!hasRef(get_flags_novalue(start))
					&& !hasRef(get_flags_novalue(start + 2))
					&& has_any_name(get_flags_novalue(start))) del_global_name(start);
			}
			break;
		case ASCSTR_UNICODE:
			if (get_str_type_code(get_string_type(start)) == ASCSTR_UNICODE)
				return (get_item_size(start) >> 1) - 1;
			for (scan = start; (c = get_word(scan)) != get_str_term1(strtype)
				|| get_str_term2(strtype) == 0
				|| get_word(scan + 2) != get_str_term2(strtype); scan += 2)
				if (!isEnabled(scan) || isLoaded(scan) && isstring(c) == 0) return 0;
			if (scan <= start) return 0;
			do_unknown_range(start, sz = scan + 2 - start, false);
			if (!make_ascii_string(start, sz, ASCSTR_UNICODE)) return 0;
			if (!hasRef(flags = get_flags_novalue(start)) && has_any_name(flags))
				del_global_name(start);
			return (sz >> 1) - 1;
		case ASCSTR_PASCAL:
			if ((sz = get_byte(start)) > 0
				&& (get_str_type_code(get_string_type(start)) != ASCSTR_PASCAL
				|| get_item_size(start) != 1 + sz + allowzeroterminated)) {
				for (scan = start + 1; scan < start + 1 + sz; ++scan)
					if (!isEnabled(scan) || isLoaded(scan)
						&& isstring(get_byte(scan)) == 0) return 0;
				if (scan <= start + 1) return 0;
				foo = start + 1 + sz;
				allowzeroterminated = allowzeroterminated && get_byte(foo) == 0
					&& !isBoundary(get_flags_novalue(foo));
				do_unknown_range(start, 1 + sz + allowzeroterminated, false);
				if (!make_ascii_string(start, 1 + sz + allowzeroterminated, ASCSTR_PASCAL))
					return 0;
#ifdef _DEBUG
				if (sz <= 0) _RPT3(_CRT_WARN, "%s(%08IX, %s, ...): trying to create string of zero size\n",
					__FUNCTION__, start, "ASCSTR_PASCAL");
#endif // _DEBUG
				if (!hasRef(get_flags_novalue(start))
					&& !hasRef(get_flags_novalue(start + 1))
					&& has_any_name(get_flags_novalue(start))) del_global_name(start);
			}
			break;
		case ASCSTR_LEN4:
			if ((sz = get_long(start)) > 0
				&& (get_str_type_code(get_string_type(start)) != ASCSTR_LEN4
				|| get_item_size(start) != 4 + sz + allowzeroterminated)) {
				for (scan = start + 4; scan < start + 4 + sz; ++scan)
					if (!isEnabled(scan) || isLoaded(scan)
						&& isstring(get_byte(scan)) == 0) return 0;
				if (scan <= start + 4) return 0;
				foo = start + 4 + sz;
				allowzeroterminated = allowzeroterminated && get_byte(foo) == 0
					&& !isBoundary(get_flags_novalue(foo));
				do_unknown_range(start, 4 + sz + allowzeroterminated, false);
				if (!make_ascii_string(start, 4 + sz + allowzeroterminated, ASCSTR_LEN4))
					return 0;
#ifdef _DEBUG
				if (sz <= 0) _RPT3(_CRT_WARN, "%s(%08IX, %s, ...): trying to create string of zero size\n",
					__FUNCTION__, start, "ASCSTR_LEN4");
#endif // _DEBUG
				if (!hasRef(get_flags_novalue(start))
					&& !hasRef(get_flags_novalue(start + 4))
					&& has_any_name(get_flags_novalue(start))) del_global_name(start);
				if (allowzeroterminated && get_long(start - 4) == 0xFFFFFFFF
					&& !isDwrd(get_flags_novalue(start - 4))) {
					do_unknown_range(start - 4, 4, false);
					doDwrd(start - 4, 4);
					op_hex(start - 4, 0);
				}
			}
			break;
		case ASCSTR_ULEN2:
			if ((sz = get_word(start)/* >> 1*/) > 0
				&& (get_str_type_code(get_string_type(start)) != ASCSTR_ULEN2
				|| get_item_size(start) != 2 + (sz << 1) + allowzeroterminated)) {
				for (scan = start + 2; scan < start + 2 + (sz << 1); scan += 2)
					if (!isEnabled(scan) || isLoaded(scan)
						&& isstring(get_word(scan)) == 0) return 0;
				if (scan <= start + 2) return 0;
				foo = start + 2 + (sz << 1);
				allowzeroterminated = allowzeroterminated && get_byte(foo) == 0
					&& !isBoundary(get_flags_novalue(foo));
				do_unknown_range(start, 2 + (sz + allowzeroterminated << 1), false);
				if (!make_ascii_string(start, 2 + (sz + allowzeroterminated << 1), ASCSTR_ULEN2))
					return 0;
#ifdef _DEBUG
				if (sz <= 0) _RPT3(_CRT_WARN, "%s(%08IX, %s, ...): trying to create string of zero size\n",
					__FUNCTION__, start, "ASCSTR_ULEN2");
#endif // _DEBUG
				if (!hasRef(get_flags_novalue(start))
					&& !hasRef(get_flags_novalue(start + 2))
					&& has_any_name(get_flags_novalue(start))) del_global_name(start);
			}
			break;
		case ASCSTR_ULEN4:
			if ((sz = get_long(start)/* >> 1*/) > 0
				&& (get_str_type_code(get_string_type(start)) != ASCSTR_ULEN4
				|| get_item_size(start) != 4 + (sz << 1) + allowzeroterminated)) {
				for (scan = start + 4; scan < start + 4 + (sz << 1); scan += 2)
					if (!isEnabled(scan) || isLoaded(scan)
						&& isstring(get_word(scan)) == 0) return 0;
				if (scan <= start + 4) return 0;
				foo = start + 4 + (sz << 1);
				allowzeroterminated = allowzeroterminated && get_byte(foo) == 0
					&& !isBoundary(get_flags_novalue(foo));
				do_unknown_range(start, 4 + (sz + allowzeroterminated << 1), false);
				if (!make_ascii_string(start, 4 + (sz + allowzeroterminated << 1), ASCSTR_ULEN4))
					return 0;
#ifdef _DEBUG
				if (sz <= 0) _RPT3(_CRT_WARN, "%s(%08IX, %s, ...): trying to create string of zero size\n",
					__FUNCTION__, start, "ASCSTR_ULEN4");
#endif // _DEBUG
				if (!hasRef(get_flags_novalue(start))
					&& !hasRef(get_flags_novalue(start + 4))
					&& has_any_name(get_flags_novalue(start))) del_global_name(start);
			}
			break;
	} // switch statement
	return sz;
}

std::hash_set<RegNo, std::hash<int> > get_segs_used(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	std::hash_set<RegNo, std::hash<int> > result;
	if (isCode(get_flags_novalue(ea)) && ua_ana0(ea) > 0)
		for (int iter = 0; iter < UA_MAXOP; ++iter) {
			if (cmd.Operands[iter].type == o_last) break;
			if (cmd.Operands[iter].specval_shorts.high >= ph.regFirstSreg
				&& cmd.Operands[iter].specval_shorts.high <= ph.regLastSreg)
				result.insert(static_cast<RegNo>(cmd.Operands[iter].specval_shorts.high));
		}
	return result;
}

bool is_in_rsrc(ea_t ea) {
	//_ASSERTE(isEnabled(ea));
	if (!isEnabled(ea)) return false;
	ea_t imagebase;
	IMAGE_NT_HEADERS pehdr;
	if (netnode("$ PE header").valobj(&pehdr, sizeof pehdr) >= sizeof pehdr) {
		imagebase = pehdr.OptionalHeader.ImageBase;
		const PIMAGE_DATA_DIRECTORY rsrcinfo(&pehdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]);
		return ea >= imagebase + rsrcinfo->VirtualAddress
			&& ea < imagebase + rsrcinfo->VirtualAddress + rsrcinfo->Size;
	}
	segment_t *const rsrc(get_segm_by_name(".rsrc"));
	return rsrc != 0 && rsrc->contains(ea);
}

bool doOff32(ea_t ea, ulong size) {
	_ASSERTE(isEnabled(ea));
	//return do_data_ex(ea, dwrdflag() | offflag(), size, BADNODE);
	do_unknown_range(ea, size, false);
	bool ok(doDwrd(ea, size) && op_offset(ea, 0, get_default_reftype(ea)) != 0);
	if (ok) analyze_area(ea, next_not_tail(ea));
	return ok;
}

bool do_data_ex(ea_t ea, flags_t flags, const typeinfo_t *pti, asize_t size) {
	_ASSERTE(isEnabled(ea));
	if (!isEnabled(ea)) return false;
	bool ok(false);
	flags = FF_DATA | flags & (DT_TYPE | MS_0TYPE);
	if (size <= 0) size = get_data_type_size(flags, pti);
	if (size > 0) {
		do_unknown_range(ea, size, false);
		ok = do_data_ex(ea, flags, size, isStruct(flags) && pti != 0 ? pti->tid : BADNODE);
	}
	if (pti != 0) {
		ok = set_typeinfo(ea, 0, flags, pti) != 0 && ok;
		if (isOff0(flags) || isStruct(flags))
			analyze_area(ea, next_not_tail(ea)); // create x-refs
		if (isStruct(flags)) clr_terse_struc(ea); // face-lift
	}
	return ok;
}

bool append_unique_cmt(ea_t ea, const char *str, bool rptble) {
	_ASSERTE(isEnabled(ea) && str != 0);
	char cmt[MAXSPECSIZE], *pattern;
	return GET_CMT(ea, rptble, CPY(cmt)) <= 0 || (pattern = strstr(cmt, str)) == 0
		|| pattern > cmt && strchr("\r\n", *(pattern - 1)) == 0 ?
			append_cmt(ea, str, rptble) : false;
}

void add_unique_long_cmt(ea_t ea, bool isprev, const char *format, ...) {
	_ASSERTE(format != 0 && *format != 0);
	if (format == 0 || *format == 0) return;
	va_list va;
	va_start(va, format);
	if (!hasExtra(get_flags_novalue(ea)))
		add_long_cmt_v(ea, isprev, format, va);
	else {
		std::string cmt;
		_vsprintf(cmt, format, va);
		char ln[MAXSPECSIZE];
		ssize_t sz;
		for (int i = isprev ? E_PREV : E_NEXT;
			(sz = ExtraGet(ea, i, CPY(ln))) > 0; ++i) if (cmt == ln) break;
		if (sz <= 0) add_long_cmt_v(ea, isprev, format, va);
	}
	va_end(va);
}

/*
char *GET_ANY_CMT(ea_t ea, color_t *cmttype) {
	_ASSERTE(isEnabled(ea));
	char *cmt(get_any_indented_cmt(ea, cmttype));
	if (!cmt && isFunc(get_flags_novalue(ea))) {
		func_t *func = get_func(ea);
		cmt = get_func_cmt(func, false);
		if (!cmt) cmt = get_func_cmt(func, true);
	}
	return cmt;
}
*/

#if IDP_INTERFACE_VERSION < 76

char *GET_CMT(ea_t ea, bool rptble) {
	_ASSERTE(isEnabled(ea));
	char *cmt(get_cmt(ea, rptble));
	if (cmt == 0 && isFunc(get_flags_novalue(ea)))
		cmt = get_func_cmt(get_func(ea), rptble);
	return cmt;
}

ssize_t GET_CMT(ea_t ea, bool rptble, char *buf, size_t bufsize) {
	if (buf != 0 && bufsize > 0) *buf = 0;
	_ASSERTE(isEnabled(ea));
	char *const s = GET_CMT(ea, rptble);
	return s != 0 ? strlen(buf != 0 ? qstrncpy(buf, s, bufsize) : s) : -1;
}

#else // IDP_INTERFACE_VERSION >= 76

ssize_t GET_CMT(ea_t ea, bool rptble, char *buf, size_t bufsize) {
	_ASSERTE(isEnabled(ea));
	if (buf != 0 && bufsize > 0) *buf = 0;
	ssize_t s(get_cmt(ea, rptble, buf, bufsize));
	if (s <= 0 && isFunc(get_flags_novalue(ea))) {
		char *const cmt(get_func_cmt(get_func(ea), rptble));
		s = cmt != 0 ? strlen(cmt) : 0;
	}
	return s;
}

#endif // IDP_INTERFACE_VERSION < 76

#ifdef _DEBUG

static std::string get_enum_error_string(int result) {
	switch (result) {
		case CONST_ERROR_NAME: return "CONST_ERROR_NAME";
		case CONST_ERROR_VALUE: return "CONST_ERROR_VALUE";
		case CONST_ERROR_ENUM: return "CONST_ERROR_ENUM";
		case CONST_ERROR_MASK: return "CONST_ERROR_MASK";
		case CONST_ERROR_ILLV: return "CONST_ERROR_ILLV";
		case 0: return "OK";
	}
	return _sprintf("%i", result);
}

#endif // _DEBUG

uint add_consts(enum_t id, const enum_entry_t *consts, size_t count) {
	_ASSERTE(id != BADNODE);
	_ASSERTE(consts != 0);
	_ASSERTE(count > 0);
	if (id == BADNODE || consts == 0 || count <= 0) return BADNODE;
	uint total(0);
	for (uint cntr = 0; cntr < count; ++cntr) try {
		const int result(add_const(id, consts[cntr].name, consts[cntr].value, DEFMASK));
		if (result == 0) ++total;
#ifdef _DEBUG
		else
			_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
				"%s(..., %Iu): add_const(..., %s, %Iu, DEFMASK) returned %s (index=%u)\n",
				__FUNCTION__, count, consts[cntr].name, consts[cntr].value,
				get_enum_error_string(result).c_str(), cntr);
	} catch (const std::exception &e) {
		_CrtDbgReport(_CRT_ERROR, __FILE__, __LINE__, __FUNCTION__,
			"%s(..., %Iu): %s during add_const(..., %Iu, DEFMASK) (consts[%u].name=%08X)\n",
			__FUNCTION__, count, e.what(), consts[cntr].value, cntr, consts[cntr].name);
#else // !_DEBUG
	} catch (...) {
#endif // _DEBUG
	}
	return total;
}

enum_t create_enum(const char *name, flags_t flag, const enum_entry_t *consts,
	size_t count, bool deleteexisting, const char *cmt, bool repeatable) {
	_ASSERTE(name != 0 && *name != 0);
	_ASSERTE(consts != 0);
	_ASSERTE(count > 0);
	if (name == 0 || *name == 0 || consts == 0 || count <= 0) return BADNODE;
	enum_t id(get_enum(name));
	if (id != BADNODE) if (!deleteexisting) return id; else del_enum(id);
#ifdef _DEBUG
	if (get_optype_flags0(flag) == 0) _RPTF4(_CRT_WARN, "%s(\"%s\", %s, ..., %Iu, ...): MS_0TYPE==0\n",
		__FUNCTION__, name, flags2str(flag).c_str(), count);
#endif // _DEBUG
	if ((id = add_enum(BADADDR, name, flag)) != BADNODE) {
		set_enum_bf(id, false);
		add_consts(id, consts, count);
		set_enum_hidden(id, true);
		if (cmt != 0 && *cmt != 0) set_enum_cmt(id, cmt, repeatable);
	}
#ifdef _DEBUG
	else
		_RPTF3(_CRT_ERROR, "%s(...): add_enum(BADADDR, \"%s\", %s) returned BADNODE\n",
			__FUNCTION__, name, flags2str(flag).c_str());
#endif // _DEBUG
	return id;
}

uint add_consts(enum_t id, const bitfield_entry_t *consts, size_t count) {
	_ASSERTE(id != BADNODE);
	_ASSERTE(consts != 0);
	_ASSERTE(count > 0);
	if (id == BADNODE || consts == 0 || count <= 0) return BADNODE;
	uint total(0);
	for (uint cntr = 0; cntr < count; ++cntr) try {
		const int result(add_const(id, consts[cntr].name,
			consts[cntr].value, consts[cntr].bmask));
		if (result == 0) ++total;
#ifdef _DEBUG
		else
			_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
				"%s(..., %Iu): add_const(..., %s, 0x%IX, 0x%IX) returned %s (index=%u)\n",
				__FUNCTION__, count, consts[cntr].name, consts[cntr].value,
				consts[cntr].bmask, get_enum_error_string(result).c_str(), cntr);
	} catch (const std::exception &e) {
		_CrtDbgReport(_CRT_ERROR, __FILE__, __LINE__, __FUNCTION__,
			"%s(..., %Iu): %s during add_const(..., 0x%IX, 0x%IX) (consts[%u].name=%08X)\n",
			__FUNCTION__, count, e.what(), consts[cntr].value,
			consts[cntr].bmask, cntr, consts[cntr].name);
#else // !_DEBUG
	} catch (...) {
#endif // _DEBUG
	}
	return total;
}

enum_t create_enum(const char *name, flags_t flag,
	const bitfield_entry_t *consts, size_t count, bool deleteexisting,
	const char *cmt, bool repeatable) {
	_ASSERTE(name != 0 && *name != 0);
	_ASSERTE(consts != 0);
	_ASSERTE(count > 0);
	if (name == 0 || *name == 0 || consts == 0 || count <= 0) return BADNODE;
	enum_t id(get_enum(name));
	if (id != BADNODE) if (!deleteexisting) return id; else del_enum(id);
#ifdef _DEBUG
	if (get_optype_flags0(flag) == 0) _RPTF4(_CRT_WARN, "%s(\"%s\", %s, ..., %Iu, ...): MS_0TYPE==0\n",
		__FUNCTION__, name, flags2str(flag).c_str(), count);
#endif // _DEBUG
	if ((id = add_enum(BADADDR, name, flag)) != BADNODE) {
		set_enum_bf(id, true);
		add_consts(id, consts, count);
		set_enum_hidden(id, true);
		if (cmt != 0 && *cmt != 0) set_enum_cmt(id, cmt, repeatable);
	}
#ifdef _DEBUG
	else
		_RPTF3(_CRT_ERROR, "%s(...): add_enum(BADADDR, \"%s\", %s) returned BADNODE\n",
			__FUNCTION__, name, flags2str(flag).c_str());
#endif // _DEBUG
	return id;
}

uint add_consts(enum_t id, const enum_entry_ex_t *consts, size_t count,
	bool repeatable) {
	_ASSERTE(id != BADNODE);
	_ASSERTE(consts != 0);
	_ASSERTE(count > 0);
	if (id == BADNODE || consts == 0 || count <= 0) return BADNODE;
	uint total(0);
	for (uint cntr = 0; cntr < count; ++cntr) try {
		const int result(add_const(id, consts[cntr].name, consts[cntr].value, DEFMASK));
		if (result == 0) {
			++total;
			if (consts[cntr].comment != 0) set_const_cmt(get_const_by_name(consts[cntr].name),
				consts[cntr].comment, repeatable);
		}
#ifdef _DEBUG
		else
			_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
				"%s(..., %Iu, ...): add_const(..., %s, %Iu, DEFMASK) returned %s (index=%u)\n",
				__FUNCTION__, count, consts[cntr].name, consts[cntr].value,
				get_enum_error_string(result).c_str(), cntr);
	} catch (const std::exception &e) {
		_CrtDbgReport(_CRT_ERROR, __FILE__, __LINE__, __FUNCTION__,
			"%s(..., %Iu, ...): %s during add_const(..., %Iu, DEFMASK) (consts[%u].name=%08X)\n",
			__FUNCTION__, count, e.what(), consts[cntr].value, cntr, consts[cntr].name);
#else // !_DEBUG
	} catch (...) {
#endif // _DEBUG
	}
	return total;
}

enum_t create_enum(const char *name, flags_t flag, const enum_entry_ex_t *consts,
	size_t count, bool rptble, bool deleteexisting, const char *cmt, bool repeatable) {
	_ASSERTE(name != 0 && *name != 0);
	_ASSERTE(consts != 0);
	_ASSERTE(count > 0);
	if (name == 0 || *name == 0 || consts == 0 || count <= 0) return BADNODE;
	enum_t id(get_enum(name));
	if (id != BADNODE) if (!deleteexisting) return id; else del_enum(id);
#ifdef _DEBUG
	if (get_optype_flags0(flag) == 0) _RPTF4(_CRT_WARN, "%s(\"%s\", %s, ..., %Iu, ...): MS_0TYPE==0\n",
		__FUNCTION__, name, flags2str(flag).c_str(), count);
#endif // _DEBUG
	if ((id = add_enum(BADADDR, name, flag)) != BADNODE) {
		set_enum_bf(id, false);
		add_consts(id, consts, count, rptble);
		set_enum_hidden(id, true);
		if (cmt != 0 && *cmt != 0) set_enum_cmt(id, cmt, repeatable);
	}
#ifdef _DEBUG
	else
		_RPTF3(_CRT_ERROR, "%s(...): add_enum(BADADDR, \"%s\", %s) returned BADNODE\n",
			__FUNCTION__, name, flags2str(flag).c_str());
#endif // _DEBUG
	return id;
}

uint add_consts(enum_t id, const bitfield_entry_ex_t *consts,
	size_t count, bool repeatable) {
	_ASSERTE(id != BADNODE);
	_ASSERTE(consts != 0);
	_ASSERTE(count > 0);
	if (id == BADNODE || consts == 0 || count <= 0) return BADNODE;
	uint total(0);
	for (uint cntr = 0; cntr < count; ++cntr) try {
		const int result(add_const(id, consts[cntr].name,
			consts[cntr].value, consts[cntr].bmask));
		if (result == 0) {
			++total;
			if (consts[cntr].comment != 0) set_const_cmt(get_const_by_name(consts[cntr].name),
				consts[cntr].comment, repeatable);
		}
#ifdef _DEBUG
		else
			_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
				"%s(..., %Iu, ...): add_const(..., %s, 0x%lu, 0x%lX) returned %s (index=%u)\n",
				__FUNCTION__, count, consts[cntr].name, consts[cntr].value,
				consts[cntr].bmask, get_enum_error_string(result).c_str(), cntr);
	} catch (const std::exception &e) {
		_CrtDbgReport(_CRT_ERROR, __FILE__, __LINE__, __FUNCTION__,
			"%s(..., %Iu, ...): %s during add_const(..., 0x%lu, 0x%lX) (index=%u consts[%u].name=%08X)\n",
			__FUNCTION__, count, e.what(), consts[cntr].value,
			consts[cntr].bmask, cntr, cntr, consts[cntr].name);
#else // !_DEBUG
	} catch (...) {
#endif // _DEBUG
	}
	return total;
}

enum_t create_enum(const char *name, flags_t flag,
	const bitfield_entry_ex_t *consts, size_t count, bool rptble,
	bool deleteexisting, const char *cmt, bool repeatable) {
	_ASSERTE(name != 0 && *name != 0);
	_ASSERTE(consts != 0);
	_ASSERTE(count > 0);
	if (name == 0 || *name == 0 || consts == 0 || count <= 0) return BADNODE;
	enum_t id(get_enum(name));
	if (id != BADNODE) if (!deleteexisting) return id; else del_enum(id);
#ifdef _DEBUG
	if (get_optype_flags0(flag) == 0) _RPTF4(_CRT_WARN, "%s(\"%s\", %s, ..., %Iu, ...): MS_0TYPE==0\n",
		__FUNCTION__, name, flags2str(flag).c_str(), count);
#endif // _DEBUG
	if ((id = add_enum(BADADDR, name, flag)) != BADNODE) {
		set_enum_bf(id, true);
		add_consts(id, consts, count, rptble);
		set_enum_hidden(id, true);
		if (cmt != 0 && *cmt != 0) set_enum_cmt(id, cmt, repeatable);
	}
#ifdef _DEBUG
	else
		_RPTF3(_CRT_ERROR, "%s(...): add_enum(BADADDR, \"%s\", %s) returned BADNODE\n",
			__FUNCTION__, name, flags2str(flag).c_str());
#endif // _DEBUG
	return id;
}

void add_local_struct_member(struc_t *frame, ea_t offset, const char *varname,
	const struc_t *sptr, asize_t varsize) {
	_ASSERTE(frame != 0);
	_ASSERTE(sptr != 0);
	if (frame == 0 || sptr == 0) return;
	const asize_t strucsize = get_struc_size(sptr);
	if (varsize <= 0) varsize = strucsize;
	_ASSERTE(varsize % strucsize == 0);
	for (uint index = 0; index * strucsize < varsize; ++index)
		for (ea_t varoffset = get_struc_first_offset(sptr); varoffset != BADADDR;
			varoffset = get_struc_next_offset(sptr, varoffset)) {
			const member_t *const member = get_member(sptr, varoffset);
			if (member == 0) continue;
			char name[MAXNAMESIZE], memname[MAXSPECSIZE];
			name[0] = 0;
			if (varname != 0 && *varname != 0
				&& get_member_name(member->id, CPY(memname)) > 0
				&& !is_anonymous_member_name(memname)) {
				uint suffix(1);
				do {
					qsnprintf(CPY(name), "%s_%s", varname, memname);
					if (suffix++ >= 2) qsnprintf(CAT(name), "_%u", suffix);
				} while (get_member_by_name(frame, name) != 0);
			}
			if (isStruct(member->flag))
				add_local_struct_member(frame, offset + index * strucsize + varoffset,
					name[0] != 0 ? name : varname, get_sptr(member), get_member_size(member));
			else {
				type_t typinfo[MAXSPECSIZE];
				if (!get_member_ti(member, CPY(typinfo))) typinfo[0] = 0;
#if IDP_INTERFACE_VERSION < 76
				const p_list *const fnames =
					(const p_list *)netnode(member->id).supval(NSUP_TYPEINFO + 1);
				const char *const cmt[] = {
					get_member_cmt(member->id, false),
					get_member_cmt(member->id, true),
				};
#else // IDP_INTERFACE_VERSION >= 76
				p_list fnames[MAXSPECSIZE];
				char cmt[2][MAXSPECSIZE];
				const ssize_t s[] = {
					netnode(member->id).supval(NSUP_TYPEINFO + 1, &fnames, sizeof(fnames)),
					get_member_cmt(member->id, false, CPY(cmt[0])),
					get_member_cmt(member->id, true, CPY(cmt[1])),
				};
#endif // IDP_INTERFACE_VERSION < 76
				array_parameters_t array_parm;
				const bool has_array_parameters = get_array_parameters(member->id,
					&array_parm, sizeof array_parameters_t) >= sizeof array_parameters_t;
				typeinfo_t ti;
				if (add_struc_member(frame, name[0] != 0 ? name : NULL,
					offset + index * strucsize + varoffset, member->flag,
					retrieve_member_info(member, &ti), get_member_size(member)) ==
#ifdef STRUC_ERROR_MEMBER_OK
					STRUC_ERROR_MEMBER_OK
#else
					0
#endif
					) {
					member_t *const stkvar = get_member(frame,
						offset + index * strucsize + varoffset);
					_ASSERTE(stkvar != 0);
					if (stkvar != 0) {
#if IDP_INTERFACE_VERSION < 76
						if (typinfo[0] != 0) {
							set_member_ti(frame, stkvar, typinfo, true);
							if (fnames != 0) netnode(stkvar->id).supset(NSUP_TYPEINFO + 1,
								&fnames, typlen(fnames) + 1);
						}
						if (cmt[0] != 0) set_member_cmt(stkvar, cmt[0], false);
						if (cmt[1] != 0) set_member_cmt(stkvar, cmt[1], true);
#else // IDP_INTERFACE_VERSION >= 76
						if (typinfo[0] != 0) {
							set_member_ti(frame, stkvar, typinfo, SET_MEMTI_MAY_DESTROY);
							if (s[0] > 0) netnode(stkvar->id).supset(NSUP_TYPEINFO + 1,
								&fnames, s[0]);
						}
						if (s[1] > 0) set_member_cmt(stkvar, cmt[0], false);
						if (s[2] > 0) set_member_cmt(stkvar, cmt[1], true);
#endif // IDP_INTERFACE_VERSION < 76
						if (has_array_parameters) set_array_parameters(stkvar->id, &array_parm);
					}
				}
			}
		}
}

int add_struc_member_ex(struc_t *sptr, const char *fieldname, ea_t offset,
	flags_t flag, const typeinfo_t *mt, asize_t nbytes, const char *cmt, bool repeatable) {
	int result(add_struc_member(sptr, fieldname, offset, flag, mt, nbytes));
	if (result != 0) return result; // error
	return cmt != 0 && *cmt != 0 ? !set_member_cmt(get_member_by_name(sptr,
		fieldname), cmt, repeatable) : 0 /* ok */;
}

bool iscalled(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	xrefblk_t xref;
	for (bool ok = xref.first_to(ea, XREF_FAR); ok; ok = xref.next_to())
		if (xref.iscode && isCode(get_flags_novalue(xref.from))
			&& is_call_insn(xref.from)) return true;
	return false;
}

char *make_ident_name(char *name, size_t namesize, char substchar) {
	_ASSERTE(name != 0);
	_ASSERTE(namesize > 0);
	//_ASSERTE(substchar != 0);
	if (name != 0 && namesize > 0) {
		if (substchar == 0) substchar = SubstChar;
		if (NameChars[0] != 0) for (char *s = name; *s != 0; ++s)
			if (strchr(NameChars, *s) == 0) *s = substchar;
		while (isdigit(name[0]) || !isident(name))
			qstrncpy(name, std::string(1, '_').append(name).c_str(), namesize);
	}
	return isident(name) ? name : 0;
}

char *make_unique_name(char *name, size_t namesize) {
	_ASSERTE(name != 0);
	_ASSERTE(namesize > 0);
	if (name == 0 || namesize <= 0) return 0;
	if (get_name_ea(BADADDR, name) == BADADDR) return name; // is uniwue
	char tryname[MAXNAMESIZE];
	uint16 suffix(2);
	while (suffix != 0) {
		qsnprintf(CPY(tryname), "%s_%hu", name, suffix++);
		if (get_name_ea(BADADDR, tryname) == BADADDR) {
			qstrncpy(name, tryname, namesize);
			break;
		}
	}
	return get_name_ea(BADADDR, name) == BADADDR ? name : 0;
}

// is pure import (API frontend) function?
bool is_pure_import_func(const func_t *func) {
	return func != 0 && has_name(get_flags_novalue(func->startEA))
		&& (func->tailqty == 0 && next_not_tail(func->startEA) == func->endEA
		&& does_ref_extern(func->startEA)/* || (func->flags & FUNC_THUNK) != 0*/);
}

bool is_libfuncname(ea_t ea) {
	const flags_t flags(get_flags_novalue(ea));
	return isFunc(flags) && has_user_name(flags) && is_true_libfunc(ea)
		/*&& get_supressed_library_flag(ea) != 1 */&& !is_extern(ea);
}

bool is_libvarname(ea_t ea) {
	const flags_t flags(get_flags_novalue(ea));
	return !isFunc(flags) && !isCode(flags) && has_user_name(flags)
		&& is_libitem(ea) && get_supressed_library_flag(ea) != 1 && !is_extern(ea);
}

asize_t get_near_ptr_size() {
	switch (inf.cc.cm & CM_MASK) {
		case CM_N32_F48: return 4;
		case CM_N16_F32: return 2;
		case CM_N8_F16: return inf.cc.size_i > 2 ? 8 : 1;
#ifdef _DEBUG
		default:
			_RPT2(_CRT_WARN, "%s(): unexpected inf.cc.cm value (%u)\n", __FUNCTION__, inf.cc.cm);
#endif // _DEBUG
	}
	return 0; // unknown
}

asize_t get_far_ptr_size() {
	switch (inf.cc.cm & CM_MASK) {
		case CM_N32_F48: return 6;
		case CM_N16_F32: return 4;
		case CM_N8_F16: return inf.cc.size_i > 2 ? 8 : 2;
#ifdef _DEBUG
		default:
			_RPT2(_CRT_WARN, "%s(): unexpected inf.cc.cm value (%u)\n", __FUNCTION__, inf.cc.cm);
#endif // _DEBUG
	}
	return 0; // unknown
}

asize_t get_ptr_size(flags_t type) { // type == FF_DATA || FF_CODE
	const cm_t model = inf.cc.cm & CM_M_MASK;
	return model == CM_M_NN || isCode(type) && model == CM_M_NF
		|| isData(type) && model == CM_M_FN ? get_near_ptr_size() :
		model == CM_M_FF || isCode(type) && model == CM_M_FN
		|| isData(type) && model == CM_M_NF ? get_far_ptr_size() : max_ptr_size();
}

bool has_rsrc() {
	PIMAGE_DATA_DIRECTORY rsrcinfo;
	IMAGE_NT_HEADERS pehdr;
	return netnode("$ PE header").valobj(&pehdr, sizeof pehdr) >= sizeof pehdr
		&& (rsrcinfo = &pehdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]) != 0
		&& rsrcinfo->VirtualAddress != 0 && rsrcinfo->Size != 0
		&& isLoaded(pehdr.OptionalHeader.ImageBase + rsrcinfo->VirtualAddress)
		|| get_segm_by_name(".rsrc") != 0;
}

// experimental
int kill_tail_chunks(func_t *pfn) {
	_ASSERTE(pfn != 0);
	_ASSERTE(is_func_entry(pfn));
	if (pfn == 0 || !is_func_entry(pfn) || pfn->tailqty < 1) return 0; // invalid function or nothing to do
	int total(0);
	rangelist_t list;
	func_t func(*pfn);
	func_tail_iterator_t fti(&func);
	for (bool ok = fti.first(); ok; ok = fti.next()) list.insert(fti.chunk());
	if (!del_func(func.startEA)) return 0; // cant delete functino
	for (rangelist_t::const_iterator tail = list.begin(); tail != list.end(); ++tail) {
		if (add_func(tail->startEA, tail->endEA/*BADADDR*/)) {
			pfn = get_fchunk(tail->startEA);
			_ASSERTE(pfn != 0);
			if (pfn != 0) analyze_area(*pfn);
			++total;
		}
	}
#ifdef _DEBUG
	if (total != func.tailqty)
		_RPT3(_CRT_WARN, "%s(...): not all tail chunks were converted to standalone functions (%i!=%i)\n",
			__FUNCTION__, total, func.tailqty);
#endif // _DEBUG
	if (!add_func(func.startEA, func.endEA/*BADADDR*/)) return 0; // failed to re-create the entry chunk
again:
	pfn = get_fchunk(func.startEA);
	_ASSERTE(pfn != 0);
	if (pfn != 0) analyze_area(*pfn);
	if (is_func_entry(pfn)) {
		func = *pfn;
		for (rangelist_t::iterator tail = list.begin(); tail != list.end(); ++tail)
			if (tail->startEA == func.endEA
				&& is_func_entry(pfn = get_fchunk(tail->startEA))) {
				xrefblk_t xref;
				for (bool ok = xref.first_to(pfn->startEA, XREF_FAR); ok; ok = xref.next_to())
					if ((pfn = get_func(xref.from)) == 0 || pfn->startEA != func.startEA
						|| is_call_insn(xref.from)) break; // regular function
				if (!ok) {
					pfn = get_fchunk(tail->startEA);
					_ASSERTE(pfn != 0);
					_ASSERTE(is_func_entry(pfn));
					ea_t endEA(pfn->endEA);
					del_global_name(pfn->startEA);
					if (del_func(tail->startEA) && func_setend(func.startEA, endEA)) {
						list.erase(tail);
						goto again;
					}
				}
			}
	}
	return total;
}

bool is_xrefd(ea_t ea) {
	return hasRef(get_flags_novalue(ea = get_item_head(ea)))
		|| nextthat(ea, get_item_end(ea), TESTFUNC(hasRef)) < get_item_end(ea);
}

uint xrefs_to(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	uint result(0);
	xrefblk_t xref;
	for (bool ok = xref.first_to(ea, XREF_FAR); ok; ok = xref.next_to()) ++result;
	return result;
}

uint xrefs_from(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	typeinfo_t ti;
	flags_t flags(get_flags_novalue(ea));
	if (!get_typeinfo(ea, 0, flags, &ti)) ti.tid = BADNODE;
	tid_t structid(isStruct(flags) ? get_strid(ea) : BADNODE);
	xrefblk_t xref;
	uint result(0);
	for (bool ok = xref.first_from(ea, XREF_FAR); ok; ok = xref.next_from())
		if (xref.to != ti.tid && xref.to != structid) ++result;
	return result;
}

uint crefs_to(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	xrefblk_t xref;
	uint result(0);
	for (bool ok = xref.first_to(ea, XREF_FAR); ok; ok = xref.next_to())
		if (xref.iscode == 1) ++result;
	return result;
}

uint crefs_from(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	flags_t flags(get_flags_novalue(ea));
	typeinfo_t ti;
	if (get_typeinfo(ea, 0, flags, &ti) == 0) ti.tid = BADNODE;
	xrefblk_t xref;
	tid_t structid(isStruct(flags) ? get_strid(ea) : BADNODE);
	uint result(0);
	for (bool ok = xref.first_from(ea, XREF_FAR); ok; ok = xref.next_from())
		if (xref.iscode == 1 && xref.to != ti.tid && xref.to != structid) ++result;
	return result;
}

uint drefs_to(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	xrefblk_t xref;
	uint result(0);
	for (bool ok = xref.first_to(ea, XREF_DATA); ok; ok = xref.next_to()) ++result;
	return result;
}

uint drefs_from(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	flags_t flags(get_flags_novalue(ea));
	typeinfo_t ti;
	if (get_typeinfo(ea, 0, flags, &ti) == 0) ti.tid = BADNODE;
	tid_t structid(isStruct(flags) ? get_strid(ea) : BADNODE);
	xrefblk_t xref;
	uint result(0);
	for (bool ok = xref.first_from(ea, XREF_DATA); ok; ok = xref.next_from())
		if (xref.to != ti.tid && xref.to != structid) ++result;
	return result;
}

std::string flags2str(flags_t flags) {
	std::string localbuf;
	if (isCode(flags)) localbuf.append("FF_CODE|");
	else if (isData(flags)) localbuf.append("FF_DATA|");
	else if (isTail(flags)) localbuf.append("FF_TAIL|");
	else if (isUnknown(flags)) localbuf.append("FF_UNK|");
	if ((flags & FF_COMM) != 0) localbuf.append("FF_COMM|");
	if ((flags & FF_REF) != 0) localbuf.append("FF_REF|");
	if ((flags & FF_NAME) != 0) localbuf.append("FF_NAME|");
	if ((flags & FF_LABL) != 0) localbuf.append("FF_LABL|");
	if ((flags & FF_FLOW) != 0) localbuf.append("FF_FLOW|");
	if ((flags & FF_SIGN) != 0) localbuf.append("FF_SIGN|");
	if ((flags & FF_VAR) != 0) localbuf.append("FF_VAR|");
	if (get_optype_flags0(flags) == FF_0VOID) localbuf.append("FF_0VOID|");
	if (get_optype_flags0(flags) == FF_0NUMH) localbuf.append("FF_0NUMH|");
	if (get_optype_flags0(flags) == FF_0NUMD) localbuf.append("FF_0NUMD|");
	if (get_optype_flags0(flags) == FF_0CHAR) localbuf.append("FF_0CHAR|");
	if (get_optype_flags0(flags) == FF_0SEG) localbuf.append("FF_0SEG|");
	if (get_optype_flags0(flags) == FF_0OFF) localbuf.append("FF_0OFF|");
	if (get_optype_flags0(flags) == FF_0NUMB) localbuf.append("FF_0NUMB|");
	if (get_optype_flags0(flags) == FF_0NUMO) localbuf.append("FF_0NUMO|");
	if (get_optype_flags0(flags) == FF_0ENUM) localbuf.append("FF_0ENUM|");
	if (get_optype_flags0(flags) == FF_0FOP) localbuf.append("FF_0FOP|");
	if (get_optype_flags0(flags) == FF_0STRO) localbuf.append("FF_0STRO|");
	if (get_optype_flags0(flags) == FF_0STK) localbuf.append("FF_0STK|");
	if (get_optype_flags0(flags) == FF_0FLT) localbuf.append("FF_0FLT|");
	if (get_optype_flags1(flags) == FF_1VOID) localbuf.append("FF_1VOID|");
	if (get_optype_flags1(flags) == FF_1NUMH) localbuf.append("FF_1NUMH|");
	if (get_optype_flags1(flags) == FF_1NUMD) localbuf.append("FF_1NUMD|");
	if (get_optype_flags1(flags) == FF_1CHAR) localbuf.append("FF_1CHAR|");
	if (get_optype_flags1(flags) == FF_1SEG) localbuf.append("FF_1SEG|");
	if (get_optype_flags1(flags) == FF_1OFF) localbuf.append("FF_1OFF|");
	if (get_optype_flags1(flags) == FF_1NUMB) localbuf.append("FF_1NUMB|");
	if (get_optype_flags1(flags) == FF_1NUMO) localbuf.append("FF_1NUMO|");
	if (get_optype_flags1(flags) == FF_1ENUM) localbuf.append("FF_1ENUM|");
	if (get_optype_flags1(flags) == FF_1FOP) localbuf.append("FF_1FOP|");
	if (get_optype_flags1(flags) == FF_1STRO) localbuf.append("FF_1STRO|");
	if (get_optype_flags1(flags) == FF_1STK) localbuf.append("FF_1STK|");
	if (get_optype_flags1(flags) == FF_1FLT) localbuf.append("FF_1FLT|");
	if (isData(flags)) {
		if ((flags & DT_TYPE) == FF_BYTE) localbuf.append("FF_BYTE|");
		if ((flags & DT_TYPE) == FF_WORD) localbuf.append("FF_WORD|");
		if ((flags & DT_TYPE) == FF_DWRD) localbuf.append("FF_DWRD|");
		if ((flags & DT_TYPE) == FF_QWRD) localbuf.append("FF_QWRD|");
		if ((flags & DT_TYPE) == FF_TBYT) localbuf.append("FF_TBYT|");
		if ((flags & DT_TYPE) == FF_ASCI) localbuf.append("FF_ASCI|");
		if ((flags & DT_TYPE) == FF_STRU) localbuf.append("FF_STRU|");
		if ((flags & DT_TYPE) == FF_OWRD) localbuf.append("FF_OWRD|");
		if ((flags & DT_TYPE) == FF_FLOAT) localbuf.append("FF_FLOAT|");
		if ((flags & DT_TYPE) == FF_DOUBLE) localbuf.append("FF_DOUBLE|");
		if ((flags & DT_TYPE) == FF_PACKREAL) localbuf.append("FF_PACKREAL|");
		if ((flags & DT_TYPE) == FF_ALIGN) localbuf.append("FF_ALIGN|");
	} else if (isCode(flags)) {
		if ((flags & MS_CODE) == FF_FUNC) localbuf.append("FF_FUNC|");
		if ((flags & MS_CODE) == FF_IMMD) localbuf.append("FF_IMMD|");
		if ((flags & MS_CODE) == FF_JUMP) localbuf.append("FF_JUMP|");
		if ((flags & MS_CODE) == 0x20000000) localbuf.append("0x20000000|");
	}
	if ((flags & FF_IVL) != 0)
		_sprintf_append(localbuf, "FF_IVL|0x%02X", flags & MS_VAL);
	else if (!localbuf.empty() && back(localbuf) == '|')
		localbuf.erase(localbuf.length() - 1);
	if (localbuf.empty()) localbuf.assign("<none>");
	return localbuf;
}

bool can_be_cbuilder_app() {
	if (default_compiler() != COMP_BC && default_compiler() != COMP_BP) return false;
	segment_t *const segment(getnseg(0));
	return segment != 0 ? isEnabled(bin_search(segment->startEA, segment->endEA,
		(const uchar *)"fb:C++HOOK", NULL, 10, BIN_SEARCH_FORWARD,
		BIN_SEARCH_CASE | BIN_SEARCH_NOBREAK)) : false;
}

bool change_root(const char *newroot) {
	_ASSERTE(newroot != 0 && *newroot != 0);
	_ASSERTE(qfileexist(newroot));
	if (newroot == 0 || *newroot == 0 || !qfileexist(newroot)) return false;
	if (RootNode == BADNODE || !RootNode.set(newroot)) {
		_RPTF3(_CRT_WARN, "%s(\"%s\"): RootNode invalid or RootNode.set(\"%s\") returned false\n",
			__FUNCTION__, newroot, newroot);
		return false;
	}
	// change path in header
	char newpath[QMAXPATH];
	if (get_input_file_path(CPY(newpath)) > 0) {
		static const char prefix[] = "; File Name   : ";
		char line[MAXSTR];
		for (int index = E_PREV; ExtraGet(inf.minEA, index, CPY(line)) >= 0; ++index)
			if (strncmp(line, prefix, qnumber(prefix) - 1) == 0) ExtraUpdate(inf.minEA,
				const_cast<char *>(std::string(prefix).append(newpath).c_str()), index);
		msg("root changed to '%s'\n", newpath);
	}
#ifdef _DEBUG
	else
		_RPTF2(_CRT_WARN, "%s(\"%s\"): get_input_file_path(...) returned <=0\n",
			__FUNCTION__, newroot);
#endif // _DEBUG
	return true;
}

nodeidx_t sup1stfree(const netnode &node, char tag) {
	for (nodeidx_t ndx = 0; ndx != BADNODE; ++ndx)
		if (node.supval(ndx, NULL, 0, tag) < 0) break;
	return ndx;
}

nodeidx_t alt1stfree(const netnode &node, char tag) {
	for (nodeidx_t ndx = 0; ndx != BADNODE; ++ndx)
		if (node.altval(ndx, tag) == BADNODE) break;
	return ndx;
}

layered_wait_box::layered_wait_box(const char *format, ...) : __M_layer_counter(0) {
	va_list va;
	va_start(va, format);
	show_wait_box_v(format, va);
	va_end(va);
	++__M_layer_counter;
}

uint layered_wait_box::open(const char *format, ...) {
	va_list va;
	va_start(va, format);
	show_wait_box_v(format, va);
	va_end(va);
	return ++__M_layer_counter;
}

uint layered_wait_box::change(const char *format, ...) {
	if (__M_layer_counter > 0) {
		hide_wait_box();
		va_list va;
		va_start(va, format);
		show_wait_box_v(format, va);
		va_end(va);
	}
	return __M_layer_counter;
}

bool simple_hooker::hook(hook_type_t hook_type, hook_cb_t *cb, void *user_data) {
	const bool ok = hook_to_notification_point(hook_type, cb, user_data);
	if (ok) {
		++count;
		PLUGIN.flags &= ~PLUGIN_UNL;
	}
	return ok;
}

bool simple_hooker::unhook(hook_type_t hook_type, hook_cb_t *cb, void *user_data) {
	if (count <= 0) return true; // not hooked
	const int i = unhook_from_notification_point(hook_type, cb, user_data);
	_ASSERTE(i >= 0);
	_ASSERTE(i <= count);
	count -= std::min<uint>(i, count);
	return i > 0;
}

bool simple_hooker::activate(bool on) {
	_ASSERTE(count <= 1);
	return on == is_active()
		|| (this->*(on ? hook : unhook))(hook_type, cb, user_data);
}

bool simple_hooker::activate(void *ud) {
	if (user_data != ud) {
		if (is_active() && !deactivate()) return false;
		user_data = ud;
	}
	return activate();
}

bool multi_hooker::activate(bool on, void *ud) {
	if (ud == NULL) ud = user_data;
	bool ok;
	if (on) {
		if ((ok = hook(hook_type, cb, ud)) && ud != user_data) _M_uds.insert(ud);
	} else {
		if ((ok = unhook(hook_type, cb, ud)) && ud != user_data) {
			_ASSERTE(_M_uds.find(ud) != _M_uds.end());
			_M_uds.erase(ud);
		}
	}
	return ok;
}

void multi_hooker::deactivate_all() {
	if (!is_hooked()) return;
	std::for_each(CONTAINER_RANGE(_M_uds),
		boost::bind(simple_hooker::unhook, this, hook_type, cb, _1));
	_M_uds.clear();
}

bool variatic_hooker::activate(hook_type_t hook_type, hook_cb_t cb, bool on, void *ud) {
	if (ud == NULL) ud = user_data;
	bool ok;
	const hook_descr_t hook_descr(hook_type, cb, ud);
	if (on) {
		if (ok = hook(hook_type, cb, ud)) _M_hooks.insert(hook_descr);
	} else {
		if (ok = unhook(hook_type, cb, ud)) {
			_ASSERTE(_M_hooks.find(hook_descr) != _M_hooks.end());
			_M_hooks.erase(hook_descr);
		}
	}
	return ok;
}

void variatic_hooker::deactivate_all() {
	if (!is_hooked()) return;
	std::for_each(CONTAINER_RANGE(_M_hooks),
		boost::bind(simple_hooker::unhook, this,
			boost::bind(&hook_descr_t::hook_type, _1),
			boost::bind(&hook_descr_t::cb, _1),
			boost::bind(&hook_descr_t::user_data, _1)));
	_M_hooks.clear();
}
