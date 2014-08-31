
/******************************************************************************
 *                                                                            *
 * idasdk.hpp: IDA SDK front-end                                              *
 * (c) 2003-2008 servil <servil@gmx.net>                                      *
 *                                                                            *
 ******************************************************************************/

#ifndef _IDASDK_HPP_
#define _IDASDK_HPP_

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#pragma warning(disable: 47) // incompatible redefinition of macro "XXX"
#endif

#define __IDP__                     1
/*
#define BYTES_SOURCE                1
#define ENUM_SOURCE                 1
#define USE_DANGEROUS_FUNCTIONS     1
#define USE_STANDARD_FILE_FUNCTIONS 1
*/

#include "undbgnew.h"
#ifndef USE_STANDARD_FILE_FUNCTIONS
#include <cstdio>
#endif
#include <pro.h>
#include <ida.hpp>
#include <netnode.hpp>
#include <nalt.hpp>
#include <fpro.h>
#include <help.h>
#include <area.hpp>
#include <lines.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <struct.hpp>
#include <enum.hpp>
#include <offset.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <loader.hpp>
#include <llong.hpp>
#include <kernwin.hpp>
#include <auto.hpp>
#include <ua.hpp>
#include <diskio.hpp>
#include <search.hpp>
#include <entry.hpp>
#include <fixup.hpp>
#include <ints.hpp>
#include <queue.hpp>
#include <idp.hpp>
#include <srarea.hpp>
#include <typeinf.hpp>
#include <ieee.h>
#include <expr.hpp>
#include <allins.hpp>
#include <compress.hpp>
#include <demangle.hpp>
#include <err.h>
#include <exehdr.h>
#include <gdl.hpp>
#include <md5.h>
#include <sistack.hpp>
#include <moves.hpp>
#include <prodir.h>
#include <regex.h>
#include <strlist.hpp>
#include <vm.hpp>
#include <va.hpp>
#if IDP_INTERFACE_VERSION >= 63
#include <idd.hpp>
#if IDP_INTERFACE_VERSION >= 66
#include <dbg.hpp>
#if IDP_INTERFACE_VERSION >= 76
#include <lex.hpp>
#ifdef SFL_HIDETYPE /* ENUM_SIZE ? */
#include <graph.hpp> /* IDA >= 5.0 */
#endif /* SDK >= 5.0 */
#endif /* SDK >= 4.9 */
#endif /* SDK >= 4.6 */
#endif /* SDK >= 4.5 */
#include <intel.hpp>

#ifndef IDA_SDK_VERSION
#	if IDP_INTERFACE_VERSION >= 76
#		if defined(QASSERT) // pro.h
#			define IDA_SDK_VERSION 510
#		elif defined(SFL_HIDETYPE)/* || defined(ENUM_SIZE)*/ // segment.hpp
#			define IDA_SDK_VERSION 500
#		else
#			define IDA_SDK_VERSION 490
#		endif
#	elif IDP_INTERFACE_VERSION >= 75
#		define IDA_SDK_VERSION 480
#	elif IDP_INTERFACE_VERSION >= 70
#		define IDA_SDK_VERSION 470
#	elif IDP_INTERFACE_VERSION >= 66
#		define IDA_SDK_VERSION 460
#	elif IDP_INTERFACE_VERSION >= 63
#		define IDA_SDK_VERSION 450
#	elif IDP_INTERFACE_VERSION >= 61
#		define IDA_SDK_VERSION 430
#	else
#		define IDA_SDK_VERSION
#		pragma message("WARNING: Too old IDA SDK")
#	endif
#endif

#if IDP_INTERFACE_VERSION < 76

#include "mscrtdbg.h"

#define areacb_t_get_area_cmt areacb_t_get_area_comment
#define areacb_t_set_area_cmt areacb_t_set_area_comment
#define del_area_cmt del_area_comment
#define del_func_cmt del_func_comment
#define del_segment_cmt del_segment_comment
#define get_any_indented_cmt get_any_cmt
#define get_area_cmt get_area_comment
#define get_func_cmt get_func_comment
#define get_repeatable_cmt get_rpt_cmt
#define get_segment_cmt get_segment_comment
#define guess_table_address guessTableAddress
#define guess_table_size guessTableSize
#define set_area_cmt set_area_comment
#define set_func_cmt set_func_comment
#define set_segment_cmt set_segment_comment
inline flags_t get_flags_ex(ea_t ea, int) { return ::getFlags(ea); }
inline flags_t get_flags_novalue(ea_t ea) { return ::getFlags(ea); }
inline bool is_resolved_type_struni(const type_t *type) {
	return is_resolved_type_struct(type) || is_resolved_type_union(type);
}

/* safe adaptors to new api model */
#ifdef _DEBUG
#	define ADAPTOR(type, theCall) return ida::safe_##type##_call(buf, theCall, bufsize, __FUNCTION__);
#else
#	define ADAPTOR(type, theCall) return ida::safe_##type##_call(buf, theCall, bufsize);
#endif /* _DEBUG */

namespace ida {

ssize_t safe_string_call(char *buf, const char *s, size_t bufsize
#ifdef _DEBUG
	, const char *funcname
#endif
	);
ssize_t safe_void_call(void *buf, const void *v, size_t bufsize
#ifdef _DEBUG
	, const char *funcname
#endif
	);

} /* namespace ida */

inline ssize_t get_root_filename(char *buf, size_t bufsize)
	{ ADAPTOR(string, get_root_filename()) }
inline ssize_t get_input_file_path(char *buf, size_t bufsize)
	{ ADAPTOR(string, get_input_file_path()) }
inline ssize_t get_asm_inc_file(char *buf, size_t bufsize)
	{ ADAPTOR(string, get_asm_inc_file()) }
inline ssize_t get_segm_name(const segment_t *seg, char *buf, size_t bufsize) {
	_ASSERTE(seg != 0);
	ADAPTOR(string, seg != 0 ? get_segm_name(seg) : 0)
}
inline ssize_t get_segm_name(ea_t ea, char *buf, size_t bufsize) {
	_ASSERTE(isEnabled(ea));
	ADAPTOR(string, get_segm_name(ea))
}
inline ssize_t get_true_segm_name(const segment_t *seg, char *buf, size_t bufsize) {
	_ASSERTE(seg != 0);
	ADAPTOR(string, seg != 0 ? get_true_segm_name(seg) : 0)
}
inline ssize_t get_segm_class(const segment_t *seg, char *buf, size_t bufsize) {
	_ASSERTE(seg != 0);
	ADAPTOR(string, seg != 0 ? get_segm_class(seg) : 0)
}
ssize_t get_array_parameters(ea_t ea, array_parameters_t *buf, size_t bufsize);
inline ssize_t ExtraGet(ea_t ea, int what, char *buf, size_t bufsize) {
	_ASSERTE(isEnabled(ea));
	ADAPTOR(string, ExtraGet(ea, what))
}
inline ssize_t get_forced_operand(ea_t ea, int n, char *buf, size_t bufsize) {
	_ASSERTE(isEnabled(ea));
	_ASSERTE(n < UA_MAXOP);
	ADAPTOR(string, get_forced_operand(ea, n))
}
inline ssize_t get_cmt(ea_t ea, bool rptble, char *buf, size_t bufsize) {
	_ASSERTE(isEnabled(ea));
	ADAPTOR(string, get_cmt(ea, rptble))
}
inline ssize_t get_struc_name(tid_t id, char *buf, size_t bufsize) {
	_ASSERTE(id != BADNODE);
	ADAPTOR(string, id != BADNODE ? get_struc_name(id) : 0)
}
inline ssize_t get_struc_cmt(tid_t id, bool repeatable, char *buf, size_t bufsize) {
	_ASSERTE(id != BADNODE);
	ADAPTOR(string, id != BADNODE ? get_struc_cmt(id, repeatable) : 0)
}
inline ssize_t get_member_fullname(tid_t mid, char *buf, size_t bufsize) {
	_ASSERTE(mid != BADNODE);
	ADAPTOR(string, mid != BADNODE ? get_member_fullname(mid) : 0)
}
inline ssize_t get_member_name(tid_t mid, char *buf, size_t bufsize) {
	_ASSERTE(mid != BADNODE);
	ADAPTOR(string, mid != BADNODE ? get_member_name(mid) : 0)
}
inline ssize_t get_member_cmt(tid_t mid, bool repeatable, char *buf, size_t bufsize) {
	_ASSERTE(mid != BADNODE);
	ADAPTOR(string, mid != BADNODE ? get_member_cmt(mid, repeatable) : 0)
}
inline ssize_t get_enum_name(enum_t id, char *buf, size_t bufsize) {
	_ASSERTE(id != BADNODE);
	ADAPTOR(string, id != BADNODE ? get_enum_name(id) : 0)
}
inline ssize_t get_enum_cmt(enum_t id, bool repeatable, char *buf, size_t bufsize) {
	_ASSERTE(id != BADNODE);
	ADAPTOR(string, id != BADNODE ? get_enum_cmt(id, repeatable) : 0)
}
inline ssize_t get_const_name(const_t id, char *buf, size_t bufsize) {
	_ASSERTE(id != BADNODE);
	ADAPTOR(string, id != BADNODE ? get_const_name(id) : 0)
}
inline ssize_t get_const_cmt(const_t id, bool repeatable, char *buf, size_t bufsize) {
	_ASSERTE(id != BADNODE);
	ADAPTOR(string, id != BADNODE ? get_const_cmt(id, repeatable) : 0)
}
inline ssize_t get_bmask_name(enum_t id,bmask_t bmask, char *buf, size_t bufsize) {
	_ASSERTE(id != BADNODE);
	ADAPTOR(string, id != BADNODE ? get_bmask_name(id, bmask) : 0)
}
inline ssize_t get_bmask_cmt(enum_t id,bmask_t bmask, bool repeatable, char *buf, size_t bufsize) {
	_ASSERTE(id != BADNODE);
	ADAPTOR(string, id != BADNODE ? get_bmask_cmt(id, bmask, repeatable) : 0)
}
inline ssize_t get_entry_name(uval_t ord, char *buf, size_t bufsize)
	{ ADAPTOR(string, get_entry_name(ord)) }
inline ssize_t get_type_name(flags_t flag, ea_t ea_or_id, char *buf, size_t bufsize)
	{ ADAPTOR(string, get_type_name(flag, ea_or_id)) /* NOT EXPORTED */ }
inline ssize_t get_loader_name(char *buf, size_t bufsize)
	{ ADAPTOR(string, get_loader_name()) }
inline ssize_t get_name_expr(ea_t from, int n, ea_t ea, adiff_t off, char *buf, size_t bufsize, int flags=GETN_APPZERO) {
	_ASSERTE(isEnabled(ea));
	ADAPTOR(string, get_name_expr(from, n, ea, off))
}

size_t btoa32(char *buf, size_t bufsize, ulong x, int radix=0);
size_t btoa64(char *buf, size_t bufsize, ulonglong x, int radix=0);
size_t btoa128(char *buf, size_t bufsize, uint128 x, int radix=0);

namespace ida {

class safe_netnode_adaptor : public netnode {
public:
	inline safe_netnode_adaptor() throw() { }
	inline safe_netnode_adaptor(nodeidx_t num) throw() : netnode(num) { }
	inline safe_netnode_adaptor(const char *name, size_t namlen=0,
		bool do_create=false) : netnode(name, namlen, do_create) { }

	/* inherit old-style interface */
	inline char *name(void) const { return __super::name(); }
	inline char *supval(sval_t alt, char tag=stag) const { return __super::supval(alt,tag); }
	inline char *supval_idx8(uchar alt,char tag) const { return __super::supval_idx8(alt,tag); }
	inline char *hashval(const char *idx,char tag=htag) const { return __super::hashval(idx,tag); }
	inline char *hash1st(char tag=htag) const { return __super::hash1st(tag);}
	inline char *hashnxt(const char *idx,char tag=htag) const { return __super::hashnxt(idx,tag); }
	inline char *hashlast(char tag=htag) const { return __super::hashlast(tag); }
	inline char *hashprev(const char *idx,char tag=htag) const { return __super::hashprev(idx,tag); }
#ifndef __GNUC__
	inline char *linkspec(netnode to,netlink linktype) const { return __super::linkspec(to,linktype); }
#endif

	/* new-style adaptors */
	inline ssize_t name(char *buf, size_t bufsize) const
		{ ADAPTOR(string, __super::name()) }
	inline ssize_t valobj(void *buf, size_t bufsize) const
		{ ADAPTOR(void, __super::value()) }
	inline ssize_t valstr(char *buf, size_t bufsize) const
		{ ADAPTOR(string, __super::value()) }
	inline ssize_t supval(sval_t alt, void *buf, size_t bufsize, char tag=stag) const
		{ ADAPTOR(void, __super::supval(alt, tag)) }
	inline ssize_t supstr(sval_t alt, char *buf, size_t bufsize, char tag=stag) const
		{ ADAPTOR(string, __super::supval(alt, tag)) }
	inline ssize_t supval_idx8(uchar alt, void *buf, size_t bufsize, char tag=stag) const
		{ ADAPTOR(void, __super::supval_idx8(alt, tag)) }
	inline ssize_t supstr_idx8(uchar alt, char *buf, size_t bufsize, char tag=stag) const
		{ ADAPTOR(string, __super::supval_idx8(alt, tag)) }
	inline ssize_t hashval(const char *idx, void *buf, size_t bufsize, char tag=htag) const
		{ ADAPTOR(void, __super::hashval(idx, tag)) }
	inline ssize_t hashstr(const char *idx, char *buf, size_t bufsize, char tag=htag) const
		{ ADAPTOR(string, __super::hashval(idx, tag)) }
	inline ssize_t hash1st(char *buf, size_t bufsize, char tag=htag) const
		{ ADAPTOR(string, __super::hash1st(tag)) }
	inline ssize_t hashnxt(const char *idx, char *buf, size_t bufsize, char tag=htag) const
		{ ADAPTOR(string, __super::hashnxt(idx, tag)) }
	inline ssize_t hashlast(char *buf, size_t bufsize, char tag=htag) const
		{ ADAPTOR(string, __super::hashlast(tag)) }
	inline ssize_t hashprev(const char *idx, char *buf, size_t bufsize, char tag=htag) const
		{ ADAPTOR(string, __super::hashprev(idx, tag)) }
#ifndef __GNUC__
	inline ssize_t linkspec(netnode to, char *buf, size_t bufsize, netlink linktype) const
		{ ADAPTOR(string, __super::linkspec(to, linktype)) }
#endif
}; /* safe_netnode_adaptor */

} /* namespace ida */

#define netnode ida::safe_netnode_adaptor
#undef ADAPTOR

#endif /* IDP_INTERFACE_VERSION < 76 */

#include "dbgnew.h"

/* force back full VC6 extension compatibility (non-ANSI conformance) */
#ifdef for
#undef for
#endif

#endif /* _IDASDK_HPP_ */
