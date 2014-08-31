
/*****************************************************************************
 *                                                                           *
 * plugtinf.hpp: helpers for ida typeinfo handling                           *
 * (c) 2003-2008 servil                                                      *
 *                                                                           *
 *****************************************************************************/

#ifndef _PLUGTINF_HPP_
#define _PLUGTINF_HPP_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#pragma warning(disable: 186) // pointless comparison of unsigned integer with zero
#endif

#include "undbgnew.h"
#include "mscrtdbg.h"
#include <string>
#include <algorithm>
#include <stdexcept>
#define BYTES_SOURCE                1
#include "idasdk.hpp"
#include "plughlpr.hpp"
#include "dbgnew.h"

#if IDA_SDK_VERSION < 510
#define R_none static_cast<RegNo>(-1)
#endif

// ******************** type_t strings helpers ********************

namespace std {
template<>class char_traits<type_t> : public __char_traits_base<type_t, int> {
#if IDA_SDK_VERSION < 520
private:
	static inline int typncmp(const char_type *dst, const char_type *src, size_t size)
		{ return strncmp((const char *)dst, (const char *)src, size); }
#endif
public:
	static inline int compare(const char_type* __s1, const char_type* __s2, size_t __n)
		{ return typncmp(__s1, __s2, __n); }
	static inline size_t length(const char_type* __s)
		{ return typlen(__s); }
	static inline char_type* assign(char_type* __s, size_t __n, char_type __c)
		{ memset(__s, __c, __n); return __s; }
	static inline void assign(char_type& __c1, const char_type& __c2)
		{ __super::assign(__c1, __c2); }
};
} // std

#if IDA_SDK_VERSION < 510
class qtype;
#endif

class type_api_traits {
private:
	typedef int (idaapi *get_ptr_object_size_t)(til_t *, const type_t *);
	typedef bool (idaapi *build_array_type_t)(qtype *, const type_t *, int);
	typedef ssize_t (idaapi *print_type_to_qstring_t)(qstring *, const char *,
		int, int, int, const til_t *, const type_t *, const char *, const char *,
		const p_list *, const p_list *);

#	define DECL_DYNPROC_PTR(Name) static Name##_t p##Name;
	DECL_DYNPROC_PTR(get_ptr_object_size)
	DECL_DYNPROC_PTR(build_array_type)
	DECL_DYNPROC_PTR(print_type_to_qstring)
#	undef DECL_DYNPROC_PTR

public:
	type_api_traits() throw();

	inline static int get_ptr_object_size(til_t *til, const type_t *type) {
		return pget_ptr_object_size != NULL ? pget_ptr_object_size(til, type) :
			get_pointer_object_size(type);
	}
	inline static bool build_array_type(qtype *outtype, const type_t *type, int size) {
		return pbuild_array_type != NULL ? pbuild_array_type(outtype, type, size) : false;
	}
	inline static ssize_t print_type_to_qstring(qstring *result,
		const char *prefix, int indent, int cmtindent, int flags, const til_t *ti,
		const type_t *pt, const char *name=NULL, const char *cmt=NULL,
		const p_list *field_names=NULL, const p_list *field_cmts=NULL) {
		return pprint_type_to_qstring != NULL ? pprint_type_to_qstring(result,
			prefix, indent, cmtindent, flags, ti, pt, name, cmt, field_names,
				field_cmts) : -1;
	}
};  // type_api_traits

#if IDP_INTERFACE_VERSION >= 76
#if !defined(BAD_ARGLOC)
ulong make_argloc(int r1, int r2);
#endif
extern const double kernel_version;
#endif

struct argloc {
#if IDP_INTERFACE_VERSION >= 76 && !defined(BAD_ARGLOC)
public:
	typedef ulong argloc_t;

private:
	static inline bool is_reg_argloc(ulong argloc)
		{ return (argloc & 0x80000000L) != 0; }
	static inline bool is_stack_argloc(ulong argloc)
		{ return !is_reg_argloc(argloc); }
	static inline bool is_reg2_argloc(ulong reg_argloc)
		{ return (reg_argloc & 0x40000000L) != 0; }
	static inline int get_argloc_r1(ulong reg_argloc)
		{ return (reg_argloc & 0x7FFF); }
	static inline int get_argloc_r2(ulong reg_argloc)
		{ return (reg_argloc >> 15) & 0x7FFF; }
#endif
private:
	argloc_t data;

	inline uint8 get_old_scheme_reg_bits(int n) const
		{ return data >> (n - 1 << 3) & 0x7F; }
	static argloc_t make_argloc(RegNo loreg, RegNo hireg);

public:
	inline argloc(RegNo loreg = R_none/*=pushed on stack*/, RegNo hireg = R_none/*=not used*/)
		: data(make_argloc(loreg, hireg)) { }

	bool is_reg(int n = 1) const {
		return
#if IDP_INTERFACE_VERSION >= 76
			kernel_version >= 5.1 ? n == 1 && is_reg_argloc(data)
				|| n == 2 && is_reg2_argloc(data) :
#endif
			(n == 1 || n == 2) && get_old_scheme_reg_bits(n) > 0;
	}
	inline bool is_loreg() const { return is_reg(1); }
	inline bool is_hireg() const { return is_reg(2); }
	bool is_stack() const {
		return
#if IDP_INTERFACE_VERSION >= 76
			kernel_version >= 5.1 ? is_stack_argloc(data) :
#endif
			!is_reg();
	}
	RegNo get_reg(int n = 1) const {
		return is_reg(n) ? static_cast<RegNo>(
#if IDP_INTERFACE_VERSION >= 76
			kernel_version >= 5.1 ? (n == 1 ? get_argloc_r1 : get_argloc_r2)(data) :
#endif
			get_old_scheme_reg_bits(n) - 1) : R_none;
	}
	inline RegNo get_loreg() const { return get_reg(1); }
	inline RegNo get_hireg() const { return get_reg(2); }
#if IDP_INTERFACE_VERSION >= 76
	asize_t get_stack_offset() const throw (std::exception);
#endif
}; // argloc

template<const size_t N>struct __type_encoded_number {
protected:
	type_t t[N + 1];
	inline __type_encoded_number() throw() { reset(); }
public:
	typedef const type_t *const_pointer;
	inline void reset() throw() { memset(t, 0, sizeof(t))/*std::fill_n(t, qnumber(t), 0)*/; }
	inline operator const_pointer() const throw() { return t; }
};

struct dt : public __type_encoded_number<2> {
	explicit dt(uint16 __n = 0) { __set(__n); }
	operator uint16() const throw(std::exception);
	void set(uint16 __n = 0) { reset(); __set(__n); }
private:
	void __set(uint16 __n) throw(std::exception);
};

struct da : public __type_encoded_number<9> {
	explicit da(ulong num_el = 0, ulong base = 0) { __set(num_el, base); }
	void set(ulong num_el = 0, ulong base = 0) { reset(); __set(num_el, base); }
private:
	inline void __set(ulong num_el, ulong base) {
		_ASSERTE(num_el <= 0x7FFFFFFF);
		::set_da(t, num_el, base);
#ifdef _DEBUG
		const_pointer pt(t);
		ulong __num_el, __base;
		_ASSERTE(::get_da(pt, &__num_el, &__base));
		_ASSERTE(__num_el == num_el);
		_ASSERTE(__base == base);
#endif // _DEBUG
	}
};

struct de : public __type_encoded_number<5> {
	explicit de(ulong __n = 0) { __set(__n); }
	operator ulong() const throw(std::exception);
	void set(ulong __n = 0) { reset(); __set(__n); }
private:
	inline void __set(ulong __n) {
		::set_de(t, __n);
		_ASSERTE(operator ulong() == __n);
	}
};

template<class _CharT>
class __basic_tstring : public virtual std::basic_string<_CharT> {
public:
	inline operator const_pointer() const
		{ return c_str(); }
	inline void truncate(size_type max_len = MAXSPECSIZE - 1)
		{ ::truncate(*this, max_len); }

protected:
	int get_dt(const size_type _Off = 0) const throw(std::exception);
	void append_pstring(const char *s) {
		_ASSERTE(s != 0);
		if (s != 0) append(dt(strlen(s))).append((const_pointer)s);
	}
	void append_typedef(const char *s) {
		_ASSERTE(s != 0 && *s != 0);
		if (s != 0 && *s != 0) {
			push_back(BTF_TYPEDEF);
			append_pstring(s);
		}
	}
}; // __basic_tstring

class tdef : public __basic_tstring<type_t> {
public:
	explicit tdef(const char *s) { append_typedef(s); }
	explicit tdef(const std::string &s) { append_typedef(s.c_str()); }

	void set(const char *s) {
		clear();
		append_typedef(s);
	}
	inline void set(const std::string &s) { set(s.c_str()); }
};

class typestring : public __basic_tstring<type_t> {
public:
	// construction
	typestring() { }
	explicit typestring(const_pointer _Ptr) : _Self(_Ptr) { }
	explicit typestring(value_type _Val) : _Self(1, _Val) { }
	explicit typestring(const _Self &_Other) : _Self(_Other) { }
#if IDA_SDK_VERSION >= 510
	explicit typestring(const qtype &qt) : _Self(qt.c_str()) { }
#endif

	// operator overrides
	typestring &operator =(const_pointer _Ptr)
		{ assign(_Ptr); return *this; }
	typestring &operator =(value_type _Val)
		{ _Self::operator =(_Val); return *this; }
	typestring &operator =(const _Self &_Other)
		{ assign(_Other); return *this; }
#if IDA_SDK_VERSION >= 510
	typestring &operator =(const qtype &qt)
		{ assign(qt.c_str()); return *this; }
#endif

	inline typestring &operator <<(const_pointer _Ptr)
		{ return append(_Ptr); }
	inline typestring &operator <<(value_type _Val)
		{ return append(_Val); }
	template<class T>inline typestring &operator <<(const T &t)
		{ return append(t); }

	// append(...) implementation
	typestring &append(const_pointer _Ptr)
		{ _Self::append(_Ptr); return *this; }
	typestring &append(value_type _Val)
		{ push_back(_Val); return *this; }
	typestring &append(const _Self &t)
		{ _Self::append(t); return *this; }
#if IDA_SDK_VERSION >= 510
	typestring &append(const qtype &qt)
		{ _Self::append(qt.c_str()); return *this; }
#endif
	typestring &append(const argloc &);
	template<const size_t N>
	inline typestring &append(const __type_encoded_number<N> &t)
		{ return append((const_pointer)t.operator const_pointer()); }

	// append aliases
	typestring &append_dt(uint16 value = 0)
		{ return append(dt(value)); }
	typestring &append_da(ulong num_el = 0, ulong base = 0)
		{ return append(da(num_el, base)); }
	typestring &append_de(ulong val = 0)
		{ return append(de(val)); }
	inline typestring &append_pstring(const char *ps)
		{ __super::append_pstring(ps); return *this; }
	inline typestring &append_typedef(const char *td)
		{ __super::append_typedef(td); return *this; }
	typestring &append_argloc(RegNo loreg = R_none, RegNo hireg = R_none)
		{ return append(argloc(loreg, hireg)); }
#if IDP_INTERFACE_VERSION >= 76
	// store argloc_t for CM_CC_SPECIAL{P}
	//typestring &append_argloc(RegNo loreg = R_none, RegNo hireg = R_none, bool ret = false) {
	//	type_t type[4];
	//	set_argloc(type, static_cast<int>(loreg), static_cast<int>(hireg), ret);
	//	return append(type);
	//}
	// store spoil list for __spoil<> functions
	// regs[n] must be in interval 0-127, and lens[n] 1-255.
	// if the spoil information is present, it overrides the standard spoiled registers
	//typestring &append_spoils(uint reg, uint size) {
	//	type_t type[4];
	//	set_spoils(uint reg, uint size);
	//	return append(type);
	//}
#endif // IDP_INTERFACE_VERSION >= 76

	void push_front(value_type _Val)
		{ insert(begin(), _Val); }

	// before(...) implementation
	typestring &before(const_pointer _Ptr)
		{ insert(0, _Ptr); return *this; }
	inline typestring &before(value_type _Val)
		{ push_front(_Val); return *this; }
	typestring &before(const _Self &t)
		{ insert(0, t); return *this; }
#if IDA_SDK_VERSION >= 510
	inline typestring &before(const qtype &qt)
		{ return before(qt.c_str()); }
#endif
	typestring &before(const argloc &);
	template<const size_t N>
	inline typestring &before(const __type_encoded_number<N> &t)
		{ return before((const_pointer)t.operator const_pointer()); }

	inline bool equal_to(const_pointer _Other/*, const til_t *ti = idati*/) const {
		_ASSERTE(_Other != 0);
		return _Other != 0 && equal_types(idati, operator const_pointer(), _Other);
	}
	inline bool operator ==(const_pointer _Other) const
		{ return equal_to(_Other); }
	template<class T>inline bool operator ==(const T &t) const
		{ return operator ==(t.c_str()); }
	template<class T>inline bool operator !=(const T &t) const
		{ return !operator ==(t); }

	// resolve typedef recursively if is_type_typedef(*p)
	// fields will contains the field list if the type is resolved
	inline pointer resolve_typedef(const p_list **fields=NULL) const
		{ return (pointer)::resolve_typedef(idati, operator const_pointer(), fields); }

#	define DECL_RESTYPE_SHORTCUT(t) \
	inline bool is_resolved_##t() const \
		{ return ::is_resolved_type_##t(operator const_pointer()); }
	DECL_RESTYPE_SHORTCUT(const)
	DECL_RESTYPE_SHORTCUT(void)
	DECL_RESTYPE_SHORTCUT(ptr)
	DECL_RESTYPE_SHORTCUT(func)
	DECL_RESTYPE_SHORTCUT(array)
	DECL_RESTYPE_SHORTCUT(complex)
	DECL_RESTYPE_SHORTCUT(struct)
	DECL_RESTYPE_SHORTCUT(union)
	DECL_RESTYPE_SHORTCUT(struni)
	DECL_RESTYPE_SHORTCUT(enum)
	DECL_RESTYPE_SHORTCUT(bitfld)
#	undef DECL_RESTYPE_SHORTCUT
	inline type_sign_t get_signess() const
		{ return ::get_type_signness(operator const_pointer()); }
	inline bool is_signed() const
		{ return ::is_type_signed(operator const_pointer()); }
	inline bool is_unsigned() const
		{ return ::is_type_unsigned(operator const_pointer()); }
	inline bool is_castable(const_pointer to) const
		{ return ::is_castable(operator const_pointer(), to); }
	inline bool is_castable(const _Self &to) const
		{ return ::is_castable(operator const_pointer(), to.c_str()); }
	inline bool is_scalar() const
		{ return ::is_type_scalar(operator const_pointer()); }
	inline size_t get_size(size_t *lp = NULL) const
		{ return ::get_type_size0(idati, operator const_pointer(), lp); }
	size_t get_pointer_object_size() const
		{ return static_cast<size_t>(type_api_traits::get_ptr_object_size(idati, operator const_pointer())); }

#if IDP_INTERFACE_VERSION >= 76
	typestring toArray(int size) const;
	std::string toString(int flags = 0/*PRTYPE_1LINE*/, const char *name = NULL,
		const char *prefix = NULL, int indent = 0,
		const char *cmt = NULL, int cmtindent = 0,
		const p_list *field_names = NULL, const p_list *field_cmts = NULL) const;
#endif

	// extract encoded number from position
	uint16 get_dt(size_type _Off = 0) const throw(std::exception);
	bool get_dt(uint16 &, typestring::size_type _Off = 0);
	bool get_da(ulong &num_el, ulong &base, size_type _Off = 0) const throw(std::exception);
	ulong get_de(size_type _Off = 0) const throw(std::exception);
	bool get_de(ulong &, size_type _Off = 0) const throw(std::exception);

	// convenience
	inline bool operator !() const { return empty(); }
	inline reference back() { return ::back(*this); }
	inline const_reference back() const { return ::back(*this); }
	inline size_type back_pos() const { return ::back_pos(*this); }
}; // typestring

class pstring : public __basic_tstring<p_string> {
private:
	// not allowed
	template<class T>void insert(const T &);
	template<class T>void erase(const T &);
	void push_back(value_type);

public:
	// construction
	pstring() : _Self(dt(0)) { }
	explicit pstring(const_pointer _Ptr) : _Self(_Ptr) { }
	explicit pstring(const _Self &t) : _Self(t) { }
	explicit pstring(const char *_Ptr) { append_pstring(_Ptr); }
	explicit pstring(const std::string &s) { append_pstring(s.c_str()); }

	// operator overrides
	inline pstring &operator =(const_pointer _Ptr) { return assign(_Ptr); }
	inline pstring &operator =(const char *ps) { return assign(ps); }
	template<class T>inline pstring &operator =(const T &t) { return assign(t); }

	inline pstring &operator +=(const_pointer _Ptr) { return append(_Ptr); }
	inline pstring &operator +=(const char *ps) { return append(ps); }
	template<class T>inline pstring &operator +=(const T &t) { return append(t); }

	inline pstring &assign(const_pointer _Ptr)
		{ _Self::assign(_Ptr); return *this; }
	inline pstring &assign(const _Self &t)
		{ _Self::assign(t); return *this; }
	pstring &assign(const char *ps)
		{ _Self::clear(); append_pstring(ps); return *this; }
	inline pstring &assign(const std::string &s)
		{ return assign(s.c_str()); }

	pstring &append(const_pointer);
	pstring &append(const char *);
	template<class T>inline pstring &append(const T &t)
		{ return append(t.c_str()); }

	inline operator std::string() const
		{ return get_string(); }
	std::string get_string() const throw(std::exception);
	size_type get_length() const throw(std::exception);
	void clear()
		{ _Self::assign(dt(0)); }
}; // pstring

class plist : public __basic_tstring<p_list> {
private:
	mutable const_iterator it;

public:
	// construction
	plist() : it(begin()) { }
	explicit plist(const_pointer _Ptr) : _Self(_Ptr), it(begin()) { }
	explicit plist(const _Self &_Other) : _Self(_Other), it(begin()) { }

	// operator overrides
	plist &operator =(const_pointer);
	plist &operator =(const _Self &);

	inline plist &operator <<(const_pointer _Ptr) { return append(_Ptr); }
	inline plist &operator <<(const char *ps) { return append(ps); }
	template<class T>inline plist &operator <<(const T &t) { return append(t); }

	const plist &operator >>(std::string &s) const {
		s = next_pstring();
		return *this;
	}

	// append(...) overrides
	plist &append(const_pointer);
	plist &append(const _Self &);
	plist &append(const char *);
	inline plist &append(const std::string &s)
		{ return append(s.c_str()); }

	void clear()
		{ _Self::clear(); reset(); }
	inline void reset() const
		{ it = begin(); }
	inline bool eof() const
		{ return it == end(); }
	std::string next_pstring() const throw(std::exception);
}; // plist

#endif // _PLUGTINF_HPP_
