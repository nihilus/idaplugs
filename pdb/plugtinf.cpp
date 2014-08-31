
/*****************************************************************************
 *                                                                           *
 * plugtinf.cpp: helpers for ida typeinfo handling                           *
 * (c) 2003-2008 servil                                                      *
 *                                                                           *
 *****************************************************************************/

#include "plugtinf.hpp"

type_api_traits::type_api_traits() throw() {
	HMODULE hIdaWll;
#ifdef __X64__ // 64-bit kernel
	if ((hIdaWll = GetModuleHandle("IDA64.WLL")) == NULL)
#endif
	hIdaWll = GetModuleHandle("IDA.WLL");
	_ASSERTE(hIdaWll != NULL);
#	define GET_DYNPROC_PTR(Name) p##Name = (Name##_t)GetProcAddress(hIdaWll, #Name);
	GET_DYNPROC_PTR(get_ptr_object_size)
	GET_DYNPROC_PTR(build_array_type)
	GET_DYNPROC_PTR(print_type_to_qstring)
#	undef GET_DYNPROC_PTR
}

#define DECL_DYNPROC_PTR(Name) type_api_traits::Name##_t type_api_traits::p##Name;
DECL_DYNPROC_PTR(get_ptr_object_size)
DECL_DYNPROC_PTR(build_array_type)
DECL_DYNPROC_PTR(print_type_to_qstring)
#undef DECL_DYNPROC_PTR

void dt::__set(uint16 __n) throw(std::exception) {
	_ASSERTE(__n <= MAX_DT);
	if (__n > MAX_DT) std::__stl_throw_out_of_range("dt value too high");
	::set_dt(t, __n);
	_ASSERTE(operator uint16() == __n);
}

dt::operator uint16() const throw(std::exception) {
	const_pointer pt(t);
	const int r = ::get_dt(pt);
	if (r < 0) throw std::logic_error("not a valid dt sequence");
	return static_cast<uint16>(r);
}

de::operator ulong() const throw(std::exception) {
	const_pointer pt(t);
	ulong val;
	if (!::get_de(pt, &val)) throw std::logic_error("not a valid de sequence");
	return val;
}

argloc_t argloc::make_argloc(RegNo loreg, RegNo hireg) {
#if IDP_INTERFACE_VERSION >= 76
	if (kernel_version >= 5.1) return ::make_argloc(loreg, hireg); // new scheme
#endif
	// old scheme
	argloc_t a;
	if (loreg == R_none) // push on stack
#if IDP_INTERFACE_VERSION >= 76
		a = 0x80;
#else
		a = 0;
#endif
	else {
		a = loreg + 1 & 0x7F;
		if (static_cast<int>(hireg) >= 0) a |= (hireg + 1 & 0x7F) << 8;
	}
	return a;
}

template<>
int __basic_tstring<type_t>::get_dt(const __basic_tstring<type_t>::size_type _Off) const throw(std::exception) {
	_ASSERTE(_Off >= 0 && _Off < size());
	if (_Off < 0 || _Off >= size()) std::__stl_throw_out_of_range("offset out of range");
	const_pointer p(operator const_pointer() + _Off);
#ifdef _DEBUG
	const int result = ::get_dt(p);
	if (result < 0) _RPT4(_CRT_WARN, "%s(0x%IX): %s(...) returned %i\n",
		__FUNCTION__, _Off, "::get_dt", result);
	return result;
#else
	return ::get_dt(p);
#endif
}

#if IDP_INTERFACE_VERSION >= 76

#if !defined(BAD_ARGLOC)

// new scheme
ulong make_argloc(int r1, int r2) {
	ulong a = 0;
	if ( r1 != -1 ) a |= 0x80000000L | r1;
	if ( r2 != -1 ) a |= 0x40000000L | (r2 << 15);
	return a;
}

#endif // !BAD_ARGLOC

asize_t argloc::get_stack_offset() const throw (std::exception) {
	if (kernel_version < 5.1) throw std::logic_error("not available");
	return is_stack() ? data & ~(ARGLOC_REG | ARGLOC_REG2) : 0;
}

typestring typestring::toArray(int size) const {
	qtype qt;
	return type_api_traits::build_array_type(&qt, operator const_pointer(), size) ?
		typestring(qt) : typestring();
}

std::string typestring::toString(int flags, const char *name,
	const char *prefix, int indent, const char *cmt, int cmtindent,
	const p_list *field_names, const p_list *field_cmts) const {
	qstring ostr;
	return type_api_traits::print_type_to_qstring(&ostr, prefix, indent,
		cmtindent, flags, idati, operator const_pointer(), name, cmt,
			field_names, field_cmts) >= 0 ? ostr.c_str() : std::string();
}

#endif // IDP_INTERFACE_VERSION

typestring &typestring::append(const argloc &a) {
	if (a.is_reg()) {
		if (a.is_hireg()) push_back(a.get_hireg() + 1 | 0x80);
		push_back(a.get_reg() + 1);
	} else 	if (a.is_stack())
#if IDP_INTERFACE_VERSION < 76
		push_back(0x80); // ??? (not too clear from sdk)
#else
		push_back(0x80);
#endif
#ifdef _DEBUG
	else
		_RPT1(_CRT_WARN, "%s(const argloc_t &): invalid argloc value\n", __FUNCTION__);
#endif // _DEBUG
	return *this;
}

typestring &typestring::before(const argloc &a) {
	if (a.is_reg()) {
		push_front(a.get_reg() + 1);
		if (a.is_hireg()) push_front(a.get_hireg() + 1 | 0x80);
	} else if (a.is_stack())
#if IDP_INTERFACE_VERSION < 76
		push_front(0x80); // ??? (not too clear from sdk)
#else
		push_front(0x80);
#endif
#ifdef _DEBUG
	else
		_RPT1(_CRT_WARN, "%s(const argloc_t &): invalid argloc value\n", __FUNCTION__);
#endif // _DEBUG
	return *this;
}

uint16 typestring::get_dt(typestring::size_type _Off) const throw(std::exception) {
	const int r = __super::get_dt(_Off);
	if (r < 0) throw std::logic_error("not a valid dt sequence");
	return static_cast<uint16>(r);
}

bool typestring::get_dt(uint16 &val, typestring::size_type _Off) {
	const int r = __super::get_dt(_Off);
	val = static_cast<uint16>(r);
	return r >= 0;
}

bool typestring::get_da(ulong &num_el, ulong &base, size_type _Off) const throw(std::exception) {
	_ASSERTE(_Off >= 0 && _Off < size());
	if (_Off < 0 || _Off >= size()) std::__stl_throw_out_of_range("offset out of range");
	const_pointer p(operator const_pointer() + _Off);
#ifdef _DEBUG
	bool result = ::get_da(p, &num_el, &base);
	if (!result) _RPT3(_CRT_WARN, "%s(..., 0x%IX): %s(...) returned false\n",
		__FUNCTION__, _Off, "::get_da");
	return result;
#else
	return ::get_da(p, &num_el, &base);
#endif
}

ulong typestring::get_de(size_type _Off) const throw(std::exception) {
	_ASSERTE(_Off >= 0 && _Off < size());
	if (_Off < 0 || _Off >= size()) std::__stl_throw_out_of_range("offset out of range");
	const_pointer p(operator const_pointer() + _Off);
	ulong val;
	if (!::get_de(p, &val)) throw std::logic_error("not a valid de sequence");
	return val;
}

bool typestring::get_de(ulong &val, size_type _Off) const throw(std::exception) {
	_ASSERTE(_Off >= 0 && _Off < size());
	if (_Off < 0 || _Off >= size()) std::__stl_throw_out_of_range("offset out of range");
	const_pointer p(operator const_pointer() + _Off);
#ifdef _DEBUG
	bool result(::get_de(p, &val));
	if (!result) _RPT3(_CRT_WARN, "%s(..., 0x%IX): %s(...) returned false\n",
		__FUNCTION__, _Off, "::get_de");
	return result;
#else
	return ::get_de(p, &val);
#endif
}

pstring &pstring::append(const_pointer _Ptr) {
	_ASSERTE(_Ptr != 0);
	if (_Ptr != 0 && *_Ptr != 0) {
		const int _Length = ::get_dt(_Ptr);
		if (_Length < 0) throw std::logic_error("couldnot get pstring length");
		assign(get_string().append((std::string::const_pointer)_Ptr,
			static_cast<size_type>(_Length)));
	}
	return *this;
}

pstring::size_type pstring::get_length() const throw(std::exception) {
	if (empty()) return 0;
	const int _Length = get_dt();
	if (_Length < 0) throw std::logic_error("couldnot get pstring length");
	return static_cast<size_type>(_Length);
}

std::string pstring::get_string() const throw(std::exception) {
	std::string result;
	if (!empty()) {
		const_pointer p(operator const_pointer());
		const int _Length = ::get_dt(p);
		if (_Length < 0) throw std::logic_error("couldnot get pstring length");
		result.assign((std::string::const_pointer)p, _Length);
	}
	return result;
}

pstring &pstring::append(const char *ps) {
	_ASSERTE(ps != 0);
	if (ps != 0 && *ps != 0) assign(get_string() + ps);
	return *this;
}

plist &plist::operator =(plist::const_pointer _Ptr) {
	assign(_Ptr);
	reset();
	return *this;
}

plist &plist::operator =(const plist::_Self &_Other) {
	assign(_Other);
	reset();
	return *this;
}

plist &plist::append(plist::const_pointer _Ptr) {
	bool __empty(empty());
	_Self::append(_Ptr);
	if (__empty) reset();
	return *this;
}

plist &plist::append(const plist::_Self &_Other) {
	bool __empty(empty());
	_Self::append(_Other);
	if (__empty) reset();
	return *this;
}

plist &plist::append(const char *ps) {
	bool __empty(empty());
	append_pstring(ps);
	if (__empty) reset();
	return *this;
}

std::string plist::next_pstring() const throw(std::exception) {
	if (empty() || it == end()) return std::string();
	//if (*it == 0) std::__stl_throw_invalid_argument("no pstring length"); //it = t.end();
	const size_type _Pos = std::distance(begin(), it);
	const int _Length = get_dt(_Pos);
	if (_Length < 0) throw std::logic_error("couldnot get pstring length");
	const size_type _Offset = _Length < 0x7F ? 1 : 2;
	std::advance(it, _Offset + _Length);
	return std::string((std::string::const_pointer)operator const_pointer() +
		_Pos + _Offset, _Length);
}
