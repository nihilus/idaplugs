
/*****************************************************************************
 *                                                                           *
 *  plugstrm.hpp: ida common library stream routines implementation          *
 *  (c) 2006-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef _PLUGSTRM_HPP_
#define _PLUGSTRM_HPP_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#pragma warning(disable:   47) // incompatible redefinition of macro "XXX"
#elif defined(_MSC_VER)
#pragma warning(disable: 4005) // macro redefinition
#endif

#include "undbgnew.h"
#include "mscrtdbg.h"
#include <ostream>
#define BYTES_SOURCE                1
#include "idasdk.hpp"
#include "dbgnew.h"

extern std::ostream cmsg; // streamed frontend to log window output

#if defined(_MSC_VER) && (_MSC_VER < 1300)

#define CUSTOM_TYPE_OSTREAM_IMPL0(from, to) \
	template<class _CharT, class _Traits>std::basic_ostream<_CharT, _Traits> \
	&operator<<(std::basic_ostream<_CharT, _Traits> &__os, const from __n) { \
		__os << static_cast<to>(__n); \
		return __os; \
	}
#define CUSTOM_TYPE_OSTREAM_IMPL(from, to) \
	CUSTOM_TYPE_OSTREAM_IMPL0(unsigned from, unsigned to) \
	CUSTOM_TYPE_OSTREAM_IMPL0(from, to)
CUSTOM_TYPE_OSTREAM_IMPL(__int32, long)
CUSTOM_TYPE_OSTREAM_IMPL(__int16, short)
CUSTOM_TYPE_OSTREAM_IMPL(__int8, int/*char*/)
#undef CUSTOM_TYPE_OSTREAM_IMPL0
#undef CUSTOM_TYPE_OSTREAM_IMPL

#endif // VC6 and older

//////////////////////////////////////////////////////////
// std::ostream format manipulators for commonly used types

template<class _ValT>struct _S_PutInt {
//BOOST_STATIC_ASSERT(boost::is_integral<_ValT>::value)
	typedef _S_PutInt manip_type;
	typedef _ValT value_type;
	value_type _M_value;
	std::ios_base::fmtflags _M_flags, _M_clrmask;
	std::streamsize _M_width, _M_precision;
	char _M_fill;
	bool _M_prefix;

	explicit _S_PutInt(value_type __v, std::ios_base::fmtflags flags,
		std::ios_base::fmtflags clrmask, std::streamsize width,
		std::streamsize precision, bool prefix, char fill) :
		_M_value(__v), _M_flags(flags), _M_clrmask(clrmask), _M_width(width),
		_M_precision(std::numeric_limits<value_type>::is_integer ? 0 : precision),
		_M_fill(fill), _M_prefix(std::numeric_limits<value_type>::is_integer ?
		prefix : false) { }
};

template<class _ValT>
_S_PutInt<_ValT> ashex(_ValT __v, bool prefix = true, bool uppercase = true) {
	return _S_PutInt<_ValT>(__v, std::ios_base::hex | (uppercase ?
		std::ios_base::uppercase : 0), std::ios_base::uppercase, 0, 0, prefix, ' ');
}

template<class _ValT>
_S_PutInt<_ValT> ashex(_ValT __v, std::streamsize width,
	bool prefix = false, char fill = '0', bool uppercase = true) {
	return _S_PutInt<_ValT>(__v,
		std::ios_base::hex | std::ios_base::right | (uppercase ?
		std::ios_base::uppercase : 0), std::ios_base::uppercase,
		width, 0, prefix, prefix ? '0' : fill);
}

struct asea : _S_PutInt<ea_t> {
	explicit asea(value_type ea) : manip_type(ea,
		std::ios_base::hex | std::ios_base::uppercase | std::ios_base::right, 0,
		sizeof(value_type) << 1, 0, false, '0') { }
};

struct asptr : _S_PutInt<uint> {
	explicit asptr(const void *pv) : manip_type(reinterpret_cast<value_type>(pv),
		std::ios_base::hex | std::ios_base::uppercase | std::ios_base::right,
		0, sizeof(value_type) << 1, 0, false, '0') { }
	explicit asptr(value_type __v) : manip_type (__v,
		std::ios_base::hex | std::ios_base::uppercase | std::ios_base::right,
		0, sizeof(value_type) << 1, 0, false, '0') { }
};

template<class _ValT>
std::ostream &operator<<(std::ostream &__os, const _S_PutInt<_ValT> &__m) {
	std::ios_base::fmtflags clearmask(__m._M_clrmask | std::ios_base::showbase);
	if ((__m._M_flags & std::ios_base::adjustfield) != 0) clearmask |= std::ios_base::adjustfield;
	if ((__m._M_flags & std::ios_base::basefield) != 0) clearmask |= std::ios_base::basefield;
	if ((__m._M_flags & std::ios_base::floatfield) != 0) clearmask |= std::ios_base::floatfield;
	__os.unsetf(clearmask);
	if (__m._M_flags != 0) __os.setf(__m._M_flags);
	if (__m._M_prefix) {
		__os.width(0);
		switch (__os.flags() & std::ios_base::basefield) {
			case std::ios_base::hex: __os << __os.widen('0') << __os.widen('x'); break;
			case std::ios_base::oct: __os << __os.widen('0'); break;
		}
	}
	if (__m._M_width > 0) {
		__os.width(__m._M_width);
		__os.fill(__os.widen(__m._M_fill));
	}
	if (!std::numeric_limits<_S_PutInt<_ValT>::value_type>::is_integer)
		__os.precision(__m._M_precision);
	return sizeof(_S_PutInt<_ValT>::value_type) > 1 ? __os << __m._M_value :
		std::numeric_limits<_S_PutInt<_ValT>::value_type>::is_signed ?
		__os << static_cast<signed short>(__m._M_value) : __os <<
			static_cast<uint16>(__m._M_value);
}

struct asshex : _S_PutInt<sval_t> {
	explicit asshex(value_type __v, bool prefix = true, bool uppercase = true) :
		manip_type(__v, std::ios_base::hex | (uppercase ? std::ios_base::uppercase : 0),
		std::ios_base::uppercase, 0, 0, prefix, ' ') { }
	explicit asshex(value_type __v, std::streamsize width, bool prefix = false,
		char fill = '0', bool uppercase = true) :
		manip_type(__v, std::ios_base::hex | std::ios_base::right | (uppercase ? std::ios_base::uppercase : 0),
		std::ios_base::uppercase, width, 0, prefix, prefix ? '0' : fill) { }
};

std::ostream &operator<<(std::ostream &__os, const asshex &__m);

size_t _M_put_wstr(std::ostream &__os, const wchar_t *const ws, size_t length = (size_t)-1);
inline std::ostream &operator<<(std::ostream &__os, const wchar_t *ws) {
	_M_put_wstr(__os, ws);
	return __os;
}
inline std::ostream &operator<<(std::ostream &__os, const std::wstring &ws) {
	_M_put_wstr(__os, ws.data(), ws.length());
	return __os;
}

// returns: 0 if signature not present or general error, BADADDR if search
// performed but no match, otherwise ea of pattern in the disassembly
// if sigfile omitted then signs.txt in ida plugins dir is used (if any)
ea_t find_signature(const char *s, const char *sigfile = 0);

#endif // _PLUGSTRM_HPP_
