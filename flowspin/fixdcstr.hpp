
/******************************************************************************
 *                                                                            *
 * This is fixed-length C-string adaptor suitable for assocaitive STL         *
 * containers; STL containers featured                                        *
 * (c) 2008 servil <servil@gmx.net>                                           *
 *                                                                            *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#ifndef _FIXEDCSTR_HPP_20081014_
#define _FIXEDCSTR_HPP_20081014_ 1 /* #pragma once */

#include <cstring>
#include <memory.h>
#include <string>
#include <locale>
#include <stdexcept>
#include <functional>
#include <boost/functional/hash.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/static_assert.hpp>

template<const size_t _Size, class _CharT = char,
	class _Traits = std::char_traits<_CharT> >
struct fixed_cstr_adaptor {
BOOST_STATIC_ASSERT(_Size > 0);
public:
	typedef _CharT char_type;
	typedef _CharT value_type;
	typedef _CharT *pointer;
	typedef const _CharT *const_pointer;
	typedef _CharT &reference;
	typedef const _CharT &const_reference;
	typedef pointer iterator;
	typedef const_pointer const_iterator;
	typedef pointer reverse_iterator;
	typedef const_pointer const_reverse_iterator;
	typedef size_t size_type;
	typedef ptrdiff_t difference_type;

	_CharT str[_Size];

	inline fixed_cstr_adaptor() throw() { clear(); }
	inline fixed_cstr_adaptor(const_pointer ptr) { assign(ptr); }
	template<size_t Size, class Traits>
	inline fixed_cstr_adaptor(const fixed_cstr_adaptor<Size, _CharT, Traits> &_Other)
		{ assign(_Other); }

	inline operator const_pointer() const throw() { return str; }
	inline operator pointer() throw() { return str; }
	inline const_pointer get() const throw() { return str; }
	inline pointer get() throw() { return str; }
	inline const_pointer c_str() const throw() { return str; }
	inline const_pointer data() const throw() { return str; }

	inline const_reference front() const throw(std::exception)
		{ __check_not_empty(); return str[0]; }
	inline reference front() throw(std::exception)
		{ __check_not_empty(); return str[0]; }
	inline const_reference back() const throw(std::exception)
		{ __check_not_empty(); return str[length() - 1]; }
	inline reference back() throw(std::exception)
		{ __check_not_empty(); return str[length() - 1]; }

	inline const_iterator begin() const throw() { return str; }
	inline iterator begin() throw() { return str; }
	inline const_iterator end() const throw() { return str + length(); }
	inline iterator end() throw() { return str + length(); }

	inline const_reverse_iterator rbegin() const throw() { return str + length() - 1; }
	inline reverse_iterator rbegin() throw() { return str + length() - 1; }
	inline const_reverse_iterator rend() const throw() { return str - 1; }
	inline reverse_iterator rend() throw() { return str - 1; }

	const_reference at(size_type __pos) const throw(std::exception)
		{ __check_position(__pos); return str[__pos]; }
	reference at(size_type __pos) throw(std::exception)
		{ __check_position(__pos); return str[__pos]; }

	inline fixed_cstr_adaptor &operator =(const_pointer rhs)
		{ return assign(rhs); }
	template<size_t Size, class Traits>
	inline fixed_cstr_adaptor &operator =(const fixed_cstr_adaptor<Size, _CharT, Traits> &rhs)
		{ return assign(rhs); }

	inline fixed_cstr_adaptor &operator +=(const_pointer rhs)
		{ return append(rhs); }
	template<size_t Size, class Traits>
	inline fixed_cstr_adaptor &operator +=(const fixed_cstr_adaptor<Size, _CharT, Traits> &rhs)
		{ return append(rhs); }

	fixed_cstr_adaptor operator +(const_pointer rhs)
		{ return fixed_cstr_adaptor(*this).append(rhs); }
	template<size_t Size, class Traits>
	fixed_cstr_adaptor operator +(const fixed_cstr_adaptor<Size, _CharT, Traits> &rhs)
		{ return fixed_cstr_adaptor(*this).append(rhs); }

	inline bool operator ==(const_pointer rhs) const throw()
		{ return compare(rhs) == 0; }
	template<size_t Size, class Traits>
	inline bool operator ==(const fixed_cstr_adaptor<Size, _CharT, Traits> &rhs) const throw()
		{ return compare(rhs) == 0; }
	template<class T>inline bool operator !=(const T &rhs) const throw()
		{ return !operator ==(rhs); }

	// ordered containers support
	inline bool operator <(const_pointer rhs) const throw()
		{ return compare(rhs) < 0; }
	template<size_t Size, class Traits>
	inline bool operator <(const fixed_cstr_adaptor<Size, _CharT, Traits> &rhs) const throw()
		{ return compare(rhs) < 0; }

	inline bool operator >(const_pointer rhs) const throw()
		{ return compare(rhs) > 0; }
	template<size_t Size, class Traits>
	inline bool operator >(const fixed_cstr_adaptor<Size, _CharT, Traits> &rhs) const throw()
		{ return compare(rhs) > 0; }

	inline bool operator <=(const_pointer rhs) const throw()
		{ return compare(rhs) <= 0; }
	template<size_t Size, class Traits>
	inline bool operator <=(const fixed_cstr_adaptor<Size, _CharT, Traits> &rhs) const throw()
		{ return compare(rhs) <= 0; }

	inline bool operator >=(const_pointer rhs) const throw()
		{ return compare(rhs) >= 0; }
	template<size_t Size, class Traits>
	inline bool operator >=(const fixed_cstr_adaptor<Size, _CharT, Traits> &rhs) const throw()
		{ return compare(rhs) >= 0; }

	inline bool operator !() const throw() { return empty(); }
	//inline pointer operator &() throw() { return str; }

	fixed_cstr_adaptor &assign(const_pointer ptr = 0) {
		if (ptr != 0) {
			_Traits::copy(str, ptr, std::min(_Size, _Traits::length(ptr) + 1));
			__ensure_zero_terminated();
		} else clear();
		return *this;
	}
	template<size_t Size, class Traits>
	fixed_cstr_adaptor &assign(const fixed_cstr_adaptor<Size, _CharT, Traits> &_Other) {
		_Traits::copy(str, _Other.str, std::min(_Size, Size));
		__ensure_zero_terminated();
		return *this;
	}

	fixed_cstr_adaptor &append(const_pointer ptr) {
		if (ptr != 0) {
			const size_type length(this->length());
			if (length < max_size()) {
				_Traits::copy(str + length, ptr,
					std::min(_Size - length, _Traits::length(ptr) + 1));
				__ensure_zero_terminated();
			}
		}
		return *this;
	}
	template<size_t Size, class Traits>
	fixed_cstr_adaptor &append(const fixed_cstr_adaptor<Size, _CharT, Traits> &_Other) {
		const size_type length(this->length());
		if (length < max_size()) {
			_Traits::copy(str + length, _Other.str, std::min(_Size - length, Size));
			__ensure_zero_terminated();
		}
		return *this;
	}

	inline int compare(const_pointer ptr) const
		{ return ptr == 0 ? 1 : _Traits::compare(str, ptr, std::min(_Size, _Traits::length(ptr) + 1)); }
	template<size_t Size, class Traits>
	inline int compare(const fixed_cstr_adaptor<Size, _CharT, Traits> &_Other) const
		{ return _Traits::compare(str, _Other.str, std::min(_Size, Size)); }

	inline void clear() throw()
		{ _Traits::assign(str, _Size, _Traits::to_char_type(0)); }
	inline bool empty() const throw()
		{ return _Traits::eq_int_type(_Traits::to_int_type(str[0]), 0); }
	inline size_type length() const throw()
		{ return _Traits::length(str); }
	inline size_type size() const throw()
		{ return length(); }
	static inline size_type capacity() throw()
		{ return _Size; }
	static inline size_type max_size() throw()
		{ return _Size - 1; }
	// std violation: return free space available
	inline size_type reserve() const throw()
		{ return max_size() - length(); }

	// hashed containers support
	friend static inline std::size_t hash_value(const fixed_cstr_adaptor &__x)
		{ return boost::hash_value(__x.str); }
	struct hash {
		inline size_t operator ()(const fixed_cstr_adaptor &__x) const
			{ return hash_value(__x); }
	};

	// locale-regarding functors for associative containers
	// case-sensitive functor for sorted containers
	struct less : public std::binary_function<fixed_cstr_adaptor, fixed_cstr_adaptor, bool> {
		less(const std::locale &loc = std::locale()) : m_Loc(loc) { }
		bool operator ()(const fixed_cstr_adaptor &lhs, const fixed_cstr_adaptor &rhs) const
			{ return boost::lexicographical_compare(lhs, rhs, m_Loc); }
	private:
		std::locale m_Loc;
	};
	// case-insensitive functor for sorted containers
	struct iless : public std::binary_function<fixed_cstr_adaptor, fixed_cstr_adaptor, bool> {
		iless(const std::locale &loc = std::locale()) : m_Loc(loc) { }
		bool operator ()(const fixed_cstr_adaptor &lhs, const fixed_cstr_adaptor &rhs) const
			{ return boost::ilexicographical_compare(lhs, rhs, m_Loc); }
	private:
		std::locale m_Loc;
	};
	// case-sensitive functor for hashed containers (case-insensitive hasher not supplied atm.)
	struct equal : public std::binary_function<fixed_cstr_adaptor, fixed_cstr_adaptor, bool> {
		equal(const std::locale &loc = std::locale()) : m_Loc(loc) { }
		bool operator ()(const fixed_cstr_adaptor &lhs, const fixed_cstr_adaptor &rhs) const
			{ return boost::equals(lhs, rhs, m_Loc); }
	private:
		std::locale m_Loc;
	};
	// case-insensitive functor for hashed containers (case-insensitive hasher not supplied atm.)
	struct iequal : public std::binary_function<fixed_cstr_adaptor, fixed_cstr_adaptor, bool> {
		iequal(const std::locale &loc = std::locale()) : m_Loc(loc) { }
		bool operator ()(const fixed_cstr_adaptor &lhs, const fixed_cstr_adaptor &rhs) const
			{ return boost::iequals(lhs, rhs, m_Loc); }
	private:
		std::locale m_Loc;
	};

private:
	static void __check_position(size_type __pos) throw(std::exception) {
		if (__pos >= _Size/*size()*/)
			std::__stl_throw_out_of_range("fixed_cstr_adaptor: index out of range");
	}
	void __check_not_empty() const throw(std::exception) {
		if (empty())
			std::__stl_throw_length_error("fixed_cstr_adaptor: string is empty");
	}
	inline void __ensure_zero_terminated() throw()
		{ str[_Size - 1] = _Traits::to_char_type(0); }
}; // fixed_cstr_adaptor

#include <cstdlib>

#if defined(_MAX_PATH) && _MAX_PATH > 0

// file-path convenient specializations
typedef fixed_cstr_adaptor<_MAX_PATH, char> fixed_path_t;
template<>inline int fixed_path_t::compare(fixed_path_t::const_pointer ptr) const
	{ return ptr == 0 ? 1 : _strnicmp(str, ptr, std::min<size_t>(_MAX_PATH, strlen(ptr) + 1)); }
template<>template<size_t Size, class Traits>
inline int fixed_path_t::compare(const fixed_cstr_adaptor<Size, char, Traits> &_Other) const
	{ return _strnicmp(str, _Other.str, std::min<size_t>(_MAX_PATH, Size)); }

#include <cwchar>
typedef fixed_cstr_adaptor<_MAX_PATH, wchar_t> fixed_wpath_t;
template<>inline int fixed_wpath_t::compare(fixed_wpath_t::const_pointer ptr) const
	{ return ptr == 0 ? 1 : _wcsnicmp(str, ptr, std::min<size_t>(_MAX_PATH, wcslen(ptr) + 1)); }
template<>template<size_t Size, class Traits>
inline int fixed_wpath_t::compare(const fixed_cstr_adaptor<Size, wchar_t, Traits> &_Other) const
	{ return _wcsnicmp(str, _Other.str, std::min<size_t>(_MAX_PATH, Size)); }

#include <tchar.h>
typedef fixed_cstr_adaptor<_MAX_PATH, _TCHAR> fixed_tpath_t;

#endif // _MAX_PATH

#ifndef MAX_PATH
#	ifdef _WIN32
#		define MAX_PATH 260
#	else

#	endif
#endif

#if defined(MAX_PATH) && MAX_PATH > 0 \
	&& (!defined(_MAX_PATH) || MAX_PATH != _MAX_PATH)

//typedef fixed_cstr_adaptor<MAX_PATH, char> fixed_path_t;
template<>inline int fixed_cstr_adaptor<MAX_PATH, char>::compare(fixed_cstr_adaptor<MAX_PATH, char>::const_pointer ptr) const
	{ return ptr == 0 ? 1 : _strnicmp(str, ptr, std::min<size_t>(MAX_PATH, strlen(ptr) + 1)); }
template<>template<size_t Size, class Traits>
inline int fixed_cstr_adaptor<MAX_PATH, char>::compare(const fixed_cstr_adaptor<Size, char, Traits> &_Other) const
	{ return _strnicmp(str, _Other.str, std::min<size_t>(MAX_PATH, Size)); }

#include <cwchar>
//typedef fixed_cstr_adaptor<MAX_PATH, wchar_t> fixed_wpath_t;
template<>inline int fixed_cstr_adaptor<MAX_PATH, wchar_t>::compare(fixed_cstr_adaptor<MAX_PATH, wchar_t>::const_pointer ptr) const
	{ return ptr == 0 ? 1 : _wcsnicmp(str, ptr, std::min<size_t>(MAX_PATH, wcslen(ptr) + 1)); }
template<>template<size_t Size, class Traits>
inline int fixed_cstr_adaptor<MAX_PATH, wchar_t>::compare(const fixed_cstr_adaptor<Size, wchar_t, Traits> &_Other) const
	{ return _wcsnicmp(str, _Other.str, std::min<size_t>(MAX_PATH, Size)); }

/*
#include <tchar.h>
typedef fixed_cstr_adaptor<MAX_PATH, TCHAR> fixed_tpath_t;
*/

#endif // MAX_PATH

#endif // _FIXEDCSTR_HPP_20081014_
