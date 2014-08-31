
/*****************************************************************************
 *                                                                           *
 *  plughlpr.hpp: ida toolkit common helpers                                 *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef _PLUGHLPR_HPP_
#define _PLUGHLPR_HPP_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "undbgnew.h"
#include "mscrtdbg.h"
#include <string>
#include <stdexcept>
#include <typeinfo>
#define NOMINMAX 1
#undef FUNC_STATIC
#undef FUNC_VIRTUAL
#include <windows.h>
#include "idasdk.hpp"
#include "dbgnew.h"

#define CPY(x) x, qnumber(x)
#define CAT(x) tail(x), qnumber(x) - strlen(x)
#define CPY_RANGE(x) x, x + qnumber(x)
#define CAT_RANGE(x) tail(x), x + qnumber(x)
#define CONTAINER_RANGE(x) x.begin(), x.end()
#define ARRAY_RANGE(x) boost::begin(x), boost::end(x)
#define SIZEDTEXT(t) t, sizeof(t) - 1

#define qstrcpy(x, y) qstrncpy(x, y, qnumber(x))
#define qstrcat(x, y) qstrncat(x, y, qnumber(x))

#define AT_IMPL \
	_ASSERTE(i != t.end()); \
	if (i == t.end()) std::__stl_throw_length_error("container is empty"); \
	_ASSERTE(_Off >= 0 && _Off < t.size()); \
	if (_Off < 0 || _Off >= t.size()) std::__stl_throw_out_of_range("container position index out of range"); \
	std::advance(i, _Off); \
	return *i;
template<class T>typename T::reference at(T &t, typename T::size_type _Off)
	throw(std::exception) { typename T::iterator i(t.begin()); AT_IMPL }
template<class T>typename T::const_reference at(const T &t, typename T::size_type _Off)
	throw(std::exception) { typename T::const_iterator i(t.begin()); AT_IMPL }
#undef AT_IMPL

template<class T>typename T::size_type back_pos(const T &t) throw(std::exception) {
	_ASSERTE(!t.empty());
	if (t.empty()) std::__stl_throw_length_error("container is empty");
	return t.size() - 1;
}

template<class T>typename T::reference back(T &t) throw(std::exception) {
	_ASSERTE(!t.empty());
	if (t.empty()) std::__stl_throw_length_error("container is empty");
	return *t.rbegin();
}

template<class T>typename T::const_reference back(const T &t) throw(std::exception) {
	_ASSERTE(!t.empty());
	if (t.empty()) std::__stl_throw_length_error("container is empty");
	return *t.rbegin();
}

template<class _CharT, class _Traits, class _Alloc>
void truncate(std::basic_string<_CharT, _Traits, _Alloc> &t,
	typename std::basic_string<_CharT, _Traits, _Alloc>::size_type max_len)
	{ if (t.size() > max_len) t.erase(max_len); }

// use with STL-compatible containers (iterator class with value_type defined),
// mostly for direct modifying of non-indiced value parts of set and hash_set
// entries
template<class _IterT>
inline typename std::iterator_traits<_IterT>::value_type &deconst_it(const _IterT &iter)
	{ return const_cast<typename std::iterator_traits<_IterT>::value_type &>(*iter); }
// use with custom containers that don't conform all stl iterator traits specs
// (no value_type defined for iterator)
template<class _CntnrT>
inline typename _CntnrT::value_type &deconst_nonstd_it(const typename _CntnrT::iterator &iter)
	{ return const_cast<typename _CntnrT::value_type &>(*iter); }

template<class T>inline sint8 cmp(const T &left, const T &right)
	{ return left < right ? -1 : left > right ? 1 : 0; }
template<class T>inline char sign(const T &val, bool xtdzero = true)
	{ return val < 0 ? '-' : val == 0 && !xtdzero ? ' ' : '+'; }
template<class T>inline T qabs(const T &val)
	{ return val >= 0 ? val : -val; }
#define SIGNED_PAIR(x) sign(x), qabs(x)

// VC<7 workaround
//template<class T>std::size_t hash_value(const T &);
//namespace boost { using ::hash_value; }

#include <boost/shared_ptr.hpp>
#include <boost/crc.hpp>
#include <md5.hpp>

class CRTAllocator {
public:
	static inline void *Allocate(size_t size) { return malloc(size); }
	static inline void *ReAllocate(void *ptr, size_t size) { return realloc(ptr, size); }
	static inline void Free(void *ptr) { free(ptr); }
	static inline size_t Size(void *ptr) { return _msize(ptr); }
};

class IDAAllocator {
public:
	static inline void *Allocate(size_t size) { return qalloc(size); }
	static inline void *ReAllocate(void *ptr, size_t size) { return qrealloc(ptr, size); }
	static inline void Free(void *ptr) { qfree(ptr); }
	static size_t Size(void *ptr) throw(std::exception)
		{ throw std::runtime_error("not available"); /*return 0;*/ }
};

#define WINDOWS_ALLOC_IMPL(Prefix, Default, Pointer) \
	template<const UINT uFlags = Default>class Prefix##Allocator { \
	public: \
		static inline void *Allocate(size_t size) \
			{ return (void *)Prefix##Alloc(uFlags, static_cast<SIZE_T>(size)); } \
		static inline void *ReAllocate(void *ptr, size_t size) { \
			return (void *)Prefix##ReAlloc((Pointer)ptr, \
				static_cast<SIZE_T>(size), uFlags); \
		} \
		static inline void Free(void *ptr) \
			{ Prefix##Free((Pointer)ptr); } \
		static inline size_t Size(void *ptr) \
			{ return static_cast<size_t>(Prefix##Size((Pointer)ptr)); } \
	};
WINDOWS_ALLOC_IMPL(Local, LMEM_FIXED, HLOCAL)
WINDOWS_ALLOC_IMPL(Global, GMEM_FIXED, HGLOBAL)
#undef WINDOWS_ALLOC_IMPL

template<class _CharT = CHAR, class _Allocator = LocalAllocator<> >
class SimpleString {
private:
	typedef _CharT *pointer;
	typedef const _CharT *const_pointer;
	typedef typename std::char_traits<_CharT> _Traits;

	_CharT *_m_str;

	void copy(const_pointer str) {
		if (str != 0) {
			const size_t size = _Traits::length(str) + 1;
			_m_str = (_CharT *)_Allocator::Allocate(size * sizeof _CharT);
			if (_m_str != 0) _Traits::copy(_m_str, str, size);
		}
	}

public:
	inline SimpleString() : _m_str(0) { }
	inline SimpleString(const SimpleString &other) : _m_str(0) { copy(other); }
	inline SimpleString(const_pointer pstr) : _m_str(0) { copy(pstr); }

	inline ~SimpleString() { Empty(); }

	SimpleString &operator =(const SimpleString &rhs) {
		Empty();
		copy(rhs);
		return *this;
	}
	SimpleString &operator =(const_pointer rhs) {
		Empty();
		copy(rhs);
		return *this;
	}

	inline operator const_pointer() const
		{ return _m_str; }
	inline pointer *operator &() {
		_ASSERTE(operator !());
		return &_m_str;
	}
	inline operator bool() const
		{ return _m_str != 0; }
	inline bool operator !() const
		{ return !operator bool(); }

	inline size_t Length() const
		{ return _m_str != 0 ? _Traits::length(_m_str) : 0; }
	void Empty()
		{ if (_m_str != 0) { _Allocator::Free(_m_str); _m_str = 0; } }
}; // SimpleString

namespace boost {

	template<class T, class _A>class shared_custptr : public shared_ptr<T> {
	protected:
		typedef shared_custptr _Base;
		typedef _A _Allocator;
	public:
		// construction
		shared_custptr() throw() { }
		shared_custptr(pointer p) : shared_ptr<T>(p, _Allocator::Free) { }
		shared_custptr(size_t sz) :
			shared_ptr<T>(reinterpret_cast<pointer>(_Allocator::Allocate(sz)),
				_Allocator::Free) { }
		// overrides
		inline void reset() { __super::reset(); }
		inline shared_custptr &reset(pointer p) {
			__super::reset(p, _Allocator::Free);
			return *this;
		}
		inline shared_custptr &reset(size_t sz) {
			return reset(reinterpret_cast<pointer>(_Allocator::Allocate(sz)));
			/* Realloc() is dangerous for shared pointer - original buffer may get invalidated
			if (px == 0) reset(reinterpret_cast<pointer>(_Allocator::Allocate(sz)));
				else px = reinterpret_cast<pointer>(_Allocator::ReAllocate(get(), sz));
			return *this;*/
		}
		//
		size_t size() const { return get() != 0 ? _Allocator::Size(get()) : 0; }
	};

#	define TEMPL_CONSTRUCT_IMPL(name) \
	public: \
		name() throw() { } \
		name(pointer p) : _Base(p) { } \
		name(size_t sz) : _Base(sz) { }
	template<class T = void>class shared_crtptr : public shared_custptr<T, CRTAllocator> {
		TEMPL_CONSTRUCT_IMPL(shared_crtptr)
	};
	template<class T = void>class shared_qptr : public shared_custptr<T, IDAAllocator> {
		TEMPL_CONSTRUCT_IMPL(shared_qptr)
	};
	template<class T = VOID, const UINT uFlags = LMEM_FIXED>
	class shared_localptr : public shared_custptr<T, LocalAllocator<uFlags> > {
		TEMPL_CONSTRUCT_IMPL(shared_localptr)
	};
	template<class T = VOID, const UINT uFlags = GMEM_FIXED>
	class shared_globalptr : public shared_custptr<T, GlobalAllocator<uFlags> > {
		TEMPL_CONSTRUCT_IMPL(shared_globalptr)
	};
#	undef TEMPL_CONSTRUCT_IMPL

#	ifdef _DEBUG
#		define DBG_RPT_GETMANYBYTES_FAILURE \
			else _RPT3(_CRT_WARN, "%s(ea_t const, asize_t const): get_many_bytes(%08IX, ..., 0x%IX) failed\n", \
				__FUNCTION__, ea, size);
#	else // !_DEBUG
#		define DBG_RPT_GETMANYBYTES_FAILURE
#	endif // _DEBUG

#	define DIGEST_UPDATE(methname) \
	void methname(ea_t ea, asize_t size) { \
		_ASSERTE(isLoaded(ea)); \
		_ASSERTE(isLoaded(ea + size)); \
		if (!isLoaded(ea) || size <= 0 || !isLoaded(ea + size)) return; \
		shared_crtptr<void> buffer(size); \
		if (!buffer) { \
			_RPT2(_CRT_ERROR, "%s(...): failed to allocate memory block of size 0x%IX\n", \
				__FUNCTION__, size); \
			return; \
		} \
		if (get_many_bytes(ea, buffer.get(), size)) \
			__super::methname(buffer.get(), size); \
		DBG_RPT_GETMANYBYTES_FAILURE \
	} \
	inline void methname(const area_t &area) { \
		methname(area.startEA, area.size()); \
	}

	class crc32 : public crc_32_type {
	public:
		crc32() { }
		crc32(const void *bytes_begin, const void *bytes_end)
			{ process_block(bytes_begin, bytes_end); }
		crc32(const void *buffer, std::size_t byte_count)
			{ __super::process_bytes(buffer, byte_count); }
		crc32(ea_t ea, asize_t size)
			{ process_bytes(ea, size); }
		crc32(const area_t &area)
			{ process_bytes(area); }

		DIGEST_UPDATE(process_bytes)

		inline operator value_type() const { return checksum(); }
	};

	class ida_md5 : public md5 {
	public:
		ida_md5() { }
		ida_md5(ea_t ea, asize_t size) { update(ea, size); }
		ida_md5(const area_t &area) { update(area); }

		DIGEST_UPDATE(update)
	};

#	undef DIGEST_UPDATE
#	undef DBG_RPT_GETMANYBYTES_FAILURE

} // namespace boost

#endif // _PLUGHLPR_HPP_ 1
