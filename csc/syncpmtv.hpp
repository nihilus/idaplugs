
/*
 * syncpmtv.hpp: collection of C++ frontends for thread synchronization
 * using Windows native APIs
 * (c) 2007-2008 servil
 *
 * these objects are intended to supplement lacking synchronization primitives
 * for Boost.Thread library
 * note: usage of these objects in respective situation is as safe as using
 * synchronization APIs directly - unlike Boost.Thread the collection doesnot
 * integrate any safety control in conjunction with Boost.Thread library, in
 * another words this is fully up to programmer to evaluate if using intended
 * primitive in respective situation is safe
 */

#ifndef __cplusplus
#error C++ compiler required.
#endif // __cplusplus

#if !defined(_WIN32) || WINVER < 0x0410 && _WIN32_WINDOWS < 0x0410
#error Synchronization API not available for current platform.
#endif

#if defined(__ICL)
#pragma warning(disable:  47) // incompatible redefinition of macro "XXX"
#pragma warning(disable: 186) // pointless comparison to zero
#endif

#ifndef _SYNCPMTV_HPP_
#define _SYNCPMTV_HPP_ 1

#define NOMINMAX 1
#include "undbgnew.h"
#include <cstddef>
#include "mscrtdbg.h"
#include <string>
#include <new>
#include <algorithm>
#include <stdexcept>
#include <boost/noncopyable.hpp>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/functional.hpp>
#include <boost/type_traits.hpp>
#include <boost/call_traits.hpp>
#include <boost/static_assert.hpp>
#include <boost/preprocessor/repetition.hpp>
#include <boost/scoped_array.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <boost/next_prior.hpp>
#include <boost/utility/addressof.hpp>
#include <boost/checked_delete.hpp>
#include <windows.h>
#include "dbgnew.h"

namespace __internal {

class __primitive_base;

template<class T>class __declspec(novtable) __primitives_base :
	public boost::ptr_vector<T>, private boost::noncopyable {
public:
	typedef size_type index_type;

	// remove function introduce potentional danger: succeeding objects in
	// the collection get reindexed - use with care!
	void remove(index_type index) {
		_ASSERTE(index < count());
		if (index < count()) erase(boost::next(begin(), index));
	}
	inline void remove_all()
		{ clear(); }
	inline index_type count() const
		{ return static_cast<index_type>(size()); }
	// wait for one object
	inline bool wait(index_type index, DWORD dwMiliseconds = INFINITE, BOOL bAlertable = FALSE) {
		_ASSERTE(index < count());
		return /*index < count() ? */at(index).wait(dwMiliseconds, bAlertable)/* : false*/;
	}
	// wait for all objects
	bool wait_all(DWORD dwMiliseconds = INFINITE, BOOL bAlertable = FALSE) {
		DWORD result = do_wait(TRUE, dwMiliseconds, bAlertable);
		return result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + count();
	}
	// wait for whichever first object
	// returns index or -1 if none signaled in time
	index_type wait_any(DWORD dwMiliseconds = INFINITE, BOOL bAlertable = FALSE) {
		DWORD result = do_wait(FALSE, dwMiliseconds, bAlertable);
		return result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + count() ?
			result - WAIT_OBJECT_0 : static_cast<index_type>(-1);
	}

private:
	class T1 : public T {
	public:
		inline operator HANDLE() const { return hObject; }
	};
	DWORD do_wait(BOOL bWaitAll, DWORD dwMiliseconds, BOOL bAlertable) throw (std::exception) {
		_ASSERTE(!empty());
		if (empty()) return WAIT_OBJECT_0;
		boost::scoped_array<HANDLE> handles(new HANDLE[count()]);
		if (!handles) throw std::bad_alloc();
		typedef boost::ptr_vector<T1>::const_iterator iter_alias;
		std::copy<iter_alias>((iter_alias)begin(), (iter_alias)end(), handles.get());
		return WaitForMultipleObjectsEx(count(), handles.get(), bWaitAll,
			dwMiliseconds, bAlertable);
	}
}; // __primitives_base

class __declspec(novtable) __primitive_base : private boost::noncopyable {
protected:
	HANDLE hObject;

public:
	//inline __primitive_base() : hObject(NULL) { }
	inline ~__primitive_base()
		{ if (hObject != NULL) CloseHandle(hObject); }

	/*
	// providing handle may allow closing it
	inline operator HANDLE() const { return hObject; }
	*/

	inline bool wait(DWORD dwMiliseconds = INFINITE, BOOL bAlertable = FALSE) {
		return WaitForSingleObjectEx(hObject, dwMiliseconds, bAlertable) == WAIT_OBJECT_0;
	}
}; // __primitive_base

} // __internal

// C++ frontends for win native synchronization objects follow,
// auto-destructible, not copyable (static storage assumed)

class event : public __internal::__primitive_base {
public:
	event(BOOL bManualReset = FALSE, BOOL bInitialState = FALSE, LPCTSTR lpName = NULL) throw (std::exception) {
		if ((hObject = CreateEvent(NULL, bManualReset, bInitialState, lpName)) == NULL)
			throw std::runtime_error("failed to create event object");
	}

	inline bool set()
		{ return SetEvent(hObject) != FALSE; }
	inline bool reset()
		{ return ResetEvent(hObject) != FALSE; }
}; // event

class events : public __internal::__primitives_base<event> {
public:
	events() { }
	events(index_type count, BOOL bManualReset = FALSE, BOOL bInitialState = FALSE)
		{ add_many(count, bManualReset, bInitialState); }

	index_type add(BOOL bManualReset = FALSE, BOOL bInitialState = FALSE,
		LPCTSTR lpName = NULL) throw(std::exception) {
		if (count() >= MAXIMUM_WAIT_OBJECTS)
			std::__stl_throw_overflow_error("MAXIMUM_WAIT_OBJECTS threshold reached");
		push_back(new event(bManualReset, bInitialState, lpName));
		return count() - 1;
	}
	inline void add_many(index_type count, BOOL bManualReset = FALSE, BOOL bInitialState = FALSE) {
		_ASSERTE(count > 0 && this->count() + count <= MAXIMUM_WAIT_OBJECTS);
		while (count-- > 0) add(bManualReset, bInitialState);
	}
	inline bool set(index_type index) {
		_ASSERTE(index < count());
		return /*index < count() ? */at(index).set()/* : false*/;
	}
	void set_all()
		{ std::for_each(begin(), end(), boost::mem_fun_ref(event::set)); }
	inline bool reset(index_type index) {
		_ASSERTE(index < count());
		return /*index < count() ? */at(index).reset()/* : false*/;
	}
	void reset_all()
		{ std::for_each(begin(), end(), boost::mem_fun_ref(event::reset)); }
}; // events

class semaphore : public __internal::__primitive_base {
public:
	semaphore(LONG lInitialCount, LONG lMaximumCount, LPCTSTR lpName = NULL) throw(std::exception) {
		if (lMaximumCount <= 0) lMaximumCount = 1;
		if (lInitialCount < 0) lInitialCount = 0;
		if (lInitialCount > lMaximumCount) lInitialCount = lMaximumCount;
		if ((hObject = CreateSemaphore(NULL, lInitialCount, lMaximumCount, lpName)) == NULL)
			throw std::runtime_error("failed to create semaphore object");
	}

	inline bool release(LONG lReleaseCount = 1, LPLONG lpPreviousCount = NULL) {
		return ReleaseSemaphore(hObject, lReleaseCount > 0 ? lReleaseCount : 1,
			lpPreviousCount) != FALSE;
	}
}; // semaphore

class waitable_timer : public __internal::__primitive_base {
public:
	waitable_timer(BOOL bManualReset = FALSE, LPCTSTR lpName = NULL) throw (std::exception) {
		if ((hObject = CreateWaitableTimer(NULL, bManualReset, lpName)) == NULL)
			throw std::runtime_error("failed to create waitable timer object");
	}

	inline bool set(const LARGE_INTEGER &DueTime, LONG lPeriod = 0,
		PTIMERAPCROUTINE pfnCompletionRoutine = NULL,
		LPVOID lpArgToCompletionRoutine = NULL, BOOL fResume = FALSE) {
		return SetWaitableTimer(hObject, &DueTime, lPeriod,
			pfnCompletionRoutine, lpArgToCompletionRoutine, fResume) != FALSE;
	}
	inline bool set(LONGLONG DueTime, LONG lPeriod = 0,
		PTIMERAPCROUTINE pfnCompletionRoutine = NULL,
		LPVOID lpArgToCompletionRoutine = NULL, BOOL fResume = FALSE) {
		return set(reinterpret_cast<const LARGE_INTEGER &>(DueTime), lPeriod,
			pfnCompletionRoutine, lpArgToCompletionRoutine, fResume);
	}
	inline bool cancel() { return CancelWaitableTimer(hObject) != FALSE; }
}; // waitable_timer

class waitable_timers : public __internal::__primitives_base<waitable_timer> {
public:
	waitable_timers() { }
	waitable_timers(index_type count, BOOL bManualReset = FALSE)
		{ add_many(count, bManualReset); }

	index_type add(BOOL bManualReset = FALSE, LPCTSTR lpName = NULL) throw(std::exception) {
		if (count() >= MAXIMUM_WAIT_OBJECTS)
			std::__stl_throw_overflow_error("MAXIMUM_WAIT_OBJECTS threshold reached");
		push_back(new waitable_timer(bManualReset, lpName));
		return count() - 1;
	}
	inline void add_many(index_type count, BOOL bManualReset = FALSE) {
		_ASSERTE(count > 0 && this->count() + count <= MAXIMUM_WAIT_OBJECTS);
		while (count-- > 0) add(bManualReset);
	}
# define __DECL_SET_IMPL \
	__SET_IMPL(const LARGE_INTEGER &) \
	__SET_IMPL(LONGLONG)
#	define __SET_IMPL(T) \
	bool set(index_type index, T DueTime, \
		LONG lPeriod = 0, PTIMERAPCROUTINE pfnCompletionRoutine = NULL, \
		LPVOID lpArgToCompletionRoutine = NULL, BOOL fResume = FALSE) { \
		_ASSERTE(index < count()); \
		return /*index < count() ? */at(index).set(DueTime, lPeriod, \
			pfnCompletionRoutine, lpArgToCompletionRoutine, fResume) != FALSE/* : false*/; \
	}
	__DECL_SET_IMPL
#	define __SET_IMPL(T) \
	void set_all(T DueTime, \
		LONG lPeriod = 0, PTIMERAPCROUTINE pfnCompletionRoutine = NULL, \
		LPVOID lpArgToCompletionRoutine = NULL, BOOL fResume = FALSE) { \
		std::for_each(begin(), end(), \
			boost::bind<bool, waitable_timer, T>(&waitable_timer::set, \
				boost::arg<1>(), DueTime, lPeriod, pfnCompletionRoutine, \
					lpArgToCompletionRoutine, fResume)); \
	}
	__DECL_SET_IMPL
#	undef __SET_IMPL
#	undef __DECL_SET_IMPL
	bool cancel(index_type index) {
		_ASSERTE(index < count());
		return /*index < count() ? */at(index).cancel() != FALSE/* : false*/;
	}
	void cancel_all()
		{ std::for_each(begin(), end(), boost::mem_fun_ref(&waitable_timer::cancel)); }
}; // waitable_timers

class mutex : public __internal::__primitive_base {
public:
	mutex(BOOL bInitialOwner = FALSE, LPCTSTR lpName = NULL) throw(std::exception) {
		if ((hObject = CreateMutex(NULL, bInitialOwner, lpName)) == NULL)
			throw std::runtime_error("failed to create mutex object");
	}

	inline bool release() { return ReleaseMutex(hObject) != FALSE; }
}; // mutex

class critical_section : private boost::noncopyable {
private:
	CRITICAL_SECTION cs;

public:
	inline critical_section()
		{ InitializeCriticalSection(&cs); }
	inline critical_section(DWORD dwSpinCount)
		{ InitializeCriticalSectionAndSpinCount(&cs, dwSpinCount); }
	inline ~critical_section()
		{ DeleteCriticalSection(&cs); }

	inline void enter()
		{ EnterCriticalSection(&cs); }
	inline bool try_enter()
		{ return TryEnterCriticalSection(&cs) != FALSE; }
	inline void leave()
		{ LeaveCriticalSection(&cs); }
	inline DWORD set_spincount(DWORD dwSpinCount)
		{ return SetCriticalSectionSpinCount(&cs, dwSpinCount); }
}; // critical_section

// thread-safe static 32- and 64-bit integral types (note: 64-bit integers
// only supported by Windows 2003 and later, check platform SDK documentation
// for InterlockedXxxx64 API versions availability)
// atomic_integer is copyable but copying this kind of object is senseles in
// the usual way (static storage always assumed)
template<class T = LONG>class atomic_integer {
	BOOST_STATIC_ASSERT(boost::is_integral<T>::value
		&& (sizeof(T) == sizeof(LONG) && boost::is_convertible<T, LONG>::value
		|| WINVER >= 0x0502 && sizeof(T) == sizeof(LONGLONG)
		&& boost::is_convertible<T, LONGLONG>::value));
	//template<class F>friend atomic_integer<F> &safe_cast<atomic_integer, F>(F &);
public:
	typedef typename boost::call_traits<typename
		boost::remove_cv<T>::type>::value_type value_type;
private:
	typedef typename boost::call_traits<typename
		boost::remove_cv<T>::type>::param_type param_type;

	volatile value_type data;

	// Windows API frontends
#	define CASTED_ARG(a, n, p) static_cast<p>(arg##n)
#	define FTMPL_SPEC(name, type, specname, argcount) \
		template<>inline value_type name<sizeof(type)>(BOOST_PP_ENUM_PARAMS(argcount, param_type arg)) { \
			return static_cast<value_type>(::specname(reinterpret_cast<type volatile *>(&data) \
				BOOST_PP_ENUM_TRAILING(argcount, CASTED_ARG, type))); \
		}
#	define FTMPL_IMPL(shortname, name, argcount) \
	private: \
		template<const size_t>value_type name(BOOST_PP_ENUM_PARAMS(argcount, param_type arg)); \
		FTMPL_SPEC(name, LONG, name, argcount)         /* 32-bit version */ \
		FTMPL_SPEC(name, LONGLONG, name##64, argcount) /* 64-bit version */ \
	public: \
		inline value_type shortname(BOOST_PP_ENUM_PARAMS(argcount, param_type arg)) { \
			return name<sizeof(T)>(BOOST_PP_ENUM_PARAMS(argcount, arg)); \
		}
#	define FGROUP_IMPL(corename, argcount) \
	FTMPL_IMPL(corename, Interlocked##corename, argcount) \
	FTMPL_IMPL(corename##Acquire, Interlocked##corename##Acquire, argcount) \
	FTMPL_IMPL(corename##Release, Interlocked##corename##Release, argcount)
	FGROUP_IMPL(Increment, 0)
	FGROUP_IMPL(Decrement, 0)
	FGROUP_IMPL(Exchange, 1)
	FGROUP_IMPL(ExchangeAdd, 1)
	FGROUP_IMPL(CompareExchange, 2)
#	undef CASTED_ARG
#	undef FTMPL_SPEC
#	undef FTMPL_IMPL
#	undef FGROUP_IMPL

public:
	// construction
	inline atomic_integer(param_type val = value_type()) : data(val)
		{ check_alignment(); }
	template<class Y>inline atomic_integer(const atomic_integer<Y> &other) :
		data(static_cast<value_type>(other.data)) { check_alignment(); }

	// assignment (NOTICE: result refinement - return initial value in the
	// fashion of interlocked exchange operations)
	inline value_type operator =(param_type rhs)
		{ return exchange(rhs); }
	template<class Y>inline value_type operator =(const atomic_integer<Y> &rhs)
		{ return operator =(static_cast<value_type>(rhs.data)); }

	inline value_type operator +=(param_type rhs)
		{ return exchange_add(rhs); }
	inline value_type operator -=(param_type rhs)
		{ return operator +=(static_cast<value_type>(-rhs)); }
	// these operators may be not thread-safe - use with care
	// (may be removed in future)
#	define IMPL_OP(op) \
	inline value_type operator op##=(param_type rhs) \
		{ return operator =(data op rhs); }
	IMPL_OP(*) IMPL_OP(/) IMPL_OP(%)
	IMPL_OP(&) IMPL_OP(|) IMPL_OP(^)
	IMPL_OP(<<) IMPL_OP(>>)
#	undef IMPL_OP

	// increment/decrement (postfix versions may be not thread-safe - may
	// be removed in future)
	inline value_type operator ++()
		{ return Increment(); }
	value_type operator ++(int) {
		const value_type oldval(data);
		operator ++();
		return oldval;
	}
	inline value_type operator --()
		{ return Decrement(); }
	value_type operator --(int) {
		const value_type oldval(data);
		operator --();
		return oldval;
	}

	// modify
	inline void reset(param_type val = value_type()())
		{ operator =(val); }
	template<class Y>void swap(atomic_integer<Y> &other) {
		const typename atomic_integer<Y>::value_type
			oldval(other.exchange(static_cast<typename atomic_integer<Y>::value_type>(data)));
		exchange(static_cast<value_type>(oldval));
	}
	inline value_type exchange(param_type val)
		{ return Exchange(val); }
	inline value_type exchange_add(param_type val)
		{ return ExchangeAdd(val); }
	inline value_type exchange_if_equal(param_type val, param_type comp)
		{ return CompareExchange(val, comp); }

	// query content
	inline bool operator !() const
		{ return data == value_type(); }
	inline operator value_type() const
		{ return data; }
	inline const value_type *operator &() const
		{ return const_cast<const value_type *>(&data); }
	inline value_type get() const
		{ return data; }

	// class projection (experimantal)
	atomic_integer *attach(T *var) {
		this = reinterpret_cast<atomic_integer *>(var);
		check_alignment();
		return this;
	}
	atomic_integer &attach(T &var) {
		this = reinterpret_cast<atomic_integer *>(&var);
		check_alignment();
		return *this;
	}

private:
	void check_alignment() const throw(std::exception) {
		if (reinterpret_cast<unsigned int>(&data) % sizeof(T) != 0)
			throw std::logic_error("interlocked variable misaligned");
	}
}; // atomic_integer

/*
following functions are likely to change in future due to inconsistency
in templated static specialisation and member access policy
template<class U, class X>X *safe_cast(U *const);
template<class U, atomic_integer<U> >atomic_integer<U> *safe_cast(U *const var) {
	atomic_integer *obj(reinterpret_cast<atomic_integer *>(var));
	obj->check_alignment();
	return obj;
}

template<template<class F>class T>typename T<F> &safe_cast(F &);
template<class F>typename atomic_integer<F> &safe_cast<atomic_integer>(F &var) {
	atomic_integer<F> &obj(reinterpret_cast<atomic_integer<F> &>(var));
	obj.check_alignment();
	return obj;
}
*/

namespace __internal {

template<class T>class __declspec(novtable) __atomic_pointer_base0 {
public:
	typedef typename boost::call_traits<T *>::value_type pointer_type;

protected:
	typedef typename boost::call_traits<T *>::param_type param_type;

	volatile pointer_type p;

	inline pointer_type exchange(param_type p) {
		return static_cast<pointer_type>(InterlockedExchangePointer((PVOID
			volatile *)boost::addressof(this->p), (PVOID)p));
	}
	inline pointer_type exchange_if_equal(param_type p, param_type comp) {
		return static_cast<pointer_type>(InterlockedCompareExchangePointer((PVOID
			volatile *)boost::addressof(this->p), (PVOID)p, (PVOID)comp));
	}

public:
	// query content
	inline bool operator !() const
		{ return nil(); }
	inline operator pointer_type()
		{ return p; }
	inline pointer_type operator ->() const
		{ return p; }
	inline const pointer_type *operator &() const
		{ return const_cast<const pointer_type *>(boost::addressof(p)); }
	inline bool nil() const
		{ return p == pointer_type(); }
	inline pointer_type get() const
		{ return p; }

protected:
	void check_alignment() const throw(std::exception) {
		if (((unsigned int)&p) % sizeof(pointer_type) != 0)
			throw std::logic_error("interlocked pointer misaligned");
	}
}; // __atomic_pointer_base0

template<class T>class __declspec(novtable) __atomic_pointer_base :
	public __atomic_pointer_base0<T> {
public:
	typedef typename boost::call_traits<T>::reference reference;
	typedef typename boost::call_traits<T>::const_reference const_reference;

	inline reference operator *() {
		_ASSERTE(!nil());
		return *p;
	}
	inline const_reference operator *() const {
		_ASSERTE(!nil());
		return *p;
	}
}; // __atomic_pointer_base
#define APR_EMPTY_IMPL(spec) template<>class __atomic_pointer_base<spec> : \
	public __atomic_pointer_base0<spec> { private: void operator *() const; };
APR_EMPTY_IMPL(void)
APR_EMPTY_IMPL(void const)
APR_EMPTY_IMPL(void volatile)
APR_EMPTY_IMPL(void const volatile)
#undef APR_EMPTY_IMPL

template<class T>class __declspec(novtable) __scoped_atomic_pointer_base :
	public __internal::__atomic_pointer_base<T>, private boost::noncopyable {
protected:
	typedef boost::function1<void, pointer_type> deleter_type;

private:
	deleter_type deleter;
	mutex m; //critical_section cs;

public:
	// construction
	__scoped_atomic_pointer_base(param_type p, const deleter_type &deleter) :
		deleter(deleter), m(FALSE) {
		check_alignment();
		this->p = p;
	}
	~__scoped_atomic_pointer_base() {
		m.wait();
		release(p);
		// this was the last operation over stored value
	}

	// assignment
	void operator =(param_type rhs) {
		m.wait();
		__try {
			release(exchange(rhs));
		} __finally {
			m.release();
		}
	}

	// modify
	inline void reset(param_type p = pointer_type()) { operator =(p); }
	void reset(param_type p, const deleter_type &deleter) {
		m.wait();
		__try {
			release(exchange(p));
			this->deleter = deleter;
		} __finally {
			m.release();
		}
	}

private:
	void release(param_type p) {
		if (deleter && p != pointer_type()) deleter(const_cast<pointer_type>(p));
	}
}; // __scoped_atomic_pointer_base

} // __internal

// thread-safe static pointers, not auto-destructible, copyable (but senseles)
template<class T = VOID>class atomic_pointer :
	public __internal::__atomic_pointer_base<T> {
public:
	// construction
	inline atomic_pointer(param_type p = pointer_type()) {
		check_alignment();
		this->p = p;
	}

	// assignment (NOTICE: result refinement - return initial value in the
	// fashion of interlocked exchange operations)
	inline pointer_type operator =(param_type rhs)
		{ return exchange(rhs); }
	inline pointer_type operator =(const atomic_pointer &rhs)
		{ return operator =(rhs.p); }

	// modify
	inline void reset(param_type p = pointer_type())
		{ operator =(p); }
	/*template<Y>*/void swap(atomic_pointer/*<Y>*/ &other) {
		const /*typename atomic_pointer<Y>::*/pointer_type
			oldval(other.exchange(/*reinterpret_cast<typename
				atomic_pointer<Y>::pointer_type>(*/p/*)*/));
		exchange(/*reinterpret_cast<pointer_type>(*/oldval/*)*/);
	}
	inline pointer_type exchange(param_type p)
		{ return __super::exchange(p); }
	inline pointer_type exchange_if_equal(param_type p, param_type comp)
		{ return __super::exchange_if_equal(p, comp); }
}; // atomic_pointer

// thread-safe static pointers, auto-destructible, not copyable
template<class T = VOID>class scoped_atomic_pointer :
	public __internal::__scoped_atomic_pointer_base<T> {
public:
	scoped_atomic_pointer(param_type p = pointer_type(),
		const deleter_type &deleter = boost::checked_deleter<T>()) :
		__internal::__scoped_atomic_pointer_base<T>(p, deleter) { }
// 	scoped_atomic_pointer(const deleter_type &deleter = boost::checked_deleter<T>()) :
// 		__internal::__scoped_atomic_pointer_base<T>(pointer_type(), deleter) { }

	inline scoped_atomic_pointer &operator =(param_type rhs) {
		__internal::__scoped_atomic_pointer_base<T>::operator =(rhs);
		return *this;
	}
}; // scoped_atomic_pointer

// thread-safe static dynamic arrays, auto-destructible, not copyable
template<class T>class scoped_atomic_array :
	public __internal::__scoped_atomic_pointer_base<T> {
	BOOST_STATIC_ASSERT(!boost::is_void<T>::value);
public:
	scoped_atomic_array(param_type p = pointer_type(),
		const deleter_type &deleter = boost::checked_array_deleter<T>()) :
		__internal::__scoped_atomic_pointer_base<T>(p, deleter) { }
// 	scoped_atomic_array(const deleter_type &deleter = boost::checked_array_deleter<T>()) :
// 		__internal::__scoped_atomic_pointer_base<T>(pointer_type(), deleter) { }

	inline scoped_atomic_array &operator =(param_type rhs) {
		__internal::__scoped_atomic_pointer_base<T>::operator =(rhs);
		return *this;
	}

	inline reference operator [](ptrdiff_t index) {
		_ASSERTE(!nil());
		_ASSERTE(index >= 0);
		return p[index];
	}
	inline const_reference operator [](ptrdiff_t index) const {
		_ASSERTE(!nil());
		_ASSERTE(index >= 0);
		return p[index];
	}
}; // scoped_atomic_array

#endif // !_SYNCPMTV_HPP_
