
/*****************************************************************************
 *                                                                           *
 *  areaex.hpp: an extension to datarescue's area_t struct                   *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif // __cplusplus

#ifndef _AREAEX_HPP_
#define _AREAEX_HPP_ 1

#if defined(__ICL)
#pragma warning(disable:   47) // incompatible redefinition of macro "XXX"
#elif defined(_MSC_VER)
#pragma warning(disable: 4005) // macro redefinition
#endif

#include "undbgnew.h"
#include "mscrtdbg.h"
#include <algorithm>
#include <hash_set>
#include <boost/functional.hpp>
#include <boost/functional/hash.hpp>
#define BYTES_SOURCE                1
#include "idasdk.hpp"
#include "dbgnew.h"

struct areaex_t : public area_t {
public:
	inline areaex_t() throw() : area_t(BADADDR, BADADDR) { }
	inline areaex_t(ea_t startEA, ea_t endEA) throw() :
		area_t(startEA, startEA != BADADDR && endEA != BADADDR && endEA > startEA ? endEA : BADADDR) { }
	inline areaex_t(const area_t &from) throw() : area_t(from) { }

	inline bool operator ==(const areaex_t &rhs) const throw()
		{ return startEA == rhs.startEA && safeEndEA() == rhs.safeEndEA(); }
	inline bool operator !=(const areaex_t &rhs) const throw()
		{ return !operator ==(rhs); }
	inline bool operator <(const areaex_t &rhs) const throw()
		{ return startEA < rhs.startEA; }
	inline areaex_t &operator |=(const areaex_t &rhs) throw() {
		unite(rhs);
		return *this;
	}
	inline areaex_t &operator &=(const areaex_t &rhs) throw() {
		intersect(rhs);
		return *this;
	}
	areaex_t operator |(const areaex_t &rhs) const throw() {
		areaex_t r(*this);
		r.unite(rhs);
		return r;
	}
	areaex_t operator &(const areaex_t &rhs) const throw() {
		areaex_t r(*this);
		r.intersect(rhs);
		return r;
	}

	inline void clear() throw()
		{ startEA = BADADDR; endEA = BADADDR; }
	inline operator bool() const
		{ return startEA != BADADDR && endEA != BADADDR && startEA != 0 && endEA != 0; }
	void intersect(const areaex_t &rhs) throw() {
		if (!intersects(rhs)) {
			clear();
			return;
		}
		startEA = std::max(startEA, rhs.startEA);
		endEA = std::min(safeEndEA(), rhs.safeEndEA());
		_ASSERTE(endEA >= startEA);
	}
	void unite(const areaex_t &rhs) throw() {
		if (rhs.startEA > safeEndEA() || rhs.safeEndEA() < startEA) return;
		startEA = std::min(startEA, rhs.startEA);
		endEA = std::max(safeEndEA(), rhs.safeEndEA());
		_ASSERTE(endEA >= startEA);
	}
	ea_t safeEndEA() const throw() {
		return startEA == BADADDR ? BADADDR :
			endEA != BADADDR && endEA > startEA ? endEA : startEA + 1;
	}
	inline bool start_at(ea_t ea) const throw()
		{ return startEA == ea; }
	inline bool end_at(ea_t ea) const throw()
		{ return safeEndEA() == ea; }
	inline bool has_address(ea_t ea) const throw()
		{ return contains(ea); }
	inline bool intersects(const areaex_t &rhs) const throw()
		{ return rhs.startEA < safeEndEA() && rhs.safeEndEA() > startEA; }
	inline bool covers(const areaex_t &area) const throw()
		{ return area.startEA >= startEA && area.safeEndEA() <= safeEndEA(); }
	inline bool subrange_of(const areaex_t &area) const throw()
		{ return area.startEA <= startEA && area.safeEndEA() >= safeEndEA(); }
	inline asize_t size() const throw()
		{ return safeEndEA() - startEA; }

	// for hased containers...
	struct hash {
		inline size_t operator ()(const areaex_t &__x) const throw()
			{ return static_cast<size_t>(__x.startEA); }
	};
	friend std::size_t hash_value(const areaex_t &__x) {
		std::size_t seed(0);
		boost::hash_combine(seed, __x.startEA);
		boost::hash_combine(seed, __x.safeEndEA());
		return seed;
	}
}; // areaex_t

class rangelist_t : public std::hash_set<areaex_t, areaex_t::hash/*boost::hash<areaex_t>*/> {
public:
	iterator find(ea_t ea) { return find_if(begin(), end(),
		boost::bind2nd(boost::mem_fun_ref(areaex_t::has_address), ea)); }
	inline const_iterator find(ea_t ea) const
		{ return const_cast<rangelist_t *>(this)->find(ea); }
	bool has(ea_t ea) const
		{ return find(ea) != end(); }
};

#endif // _AREAEX_HPP_
