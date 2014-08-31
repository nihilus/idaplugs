
/*****************************************************************************
 *                                                                           *
 * pcre: Perl-compatible regular expressions library (PCRE) frontend         *
 * (c) 2003-2008 servil                                                      *
 *                                                                           *
 *****************************************************************************/

#ifndef _PCRE_HPP_ /* #pragma once */
#define _PCRE_HPP_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#pragma warning(disable: 47) // incompatible redefinition of macro "XXX"
#endif
//#pragma auto_inline(off)

// Define to enable dfa algorithm on regexp type
// note: dfa_exec increases result code considerably evem when not used
//#define PCRE_DFA_EXEC 1

#include "undbgnew.h"
#include <cstdlib>
#include <cstring>
#include <malloc.h>
#include <excpt.h>
#include "mscrtdbg.h"
#include <memory>
#include <string>
#include <stdexcept>
#include <limits>
#include <clocale>
#include <boost/smart_ptr.hpp>
#include <pcre.h>
#include "dbgnew.h"

#if defined(_MSC_VER) && !defined(PCRE_DONT_USE_AUTO_LINK)
#	ifndef _DEBUG
#		ifdef PCRE_STATIC
#			if defined(SUPPORT_UTF8) || defined(SUPPORT_UCP)
#				pragma comment(lib, "libpcreu.lib")
#		else
#				pragma comment(lib, "libpcre.lib")
#			endif
#		else
#			pragma comment(lib, "pcre.lib")
#		endif // PCRE_STATIC
#	else
#		ifdef PCRE_STATIC
//#			if defined(SUPPORT_UTF8) || defined(SUPPORT_UCP)
//#				pragma comment(lib, "libpcreud.lib")
//#			else
#			pragma comment(lib, "libpcred.lib")
//#			endif
#		else
#			pragma comment(lib, "pcred.lib")
#		endif // PCRE_STATIC
#	endif // _DEBUG
#endif // _MSC_VER && !PCRE_DONT_USE_AUTO_LINK

// the result is a negative number on any error, otherwise same as pcre_exec(...)
// for compilation errors, result is (-0x100 - pcre_compile2(...) result) to
// assure negativeness
int pcre_exec(const char *pattern, const char *subject, int *ovector,
	size_t ovecsize, int cflags = 0, int startoffset = 0, int options = 0);
// no sub-pattern capturing, result: negative error code or zero-based position
// of whole pattern
// for compilation errors, result is (-0x100 - pcre_compile2(...) result) to
// assure negativeness
int pcre_exec(const char *pattern, const char *subject, int cflags = 0,
	int startoffset = 0, int options = 0);
inline bool pcre_match(const char *pattern, const char *subject, int cflags = 0,
	int startoffset = 0, int options = 0)
		{ return pcre_exec(pattern, subject, cflags, startoffset, options) >= 0; }
#ifdef PCRE_DFA_EXEC
// result: same as original pcre_dfa_exec(...)
int pcre_dfa_exec(const pcre *code, const char *subject, int *ovector,
	size_t ovecsize, int startoffset = 0, int options = 0, size_t wscount = 40);
// result: error code or zero-based offset of matched pattern
int pcre_dfa_exec(const pcre *code, const char *subject, int startoffset = 0,
	int options = 0, size_t wscount = 40);
#endif // PCRE_DFA_EXEC

// helper for passing pcre captured substrings to printf compatible functions
// use '%-.*s' in format string to insert the substring
// n = 1-based substring index (zero for whole match)
// ovector = subpattern array returned by pcre_exec(...)
#define PCRE_PRINTF_SUBSTRING(subject, ovector, n) (ovector[(n << 1) + 1] - \
	ovector[n << 1]), (subject + ovector[n << 1])

namespace PCRE {

template<class T>class shared_ptr : public boost::shared_ptr<T> {
public:
	shared_ptr() { }
	shared_ptr(pointer p) :
		boost::shared_ptr<T>(p, (void (__cdecl *)(pointer))free) { }

	bool operator ==(const shared_ptr &rhs) const {
		size_t size;
		return get() == rhs.get() || get() != 0 && rhs.get() != 0
			&& (size = this->size()) == rhs.size()
			&& memcmp(get(), rhs.get(), size) == 0;
	}
	bool operator <(const shared_ptr &rhs) const {
		if (!rhs || get() == rhs.get()) return false;
		if (operator !()) return true;
		const size_t sizes[] = { this->size(), rhs.size() };
		const int r(memcmp(get(), rhs.get(), std::min(sizes[0], sizes[1])));
		return r < 0 || r == 0 && sizes[0] < sizes[1];
	}

	inline size_t size() const { return operator !() ? 0 : _msize(get()); }
	// overrides
	inline void reset() { __super::reset(); }
	inline shared_ptr &reset(pointer p) {
		__super::reset(p, (void (__cdecl *)(pointer))free);
		return *this;
	}
}; // shared_ptr

class tables : private shared_ptr<const unsigned char> {
public:
	tables(const char *loc = "") { set(loc); }

	inline bool operator ()(const char *loc = "") { return set(loc); }
	inline operator pointer() const { return get(); }

	inline void reset() { __super::reset(); }

private:
	bool set(const char *loc) {
		setlocale(LC_ALL, loc);
		__super::reset(pcre_maketables());
#ifdef _DEBUG
		if (operator !()) _RPT3(_CRT_ERROR, "%s(\"%s\"): %s() returned NULL\n",
			__FUNCTION__, loc, "pcre_maketables");
#endif // _DEBUG
		return get() != 0;
	}
}; // tables

class regexp : private shared_ptr<pcre>, private shared_ptr<pcre_extra> {
private:
	typedef shared_ptr<pcre> _Code;
	typedef shared_ptr<pcre_extra> _Extra;
	std::string pattern;

public:
	// construction
	regexp() throw() { _ASSERTE(!compiled()); }
	regexp(const char *pattern, int options = 0, bool study = false,
		const unsigned char *tableptr = 0)
			{ if (compile(pattern, options, tableptr) == 0 && study) this->study(); }
	regexp(const std::string &pattern, int options = 0, bool study = false,
		const unsigned char *tableptr = 0)
			{ if (compile(pattern, options, tableptr) == 0 && study) this->study(); }
	regexp(const char *pattern, const char *&errptr, int &erroffset,
		int options = 0, bool study = false, const unsigned char *tableptr = 0) {
		if (compile(pattern, options, errptr, erroffset, tableptr) == 0 && study)
			this->study();
	}
	regexp(const std::string &pattern, const char *&errptr, int &erroffset,
		int options = 0, bool study = false, const unsigned char *tableptr = 0) {
		if (compile(pattern, options, errptr, erroffset, tableptr) == 0 && study)
			this->study();
	}

	// implicit conversion
	inline operator bool() const throw() { return compiled(); }
	inline bool operator !() const throw() { return !operator bool(); }
	inline operator const pcre *() const throw() { return _Code::get(); }
	inline operator const pcre_extra *() const throw() { return _Extra::get(); }
	inline operator const char *() const throw() { return pattern.c_str(); }

	// comparison
	inline bool operator ==(const regexp &rhs) const { return _Code::operator ==(rhs); }
	// for sorted containers...
	inline bool operator <(const regexp &rhs) const { return _Code::operator <(rhs); }

	// matching
	inline int operator ()(const char *subject, int *ovector, size_t ovecsize,
		int startoffset = 0, int options = 0) const
			{ return exec(subject, ovector, ovecsize, startoffset, options); }
	inline int operator ()(const std::string &subject, int *ovector,
		size_t ovecsize, int startoffset = 0, int options = 0) const
			{ return exec(subject, ovector, ovecsize, startoffset, options); }
	inline int operator ()(const char *subject, int startoffset = 0,
		int options = 0) const
			{ return exec(subject, startoffset, options); }
	inline int operator ()(const std::string &subject, int startoffset = 0,
		int options = 0) const
			{ return exec(subject, startoffset, options); }

	// compilation
	int compile(const char *pattern, int options = 0, const unsigned char *tableptr = 0) {
		const char *errptr;
		int erroffset;
		return compile(pattern, options, errptr, erroffset, tableptr);
	}
	int compile(const std::string &pattern, int options = 0,
		const unsigned char *tableptr = 0) {
		const char *errptr;
		int erroffset;
		return compile(pattern, options, errptr, erroffset, tableptr);
	}
	int compile(const char *pattern, int options, const char *&errptr,
		int &erroffset, const unsigned char *tableptr = 0);
	inline int compile(const std::string &pattern, int options,
		const char *&errptr, int &erroffset, const unsigned char *tableptr = 0)
			{ return compile(pattern.c_str(), options, errptr, erroffset, tableptr); }
	// matching
	// result: same as pcre_exec(...)
	int exec(const char *subject, int *ovector, size_t ovecsize,
		int startoffset = 0, int options = 0) const {
		return exec_internal(subject, subject != 0 ? strlen(subject) : 0,
			ovector, ovecsize, startoffset, options);
	}
	int exec(const std::string &subject, int *ovector, size_t ovecsize,
		int startoffset = 0, int options = 0) const {
		return exec_internal(subject.data(), subject.length(),
			ovector, ovecsize, startoffset, options);
	}
	// result: error code or zero-based offset of pattern match
	int exec(const char *subject, int startoffset = 0, int options = 0) const {
		return exec_internal(subject, subject != 0 ? strlen(subject) : 0,
			startoffset, options);
	}
	int exec(const std::string &subject, int startoffset = 0, int options = 0) const {
		return exec_internal(subject.data(), subject.length(),
			startoffset, options);
	}
	// result: class result
	class result;
	result exec2(const char *subject, int startoffset = 0, int options = 0) const
			{ return result(*this, subject, startoffset, options); }
	result exec2(const std::string &subject, int startoffset = 0, int options = 0) const
			{ return result(*this, subject, startoffset, options); }
#ifdef PCRE_DFA_EXEC
	// result: same as pcre_exec(...)
	int dfa_exec(const char *subject, int *ovector, size_t ovecsize,
		int startoffset = 0, int options = 0, size_t wscount = 40) const {
		return dfa_exec_internal(subject, subject != 0 ? strlen(subject) : 0,
			ovector, ovecsize, startoffset, options, wscount);
	}
	int dfa_exec(const std::string &subject, int *ovector, size_t ovecsize,
		int startoffset = 0, int options = 0, size_t wscount = 40) const {
		return dfa_exec_internal(subject.data(), subject.length(),
			ovector, ovecsize, startoffset, options, wscount);
	}
	// result: error code or zero-based offset of pattern match
	int dfa_exec(const char *subject, int startoffset = 0,
		int options = 0, size_t wscount = 40) const {
		return dfa_exec_internal(subject, subject != 0 ? strlen(subject) : 0,
			startoffset, options, wscount);
	}
	int dfa_exec(const std::string &subject, int startoffset = 0,
		int options = 0, size_t wscount = 40) const {
		return dfa_exec_internal(subject.data(), subject.length(),
			startoffset, options, wscount);
	}
	// result: class result
	result dfa_exec2(const char *subject, int startoffset = 0,
		int options = 0, size_t wscount = 40) const
			{ return result(*this, subject, startoffset, options, wscount); }
	result dfa_exec2(const std::string &subject, int startoffset = 0,
		int options = 0, size_t wscount = 40) const
			{ return result(*this, subject, startoffset, options, wscount); }
#endif // PCRE_DFA_EXEC
	// result: match/no match
	inline bool match(const char *subject, int startoffset = 0, int options = 0) const
		{ return exec(subject, startoffset, options) >= 0; }
	inline bool match(const std::string &subject, int startoffset = 0, int options = 0) const
		{ return exec(subject, startoffset, options) >= 0; }

	inline bool compiled() const throw() { return _Code::get() != 0; }
	bool study(/*int const options = 0, */const char **const errptr = 0);
	inline bool studied() const throw() { return _Extra::get() != 0; }
	void reset() {
		_Code::reset();
		_Extra::reset();
		pattern.clear();
	}

	// named subpatterns
	int get_stringnumber(const char *stringname) const throw(std::exception) {
		_ASSERTE(compiled());
		check_stringname(stringname);
		return pcre_get_stringnumber(_Code::get(), stringname);
	}
	int copy_named_substring(const char *subject, const int *ovector,
		const char *stringname, char *buffer, int buffersize) const throw(std::exception);
	int get_named_substring(const char *subject, const int *ovector,
		const char *stringname, const char **stringptr) const throw(std::exception);
	// regexp info
	inline int fullinfo(int what, void *where) const {
		_ASSERTE(compiled() && where != 0);
		return pcre_fullinfo(_Code::get(), _Extra::get(), what, where);
	}
	inline int info(int *optptr, int *firstcharptr) const {
		_ASSERTE(compiled());
		return pcre_info(_Code::get(), optptr, firstcharptr);
	}
	// fullinfo... helper functions
	#define DECL_INFO_HELPER_FUNCTION(name, paramname, type) \
		inline type get_##name(void) const { \
			type r; \
			int i(fullinfo(PCRE_INFO_##paramname, &r)); \
			return i == 0 ? r : (type)i; \
		}
	DECL_INFO_HELPER_FUNCTION(options, OPTIONS, unsigned long)
	DECL_INFO_HELPER_FUNCTION(size, SIZE, size_t)
	DECL_INFO_HELPER_FUNCTION(capturecount, CAPTURECOUNT, int)
	DECL_INFO_HELPER_FUNCTION(backrefmax, BACKREFMAX, int)
	DECL_INFO_HELPER_FUNCTION(firstbyte, FIRSTBYTE, int)
	DECL_INFO_HELPER_FUNCTION(firstchar, FIRSTCHAR, int)
	inline char *get_firsttable(void) const {
		char *r;
		return fullinfo(PCRE_INFO_FIRSTTABLE, &r) == 0 ? r : 0;
	}
	DECL_INFO_HELPER_FUNCTION(lastliteral, LASTLITERAL, int)
	DECL_INFO_HELPER_FUNCTION(nameentrysize, NAMEENTRYSIZE, int)
	DECL_INFO_HELPER_FUNCTION(namecount, NAMECOUNT, int)
	inline char *get_nametable(void) const {
		char *r;
		return fullinfo(PCRE_INFO_NAMETABLE, &r) == 0 ? r : 0;
	}
	DECL_INFO_HELPER_FUNCTION(studysize, STUDYSIZE, size_t)
	inline char *get_default_tables(void) const {
		char *r;
		return fullinfo(PCRE_INFO_DEFAULT_TABLES/*11*/, &r) == 0 ? r : 0;
	}
	#undef DECL_INFO_HELPER_FUNCTION

	inline int config(int what) const {
		int where, result(pcre_config(what, &where));
		return result >= 0 ? where : result;
	}
	// config... helper wrappers
#define DECL_CONFIG_HELPER_FUNCTION(name, partname) \
	inline int config_##name() const { return config(PCRE_CONFIG_##partname); }
	DECL_CONFIG_HELPER_FUNCTION(utf8, UTF8)
	DECL_CONFIG_HELPER_FUNCTION(newline, NEWLINE)
	DECL_CONFIG_HELPER_FUNCTION(link_size, LINK_SIZE)
	DECL_CONFIG_HELPER_FUNCTION(posix_malloc_threshold, POSIX_MALLOC_THRESHOLD)
	DECL_CONFIG_HELPER_FUNCTION(match_limit, MATCH_LIMIT)
	DECL_CONFIG_HELPER_FUNCTION(stackrecurse, STACKRECURSE)
	DECL_CONFIG_HELPER_FUNCTION(unicode_properties, UNICODE_PROPERTIES)
	DECL_CONFIG_HELPER_FUNCTION(match_limit_recursion, MATCH_LIMIT_RECURSION)
#undef DECL_CONFIG_HELPER_FUNCTION

private:
	int exec_internal(const char *, size_t, int *, size_t,
		int startoffset = 0, int options = 0) const;
	int exec_internal(const char *, size_t,
		int startoffset = 0, int options = 0) const;
#ifdef PCRE_DFA_EXEC
	int dfa_exec_internal(const char *subject, size_t length, int *ovector,
		size_t ovecsize, int startoffset = 0, int options = 0, size_t wscount = 40) const;
	int dfa_exec_internal(const char *subject, size_t length, int startoffset = 0,
		int options = 0, size_t wscount = 40) const;
#endif // PCRE_DFA_EXEC
	static void check_stringname(const char *stringname) throw(std::exception);

public:
	class result : private boost::shared_array<int>,
		private boost::shared_array<const char *> {
	friend class regexp;
	private:
		typedef boost::shared_array<const char *> _Substr;
		typedef boost::shared_array<int> _Ovec;

		int count;
		std::string _subject;
		shared_ptr<pcre> code;
		shared_ptr<pcre_extra> extra;

	public:
		result() throw() : count(PCRE_ERROR_NOMATCH) { }
		result(const regexp &regex, const char *subject = 0, int startoffset = 0,
			int options = 0) : count(PCRE_ERROR_NOMATCH), code(regex), extra(regex)
				{ set(subject != 0 ? subject : std::string(), startoffset, options); }
		result(const regexp &regex, const std::string &subject, int startoffset = 0,
			int options = 0) : count(PCRE_ERROR_NOMATCH), code(regex), extra(regex)
				{ set(subject, startoffset, options); }
#ifdef PCRE_DFA_EXEC
		result(const regexp &regex, const char *subject = 0, int startoffset,
			int options, size_t wscount) : count(PCRE_ERROR_NOMATCH), code(regex), extra(regex) {
			set(subject != 0 ? subject : std::string(), startoffset, options, wscount);
		}
		result(const regexp &regex, const std::string &subject, int startoffset,
			int options, size_t wscount) : count(PCRE_ERROR_NOMATCH), code(regex), extra(regex)
				{ set(subject, startoffset, options, wscount); }
#endif // PCRE_DFA_EXEC
	private:
		result(int count) : count(count) { _ASSERTE(count < 0); }

	public:
		int operator ()(const regexp &regex, const char *subject = 0,
			int startoffset = 0, int options = 0) {
			reset();
			set(regex, subject != 0 ? subject : std::string(), startoffset, options);
			return count;
		}
		int operator ()(const regexp &regex, const std::string &subject,
			int startoffset = 0, int options = 0) {
			reset();
			set(regex, subject, startoffset, options);
			return count;
		}
		int operator ()(const char *subject = 0, int startoffset = 0, int options = 0) {
			__reset();
			set(subject != 0 ? subject : std::string(), startoffset, options);
			return count;
		}
		int operator ()(const std::string &subject, int startoffset = 0, int options = 0) {
			__reset();
			set(subject, startoffset, options);
			return count;
		}
#ifdef PCRE_DFA_EXEC
		int operator ()(const regexp &regex, const char *subject, int startoffset,
			int options, size_t wscount) {
			reset();
			set(regex, subject != 0 ? subject : std::string(), startoffset, options, wscount);
			return count;
		}
		int operator ()(const regexp &regex, const std::string &subject,
			int startoffset, int options, size_t wscount) {
			reset();
			set(regex, subject, startoffset, options, wscount);
			return count;
		}
		int operator ()(const char *subject, int startoffset, int options,
			size_t wscount) {
			__reset();
			set(subject != 0 ? subject : std::string(), startoffset, options, wscount);
			return count;
		}
		int operator ()(const std::string &subject, int startoffset, int options,
			size_t wscount) {
			__reset();
			set(subject, startoffset, options, wscount);
			return count;
		}
#endif // PCRE_DFA_EXEC

		bool operator ==(const result &rhs) const;
		const char *operator [](int index) const throw(std::exception);
		const char *operator [](const char *stringname) const throw(std::exception);
		inline size_t operator ()(int index/* = 0*/) const throw(std::exception)
			{ return length(index); }
		inline size_t operator ()(const char *stringname) const throw(std::exception)
			{ return length(stringname); }
		inline operator int() const // errorcode or substring count
			{ return count; }
		inline operator const char *() const
			{ return operator [](0); }
		inline bool operator ()() const throw()
			{ return count >= 0; }
		inline const char *subject() const throw()
			{ return _subject.c_str(); }

		// retrieving subpatterns information
		int start(int index = 0) const throw(std::exception);
		int start(const char *stringname) const throw(std::exception);
		int end(int index = 0) const throw(std::exception);
		int end(const char *stringname) const throw(std::exception);
		size_t length(int index = 0) const throw(std::exception);
		size_t length(const char *stringname) const throw(std::exception);
		// named subpattern front-ends
		int copy_named_substring(const char *stringname, char *buffer, int bufsize) const throw(std::exception);
		int get_named_substring(const char *stringname, const char **stringptr) const throw(std::exception);

		void reset() {
			__reset();
			code.reset();
			extra.reset();
		}

	private:
		bool set(const result &);
		bool set(const regexp &regex, const std::string &subject,
			int startoffset = 0, int options = 0) {
			_ASSERTE(regex.compiled());
			_ASSERTE(count == PCRE_ERROR_NOMATCH);
			if (!regex) return false;
			code = regex;
			extra = regex;
			return set(subject, startoffset, options);
		}
		bool set(const std::string &, int startoffset = 0, int options = 0);
#ifdef PCRE_DFA_EXEC
		bool set(const regexp &regex, const std::string &subject, int startoffset,
			int options, size_t wscount) {
			_ASSERTE(regex.compiled());
			_ASSERTE(count == PCRE_ERROR_NOMATCH);
			if (!regex) return false;
			code = regex;
			extra = regex;
			return set(subject, length, startoffset, options, wscount);
		}
		bool set(const std::string &, int, int, size_t);
#endif // PCRE_DFA_EXEC
		int get_substring_list(const std::string &, const int *);
		void __reset() {
			count = PCRE_ERROR_NOMATCH;
			_Ovec::reset();
			_Substr::reset();
			_subject.clear();
		}
	}; // class result
}; // class regexp

} // namespace PCRE

#endif // _pcre_hpp_
