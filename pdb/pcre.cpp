
/*****************************************************************************
 *                                                                           *
 * pcre: Perl-compatible regular expressions library (PCRE) frontend         *
 * (c) 2003-2008 servil                                                      *
 *                                                                           *
 *****************************************************************************/

#include <algorithm>
#include "pcre.hpp"

// result: same as original pcre_exec(...) or (-0x100 - error) on compilation error
// this assures the result is always negative if any error to avoid mess up
// with true match count
int pcre_exec(const char *pattern, const char *subject, int *ovector,
	size_t ovecsize, int cflags, int startoffset, int options) {
#ifdef _DEBUG
	if (ovector == 0 && ovecsize > 0)
		_RPT1(_CRT_WARN, "%s(...): ovector size is non-zero but pointer to ovector is NULL: no subpatterns will be captured\n",
			__FUNCTION__);
	if (ovector != 0 && ovecsize <= 0)
		_RPT1(_CRT_WARN, "%s(...): ovector size is zero but pointer to ovector is not NULL: no subpatterns will be captured\n",
			__FUNCTION__);
#endif // _DEBUG
	if (ovector == 0 || ovecsize <= 0) {
		_RPT3(_CRT_WARN, "%s(..., \"%s\", ...): subpattern vector not present, calling %s(const char *, const char *, int, int, int): result meaning changed\n",
			__FUNCTION__, subject, __FUNCTION__);
		return pcre_exec(pattern, subject, cflags, startoffset, options);
	}
	int errorcode, erroffset;
	const char *errptr;
	_ASSERTE(pattern != 0);
	boost::shared_ptr<pcre> code(pcre_compile2(pattern, cflags,
		&errorcode, &errptr, &erroffset, 0), free);
	if (!code) {
		_RPT4(_CRT_ERROR, "%s(\"%s\", ...): pcre_compile2(...) returned NULL (%s at %i)\n",
			__FUNCTION__, pattern, errptr, erroffset);
		_ASSERTE(errorcode != 0);
		if (errorcode > 0) errorcode = -0x100 - errorcode;
		return errorcode; // error on compile
	}
	std::fill_n(ovector, ovecsize, 0);
	_ASSERTE(subject != 0);
	return pcre_exec(code.get(), 0/* pcre_extra* */, subject, subject != 0 ?
		strlen(subject) : 0, startoffset, options, ovector, static_cast<int>(ovecsize));
}

// result: zero-based offset of whole subpattern occurence
int pcre_exec(const char *pattern, const char *subject, int cflags,
	int startoffset, int options) {
	int errorcode, capturecount;
	const char *errptr;
	_ASSERTE(pattern != 0);
	boost::shared_ptr<pcre> code(pcre_compile2(pattern, cflags,
		&errorcode, &errptr, &capturecount, 0), free);
	if (!code) {
		_RPT4(_CRT_ERROR, "%s(\"%s\", ...): pcre_compile2(...) returned NULL (%s at %i)\n",
			__FUNCTION__, pattern, errptr, capturecount);
		_ASSERTE(errorcode != 0);
		if (errorcode > 0) errorcode = -0x100 - errorcode;
		return errorcode;
	}
	errorcode = pcre_fullinfo(code.get(), 0/* pcre_extra* */,
		PCRE_INFO_CAPTURECOUNT, &capturecount);
	if (errorcode < 0) {
		_RPT3(_CRT_ERROR, "%s(..., \"%s\", ...): pcre_fullinfo(..., PCRE_INFO_CAPTURECOUNT, ...) returned %i\n",
			__FUNCTION__, subject, errorcode);
		return errorcode;
	}
	_ASSERTE(errorcode == 0);
	_ASSERTE(capturecount >= 0);
	boost::scoped_array<int> ovector(new int[capturecount = (capturecount + 1) * 3]);
	if (!ovector) {
		_RPT2(_CRT_ERROR, "%s(...): failed to allocate int[%i] array\n",
			__FUNCTION__, capturecount);
		return PCRE_ERROR_NOMEMORY; //throw std::bad_alloc();
	}
	std::fill_n(ovector.get(), capturecount, 0);
	_ASSERTE(subject != 0);
	errorcode = pcre_exec(code.get(), 0/* pcre_extra* */, subject,
		subject != 0 ? strlen(subject) : 0, startoffset, options, ovector.get(),
		capturecount);
	if (errorcode >= 1)
		errorcode = ovector[0];
	else if (errorcode == 0)
		errorcode = PCRE_ERROR_NOMATCH;
	return errorcode;
}

#ifdef PCRE_DFA_EXEC

int pcre_dfa_exec(const pcre *code, const char *subject, int *ovector,
	size_t ovecsize, int startoffset, int options, size_t wscount) {
	_ASSERTE(code != 0);
	if (code == 0) return PCRE_ERROR_NULL;
#ifdef _DEBUG
	if (ovector == 0 && ovecsize > 0)
		_RPT1(_CRT_WARN, "%s(...): ovector size is non-zero but pointer to ovector is NULL: no subpatterns will be captured\n",
			__FUNCTION__);
	if (ovector != 0 && ovecsize <= 0)
		_RPT1(_CRT_WARN, "%s(...): ovector size is zero but pointer to ovector is not NULL: no subpatterns will be captured\n",
			__FUNCTION__);
#endif // _DEBUG
	if (ovector == 0 || ovecsize <= 0) {
		_RPT3(_CRT_WARN, "%s(..., \"%s\", ...): subpattern vector not present, calling %s(pcre *, const char *, int, int): result meaning changed\n",
			__FUNCTION__, subject, __FUNCTION__);
		return pcre_dfa_exec(code, subject, startoffset, options, wscount);
	}
	if (wscount < 20) wscount = 20;
	boost::scoped_array<int> wspace(new int[wscount]);
	if (!wspace) {
		_RPT2(_CRT_ERROR, "%s(...): failed to allocate int[%Iu] array\n",
			__FUNCTION__, wscount);
		return PCRE_ERROR_NOMEMORY; //throw std::bad_alloc();
	}
	std::fill_n(ovector, ovecsize, 0);
	_ASSERTE(subject != 0);
	return pcre_dfa_exec(code, 0/* pcre_extra* */, subject,
		subject != 0 ? strlen(subject) : 0, startoffset, options, ovector,
		static_cast<int>(ovecsize), wspace.get(), wscount);
}

int pcre_dfa_exec(const pcre *code, const char *subject, int startoffset,
	int options, size_t wscount) {
	_ASSERTE(code != 0);
	if (code == 0) return PCRE_ERROR_NULL;
	int capturecount, result(pcre_fullinfo(code, 0/* pcre_extra* */,
		PCRE_INFO_CAPTURECOUNT, &capturecount));
	if (result < 0) {
		_RPT3(_CRT_ERROR, "%s(..., \"%s\", ...): pcre_fullinfo(..., PCRE_INFO_CAPTURECOUNT, ...) returned %i\n",
			__FUNCTION__, subject, result);
		return result;
	}
	_ASSERTE(result == 0);
	_ASSERTE(capturecount >= 0);
	boost::scoped_array<int> ovector(new int[capturecount = (capturecount + 1) * 3]);
	if (!ovector) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate int[%i] array\n",
			__FUNCTION__, capturecount);
		return PCRE_ERROR_NOMEMORY; //throw std::bad_alloc();
	}
	if (wscount < 20) wscount = 20;
	boost::scoped_array<int> wspace(new int[wscount]);
	if (!wspace) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate int[%Iu] array\n",
			__FUNCTION__, wscount);
		return PCRE_ERROR_NOMEMORY; //throw std::bad_alloc();
	}
	std::fill_n(ovector.get(), capturecount, 0);
	_ASSERTE(subject != 0);
	result = pcre_dfa_exec(code, 0/* pcre_extra* */, subject,
		subject != 0 ? strlen(subject) : 0, startoffset, options, ovector.get(),
		capturecount, wspace.get(), wscount);
	if (result >= 1)
		result = ovector[0];
	else if (result == 0)
		result = PCRE_ERROR_NOMATCH;
	return result;
}

#endif // PCRE_DFA_EXEC

namespace PCRE {

//////////////////////////////// class regexp ////////////////////////////////

int regexp::compile(const char *pattern, int options, const char *&errptr,
	int &erroffset, const unsigned char *tableptr) {
	reset();
	_ASSERTE(pattern != 0);
	int errorcode;
	_Code::reset(pcre_compile2(pattern, options,
		&errorcode, &errptr, &erroffset, tableptr));
#ifdef _DEBUG
	if (_Code::operator !()) _CrtDbgReport(_CRT_ERROR, __FILE__, __LINE__, __FUNCTION__,
		"%s(\"%s\", ...): pcre_compile2 returned %i: %s(%i)\n", __FUNCTION__,
		pattern, errorcode, errptr, erroffset);
#endif // _DEBUG
	if (pattern != 0) this->pattern.assign(pattern);
	return errorcode;
}

bool regexp::study(/*int options, */const char **errptr) {
	_ASSERTE(compiled());
	if (compiled()) {
		const char *_errptr;
		_Extra::reset(pcre_study(_Code::get(), 0/*options*/, &_errptr));
		if (errptr != 0) *errptr = _errptr;
#ifdef _DEBUG
		if (_Extra::operator !()) _RPT3(_CRT_WARN, "%s(...): pcre_study(\"%s\") without result: %s\n",
			__FUNCTION__, pattern.c_str(), _errptr);
#endif // _DEBUG
	} else
		_Extra::reset();
	return studied();
}

int regexp::exec_internal(const char *subject, size_t length, int *ovector,
	size_t ovecsize, int startoffset, int options) const {
	_ASSERTE(compiled());
	if (!compiled()) return PCRE_ERROR_NULL;
#ifdef _DEBUG
	if (ovector == 0 && ovecsize > 0)
		_RPT1(_CRT_WARN, "%s(...): ovector size is non-zero but pointer to ovector is NULL: no subpatterns will be captured\n",
			__FUNCTION__);
	if (ovector != 0 && ovecsize <= 0)
		_RPT1(_CRT_WARN, "%s(...): ovector size is zero but pointer to ovector is not NULL: no subpatterns will be captured\n",
			__FUNCTION__);
#endif // _DEBUG
	if (ovector == 0 || ovecsize <= 0) {
		_RPT3(_CRT_WARN, "%s(..., \"%s\", ...): subpattern vector not present, calling %s(const char *, int, int): result meaning changed\n",
			__FUNCTION__, subject, __FUNCTION__);
		return exec_internal(subject, length, startoffset, options);
	}
	std::fill_n(ovector, ovecsize, 0);
	_ASSERTE(subject != 0);
	return pcre_exec(_Code::get(), _Extra::get(), subject, length, startoffset,
		options, ovector, static_cast<int>(ovecsize));
}

int regexp::exec_internal(const char *subject, size_t length, int startoffset,
	int options) const {
	_ASSERTE(compiled());
	if (!compiled()) return PCRE_ERROR_NULL;
	int result(get_capturecount());
	if (result < 0) {
		_RPT3(_CRT_ERROR, "%s(..., \"%s\", ...): pcre_fullinfo(PCRE_INFO_CAPTURECOUNT, ...) returned %i\n",
			__FUNCTION__, subject, result);
		return result;
	}
	boost::scoped_array<int> ovector(new int[result = (result + 1) * 3]);
	if (!ovector) {
		_RPT2(_CRT_ERROR, "%s(...): failed to allocate int[%i] array\n",
			__FUNCTION__, result);
		return PCRE_ERROR_NOMEMORY; //throw std::bad_alloc();
	}
	std::fill_n(ovector.get(), result, 0);
	_ASSERTE(subject != 0);
	result = pcre_exec(_Code::get(), _Extra::get(), subject, length, startoffset,
		options, ovector.get(), result);
	_ASSERTE(result != 0);
	if (result >= 1)
		result = ovector[0];
	else if (result == 0)
		result = PCRE_ERROR_NOMATCH;
	return result;
}

#ifdef PCRE_DFA_EXEC

int regexp::dfa_exec_internal(const char *subject, size_t length, int *ovector,
	size_t ovecsize, int startoffset, int options, size_t wscount) const {
	_ASSERTE(compiled());
	if (!compiled()) return PCRE_ERROR_NULL;
#ifdef _DEBUG
	if (ovector == 0 && ovecsize > 0)
		_RPT1(_CRT_WARN, "%s(...): ovector size is non-zero but pointer to ovector is NULL: no subpatterns will be captured\n",
			__FUNCTION__);
	if (ovector != 0 && ovecsize <= 0)
		_RPT1(_CRT_WARN, "%s(...): ovector size is zero but pointer to ovector is not NULL: no subpatterns will be captured\n",
			__FUNCTION__);
#endif // _DEBUG
	if (ovector == 0 || ovecsize <= 0) {
		_RPT3(_CRT_WARN, "%s(..., \"%s\", ...): subpattern vector not present, calling %s(const char *, int, int): result meaning changed\n",
			__FUNCTION__, subject, __FUNCTION__);
		return dfa_exec_internal(subject, startoffset, options);
	}
	if (wscount < 20) wscount = 20;
	boost::scoped_array<int> wspace(new int[wscount]);
	if (!wspace) {
		_RPT2(_CRT_ERROR, "%s(...): failed to allocate int[%Iu] array\n",
			__FUNCTION__, wscount);
		return PCRE_ERROR_NOMEMORY; //throw std::bad_alloc();
	}
	std::fill_n(ovector, ovecsize, 0);
	_ASSERTE(subject != 0);
	return pcre_dfa_exec(_Code::get(), _Extra::get(), subject, length, startoffset,
		options, ovector, static_cast<int>(ovecsize), wspace.get(), wscount);
}

int regexp::dfa_exec_internal(const char *subject, size_t length,
	int startoffset, int options, size_t wscount) const {
	_ASSERTE(compiled());
	if (!compiled()) return PCRE_ERROR_NULL;
	int result(get_capturecount());
	if (result < 0) {
		_RPT3(_CRT_ERROR, "%s(..., \"%s\", ...): pcre_fullinfo(PCRE_INFO_CAPTURECOUNT, ...) returned %i\n",
			__FUNCTION__, subject, result);
		return result;
	}
	boost::scoped_array<int> ovector(new int[result = (result + 1) * 3]);
	if (!ovector) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate int[%i] array\n",
			__FUNCTION__, result);
		return PCRE_ERROR_NOMEMORY; //throw std::bad_alloc();
	}
	if (wscount < 20) wscount = 20;
	boost::scoped_array<int> wspace(new int[wscount]);
	if (!wspace) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate int[%Iu] array\n",
			__FUNCTION__, wscount);
		return PCRE_ERROR_NOMEMORY; //throw std::bad_alloc();
	}
	std::fill_n(ovector.get(), result, 0);
	_ASSERTE(subject != 0);
	result = pcre_dfa_exec(_Code::get(), _Extra::get(), subject, length,
		startoffset, options, ovector.get(), result, wspace.get(), wscount);
	_ASSERTE(result != 0);
	if (result >= 1)
		result = ovector[0];
	else if (result == 0)
		result = PCRE_ERROR_NOMATCH;
	return result;
}

#endif // PCRE_DFA_EXEC

int regexp::copy_named_substring(const char *subject, const int *ovector,
	const char *stringname, char *buffer, int buffersize) const throw(std::exception) {
	_ASSERTE(buffer != 0 && buffersize > 0);
	if (buffer == 0 || buffersize == 0) return PCRE_ERROR_NULL;
	*buffer = 0;
	check_stringname(stringname);
	_ASSERTE(compiled() && subject != 0 && ovector != 0);
	return pcre_copy_named_substring(_Code::get(), subject,
		const_cast<int *>(ovector), INT_MAX, stringname, buffer, buffersize);
}

int regexp::get_named_substring(const char *subject, const int *ovector,
	const char *stringname, const char **stringptr) const throw(std::exception) {
	_ASSERTE(stringptr != 0);
	if (stringptr == 0) return PCRE_ERROR_NULL;
	*stringptr = 0;
	check_stringname(stringname);
	_ASSERTE(compiled() && subject != 0 && ovector != 0);
	return pcre_get_named_substring(_Code::get(), subject,
		const_cast<int *>(ovector), INT_MAX, stringname, stringptr);
}

void regexp::check_stringname(const char *stringname) {
	_ASSERTE(stringname != 0);
	if (stringname == 0)
		std::__stl_throw_invalid_argument("subpattern name cannot be NULL");
}

//////////////////////////// class regexp::result ////////////////////////////

bool regexp::result::set(const std::string &subject, int startoffset, int options) {
	_ASSERTE(count == PCRE_ERROR_NOMATCH);
	_ASSERTE(code);
	if (!code) return false;
	int errorcode(pcre_fullinfo(code.get(), extra.get(),
		PCRE_INFO_CAPTURECOUNT, &count));
	if (errorcode < 0) {
		count = errorcode;
		_RPT3(_CRT_ERROR, "%s(..., \"%s\", ...): pcre_fullinfo(PCRE_INFO_CAPTURECOUNT, ...) returned %i\n",
			__FUNCTION__, subject.c_str(), errorcode);
		return false;
	}
	_ASSERTE(count >= 0);
	boost::scoped_array<int> ovector(new int[count = (count + 1) * 3]);
	if (!ovector) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate int[%i] array\n",
			__FUNCTION__, count);
		count = PCRE_ERROR_NOMEMORY;
		return false; //throw std::bad_alloc();
	}
	std::fill_n(ovector.get(), count, 0);
	if ((count = pcre_exec(code.get(), extra.get(), subject.data(),
		subject.length(), startoffset, options, ovector.get(), count)) >= 1) {
		_Ovec::reset(new int[count << 1]);
		if (_Ovec::operator !()) {
			_RPTF2(_CRT_ERROR, "%s(...): failed to allocate int[%i] array\n",
				__FUNCTION__, count << 1);
			count = PCRE_ERROR_NOMEMORY;
			return false; //throw std::bad_alloc();
		}
		std::copy(ovector.get(), ovector.get() + (count << 1), _Ovec::get());
		get_substring_list(subject, ovector.get());
		_ASSERTE(_Substr::get() != 0);
	}
	_subject.assign(subject);
	return true;
}

#ifdef PCRE_DFA_EXEC

bool regexp::result::set(const std::string &subject, int startoffset,
	int options, size_t wscount) {
	_ASSERTE(count == PCRE_ERROR_NOMATCH);
	_ASSERTE(code);
	if (!code) return false;
	int errorcode(pcre_fullinfo(code.get(), extra.get(),
		PCRE_INFO_CAPTURECOUNT, &count));
	if (errorcode < 0) {
		count = errorcode;
		_RPT3(_CRT_ERROR, "%s(..., \"%s\", ...): pcre_fullinfo(PCRE_INFO_CAPTURECOUNT, ...) returned %i\n",
			__FUNCTION__, subject.c_str(), errorcode);
		return false;
	}
	_ASSERTE(count >= 0);
	boost::scoped_array<int> ovector(new int[count = (count + 1) * 3]);
	if (!ovector) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate int[%i] array\n",
			__FUNCTION__, count);
		count = PCRE_ERROR_NOMEMORY;
		return false; //throw std::bad_alloc();
	}
	if (wscount < 20) wscount = 20;
	boost::scoped_array<int> wspace(new int[wscount]);
	if (!wspace) {
		_RPTF2(_CRT_ERROR, "%s(...): failed to allocate int[%Iu] array\n",
			__FUNCTION__, wscount);
		count = PCRE_ERROR_NOMEMORY;
		return false; //throw std::bad_alloc();
	}
	std::fill_n(ovector.get(), count, 0);
	if ((count = pcre_dfa_exec(code.get(), extra.get(), subject.data(),
		subject.length(), startoffset, options, ovector.get(), count,
		wspace.get(), wscount)) >= 1) {
		_Ovec::reset(new int[count << 1]);
		if (_Ovec::operator !()) {
			count = PCRE_ERROR_NOMEMORY;
			_RPTF2(_CRT_ERROR, "%s(...): failed to allocate int[%i] array\n",
				__FUNCTION__, count << 1);
			return false; //throw std::bad_alloc();
		}
		std::copy(ovector.get(), ovector.get() + (count << 1), _Ovec::get());
		get_substring_list(subject, ovector.get());
		_ASSERTE(_Substr::get() != 0);
	}
	_subject.assign(subject);
	return true;
}

#endif // PCRE_DFA_EXEC

int regexp::result::get_substring_list(const std::string &subject, const int *ovector) {
	_ASSERTE(ovector != 0);
	const char **tmp;
	const int yield(ovector != 0 ? pcre_get_substring_list(subject.data(),
		const_cast<int *>(ovector), count, &tmp) : PCRE_ERROR_NULL);
	if (yield == 0) {
		_ASSERTE(tmp != 0);
		_Substr::reset(tmp, pcre_free_substring_list);
#ifdef _DEBUG
		for (int ndx = 0; ndx < count; ++ndx)
			_ASSERTE(strlen(tmp[ndx]) == ovector[(ndx << 1) + 1] - ovector[ndx << 1]);
#endif // _DEBUG
	} else {
		_Substr::reset();
#ifdef _DEBUG
		_CrtDbgReport(_CRT_WARN, NULL, 0, NULL, "%s(\"%s\", %p, %i): %s(...) returned %i\n",
			__FUNCTION__, subject.c_str(), ovector, count, "pcre_get_substring_list", yield);
#endif // _DEBUG
	}
	return yield;
}

bool regexp::result::operator ==(const regexp::result &rhs) const {
	if (count != rhs.count || _Substr::operator !() && rhs._Substr::get() != 0
		|| _Substr::get() != 0 && rhs._Substr::operator !()) return false;
	if (_Substr::operator !() && rhs._Substr::operator !()) return true;
	for (int ndx = 0; ndx < count; ++ndx)
		if ((_Substr::operator [](ndx) != 0 || rhs._Substr::operator [](ndx) != 0)
			&& (_Substr::operator [](ndx) != 0 && rhs._Substr::operator [](ndx) == 0
			|| _Substr::operator [](ndx) == 0 && rhs._Substr::operator [](ndx) != 0
			|| strcmp(_Substr::operator [](ndx), rhs._Substr::operator [](ndx)) != 0))
				return false;
	return true;
}

#define DECL_POSFUNC(name, retype, defret) \
	retype regexp::result::name(const char *stringname) const { \
		_ASSERTE(code); \
		if (code) { \
			regexp::check_stringname(stringname); \
			const int index(pcre_get_stringnumber(code.get(), stringname)); \
			if (index >= 0) return name(index); \
			_RPT2(_CRT_WARN, "%s(\"%s\"): this pattern wasnot captured\n", \
				__FUNCTION__, stringname); \
		} \
		return (defret); \
	}

const char *regexp::result::operator [](int index) const {
	_ASSERTE(index >= 0 && index < count);
	if (index < 0 || index >= count)
		std::__stl_throw_out_of_range("subpattern index out of range");
	_ASSERTE(_Substr::get() != 0);
	if (_Substr::operator !()) throw std::logic_error("no subpatterns available");
	return /*_Substr::operator !() ? 0 : */_Substr::operator [](index);
}
DECL_POSFUNC(operator [], const char *, 0)

int regexp::result::start(int index) const {
	_ASSERTE(index >= 0 && index < count);
	if (index < 0 || index >= count)
		std::__stl_throw_out_of_range("subpattern index out of range");
	_ASSERTE(_Ovec::get() != 0);
	if (_Ovec::operator !()) throw std::logic_error("no subpatterns available");
	return _Ovec::operator [](index << 1);
}
DECL_POSFUNC(start, int, -1)

int regexp::result::end(int index) const {
	_ASSERTE(index >= 0 && index < count);
	if (index < 0 || index >= count)
		std::__stl_throw_out_of_range("subpattern index out of range");
	_ASSERTE(_Ovec::get() != 0);
	if (_Ovec::operator !()) throw std::logic_error("no subpatterns available");
	return _Ovec::operator []((index << 1) + 1);
}
DECL_POSFUNC(end, int, -1)

size_t regexp::result::length(int index) const {
	_ASSERTE(index >= 0 && index < count);
	if (index < 0 || index >= count)
		std::__stl_throw_out_of_range("subpattern index out of range");
	_ASSERTE(_Ovec::get() != 0);
	if (_Ovec::operator !()) throw std::logic_error("no subpatterns available");
	return _Ovec::operator []((index << 1) + 1) - _Ovec::operator [](index << 1);
}
DECL_POSFUNC(length, size_t, 0)

#undef DECL_POSFUNC

int regexp::result::copy_named_substring(const char *stringname, char *buffer, int bufsize) const throw(std::exception) {
	_ASSERTE(code);
	regexp::check_stringname(stringname);
	return pcre_copy_named_substring(code.get(), _subject.c_str(),
		_Ovec::get(), count, stringname, buffer, bufsize);
}

int regexp::result::get_named_substring(const char *stringname, const char **stringptr) const throw(std::exception) {
	_ASSERTE(code);
	regexp::check_stringname(stringname);
	return pcre_get_named_substring(code.get(), _subject.c_str(),
		_Ovec::get(), count, stringname, stringptr);
}

} // namespace PCRE
