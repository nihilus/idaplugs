
///////////////////////////////////////////////////////////////////////////////
//
//  pcre_replacer.hpp: regexp replacer helper class for pcre library
//  (c) 2007-2008 servil <servil@gmx.net>
//

#ifndef _PCRE_REPLACER_HPP_
#define _PCRE_REPLACER_HPP_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "undbgnew.h"
#include <clocale>
#include <string>
#include <locale>
#include <stdexcept>
#include "pcre.hpp"
#include "dbgnew.h"

namespace PCRE {

class replacer {
private:
	regexp regex;
	std::string replacestring;
	std::locale loc;
	static const regexp is_subnum, is_subname, is_ordinal[2], is_datetime, is_counter;
	unsigned int counter;

public:
	template<class T>replacer(const regexp &regex = regexp(),
		const T &replacestring = std::string(),
		const std::locale &loc = std::locale(setlocale(LC_ALL, NULL))) :
		counter(0), regex(regex), replacestring(replacestring), loc(loc) {
			if (!is_subnum || !is_subname || !is_ordinal[0] || !is_ordinal[1]
				|| !is_datetime || !is_counter) throw
					std::runtime_error("class PCRE::replacer not functional (one or more internal regexps failed to compile");
		}

	unsigned int exec(std::string &subject); // returns replacements performed
	inline void reset_counter() throw() { counter = 0; } // reset total

	// set new search and replace patterns
	template<class T>void operator ()(const regexp &regex, const T &replacestring = std::string()) {
		reset_counter();
		this->regex = regex;
		this->replacestring.assign(replacestring);
	}
	// set new locale
	void operator ()(const std::locale &loc) { this->loc = loc; }
	inline unsigned int operator()(std::string &subject) { return exec(subject); }
	// returns replacement performed in all exec(...) calls
	inline operator unsigned int() const throw() { return counter; }
}; // replacer

} // namespace PCRE

#endif // _PCRE_REPLACER_HPP_
