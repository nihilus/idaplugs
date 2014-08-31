
///////////////////////////////////////////////////////////////////////////////
//
//  pcre_replacer.cpp: regexp replacer helper class for pcre library
//  (c) 2007-2008 servil <servil@gmx.net>
//

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include <ctime>
#include <cstdarg>
#include "mscrtdbg.h"
#include "msvc70rt.h"
#include <sstream>
#include <typeinfo>
#include <boost/algorithm/string.hpp>
#include <boost/functional.hpp>
#include "pcre_replacer.hpp"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

namespace PCRE {

static int _sprintf(std::string &s, const char *format, ...) {
	s.clear();
	_ASSERTE(format != 0);
	if (format == 0) return -1;
	int len;
	try {
		va_list va;
		va_start(va, format);
		if ((len = _vscprintf(format, va)) >= 0) {
			s.resize(len, 0);
			_vsnprintf(const_cast<char *>(s.data()), len, format, va);
		}
		va_end(va);
	} catch (const std::exception &e) {
		s.clear();
		len = -1;
		_RPT3(_CRT_ERROR, "%s(...): _vs*printf(..., \"%-.4000s\", ...) crashed: %s\n",
			__FUNCTION__, format, e.what());
	}
	return len;
}

enum conversion_t {
	as_is = 0,
	to_lower, to_upper, invert,
	to_lower_one, to_upper_one, invert_one,
};

static inline void upper_character(std::string::reference ch,
	const std::locale &loc) { ch = std::toupper(ch, loc); }
static inline void lower_character(std::string::reference ch,
	const std::locale &loc) { ch = std::tolower(ch, loc); }
static void invert_character(std::string::reference ch,
	const std::locale &loc) {
	if (std::isupper(ch, loc)) lower_character(ch, loc);
		else if (std::islower(ch, loc)) upper_character(ch, loc);
}

static void apply_case_and_width(std::string &s, conversion_t conversion,
	const regexp::result &match, int start_index, const std::locale &loc) {
	if (!s.empty()) switch (conversion) {
		case to_lower_one: lower_character(s[0], loc); break;
		case to_lower: boost::to_lower(s, loc); break;
		case to_upper_one: upper_character(s[0], loc); break;
		case to_upper: boost::to_upper(s, loc); break;
		case invert_one: invert_character(s[0], loc); break;
		case invert:
			std::for_each(s.begin(), s.end(), boost::bind2nd(invert_character, loc));
			break;
	} // conversion
	// width
	if (match < start_index + 2) return;
	const std::string::size_type width = strtoul(match[start_index + 1], 0, 10);
	if (s.length() < width) {
		const char filler = match >= start_index + 4 ?
			strcmp(match[start_index + 3], "\\}") != 0 ?
				match[start_index + 3][0] : '}' : ' ';
		switch (std::toupper(match[start_index][0], loc)) {
			case 'L':
				s.append(width - s.length(), filler);
				break;
			case 'C':
				s.insert(s.begin(), width - s.length() >> 1, filler);
				s.append(width - s.length() - (width - s.length() >> 1), filler);
				break;
			case 'R':
				s.insert(s.begin(), width - s.length(), filler);
				break;
		}
	} else if (s.length() > width)
		if (match >= start_index + 3 && std::toupper(match[start_index + 2][0], loc) == 'L')
			s.erase(0, s.length() - width);
		else
			s.erase(width);
}

unsigned int replacer::exec(std::string &subject) {
	unsigned int total(0);
	int offset(0);
	regexp::result match[2];
	while (match[0](regex, subject, offset) >= 1) {
		// first, interpolate all substring references and control sequences in
		// replace string with substrings in actual match
		std::string r(replacestring);
		std::string::size_type roff(0);
		conversion_t conversion(as_is);
		bool quotation(false);
		std::string tmp;
		while (roff < r.length()) try {
			const char *const cs(r.c_str() + roff);
			if (quotation) {
				if (cs[0] == '\\' && cs[1] == 'E') {
					r.erase(roff, 2);
					quotation = false;
				} else
					++roff;
				continue;
			}
			bool dropconversion = conversion == to_lower_one
				|| conversion == to_upper_one || conversion == invert_one;
			if (cs[0] == '\\') switch (cs[1]) {
				case 't':
					r.replace(roff++, 2, 1, '\t');
					break;
				case 'n':
					r.replace(roff++, 2, 1, '\n');
					break;
				case 'r':
					r.replace(roff++, 2, 1, '\r');
					break;
				case 'L':
					conversion = to_lower;
					dropconversion = false;
					r.erase(roff, 2);
					break;
				case 'U':
					conversion = to_upper;
					dropconversion = false;
					r.erase(roff, 2);
					break;
				case 'I':
					conversion = invert;
					dropconversion = false;
					r.erase(roff, 2);
					break;
				case 'E':
				case '/':
					dropconversion = true;
					r.erase(roff, 2);
					break;
				case 'l':
					conversion = to_lower_one;
					dropconversion = false;
					r.erase(roff, 2);
					break;
				case 'u':
					conversion = to_upper_one;
					dropconversion = false;
					r.erase(roff, 2);
					break;
				case 'i':
					conversion = invert_one;
					dropconversion = false;
					r.erase(roff, 2);
					break;
				case 'Q':
					quotation = true;
					r.erase(roff, 2);
					break;
				case 'x': // literal in form of hex ordinal number
					if (match[1](is_ordinal[0]/*\x41*/, cs + 2) >= 2
						|| match[1](is_ordinal[1]/*\x{061} - care!*/, cs + 2) >= 2)
						r.replace(roff++, match[1].length(), 1,
							static_cast<char>(strtoul(match[1][1], 0, 16)));
					else {
						_RPTF4(_CRT_WARN, "%s(\"%s\"): invalid literal code in replace string at '%s'[%Iu[\n",
							__FUNCTION__, subject.c_str(), r.c_str(), roff);
						r.erase(roff, 2);
					}
					break;
				case '#': // macro: counter
					match[1](is_counter/*\#{...}*/, cs + 2);
					try {
						if (match[1] >= 5) {
							const bool issign(match[1].length(1) > 0), ishex(match[1].length(4) > 0),
								showsign(match[1] >= 7 && match[1].length(6) > 0);
							_ASSERTE(!issign || strcmp(match[1][1], "-") == 0);
							_ASSERTE(!ishex || _stricmp(match[1][4], "h") == 0);
							_ASSERTE(!showsign || _stricmp(match[1][6], "s") == 0);
							const int width(match[1] >= 6 ?
								static_cast<int>(strtoul(match[1][5], 0, 10)) : 0);
							int counter_adjusted;
							char fmt_char;
							if (ishex) {
								counter_adjusted = static_cast<int>(strtoul(match[1][3], 0, 16));
								fmt_char = 'X';
							} else {
								counter_adjusted = static_cast<int>(strtoul(match[1][2], 0, 10));
								fmt_char = 'i';
							}
							char s[12];
							std::fill_n(s, ARRAY_SIZE(s), 0);
							if (issign) counter_adjusted = -counter_adjusted;
							if ((counter_adjusted += static_cast<int>(counter)) < 0) {
								s[0] = '-';
								counter_adjusted = -counter_adjusted;
								_ASSERTE(counter_adjusted >= 0);
							} else if (showsign)
								s[0] = '+';
							const size_t len(strlen(s));
							_snprintf(s + len, ARRAY_SIZE(s) - len, "%%0*%c", fmt_char);
							_sprintf(tmp, s, width, counter_adjusted);
						} else
							_sprintf(tmp, "%u", counter);
						apply_case_and_width(tmp, conversion, match[1], 7, loc); // ??? (doubtful)
						r.replace(roff, (match[1] >= 1 ? match[1].length() : 0), tmp);
						roff += tmp.length();
#ifdef _DEBUG
					} catch (const std::exception &e) {
						_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
							"%s(\"%s\"): %s during replace string interpolation at '%s'[%Iu]\n",
							__FUNCTION__, subject.c_str(), e.what(), r.c_str(), roff);
#else // !_DEBUG
					} catch (...) {
#endif // _DEBUG
						dropconversion = false;
						r.erase(roff, 2 + (match[1] >= 1 ? match[1].length() : 0));
					}
					break;
				case 'D': // macro: date/time value
					if (match[1](is_datetime/*\D{Y}*/, cs + 2) >= 2) try {
						_ASSERTE(match[1].start() == 0);
						_tzset();
						__time64_t now;
						_time64(&now);
						const tm *newtime(_localtime64(&now));
						if (newtime == 0) throw std::logic_error("_localtime64(...) failed");
						if (strcmp(match[1][1], "Y") == 0)
							_sprintf(tmp, "%i", 1900 + newtime->tm_year);
						else if (strcmp(match[1][1], "M") == 0)
							_sprintf(tmp, "%i", newtime->tm_mon);
						else if (strcmp(match[1][1], "D") == 0)
							_sprintf(tmp, "%i", newtime->tm_mday);
						else if (strcmp(match[1][1], "h") == 0)
							_sprintf(tmp, "%i", newtime->tm_hour);
						else if (strcmp(match[1][1], "m") == 0)
							_sprintf(tmp, "%i", newtime->tm_min);
						else if (strcmp(match[1][1], "s") == 0)
							_sprintf(tmp, "%i", newtime->tm_sec);
						else {
							std::ostringstream oss;
							oss.imbue(loc);
							std::use_facet<std::time_put<char> >(loc).
								put(std::ostreambuf_iterator<char>(oss.rdbuf()),
								oss, ' ', newtime, match[1][1], match[1][1] + match[1].length(1));
							tmp.assign(oss.str());
						}
						if (tmp.empty()) throw std::logic_error("invalid time format parameter");
						apply_case_and_width(tmp, conversion, match[1], 2, loc);
						r.replace(roff, 2 + match[1].length(), tmp);
						roff += tmp.length();
						break;
#ifdef _DEBUG
					} catch (const std::exception &e) {
						_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
							"%s(\"%s\"): %s during replace string interpolation at '%s'[%Iu]\n",
							__FUNCTION__, subject.c_str(), e.what(), r.c_str(), roff);
#else // !_DEBUG
					} catch (...) {
#endif // _DEBUG
						dropconversion = false;
						r.erase(roff, 2 + match[1].length());
						break;
					}
				default: // otherwise literalize whatever next character
					r.erase(roff++, 1);
			} else if (cs[0] == '$' && cs[1] == '$') {
				r.replace(roff, 2, "\\r\\n");
				roff += 2;
			} else if (match[1](is_subnum/*$1*/, cs) >= 2) try {
				_ASSERTE(match[1].start() == 0);
				tmp.assign(match[0][std::isdigit(match[1][1][0], loc) ?
					static_cast<int>(match[1][1][0] - '0') :
					10 + (std::toupper(match[1][1][0], loc) - 'A')]);
				if (tmp.empty()) throw std::logic_error("subpattern is empty");
				apply_case_and_width(tmp, conversion, match[1], 2, loc);
				r.replace(roff, match[1].length(), tmp);
				roff += tmp.length();
#ifdef _DEBUG
			} catch (const std::exception &e) {
				_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
					"%s(\"%s\"): %s during replace string interpolation at '%s'[%Iu]\n",
					__FUNCTION__, subject.c_str(), e.what(), r.c_str(), roff);
#else // !_DEBUG
			} catch (...) {
#endif // _DEBUG
				dropconversion = false;
				r.erase(roff, match[1].length());
			} else if (match[1](is_subname/*${name}*/, cs) >= 2) try {
				_ASSERTE(match[1].start() == 0);
				const char *foo = match[0][match[1][1]];
				if (foo == 0) foo = getenv(match[1][1]);
				if (foo == 0) throw std::logic_error("subpattern name mismatch");
				if (*foo == 0) throw std::logic_error("subpattern is empty");
				apply_case_and_width(tmp.assign(foo), conversion, match[1], 2, loc);
				r.replace(roff, match[1].length(), tmp);
				roff += tmp.length();
#ifdef _DEBUG
			} catch (const std::exception &e) {
				_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
					"%s(\"%s\"): %s during replace string interpolation at '%s'[%Iu]\n",
					__FUNCTION__, subject.c_str(), e.what(), r.c_str(), roff);
#else // !_DEBUG
			} catch (...) {
#endif // _DEBUG
				dropconversion = false;
				r.erase(roff, match[1].length());
			} else { // simple literal (no interpolation)
				switch (conversion) {
					case to_lower:
					case to_lower_one:
						lower_character(r[roff], loc);
						break;
					case to_upper:
					case to_upper_one:
						upper_character(r[roff], loc);
						break;
					case invert:
					case invert_one:
						invert_character(r[roff], loc);
						break;
				} // switch conversion
				++roff;
			}
			if (dropconversion) conversion = as_is;
#ifdef _DEBUG
		} catch (const std::exception &e) {
			_CrtDbgReport(_CRT_ERROR, __FILE__, __LINE__, __FUNCTION__,
				"%s(\"%s\"): %s during replace string interpolation at '%s'[%Iu]\n",
				__FUNCTION__, subject.c_str(), e.what(), r.c_str(), roff);
#else // !_DEBUG
		} catch (...) {
#endif // _DEBUG
			break; ///*re*/throw;
		}
		if (r != match[0][0]) {
			subject.replace(match[0].start(), match[0].length(), r);
			++total;
			++counter;
			offset = match[0].start() + r.length();
		} else
			offset = match[0].start() + 1;
	} // while match
	return total;
} // exec

#define FORMAT_SUFFIX "(?i:\\-\\{([LCR])(?:,(\\d+)(?:,([LR])(?:,([^\\\\\\}]|\\\\\\}))?)?)?\\})?"
/*__declspec(selectany) */const regexp
	replacer::is_subnum("^\\$([[:alnum:]])" FORMAT_SUFFIX, 0, true),
	replacer::is_subname("^\\$\\{(\\w+)\\}" FORMAT_SUFFIX, 0, true),
	replacer::is_ordinal[2] = {
		regexp("^([[:xdigit:]]{1,2})", PCRE_CASELESS, true),
		regexp("^\\{([[:xdigit:]]+)\\}", PCRE_CASELESS, true),
	},
	replacer::is_datetime("^\\{((?:[^\\\\\\}]|\\\\\\})+)\\}" FORMAT_SUFFIX, 0, true),
	replacer::is_counter("^\\{(\\-)?(\\d+|([[:xdigit:]]+)(h))(?:,(\\d+)(?:,(s))?)?\\}" FORMAT_SUFFIX, PCRE_CASELESS, true);
#undef FORMAT_SUFFIX

} // namespace PCRE
