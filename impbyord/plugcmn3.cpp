
/*****************************************************************************
 *                                                                           *
 *  plugcmn3.cpp: ida plugins shared code                                    *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#pragma warning(disable: 181)

#include "mscrtdbg.h"
#include "pcre.hpp"
#include "plugcmn.hpp"
#include "plughlpr.hpp"
#include "plugxcpt.hpp"

bool can_be_mfc_app() {
	netnode importz("$ imports");
	if (importz != BADNODE) for (ulong ndx = importz.sup1st(); ndx != BADNODE; ndx = importz.supnxt(ndx)) try {
		char impname[MAXSPECSIZE];
		if (importz.supstr(ndx, CPY(impname)) > 0
			&& pcre_match("^mfc\\d{2,}", impname, PCRE_CASELESS)) return true; // assumed by imported rtl
#ifdef _DEBUG
	} catch (const std::exception &e) {
		_RPT3(_CRT_ERROR, "%s(...): %s on iterating import node: index=0x%IX\n",
			__FUNCTION__, e.what(), ndx);
#endif // _DEBUG
	} catch (...) {
		_RPT3(_CRT_ERROR, "%s(...): %s on iterating import node: index=0x%IX\n",
			__FUNCTION__, "unknown exception", ndx);
	}
	char buf[MAXSPECSIZE/*??*/];
	ulong total(0);
	for (int counter = 0; counter < get_idasgn_qty(); ++counter) {
		const long applieds(get_idasgn_desc(counter, CPY(buf), NULL, 0));
		if (applieds != -1 && pcre_match("^vc(?:32|64)mfc", buf, PCRE_CASELESS))
			switch (calc_idasgn_state(counter)) {
				case IDASGN_APPLIED: total += applieds; break;
				case IDASGN_CURRENT:
				case IDASGN_PLANNED: return true;
			}
	}
	return total > 0;
}

ulong get_signature_state(const char *signame) {
	_ASSERTE(signame != 0 && *signame != 0);
	if (signame != 0 && *signame != 0) {
		std::string pattern(signame);
		const int extpos(pcre_match("\\.sig$", pattern.c_str(), PCRE_CASELESS));
		if (extpos >= 0) pattern.erase(extpos);
		const PCRE::regexp regex(pattern.insert(0, "^\\Q").append("\\E(?:\\.sig)?$"), PCRE_CASELESS/*, true*/);
		if (!regex) throw fmt_exception("failed to compile regexp for \"%s\"", signame);
		char buf[MAXSPECSIZE/*??*/];
		for (int counter = 0; counter < get_idasgn_qty(); ++counter) {
			const long applieds(get_idasgn_desc(counter, CPY(buf), NULL, 0));
			if (applieds >= 0 && regex.match(buf)) {
				const ulong state(static_cast<ulong>(calc_idasgn_state(counter)));
				_ASSERTE(state <= 7);
				if (state == IDASGN_APPLIED || state == IDASGN_CURRENT || state == IDASGN_PLANNED)
					return static_cast<ulong>(applieds) & SIG_COUNT | (state & 7) << 29;
			}
		}
	}
	return (IDASGN_BADARG & 7) << 29; // signature not in list
}

bool has_meaningful_name(ea_t ea) {
	_ASSERTE(isEnabled(ea));
	char tmp[MAXNAMESIZE];
	return has_name(get_flags_novalue(ea)) && get_true_name(BADADDR, ea, CPY(tmp)) != 0
		&& !pcre_match("^unknown_libname_\\d+$", tmp);
}
