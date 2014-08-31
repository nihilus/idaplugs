
/*****************************************************************************
 *                                                                           *
 *  xrefmgr.hpp: Code snippet creator: plugin for IDA Pro                      *
 *  (c) 2006-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef _XREFMGR_H_ // #pragma once
#define _XREFMGR_H_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "idasdk.hpp"
#include "idaview.hpp"
#include "undbgnew.h"
#include <boost/next_prior.hpp>
#include "dbgnew.h"

/*****************************************************************************
 *  *
 *  C0MPONENT 4: X-REF MANAGER  *
 *  *
 *****************************************************************************/

class CXRefManager : public CIdaChooser {
private:
	struct item_t : public xrefblk_t {
		inline operator ea_t() const throw() { return to; }
		inline bool operator <(const xrefblk_t &xref) const throw()
			{ return to < xref.to; }
	};

	ea_t from;
	multiset<item_t> items;

public:
	CXRefManager(ea_t from = get_screen_ea()) : from(from) { Rebuild(); }

	operator size_t() const { return items.size(); }

	void Clear() { items.clear(); }
	ea_t Lister(bool canchange = false) {
		static const int widths[] = { 10, 13, 30, 1, };
		char title[80];
		qsnprintf(CPY(title), "XRefs from %08a (use Ins/Del, Enter/Esc when done)", from);
		static const char *const popup_names[] = { "Add XRef", "Remove XRef", 0, "Refresh" };
		return operator[](choose2((void *)this, qnumber(widths), widths, sizer,
			getl, title, GetIcon(0), 1, canchange ? del : 0, canchange ? ins : 0,
			0/*update*/, 0/*edit*/, 0/*enter*/, 0/*destroy*/, popup_names, get_icon));
	}

protected:
	ea_t operator[](ulong n) const {
		//_ASSERTE(n > 0 && n <= operator size_t());
		return n == 0 || n > operator size_t() ? BADADDR : at(n - 1);
	}

	void Rebuild() {
		Clear();
		xrefblk_t xref;
		for (bool ok = xref.first_from(from, XREF_FAR); ok; ok = xref.next_from())
			if (isEnabled(xref.to)) items.insert(static_cast<item_t &>(xref));
	}
	const item_t &at(ulong n) const { return ::at(items, n); }

	// IDA callback overrides
	void GetLine(ulong n, char * const *arrptr) const {
		if (n == 0) { // header
			static const char *const headers[] = { "type", "address", "name", "user?", };
			for (uint i = 0; i < qnumber(headers); ++i)
				qstrncpy(arrptr[i], headers[i], MAXSTR);
		} else if (n > operator size_t())
			fill_n(*arrptr, 4, 0);
		else { // item exists
			const item_t &item(at(n - 1));
			const char *type;
			switch (item.type & 0x1F) {
				case dr_O: type = "offset"; break;
				case dr_W: type = "write address"; break;
				case dr_R: type = "read address"; break;
				case dr_T: type = "text"; break;
				case dr_I: type = "informational"; break;
				case fl_CF: type = "call far"; break;
				case fl_CN: type = "call near"; break;
				case fl_JF: type = "jump far"; break;
				case fl_JN: type = "jump near"; break;
				case fl_USobsolete: type = "obsolete"; break;
				case fl_F: type = "execution flow"; break;
				case fl_U:
				default: type = "unknown";
			}
			qstrncpy(arrptr[0], type, MAXSTR);
			ea2str(item.to, arrptr[1], MAXSTR); //qsnprintf(arrptr[1], MAXSTR, "%08a", item.to);
			if (get_short_name(item.to, item.to, arrptr[2], MAXSTR) == 0) *arrptr[2] = 0;
			qstrncpy(arrptr[3], item.user != 0 ? "U" : "", MAXSTR);
		} // item valid
	}
	ulong Delete(ulong n) {
		//_ASSERTE(n > 0 && n <= operator size_t());
		if (n == 0 || n > operator size_t()) return 0; // failed
		const multiset<item_t>::iterator deleter(boost::next(items.begin(), n - 1));
		if (deleter->iscode)
			del_cref(deleter->from, deleter->to, 0);
		else
			del_dref(deleter->from, deleter->to);
		items.erase(deleter); //Rebuild();
		return 1; // ok
	}
	void Insert() {
		const ea_t to(choose_name("Choose new link target"));
		if (to == BADADDR) return;
		xrefblk_t xref;
		for (bool ok = xref.first_from(from, XREF_FAR); ok; ok = xref.next_from())
			if (to == xref.to) return; // no dupes
		//item_t item;
		//item.from = from;
		//item.to = to;
		if (isCode(get_flags_novalue(from)) && isCode(get_flags_novalue(to))) {
			add_cref(from, to, (cref_t)(fl_USobsolete | XREF_USER));
			//item.iscode = 1;
			//item.type = fl_USobsolete;
		} else {
			add_dref(from, to, (dref_t)(dr_I | XREF_USER));
			//item.iscode = 0;
			//item.type = dr_I;
		}
		//item.user = 1;
		Rebuild(); //items.insert(item);
	}
	int GetIcon(ulong n) const {
		//_ASSERTE(n <= operator size_t());
		return n > operator size_t() ? -1 : n == 0 ? 55/*chooser icon*/ :
			at(n - 1).iscode ? 2 : 3;
	}
}; // CXRefManager

#endif // !_xrefmgr_h_
