
// Indirect call runtime resolver report list definition

#ifndef _RTRLIST_H_ /* #pargma once */
#define _RTRLIST_H_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "undbgnew.h"
#include "mscrtdbg.h"
#define NOMINMAX 1
#include <windows.h>
#include "idasdk.hpp"
#include "plughlpr.hpp"
#include "idaview.hpp"
#include "dbgnew.h"

extern class CRTRList : public CIdaChooser {
protected:
	struct item_t {
		ea_t from, to;
		uint16 type;
		std::string text;

		item_t(ea_t from, ea_t to, uint16 type = 0, const char *text = 0) :
			from(from), to(to), type(type) { if (text != 0) this->text.assign(text); }

		inline bool operator <(const item_t &r) const throw()
			{ return from < r.from || from == r.from && to < r.to; }
		inline operator ea_t() const throw() { return from; }
	};

	std::set<item_t> items;

public:
	operator size_t() const { return items.size(); }

	bool Add(ea_t from, ea_t to, uint16 type, const char *text = 0)
		{ return items.insert(item_t(from, to, type, text)).second; }
	bool Has(ea_t from, ea_t to) const
		{ return items.find(item_t(from, to)) != items.end(); }
	bool Open() {
		if (items.empty()) {
#if IDP_INTERFACE_VERSION >= 76
			//Close();
#endif
			return false;
		}
#if IDA_SDK_VERSION >= 520
		//if (IsOpen() && Refresh()) return true; // re-use existing rather than opening new
#endif
		static int const widths[] = { 13, 9, 8, 68, };
		choose2(0, -1, -1, -1, -1, this, qnumber(widths), widths, sizer, getl,
			GetTitle(), GetIcon(0), 1, 0, 0, 0, 0, enter, destroy, 0, get_icon);
		PLUGIN.flags &= ~PLUGIN_UNL;
		return true;
	}
	void Clear() { items.clear(); }

protected:
	const char *GetTitle() const { return "Runtime resolved targets"; }
	// IDA callback overrides
	void GetLine(ulong n, char * const *arrptr) const {
		if (n == 0) { // header
			static const char *const headers[] = { "from", "relation", "to", "result", };
			for (uint i = 0; i < qnumber(headers); ++i)
				qstrncpy(arrptr[i], headers[i], MAXSTR);
		} else { // regilar item
			if (n > operator size_t()) return; //_ASSERTE(n <= operator size_t());
			const item_t &item(at(items, n - 1));
			ea2str(item.from, arrptr[0], MAXSTR); //qsnprintf(arrptr[0], MAXSTR, "%08a", item.from); // 1. address
			switch (item.type) { // 3. type
				case fl_CN: qstrncpy(arrptr[1], "call near", MAXSTR); break;
				case fl_CF: qstrncpy(arrptr[1], "call far", MAXSTR); break;
				case fl_JN: qstrncpy(arrptr[1], "jump near", MAXSTR); break;
				case fl_JF: qstrncpy(arrptr[1], "jump far", MAXSTR); break;
				case dr_I: qstrncpy(arrptr[1], "data offset", MAXSTR); break;
				case 0xFFFF: qstrncpy(arrptr[1], "problem", MAXSTR); break;
				default: qsnprintf(arrptr[1], MAXSTR, "%04hX", item.type);
			} // switch statement
			if (item.type != 0xFFFF) // 2. address
				qsnprintf(arrptr[2], MAXSTR, "%08a", item.to); //ea2str(item.to, arrptr[2], MAXSTR);
			else
				*arrptr[2] = 0;
			if (!item.text.empty()) // 4. description
				qstrncpy(arrptr[3], item.text.c_str(), MAXSTR);
			else
				*arrptr[3] = 0;
		} // regular item
	}
	void Enter(ulong n) const {
		_ASSERTE(n > 0);
		if (n > operator size_t()) return; //_ASSERTE(n <= operator size_t());
		const ea_t ea(at(items, n - 1));
		if (isEnabled(ea)) jumpto(ea); else MessageBeep(MB_ICONWARNING);
	}
	int GetIcon(ulong n) const {
		if (n == 0) return 88; // list head icon
		if (n > operator size_t()) return -1; //_ASSERTE(n <= operator size_t());
		switch (at(items, n - 1).type) {
			case fl_CN: return 84; // xref created
			case fl_CF: return 93; // xref created
			case fl_JN: return 85; // xref created
			case fl_JF: return 90; // xref created
			case dr_I: return 23; // dref
			case 0xFFFF: return 60; // Al_Fatal
		}
		return 84;
	}
} rtrlist;

#endif // _RTRLIST_H_
