
/*****************************************************************************
 *                                                                           *
 *  flirtmatch.h: Code snippet creator plugin for ida pro                    *
 *  (c) 2005-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef _flirtmatch_h_
#define _flirtmatch_h_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif // __cplusplus

#include "plugida.hpp"

namespace LNM {

extern class clist : public CIdaChooser {
protected:
	struct item_t {
		ea_t ea;
		string name;
		uint16 ID;
		string comment;
		bool iscode;

		item_t(ea_t ea, const char *name, uint16 ID, const char *comment = 0,
			bool iscode = true) : ea(ea),  ID(ID), iscode(iscode) {
			if (name != 0) this->name.assign(name);
			if (comment != 0) this->comment.assign(comment);
		}

		inline operator ea_t() const throw() { return ea; }
	};

	set<item_t> items;

public:
	operator size_t() const { return items.size(); }

	bool Add(ea_t ea, const char *name, uint16 ID,
		const char *comment = 0, bool iscode = true)
			{ return items.insert(item_t(ea, name, ID, comment, iscode)).second; }
	bool Open() {
		if (items.empty()) {
#if IDP_INTERFACE_VERSION >= 76
			Close();
#endif
			return false;
		}
#if IDA_SDK_VERSION >= 520
		if (IsOpen() && Refresh()) return true; // re-use existing rather than opening new
#endif
		static const int widths[] = { 13, 31, 9, 36, 7, };
		choose2(0, -1, -1, -1, -1, this, qnumber(widths), widths, sizer, getl,
			GetTitle(), GetIcon(0), 1, 0, 0, 0, 0, enter, destroy, 0, get_icon);
		PLUGIN.flags &= ~PLUGIN_UNL;
		return true;
	}
	void Clear() { items.clear(); }

protected:
	const char *GetTitle() const { return "Lib names matching"; }
	// IDA callback overrides
	void GetLine(ulong n, char * const *arrptr) const;
	void Enter(ulong n) const {
		_ASSERTE(n > 0);
		if (n > operator size_t()) return; //_ASSERTE(n <= operator size_t());
		const ea_t ea(at(items, n - 1));
		if (isEnabled(ea)) jumpto(ea); else MessageBeep(MB_ICONWARNING);
	}
	int GetIcon(ulong n) const;
} list;

bool Execute();

} // namespace LNM

#endif // _flirtmatch_h_
