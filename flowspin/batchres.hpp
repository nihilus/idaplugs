
#ifndef _BATCHRES_HPP_
#define _BATCHRES_HPP_ 1

#include "undbgnew.h"
#include "mscrtdbg.h"
#include <algorithm>
#include <vector>
#define NOMINMAX 1
#include <windows.h>
#include "idaview.hpp"
#include "plughlpr.hpp"

class CBatchResults : public CIdaChooser {
protected:
	struct item_t {
		ea_t ea;
		uint16 type;
		string text;

		item_t(ea_t ea, uint16 type, const char *text = 0) : ea(ea), type(type)
			{ if (text != 0) this->text.assign(text); }

		inline bool operator ==(const item_t &r) const throw()
			{ return ea == r.ea && type == r.type; }
		inline bool operator <(const item_t &r) const throw()
			{ return ea < r.ea || ea == r.ea && type < r.type; }
		inline operator ea_t() const throw() { return ea; }
	};

	std::vector/*set*/<item_t> items;

public:
	operator size_t() const { return items.size(); }

	bool Add(ea_t ea, uint16 type, const char *text = 0) {
		//return items.insert(item_t(ea, type, text)).second;
		const item_t item(ea, type, text);
		const bool unique(std::find(CONTAINER_RANGE(items), item) == items.end());
		if (unique) items.push_back(item);
		return unique;
	}
	bool Has(ea_t ea, uint16 type) const {
		//return items.find(item_t(ea, type)) != items.end();
		return std::find(CONTAINER_RANGE(items), item_t(ea, type)) != items.end();
	}
	void Sort() { std::sort(CONTAINER_RANGE(items)); }
	bool Open() {
		if (items.empty()) {
#if IDP_INTERFACE_VERSION >= 76
			Close();
#endif
			return false;
		}
		Sort();
#if IDA_SDK_VERSION >= 520
		if (IsOpen() && Refresh()) return true; // re-use existing rather than opening new
#endif
		static int const widths[] = { 13, 14, 73, };
		choose2(0, -1, -1, -1, -1, this, qnumber(widths), widths, sizer, getl,
			GetTitle(), GetIcon(0), 1, 0, 0, 0, 0, enter, destroy, 0, get_icon);
		PLUGIN.flags &= ~PLUGIN_UNL;
		return true;
	}
	void Clear() { items.clear(); }

protected:
	const char *GetTitle() const { return "Fubar rèsumè"; }
	// IDA callback overrides
	void GetLine(ulong n, char * const *arrptr) const {
		if (n == 0) { // header
			static const char *const headers[] = { "address", "change type", "result", };
			for (uint i = 0; i < qnumber(headers); ++i)
				qstrncpy(arrptr[i], headers[i], MAXSTR);
		} else { // regular item
			if (n > operator size_t()) return; //_ASSERTE(n <= operator size_t());
			const item_t &item(items.at(n - 1));
			ea2str(item.ea, arrptr[0], MAXSTR); //qsnprintf(arrptr[0], MAXSTR, "%08a", item.ea);
			switch (item.type) {
				case 0x0001: qstrncpy(arrptr[1], "lstring", MAXSTR); break;
				case 0x0002: qstrncpy(arrptr[1], "pstring", MAXSTR); break;
				case 0x0003: qstrncpy(arrptr[1], "function", MAXSTR); break;
				case 0x0004: qstrncpy(arrptr[1], "seh frame", MAXSTR); break;
				case 0x0005: qstrncpy(arrptr[1], "offset", MAXSTR); break;
				case 0x0006: qstrncpy(arrptr[1], "signess", MAXSTR); break;
				case 0x0007: qstrncpy(arrptr[1], "fake name", MAXSTR); break;
				case 0x0008: qstrncpy(arrptr[1], "bp frame", MAXSTR); break;
				case 0x0009: qstrncpy(arrptr[1], "mfc messagemap", MAXSTR); break;
				case 0x000A: qstrncpy(arrptr[1], "doubtful function", MAXSTR); break;
				case 0x000B: qstrncpy(arrptr[1], "false function", MAXSTR); break;
				case 0x000C: qstrncpy(arrptr[1], "offset renamed", MAXSTR); break;
				case 0x000D: qstrncpy(arrptr[1], "vcl object template", MAXSTR); break;
				case 0x000E: qstrncpy(arrptr[1], "stack variable", MAXSTR); break;
				case 0x0031:
				case 0x0032:
				case 0x0200: qstrncpy(arrptr[1], "suspicious offset", MAXSTR); break;
				case 0x0100: qstrncpy(arrptr[1], "information", MAXSTR); break;
				case 0xFFFF: qstrncpy(arrptr[1], "problem", MAXSTR); break;
				default: qsnprintf(arrptr[1], MAXSTR, "%04hX", item.type);
			}
			if (!item.text.empty())
				qstrncpy(arrptr[2], item.text.c_str(), MAXSTR);
			else
				*arrptr[2] = 0;
		} // regular item
	}
	void Enter(ulong n) const {
		_ASSERTE(n > 0);
		if (n > operator size_t()) return; //_ASSERTE(n <= operator size_t());
		const ea_t ea(items.at(n - 1));
		if (isEnabled(ea)) jumpto(ea); else MessageBeep(MB_ICONWARNING);
	}
	int GetIcon(ulong n) const {
		if (n == 0) return 106; // list head icon
		//_ASSERTE(n <= operator size_t());
		if (n <= operator size_t()) switch (items.at(n - 1).type) {
			case 0x0001: return 82;  // L-String
			case 0x0002: return 0;   // P-String
			case 0x0003: return 13;  // new func
			case 0x0004: return 72;  // SEH frame
			case 0x0005: return 20;  // offset
			case 0x0006: return 17;  // signess
			case 0x0007: return 32;  // fake name
			case 0x0008: return 101; // BP-frame
			case 0x0009: return 52;  // msgmap
			case 0x000A:
			case 0x000B: return 90;  // doubtful function
			case 0x000C: return 19;  // offset renamed
			case 0x000D: return 122;  // vcl object template
			case 0x000E: return 15;  // stack variable created
			case 0x0031:
			case 0x0032:
			case 0x0200: return 21; // offset misalignment
			case 0x0100: return 42;  // information
			case 0xFFFF: return 60;  // warning
		}
		return -1;
	}
};

#endif // _BATCHRES_HPP_
