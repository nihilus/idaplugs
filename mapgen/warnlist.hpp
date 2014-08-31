
#ifndef _WARNLIST_H_ /* #pragma once */
#define _WARNLIST_H_ 1

#include "batchres.hpp"

class CWarningList : public CBatchResults {
public:
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
		static int const widths[] = { 13, 17, 70, };
		choose2(0, -1, -1, -1, -1, this, qnumber(widths), widths, sizer, getl,
			GetTitle(), GetIcon(0), 1, 0, 0, 0, 0, enter, destroy, 0, get_icon);
		PLUGIN.flags &= ~PLUGIN_UNL;
		return true;
	}

protected:
	const char *GetTitle() const { return "Data format warnings"; }
	// IDA callback overrides
	void GetLine(ulong n, char * const *arrptr) const {
		if (n == 0) { // header
			static const char *const headers[] = { "address", "warning Id", "description", };
			for (uint i = 0; i < qnumber(headers); ++i)
				qstrncpy(arrptr[i], headers[i], MAXSTR);
		} else {
			if (n > operator size_t()) return; //_ASSERTE(n <= operator size_t());
			const item_t &item(items.at(n - 1));
			ea2str(item.ea, arrptr[0], MAXSTR); //qsnprintf(arrptr[0], MAXSTR, "%08a", item.ea);
			switch (item.type) {
				case 0x0007: // unexpected code
				case 0x0417: // hole inside variable
				case 0x0517: // unexpected alignment
					qstrncpy(arrptr[1], "DATA CONTINUITY", MAXSTR);
					break;
				case 0x0005: // variable overlap
				case 0x0205: // variable truncation
					qstrncpy(arrptr[1], "DATA BOUNDS", MAXSTR);
					break;
				case 0x0008: // ref to tail
				case 0x0021: // ref to align
				case 0x0031: // ref to tail
				case 0x0032: // dword unaligned
				case 0x0010: // auto align?
				case 0x0200: // access violation from static data
					qstrncpy(arrptr[1], "UNSURE OFFSET", MAXSTR);
					break;
				case 0x0FFF:
					qstrncpy(arrptr[1], "PROBLEM", MAXSTR);
					break;
				case 0xFFFF:
					qstrncpy(arrptr[1], "CATASTROPHIC", MAXSTR);
					break;
				default:
					qsnprintf(arrptr[1], MAXSTR, "%04hX", item.type);
			}
			if (!item.text.empty())
				qstrncpy(arrptr[2], item.text.c_str(), MAXSTR);
			else
				*arrptr[2] = 0;
		}
	}
	int GetIcon(ulong n) const {
		if (n == 0) return 107; // list head icon
		//_ASSERTE(n <= operator size_t());
		if (n <= operator size_t()) switch (items.at(n - 1).type) {
			case 0x0007: return   2;  // unexpected code
			case 0x0031:
			case 0x0032:
			case 0x0008: return  21; // offset misalignment
			case 0x0005: return 110; // variable expansion?
			case 0x0517: // unexpected align directive inside data block
			case 0x0010: return  72; // auto align
			case 0x0021: return  64; // ref to align
			case 0x0200: return 126; // invalid address referred
			case 0x0205: return  43; // variable truncated?
			case 0x0417: return  32; // undefined hole inside variable
			case 0xFFFF: return  59; // Al_Fatal
		}
		return -1; //__super::GetIcon(n);
	}
}; // CWarningList

#endif // !_WARNLIST_H_
