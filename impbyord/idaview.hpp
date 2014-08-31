
///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// This is the adaptor class for kernel's choose2(...) function              //
// (c) 2003(?)-2008 servil <servil@gmx.net>                                  //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#ifndef _IDAVIEW_HPP_
#define _IDAVIEW_HPP_

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "undbgnew.h"
#include "mscrtdbg.h"
#define NOMINMAX 1
#include <wtypes.h>
#include <boost/noncopyable.hpp>
#include "idasdk.hpp"

extern const double kernel_version;

// *********************** class CIdaChooser *********************************
class __declspec(novtable) CIdaChooser : private boost::noncopyable {
private:
	// declare type item_t having all column data
	// optionally declare item_t constructor for convenient inserting by Add(...)
	//
	//struct item_t {
	//	ea_t address;
	//	uint16 type;
	//	std::string desc;
	//	...
	//
	//	item_t(ea_t address, uint16 type, const char *desc) :
	//		address(address), type(type), desc(desc) {
	//		_ASSERTE(isEnabled(address));
	//		_ASSERTE(desc != 0 && *desc != 0);
	//	}
	//
	//	inline bool operator <(const item_t &rhs) const {
	//		return address < rhs.address || address == rhs.address && type < rhs.type;
	//	}
	//};
	//
	// declare private container member of item_t's (e.g. STL container):
	//
	//set<item_t> items;

public:
#if IDP_INTERFACE_VERSION >= 76
	inline ~CIdaChooser() { Close(); }
#endif

	// must define: return count of lines in the list
	virtual operator size_t() const = 0; // call items.size()

	// declare item adder: return true if new item was inserted successfully
	//bool Add(...) {
	//	return items.insert(item_t(...)).second;
	//}
	virtual void Clear() { /*items.clear();*/ }
	bool Open() {
		if (operator size_t() <= 0/*items.empty()*/) {
#if IDP_INTERFACE_VERSION >= 76
			Close();
#endif
			return false;
		}
#if IDA_SDK_VERSION >= 520
		if (IsOpen() && Refresh()) return true; // re-use existing rather than opening new
#endif
		return false;
		//static int const widths[] = { 13, 12, 75, };
		//choose2(0/*CH_MULTI*/, -1, -1, -1, -1, this, qnumber(widths), widths,
		//	sizer, getl, GetTitle(), GetIcon(0), 1, del, ins, update, edit, enter,
		//	destroy, 0/*popup_names*/, get_icon);
		//PLUGIN.flags &= ~PLUGIN_UNL;
		//return true;
	}
#if IDP_INTERFACE_VERSION >= 76 // kernel v4.9 and above
	inline bool Close() {
		const char *const title = GetTitle();
		return title != 0 ? close_chooser(title) : false;
	}
#if IDA_SDK_VERSION >= 510
	TForm *GetTForm() const
		{ return kernel_version >= 5.1/*??*/ ? find_tform(GetTitle()) : NULL; }
	inline bool IsOpen() const
		{ return GetTForm() != NULL; }
	inline void SwitchTo(bool take_focus = true) const
		{ if (IsOpen()) switchto_tform(GetTForm(), take_focus); }
	inline HWND getHwnd() const
		{ return IsOpen() ? get_tform_handle(GetTForm()) : NULL; }
	//inline operator HWND() const
	//	{ return getHwnd(); }
#if IDA_SDK_VERSION >= 520
	bool Refresh() const {
		if (kernel_version < 5.2) return false;
		const char *const title = GetTitle();
		return title != 0 ? refresh_chooser(title) : false;
	}
#endif // SDK >= 5.2
#endif // SDK >= 5.1
#endif // SDK >= 4.9

protected:
	// for non-modal viewers
	virtual const char *GetTitle() const { return 0; }
	// IDA callback overrides
	virtual void GetLine(ulong n, char * const *arrptr) const = 0;
	//{
	//	if (n == 0) { // header
	//		static const char *const headers[] = { "address", "type", "description", };
	//		for (uint i = 0; i < qnumber(headers); ++i)
	//			qstrncpy(arrptr[i], headers[i], MAXSTR);
	//	} else { // item exists
	//		//_ASSERTE(n <= operator size_t());
	//		if (n > operator size_t()) return;
	//		const item_t &item(at(items, n - 1));
	//		ea2str(item.address, arrptr[0], MAXSTR); //qsnprintf(arrptr[0], MAXSTR, "%08a", item.address);
	//		switch (item.type) {
	//			case 0: qstrncpy(arrptr[1], "....", MAXSTR); break;
	//			case 1: ...
	//			default:
	//				*arrptr[1] = 0;
	//				_RPT3(_CRT_ASSERT, "%s(%u, ...): unexpected item kind (%hu)\n",
	//					__FUNCTION__, n, item.type);
	//		}
	//		if (!item.desc.empty())
	//			qstrncpy(arrptr[2], item.desc.c_str(), MAXSTR);
	//		else
	//			*arrptr[2] = 0;
	//		...
	//	}
	//}
#if IDP_INTERFACE_VERSION < 70 // too old
	virtual void Delete(ulong n) {
		_ASSERTE(n > 0 && n <= operator size_t());
	}
#else
	// returns 0:ok 1:failed (???)
	virtual ulong Delete(ulong n) {
		_ASSERTE(n > 0 && n <= operator size_t());
		return 0;
	}
#endif
	virtual void Insert() { }
	// returns new location of item 'n'
	virtual ulong Update(ulong n) {
		_ASSERTE(n > 0 && n <= operator size_t());
		return n;
	}
	virtual void Edit(ulong n) {
		_ASSERTE(n > 0 && n <= operator size_t());
	}
	virtual void Enter(ulong n) const {
		_ASSERTE(n > 0 && n <= operator size_t());
		//const ea_t ea(at(items, n - 1).address);
		//if (isEnabled(ea)) jumpto(ea); else MessageBeep(MB_ICONWARNING);
	}
	virtual int GetIcon(ulong n) const {
		if (n == 0) return -1; // replace by list head icon
		//_ASSERTE(n <= operator size_t());
		//if (n <= operator size_t()) switch (at(items, n - 1).type) {
		//	case 0: return ...;
		//	case 1: return ...;
		//	...
		//#ifdef _DEBUG
		//	default:
		//		_RPT3(_CRT_ASSERT, "%s(%u): unexpected item kind (%hu)\n",
		//			__FUNCTION__, n, at(items, n - 1).type);
		//#endif // _DEBUG
		//}
		return -1; // display no icon
	}
	virtual void Destroy() { Clear(); }

	// chooser2(...) callback adaptors
	static ulong idaapi sizer(void *obj) { return static_cast<ulong>(static_cast<CIdaChooser *>(obj)->operator size_t()); }
	static void idaapi getl(void *obj,ulong n,char * const *arrptr) { static_cast<CIdaChooser *>(obj)->GetLine(n, arrptr); }
#if IDP_INTERFACE_VERSION < 70
	static void idaapi del(void *obj,ulong n) { static_cast<CIdaChooser *>(obj)->Delete(n); }
#else
	static ulong idaapi del(void *obj,ulong n) { return static_cast<CIdaChooser *>(obj)->Delete(n); }
#endif
	static void idaapi ins(void *obj) { static_cast<CIdaChooser *>(obj)->Insert(); }
	static ulong idaapi update(void *obj,ulong n) { return static_cast<CIdaChooser *>(obj)->Update(n); }
	static void idaapi edit(void *obj,ulong n) { static_cast<CIdaChooser *>(obj)->Edit(n); }
	static void idaapi enter(void * obj,ulong n) { static_cast<CIdaChooser *>(obj)->Enter(n); }
	static void idaapi destroy(void *obj) { static_cast<CIdaChooser *>(obj)->Destroy(); }
	static int idaapi get_icon(void *obj,ulong n) { return static_cast<CIdaChooser *>(obj)->GetIcon(n); }
}; // CIdaChooser

class __declspec(novtable) CIdaDynTitleChooser : public CIdaChooser {
public:
	CIdaDynTitleChooser() : _M_is_constructed(true) { }
	CIdaDynTitleChooser(const char *title) : _M_is_constructed(true) { SetTitle(title); }
	CIdaDynTitleChooser(const std::string &title) : _M_is_constructed(true), title(title) { }

	~CIdaDynTitleChooser() { _M_is_constructed = false; } // title string is destructed now, don't use anymore

protected:
	std::string title;

	inline bool SetTitle(const char *title) {
		_ASSERTE(title != 0);
		if (title == 0) return false;
		this->title.assign(title);
		return true;
	}
	inline void SetTitle(const std::string &title) { this->title.assign(title); }
	const char *GetTitle() const throw() { return _M_is_constructed ? title.c_str() : 0; }
// 	std::string &GetTitle() {
// 		if (!_M_is_constructed) throw std::runtime_error("not constructed");
// 		return title;
// 	}

private:
	bool _M_is_constructed;
}; // CIdaDynTitleChooser

#endif // _IDAVIEW_HPP_
