
/*****************************************************************************
 *                                                                           *
 *  plugcom.hpp: ida plugins OLE/COM routines                                *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef _PLUGCOM_HPP_
#define _PLUGCOM_HPP_ 1

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "undbgnew.h"
#include "fixdcstr.hpp"
#include <string>
#include <algorithm>
#include <boost/functional/hash.hpp>
#define NOMINMAX 1
#include <guiddef.h>
#include <oaidl.h>
#include <atlbase.h>
#include "idasdk.hpp"
#include "plughlpr.hpp"
#include "plugtinf.hpp"
#include "dbgnew.h"

typedef struct GUIDEX : public GUID {
public:
	inline GUIDEX() throw() { reset(); }
	inline GUIDEX(const GUID &guid) throw() { operator =(guid); }
	GUIDEX(uint32 d1, uint16 d2, uint16 d3,
		uint8 d41 = 0xC0, uint8 d42 = 0x00, uint8 d43 = 0x00, uint8 d44 = 0x00,
		uint8 d45 = 0x00, uint8 d46 = 0x00, uint8 d47 = 0x00, uint8 d48 = 0x46) throw()
			{ set(d1, d2, d3, d41, d42, d43, d44, d45, d46, d47, d48); }
	inline GUIDEX(LPCSTR s) { set(s); }
	inline GUIDEX(const std::string &s) { set(s.c_str()); }
	inline GUIDEX(LPCOLESTR ws) { set(ws); }
	inline GUIDEX(const std::wstring &ws) { set(ws.c_str()); }
	inline GUIDEX(ea_t ea) { set(ea); }

	// assignment
	template<class T>inline GUIDEX &operator =(const T &rhs)
		{ return operator =(GUIDEX(rhs)); }
	template<>inline GUIDEX &operator =<GUID>(const GUID &other) throw()
		{ memcpy(this, &other, sizeof GUID); return *this; }
	template<>inline GUIDEX &operator =<GUIDEX>(const GUIDEX &other) throw()
		{ return operator =(static_cast<const GUID &>(other)); }
	// comparison
	template<class T>bool operator ==(const T &rhs) const
		{ return operator ==(GUIDEX(rhs)); }
	template<>inline bool operator ==<GUID>(const GUID &other) const throw()
		{ return IsEqualGUID(*this, other); }
	template<>inline bool operator ==<GUIDEX>(const GUIDEX &other) const throw()
		{ return operator ==(static_cast<const GUID &>(other)); }
	template<class T>inline bool operator !=(const T &rhs) const
		{ return !operator ==(rhs); }
	// for sorted containers...
	inline bool operator <(const GUID &other) const throw()
		{ return memcmp(this, &other, sizeof GUID) < 0; }
	//inline bool operator ()() const { return isSet(); }
	//inline operator std::string() const { return toString(); }

	inline void reset() throw() { memset(this, 0, sizeof *this); }
	bool isSet() const throw();
	void set(uint32 d1, uint16 d2, uint16 d3,
		uint8 d41 = 0xC0, uint8 d42 = 0x00, uint8 d43 = 0x00, uint8 d44 = 0x00,
		uint8 d45 = 0x00, uint8 d46 = 0x00, uint8 d47 = 0x00, uint8 d48 = 0x46) throw();
	void set(ea_t ea) throw(std::exception);
	void set(LPCSTR s) throw(std::exception);
	void set(LPCOLESTR ws) throw(std::exception);

	LPSTR toString(LPSTR buf, SIZE_T size) const;
	LPOLESTR toString(LPOLESTR wbuf, SIZE_T size) const {
		return wbuf != NULL && StringFromGUID2(*this, wbuf, size) > 0 ? wbuf : NULL;
	}
	std::string toString() const;

	// for hashed containers...
	struct hash { // may not always ba unique, there's no way for two-way losless conversion 1dword <=> 4dwords
		size_t operator ()(const GUID &__x) const throw() {
			size_t seed(0);
			for (const size_t *i = (const size_t *)&__x;
				i < (const size_t *)((PBYTE)&__x + sizeof(GUID)); ++i) seed ^= *i;
			return seed;
		}
	};
	friend std::size_t hash_value(const GUID &__x) {
		std::size_t seed(0);
		for (const size_t *i = (const size_t *)&__x;
			i < (const size_t *)((PBYTE)&__x + sizeof(GUID)); ++i)
				boost::hash_combine(seed, *i);
		return seed;
	}
}	GUIDEX,  *PGUIDEX,   *LPGUIDEX,
	IIDEX,   *PIIDEX,    *LPIIDEX,
	CLSIDEX, *PCLSIDEX,  *LPCLSIDEX,
	FMTIDEX, *PMFMTIDEX, *LPFMTIDEX;

typedef struct clsid_t : CLSIDEX {
	std::string name;
	fixed_path_t server16, server32;

	clsid_t() { clear(); }
	clsid_t(const CLSIDEX &id) { Load(id); }
	clsid_t(const CLSID &id) { Load(id); }

	inline bool hasServer16() const throw() { return !server16.empty(); }
	inline bool hasServer32() const throw() { return !server32.empty(); }
	bool Load(const CLSIDEX &id) throw(std::exception);
	inline bool Load(const CLSID &id)
		{ return Load(static_cast<const CLSIDEX &>(id)); }
	void clear();
} *clsid_p;

typedef struct typelib_t : GUIDEX {
	WORD vermajor, verminor;
	LCID lcid;
	DWORD flags;
	std::string name;
	fixed_path_t filename;
	CComPtr<ITypeLib> ptlb;

	typelib_t() { clear(); }
	typelib_t(const GUIDEX &id) { Load(id); }
	typelib_t(const GUID &id) { Load(id); }

	inline bool hasTypeLib() const throw() { return !filename.empty(); }
	BOOL verFromStr(LPCSTR ver);
	bool Load(const GUIDEX &id) throw(std::exception);
	inline bool Load(const GUID &id) { return Load(static_cast<const GUIDEX &>(id)); }
	void clear();
} *typelib_p;

typedef struct interface_t : IIDEX {
	std::string name;
	clsid_t Class;
	typelib_t TypeLib;
	CComPtr<ITypeInfo> pti;

	interface_t() { clear(); }
	interface_t(const IIDEX &id) { Load(id); }
	interface_t(const IID &id) { Load(id); }

	bool Load(const IIDEX &id) throw(std::exception);
	inline bool Load(const IID &id)
		{ return Load(static_cast<const IIDEX &>(id)); }
	void clear();
} *interface_p;

bool GetCDeclStrFromTYPEDESC(const TYPEDESC &tdesc, std::string &s,
	ITypeInfo *pti = NULL, const char *lpParamName = 0);
bool GetTypeInfoFromTYPEDESC(const TYPEDESC &tdesc, typestring &type,
	ITypeInfo *pti = NULL);
bool TokenizePARAMDESCEX(const PARAMDESCEX &paramdescex, std::string &s)
	throw(std::exception)/*std::bad_alloc()*/;
std::wstring TokenizeVariant(const VARIANT &var);
const char *TokenizeVarType(VARENUM vt);
inline const char *TokenizeVarType(VARTYPE vt)
	{ return TokenizeVarType(static_cast<VARENUM>(vt)); }

#endif // _PLUGCOM_HPP_
