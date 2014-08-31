
/*****************************************************************************
 *                                                                           *
 *  plugcom.cpp: ida plugins OLE/COM routines                                *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#pragma warning(disable:  186) // pointless comparison of unsigned integer with zero
#endif

#include "mscrtdbg.h"
#include <algorithm>
#include <boost/scoped_array.hpp>
#define NOMINMAX 1
#include <wtypes.h>
#include <ole2.h>
#include "plugcom.hpp"
#include "plugsys.hpp"

static std::string &append_cosmetic_space(std::string &s) {
	if (!s.empty() && strchr("&*", back(s)) == 0) s.push_back(' ');
	return s;
}

/*
 * VARENUM usage key,
 *
 * * [V] - may appear in a VARIANT
 * * [T] - may appear in a TYPEDESC
 * * [P] - may appear in an OLE property set
 * * [S] - may appear in a Safe Array
 *
 *
 *  VT_EMPTY            [V]   [P]     nothing
 *  VT_NULL             [V]   [P]     SQL style Null
 *  VT_I2               [V][T][P][S]  2 byte signed int
 *  VT_I4               [V][T][P][S]  4 byte signed int
 *  VT_R4               [V][T][P][S]  4 byte real
 *  VT_R8               [V][T][P][S]  8 byte real
 *  VT_CY               [V][T][P][S]  currency
 *  VT_DATE             [V][T][P][S]  date
 *  VT_BSTR             [V][T][P][S]  OLE Automation string
 *  VT_DISPATCH         [V][T]   [S]  IDispatch *
 *  VT_ERROR            [V][T][P][S]  SCODE
 *  VT_BOOL             [V][T][P][S]  True=-1, False=0
 *  VT_VARIANT          [V][T][P][S]  VARIANT *
 *  VT_UNKNOWN          [V][T]   [S]  IUnknown *
 *  VT_DECIMAL          [V][T]   [S]  16 byte fixed point
 *  VT_RECORD           [V]   [P][S]  user defined type
 *  VT_I1               [V][T][P][s]  signed char
 *  VT_UI1              [V][T][P][S]  unsigned char
 *  VT_UI2              [V][T][P][S]  unsigned short
 *  VT_UI4              [V][T][P][S]  unsigned long
 *  VT_I8                  [T][P]     signed 64-bit int
 *  VT_UI8                 [T][P]     unsigned 64-bit int
 *  VT_INT              [V][T][P][S]  signed machine int
 *  VT_UINT             [V][T]   [S]  unsigned machine int
 *  VT_INT_PTR             [T]        signed machine register size width
 *  VT_UINT_PTR            [T]        unsigned machine register size width
 *  VT_VOID                [T]        C style void
 *  VT_HRESULT             [T]        Standard return type
 *  VT_PTR                 [T]        pointer type
 *  VT_SAFEARRAY           [T]        (use VT_ARRAY in VARIANT)
 *  VT_CARRAY              [T]        C style array
 *  VT_USERDEFINED         [T]        user defined type
 *  VT_LPSTR               [T][P]     null terminated string
 *  VT_LPWSTR              [T][P]     wide null terminated string
 *  VT_FILETIME               [P]     FILETIME
 *  VT_BLOB                   [P]     Length prefixed bytes
 *  VT_STREAM                 [P]     Name of the stream follows
 *  VT_STORAGE                [P]     Name of the storage follows
 *  VT_STREAMED_OBJECT        [P]     Stream contains an object
 *  VT_STORED_OBJECT          [P]     Storage contains an object
 *  VT_VERSIONED_STREAM       [P]     Stream with a GUID version
 *  VT_BLOB_OBJECT            [P]     Blob contains an object
 *  VT_CF                     [P]     Clipboard format
 *  VT_CLSID                  [P]     A Class ID
 *  VT_VECTOR                 [P]     simple counted array
 *  VT_ARRAY            [V]           SAFEARRAY*
 *  VT_BYREF            [V]           void* for local use
 *  VT_BSTR_BLOB                      Reserved for system use
 */
// never should throw, this is assertion
bool GetCDeclStrFromTYPEDESC(const TYPEDESC &tdesc, std::string &s,
	ITypeInfo *pti, const char *ParamName) {
	std::string result;
	_ASSERTE(result.empty());
	switch (tdesc.vt & VT_TYPEMASK) {
		// VT_CARRAY
		// struct FARSTRUCT tagARRAYDESC FAR* lpadesc;
		case VT_CARRAY: { // Indicates a C style array.
			_ASSERTE(tdesc.lpadesc != NULL);
			if (tdesc.lpadesc == NULL
				|| !GetCDeclStrFromTYPEDESC(tdesc.lpadesc->tdescElem, result, pti)) {
				//result.assign("void"/*"VOID"*/);
				_RPTF3(_CRT_ERROR, "%s(...): lpadesc NULL or GetCDeclStrFromTYPEDESC(...) couldnot parse VarType=0x%X(%s)\n",
					__FUNCTION__, tdesc.lpadesc->tdescElem.vt, TokenizeVarType(tdesc.lpadesc->tdescElem.vt));
				return false;
			}
			if (ParamName != 0 && *ParamName != 0) {
				append_cosmetic_space(result);
				if ((tdesc.vt & VT_BYREF) != 0) result.append("(&");
				result.append(ParamName);
				if ((tdesc.vt & VT_BYREF) != 0) result.push_back(')');
			} else if ((tdesc.vt & VT_BYREF) != 0)
				append_cosmetic_space(result).push_back('&');
			for (uint16 dim = 0; dim < tdesc.lpadesc->cDims; ++dim)
				_sprintf_append(result, "[%lu]", tdesc.lpadesc->rgbounds[dim].cElements);
			goto done_ok;
		}
		// If the variable is VT_SAFEARRAY or VT_PTR, the union portion of the
		// TYPEDESC contains a pointer to a TYPEDESC that specifies the element type.
		case VT_SAFEARRAY: // Indicates a SAFEARRAY. Not valid in a VARIANT.
			_ASSERTE(tdesc.lptdesc != NULL);
			if (tdesc.lptdesc == NULL
				|| !GetCDeclStrFromTYPEDESC(*tdesc.lptdesc, result, pti)) {
				//result.assign("void"/*"VOID"*/);
				_RPTF3(_CRT_ERROR, "%s(...): lptdesc NULL or GetCDeclStrFromTYPEDESC(...) couldnot parse VarType=0x%X(%s)\n",
					__FUNCTION__, tdesc.lptdesc->vt, TokenizeVarType(tdesc.lptdesc->vt));
				return false;
			}
			if (ParamName != 0 && *ParamName != 0) {
				append_cosmetic_space(result);
				if ((tdesc.vt & VT_BYREF) != 0) result.append("(&");
				result.append(ParamName);
				if ((tdesc.vt & VT_BYREF) != 0) result.push_back(')');
			} else if ((tdesc.vt & VT_BYREF) != 0)
				append_cosmetic_space(result).push_back('&');
			result.append("[]"); // unsized array?
			goto done_ok;
		// VT_PTR - the pointed-at type
		// struct FARSTRUCT tagTYPEDESC FAR* lptdesc;
		case VT_PTR: // Indicates a pointer type.
			_ASSERTE(tdesc.lptdesc != NULL);
			if (tdesc.lptdesc == NULL
				|| !GetCDeclStrFromTYPEDESC(*tdesc.lptdesc, result, pti)) {
				//result.assign("void"/*"VOID"*/);
				_RPTF3(_CRT_ERROR, "%s(...): lptdesc NULL or GetCDeclStrFromTYPEDESC(...) couldnot parse VarType=0x%X(%s)\n",
					__FUNCTION__, tdesc.lptdesc->vt, TokenizeVarType(tdesc.lptdesc->vt));
				return false;
			}
			append_cosmetic_space(result).push_back('*');
			break;
		// VT_USERDEFINED - this is used to get a TypeInfo for the UDT
		// HREFTYPE hreftype;
		case VT_USERDEFINED: // Indicates a user defined type.
			_ASSERTE(pti != NULL);
			if (pti != NULL) try {
				CComPtr<ITypeInfo> pusrti;
				if (pti->GetRefTypeInfo(tdesc.hreftype, &pusrti) == S_OK) {
					_ASSERTE(pusrti != NULL);
					CComBSTR strName, strDesc;
					if (pusrti->GetDocumentation(MEMBERID_NIL, &strName, &strDesc, NULL, NULL) == S_OK) {
						if (strName != NULL) {
							const size_t strlen(wcslen(strName) + 1);
							boost::scoped_array<char> buf(new char[strlen]);
							if (!buf) throw std::bad_alloc();
							if (static_cast<int>(wcstombs(buf.get(), strName, strlen)) > 0) {
								result.assign(buf.get());
								break;
							}
						}
					}
#ifdef _DEBUG
					else
						_RPT2(_CRT_ERROR, "%s(...): pusrti->GetDocumentation(...) failed for hreftype=%08lX\n",
							__FUNCTION__, tdesc.hreftype);
#endif // _DEBUG
				}
#ifdef _DEBUG
				else
					_RPT2(_CRT_ERROR, "%s(...): pti->GetRefTypeInfo(%08lX, ...): error\n",
						__FUNCTION__, tdesc.hreftype);
			} catch (const std::exception &e) {
				_RPT3(_CRT_ERROR, "%s(...): %s when parsing user defined typeinfo (tpdesc.hreftype=%08lX)\n",
					__FUNCTION__, e.what(), tdesc.hreftype);
#endif // _DEBUG
			} catch (...) {
				_RPT3(_CRT_ERROR, "%s(...): %s when parsing user defined typeinfo (tpdesc.hreftype=%08lX)\n",
					__FUNCTION__, "unknown exception", tdesc.hreftype);
			}
			//result.assign("void"/*"VOID"*/);
			//break;
			return false;
		default: {
			const char *dirtype(0);
			switch (tdesc.vt & VT_TYPEMASK) {
				/* ----------------------------- basic ------------------------------ */
				case VT_BOOL: dirtype = "VARIANT_BOOL"; break; // Indicates a Boolean value.
				case VT_BSTR: dirtype = "BSTR"; break; // Indicates a BSTR string.
				case VT_CY: dirtype = "CY"; break; // Indicates a currency value.
				case VT_DATE: dirtype = "DATE"; break; // Indicates a DATE value.
				case VT_DECIMAL: dirtype = "DECIMAL"; break; // Indicates a decimal value.
				case VT_DISPATCH: dirtype = "IDispatch far *"; break; // Indicates an IDispatch far pointer.
				case VT_ERROR: dirtype = "SCODE"; break; // Indicates an SCODE.
				case VT_HRESULT: dirtype = "HRESULT"; break; // Indicates an HRESULT.
				case VT_I1: dirtype = "CHAR"; break; // Indicates a char value.
				case VT_I2: dirtype = "SHORT"; break; // Indicates a short integer.
				case VT_I4: dirtype = "LONG"; break; // Indicates a long integer.
				case VT_I8: dirtype = "LONGLONG"; break; // Indicates a 64-bit integer.
				case VT_INT: dirtype = "INT"; break; // Indicates an integer value.
				case VT_INT_PTR: dirtype = "INT_PTR"; break; // int (__int3264)
				case VT_LPSTR: dirtype = "LPSTR"; break; // Indicates a a null reference (Nothing in Visual Basic) terminated string.
				case VT_LPWSTR: dirtype = "LPWSTR"; break; // Indicates a wide string terminated by a null reference (Nothing in Visual Basic).
				case VT_R4: dirtype = "FLOAT"; break; // Indicates a float value.
				case VT_R8: dirtype = "DOUBLE"; break; // Indicates a double value.
				case VT_UI1: dirtype = /*"UCHAR"*/"BYTE"; break; // Indicates a byte.
				case VT_UI2: dirtype = "USHORT"/*"WORD"*/; break; // Indicates an unsigned short.
				case VT_UI4: dirtype = "ULONG"/*"DWORD"*/; break; // Indicates an unsigned long.
				case VT_UI8: dirtype = "ULONGLONG"/*"DWORDLONG"*/; break; // Indicates an 64-bit unsigned integer.
				case VT_UINT: dirtype = "UINT"; break; // Indicates an unsigned integer value.
				case VT_UINT_PTR: dirtype = "UINT_PTR"; break; // uint (unsigned __int3264)
				case VT_UNKNOWN: dirtype = "IUnknown far *"; break; // Indicates an IUnknown far pointer.
				case VT_VARIANT: dirtype = "VARIANT far *"; break; // Indicates a VARIANT far pointer.
				case VT_VOID: dirtype = "void"/*"VOID"*/; break; // Indicates a C style void.
				/* ------ not allowed in TYPEDESC, implemented for completness ------ */
				case VT_BLOB: dirtype = "BLOB"; break; // Indicates length prefixed bytes.
				//case VT_BLOB_OBJECT: // Indicates that a blob contains an object.
				//case VT_BSTR_BLOB: // Reserved for system use
				//case VT_CF: // Indicates the clipboard format.
				case VT_CLSID: dirtype = "CLSID"; break; // Indicates a class ID.
				//case VT_EMPTY: // Not specified.
				case VT_FILETIME: dirtype = "FILETIME"; break; // Indicates a FILETIME value.
				//case VT_NULL: // Indicates a a null reference (Nothing in Visual Basic) value, similar to a null value in SQL.
				//case VT_RECORD: // Indicates a user defined type.
				//case VT_STORAGE: // Indicates that the name of a storage follows.
				//case VT_STORED_OBJECT: // Indicates that a storage contains an object.
				//case VT_STREAM: // Indicates that the name of a stream follows.
				//case VT_STREAMED_OBJECT: // Indicates that a stream contains an object.
				//case VT_VERSIONED_STREAM:
				case 0/*VT_EMPTY*/:
					if ((tdesc.vt & 0xF000) != 0) {
						dirtype = "void"/*"VOID"*/; // ok with modifiers
						break;
					}
				default:
					_RPT3(_CRT_WARN, "%s(...): unexpected TYPEDESC VarType value (0x%X(%s))\n",
						__FUNCTION__, tdesc.vt, TokenizeVarType(tdesc.vt));
					return false;
			} // type switch
			_ASSERTE(dirtype != 0);
			result.assign(dirtype);
		} // std. type
	} // main switch
	_ASSERTE(!result.empty());
	// ==================== decorate with modifiers (if any) ====================
	// Indicates that a value is a reference. should never be set in TYPEDESC
	//_ASSERTE((tdesc.vt & VT_BYREF) == 0);
	if ((tdesc.vt & VT_BYREF) != 0) append_cosmetic_space(result).append("(&");
	if (ParamName != 0 && *ParamName != 0)
		append_cosmetic_space(result).append(ParamName);
	if ((tdesc.vt & VT_BYREF) != 0) result.push_back(')');
done_ok:
	// Indicates a SAFEARRAY pointer. should never be set in TYPEDESC
	//_ASSERTE((tdesc.vt & VT_ARRAY) == 0);
	if ((tdesc.vt & VT_ARRAY) != 0) {
		// parray or pparray member of VARIANT
	}
	// Indicates a simple, counted array. should never be set in TYPEDESC
	//_ASSERTE((tdesc.vt & VT_VECTOR) == 0);
	if ((tdesc.vt & VT_VECTOR) != 0) {
		// ca* members of PROPVARIANT
		//result.insert((std::string::size_type)0, 1, '<');
		//result.push_back('>');
	}
	s.append(result);
	return !result.empty();
}

bool GetTypeInfoFromTYPEDESC(const TYPEDESC &tdesc,
	typestring &type, ITypeInfo *pti) {
	typestring result;
	_ASSERTE(result.empty());
	// ==================== decorate with modifiers (if any) ====================
	// Indicates that a value is a reference. should never be set in TYPEDESC
	//_ASSERTE((tdesc.vt & VT_BYREF) == 0);
	if ((tdesc.vt & VT_BYREF) != 0)
		result << (BT_PTR | BTMT_DEFPTR);
	// Indicates a SAFEARRAY pointer. should never be set in TYPEDESC
	//_ASSERTE((tdesc.vt & VT_ARRAY) == 0);
	if ((tdesc.vt & VT_ARRAY) != 0)
		// parray or pparray member of VARIANT
		result << (BT_ARRAY | BTMT_NONBASED) << dt(0);
	// Indicates a simple, counted array. should never be set in TYPEDESC
	//_ASSERTE((tdesc.vt & VT_VECTOR) == 0);
	if ((tdesc.vt & VT_VECTOR) != 0) {
		// ca* members of PROPVARIANT
	}
	switch (tdesc.vt & VT_TYPEMASK) {
		// VT_CARRAY
		// struct FARSTRUCT tagARRAYDESC FAR* lpadesc;
		case VT_CARRAY: { // Indicates a C style array.
			for (uint16 dim = 0; dim < tdesc.lpadesc->cDims; ++dim)
				result << (BT_ARRAY | BTMT_NONBASED) << dt(tdesc.lpadesc->rgbounds[dim].cElements);
			_ASSERTE(tdesc.lpadesc != NULL);
			if (tdesc.lpadesc == NULL
				|| !GetTypeInfoFromTYPEDESC(tdesc.lpadesc->tdescElem, result, pti)) {
				//result << BTF_VOID/*tdef("VOID")*/;
				_RPTF3(_CRT_ERROR, "%s(...): lpadesc NULL or GetTypeInfoFromTYPEDESC(...) couldnot parse VarType=0x%X(%s)\n",
					__FUNCTION__, tdesc.lpadesc->tdescElem.vt, TokenizeVarType(tdesc.lpadesc->tdescElem.vt));
				return false;
			}
			break;
		}
		// If the variable is VT_SAFEARRAY or VT_PTR, the union portion of the
		// TYPEDESC contains a pointer to a TYPEDESC that specifies the element type.
		case VT_SAFEARRAY: // Indicates a SAFEARRAY. Not valid in a VARIANT.
			result << (BT_ARRAY | BTMT_NONBASED) << dt(0);
			_ASSERTE(tdesc.lptdesc != NULL);
			if (tdesc.lptdesc == NULL
				|| !GetTypeInfoFromTYPEDESC(*tdesc.lptdesc, result, pti)) {
				//result << BTF_VOID/*tdef("VOID")*/;
				_RPTF3(_CRT_ERROR, "%s(...): lptdesc NULL or GetTypeInfoFromTYPEDESC(...) couldnot parse VarType=0x%X(%s)\n",
					__FUNCTION__, tdesc.lptdesc->vt, TokenizeVarType(tdesc.lptdesc->vt));
				return false;
			}
			break;
		// VT_PTR - the pointed-at type
		// struct FARSTRUCT tagTYPEDESC FAR* lptdesc;
		case VT_PTR: // Indicates a pointer type.
			result << (BT_PTR | BTMT_DEFPTR);
			_ASSERTE(tdesc.lptdesc != NULL);
			if (tdesc.lptdesc == NULL
				|| !GetTypeInfoFromTYPEDESC(*tdesc.lptdesc, result, pti)) {
				//result << BTF_VOID/*tdef("VOID")*/;
				_RPTF3(_CRT_ERROR, "%s(...): lptdesc NULL or GetTypeInfoFromTYPEDESC(...) couldnot parse VarType=0x%X(%s)\n",
					__FUNCTION__, tdesc.lptdesc->vt, TokenizeVarType(tdesc.lptdesc->vt));
				return false;
			}
			break;
		// VT_USERDEFINED - this is used to get a TypeInfo for the UDT
		// HREFTYPE hreftype;
		case VT_USERDEFINED: // Indicates a user defined type.
			_ASSERTE(pti != NULL);
			if (pti != NULL) try {
				CComPtr<ITypeInfo> pusrti;
				if (pti->GetRefTypeInfo(tdesc.hreftype, &pusrti) == S_OK) {
					_ASSERTE(pusrti != NULL);
					CComBSTR strName, strDesc;
					if (pusrti->GetDocumentation(MEMBERID_NIL, &strName, &strDesc, NULL, NULL) == S_OK) {
						if (strName != NULL) {
							const size_t strlen(wcslen(strName) + 1);
							boost::scoped_array<char> buf(new char[strlen]);
							if (!buf) throw std::bad_alloc();
							if (static_cast<int>(wcstombs(buf.get(), strName, strlen)) > 0) {
								result << tdef(buf.get());
								break;
							}
						}
					}
#ifdef _DEBUG
					else
						_RPT2(_CRT_ERROR, "%s(...): pusrti->GetDocumentation(...) failed for hreftype=%08lX\n",
							__FUNCTION__, tdesc.hreftype);
#endif // _DEBUG
				}
#ifdef _DEBUG
				else
					_RPT2(_CRT_ERROR, "%s(...): pti->GetRefTypeInfo(%08lX, ...): error\n",
						__FUNCTION__, tdesc.hreftype);
			} catch (const std::exception &e) {
				_RPT3(_CRT_ERROR, "%s(...): %s when parsing user defined typeinfo (tpdesc.hreftype=%08lX)\n",
					__FUNCTION__, e.what(), tdesc.hreftype);
#endif // _DEBUG
			} catch (...) {
				_RPT3(_CRT_ERROR, "%s(...): %s when parsing user defined typeinfo (tpdesc.hreftype=%08lX)\n",
					__FUNCTION__, "unknown exception", tdesc.hreftype);
			}
			//result << BTF_VOID/*tdef("VOID")*/;
			//break;
			return false;
		/* ----------------------------- basic ------------------------------ */
		case VT_BOOL: result << tdef("VARIANT_BOOL")/*BT_INT16*/; break; // Indicates a Boolean value.
		case VT_BSTR: result << tdef("BSTR")/*(BT_PTR | BTMT_DEFPTR) << BT_INT16*/; break; // Indicates a BSTR string.
		case VT_CY: result << tdef("CY"); break; // Indicates a currency value.
		case VT_DATE: result << tdef("DATE")/*(BT_FLOAT | BTMT_DOUBLE)*/; break; // Indicates a DATE value.
		case VT_DECIMAL: result << tdef("DECIMAL"); break; // Indicates a decimal value.
		case VT_DISPATCH: result << (BT_PTR | BTMT_FAR) << tdef("IDispatch"); break; // Indicates an IDispatch far pointer.
		case VT_ERROR: result << tdef("SCODE")/*BT_INT32*/; break; // Indicates an SCODE.
		case VT_HRESULT: result << tdef("HRESULT")/*BT_INT32*/; break; // Indicates an HRESULT.
		case VT_I1: result << tdef("CHAR")/*(BT_INT8 | BTMT_CHAR)*/; break; // Indicates a char value.
		case VT_I2: result << tdef("SHORT")/*BT_INT16*/; break; // Indicates a short integer.
		case VT_I4: result << tdef("LONG")/*BT_INT32*/; break; // Indicates a long integer.
		case VT_I8: result << tdef("LONGLONG")/*BT_INT64*/; break; // Indicates a 64-bit integer.
		case VT_INT: result << tdef("INT")/*BT_INT*/; break; // Indicates an integer value.
		case VT_INT_PTR: result << tdef("INT_PTR")/*BT_INT*/; break; // int (__int3264)
		case VT_LPSTR: result << tdef("LPSTR")/*(BT_PTR | BTMT_DEFPTR) << (BT_INT8 | BTMT_CHAR)*/; break; // Indicates a a null reference (Nothing in Visual Basic) terminated string.
		case VT_LPWSTR: result << tdef("LPWSTR")/*(BT_PTR | BTMT_DEFPTR) << BT_INT16*/; break; // Indicates a wide string terminated by a null reference (Nothing in Visual Basic).
		case VT_R4: result << tdef("FLOAT")/*(BT_FLOAT | BTMT_FLOAT)*/; break; // Indicates a float value.
		case VT_R8: result << tdef("DOUBLE")/*(BT_FLOAT | BTMT_DOUBLE)*/; break; // Indicates a double value.
		case VT_UI1: result << tdef(/*"UCHAR"*/"BYTE")/*(BT_INT8 | BTMT_USIGNED)*/; break; // Indicates a byte.
		case VT_UI2: result << tdef("USHORT"/*"WORD"*/)/*(BT_INT16 | BTMT_USIGNED)*/; break; // Indicates an unsigned short.
		case VT_UI4: result << tdef("ULONG"/*"DWORD"*/)/*(BT_INT32 | BTMT_USIGNED)*/; break; // Indicates an unsigned long.
		case VT_UI8: result << tdef("ULONGLONG"/*"DWORDLONG"*/)/*(BT_INT64 | BTMT_USIGNED)*/; break; // Indicates an 64-bit unsigned integer.
		case VT_UINT: result << tdef("UINT")/*(BT_INT | BTMT_USIGNED)*/; break; // Indicates an unsigned integer value.
		case VT_UINT_PTR: result << tdef("UINT_PTR")/*(BT_INT | BTMT_USIGNED)*/; break; // uint (unsigned __int3264)
		case VT_UNKNOWN: result << (BT_PTR | BTMT_FAR) << tdef("IUnknown"); break; // Indicates an IUnknown far pointer.
		case VT_VARIANT: result << (BT_PTR | BTMT_FAR) << tdef("VARIANT"); break; // Indicates a VARIANT far pointer.
		case VT_VOID: result << BTF_VOID/*tdef("VOID")*/; break; // Indicates a C style void.
		/* ------ not allowed in TYPEDESC, implemented for completness ------ */
		case VT_BLOB: result << tdef("BLOB"); break; // Indicates length prefixed bytes.
		//case VT_BLOB_OBJECT: // Indicates that a blob contains an object.
		//case VT_BSTR_BLOB: // Reserved for system use
		//case VT_CF: // Indicates the clipboard format.
		case VT_CLSID: result << tdef("CLSID"); break; // Indicates a class ID.
		//case VT_EMPTY: // Not specified.
		case VT_FILETIME: result << tdef("FILETIME"); break; // Indicates a FILETIME value.
		//case VT_NULL: // Indicates a a null reference (Nothing in Visual Basic) value, similar to a null value in SQL.
		//case VT_RECORD: // Indicates a user defined type.
		//case VT_STORAGE: // Indicates that the name of a storage follows.
		//case VT_STORED_OBJECT: // Indicates that a storage contains an object.
		//case VT_STREAM: // Indicates that the name of a stream follows.
		//case VT_STREAMED_OBJECT: // Indicates that a stream contains an object.
		//case VT_VERSIONED_STREAM:
		case 0/*VT_EMPTY*/:
			if (!result.empty()) {
				result << BTF_VOID/*tdef("VOID")*/;
				break;
			}
		default:
			_RPT3(_CRT_WARN, "%s(...): unexpected TYPEDESC VarType value (0x%X(%s))\n",
				__FUNCTION__, tdesc.vt, TokenizeVarType(tdesc.vt));
			return false;
	} // main switch
	_ASSERTE(!result.empty());
	type.append(result);
	return !result.empty();
}
