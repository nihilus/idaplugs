
/*****************************************************************************
 *                                                                           *
 *  plugcmn2.cpp: ida plugins shared code                                    *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#if defined(__ICL)
#pragma warning(disable: 181)
#endif

#include "mscrtdbg.h"
#include "plugcmn.hpp"
#include "pluginsn.hpp"
#include "areaex.hpp"
#include "batchres.hpp"
#include "warnlist.hpp"

#define _SHOWADDRESS               1         // display progress

static bool __is_fake_code(ea_t ea, ea_t *startEA, ea_t *endEA, rangelist_t &list) {
	//_ASSERTE(isEnabled(ea));
	if (startEA != 0) *startEA = BADADDR;
	if (endEA != 0) *endEA = BADADDR;
	if (isEnabled(ea) && isCode(get_flags_novalue(ea = get_item_head(ea)))
		&& get_func(ea) == 0) {
		ea_t end(ea);
		while (isCode(get_flags_novalue(end)) && get_func(end) == 0)
			end = next_not_tail(end);
		if (!is_flowchange_insn(ea = prev_not_tail(end))) {
			while (isCode(get_flags_novalue(ea)) && get_func(ea) == 0)
				ea = prev_not_tail(ea);
			ea = next_not_tail(ea);
			if (!list.has(ea) && hasRef(get_flags_novalue(ea))) {
#ifdef _DEBUG
				bool ok(list.insert(area_t(ea, end)).second);
				_ASSERTE(ok);
#else // !_DEBUG
				list.insert(area_t(ea, end));
#endif // _DEBUG
				xrefblk_t xref;
				for (bool ok = xref.first_to(ea, XREF_FAR); ok; ok = xref.next_to())
					if ((xref.from < ea || xref.from >= end) && isEnabled(xref.from)
						&& isCode(get_flags_novalue(xref.from))
						&& !__is_fake_code(xref.from, 0, 0, list)) return false;
			}
			if (startEA != 0) *startEA = ea;
			if (endEA != 0) *endEA = end;
			list.insert(area_t(ea, end));
			return true;
		}
	}
	return false;
}

bool is_fake_code(ea_t ea, ea_t *startEA, ea_t *endEA)
	{ return __is_fake_code(ea, startEA, endEA, rangelist_t()); }

// set weak for more relaxed rule
bool is_dummy_data(ea_t ea, bool weak) {
	// _ASSERTE(isEnabled(ea));
	flags_t bmask, flags(get_flags_novalue(ea = get_item_head(ea)));
	return !isCode(flags) && ((bmask = flags & DT_TYPE) == FF_BYTE
		|| bmask == FF_WORD || bmask == FF_DWRD || bmask == FF_QWRD)
		&& (!isDefArg0(flags) || weak && ((bmask = get_optype_flags0(flags)) == FF_0NUMH
		|| bmask == FF_0NUMD || bmask == FF_0NUMO || bmask == FF_0NUMB))
		&& !does_prefix_lstring(ea)
		&& get_array_parameters(ea, NULL, 0) < sizeof array_parameters_t
 		|| is_fake_code(ea);
}

bool is_dummy_data_range(ea_t ea, asize_t size, bool weak) {
	while (size-- > 0) {
		if (!is_dummy_data(ea, weak)) return false;
		ea = nextaddr(ea);
	}
	return true;
}

#include "warnlist.hpp"

// returns estimated start of next block or BADADDR
ea_t format_data_area(ea_t &ea, bool createoffsets, size_t offboundary,
	uint8 offtohead, bool makealigns, uint &totalarraya, uint &totaloffsets,
	CWarningList *list, CBatchResults *batchresults, uint8 verbosity,
	const char *prefix) {
	_ASSERTE(isEnabled(ea));
	// preconditions
	segment_t *segment(getseg(ea));
	_ASSERTE(segment != 0);
	if (segment == 0) return ea = BADADDR;
	ea_t refEA(ea);
	// anchor lorange to line start
	ea = get_item_head(ea);
	if (does_prefix_lstring(ea)) ea += 4; // temporary shift to have proper type
	flags_t flags = getFlags(ea);
	if (isCode(flags) || isAlign(flags)) return ea; // skip code
	if (!isASCII(flags) && does_prefix_lstring(ea - 4)) goto _b1;
	// move lorange down if inside string (this var)
	if (isASCII(flags) && get_str_type_code(get_string_type(ea)) == ASCSTR_C
		&& does_prefix_lstring(ea - 8) /* VCL-specific L4String (offset +4) identified as C-string */) {
		ea -= 4;
		flags = getFlags(ea); // refresh flags
		_ASSERTE(isNotTail(flags));
	_b1:
		do_unknown_range(ea, get_long(ea) + 5, false);
		make_ascii_string(ea, get_long(ea) + 5, ASCSTR_LEN4);
	}
	// basic hirange estimation
	ea_t endEA(get_item_end(ea));
#ifdef _DEBUG
	ea_t item_end(endEA);
#endif
	ea_t tmp;
	if (canRefByTail(flags)) {
		if (!isVariableEnd(get_flags_novalue(endEA)))
			endEA = nextthat(endEA, segment->endEA, isVariableEnd);
	} else
		if ((tmp = nextthat(ea, segment->endEA, isVariableEnd)) > endEA)
			endEA = tmp;
	if (endEA > segment->endEA) endEA = segment->endEA; // stay within segment
	// adjust hirange to line start
	if (isTail(get_flags_novalue(endEA))) {
		endEA = canRefByTail(get_flags_novalue(get_item_head(endEA))) ?
			get_item_head(endEA) : get_item_end(endEA) /* possible variable overlap */;
		_ASSERTE(endEA <= segment->endEA);
	}
	// VCL-specific L4String (identified as C-string)
	if (does_prefix_lstring(endEA - 8)) {
		endEA -= 8;
		goto _ib7;
	} else if (does_prefix_lstring(endEA - 4)) {
		endEA -= 4;
	_ib7:
		_ASSERTE(get_long(endEA) == (ulong)-1);
		do_unknown(endEA, true);
		doDwrd(endEA, 4);
		//make_ascii_string(endEA + 4, get_long(endEA) + 5, ASCSTR_LEN4);
	}
	// remove trailing aligns
	char dbg_out[512];
#ifdef _DEBUG
	if (endEA <= ea) _CrtDbgReport(_CRT_ASSERT, __FILE__, __LINE__, __FUNCTION__,
		"%s(...): endEA<=ea (ea=%08IX endEA=%08IX refEA=%08IX flags(ea)=%s long(ea)=%08lX long(refEA)=%08lX)\n",
		__FUNCTION__, ea, endEA, refEA, flags2str(getFlags(ea)).c_str(),
		get_long(ea), get_long(refEA));
#endif // _DEBUG
	while (isAlign(get_flags_novalue(tmp = prev_not_tail(endEA))) && tmp >= ea)
		endEA = tmp;
	if (endEA <= ea) {
		_ASSERTE(endEA == ea);
		_ASSERTE(isAlign(get_flags_novalue(ea)));
		return ea;
	}
	const asize_t elementwidth = get_data_type_size(ea, flags);
	// detect undeclared align directives (only to dword boundary)
	if ((inf.cc.cm & (CM_MASK | CM_M_MASK)) == C_PC_FLAT && hasValue(flags)
		&& ea + get_item_size(ea) < endEA
		&& (elementwidth & 3) != 0 && (endEA & 3) == 0) {
		const bool is_unknown[] = {
			isUnknown(get_flags_novalue(endEA - 1)),
			isUnknown(get_flags_novalue(endEA - 2)),
			isUnknown(get_flags_novalue(endEA - 3)),
		};
		asize_t alignsize;
		if (is_unknown[0] && get_byte(endEA - 1) == 0
			&& is_unknown[1] && get_byte(endEA - 2) == 0x40
			&& is_unknown[2] && get_byte(endEA - 3) == 0x8D)
			alignsize = 3;
		else if (is_unknown[0] && get_byte(endEA - 1) == 0xC0
			&& is_unknown[1] && get_byte(endEA - 2) == 0x8B)
			alignsize = 2;
		else if (is_unknown[0] && get_byte(endEA - 2) == 0x90)
			alignsize = 1;
		else
			alignsize = 0;
		if (alignsize > 0) {
			tmp = endEA - alignsize;
			_ASSERTE(tmp >= ea + get_item_size(ea));
			if (tmp >= ea) {
				_ASSERTE(tmp == get_item_head(tmp));
				if (verbosity >= 3) msg("%s  info: possible alignment directive? at %08a\n",
					prefix != 0 ? prefix : "", tmp);
				if (makealigns && (doAlign(tmp, alignsize, 2))) {
					// set_alignment(tmp, 2);
					endEA -= alignsize;
				}
				if (list != 0 && verbosity >= 2) list->Add(tmp, 0x0010,
					"possible alignment directive");
				append_unique_cmt(tmp, "possible dword alignment");
				if (endEA <= ea) {
					_ASSERTE(endEA == ea);
					_ASSERTE(isAlign(get_flags_novalue(ea)));
					return ea;
				}
			} // align start >= ea
		} // align size > 0
	} // can have alignment
#ifdef _DEBUG
	if (endEA <= ea) _CrtDbgReport(_CRT_ASSERT, __FILE__, __LINE__, __FUNCTION__,
		"%s(...): endEA<=ea (ea=%08IX endEA=%08IX refEA=%08IX flags(ea)=%s long(ea)=%08lX long(refEA)=%08lX)\n",
		__FUNCTION__, ea, endEA, refEA, flags2str(getFlags(ea)).c_str(),
		get_long(ea), get_long(refEA));
#endif // _DEBUG
	char dassm[MAXSTR];
	// detect variable overlap
	tmp = refEA;
	do
		tmp = nextthat(tmp, segment->endEA, isBoundary);
	while (tmp < endEA && isTail(get_flags_novalue(tmp)) && can_ref_ea(tmp));
	if (tmp < endEA) {
		if (verbosity >= 2) msg("%swarning: possible variable %s at %08a\n",
			prefix != 0 ? prefix : "", "overlap", tmp);
		if (list != 0 && verbosity >= 2) {
			qsnprintf(CPY(dbg_out), "possible variable %s (estimated end at %08a; mnemonics: %s)",
				"overlap", endEA, get_disasm(tmp, CPY(dassm)));
			list->Add(tmp, 0x0005, dbg_out);
		}
		OutputDebugString("%s(...): %s info: startEA=%08IX anchor=%08IX(%s) endEA=%08IX\n",
			__FUNCTION__, "overlap", ea, tmp, dassm, endEA);
	}
	flags_t f1;
	// detect variable truncation
	tmp = endEA;
	while (tmp < segment->endEA && isAlign(f1 = get_flags_novalue(tmp)))
		tmp = next_not_tail(tmp);
	long strtype;
	if (tmp < segment->endEA && !isVariableEnd(f1) && !does_prefix_lstring(tmp)
		&& (strtype = get_str_type_code(get_string_type(tmp))) != ASCSTR_LEN2
		&& strtype != ASCSTR_LEN4 && strtype != ASCSTR_ULEN2 && strtype != ASCSTR_ULEN4) {
		// possible variable truncation
		if (verbosity >= 2) msg("%swarning: possible variable %s at %08a\n",
			prefix != 0 ? prefix : "", "truncation", endEA);
		if (list != 0 && verbosity >= 2) {
			qsnprintf(CPY(dbg_out), "possible variable %s (estimated end at %08a; mnemonics: %s)",
				"truncation", endEA, get_disasm(tmp, CPY(dassm)));
			list->Add(endEA, 0x0205, dbg_out);
		}
		OutputDebugString("%s(...): %s info: startEA=%08IX endEA=%08IX anchor=%08IX(%s)\n",
			__FUNCTION__, "truncation", ea, endEA, tmp, dassm);
	}
	// data formatting & collapsing
	// area must be atleast twice the element's size and not an defined array
	asize_t sizearea(endEA - ea);
	typeinfo_t ti, *pti(get_typeinfo(ea, 0, flags, &ti));
	struc_t *struc(0);
	if (isStruct(flags) && (pti == 0 || (struc = get_struc(ti.tid)) == 0)) {
		struc = get_struc(get_strid(ea));
#ifdef _DEBUG
		if (struc == 0) _RPTF2(_CRT_ERROR, "%s(...): can't get struct at %08IX\n",
			__FUNCTION__, ea);
#endif // _DEBUG
	}
	bool canformat(sizearea >= elementwidth << 1 && get_item_size(ea) == elementwidth
		&& !isASCII(flags) && (!isStruct(flags) || struc != 0
		&& !struc->is_varstr())/* && (!isEnum0(flags) && !isOff0(flags)
		&& !isStroff0(flags) || pti != 0)*/);
	bool changed(false);
	ea_t scan;
	flags_t flags1;
	if (hasValue(flags)) {
		// .data
		// pass1: finding offsets
		if (createoffsets) totaloffsets += find_offsets_range(area_t(ea, endEA),
			offboundary, offtohead, batchresults, verbosity, prefix);
		// pass 2: determine if area is safe to pack and do some nice array...
		if (canformat) { // .data
			tmp = endEA;
			for (scan = ea; scan < tmp; scan = next_not_tail(scan)) {
#ifdef _SHOWADDRESS
				//showAddr(scan);
#endif
				flags1 = getFlags(scan);
				typeinfo_t ti1;
				if (!hasValue(flags1) || ((flags1 ^ flags) & (DT_TYPE | MS_0TYPE)) != 0
					&& !is_dummy_data(scan, false) || isStruct(flags)
					&& (get_typeinfo(scan, 0, flags1, &ti1) == 0 || ti1.tid != ti.tid)
					|| isEnum0(flags) && (get_typeinfo(scan, 0, flags1, &ti1) == 0
					|| ti1.ec.tid != ti.ec.tid) || isOff0(flags)
					&& !isEnabled(can_be_off32(scan))) tmp = scan;
			}
			if ((sizearea = tmp - ea) >= elementwidth << 1) { // raw area large enough
#ifdef _SHOWADDRESS
				showAddr(ea);
#endif
				totalarraya += do_data_ex(ea, flags, pti, sizearea - sizearea % elementwidth);
				// determine if array from duplicate elements
				uint64 basevalue, max(0);
				array_parameters_t array_parameters = { AP_INDEX/*flags*/, 1/*lineitems*/, -1/*alignment*/ };
				_ASSERTE(!isStkvar0(flags));
				bool allowdupes;
				if (isOff0(flags) || isEnum0(flags) || isFloat0(flags) ||
					isStroff0(flags) || isSeg0(flags) || isFop0(flags) || isStkvar0(flags))
					allowdupes = false;
				else { // primitive type
					allowdupes = true;
					char s[65];
					switch (flags & DT_TYPE) {
						case FF_QWRD:
							max = basevalue = get_qword(ea);
							for (scan = ea + elementwidth; scan < tmp; scan += elementwidth) {
#ifdef _SHOWADDRESS
								//showAddr(scan);
#endif
								uint64 value = get_qword(scan);
								if (value > max) max = value;
								if (value != basevalue) allowdupes = false;
							}
							array_parameters.lineitems = 2;
							array_parameters.flags = (sizearea > 0x10 && !allowdupes) *
								AP_INDEX | allowdupes * AP_ALLOWDUPS;
							// set proper array formatting regarding the data type
							switch (get_optype_flags0(flags)) {
								case FF_0VOID:
								case FF_0NUMH:
									qsnprintf(CPY(s), "%I64X", max);
									array_parameters.alignment = allowdupes ? -1 : strlen(s) + 3;
									break;
								case FF_0NUMD:
									qsnprintf(CPY(s), "%I64u", max);
									array_parameters.alignment = allowdupes ? -1 : strlen(s) + 3;
									break;
								case FF_0NUMB:
									//qsnprintf(CPY(s), "%I64b", max);
									array_parameters.alignment = allowdupes ? -1 : 67;
									break;
								case FF_0NUMO:
									qsnprintf(CPY(s), "%I64o", max);
									array_parameters.alignment = allowdupes ? -1 : strlen(s) + 3;
									break;
								case FF_0CHAR:
									array_parameters.alignment = allowdupes ? -1 : 11;
									break;
							} // dwitch statement
							break;
						case FF_DWRD:
							max = basevalue = get_long(ea);
							for (scan = ea + elementwidth; scan < tmp; scan += elementwidth) {
#ifdef _SHOWADDRESS
								//showAddr(scan);
#endif
								ulong value(get_long(scan));
								if (value > max) max = value;
								if (value != basevalue) allowdupes = false;
							}
							array_parameters.lineitems = 4;
							array_parameters.flags = (sizearea > 0x10 && !allowdupes) *
								AP_INDEX | allowdupes * AP_ALLOWDUPS;
							// set proper array formatting regarding the data type
							switch (get_optype_flags0(flags)) {
								case FF_0VOID:
								case FF_0NUMH:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 16)) + 3;
									break;
								case FF_0NUMD:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 10)) + 3;
									break;
								case FF_0NUMB:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 2)) + 3;
									break;
								case FF_0NUMO:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 8)) + 3;
									break;
								case FF_0CHAR:
									array_parameters.alignment = allowdupes ? -1 : 7;
									break;
							} // dwitch statement
							break;
						case FF_WORD:
							max = basevalue = get_word(ea);
							for (scan = ea + elementwidth; scan < tmp; scan += elementwidth) {
#ifdef _SHOWADDRESS
								//showAddr(scan);
#endif
								uint16 value = get_word(scan);
								if (value > max) max = value;
								if (value != basevalue) allowdupes = false;
							}
							array_parameters.lineitems = 8;
							array_parameters.flags = (sizearea > 0x10 && !allowdupes) *
								AP_INDEX | allowdupes * AP_ALLOWDUPS;
							// set proper array formatting regarding the data type
							switch (get_optype_flags0(flags)) {
								case FF_0VOID:
								case FF_0NUMH:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 16)) + 3;
									break;
								case FF_0NUMD:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 10)) + 3;
									break;
								case FF_0NUMB:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 2)) + 3;
									break;
								case FF_0NUMO:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 8)) + 3;
									break;
								case FF_0CHAR:
									array_parameters.alignment = allowdupes ? -1 : 5;
									break;
							} // dwitch statement
							break;
						case FF_BYTE:
							max = basevalue = get_byte(ea);
							for (scan = ea + elementwidth; scan < tmp; scan += elementwidth) {
#ifdef _SHOWADDRESS
								//showAddr(scan);
#endif
								uint8 value(get_byte(scan));
								if (value > max) max = value;
								if (value != basevalue) allowdupes = false;
							}
							array_parameters.lineitems = 8;
							array_parameters.flags = (sizearea > 8 && !allowdupes) *
								AP_INDEX | allowdupes * AP_ALLOWDUPS;
							// set proper array formatting regarding the data type
							switch (get_optype_flags0(flags)) {
								case FF_0VOID:
								case FF_0NUMH:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 16)) + 3;
									break;
								case FF_0NUMD:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 10)) + 3;
									break;
								case FF_0NUMB:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 2)) + 3;
									break;
								case FF_0NUMO:
									array_parameters.alignment = allowdupes ? -1 : strlen(_ultoa(max, s, 8)) + 3;
									break;
								case FF_0CHAR:
									array_parameters.alignment = allowdupes ? -1 : 4;
									break;
							} // dwitch statement
							break;
						default: {
							boost::shared_crtptr<void> firstitem(elementwidth),
								nextitem(elementwidth);
							if (static_cast<bool>(firstitem) && static_cast<bool>(nextitem)) {
								get_many_bytes(ea, firstitem.get(), elementwidth);
								for (scan = ea + elementwidth; allowdupes && scan < tmp;
									scan += elementwidth) {
#ifdef _SHOWADDRESS
									//showAddr(scan);
#endif
									if (get_many_bytes(scan, nextitem.get(), elementwidth)
										&& memcmp(firstitem.get(), nextitem.get(), elementwidth) != 0)
										allowdupes = false;
								}
							}
						}
					} // switch statement
				} // primitive type
				array_parameters.alignment = -1; // reset to default
				set_array_parameters(ea, &array_parameters);
				changed = true;
			} // raw area large enough
		} // can format
		// pass 3: detecting odd addressed offsets
		find_doubtful_offsets_range(area_t(ea, endEA), offboundary, list, verbosity < 2, prefix);
		// pass 4: scanning for unexpected code
		flags_t lastFlags(flags);
		for (scan = ea; scan < endEA; scan = next_head(scan, endEA)) {
#ifdef _SHOWADDRESS
			//showAddr(scan);
#endif
			const flags_t thisFlags(get_flags_novalue(scan));
			if (isUnknown(thisFlags) && !isUnknown(lastFlags)) {
				if (verbosity >= 2) msg("%swarning: hole inside variable at %08a\n", prefix ? prefix : "", scan);
				if (list != 0 && verbosity >= 2) {
					qsnprintf(CPY(dbg_out), "hole inside variable (%s)", get_disasm(scan, CPY(dassm)));
					list->Add(scan, 0x0417, dbg_out);
				}
			} else if (isCode(thisFlags)) {
				if (!has_any_name(thisFlags)) {
					for (ea_t first_not_code = scan; !isCode(get_flags_novalue(first_not_code));
						first_not_code = next_not_tail(first_not_code));
					do_unknown_range(scan, first_not_code - scan, true);
					autoCancel(scan, first_not_code);
					auto_mark_range(scan, first_not_code, AU_UNK);
				}
				if (!isCode(lastFlags)) {
					if (verbosity >= 2) msg("%swarning: unexpected code inside variable at %08a%s\n",
						prefix != 0 ? prefix : "", scan, !has_any_name(thisFlags) ? " (destroyed)" : "");
					qsnprintf(CPY(dbg_out), "unexpected instruction inside variable (%s)",
						get_disasm(scan, CPY(dassm)));
					if (!has_any_name(thisFlags)) qstrcat(dbg_out, " - destroyed");
					if (list != 0 && verbosity >= 2) list->Add(scan, 0x0007, dbg_out);
				}
			} else if (isAlign(thisFlags)) {
				asize_t size(get_item_size(scan));
				do_unknown(scan, true);
				if ((size & 3) == 0)
					doDwrd(scan, size);
				else if ((size & 1) == 0)
					doWord(scan, size);
				else
					doByte(scan, size);
				autoCancel(scan, scan + size); //autoUnmark(scan, scan + size, atype_t??);
				if (!isAlign(lastFlags)) {
					if (verbosity >= 2) msg("%swarning: unexpected align directive inside variable at %08a%s\n",
						prefix != 0 ? prefix : "", scan, " - destroyed");
					if (list != 0 && verbosity >= 2) list->Add(scan, 0x0517,
						"unexpected alignment inside variable (destroyed)");
				}
			}
			lastFlags = thisFlags;
		}
	} else { // !Loaded
		if (canformat) { // .data?
			tmp = endEA;
			for (scan = ea; scan < tmp; scan = next_not_tail(scan)) {
#ifdef _SHOWADDRESS
				//showAddr(scan);
#endif
				flags1 = getFlags(scan);
				typeinfo_t ti1;
				if (hasValue(flags1) || ((flags1 ^ flags) & (DT_TYPE | MS_0TYPE)) != 0
					&& !is_dummy_data(scan, false) || isStruct(flags)
					&& (get_typeinfo(scan, 0, flags1, &ti1) == 0 || ti1.tid != ti.tid)
					|| isEnum0(flags) && (get_typeinfo(scan, 0, flags1, &ti1) == 0
					|| ti1.ec.tid != ti.ec.tid)) tmp = scan;
			}
			if ((sizearea = tmp - ea) >= elementwidth << 1) { // raw area large enough
#ifdef _SHOWADDRESS
				showAddr(ea);
#endif
				// restore full type definition
				totalarraya += do_data_ex(ea, flags, pti, sizearea - sizearea % elementwidth);
				del_array_parameters(ea);
				changed = true;
			} // raw area large enough
		}// can format
	} // !Loaded
	if (changed) analyze_area(ea, endEA);
	// VCL-specific L4String
	if (does_prefix_lstring(ea - 4)) {
		_ASSERTE(isASCII(flags) && get_str_type_code(get_string_type(ea)) == ASCSTR_LEN4);
		flags = get_flags_novalue(ea -= 4);
		_ASSERTE(isNotTail(flags));
		if (!isDwrd(flags)) {
			do_unknown_range(ea, 4, false);
			doDwrd(ea, sizeof DWORD);
			op_hex(ea, 0);
		}
	}
#ifdef _DEBUG
	OutputDebugString("%s(...) determined block bounds for %08IX=<%08IX-%08IX> size=0x%IX item_end=%08IX (%s)\n",
		__FUNCTION__, refEA, ea, endEA, endEA - ea, item_end, get_disasm(refEA, CPY(dassm)));
#endif // _DEBUG
	return endEA;
}

asize_t doAlign(ea_t ea, size_t alignment, bool force) {
	_ASSERTE(isEnabled(ea) && alignment > 0);
	size_t size;
	if (isEnabled(ea) && (alignment = rdownpow2(alignment)) >= 2
		&& (size = get_align_size(ea, alignment)) > 0
		&& (force || is_dummy_data_range(ea, size))) {
		do_unknown_range(ea, size, false);
		int exponent(log2(alignment));
		if (doAlign(ea, static_cast<ulong>(size), exponent)) {
			//set_alignment(ea, exponent);
			return size;
		}
	}
	return 0;
}

bool make_off32(ea_t ea, bool force) {
	_ASSERTE(isEnabled(ea));
	const flags_t flags = get_flags_novalue(ea);
	if (/*isOffset(ea)*/isOff0(flags)) return true;
	ea_t tgt = can_be_off32(ea);
	if (tgt != 0 && !isEnabled(tgt) || is_in_rsrc(tgt)) return false;
	const asize_t ptrsize = get_ptr_size(flags/*get_flags_novalue(ea)*/);
	if (!force && !is_dummy_data_range(ea, ptrsize)) return false;
	do_unknown_range(ea, ptrsize, false);
	if (op_offset(ea, 0, get_default_reftype(ea)) == 0) return false;
	analyze_area(ea, next_not_tail(ea));
	return true;
}

uint find_offsets_range(const area_t &area, size_t offboundary, uint8 offtohead,
	CBatchResults *list, uint8 verbosity, const char *prefix) {
	_ASSERTE(isEnabled(area.startEA));
	if (area.startEA < inf.minEA || area.endEA >= inf.maxEA
		|| area.endEA < area.startEA) return 0;
	uint retval(0), totalnamed(0);
	area_t rsrc(BADADDR, BADADDR);
	PIMAGE_DATA_DIRECTORY rsrcinfo;
	IMAGE_NT_HEADERS pehdr;
	if (netnode("$ PE header").valobj(&pehdr, sizeof pehdr) >= sizeof pehdr
		&& (rsrcinfo = &pehdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]) != 0
		&& rsrcinfo->VirtualAddress != 0 && rsrcinfo->Size != 0
		&& isLoaded(pehdr.OptionalHeader.ImageBase + rsrcinfo->VirtualAddress)) {
		rsrc.startEA = pehdr.OptionalHeader.ImageBase + rsrcinfo->VirtualAddress;
		rsrc.endEA = pehdr.OptionalHeader.ImageBase + rsrcinfo->VirtualAddress + rsrcinfo->Size;
	}
	else {
		segment_t *segment(get_segm_by_name(".rsrc"));
		if (segment != 0) rsrc = *segment;
	}
	offboundary = rdownpow2(offboundary);
	ea_t scan(area.startEA);
#ifdef _SHOWADDRESS
	ea_t lastAuto(0);
#endif
	while (scan < area.endEA) {
#ifdef _SHOWADDRESS
		if (scan > lastAuto + AUTOFREQ) showAddr(lastAuto = scan);
#endif
		if (rsrc.contains(scan)) { scan = rsrc.endEA; continue; } // don't make references in .rsrc section
		ea_t tgt;
		flags_t flags(getFlags(scan));
		if (!hasValue(flags)) break; // give up on running out of section
		char dbg_out[64 + MAXNAMESIZE], name[MAXNAMESIZE];
		if (isCode(flags) && ua_ana0(scan) > 0) { // FF_CODE
			for (uint8 ocntr = 0; ocntr < UA_MAXOP; ++ocntr) {
				if (cmd.Operands[ocntr].type == o_imm && !isDefArg(flags, ocntr)
					&& isEnabled(tgt = cmd.Operands[ocntr].value)
					&& !rsrc.contains(tgt) && (offtohead == 0
					|| (offtohead == 1 ?
						points_to_meaningful_head : points_to_defitem)(tgt))) {
#ifdef _SHOWADDRESS
					showAddr(scan);
#endif
					if (op_offset(scan, ocntr, get_default_reftype(scan)) != 0) {
						analyze_area(scan, next_not_tail(scan));
						++retval;
						char reft(isCode(get_flags_novalue(tgt)) && isCode(flags) ? 'c' : 'd');
						if (verbosity >= 3) msg("%s  info: possible %cref found from %08a (op%u)\n",
								prefix != 0 ? prefix : "", reft, scan, ocntr + 1);
						/*
						_RPTF2(_CRT_WARN, "possible cref found from %08X operand %i\n", scan, ocntr + 1);
						_RPTF4(_CRT_WARN, "  offb/type/dtyp/offb_next: 0x%02X/%u/%u/0x%02X\n",
							cmd.Operands[ocntr].offb, cmd.Operands[ocntr].type,
							cmd.Operands[ocntr].dtyp, nextop);
						*/
						if (get_true_name(scan, tgt, CPY(name)) != 0)
							qsnprintf(CPY(dbg_out), "ok: %cref to %s (%u)", reft, name, ocntr + 1);
						else
							qsnprintf(CPY(dbg_out), "ok: %cref to %08a (%u)", reft, tgt, ocntr + 1);
						if (list != 0) list->Add(scan, 0x0005, dbg_out);
					} else
						if (list != 0) list->Add(scan, 0xFFFF, "failed to create offset");
				}
			} // operand walk
			scan = next_not_tail(scan);
		} else if (is_dummy_data_range(scan, sizeof ea_t)) { // FF_DATA
			if ((offboundary == 0 || (scan & offboundary - 1) == 0)
				&& get_many_bytes(scan, &tgt, sizeof tgt) && isEnabled(tgt)
				&& !rsrc.contains(tgt) && (offtohead == 0 || (offtohead == 1 ?
					points_to_meaningful_head : points_to_defitem)(tgt))) { // can make offset
#ifdef _SHOWADDRESS
				showAddr(scan);
#endif
				do_unknown_range(scan, sizeof ea_t, false);
				bool result(op_offset(scan, 0, get_default_reftype(scan)) != 0);
				if (!result && isTail(flags)) {
					do_unknown(get_item_head(scan), true);
					result = op_offset(scan, 0, get_default_reftype(scan)) != 0;
				}
				if (result) {
					analyze_area(scan, next_not_tail(scan));
					++retval;
					if (verbosity >= 3) msg("%s  info: possible dref found from %08a\n",
						prefix != 0 ? prefix : "", scan);
					if (list != 0) {
						if (get_true_name(scan, tgt, CPY(name)) != 0)
							qsnprintf(CPY(dbg_out), "ok: dref to %s", name);
						else
							qsnprintf(CPY(dbg_out), "ok: dref to %08a", tgt);
						list->Add(scan, 0x0005, dbg_out);
					}
					scan = next_not_tail(scan);
					continue;
				} else {
					if (verbosity >= 2) msg("%swarning: failed to create dref at %08a\n", prefix != 0 ?
						prefix : "", scan);
					if (list != 0) list->Add(scan, 0xFFFF, "failed to create offset");
				}
			} // passed to create offset here
			scan = nextaddr(scan);
		} else
			// skip existing non-dummy ranges
			scan = next_not_tail(scan);
	}
	return retval;
}

uint find_doubtful_offsets_range(const area_t &area,
	size_t offset_alignment, CBatchResults *list, bool quiet, const char *prefix) {
	_ASSERTE(isEnabled(area.startEA) && area.endEA > area.startEA);
	if (offset_alignment == 0 || area.startEA < inf.minEA
		|| area.endEA >= inf.maxEA || area.endEA <= area.startEA) return 0;
	uint retval(0);
#ifdef _SHOWADDRESS
	ea_t lastAuto(0);
#endif
	offset_alignment = rdownpow2(offset_alignment);
	for (ea_t scan = area.startEA; scan < area.endEA; scan = next_head(scan, area.endEA)) {
		if (wasBreak()) throw 11;
#ifdef _SHOWADDRESS
		if (scan > lastAuto + AUTOFREQ) showAddr(lastAuto = scan);
#endif
		flags_t flags = getFlags(scan);
		if (isData(flags) && isOff0(flags)) {
			if ((scan & offset_alignment - 1) != 0) {
				if (!quiet) msg("%swarning: offset from unaligned address at %08a\n",
					prefix != 0 ? prefix : "", scan);
				if (list != 0) list->Add(scan, 0x0032, "offset from unaligned address");
				++retval;
			}
			segment_t *segment;
			if (hasValue(flags) && (segment = getseg(scan)) != 0
				&& !is_spec_segm(segment->type)) {
				const asize_t elementwidth = get_data_type_size(scan, flags);
				ea_t tgt, lastraw(next_not_tail(scan));
				char dbg_out[512];
				for (ea_t ea = scan; ea < lastraw; ea += elementwidth)
					if ((tgt = elementwidth == 4 ? get_long(ea) : elementwidth == 2 ?
						get_word(ea) : get_byte(ea)))
							if (!isEnabled(tgt)) {
								if (!quiet) msg("%swarning: offset invalid at %08a (%08a)\n",
									prefix != 0 ? prefix : "", ea, tgt);
								if (list != 0) {
									qsnprintf(CPY(dbg_out), "offset to invalid address %08a", tgt);
									list->Add(ea, 0x0200, dbg_out);
								}
								++retval;
							} else if (!points_to_meaningful_head(tgt)) {
								if (!quiet) msg("%swarning: offset to tail at %08a\n",
									prefix != 0 ? prefix : "", ea);
								if (list != 0) list->Add(ea, 0x0031, "offset to tail");
								++retval;
							} else if (is_in_rsrc(tgt)) {
								if (!quiet) msg("%swarning: .rsrc section referred from %08a\n",
									prefix != 0 ? prefix : "", ea);
								if (list != 0) {
									qsnprintf(CPY(dbg_out), "resource section referred (%08a)", tgt);
									list->Add(ea, 0x0200, dbg_out);
								}
								++retval;
							}
			} // offset is loaded
		} // data and offset
	} //range walk
	return retval;
}

uint nameanonoffsets_internal(ea_t to, uint8 verbosity,
	const char *prefix, CBatchResults *list) {
	_ASSERTE(isEnabled(to));
	flags_t flags;
	if (!isEnabled(to) || !hasRef(flags = get_flags_novalue(to))
		|| !has_name(flags) || is_in_rsrc(to)) return 0;
	uint result(0);
	char name[MAXNAMESIZE];
	qstrcpy(name, "ptr2_");
	if (get_true_name(BADADDR, to, CAT(name)) != 0) {
		xrefblk_t xr;
		for (bool ok = xr.first_to(to, XREF_DATA); ok; ok = xr.next_to())
			if (isData(flags = getFlags(xr.from)) && isOff0(flags)
				&& hasValue(flags) && !has_name(flags) && hasRef(flags)
				&& get_item_head(xr.from) == xr.from && !isArray(xr.from)) {
				if (do_name_anyway(xr.from, name)) {
					if (verbosity >= 3) msg("%s  info: offset at %08a renamed to %s\n",
						prefix != 0 ? prefix : "", xr.from, name);
					if (list != 0) list->Add(xr.from, 0x000C, name);
					result += 1 + nameanonoffsets_internal(xr.from, verbosity, prefix, list);
				} else {
					if (verbosity >= 2) msg("%swarning: failed to rename offset at %08a\n",
						prefix != 0 ? prefix : "", xr.from);
					if (list != 0) list->Add(xr.from, 0xFFFF, "failed to rename offset");
				}
			}
	}
	return result;
}
