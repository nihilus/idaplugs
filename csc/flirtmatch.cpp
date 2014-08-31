
/*****************************************************************************
 *                                                                           *
 *  flirtmatch.cpp: Code snippet creator plugin for ida pro                  *
 *  (c) 2005-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

/*
 * omf parser: checksumy u borlandu zlobí, co je/není public (recordId=???)
 */

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "fixdcstr.hpp"
#include <fstream>
#include <iomanip>
#include <vector>
#include <valarray>
#include <boost/lambda/lambda.hpp>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/if.hpp>
#include "cmangle.h"
#include "pcre.hpp"
#include "flirtmatch.h"

using namespace boost::lambda;

INT_PTR CALLBACK about_dlgproc(HWND, UINT, WPARAM, LPARAM);

/*****************************************************************************
 *  *
 *  C0MPONENT 3: FLIRT LIBNAMES MATCHER  *
 *  *
 *****************************************************************************/

namespace LNM {

// template<class T>std::size_t hash_value(const T &);
// namespace boost { using ::LNM::hash_value; }

#define _SHOWADDRESS  1         // display progress

#define LNM_RENAMED   0x0001
#define LNM_ADDLIB    0x0002
#define LNM_UNLIB     0x0003
#define LNM_ALIAS     0x00FF
#define LNM_MISMATCH  0x0100
#define LNM_WARNING   0x0FFF
#define LNM_ERROR     0xFFFF

#define LNM_NODE      "$ lnm lastlibs"

enum regexp_idx {
	bcppproc, bcpptype, bcppclass, bcppdata,
	bcppconst, vcppproc, vcppdata, vcanyname,
};

static uint8 category;
static bool collapse_matching, fix_mangling, nocase, quiet,
	omf_carechecksums, mix_type, verbose, unname_nomatch, fast_match,
	any_segment;
static PCRE::regexp regex[9];
static const char *options;
static const char prefix[] = "[lnm] ";
static const char cfgsection[] = "LNM";
clist list;

struct symbol_t {
	string name; // name in same form as in library
	IMPORT_OBJECT_TYPE area; // (code, data, const), -1 = not set
	IMPORT_OBJECT_NAME_TYPE nametype; // (byname, byord, noprefix, undecorate), -1 = not set
	fixed_path_t module; // module name providing this symbol (if known)

	symbol_t(const char *name, const char *module = 0,
		IMPORT_OBJECT_TYPE area = static_cast<IMPORT_OBJECT_TYPE>(-1),
		IMPORT_OBJECT_NAME_TYPE nametype = static_cast<IMPORT_OBJECT_NAME_TYPE>(-1))
		throw(exception) : module(module), area(area), nametype(nametype) {
		_ASSERTE(name != 0 && *name != 0);
		if (name == 0 || *name == 0)
			__stl_throw_invalid_argument("name must be non-empty string");
		this->name.assign(name);
		_ASSERTE(!this->name.empty());
	}

	bool operator ==(const symbol_t &rhs) const { return name == rhs.name; }

	bool area_match(IMPORT_OBJECT_TYPE t) const throw() {
		return area == static_cast<IMPORT_OBJECT_TYPE>(-1)
			|| t == static_cast<IMPORT_OBJECT_TYPE>(-1)
			|| area == IMPORT_OBJECT_CODE && t == IMPORT_OBJECT_CODE
			|| area != IMPORT_OBJECT_CODE && t != IMPORT_OBJECT_CODE;
	}

	struct hash {
		inline size_t operator ()(const symbol_t &__x) const
			{ return hash_value/*__stl_string_hash*/(__x/*.name*/); }
	};
	friend inline std::size_t hash_value(const symbol_t &__x)
		{ return boost::hash_value(__x.name); }
}; // symbol_t
static class symbols_t : public hash_set<symbol_t, symbol_t::hash/*boost::hash<symbol_t> */> {
public:
	bool insert(const char *name, const char *module = 0,
		IMPORT_OBJECT_TYPE area = static_cast<IMPORT_OBJECT_TYPE>(-1),
		IMPORT_OBJECT_NAME_TYPE nametype = static_cast<IMPORT_OBJECT_NAME_TYPE>(-1));
	const_iterator find(const char *name) const;
	// this is my experimental lookup method: find name that 'sounds like'
	// searched name for later renaming
	// only recommended if find above fails (much slower)
	// inhibits very simple name mangling parser for per-partes comparison
	// (additional recognition ratio via case non-sensitive mode)
	const_iterator find_root(const char *name,
		IMPORT_OBJECT_TYPE = static_cast<IMPORT_OBJECT_TYPE>(-1)) const;
} symbols;

uint16 omf_readindex(const void *record, uint16 &index);
uint32 omf_readvarvalue(const void *record, uint16 &index);

INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

bool Execute() {
	enum totals_t {
		match, addlib, rename, unlib, warning, error, alias, mismatch,
	};
	valarray<uint> totals(static_cast<uint>(0), 8);
	bool ok(true), listwasopen(list > 0);
	uint i;
	_ASSERTE(symbols.empty());
	try {
		if (DialogBox(hInstance, MAKEINTRESOURCE(IDD_LNM),
			get_ida_hwnd(), DialogProc) != IDOK) return false;
		if (!symbols.empty())
			cmsg << prefix << "total " << dec << symbols.size() << " externals recognized" << endl;
		else
			throw fmt_exception("no externals available, dying");
		if (!decide_ida_bizy("libnames matching")) {
			// Let the analysis make all data references to avoid variables merging.
			MessageBeep(MB_ICONEXCLAMATION);
			throw fmt_exception("autoanalysis is running now. call me again when finished");
		}
		layered_wait_box wait_box("please wait, plugin is running...");
		options = get_plugin_options("lnm");
		static const char *const regexps[] = {
			BCPPPROC, BCPPTYPE, BCPPCLASS, BCPPDATA,
			BCPPCONST, VCPPPROC, VCPPDATA, VCANYNAME,
		};
		if (fix_mangling) for (i = 0; i < 8; ++i)
			if (regex[i].compile(regexps[i], nocase ? PCRE_CASELESS : 0) == 0)
				regex[i].study();
		if (regex[8].compile("^(?:" FUNC_IMPORT_PREFIX ")?([_\\@\\?]?((" VCNAME ")(?:\\@(?:\\d+))?))$") == 0)
			regex[8].study();
		list.Clear();
#ifdef _SHOWADDRESS
		ea_t lastAuto(0);
#endif
		for (int iter = 0; iter < get_segm_qty(); ++iter) {
			segment_t *segment(getnseg(iter));
			if (segment == 0 || !any_segment && (is_spec_segm(segment->type)
				|| is_in_rsrc(segment->startEA))) continue;
			for (ea_t scan = segment->startEA; scan < segment->endEA; scan = nextaddr(scan)) {
				if (wasBreak()) throw fmt_exception("user break");
#ifdef _SHOWADDRESS
				if (scan > lastAuto + AUTOFREQ) showAddr(lastAuto = scan);
#endif
				flags_t flags(get_flags_novalue(scan));
				func_t *func(isFunc(flags) ? get_func(scan) : 0);
				if ((category != 2 || !isCode(flags)) && (category != 1 || isCode(flags))
					&& (func == 0 || !is_pure_import_func(func))) { // proceed
					char name[MAXNAMESIZE], true_name[MAXNAMESIZE];
					if (!has_any_name(flags) || get_name(scan, scan, CPY(name)) == 0)
						name[0] = 0;
					if (!has_any_name(flags) || get_true_name(scan, scan, CPY(true_name)) == 0)
						true_name[0] = 0;
					_ASSERTE(!has_any_name(flags) || name[0] != 0 && true_name[0] != 0);
					symbols_t::const_iterator symbol, true_symbol;
					bool name_match(has_name(flags)
							&& (symbol = symbols.find(name)) != symbols.end());
					if (name_match && !symbol->area_match(isCode(flags) ?
							IMPORT_OBJECT_CODE : IMPORT_OBJECT_DATA)) {
						if (!quiet) cmsg << prefix << asea(scan) <<
							": area mismatch for " << name << endl;
						list.Add(scan, name, LNM_MISMATCH, _sprintf("library says %s",
							symbol->area == IMPORT_OBJECT_CODE ? "code":
							symbol->area == IMPORT_OBJECT_DATA ? "data" : "const").c_str(),
							isCode(flags));
						++totals[mismatch];
						if (!mix_type) goto unlib;
					}
					bool true_name_match(has_name(flags)
						&& (true_symbol = strcmp(name, true_name) != 0 ?
						symbols.find(true_name) : symbol) != symbols.end());
					if (!name_match && true_name_match && !true_symbol->area_match(isCode(flags) ?
						IMPORT_OBJECT_CODE : IMPORT_OBJECT_DATA)) {
						if (!quiet) cmsg << prefix << asea(scan) <<
							": area mismatch for " << true_name << endl;
						list.Add(scan, true_name, LNM_MISMATCH, _sprintf("library says %s",
							true_symbol->area == IMPORT_OBJECT_CODE ? "code":
							true_symbol->area == IMPORT_OBJECT_DATA ? "data" : "const").c_str(),
							isCode(flags));
						++totals[mismatch];
						if (!mix_type) goto unlib;
					}
					if (name_match || true_name_match) { // exact match
						if (func != 0 && (func->flags & FUNC_LIB) != 0 || func == 0
							&& is_libitem(scan) /*&& get_supressed_library_flag(scan) != 1*/)
							++totals[match];
						else { // lib flag mismatch
						addlib:
							if (func != 0) {
								func->flags |= FUNC_LIB;
								if (update_func(func)) {
									if (!quiet) cmsg << prefix << "function at " << asea(scan) <<
										" addlibed successfully: " << name << endl;
									list.Add(scan, name, LNM_ADDLIB, true_name_match ?
										true_symbol->module : symbol->module, true);
									++totals[addlib];
									func = get_func(scan);
									_ASSERTE(func != 0);
									if (collapse_matching && is_visible_func(func))
										set_visible_func(func, false);
								} else {
									cmsg << prefix << "failed to addlib function at " <<
										asea(scan) << " (" << name << ')' << endl;
									list.Add(scan, name, LNM_ERROR, "failed addlib", true);
									++totals[error];
								}
							} else { // pure code or variable: !is_libitem(scan)
								if (collapse_matching && is_visible_item(scan)) {
									hide_item(scan);
#ifdef _DEBUG
									inf.s_cmtflg |= SW_SHHID_ITEM;
#endif // _DEBUG
								}
								if (!quiet) cmsg << prefix << "item at " << asea(scan) <<
									" addlibed successfully: " << name << endl;
								list.Add(scan, name, LNM_ADDLIB, true_name_match ?
									true_symbol->module : symbol->module, false);
								++totals[addlib];
							} // pure code or variable
							set_libitem(scan);
						} // addlib
						clr_supressed_library_flag(scan);
						if (true_name_match && !name_match) {
							if (!true_symbol->module.empty())
								netnode(scan).supset(AFL_LIB, true_symbol->module);
							if (!quiet) cmsg << prefix << "external " << true_name <<
								" matched by true name, aliased impdef required" << endl;
							list.Add(scan, true_name, LNM_ALIAS, name, isCode(flags));
							++totals[alias];
						} else if (name_match && !true_name_match) {
							if (!symbol->module.empty())
								netnode(scan).supset(AFL_LIB, symbol->module);
							if (!quiet) cmsg << prefix << "external " << true_name <<
								" matched by aliased name, ordinal import required?" << endl;
							list.Add(scan, true_name, LNM_ALIAS, name, isCode(flags));
							++totals[alias];
						} else {
							_ASSERTE(name_match && true_name_match);
							if (!true_symbol->module.empty())
								netnode(scan).supset(AFL_LIB, true_symbol->module);
						}
					} else if (fix_mangling && has_name(flags)
						&& ((true_symbol = symbols.find_root(name, isCode(flags) ? IMPORT_OBJECT_CODE : IMPORT_OBJECT_DATA)) != symbols.end()
						&& get_name_ea(scan, true_symbol->name.c_str()) == BADADDR
						|| (true_symbol = symbols.find_root(true_name, isCode(flags) ? IMPORT_OBJECT_CODE : IMPORT_OBJECT_DATA)) != symbols.end()
						&& get_name_ea(scan, true_symbol->name.c_str()) == BADADDR)) // partial match, alternate name available
						if (set_name(scan, true_symbol->name.c_str(), SN_CHECK | SN_NOWARN | SN_NON_WEAK)) { // ok
							_ASSERTE(!true_symbol->name.empty());
							if (!quiet) cmsg << prefix << "item at " << asea(scan) <<
								" renamed successfully: " << true_symbol->name << endl;
							list.Add(scan, name, LNM_RENAMED, true_symbol->name.c_str(), true);
							++totals[rename];
							if ((func = isFunc(flags = get_flags_novalue(scan)) ?
								get_func(scan) : 0) != 0 && (func->flags & FUNC_LIB) == 0
								|| func == 0 && !is_libitem(scan)) {
								_ASSERTE(has_name(flags));
								if (get_name(scan, scan, CPY(name)) == 0) name[0] = 0;
#ifdef _DEBUG
								if (get_true_name(scan, scan, CPY(true_name)) == 0) true_name[0] = 0;
#else // !_DEBUG
								qstrcpy(true_name, true_symbol->name.c_str());
#endif // _DEBUG
								_ASSERTE(name[0] != 0 && true_name[0] != 0);
								true_name_match =
#ifdef _DEBUG
									symbols.find(true_name) != symbols.end();
#else // !_DEBUG
									true;
#endif // _DEBUG
								_ASSERTE(true_name_match);
								name_match = (symbol = strcmp(name, true_name) != 0 ?
									symbols.find(name) : true_symbol) != symbols.end();

								goto addlib;
							}
						} else { // error
							cmsg << prefix << "warning: failed to rename at " <<
								asea(scan) << " to " << true_symbol->name << endl;
							list.Add(scan, name, LNM_ERROR, _sprintf("failed renaming to %s",
								true_symbol->name.c_str()).c_str(), true);
							++totals[error];
						} // error
					else { // unlib
					unlib:
						netnode(scan).supdel(AFL_LIB);
						if (func != 0) {
							if ((func->flags & FUNC_LIB) != 0) {
								func->flags &= ~FUNC_LIB;
								_ASSERTE(name[0] != 0);
#ifdef _DEBUG
								if (get_supressed_library_flag(scan) == 1) {
									++totals[warning];
									cmsg << prefix << "warning: non-library function " << name <<
										" at " << asea(scan) << " already unlibed by flirt matcher!" << endl;
									list.Add(scan, name, LNM_WARNING,
										"non-library function already unlibed by flirt matcher", true);
								}
#endif // _DEBUG
								if (update_func(func)) {
									if (!quiet) cmsg << prefix << "function at " <<
										asea(scan) << " unlibed successfully: " << name << endl;
									list.Add(scan, name, LNM_UNLIB, 0, true);
									++totals[unlib];
								} else {
									cmsg << prefix << "failed to unlib function at " <<
										asea(scan) << " (" << name << ')' << endl;
									list.Add(scan, name, LNM_ERROR, "failed unlib", true);
									++totals[error];
								}
								if (unname_nomatch && has_name(flags)) {
									del_global_name(scan);
									if (hasRef(scan)) set_dummy_name(BADADDR, scan);
								}
							} // func needs unlibed
						} else if (is_libitem(scan)
							/*&& get_supressed_library_flag(scan) != 1*/) {
#ifdef _DEBUG
							if (get_supressed_library_flag(scan) == 1) {
								++totals[warning];
								if (name[0] != 0)
									cmsg << prefix << "warning: non-library item " << name <<
										" at " << asea(scan) << " already unlibed by flirt matcher!" << endl;
								else
									cmsg << prefix << "warning: non-library item at " <<
										asea(scan) << " already unlibed by flirt matcher!" << endl;
								list.Add(scan, name, LNM_WARNING,
									"non-library item already unlibed by flirt matcher", false);
							}
#endif // _DEBUG
							if (!quiet) {
								cmsg << prefix << (name[0] == 0 ? "unnamed " : "") <<
									"item at " << asea(scan) << " unlibed successfully";
								if (name[0] != 0) cmsg << ": " << name;
								cmsg << endl;
							}
							list.Add(scan, name, LNM_UNLIB, 0, false);
							++totals[unlib];
							if (unname_nomatch && has_name(flags)) {
								del_global_name(scan);
								if (hasRef(scan)) set_dummy_name(scan, scan);
							}
						}
						clr_libitem(scan);
						if (is_hidden_item(scan)) unhide_item(scan);
						// set_supressed_library_flag(scan, 1);
					} // no match, remove library flag
				} // area ok, has user name
			} // walk the module
		} // walk the segments
	} catch (const exception &e) {
		ok = false;
		cmsg << prefix << "failed to match libnames: " << e.what() << endl;
		MessageBeep(MB_ICONERROR);
	}
	for_each(regex, regex + qnumber(regex), boost::mem_fun_ref(PCRE::regexp::reset));
	symbols.clear();
	if (list > 0)
		if (!listwasopen)
			list.Open();
#if IDA_SDK_VERSION >= 520
		else
			list.Refresh();
#endif
#if IDP_INTERFACE_VERSION >= 76
	else
		list.Close();
#endif
	cmsg << prefix << "sall done, totals:" << endl << dec << setfill(' ') <<
		prefix << setw(8) << totals[match] << " names matched" << endl <<
		prefix << setw(8) << totals[addlib] << " names marked as library" << endl <<
		prefix << setw(8) << totals[rename] << " names renamed (heuristic match)" << endl <<
		prefix << setw(8) << totals[unlib] << " names unmarked as library" << endl <<
		prefix << setw(8) << totals[warning] << " warnings" << endl <<
		prefix << setw(8) << totals[error] << " names failed to rename or (un)mark as library" << endl <<
		prefix << setw(8) << totals[alias] << " names matched by aliased name" << endl <<
		prefix << setw(8) << totals[mismatch] << " names mismatched by area type" << endl;
	return ok;
} // Execute()

uint AddPublics(const char *libpath, HWND hwndDlg) {
	_ASSERTE(libpath != 0 && *libpath != 0);
	if (libpath == 0 || *libpath == 0) return 0;
	_ASSERTE(qfileexist(libpath));
	ifstream is(libpath, ios_base::in | ios_base::binary);
	if (!is) {
		cmsg << prefix << "error on open library " << libpath << ": " << strerror(errno) << endl;
		return 0;
	}
	uint result(0), chsbad(0);
#define recId static_cast<uint8>(sig[0])
	char name[_MAX_FNAME], ext[_MAX_EXT];
	_splitpath(libpath, 0, 0, name, ext);
	cmsg << prefix << "dumping " << name << ext << "...";
	try {
		char sig[IMAGE_ARCHIVE_START_SIZE];
		boost::shared_crtptr<void> buf;
		if (is_pe32(libpath)) {
			HMODULE hDll(LoadLibrary(libpath));
			if (hDll != NULL) {
				try {
					cmsg << "pe module detected...";
					const PIMAGE_NT_HEADERS
						pehdr(reinterpret_cast<PIMAGE_NT_HEADERS>((LPBYTE)hDll +
							reinterpret_cast<PIMAGE_DOS_HEADER>(hDll)->e_lfanew));
					const PIMAGE_EXPORT_DIRECTORY
						expdir(reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((LPBYTE)hDll +
							pehdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
					if ((LPVOID)expdir <= hDll) throw logic_error("no symbols");
					if (expdir->NumberOfNames <= 0 || expdir->AddressOfNames == 0
						|| expdir->AddressOfNames == expdir->AddressOfNameOrdinals)
						throw logic_error("ordinal symbols");
					for (DWORD index = 0; index < expdir->NumberOfNames; ++index)
						if (symbols.insert(reinterpret_cast<LPCSTR>(hDll) +
							reinterpret_cast<LPDWORD>((LPBYTE)hDll + expdir->AddressOfNames)[index],
							reinterpret_cast<LPCSTR>(hDll) + expdir->Name)) ++result;
				} catch (...) {
					FreeLibrary(hDll);
					/*re*/throw;
				}
				FreeLibrary(hDll);
			} else
				cmsg << "pe module detected but load failed...";
		}
			/*
			 * 7. Archive (Library) File Format
			 * The COFF archive format provides a standard mechanism for storing collections of object files. These collections are frequently referred to as "libraries" in programming documentation.
			 *
			 * The first eight bytes of an archive consist of the file signature. The rest of the archive consists of a series of archive members, as follows:
			 *
			 * The first and second members are "linker members." Each has of these members has its own format as described in Section 8.3. Typically, a linker places information into these archive members. The linker members contain the directory of the archive.
			 *
			 * The third member is the longnames member. This member consists of a series of null-terminated ASCII strings, in which each string is the name of another archive member.
			 *
			 * The rest of the archive consists of standard (object-file) members. Each of these members contains the contents of one object file in its entirety.
			 * An archive member header precedes each member. The following illustration shows the general structure of an archive:
			 *
			 * Signature :"!<arch>\n"
			 *
			 * Header
			 * 1st Linker Member
			 *
			 * Header
			 * 2nd Linker Member
			 *
			 * Header
			 * Longnames Member
			 *
			 * Header
			 * Contents of OBJ File 1
			 * (COFF format)
			 *
			 * Header
			 * Contents of OBJ File 2
			 * (COFF format)
			 *
			 * .
			 *
			 * Header
			 * Contents of OBJ File N
			 * (COFF format)
			 *
			 * Figure 4. Archive File Structure
			 */
			else if (!is.seekg(0).read(sig, IMAGE_ARCHIVE_START_SIZE).fail()
			&& memcmp(sig, IMAGE_ARCHIVE_START, IMAGE_ARCHIVE_START_SIZE) == 0) {
			/*
			 * 7.1. Archive File Signature
			 * The archive file signature identifies the file type. Any utility (for example, a linker) expecting an archive file as input can check the file type by reading this signature. The signature consists of the following ASCII characters, in which each character below is represented literally, except for the newline (\n) character:
			 *
			 * !<arch>\n
			 */
			uint reccnt(0);
			uint32 membercount(0), symbolcount[2] = { 0, 0 };
			const uint32 *symboloffsets(0), *memberoffsets(0);
			const uint16 *indices(0);
			const char *stringtable[2] = { 0, 0 };
			vector<boost::shared_crtptr<void> > linkermembers;
			boost::shared_crtptr<void> longnames;
			cmsg << "coff library detected...";
			while (is.good()) {
				/*
				 * 7.2. Archive Member Headers
				 * Each member (linker, longnames, or object-file member) is preceded by a header. An archive member header has the following format, in which each field is an ASCII text string that is left justified and padded with spaces to the end of the field. There is no terminating null character in any of these fields.
				 *
				 * Each member header starts on the first even address after the end of the previous archive member.
				 *
				 * Offset Size Field Description
				 *  0     16   Name Name of archive member, with a slash (/) appended to terminate the name. If the first character is a slash, the name has a special interpretation, as described below.
				 * 16     12   Date Date and time the archive member was created: ASCII decimal representation of the number of seconds since 1/1/1970 UCT.
				 * 28      6   User ID ASCII decimal representation of the user ID.
				 * 34      6   Group ID ASCII group representation of the group ID.
				 * 40      8   Mode ASCII octal representation of the member's file mode.
				 * 48     10   Size ASCII decimal representation of the total size of the archive member, not including the size of the header.
				 * 58      2   End of Header The two bytes in the C string "'\n".
				 *
				 * The Name field has one of the formats shown in the following table. As mentioned above, each of these strings is left justified and padded with trailing spaces within a field of 16 bytes:
				 *
				 * Contents of Name Field Description
				 * Name/ The field gives the name of the archive member directly.
				 * /     The archive member is one of the two linker members. Both of the linker members have this name.
				 * //    The archive member is the longname member, which consists of a series of null-terminated ASCII strings. The longnames member is the third archive member, and must always be present even if the contents are empty.
				 * \n    The name of the archive member is located at offset n within the longnames member. The number n is the decimal representation of the offset. For example: "\26" indicates that the name of the archive member is located 26 bytes beyond the beginning of longnames member contents.
				 */
				if ((is.tellg() & 1) != 0) {
					char padding;
					if (is.read(&padding, sizeof padding).eof()) break;
					if (!is) throw logic_error("cannot skip odd byte");
#ifdef _DEBUG
					if (padding != IMAGE_ARCHIVE_PAD[0])
						_RPTF2(_CRT_WARN, "%swarning: coff module padding mismatch ('%c')\n",
							prefix, padding);
#endif // _DEBUG
				}
				_ASSERTE(is.good());
				//OutputDebugString("seekg()=0x%I64X\n", (streamoff)is.tellg());
				IMAGE_ARCHIVE_MEMBER_HEADER header;
				if (is.read(reinterpret_cast<char *>(&header), IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR).eof()) break;
				if (!is) throw logic_error("cannot read archive member header");
				if (memcmp(header.EndHeader, IMAGE_ARCHIVE_END, sizeof IMAGE_ARCHIVE_END - 1) != 0)
					throw fmt_exception("header end mismatch (0x%X,0x%X)", header.EndHeader[0], header.EndHeader[1]);
				++reccnt;
				const size_t size(strtoul(reinterpret_cast<const char *>(header.Size), 0, 10));
				if (size == 0) {
					_RPTF2(_CRT_WARN, "%s(...): archive member of zero size (%.16s)\n",
						__FUNCTION__, header.Name);
					continue;
				}
				buf.reset(size);
				if (!buf) {
					_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new block of size 0x%IX\n",
						__FUNCTION__, size);
					throw bad_alloc();
				}
				if (!is.read(static_cast<char *>(buf.get()), size).good())
					throw logic_error("cannot read archive member");
				if (memcmp(header.Name, IMAGE_ARCHIVE_LINKER_MEMBER, sizeof header.Name) == 0) { // linker member
					linkermembers.push_back(buf);
					switch (linkermembers.size()) {
						case 1: {
							/*
							 * 7.3. First Linker Member
							 * The name of the first linker member is "\". The first linker member, which is included for backward compatibility, is not used by current linkers but its format must be correct. This linker member provides a directory of symbol names, as does the second linker member. For each symbol, the information indicates where to find the archive member that contains the symbol.
							 *
							 * The first linker member has the following format. This information appears after the header:
							 *
							 * Offset Size  Field Description
							 * 0      4     Number of Symbols Unsigned long containing the number of symbols indexed. This number is stored in big-endian format. Each object-file member typically defines one or more external symbols.
							 * 4      4 * n Offsets Array of file offsets to archive member headers, in which n is equal to Number of Symbols. Each number in the array is an unsigned long stored in big-endian format. For each symbol named in the String Table, the corresponding element in the Offsets array gives the location of the archive member that contains the symbol.
							 * *      *     String Table Series of null-terminated strings that name all the symbols in the directory. Each string begins immediately after the null character in the previous string. The number of strings must be equal to the value of the Number of Symbols fields.
							 *
							 * The elements in the Offsets array must be arranged in ascending order. This fact implies that the symbols listed in the String Table must be arranged according to the order of archive members. For example, all the symbols in the first object-file member would have to be listed before the symbols in the second object file.
							 */
							symbolcount[0] = *static_cast<uint32 *>(buf.get());
							symboloffsets = static_cast<const uint32 *>(buf.get()) + 1;
							__asm { // we work in little indian
								mov eax, symbolcount
								bswap eax
								mov symbolcount, eax
								mov ecx, eax
								mov edi, symboloffsets
							lbl1:
								mov eax, [edi]
								bswap eax
								stosd
								loop lbl1
							}
							stringtable[0] = reinterpret_cast<const char *>
								(static_cast<const uint32 *>(buf.get()) + 1 + symbolcount[0]);
							/*
							try {
								char *ptr(stringtable1);
								for (uint32 iter = 0; iter < symbolcount1; ++iter) {
									if (symbols.insert(ptr)) ++result;
									ptr += string(ptr) + 1;
								}
							} catch (...) { } // exception occured
							*/
							break;
						}
						case 2: {
							/*
							 * 7.4. Second Linker Member
							 * The second linker member has the name "\" as does the first linker member. Although both the linker members provide a directory of symbols and archive members that contain them, the second linker member is used in preference to the first by all current linkers. The second linker member includes symbol names in lexical order, which enables faster searching by name.
							 *
							 * The first second member has the following format. This information appears after the header:
							 *
							 * Offset Size  Field Description
							 * 0      4     Number of Members Unsigned long containing the number of archive members.
							 * 4      4 * m Offsets Array of file offsets to archive member headers, arranged in ascending order. Each offset is an unsigned long. The number m is equal to the value of the Number of Members field.
							 * *      4     Number of Symbols Unsigned long containing the number of symbols indexed. Each object-file member typically defines one or more external symbols.
							 * *      2 * n Indices Array of 1-based indices (unsigned short) which map symbol names to archive member offsets. The number n is equal to Number of Symbols. For each symbol named in the String Table, the corresponding element in the Indices array gives an index into the Offsets array. The Offsets array, in turn, gives the location of the archive member that contains the symbol.
							 * *      *     String Table Series of null-terminated strings that name all the symbols in the directory. Each string begins immediately after the null byte in the previous string. The number of strings must be equal to the value of the Number of Symbols fields. This table lists all the symbol names in ascending lexical order.
							 */
							membercount = *static_cast<const uint32 *>(buf.get());
							memberoffsets = static_cast<const uint32 *>(buf.get()) + 1;
							symbolcount[1] = *(static_cast<const uint32 *>
								(buf.get()) + 1 + membercount);
							indices = (const uint16 *)
								(static_cast<const uint32 *>(buf.get()) + 2 + membercount);
							stringtable[1] = (const char *)
								(static_cast<uint32 *>(buf.get()) + 2 +
								membercount) + (symbolcount[1] << 1);
							/*
							try {
								char *ptr(stringtable[1]);
								for (uint iter = 0; iter < membercount; ++iter) {
									if (symbols.insert(ptr)) ++result;
									ptr += string(ptr) + 1;
								}
							} catch (...) { } // exception occured
							*/
							break;
						} // 2nd linker member
#ifdef _DEBUG
						default:
							_RPT3(_CRT_WARN, "%s(\"%s\", ...): unexpected linker member (index=%Iu)\n",
								__FUNCTION__, libpath, linkermembers.size());
#endif // _DEBUG
					} // switch linker member
				} else if (memcmp(header.Name, IMAGE_ARCHIVE_LONGNAMES_MEMBER, sizeof header.Name) == 0) {
					/*
					 * 7.5. Longnames Member
					 * The name of the longnames member is "\\". The longnames member is a series of strings of archive member names. A name appears here only when there is insufficient room in the Name field (16 bytes). The longnames member can be empty, though its header must appear.
					 *
					 * The strings are null-terminated. Each string begins immediately after the null byte in the previous string.
					 */
					longnames = buf;
				} else { // regular member
					char *memname(reinterpret_cast<char *>(header.Name));
					if (header.Name[0] == '/')
						memname = static_cast<char *>(longnames.get()) +
							strtoul(reinterpret_cast<const char *>(&header.Name[1]), 0, 10); // name is longname
					else
						for (int ndx = sizeof header.Name - 1; ndx >= 0; --ndx)
							if (*(memname + ndx) == '/') {
								*(memname + ndx) = 0;
								break;
							}
					/*
					 * 8. Import Library Format
					 * Traditional import libraries, i.e., libraries that describe the symbols from one image for use by another, typically follow the layout described in 7. Archive (Library) File Format. The primary difference is that import library members contain pseudo-object files instead of real ones, where each member includes the section contributions needed to build the Import Tables described in Section 6.4 The .idata Section. The linker generates this archive while building the exporting application.
					 *
					 * The section contributions for an import can be inferred from a small set of information. The linker can either generate the complete, verbose information into the import library for each member at the time of the library's creation, or it can write only the canonical information to the library and let the application that later uses it generate the necessary data on-the-fly.
					 *
					 * In an import library with the long format, a single member contains the following information:
					 *
					 * Archive member header
					 * File header
					 * Section headers
					 * Data corresponding to each of the section headers
					 * COFF symbol table
					 * Strings
					 *
					 * In contrast a short import library is written as follows:
					 *
					 * Archive member header
					 * Import header
					 * Null-terminated import name string
					 * Null-terminated DLL name string
					 *
					 * This is sufficient information to accurately reconstruct the entire contents of the member at the time of its use.
					 */
					if (static_cast<IMPORT_OBJECT_HEADER *>(buf.get())->Sig1 == IMAGE_FILE_MACHINE_UNKNOWN
						&& static_cast<IMPORT_OBJECT_HEADER *>(buf.get())->Sig2 == IMPORT_OBJECT_HDR_SIG2) {
						/*
						 * 8.1. Import Header
						 * The import header contains the following fields and offsets:
						 *
						 * Offset Size    Field Description
						 *  0      2      Sig1 Must be IMAGE_FILE_MACHINE_UNKNOWN. See Section 3.3.1, "Machine Types, " for more information.
						 *  2      2      Sig2 Must be 0xFFFF.
						 *  4      2      Version
						 *  6      2      Machine Number identifying type of target machine. See Section 3.3.1, "Machine Types, " for more information.
						 *  8      4      Time-Date Stamp Time and date the file was created.
						 * 12      4      Size Of Data Size of the strings following the header.
						 * 16      2      Ordinal/Hint Either the ordinal or the hint for the import, determined by the value in the Name Type field.
						 * 18      2 bits Type The import type. See Section 8.2 Import Type for specific values and descriptions.
						 *         3 bits Name Type The Import Name Type. See Section 8.3. Import Name Type for specific values and descriptions.
						 *        11 bits Reserved Reserved. Must be zero.
						 *
						 * This structure is followed by two null-terminated strings describing the imported symbol's name, and the DLL from which it came.
						 */
						const IMPORT_OBJECT_HEADER *imphdr(static_cast<IMPORT_OBJECT_HEADER *>(buf.get()));
						const char *impname(reinterpret_cast<const char *>(imphdr + 1)),
							*modname(impname + strlen(impname) + 1);
						/*
						if ((category != 1 || imphdr->Type == IMPORT_OBJECT_CODE)
								&& (category != 2 || imphdr->Type != IMPORT_OBJECT_CODE))
						*/
						{
							/*
							 * 8.2. Import Type
							 * The following values are defined for the Type field in the Import Header:
							 *
							 * Constant Value Description
							 * IMPORT_CODE 0 The import is executable code.
							 * IMPORT_DATA 1 The import is data.
							 * IMPORT_CONST 2 The import was specified as CONST in the .def file.
							 *
							 * These values are used to determine which section contributions must be generated by the tool using the library if it must access that data.
							 */
							/*
							 * 8.3. Import Name Type
							 * The null-terminated import symbol name immediately follows its associated Import Header. The following values are defined for the Name Type field in the Import Header, indicating how the name is to be used to generate the correct symbols representing the import:
							 *
							 * Constant Value Description
							 * IMPORT_OBJECT_ORDINAL 0 The import is by ordinal. This indicates that the value in the Ordinal/Hint field of the Import Header is the import's ordinal. If this constant is not specified, then the Ordinal/Hint field should always be interpreted as the import's hint.
							 * IMPORT_OBJECT_NAME 1 The import name is identical to the public symbol name.
							 * IMPORT_OBJECT_NAME_NOPREFIX 2 The import name is the public symbol name, but skipping the leading ?, @, or optionally _.
							 * IMPORT_OBJECT_NAME_UNDECORATE 3 The import name is the public symbol name, but skipping the leading ?, @, or optionally _, and truncating at the first @.
							 */
							if (symbols.insert(impname, modname,
								static_cast<IMPORT_OBJECT_TYPE>(imphdr->Type),
								static_cast<IMPORT_OBJECT_NAME_TYPE>(imphdr->NameType))) ++result;
						} // area accepted
					} else { // std header
						PIMAGE_FILE_HEADER const hdr(reinterpret_cast<PIMAGE_FILE_HEADER>(buf.get()));
						PIMAGE_SECTION_HEADER const sections(reinterpret_cast<PIMAGE_SECTION_HEADER>
							((LPBYTE)(hdr + 1) + hdr->SizeOfOptionalHeader));
						PIMAGE_SYMBOL const symboltable(reinterpret_cast<PIMAGE_SYMBOL>
							((LPBYTE)buf.get() + hdr->PointerToSymbolTable));
						const char *const stringtable(reinterpret_cast<const char *>
							(symboltable + hdr->NumberOfSymbols));
						for (DWORD iter = 0; iter < hdr->NumberOfSymbols; ++iter) {
							if ((category != 1 || symboltable[iter].Type == 0x20)
								&& (category != 2 || symboltable[iter].Type != 0x20)) {
								const char *const expname(symboltable[iter].N.Name.Short == 0 ?
									stringtable + symboltable[iter].N.Name.Long :
									reinterpret_cast<const char *>(symboltable[iter].N.ShortName));
								_ASSERTE(*expname != 0); // must not be empty
								if (symboltable[iter].SectionNumber > 0
									&& symboltable[iter].StorageClass == IMAGE_SYM_CLASS_EXTERNAL
									&& symbols.insert(expname, memname, symboltable[iter].Type == 0x20 ?
									IMPORT_OBJECT_CODE : IMPORT_OBJECT_DATA)) ++result;
							} // area accepted
							iter += symboltable[iter].NumberOfAuxSymbols; // skip them...
						} // iterate symbols of object file
					} // std header
				} // regular member
			} // walk the file
		} else if (!is.fail() && (recId == 0xF0 || recId == 0x80)) {
			// OMF lib or object
			cmsg << "omf format possible...";
			char translator[0x100], library[0x100], modname[0x100], verstr[0x100],
				implements[0x100];
			translator[0] = 0;
			library[0] = 0;
			modname[0] = 0;
			verstr[0] = 0;
			implements[0] = 0;
			uint chsgood(0), reccnt(0), verbase(0), vendor(0), version(0);
			uint32 dictoffset(0), loadflags(0);
			uint16 pagesize(0), dictlen(0);
			uint8 dictflags(0), loadbyte(0);
			bool seg_use32(false);
#define recsize reinterpret_cast<uint16 *>(&sig[1])
			is.seekg(1);
			while (is.good()) {
#ifdef _DEBUG
				const streamoff recoff(is.tellg() - static_cast<streamoff>(1));
#endif // _DEBUG
				if (is.read(sig, 2).eof()) break;
				if (!is) throw logic_error("error reading from file");
				buf.reset(*recsize);
				if (!buf) {
					_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new block of size 0x%hX\n",
						__FUNCTION__, *recsize);
					throw bad_alloc();
				}
				if (!is.read(static_cast<char *>(buf.get()), *recsize).good())
					throw logic_error("error reading from file");
				++reccnt;
				/*
				 * The Checksum field is a 1-byte field that contains the negative sum (modulo 256) of all other bytes in the record.
				 * In other words, the checksum byte is calculated so that the low-order byte of the sum of all the bytes in the
				 * record, including the checksum byte, equals 0. Overflow is ignored. Some compilers write a 0 byte rather than
				 * computing the checksum, so either form should be accepted by programs that process object modules.
				 */
				if ((recId & ~1) != 0xF0 /* exclude F0H and F1H records */
					&& *(static_cast<uint8 *>(buf.get()) + *recsize - 1) /* checksum byte must be set */) { // care checksum
					uint8 realsum(0);
					// TODO Borland omf scheme specific
					for (uint16 cntr = 0; cntr < 3; ++cntr)
						realsum += static_cast<uint8>(sig[cntr]);
					for (cntr = 0; cntr < *recsize; ++cntr)
						realsum += *(static_cast<uint8 *>(buf.get()) + cntr);
					if (realsum == 0)
						++chsgood; // ok
					else {
						_RPTF1(_CRT_WARN, "%swrong checksum in omf library:\n", prefix);
						_RPTF1(_CRT_WARN, "  record offset=0x%I64X\n", recoff);
						_RPTF1(_CRT_WARN, "  record type=%02X\n", recId);
						_RPTF1(_CRT_WARN, "  record size=%04hX\n", *recsize);
							_RPTF2(_CRT_WARN, "  current/stored checksum: %02X/%02X\n", realsum,
							*(static_cast<uint8 *>(buf.get()) + *recsize - 1));
						if (chsbad++ == 0 && omf_carechecksums && result == 0
							&& MessageBox(hwndDlg, "wrong checksum - continue scanning?",
								"libnames matching", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES)
							if (reccnt == 1) goto coffobj; else throw fmt_exception("wrong checksum");
					}
				} // care checksum
				switch (recId) {
					case 0x80: // 80H THEADR-Translator Header Record
						qstrncpy(translator, reinterpret_cast<const char *>
							(static_cast<int8 *>(buf.get()) + 1),
							*static_cast<uint8 *>(buf.get()) + 1);
						break;
					case 0x82: // 82H LHEADR-Library Module Header Record
						qstrncpy(library, reinterpret_cast<const char *>
							(static_cast<int8 *>(buf.get()) + 1),
							*static_cast<uint8 *>(buf.get()) + 1);
						break;
					case 0x88: { // 88H COMENT-Comment Record
						const uint8
							cmttype(*static_cast<uint8 *>(buf.get())), // comment type
							cmtcls(*(static_cast<uint8 *>(buf.get()) + 1)), // comment class
							cmtsubtype(*(static_cast<uint8 *>(buf.get()) + 2));
						switch (cmtcls) {
							case 0x00:
								// 000010 COMENT  Purge: No , List: Yes, Class: 0   (000h)
								//     Translator: Delphi Pascal V17.0
								break;
							case 0xA0: // OMF extensions
								switch (cmtsubtype) {
									case 0x01: { // 88H IMPDEF-Import Definition Record (Comment Class A0, Subtype 01)
										const uint8 impbyord(*(static_cast<uint8 *>(buf.get()) + 3));
										char impname[MAXNAMESIZE], dllname[QMAXPATH];
										qstrncpy(impname, reinterpret_cast<const char *>
											(static_cast<int8 *>(buf.get()) + 5),
											*(static_cast<uint8 *>(buf.get()) + 4) + 1);
										uint8 *tmp(static_cast<uint8 *>(buf.get()) +
											5 + *(static_cast<uint8 *>(buf.get()) + 4));
										qstrncpy(dllname, reinterpret_cast<const char *>(tmp + 1), *tmp + 1);
										if (symbols.insert(impname, dllname)) ++result;
										break;
									} // IMPDEF
								} // switch cmtsubtype
								break;
							case 0xA3: // 88H LIBMOD-Library Module Name Record (Comment Class A3)
								qstrncpy(modname, reinterpret_cast<const char *>
									(static_cast<int8 *>(buf.get()) + 2),
									*(static_cast<uint8 *>(buf.get()) + 1) + 1);
								break;
							case 0xFB: {
								switch (cmtsubtype) {
									case 0x08:
										// 000048 COMENT  Purge: No , List: Yes, Class: 251 (0FBh), SubClass: 8 (08h)
										//     Link: ComObj.obj
										char link[0x100];
										qstrncpy(link, reinterpret_cast<const char *>
											(static_cast<int8 *>(buf.get()) + 3),
											*(static_cast<uint8 *>(buf.get()) + 3) + 1);
										break;
									case 0x0A:
										// 000035 COMENT  Purge: No , List: Yes, Class: 251 (0FBh), SubClass: 10 (0Ah)
										//     Implements: OWC10XP.obj
										qstrncpy(implements, reinterpret_cast<const char *>
											(static_cast<int8 *>(buf.get()) + 3),
											*(static_cast<uint8 *>(buf.get()) + 3) + 1);
										break;
									case 0x0C:
										// 00002A COMENT  Purge: Yes, List: Yes, Class: 251 (0FBh), SubClass: 12 (0Ch)
										//     Package Module Record, Lead Byte: 01h, Flags: 00004000h
										loadbyte = *(static_cast<uint8 *>(buf.get()) + 3);
										loadflags = *(static_cast<uint32 *>(buf.get()) + 1);
										break;
								} // switch cmtsubtype
								break;
							}
						} // switch cmtcls
						break;
					}
					case 0x8A:
					case 0x8B: { // 8AH or 8BH MODEND-Module End Record
						const uint8 modtype(*static_cast<uint8 *>(buf.get()));
						//translator[0] = 0;
						modname[0] = 0; // ???
						implements[0] = 0;
						break;
					}
					case 0x8C: { // 8CH EXTDEF-External Names Definition Record
						/*
						uint16 pos(0);
						while (pos + 1 < *recsize && *((int8 *)buf.get() + pos) != 0) {
							char name[MAXNAMESIZE];
							qstrncpy(name, (char *)((int8 *)buf.get() + pos + 1),
								*((uint8 *)buf.get() + pos) + 1);
							if (symbols.insert(name, modname)) ++result;
							pos += *((uint8 *)buf.get() + pos) + 2;
						}
						*/
						break;
					}
					case 0x90:
					case 0x91: { // 90H or 91H PUBDEF-Public Names Definition Record
						uint16 basegrpindex, basesegindex, pos(0), baseframe;
						uint8 offsize;
						char name[MAXNAMESIZE];
						basegrpindex = omf_readindex(buf.get(), pos);
						basesegindex = omf_readindex(buf.get(), pos);
						if (basegrpindex == 0 && basesegindex == 0) {
							baseframe = *reinterpret_cast<uint16 *>
								(static_cast<uint8 *>(buf.get()) + pos);
							pos += 2;
						}
						offsize = 2 << static_cast<uint8>(recId == 0x91 || seg_use32);
						while (pos + 1 < *recsize) {
							const uint8 len(*(static_cast<uint8 *>(buf.get()) + pos));
							qstrncpy(name, reinterpret_cast<const char *>
								(static_cast<int8 *>(buf.get()) + pos + 1), len + 1);
							if (symbols.insert(name, modname)) ++result; // no typeinfo available
							pos += 1 + len;
							const uint32 offset(offsize == 2 ?
								*reinterpret_cast<uint16 *>(static_cast<int8 *>(buf.get()) + pos) :
								*reinterpret_cast<uint32 *>(static_cast<int8 *>(buf.get()) + pos));
							pos += offsize;
							uint16 type(omf_readindex(buf.get(), pos));
						} // walk pubnames
						break;
					}
					case 0x98:
					case 0x99: // 98H or 99H SEGDEF-Segment Definition Record
						seg_use32 = *static_cast<uint8 *>(buf.get()) & 1;
						break;
					case 0xB0: { // B0H COMDEF-Communal Names Definition Record
						uint16 pos(0);
						while (pos + 1 < *recsize && *(static_cast<int8 *>(buf.get()) + pos)) {
							char name[MAXNAMESIZE];
							qstrncpy(name,
								reinterpret_cast<const char *>(static_cast<int8 *>(buf.get()) + pos + 1),
								*(static_cast<uint8 *>(buf.get()) + pos) + 1);
							if (symbols.insert(name, modname)) ++result;
							pos += *(static_cast<uint8 *>(buf.get()) + pos) + 1;
							const uint16 typindex(omf_readindex(buf.get(), pos));
							const uint8
								datatype(*(static_cast<uint8 *>(buf.get()) + pos++));
							uint32 value;
							if (datatype >= 1 && datatype <= 0x5F || datatype == 0x62) // NEAR
								value = omf_readvarvalue(buf.get(), pos);
							else if (datatype == 0x61) { // FAR
								value = omf_readvarvalue(buf.get(), pos);
								value = omf_readvarvalue(buf.get(), pos);
							}
						} // walk comdefs
						break;
					}
					case 0xCC: // CCH VERNUM - OMF Version Number Record
						qstrncpy(verstr,
							reinterpret_cast<const char *>(static_cast<int8 *>(buf.get()) + 1),
							*static_cast<uint8 *>(buf.get()));
						qsscanf("%u.%u.%u", verstr, verbase, vendor, version);
						break;
					case 0xF0: // Library Header Record
						pagesize = *recsize + 3;
						dictoffset = *static_cast<uint32 *>(buf.get());
						dictlen = *(static_cast<uint16 *>(buf.get()) + 2);
						dictflags = *(static_cast<uint8 *>(buf.get()) + 6);
						break;
					case 0xF1: // Library End Record, quit parsing
						is.setstate(ios_base::eofbit);
				} // switch recId
				// skip leading zeros to next paragraph alignment
				while (is.good()) {
					if (is.read(sig, 1).eof()) break;
					if (!is) throw logic_error("error reading from file");
					if (sig[0] != 0) break;
				}
			} // walk the file
			/*
			if (dictoffset && dictlen) {
				// process dictionary, if possible
				size_t dictsize(dictlen << 9);
				if ((bool)buf.reset(0x200) && is.seekg(dictoffset).good()) {
					int8 (*HTAB)[1] = (int8 (*)[1])buf.get();
					int8 *FFLAG = (int8 *)buf.get() + 37;
					for (uint16 iter = 0; iter < dictlen; ++iter) {
						if (!is.read(buf.get(), 0x200)) throw fmt_exception("error reading from file '%s'", libpath);
						uint16 pos(38);
						char name[MAXNAMESIZE];
						while (pos < 0x200 && *((int8 *)buf.get() + pos) != 0) {
							qstrncpy(name, (char *)((int8 *)buf.get() + pos + 1),
								*((uint8 *)buf.get() + pos) + 1);
							if (symbols.insert(name)) ++result; // no typeinfo available
							pos += 1 + *((uint8 *)buf.get() + pos);
							uint16 *blocknumber = (uint16 *)((int8 *)buf.get() + pos);
							pos += 2 + ??? + (pos & 1); // Borland specific!!!
						} // walk symbols
					} // walk pages
				} // ready to read
			} // process dictionary
			*/
		} else if (!is.fail()) { // COFF object file - guessed
		coffobj:
			if (!is.seekg(0)) throw logic_error("not of a known format");
			cmsg << "trying as coff object format...";
			size_t const size(is.rdbuf()->in_avail());
			if (size == 0) throw logic_error("not of a known format");
			buf.reset(size);
			if (!buf) {
				_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new block of size 0x%IX\n",
					__FUNCTION__, size);
				throw bad_alloc();
			}
			if (!is.read(static_cast<char *>(buf.get()), size).good())
				throw fmt_exception("cannot read file content (%s bytes)", size);
			PIMAGE_FILE_HEADER const hdr(reinterpret_cast<PIMAGE_FILE_HEADER>(buf.get()));
			PIMAGE_SECTION_HEADER const sections(reinterpret_cast<PIMAGE_SECTION_HEADER>
				((LPBYTE)(hdr + 1) + hdr->SizeOfOptionalHeader));
			PIMAGE_SYMBOL const symboltable(reinterpret_cast<PIMAGE_SYMBOL>
				((LPBYTE)buf.get() + hdr->PointerToSymbolTable));
			qstrcat(name, ext);
			const char *const stringtable(reinterpret_cast<const char *>
				(symboltable + hdr->NumberOfSymbols));
			for (DWORD iter = 0; iter < hdr->NumberOfSymbols; ++iter) {
				if ((category != 1 || symboltable[iter].Type == 0x20)
					&& (category != 2 || symboltable[iter].Type != 0x20)) {
					char symname[MAXNAMESIZE];
					if (symboltable[iter].N.Name.Short == 0)
						qstrcpy(symname, stringtable + symboltable[iter].N.Name.Long);
					else
						qstrcpy(symname, reinterpret_cast<const char *>(symboltable[iter].N.ShortName));
					_ASSERTE(symname[0] != 0);
					if (symboltable[iter].SectionNumber > 0
						&& symboltable[iter].StorageClass == IMAGE_SYM_CLASS_EXTERNAL
						&& symbols.insert(symname, name, symboltable[iter].Type == 0x20 ?
						IMPORT_OBJECT_CODE : IMPORT_OBJECT_DATA)) ++result;
				} // area accepted
				iter += symboltable[iter].NumberOfAuxSymbols; // skip them...
			} // iterate symbols of object file
		} // coff object - heuristic
	} catch (const exception &e) {
		/*if (!is.eof()) */cmsg << "failed: " << e.what() << "...";
	}
	if (result == 0)
		cmsg << "done: couldnot retrieve any names" << endl;
	else {
		cmsg << "done: " << dec << result << " names";
		if (chsbad > 0) cmsg << " (" << dec << chsbad << " bad checksums)";
		cmsg << endl;
	}
	return result;
}

uint16 omf_readindex(const void *record, uint16 &index) {
	return (*(static_cast<const uint8 *>(record) + index) & 0x80) != 0 ?
		((*(static_cast<const uint8 *>(record) + index++) & 0x7F) << 8) +
			*(static_cast<const uint8 *>(record) + index++) :
		*(static_cast<const uint8 *>(record) + index++);
}

uint32 omf_readvarvalue(const void *record, uint16 &index) {
	uint32 value(*(static_cast<const uint8 *>(record) + index++));
	switch (value) {
		case 0x81:
			value = *reinterpret_cast<const uint32 *>(static_cast<const uint8 *>(record) + index);
			index += 2;
			break;
		case 0x84:
			value = *reinterpret_cast<const uint32 *>
				(static_cast<const uint8 *>(record) + index) & 0xFFFFFF;
			index += 3;
			break;
		case 0x88:
			value = *reinterpret_cast<const uint32 *>(static_cast<const uint8 *>(record) + index);
			index += 4;
			break;
#ifdef _DEBUG
		default:
			_RPT3(_CRT_WARN, "%s(..., %hu): unexpected var value index (0x%I32X)\n",
				__FUNCTION__, index - 1, value);
#endif // _DEBUG
	}
	return value;
}

bool symbols_t::insert(const char *name, const char *module,
	IMPORT_OBJECT_TYPE area, IMPORT_OBJECT_NAME_TYPE nametype) {
	_ASSERTE(name != 0 && *name != 0);
	if (name == 0 || *name == 0) return false;
	if (strlen(name) >= MAXNAMESIZE) {
#ifdef _DEBUG
	_CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
		"%s(\"%s\", \"%s\", %i, %i): symbol name too long(%Iu) to match idabase (not added to lookup table)\n",
			__FUNCTION__, name, module, area, nametype, strlen(name));
#endif // _DEBUG
		return false;
	}
	bool inserted;
	try {
		inserted = __super::insert(symbol_t(name, module, area, nametype)).second;
#ifdef _DEBUG
		if (!inserted) _CrtDbgReport(_CRT_WARN, NULL, 0, NULL,
			"%s(\"%s\", \"%s\", %i, %i): tried to insert duplicate name\n",
			__FUNCTION__, name, module, area, nametype);
#endif // _DEBUG
	} catch (const exception &e) {
		inserted = false;
		cmsg << prefix << __FUNCTION__ << "(...): " << e.what() << endl;
		_RPT2(_CRT_WARN, "%s(...): %s\n", __FUNCTION__, e.what());
	}
	return inserted;
}

symbols_t::const_iterator symbols_t::find(const char *name) const {
	const_iterator i(end());
	_ASSERTE(name != 0 && *name != 0);
	if (name != 0 && *name != 0 && (!fast_match || (i = __super::find(name)) == end())) {
		PCRE::regexp::result match[2] = { PCRE::regexp::result(regex[8], name), };
#define NameMatch(idaindex, libindex) \
	(match[0](idaindex) == match[1](libindex) \
	&& strcmp(match[0][idaindex], match[1][libindex]) == 0)
		for (i = begin(); i != end(); ++i) {
			_ASSERTE(!i->name.empty());
			if (!i->name.empty() && (i->name == name || match[0] >= 4
				&& match[1](regex[8], i->name) >= 4 && (NameMatch(1, 1)
				|| (i->nametype == -1 || i->nametype == IMPORT_OBJECT_NAME_NO_PREFIX)
				&& (NameMatch(2, 1) || NameMatch(2, 2) || NameMatch(1, 2))
				|| (i->nametype == -1 || i->nametype == IMPORT_OBJECT_NAME_UNDECORATE)
				&& (NameMatch(3, 1) || NameMatch(3, 3) || NameMatch(1, 3))))) break;
		}
#undef NameMatch
	}
	return i;
}

symbols_t::const_iterator symbols_t::find_root(const char *name,
	IMPORT_OBJECT_TYPE area) const {
	_ASSERTE(name != 0 && *name != 0);
	if (name != 0 && *name != 0) {
		int (__cdecl *STRCMP)(const char *, const char *) = nocase ? _stricmp : strcmp;
		int (__cdecl *STRNCMP)(const char *, const char *, size_t) = nocase ? _strnicmp : strncmp;
#define OVECSIZE   3 * 11   // 10 subpatterns is default
#define pcre_match(index1, string, index2) (match[index2] = \
	regex[index1](string, ovector[index2], OVECSIZE))
#define pcre_substrsize(index1, index2) (ovector[index1][2 * index2 + 1] - \
	ovector[index1][2 * index2])
#define pcre_hassubstr(index1, index2) (match[index1] > index2 \
	&& ovector[index1][2 * index2] != -1 && ovector[index1][2 * index2 + 1] != -1 \
	&& pcre_substrsize(index1, index2) > 0)
#define pcre_matchsubstr(index1, index2) (pcre_substrsize(0, index1) == \
	pcre_substrsize(1, index2) && STRNCMP(name + ovector[0][2 * index1], \
	pubsym->name.c_str() + ovector[1][2 * index2], pcre_substrsize(0, index1)) == 0)
		int match[2], ovector[2][OVECSIZE];
		for (uint16 i = 0; i < 8; ++i)
			if (pcre_match(i, name, 0) > 0) break;
#ifdef _DEBUG
		if (i > 8) _RPT2(_CRT_WARN, "%s(\"%s\", ...): name didnot pass any regular expression",
				__FUNCTION__, name);
#endif // _DEBUG
		for (const_iterator pubsym = begin(); pubsym != end(); ++pubsym)
			if ((mix_type || pubsym->area_match(area)) && !pubsym->name.empty()) {
				//_ASSERTE(!pubsym->name.empty());
				if (STRCMP(pubsym->name.c_str(), name) == 0) return pubsym; // only caseless match
				switch (i) {
					case bcppproc: // @Graphics@TBitmap@CopyImage$qqruiuirx13tagDIBSECTION (Borland C++ function)
						// \1 : @Unit@AllObjects@Func
						// \2 : @Object@Func
						// \3 : @Object
						// \4 : Func
						// \5 : @$operator
						// \6 : $mangling
						if (match[0] > 2 && pcre_match(i, pubsym->name.c_str(), 1) > 2
							&& pcre_matchsubstr(2, 2)) return pubsym;
						break;
					case bcpptype: // @$xp$14System@Boolean (Borland C++ type)
						// \1 : Length
						// \2 : Var
						if (match[0] > 2 && pubsym->name.compare(0, 5, name) == 0
							&& pcre_match(i, pubsym->name.c_str(), 1) > 2
							&& pcre_matchsubstr(2, 2)) return pubsym;
						break;
					case bcppclass: // @Graphics@TBitmap@ (Borland C++ object)
						// \0 : @Unit@Object@
						// \1 : @Unit
						// \2 : @AllObjects
						// \3 : @ThisObject
						if (match[0] > 3 && pcre_match(i, pubsym->name.c_str(), 1) > 3
							&& pcre_matchsubstr(3, 3)) return pubsym;
						break;
					case bcppdata: // @Forms@Application (Borland C++ variable)
					case bcppconst: // @Forms@_Screen (Borland C++ constant)
						// \1 : Unit
						// \2 : @AllObjects@Var
						// \3 : @AllObjects
						// \4 : @LastObject
						// \5 : Var
						if (match[0] > 2 && pcre_match(i, pubsym->name.c_str(), 1) > 2
							&& pcre_matchsubstr(2, 2)) return pubsym;
						break;
					case vcppproc: // ?MyFunc@MyClass@@QAEHPAD@Z (Microsoft C++ function)
						// \1 : nonstd. prefix (???)
						// \2 : Func@Class(es)
						// \3 : Func
						// \4 : Class(es)
						// \5 : type
						// \6 : @arglist
						if (match[0] > 1 && (pcre_match(i, pubsym->name.c_str(), 1) > 1
							&& pcre_matchsubstr(1, 1) && (!pcre_hassubstr(0, 4)
							&& !pcre_hassubstr(1, 4) || pcre_hassubstr(0, 4)
							&& pcre_hassubstr(1, 4) && pcre_matchsubstr(4, 4))
							&& !pcre_hassubstr(0, 4) && pcre_match(vcanyname, pubsym->name.c_str(), 1) > 2
							&& pcre_matchsubstr(1, 2))) return pubsym;
						break;
					case vcppdata: // ?MyClass@@3VMyCppClass@@A (Microsoft C++ variable)
						// \1 : ThisVar
						// \2 : type
						// \3 : @AllOwnerClasses@@mangling
						// \4 : @LastOwnerClass
						if (match[0] > 1 && !pcre_hassubstr(0, 3)
							&& (pcre_match(i, pubsym->name.c_str(), 1) > 1 && !pcre_hassubstr(1, 3)
							&& pcre_matchsubstr(1, 1) || pcre_match(vcanyname, pubsym->name.c_str(), 1) > 2
							&& pcre_matchsubstr(1, 2))) return pubsym;
						break;
					case vcanyname: // _GetModuleHandleA@4 (Microsoft C any name)
						// \1 : import prefix (optional)
						// \2 : Name
						// \3 : argsize (optional)
						if (match[0] > 2 && pcre_match(i, pubsym->name.c_str(), 1) > 2
							&& pcre_matchsubstr(2, 2)
							|| pcre_match(vcppproc, pubsym->name.c_str(), 1) > 1 // care: C/C++ linkage change!
							&& !pcre_hassubstr(1, 4) && pcre_matchsubstr(2, 1)
							|| pcre_match(vcppdata, pubsym->name.c_str(), 1) > 1 // care: C/C++ linkage change!
							&& !pcre_hassubstr(1, 3) && pcre_matchsubstr(2, 1)) return pubsym;
						break;
				} //switch statement
			} // type match
	} // name != 0 && *name != 0
	return end();
}

UINT AddLib(HWND hwndDlg, const char *fullpath) {
	_ASSERTE(fullpath != 0);
	_ASSERTE(_CrtIsValidPointer(fullpath, 1, 0));
	if (fullpath == 0 || IsBadReadPtr(fullpath, 1) || !qfileexist(fullpath))
		return LB_ERR;
	const UINT cntr(SendDlgItemMessage(hwndDlg, IDC_USERLIBS, LB_GETCOUNT, 0, 0));
	char *chtmp;
	if (cntr != LB_ERR) for (UINT tmp = 0; tmp < cntr; ++tmp)
		if ((chtmp = reinterpret_cast<char *>(SendDlgItemMessage(hwndDlg, IDC_USERLIBS,
			LB_GETITEMDATA, (WPARAM)tmp, 0))) != reinterpret_cast<char *>(LB_ERR)
			&& _stricmp(chtmp, fullpath) == 0) return LB_ERR; // no dupes!
	const UINT nItem(SendDlgItemMessage(hwndDlg, IDC_USERLIBS,
		LB_ADDFILE/*LB_ADDSTRING*/, 0, reinterpret_cast<LPARAM>(fullpath)));
	if (nItem != LB_ERR) {
		const size_t sz(strlen(fullpath) + 1);
		if ((chtmp = new char[sz]) != 0)
			SendDlgItemMessage(hwndDlg, IDC_USERLIBS, LB_SETITEMDATA,
				(WPARAM)nItem, reinterpret_cast<LPARAM>(qstrncpy(chtmp, fullpath, sz)));
#ifdef _DEBUG
		else
			_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new string of size 0x%IX\n",
				__FUNCTION__, sz);
#endif // _DEBUG
	}
	return nItem;
}

INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	static CFileGroups::filegroups_t file_groups;
	static HMENU hAddMenu;
	OPENFILENAME ofn;
	UINT cntr;
	switch (uMsg) {
		case WM_INITDIALOG: {
			netnode lnm("$ lnm"); // ???
			category = GetPrivateProfileInt(cfgsection, "category", 1, inipath);
			CheckDlgButton(hwndDlg, IDC_FUNCTIONS, category == 1);
			CheckDlgButton(hwndDlg, IDC_VARS, category == 2);
			CheckDlgButton(hwndDlg, IDC_ALL, category == 3);
			CheckDlgButton(hwndDlg, IDC_IGNORESECTION, GetPrivateProfileInt(cfgsection, "mix_type", false, inipath));
			CheckDlgButton(hwndDlg, IDC_ALLSEGS, GetPrivateProfileInt(cfgsection, "any_segment", false, inipath));
			CheckDlgButton(hwndDlg, IDC_UNNAMENOMATCH, GetPrivateProfileInt(cfgsection, "unname_nomatch", false, inipath));
			CheckDlgButton(hwndDlg, IDC_FIXMANGLING, GetPrivateProfileInt(cfgsection, "fix_mangling", false, inipath));
			CheckDlgButton(hwndDlg, IDC_CASELESS, GetPrivateProfileInt(cfgsection, "nocase", false, inipath));
			EnableDlgItem(hwndDlg, IDC_CASELESS, IsDlgButtonChecked(hwndDlg, IDC_FIXMANGLING));
			CheckDlgButton(hwndDlg, IDC_COLLAPSEMATCHING, GetPrivateProfileInt(cfgsection, "collapse_matching", true, inipath));
			CheckDlgButton(hwndDlg, IDC_FASTMATCH, GetPrivateProfileInt(cfgsection, "fast_match", false, inipath));
			omf_carechecksums = GetPrivateProfileInt(cfgsection, "omf_carechecksums", true, inipath);
			quiet = GetPrivateProfileInt(cfgsection, "quiet", false, inipath);
			verbose = GetPrivateProfileInt(cfgsection, "verbose", false, inipath);
			netnode lnmnode(LNM_NODE);
			if (lnmnode != BADNODE) for (nodeidx_t ndx = lnmnode.sup1st(); ndx != BADNODE; ndx = lnmnode.supnxt(ndx)) {
				char fname[MAXSPECSIZE];
				if (lnmnode.supstr(ndx, CPY(fname)) > 0) AddLib(hwndDlg, fname);
			}
			EnableDlgItem(hwndDlg, IDREMOVE, SendDlgItemMessage(hwndDlg,
				IDC_USERLIBS, LB_GETSELCOUNT, 0, 0) > 0);
			static const tooltip_item_t tooltips[] = {
				//IDC_FUNCTIONS, "Compare only code names",
				//IDC_VARS, "Compare only data names",
				//IDC_ALL, "Compare all names",
				IDC_IGNORESECTION, "The comparison engine cares of name types, ie. names prepending instruction are only matched to names marked as code in library and vice versa about data names. Type sensitivity is off if input format doesnot support type classification or this option is checked. Usage for dummy libraries deklaring everything public as code (eg. implibs made of autogenerated .def files).",
				IDC_ALLSEGS, "Process any segment type, i.e. externals, resource (segments with special meaning are normally skipped).",
				IDC_UNNAMENOMATCH, "Kill unmatched library names (applies to code and data names). Names are deleted comlpetely for items without x-refs (otherwise converted to dummy). Useful to re-virgin FLAIR false-matched sequences so that related locations can be processed again by another signature(s).",
				IDC_FIXMANGLING, "[EXPERIMENTAL] Use this feature only on own risk as it's very slow (no fundamental method was adapted to find safe find alternate to unmatched name) - its always better to use version-specific signatures for that SDK. Reviewing list of changed names is highly advised.",
				IDC_CASELESS, "Use case-insensitive method for lookup. Use this option if functions in IDAbase may have incorrect case.",
				IDC_COLLAPSEMATCHING, "Collapse (ie. hide) functions and data not found in libraries",
				IDC_FASTMATCH, "[EXPERIMENTAL] Alternate lookup method gives the same result but enables hashed pre-lookup, which may increase or decrease overall job duration in dependence on library names usage (thus alternate method might be recommended if library code participation is relatively high). Alternate method can only boost for names in exactly same form as published by library (ie. no mangling adjustments).",
				IDC_USERLIBS, "Put all available libraries for used compiler and SDK here. Be sure to use the right version - the names or types may differ between versions.",
				IDEDITGROUPS, "Manage common file groups",
			};
			const HWND hwndTT(CreateWindowEx(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL,
				WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP | TTS_BALLOON, CW_USEDEFAULT, CW_USEDEFAULT,
				CW_USEDEFAULT, CW_USEDEFAULT, hwndDlg, NULL, hInstance, NULL));
			SetWindowPos(hwndTT, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
			SendMessage(hwndTT, TTM_SETMAXTIPWIDTH, 0, (LPARAM)400);
			SendMessage(hwndTT, TTM_SETDELAYTIME, (WPARAM)TTDT_AUTOPOP, (LPARAM)20000);
			TOOLINFO tt;
			memset(&tt, 0, sizeof tt);
			tt.cbSize = sizeof tt;
			tt.uFlags = TTF_SUBCLASS | TTF_IDISHWND | TTF_TRANSPARENT;
			tt.hwnd = hwndDlg;
			tt.hinst = hInstance;
			for (UINT i = 0; i < qnumber(tooltips); ++i) {
				tt.uId = reinterpret_cast<UINT_PTR>(GetDlgItem(hwndDlg, tooltips[i].uID));
				tt.lpszText = const_cast<LPSTR>(tooltips[i].lpText);
				SendMessage(hwndTT, TTM_ADDTOOL, 0, reinterpret_cast<LPARAM>(&tt));
			}
			hAddMenu = NULL;
			if (CFileGroups::Load(file_groups) > 0)
				CFileGroups::CreateAddFilesMenu(hwndDlg, hAddMenu, file_groups, 0x1000);
			RestoreDialogPos(hwndDlg, cfgsection);
			return 1;
		} // WM_INITDIALOG
		case WM_DESTROY:
			cntr = SendDlgItemMessage(hwndDlg, IDC_USERLIBS, LB_GETCOUNT, 0, 0);
			if (cntr != LB_ERR)
				for (UINT tmp = 0; tmp < cntr; ++tmp) {
					char *fullpath(reinterpret_cast<char *>(SendDlgItemMessage(hwndDlg,
						IDC_USERLIBS, LB_GETITEMDATA, (WPARAM)tmp, 0)));
					if (fullpath != reinterpret_cast<char *>(LB_ERR)) delete[] fullpath;
				}
			SaveDialogPos(hwndDlg, cfgsection);
			SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
			CFileGroups::DestroyAddFilesMenu(hAddMenu);
			file_groups.clear();
			return 1;
		case WM_COMMAND: {
			switch (LOWORD(wParam)) {
				case IDOK:
					save_byte(cfgsection, "category", category = IsDlgButtonChecked(hwndDlg, IDC_FUNCTIONS) ? 1 : IsDlgButtonChecked(hwndDlg, IDC_VARS) ? 2 : 3);
					save_bool(cfgsection, "mix_type", mix_type = IsDlgButtonChecked(hwndDlg, IDC_IGNORESECTION));
					save_bool(cfgsection, "any_segment", any_segment = IsDlgButtonChecked(hwndDlg, IDC_ALLSEGS));
					save_bool(cfgsection, "unname_nomatch", unname_nomatch = IsDlgButtonChecked(hwndDlg, IDC_UNNAMENOMATCH));
					save_bool(cfgsection, "nocase", nocase = IsDlgButtonChecked(hwndDlg, IDC_CASELESS));
					save_bool(cfgsection, "fix_mangling", fix_mangling = IsDlgButtonChecked(hwndDlg, IDC_FIXMANGLING));
					save_bool(cfgsection, "collapse_matching", collapse_matching = IsDlgButtonChecked(hwndDlg, IDC_COLLAPSEMATCHING));
					save_bool(cfgsection, "fast_match", fast_match = IsDlgButtonChecked(hwndDlg, IDC_FASTMATCH));
					cntr = SendDlgItemMessage(hwndDlg, IDC_USERLIBS, LB_GETCOUNT, 0, 0);
					if (cntr != LB_ERR) {
						netnode lnmnode(LNM_NODE, 0, true);
						lnmnode.supdel();
						for (UINT tmp = 0; tmp < cntr; ++tmp) {
							char *fullpath(reinterpret_cast<char *>(SendDlgItemMessage(hwndDlg, IDC_USERLIBS,
								LB_GETITEMDATA, (WPARAM)tmp, 0)));
							if (fullpath != reinterpret_cast<char *>(LB_ERR)) {
								AddPublics(fullpath, hwndDlg);
								lnmnode.supset(lnmnode.suplast() + 1, fullpath);
							}
						}
					}
				case IDCANCEL:
					EndDialog(hwndDlg, LOWORD(wParam));
					SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
					break;
				case IDADD:
					if (hAddMenu != NULL) {
						_ASSERTE(!file_groups.empty());
						const POINT anchor(GetCtrlAnchorPoint(hwndDlg, IDADD));
						const UINT nID(TrackPopupMenuEx(hAddMenu, TPM_LEFTALIGN |
							TPM_TOPALIGN | TPM_RETURNCMD | TPM_LEFTBUTTON |
							TPM_VERNEGANIMATION, anchor.x, anchor.y, hwndDlg, NULL));
						if (nID == IDBROWSE)
							SendMessage(hwndDlg, WM_COMMAND, MAKELONG(nID, 0), NULL);
						else if (nID >= 0x1000 && nID < 0x1000 + file_groups.size()) {
							const CFileGroups::filegroups_t::mapped_type &
								group(at(file_groups, nID - 0x1000).second);
							for (CFileGroups::filegroups_t::mapped_type::const_iterator i = group.begin(); i != group.end(); ++i)
								if (qfileexist(*i)) AddLib(hwndDlg, *i);
// 							for_each(CONTAINER_RANGE(group), if_(bind(qfileexist,
// 								bind(&string::c_str, _1)))[bind(AddLib, hwndDlg,
// 									bind(&string::c_str, _1))]);
							EnableDlgItem(hwndDlg, IDREMOVE, SendDlgItemMessage(hwndDlg,
								IDC_USERLIBS, LB_GETSELCOUNT, 0, 0) > 0);
						}
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
						break;
					}
				case IDBROWSE: {
					memset(&ofn, 0, sizeof ofn);
					ofn.lStructSize = sizeof ofn;
					ofn.hInstance = hInstance;
					ofn.hwndOwner = hwndDlg;
					ofn.lpstrTitle = "locate user libraries";
					boost::scoped_array<char> FileName(new char[0x10000]);
					if (!FileName) {
						_RPTF2(_CRT_ERROR, "%s(...): failed to allocate new string of size 0x%X\n",
							__FUNCTION__, 0x10000);
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
						throw bad_alloc(); //break;
					}
					fill_n(FileName.get(), 0x10000, 0);
					ofn.lpstrFile = FileName.get();
					ofn.nMaxFile = 0x10000;
					ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
						OFN_LONGNAMES | OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST |
						OFN_HIDEREADONLY | OFN_ALLOWMULTISELECT;
					ofn.lpstrFilter = "all supported storage formats\0*.lib;*.a;*.exp;*.bpi;*.obj;*.o;*.?ll;*.bpl;*.dpl\0"
						"archives\0*.lib;*.a;*.exp;*.bpi;*.obj;*.o\0executable binaries\0*.?ll;*.bpl;*.dpl\0all files\0*.*\0";
					ofn.nFilterIndex = 1;
					ofn.lpstrDefExt = "lib";
					char drive[_MAX_DRIVE], dir[_MAX_DIR], path[QMAXPATH];
					get_input_file_path(CPY(path));
					_splitpath(path, drive, dir, 0, 0);
					_makepath(path, drive, dir, 0, 0);
					ofn.lpstrInitialDir = path;
					if (GetOpenFileName(&ofn))
						if (ofn.nFileOffset > strlen(ofn.lpstrFile))
							while (*(ofn.lpstrFile + ofn.nFileOffset)) {
								AddLib(hwndDlg, _sprintf("%s\\%s", ofn.lpstrFile,
									ofn.lpstrFile + ofn.nFileOffset).c_str());
								ofn.nFileOffset += strlen(ofn.lpstrFile + ofn.nFileOffset) + 1;
							}
						else
							AddLib(hwndDlg, ofn.lpstrFile);
					EnableDlgItem(hwndDlg, IDREMOVE, SendDlgItemMessage(hwndDlg,
						IDC_USERLIBS, LB_GETSELCOUNT, 0, 0) > 0);
					SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
					break;
				}
				case IDREMOVE:
					cntr = SendDlgItemMessage(hwndDlg, IDC_USERLIBS, LB_GETCOUNT, 0, 0);
					if (cntr != LB_ERR) while (cntr-- > 0)
						if (SendDlgItemMessage(hwndDlg, IDC_USERLIBS, LB_GETSEL, (WPARAM)cntr, 0) > 0) {
							char *fullpath(reinterpret_cast<char *>(SendDlgItemMessage(hwndDlg, IDC_USERLIBS,
								LB_GETITEMDATA, (WPARAM)cntr, 0)));
							if (fullpath != 0) delete[] fullpath;
							SendDlgItemMessage(hwndDlg, IDC_USERLIBS, LB_DELETESTRING,
								(WPARAM)cntr, 0);
						}
					EnableDlgItem(hwndDlg, IDREMOVE, SendDlgItemMessage(hwndDlg,
						IDC_USERLIBS, LB_GETSELCOUNT, 0, 0) > 0);
					SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
					break;
				case IDEDITGROUPS:
					CFileGroups::SetTitle("locate user libraries");
					CFileGroups::SetFilter("all supported storage formats\0"
						"*.lib;*.a;*.exp;*.bpi;*.obj;*.o;*.?ll;*.bpl;*.dpl\0"
						"archives\0*.lib;*.a;*.exp;*.bpi;*.obj;*.o\0executable binaries\0"
						"*.?ll;*.bpl;*.dpl\0all files\0*.*\0");
					CFileGroups::SetFilterIndex(1);
					CFileGroups::SetExtension("lib");
					if (CFileGroups::Manage(hwndDlg, file_groups)) { // OK, save
						CFileGroups::CreateAddFilesMenu(hwndDlg, hAddMenu, file_groups, 0x1000);
						CFileGroups::Save(file_groups);
					}
					SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
					break;
				case IDC_USERLIBS:
					if (HIWORD(wParam) == LBN_SELCHANGE) {
						EnableDlgItem(hwndDlg, IDREMOVE, SendDlgItemMessage(hwndDlg,
							IDC_USERLIBS, LB_GETSELCOUNT, 0, 0) > 0);
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
					}
					break;
				case IDC_FIXMANGLING:
					if (HIWORD(wParam) == BN_CLICKED) {
						EnableDlgItem(hwndDlg, IDC_CASELESS, IsDlgButtonChecked(hwndDlg, IDC_FIXMANGLING));
						SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
					}
					break;
				case IDABOUT:
					/*
					HFONT hFont(CreateFontIndirect(reinterpret_cast<LPLOGFONT>(LoadResource(hInstance,
						FindResource(hInstance, MAKEINTRESOURCE(IDF_CALIGRAPHIC),
						RT_FONT)))));
					*/
					DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_ABOUT), hwndDlg,
						about_dlgproc, (LPARAM)"by _servil_ v" PLUGINVERSIONTEXT " " __DATE__);
					//DeleteObject(reinterpret_cast<HGDIOBJ>(hFont));
					SetWindowLong(hwndDlg, DWL_MSGRESULT, 0);
					break;
			} // switch WM_COMMAND
			return 1;
		} // WM_COMMAND
	} // main switch
	return 0;
}

void clist::GetLine(ulong n, char * const *arrptr) const {
	if (n == 0) { // header
		static const char *const headers[] = {
			"address", "name", "type", "description", "area",
		};
		for (uint i = 0; i < qnumber(headers); ++i)
			qstrncpy(arrptr[i], headers[i], MAXSTR);
	} else { // regular item
		if (n > operator size_t()) return; //_ASSERTE(n <= operator size_t());
		const item_t &item(at(items, n - 1));
		ea2str(item.ea, arrptr[0], MAXSTR); //qsnprintf(arrptr[0], MAXSTR, "%08a", item.ea);
		if (!item.name.empty())
			qstrncpy(arrptr[1], item.name.c_str(), MAXSTR);
		else
			*arrptr[1] = 0; //fill_n(arrptr[1], MAXSTR, 0);
		switch (item.ID) {
			case LNM_RENAMED: qstrncpy(arrptr[2], "renamed to", MAXSTR); break;
			case LNM_ADDLIB: qstrncpy(arrptr[2], "addlibed", MAXSTR); break;
			case LNM_UNLIB: qstrncpy(arrptr[2], "unlibed", MAXSTR); break;
			case LNM_ALIAS: qstrncpy(arrptr[2], "aliased by", MAXSTR); break;
			case LNM_MISMATCH: qstrncpy(arrptr[2], "area mismatch", MAXSTR); break;
			case LNM_WARNING: qstrncpy(arrptr[2], "warning", MAXSTR); break;
			case LNM_ERROR: qstrncpy(arrptr[2], "error", MAXSTR); break;
			default:
				*arrptr[2] = 0;
				_RPT3(_CRT_WARN, "%s(%lu, ...): unexpected ID 0x%04hX\n", __FUNCTION__, n, item.ID);
		}
		if (!item.comment.empty())
			qstrncpy(arrptr[3], item.comment.c_str(), MAXSTR);
		else
			*arrptr[3] = 0; //fill_n(arrptr[3], MAXSTR, 0);
		qstrncpy(arrptr[4], item.iscode ? "function":"data", MAXSTR);
	} // regular item
}

int clist::GetIcon(ulong n) const {
	if (n == 0) return 114; // list head icon
	//_ASSERTE(n <= operator size_t());
	if (n <= operator size_t()) switch (at(items, n - 1).ID) {
		case LNM_RENAMED: return 19;
		case LNM_ADDLIB: return 47; // 50 '+'
		case LNM_UNLIB: return 51;
		case LNM_ALIAS: return 103;
		case LNM_MISMATCH: return 100;
		case LNM_WARNING: return 60;
		case LNM_ERROR: return 59;
#ifdef _DEBUG
		default:
			_RPT3(_CRT_WARN, "%s(%lu): unexpected ID 0x%04hX\n", __FUNCTION__, n, at(items, n - 1).ID);
#endif // _DEBUG
	}
	return -1; // unexpected
}

} // namespace LNM
