
/*****************************************************************************
 *                                                                           *
 *  impbyord.cpp: ordinal imports resolver plugin for ida pro                *
 *  (c) 2003-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif // __cplusplus

#include "fixdcstr.hpp"
#include "pcre.hpp"
#include "plugida.hpp"     // common plugin functions

//#define HOOKTOLOAD    1

#define _ntdir(dir, index) (dir.OptionalHeader.DataDirectory[index])
#define _impdir _ntdir(ntheader, IMAGE_DIRECTORY_ENTRY_IMPORT)
#define _delayimpdir _ntdir(ntheader, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
#define _expdir _ntdir(ntheader, IMAGE_DIRECTORY_ENTRY_EXPORT)
#define _ExpByOrd (expdir->NumberOfNames == 0 || expdir->AddressOfNames == 0 \
	|| expdir->AddressOfNames == expdir->AddressOfNameOrdinals)
#define _ExpBufAddr(RVA) ((LPBYTE)expdir.get() + \
	((DWORD)(RVA) - _expdir.VirtualAddress))
#define _IsInExpBuf(VA) ((LPBYTE)(VA) >= (LPBYTE)expdir.get() \
	&& (LPBYTE)(VA) < (LPBYTE)expdir.get() + _expdir.Size)
#define _IsInExpDir(RVA) (((DWORD)(RVA)) >= _expdir.VirtualAddress \
	&& ((DWORD)(RVA)) < _expdir.VirtualAddress + _expdir.Size)
#define _ExportItem(type, member, index) \
	(((const type *)_ExpBufAddr(expdir->AddressOf##member))[index])
#define _Ordinal(index) _ExportItem(WORD, NameOrdinals, (index))
#define _NameRVA(index) _ExportItem(LPCSTR, Names, (index))
#define _FuncRVA(index) _ExportItem(DWORD, Functions, (index))

class COrdinalExports;

static bool get_export_name_by_ordinal(LPCSTR modname, WORD ordinal,
	char *buffer, size_t bufferlen);
static WORD get_export_ordinal(LPCSTR modname, LPCSTR impname);
static long _lseek_by_rva(int fileio, DWORD RVA);
static void auto_process_impdir(int modio, DWORD dwRVAModuleName,
	DWORD dwRVABoundImportAddressTable, DWORD dwRVAImportNameTable,
	DWORD ImageBase, uint16 &totalordinals, uint16 &totalrenamed, bool unattended) throw(exception);
static void process_impdir(int modio, DWORD dwRVAModuleName,
	DWORD dwRVAImportAddressTable, DWORD dwRVAImportNameTable, DWORD ImageBase,
	uint16 &totalordinals, uint16 &totalrenamed, const COrdinalExports &exptable) throw(exception);

typedef struct tagImportDirectory {
	DWORD dwRVAImportNameTable;
	DWORD dwTimeDateStamp;
	DWORD dwForwarderChain;
	DWORD dwRVAModuleName;
	DWORD dwRVAImportAddressTable;
} IMAGE_IMPORT_DIRECTORY, *PIMAGE_IMPORT_DIRECTORY;

typedef struct tagDelayImportDirectory {
	DWORD dwAttributes;
	DWORD dwRVAModuleName;
	HMODULE hModule;
	DWORD dwRVAImportAddressTable;
	DWORD dwRVAImportNameTable;
	DWORD dwRVABoundImportAddressTable;
	DWORD dwRVAUnloadImportAddressTable;
	DWORD dwTimeDateStamp;
} IMAGE_DELAY_IMPORT_DIRECTORY, *PIMAGE_DELAY_IMPORT_DIRECTORY;

static bool imp_by_ord(bool unattended = false);
static bool exp_by_ord();

#ifdef HOOKTOLOAD

static int idaapi hook_cb(void *, int, va_list);
extern "C" __declspec(dllexport) simple_hooker hooker(HT_IDP, hook_cb);

static int idaapi hook_cb(void *user_data, int notification_code, va_list va) {
	if (notification_code == 0x04 || notification_code == 0x05)	{
		/*
		char dbg_out[512];
		qsnprintf(CPY(dbg_out), "[impbyord] %s file loaded", notification_code == 0x04 ?
			"new" : "old");
		*/
		if (notification_code == 0x04) imp_by_ord(true);
		_ASSERTE(hooker);
		if (hooker.deactivate()) PLUGIN.flags |= PLUGIN_UNL; // otherwise allow unload for this case
	}
	return 0;
}

#endif // HOOKTOLOAD

class COrdinalExports {
private:
	static uint32 Omf_ReadVarValue(const void *record, uint16 &index);
	static uint16 Omf_ReadIndex(const void *record, uint16 &index);

public:
	struct ordimp_t {
		fixed_path_t modname;
		string importname;
		WORD ordinal, type;

		ordimp_t(LPCSTR modname, WORD ordinal, LPCSTR importname, WORD type = IMPORT_OBJECT_CODE) :
			modname(modname), ordinal(ordinal), type(type) {
			_ASSERTE(importname != NULL && *importname != 0);
			if (importname == NULL || *importname == 0)
				__stl_throw_invalid_argument("import name must be valid non-empty string");
			this->importname.assign(importname);
		}
		ordimp_t(LPCSTR modname, WORD ordinal) : modname(modname), ordinal(ordinal) { }

		// for sorted container
		bool operator <(const ordimp_t &rhs) const {
			const int foo(modname.compare(rhs.modname));
			return foo < 0 || foo == 0 && ordinal < rhs.ordinal;
		}
	}; // ordimp_t

	class ordinals_t : public set<ordimp_t> {
	public:
		pair<iterator, bool>
			add(LPCSTR modname, WORD ordinal, LPCSTR importname, WORD type = IMPORT_OBJECT_CODE)
				{ return __super::insert(ordimp_t(modname, ordinal, importname, type)); }
	} ordinals;

	bool ScanImpLib();
}; // COrdinalExports

bool COrdinalExports::ScanImpLib() {
	char implib[QMAXPATH];
	fill_n(CPY(implib), 0);
	OPENFILENAME ofn;
	memset(&ofn, 0, sizeof OPENFILENAME);
	ofn.lStructSize = sizeof OPENFILENAME;
	ofn.hwndOwner = get_ida_hwnd();
	ofn.hInstance = hInstance;
	ofn.nFilterIndex = 1;
	ofn.nMaxFile = QMAXPATH;
	ofn.lpstrFile = implib;
	char drive[_MAX_DRIVE], dir[_MAX_DIR], path[QMAXPATH];
	get_input_file_path(CPY(path));
	_splitpath(path, drive, dir, 0, 0);
	_makepath(path, drive, dir, 0, 0);
	ofn.lpstrInitialDir = path;
	ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
		OFN_LONGNAMES | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST |
		OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
	ofn.lpstrFilter = "all known formats\0*.lib;*.a;*.exp;*.bpi;*.?ll;*.bpl;*.dpl\0"
		"import libraries\0*.lib;*.a;*.exp;*.bpi\0"
		"runtime libraries\0*.?ll;*.bpl;*.dpl\0"
		"all files\0*.*\0";
	ofn.lpstrTitle = "locate import library";
	ofn.lpstrDefExt = "lib";
	if (!GetOpenFileName(&ofn)) return false;
	int libio(_open(implib, _O_BINARY | _O_RDONLY, _S_IREAD));
	if (libio == -1) {
		msg("there was problem to open import library: %s\n", strerror(errno));
		return false;
	}
	msg("implib scanner starting...");
#define recId (uint8)sig[0]
	try {
		char sig[IMAGE_ARCHIVE_START_SIZE];
		boost::shared_crtptr<void> buf;
		if (is_pe32(implib)) {
			HMODULE hDll(LoadLibrary(implib));
			if (hDll != 0) {
				msg("pe module detected\n");
				try {
					PIMAGE_NT_HEADERS ntheader((PIMAGE_NT_HEADERS)((LPBYTE)hDll +
						((PIMAGE_DOS_HEADER)hDll)->e_lfanew));
					PIMAGE_EXPORT_DIRECTORY expdir((PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hDll +
						ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
					if ((LPCVOID)expdir <= (LPCVOID)hDll) throw logic_error("no exports");
					if (_ExpByOrd) throw logic_error("ordinal exports");
					for (DWORD index = 0; index < expdir->NumberOfNames; ++index) {
						ordinals.add((LPCSTR)hDll + expdir->Name, expdir->Base +
							((LPWORD)((LPBYTE)hDll + expdir->AddressOfNameOrdinals))[index],
							(LPCSTR)hDll + ((LPDWORD)((LPBYTE)hDll + expdir->AddressOfNames))[index]);
					} // walk export directory
					_lseek(libio, 0, SEEK_END); // lib file parsed ok
				} catch (const exception &e) {
					msg("warning: %s: %s\n", implib, e.what());
				}
				FreeLibrary(hDll);
			} else
				msg("pe module detected but cannot load\n");
		} else if (_lseek(libio, 0, SEEK_SET) == 0
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
			&& _read(libio, sig, IMAGE_ARCHIVE_START_SIZE) == IMAGE_ARCHIVE_START_SIZE
			&& memcmp(sig, IMAGE_ARCHIVE_START, IMAGE_ARCHIVE_START_SIZE) == 0) {
			/*
			 * 7.1. Archive File Signature
			 * The archive file signature identifies the file type. Any utility (for example, a linker) expecting an archive file as input can check the file type by reading this signature. The signature consists of the following ASCII characters, in which each character below is represented literally, except for the newline (\n) character:
			 *
			 * !<arch>\n
			 */
			boost::shared_crtptr<void> longnames;
			vector<boost::shared_crtptr<void> > linkermembers;
			uint32 membercount(0), symbolcount[2] = { 0, 0 };
			const uint32 *symboloffsets(0), *memberoffsets(0);
			const uint16 *indices(0);
			const char *stringtable[2] = { 0, 0 };
			msg("coff library detected\n");
			uint reccnt(0);
			const PCRE::regexp undecorate("^[\\?\\@_]?([^\\@]+)");
			while (!_eof(libio)) {
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
				 *       The name of the archive member is located at offset n within the longnames member. The number n is the decimal representation of the offset. For example: "\26" indicates that the name of the archive member is located 26 bytes beyond the beginning of longnames member contents.
				 */
				if ((_tell(libio) & 1) != 0) {
					char padding;
					_read(libio, &padding, sizeof padding);
#ifdef _DEBUG
					if (padding != IMAGE_ARCHIVE_PAD[0])
						_RPTF0(_CRT_WARN, "[impbyord] warning: coff module padding mismatch");
#endif // _DEBUG
					if (_eof(libio)) break;
				}
				IMAGE_ARCHIVE_MEMBER_HEADER header;
				if (_read(libio, &header, IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR) != IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR
					|| memcmp(header.EndHeader, IMAGE_ARCHIVE_END, sizeof IMAGE_ARCHIVE_END - 1) != 0)
					throw logic_error("error parsing library");
				++reccnt;
				const size_t size(strtoul((const char *)header.Size, 0, 10));
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
				if (_read(libio, buf.get(), size) != size) throw logic_error("error parsing library");
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
							stringtable[0] = (const char *)
								(static_cast<const uint32 *>(buf.get()) + 1 + symbolcount[0]);
							/*
							try {
								char *ptr = stringtable1;
									for (uint32 iter = 0; iter < symbolcount1; ++iter) {
										if (exports.insert(exports_t::value_type(ptr, pubsym_t())).second) ++result;
										ptr += string(ptr) + 1;
								}
							} catch (...) {
							} // exception occured
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
							membercount = *(const uint32 *)buf.get();
							memberoffsets = static_cast<const uint32 *>(buf.get()) + 1;
							symbolcount[1] = *(static_cast<const uint32 *>(buf.get()) + 1 +
								membercount);
							indices = (const uint16 *)(static_cast<const uint32 *>(buf.get()) +
								2 + membercount);
							stringtable[1] = (const char *)(static_cast<uint32 *>(buf.get()) +
								2 + membercount) + (symbolcount[1] << 1);
							/*
							try {
									char *ptr = stringtable[1];
								for (uint iter = 0; iter < membercount; ++iter) {
									if (AddPublic(ptr)) ++result;
									ptr += string(ptr) + 1;
								}
							} catch (...) {
							} // exception occured
							*/
							break;
						} // 2nd linker member
#ifdef _DEBUG
						default:
							_RPT3(_CRT_WARN, "%s(\"%s\", ...): unexpected linker member (index=%Iu)\n",
								__FUNCTION__, implib, linkermembers.size());
#endif // _DEBUG
					} // switch linker member
				} else if (memcmp(header.Name, IMAGE_ARCHIVE_LONGNAMES_MEMBER, sizeof header.Name) == 0)
					/*
					 * 7.5. Longnames Member
					 * The name of the longnames member is "\\". The longnames member is a series of strings of archive member names. A name appears here only when there is insufficient room in the Name field (16 bytes). The longnames member can be empty, though its header must appear.
					 *
					 * The strings are null-terminated. Each string begins immediately after the null byte in the previous string.
					 */
					longnames = buf;
				else { // regular member
					char *memname((char *)header.Name);
					if (header.Name[0] == '/') // name is longname: get from longnames member
						memname = static_cast<char *>(longnames.get()) +
							strtoul((const char *)&header.Name[1], 0, 10);
					else // name is short name: add terminating zero
						for (int ndx = sizeof header.Name - 1; ndx >= 0; --ndx)
							if (*(memname + ndx) == '/') {
								*(memname + ndx) = 0;
								break;
							}
					/*
					 * 8. Import Library Format
					 * Traditional import libraries, i.e., libraries that describe the exports from one image for use by another, typically follow the layout described in 7. Archive (Library) File Format. The primary difference is that import library members contain pseudo-object files instead of real ones, where each member includes the section contributions needed to build the Import Tables described in Section 6.4 The .idata Section. The linker generates this archive while building the exporting application.
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
					if (((IMPORT_OBJECT_HEADER *)buf.get())->Sig1 == IMAGE_FILE_MACHINE_UNKNOWN
						&& ((IMPORT_OBJECT_HEADER *)buf.get())->Sig2 == IMPORT_OBJECT_HDR_SIG2) {
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
						const IMPORT_OBJECT_HEADER *imphdr((IMPORT_OBJECT_HEADER *)buf.get());
						const char *truename,
							*impname((char *)(imphdr + 1)),
							*modname(impname + strlen(impname) + 1);
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
						 * IMPORT_ORDINAL 0 The import is by ordinal. This indicates that the value in the Ordinal/Hint field of the Import Header is the import's ordinal. If this constant is not specified, then the Ordinal/Hint field should always be interpreted as the import's hint.
						 * IMPORT_NAME 1 The import name is identical to the public symbol name.
						 * IMPORT_NAME_NOPREFIX 2 The import name is the public symbol name, but skipping the leading ?, @, or optionally _.
						 * IMPORT_NAME_UNDECORATE 3 The import name is the public symbol name, but skipping the leading ?, @, or optionally _, and truncating at the first @.
						 */
						WORD ordinal;
						if (imphdr->NameType == IMPORT_OBJECT_ORDINAL)
							ordinals.add(modname, imphdr->Ordinal, impname, imphdr->Type);
						else if (imphdr->NameType == IMPORT_OBJECT_NAME_UNDECORATE) {
							const PCRE::regexp::result match(undecorate, impname);
							if (match >= 2
								&& (ordinal = get_export_ordinal(modname, match[1])) != 0)
								ordinals.add(modname, ordinal, impname/*match[1]*/, imphdr->Type);
						} else {
							truename = impname;
							if (imphdr->NameType == IMPORT_OBJECT_NAME_NO_PREFIX
								&& *truename != 0 && strchr("_?@", *truename) != 0) ++truename;
							if ((ordinal = get_export_ordinal(modname, truename)) != 0)
								ordinals.add(modname, ordinal, impname/*truename*/, imphdr->Type);
						}
					} else { // std header
						// TODO: get importnames from GNU libfiles
						/*
						PIMAGE_FILE_HEADER hdr((PIMAGE_FILE_HEADER)buf.get());
						PIMAGE_SECTION_HEADER sections((PIMAGE_SECTION_HEADER)
							((int8 *)(hdr + 1) + hdr->SizeOfOptionalHeader));
						PIMAGE_SYMBOL symboltable((PIMAGE_SYMBOL)
							((int8 *)buf.get() + hdr->PointerToSymbolTable));
						const char *stringtable((const char *)
							(symboltable + hdr->NumberOfSymbols));
						for (DWORD iter = 0; iter < hdr->NumberOfSymbols; ++iter) {
							if ((category != 1 || symboltable[iter].Type == 0x20)
								&& (category != 2 || symboltable[iter].Type != 0x20)) {
								char expname[MAXNAMESIZE];
								if (symboltable[iter].N.Name.Short == 0)
									qstrcpy(expname, stringtable + symboltable[iter].N.Name.Long);
								else
									qstrcpy(expname, (const char *)symboltable[iter].N.ShortName);
								_ASSERTE(expname[0] != 0);
								if (symboltable[iter].SectionNumber > 0
									&& symboltable[iter].StorageClass == IMAGE_SYM_CLASS_EXTERNAL
									&& exports.insert(exports_t::value_type(expname,
									pubsym_t(symboltable[iter].Type == 0x20 ? IMPORT_OBJECT_CODE :
									IMPORT_OBJECT_DATA, memname))).second) ++result;
							} // area accepted
							iter += symboltable[iter].NumberOfAuxSymbols; // skip them...
						} // iterate symbols of object file
						*/
					} // std header
				} // regular member
			} // walk the file
		} else {
			// OMF implib has no good signature, it is considered if previous formats fail
			if (recId == 0xF0)
				msg("omf library possible\n");
			else
				msg("trying as omf library\n");
			char translator[0x100], library[0x100], modname[0x100], verstr[0x100],
				implements[0x100];
			translator[0] = 0;
			library[0] = 0;
			modname[0] = 0;
			verstr[0] = 0;
			implements[0] = 0;
			uint16 pagesize(0), dictlen(0);
			uint32 dictoffset(0);
			uint8 dictflags(0);
			uint chsbad(0), chsgood(0), reccnt(0), verbase(0), vendor(0),
				version(0);
			bool seg_use32(false);
#define recsize ((uint16 *)&sig[1])
			_lseek(libio, 1, SEEK_SET);
			const PCRE::regexp demangler("^[\\?\\@_](([^\\@]+)(?:\\@.*)?)$");
			while (!_eof(libio)) {
				long recoff = _tell(libio) - 1;
				if (_read(libio, recsize, 2) != 2) throw logic_error("error reading library");
				if (!buf.reset(*recsize) || _read(libio, buf.get(), *recsize) != *recsize)
					throw logic_error("error reading library");
				++reccnt;
				/*
				 * The Checksum field is a 1-byte field that contains the negative sum (modulo 256) of all other bytes in the record.
				 * In other words, the checksum byte is calculated so that the low-order byte of the sum of all the bytes in the
				 * record, including the checksum byte, equals 0. Overflow is ignored. Some compilers write a 0 byte rather than
				 * computing the checksum, so either form should be accepted by programs that process object modules.
				 */
				if ((recId & ~1) != 0xF0 /* exclude F0H and F1H records */
					&& *((uint8 *)buf.get() + *recsize - 1) /* checksum byte must be set */) {
					// care checksum
					uint8 realsum(0);
					// TODO Borland omf scheme specific
					for (uint16 cntr = 0; cntr < 3; ++cntr) realsum += (uint8)sig[cntr];
					for (cntr = 0; cntr < *recsize; ++cntr) realsum += *((uint8 *)buf.get() + cntr);
					if (realsum == 0)
						++chsgood; // ok
					else {
#ifdef _DEBUG
						_CrtDbgReport(_CRT_WARN, __FILE__, __LINE__, __FUNCTION__,
							"[ImpByOrd] wrong checksum in omf library:\n"
							"  record offset %08lX\n"
							"  record type %02X\n"
							"  record size %04hX\n"
							"  current/stored checksum: %02X/%02X\n",
							recoff, recId, *recsize, realsum, *((uint8 *)buf.get() + *recsize - 1));
#endif // _DEBUG
						if (chsbad++ <= 0 && ordinals.empty() && MessageBox(get_ida_hwnd(),
							"wrong checksum - continue scanning?", "ordinal imports resolver",
							MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES)
							throw logic_error("wrong checksum");
					}
				} // care checksum
				switch (recId) {
					case 0x80: // 80H THEADR-Translator Header Record
						qstrncpy(translator, (char *)((int8 *)buf.get() + 1), *(uint8 *)buf.get() + 1);
						break;
					case 0x82: // 82H LHEADR-Library Module Header Record
						qstrncpy(library, (char *)((int8 *)buf.get() + 1), *(uint8 *)buf.get() + 1);
						break;
					case 0x88: { // 88H COMENT-Comment Record
						uint8 cmttype(*(uint8 *)buf.get()); // comment type
						uint8 cmtcls(*((uint8 *)buf.get() + 1)); // comment class
						uint8 cmtsubtype(*((uint8 *)buf.get() + 2));
						switch (cmtcls) {
							case 0x00:
								// 000010 COMENT  Purge: No , List: Yes, Class: 0   (000h)
								//     Translator: Delphi Pascal V17.0
								break;
							case 0xA0: // OMF extensions
								switch (cmtsubtype) {
									case 0x01: { // 88H IMPDEF-Import Definition Record (Comment Class A0, Subtype 01)
										uint8 impbyord(*((uint8 *)buf.get() + 3));
										char impname[MAXNAMESIZE], modname[QMAXPATH], ident[0x100],
											*ptr((char *)((int8 *)buf.get() + 5));
										qstrncpy(impname, ptr, *((uint8 *)buf.get() + 4) + 1);
										ptr += *((uint8 *)buf.get() + 4);
										qstrncpy(modname, (char *)((int8 *)ptr + 1),
											*(uint8 *)ptr + 1);
										ptr += *(uint8 *)ptr + 1;
										WORD ordinal;
										if (impbyord == 0x01) { // impbyord
											ordinal = *(LPWORD)ptr;
											ordinals.add(modname, ordinal, impname);
										} else { // impbyname
											if (*(uint8 *)ptr != 0) {
												qstrncpy(ident, (char *)((int8 *)ptr + 1),
													*(uint8 *)ptr);
												*(ident + *(uint8 *)ptr) = 0;
											} else
												qstrcpy(ident, impname);
											ordinal = get_export_ordinal(modname, impname);
											if (ordinal != 0)
												ordinals.add(modname, ordinal, impname);
											else { // try another mangling
												const PCRE::regexp::result match(demangler, impname);
												if (match >= 3)
													if ((ordinal = get_export_ordinal(modname, match[1])) != 0)
														ordinals.add(modname, ordinal, match[1]);
													else if ((ordinal = get_export_ordinal(modname, match[2])) != 0)
														ordinals.add(modname, ordinal, match[2]);
											} // alternate mangling
										} // impbyname
										break;
									} // IMPDEF
								} // switch cmtsubtype
								break;
							case 0xA3: // 88H LIBMOD-Library Module Name Record (Comment Class A3)
								qstrncpy(modname, (char *)((int8 *)buf.get() + 0x02),
									*((uint8 *)buf.get() + 0x01) + 1);
								break;
							case 0xFB: {
								switch (cmtsubtype) {
									case 0x08:
										// 000048 COMENT  Purge: No , List: Yes, Class: 251 (0FBh), SubClass: 8 (08h)
										//     Link: ComObj.obj
										break;
									case 0x0A:
										// 000035 COMENT  Purge: No , List: Yes, Class: 251 (0FBh), SubClass: 10 (0Ah)
										//     Implements: OWC10XP.obj
										qstrncpy(implements, (char *)((int8 *)buf.get() + 0x03),
											*((uint8 *)buf.get() + 0x03) + 1);
										break;
									case 0x0C:
										// 00002A COMENT  Purge: Yes, List: Yes, Class: 251 (0FBh), SubClass: 12 (0Ch)
										//     Package Module Record, Lead Byte: 01h, Flags: 00004000h
										break;
								} // switch cmtsubtype
								break;
							}
						} // switch cmtcls
						break;
					}
					case 0x8A:
					case 0x8B: { // 8AH or 8BH MODEND-Module End Record
						uint8 modtype(*(uint8 *)buf.get());
						//translator[0] = 0;
						modname[0] = 0; // ???
						implements[0] = 0;
						break;
					}
					case 0x8C: { // 8CH EXTDEF-External Names Definition Record
						/*
						uint16 pos = 0;
						while (pos + 1 < *recsize && *((int8 *)buf.get() + pos) != 0) {
							char name[MAXNAMESIZE];
							qstrncpy(name, (char *)((int8 *)buf.get() + pos + 1),
								*((uint8 *)buf.get() + pos) + 1);
							if (AddPublic(name, unknown, modname)) ++result;
							pos += *((uint8 *)buf.get() + pos) + 2;
						}
						*/
						break;
					}
					case 0x90:
					case 0x91: { // 90H or 91H PUBDEF-Public Names Definition Record
						/*
						uint16 basegrpindex, basesegindex, pos = 0;
						uint32 baseframe;
						uint8 offsize;
						char name[MAXNAMESIZE];
						basegrpindex = Omf_ReadIndex(buf.get(), pos);
						basesegindex = Omf_ReadIndex(buf.get(), pos);
						if (basegrpindex == 0 && basesegindex == 0) {
							baseframe = *(uint16 *)((uint8 *)buf.get() + pos);
							pos += 2;
						}
						offsize = 2 << (uint8)(recId == 0x91 || seg_use32);
						while (pos + 1 < *recsize) {
							uint8 len = *((uint8 *)buf.get() + pos);
							qstrncpy(name, (char *)((int8 *)buf.get() + pos + 1), len + 1);
							if (AddPublic(name, unknown, modname)) ++result; // no typeinfo available
							pos += 1 + len;
							uint32 offset = offsize == 2 ? *(uint16 *)
								((int8 *)buf.get() + pos) : *(uint32 *)((int8 *)buf.get() + pos);
							pos += offsize;
							uint16 type = omf_readindex(buf.get(), pos);
						} // walk pubnames
						*/
						break;
					}
					case 0x98:
					case 0x99: // 98H or 99H SEGDEF-Segment Definition Record
						seg_use32 = *(uint8 *)buf.get() & 1;
						break;
					case 0xB0: { // B0H COMDEF-Communal Names Definition Record
// 						uint16 pos = 0;
// 						while (pos + 1 < *recsize != 0 && *((int8 *)buf.get() + pos) != 0) {
// 							char name[MAXNAMESIZE];
// 							qstrncpy(name, (char *)((int8 *)buf.get() + pos + 1),
// 									*((uint8 *)buf.get() + pos) + 1);
// 							if (AddPublic(name)) ++result;
// 							pos += *((uint8 *)buf.get() + pos) + 1;
// 							uint16 typindex = Omf_ReadIndex(buf.get(), pos);
// 							uint8 datatype = *((uint8 *)buf.get() + pos++);
// 							uint32 value;
// 							if (datatype >= 1 && datatype <= 0x5F || datatype == 0x62 /* NEAR */)
// 								value = Omf_ReadVarValue(buf.get(), pos);
// 							else if (datatype == 0x61) // FAR {
// 								value = Omf_ReadVarValue(buf.get(), pos);
// 								value = Omf_ReadVarValue(buf.get(), pos);
// 							}
// 						} // walk comdefs
						break;
					}
					case 0xCC: // CCH VERNUM - OMF Version Number Record
						qstrncpy(verstr, (char *)((int8 *)buf.get() + 1),
							*((uint8 *)buf.get()));
						qsscanf("%u.%u.%u", verstr, verbase, vendor, version);
						break;
					case 0xF0: // Library Header Record
						pagesize = *recsize + 3;
						dictoffset = *(uint32 *)buf.get();
						dictlen = *((uint16 *)buf.get() + 2);
						dictflags = *((uint8 *)buf.get() + 6);
						break;
					case 0xF1: // Library End Record, quit parsing
						_lseek(libio, 0, SEEK_END);
				} // switch recId
				// skip leading zeros to next paragraph alignment
				while (!_eof(libio) && _read(libio, sig, 1) >= 1 && sig[0] == 0);
			} // walk the file
			/*
			if (dictoffset && dictlen) { // process dictionary, if possible
				// process dictionary, if possible
				size_t dictsize = dictlen << 9;
				if ((bool)buf.reset(0x200) && _lseek(libio, dictoffset, SEEK_SET) ==
					dictoffset) {
					int8 (*HTAB)[1] = (int8 (*)[1])buf.get();
					int8 *FFLAG = (__int *)buf.get() + 37;
					for (uint16 iter = 0; iter < dictlen; ++iter) {
						if (_read(libio, buf.get(), 0x200) != 0x200)
							throw logic_error("error reading library");
						uint16 pos = 38;
						char name[MAXNAMESIZE];
						while (pos < 0x200 && *((int8 *)buf.get() + pos) != 0) {
							qstrncpy(name, (char *)((int8 *)buf.get() + pos + 1),
								*((uint8 *)buf.get() + pos) + 1);
							if (AddPublic(name)) _asm inc result // no typeinfo available
							pos += 1 + *((uint8 *)buf.get() + pos);
							uint32 *blocknumber =
								(uint16 *)((int8 *)buf.get() + pos);
							pos += 2 + ??? + (pos & 1); // Borland specific!!!
						} // walk symbols
					} // walk pages
				} // ready to read
			} // process dictionary
			*/
			OutputDebugString("omf library processed: %u records (%u good/%u bad)",
				reccnt, chsgood, chsbad);
			if (chsbad > 0) msg("warning: %u wrong checksums\n", chsbad);
		} // OMF implib
	} catch (const exception &e) {
		msg("warning: %s (%s)\n", e.what(), implib);
	}
	// import table constructed
	bool retval(_eof(libio));
	_close(libio);
	if (!retval) {
		msg("warning: library couldn't be scanned\n");
		return false;
	}
	if (ordinals.empty()) {
		msg("warning: no resolvable symbols imported, dying gently...\n");
		return false;
	}
	msg("implib scanner done, %Iu resolvable names imported\n", ordinals.size());
	return true;
}

uint16 COrdinalExports::Omf_ReadIndex(const void *record, uint16 &index) {
	if (*((const uint8 *)record + index) & 0x80)
		return ((*((const uint8 *)record + index++) & 0x7F) << 8) +
			*((const uint8 *)record + index++);
	else
		return *((const uint8 *)record + index++);
}

uint32 COrdinalExports::Omf_ReadVarValue(const void *record, uint16 &index) {
	uint32 value = *((const uint8 *)record + index++);
	switch (value) {
		case 0x81:
			value = *(uint16 *)((const int8 *)record + index);
			index += 2;
			break;
		case 0x84:
			value = (*(uint32 *)((const int8 *)record + index)) & 0xFFFFFF;
			index += 3;
			break;
		case 0x88:
			value = *(uint32 *)((const int8 *)record + index);
			index += 4;
			break;
	}
	return value;
}

#ifdef _DEBUG
#define CATCH_EXCEPTION } catch (const exception &e) { \
	_RPTF2(_CRT_ERROR, "%s(...): %s\n", __FUNCTION__, e.what());
#else // !_DEBUG
#define CATCH_EXCEPTION
#endif // _DEBUG
#define PROCESS_IMPTABLE(dir, dirtype, thunkproc, param) \
	if (dir.VirtualAddress != 0 && dir.Size > 0) try { /* have imports */ \
		if (_lseek_by_rva(modio, dir.VirtualAddress) == -1) \
			throw logic_error("error parsing input file"); \
		boost::shared_array<dirtype> \
			impdir((P##dirtype)malloc(dir.Size), free); \
		if (!impdir) throw bad_alloc(); \
		if (_read(modio, impdir.get(), dir.Size) < dir.Size) \
			throw logic_error("error parsing input file"); \
		for (P##dirtype iter = impdir.get(); \
			iter->dwRVAModuleName != 0 && iter->dwRVAImportNameTable != 0 \
				&& iter->dwRVAImportAddressTable != 0; \
			++iter) thunkproc(modio, iter->dwRVAModuleName, \
				iter->dwRVAImportAddressTable, iter->dwRVAImportNameTable, \
				ntheader.OptionalHeader.ImageBase, totalordinals, totalrenamed, param); \
	CATCH_EXCEPTION \
	} catch (...) { \
		_RPTF2(_CRT_ERROR, "%s(...): %s\n", __FUNCTION__, "unknown exception"); \
	} /* have imports */

static bool imp_by_ord(bool unattended) {
	char inpath[QMAXPATH];
	get_input_file_path(CPY(inpath));
	int modio(_open(inpath, _O_BINARY | _O_RDONLY, _S_IREAD));
	uint16 totalrenamed, totalordinals;
	IMAGE_DOS_HEADER dosheader;
	IMAGE_NT_HEADERS ntheader;
	if (modio == -1) {
		if (unattended) return false;
	} else {
		totalordinals = 0;
		totalrenamed = 0;
		try {
			if (_read(modio, &dosheader, sizeof dosheader) < sizeof dosheader
				|| dosheader.e_magic != IMAGE_DOS_SIGNATURE
				|| _lseek(modio, dosheader.e_lfanew, SEEK_SET) == -1
				|| _read(modio, &ntheader, sizeof ntheader) < sizeof ntheader
				|| ntheader.Signature != IMAGE_NT_SIGNATURE
				|| ntheader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
				throw logic_error("error parsing input file");
			if (_impdir.Size <= 0 && _delayimpdir.Size <= 0) throw logic_error("no imports");
			PROCESS_IMPTABLE(_impdir, IMAGE_IMPORT_DIRECTORY, auto_process_impdir, unattended)
			PROCESS_IMPTABLE(_delayimpdir, IMAGE_DELAY_IMPORT_DIRECTORY, auto_process_impdir, unattended)
		} catch (const exception &e) {
			_close(modio);
			msg("warning: %s (%s)\n", e.what(), inpath);
			return false;
		}
		if (totalrenamed > 0 || totalordinals > 0)
			if (unattended)
				msg("unattended: %hu ordinals resolved (%hu remaining)\n", totalrenamed,
					totalordinals - totalrenamed);
			else
				msg("%hu unresolved ordinals found\n", totalordinals - totalrenamed);
		if (unattended) {
			_close(modio);
			return true;
		}
		_lseek(modio, 0, SEEK_SET);
		if (totalordinals <= totalrenamed && MessageBox(get_ida_hwnd(),
			"there seem be none unresolved ordinals remaining, execute anyway?",
			"ordinal imports resolver", MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
			_close(modio);
			return false;
		}
	} // modio open
	COrdinalExports exptable; // ordinal import lookup table
	if (!exptable.ScanImpLib()) {
		if (modio != -1) _close(modio);
		return false;
	}
	// resolve imports
	while (modio == -1) {
		msg("for iat resolving original executable is required\n");
		char exepath[QMAXPATH];
		qstrcpy(exepath, inpath);
		OPENFILENAME ofn;
		memset(&ofn, 0, sizeof OPENFILENAME);
		ofn.lStructSize = sizeof OPENFILENAME;
		ofn.hwndOwner = get_ida_hwnd();
		ofn.hInstance = hInstance;
		ofn.nFilterIndex = 1;
		ofn.nMaxFile = QMAXPATH;
		ofn.lpstrFile = exepath;
		char drive[_MAX_DRIVE], dir[_MAX_DIR], path[QMAXPATH];
		_splitpath(inpath, drive, dir, 0, 0);
		_makepath(path, drive, dir, 0, 0);
		ofn.lpstrInitialDir = path;
		ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
			OFN_LONGNAMES | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST |
			OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
		ofn.lpstrFilter = "executables (*.exe;*.dll;*.ocx)\0*.exe;*.dll;*.ocx\0"
			"applications (*.exe)\0*.exe\0dynamic link libraries (*.dll)\0*.dll\0"
			"activex (*.ocx)\0*.ocx\0all files\0*.*\0";
		char rootname[QMAXPATH];
		get_root_filename(CPY(rootname));
		char strTitle[0x180];
		qsnprintf(CPY(strTitle), "locate module %s", rootname);
		ofn.lpstrTitle = strTitle;
		ofn.lpstrDefExt = strrchr(rootname, '.') + 1;
		if (!GetOpenFileName(&ofn)) return false;
		modio = _open(exepath, _O_BINARY | _O_RDONLY, _S_IREAD);
		if (modio != -1 && MessageBox(get_ida_hwnd(), "remember new root?",
			"ordinal imports resolver", MB_ICONQUESTION | MB_YESNO) == IDYES)
			change_root(exepath);
	}
	if (!decide_ida_bizy("ordinal imports resolver")) {
		// Let the analysis make all data references to avoid variables merging.
		msg("autoanalysis is running now. call me again when finished\n");
		MessageBeep(MB_ICONEXCLAMATION);
		return false;
	}
	msg("reading original iat from '%s'...\n", inpath);
	totalordinals = 0;
	totalrenamed = 0;
	bool retval;
	try {
		if (_read(modio, &dosheader, sizeof dosheader) < sizeof dosheader
			|| dosheader.e_magic != IMAGE_DOS_SIGNATURE
			|| _lseek(modio, dosheader.e_lfanew, SEEK_SET) != dosheader.e_lfanew
			|| _read(modio, &ntheader, sizeof ntheader) < sizeof ntheader
			|| ntheader.Signature != IMAGE_NT_SIGNATURE
			|| ntheader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			throw logic_error("error parsing input file");
		PROCESS_IMPTABLE(_impdir, IMAGE_IMPORT_DIRECTORY, process_impdir, exptable)
		PROCESS_IMPTABLE(_delayimpdir, IMAGE_DELAY_IMPORT_DIRECTORY, process_impdir, exptable)
		retval = true;
	} catch (const exception &e) {
		retval = false;
		msg("error: %s (%s)\n", e.what(), inpath);
	} catch (...) {
		retval = false;
		msg("error: %s (%s)\n", "unhandled exception (this message never should show)", inpath);
	}
	_close(modio);
	msg("total: %hu ordinal imports named\n", totalrenamed);
	return retval;
}

static void auto_process_impdir(int modio, DWORD dwRVAModuleName,
	DWORD dwRVAImportAddressTable, DWORD dwRVAImportNameTable, DWORD ImageBase,
	uint16 &totalordinals, uint16 &totalrenamed, bool unattended) {
	_ASSERTE(modio != -1);
	if (modio == -1) __stl_throw_invalid_argument("invalid file handle");
	_ASSERTE(dwRVAModuleName != 0);
	_ASSERTE(dwRVAImportAddressTable != 0);
	_ASSERTE(dwRVAImportNameTable != 0);
	if (dwRVAModuleName == 0 || dwRVAImportAddressTable == 0
		|| dwRVAImportNameTable == 0) __stl_throw_invalid_argument("invalid IMAGE_IMPORT_DIRECTORY values");
	if (_lseek_by_rva(modio, dwRVAModuleName) == -1)
		throw logic_error("error parsing input file");
	char modname[QMAXPATH], *ptr(modname);
	while (_read(modio, ptr, 1) >= 1 && *ptr != 0) ++ptr;
	if (_lseek_by_rva(modio, dwRVAImportAddressTable) == -1)
		throw logic_error("error parsing input file");
	IMAGE_THUNK_DATA thunk;
	for (dwRVAImportAddressTable += ImageBase; _read(modio, &thunk, sizeof thunk) == sizeof thunk
		&& thunk.u1.AddressOfData != 0; dwRVAImportAddressTable += sizeof DWORD) {
#ifdef _DEBUG
		char dbg_out[512];
		qsnprintf(CPY(dbg_out), "  processing import %s!", modname);
		if (IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal))
			_ultoa(IMAGE_ORDINAL(thunk.u1.Ordinal), tail(dbg_out), 10);
		else if (_lseek_by_rva(modio, IMAGE_ORDINAL(thunk.u1.Ordinal)/*?????*/ + 2) != -1) {
			ptr = tail(dbg_out);
			while (_read(modio, ptr, 1) >= 1 && *ptr != 0) ++ptr;
		}
		qstrcat(dbg_out, "...");
		msg(dbg_out);
#endif // _DEBUG
		if (IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal)) { // imported by ordinal
			++totalordinals;
			char truename[MAXNAMESIZE], idaname[MAXNAMESIZE];
			if (get_export_name_by_ordinal(modname,
				IMAGE_ORDINAL(thunk.u1.Ordinal), CPY(truename))) {
				if (get_true_name(BADADDR, dwRVAImportAddressTable, CPY(idaname) != 0)
					&& strstr(idaname, truename) != 0) // external already renamed
					++totalordinals;
				else if (unattended && set_name(dwRVAImportAddressTable, truename,
					SN_NOCHECK | SN_NOWARN | SN_NON_WEAK)) {
					msg("  extern at %08X: %s\n", dwRVAImportAddressTable, truename);
					++totalrenamed;
				}
			} // can lookup name
		} // imported by ordinal
#ifdef _DEBUG
		msg("done\n");
#endif // _DEBUG
	} // modules walk
}

static void process_impdir(int modio, DWORD dwRVAModuleName,
	DWORD dwRVAImportAddressTable, DWORD dwRVAImportNameTable, DWORD ImageBase,
	uint16 &totalordinals, uint16 &totalrenamed, const COrdinalExports &exptable) {
	_ASSERTE(modio != -1);
	if (modio == -1) __stl_throw_invalid_argument("invalid file handle");
	_ASSERTE(dwRVAModuleName != 0);
	_ASSERTE(dwRVAImportAddressTable != 0);
	_ASSERTE(dwRVAImportNameTable != 0);
	if (dwRVAModuleName == 0 || dwRVAImportAddressTable == 0
		|| dwRVAImportNameTable == 0) __stl_throw_invalid_argument("invalid IMAGE_IMPORT_DIRECTORY values");
	if (_lseek_by_rva(modio, dwRVAModuleName) == -1)
		throw logic_error("error parsing input file");
	char modname[QMAXPATH], *ptr(modname);
	while (_read(modio, ptr, 1) >= 1 && *ptr != 0) ++ptr;
	if (_lseek_by_rva(modio, dwRVAImportAddressTable) == -1)
		throw logic_error("error parsing input file");
	IMAGE_THUNK_DATA thunk;
	for (dwRVAImportAddressTable += ImageBase; _read(modio, &thunk, sizeof thunk) == sizeof thunk
		&& thunk.u1.AddressOfData != 0; dwRVAImportAddressTable += sizeof DWORD) {
		char formatedname[MAXNAMESIZE];
		if (IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal)) { // imported by ordinal
			++totalordinals;
			const COrdinalExports::ordinals_t::const_iterator
				i(exptable.ordinals.find(COrdinalExports::ordimp_t(modname,
					IMAGE_ORDINAL(thunk.u1.Ordinal))));
			if (i != exptable.ordinals.end()) { // can lookup name
				char idaname[MAXNAMESIZE];
				if (get_true_name(BADADDR, dwRVAImportAddressTable, CPY(idaname)) != 0
					&& strstr(idaname, i->importname.c_str()) != 0) // external already renamed
					--totalordinals;
				else {
					switch (i->type) {
						case IMPORT_OBJECT_CODE: {
							bool canbedata(false);
							xrefblk_t xref;
							for (int ok = xref.first_to(static_cast<ea_t>(dwRVAImportAddressTable),
								XREF_DATA); ok; ok = xref.next_to()) {
								if (xref.iscode) continue;
								if (isCode(get_flags_novalue(xref.from)) && ua_ana0(xref.from) > 0
									&& !is_indirectflow_insn(cmd.itype)) canbedata = true;
								func_t *func;
								if (isFunc(get_flags_novalue(xref.from)) && ua_ana0(xref.from) > 0
									&& (cmd.itype == NN_jmpni || cmd.itype == NN_jmpfi)
									&& (func = get_func(xref.from))
									&& xref.from + cmd.size >= func->endEA) // pure import function
									set_name(xref.from, i->importname.c_str(), SN_NOCHECK | SN_NOWARN | SN_NON_WEAK);
							}
							if (canbedata)
								formatedname[0] = 0;
							else
								qstrcpy(formatedname, FUNC_IMPORT_PREFIX);
							qstrcat(formatedname, i->importname.c_str());
							break;
						}
						case IMPORT_OBJECT_DATA:
						case IMPORT_OBJECT_CONST:
						default: // as-is
							qstrcpy(formatedname, i->importname.c_str());
					} // switch statement
					if (get_name_ea(BADADDR, formatedname) == static_cast<ea_t>(dwRVAImportAddressTable)
						|| make_unique_name(CPY(formatedname)) != 0
						&& set_name(static_cast<ea_t>(dwRVAImportAddressTable), formatedname, SN_NOCHECK | SN_NOWARN | SN_NON_WEAK)) {
						msg("  extern at %08X: %s\n", dwRVAImportAddressTable, formatedname);
						++totalrenamed;
					}
				} // name not set or mismatch
			} // can lookup name
		} // imported by ordinal
	} // modules walk
}

static bool exp_by_ord() {
	char inpath[QMAXPATH];
	get_input_file_path(CPY(inpath));
	int modio(_open(inpath, _O_BINARY | _O_RDONLY, _S_IREAD));
	while (modio == -1) {
		msg("for exports resolving original executable is required: %s\n", strerror(errno));
		char exepath[QMAXPATH];
		qstrcpy(exepath, inpath);
		OPENFILENAME ofn;
		memset(&ofn, 0, sizeof OPENFILENAME);
		ofn.lStructSize = sizeof OPENFILENAME;
		ofn.hwndOwner = get_ida_hwnd();
		ofn.hInstance = hInstance;
		ofn.nFilterIndex = 1;
		ofn.nMaxFile = QMAXPATH;
		ofn.lpstrFile = exepath;
		char drive[_MAX_DRIVE], dir[_MAX_DIR], path[QMAXPATH];
		_splitpath(inpath, drive, dir, 0, 0);
		_makepath(path, drive, dir, 0, 0);
		ofn.lpstrInitialDir = path;
		ofn.Flags = OFN_ENABLESIZING | OFN_EXPLORER | OFN_FORCESHOWHIDDEN |
			OFN_LONGNAMES | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST |
			OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
		ofn.lpstrFilter = "executables (*.exe;*.dll;*.ocx)\0*.exe;*.dll;*.ocx\0"
			"applications (*.exe)\0*.exe\0dynamic link libraries (*.dll)\0*.dll\0"
			"activex (*.ocx)\0*.ocx\0all files\0*.*\0";
		char strTitle[0x180];
		char rootname[QMAXPATH];
		get_root_filename(CPY(rootname));
		qsnprintf(CPY(strTitle), "locate module %s", rootname);
		ofn.lpstrTitle = strTitle;
		ofn.lpstrDefExt = strrchr(rootname, '.') + 1;
		if (!GetOpenFileName(&ofn)) return false;
		modio = _open(exepath, _O_BINARY | _O_RDONLY, _S_IREAD);
		if (modio != -1 && MessageBox(get_ida_hwnd(), "remember new root?",
			"ordinal exports resolver", MB_ICONQUESTION | MB_YESNO) == IDYES)
			change_root(exepath);
	}
	uint totalordinals(0);
	boost::shared_crtptr<IMAGE_EXPORT_DIRECTORY> expdir;
	bool retval;
	try {
		IMAGE_DOS_HEADER dosheader;
		IMAGE_NT_HEADERS ntheader;
		if (_read(modio, &dosheader, sizeof dosheader) < sizeof dosheader
			|| dosheader.e_magic != IMAGE_DOS_SIGNATURE
			|| _lseek(modio, dosheader.e_lfanew, SEEK_SET) != dosheader.e_lfanew
			|| _read(modio, &ntheader, sizeof ntheader) < sizeof ntheader
			|| ntheader.Signature != IMAGE_NT_SIGNATURE
			|| ntheader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			throw logic_error("error parsing input file");
		if (_expdir.Size == 0) throw logic_error("no exports");
		if (_lseek_by_rva(modio, _expdir.VirtualAddress) == -1)
				throw logic_error("error parsing input file");
		expdir.reset(_expdir.Size);
		if (!expdir) throw bad_alloc();
		if (_read(modio, expdir.get(), _expdir.Size) < _expdir.Size)
			throw logic_error("error parsing input file");
		if (_ExpByOrd) totalordinals = expdir->NumberOfFunctions;
		if (totalordinals == 0)
			throw logic_error("no ordinal exports in this module");
		COrdinalExports exptable; // ordinal import lookup table
		if (!exptable.ScanImpLib())
			throw logic_error("COrdinalExports::ScanImpLib() returned false");
		// resolve exports
		if (!decide_ida_bizy("ordinal exports resolver")) {
			MessageBeep(MB_ICONEXCLAMATION);
			throw logic_error("autoanalysis is running now. call me again when finished");
		}
		uint totalrenamed(0);
		_ASSERTE(_IsInExpDir(expdir->Name));
		LPCSTR modname((LPCSTR)_ExpBufAddr(expdir->Name));
		for (DWORD iter = 0; iter < expdir->NumberOfFunctions; ++iter) {
			WORD ord(0);
			if (expdir->AddressOfNameOrdinals != 0
				&& expdir->AddressOfNameOrdinals != expdir->AddressOfNames) {
				const WORD *ordinal(&_Ordinal(iter));
				if (!_IsInExpBuf(ordinal)) {
					_RPTF1(_CRT_ASSERT, "_IsInExpBuf(&_Ordinal(%lu))", iter);
					continue;
				}
				ord = *ordinal;
			} else
				ord = iter;
			const DWORD *funcrva(&_FuncRVA(ord));
			if (!_IsInExpBuf(funcrva)) {
				_RPTF1(_CRT_ASSERT, "_IsInExpBuf(&_FuncRVA(%hu))", ord);
				continue;
			}
			if (!_IsInExpDir(*funcrva)) { // not a redirect
				ord += expdir->Base;
				const COrdinalExports::ordinals_t::const_iterator
					i(exptable.ordinals.find(COrdinalExports::ordimp_t(modname, ord)));
				if (i != exptable.ordinals.end()) { // can lookup name
					ea_t export_ea(ntheader.OptionalHeader.ImageBase + *funcrva);
					if (isEnabled(export_ea)) {
						char idaname[MAXNAMESIZE];
						flags_t flags;
						if (get_true_name(BADADDR, export_ea, CPY(idaname) != 0)
							&& strstr(idaname, i->importname.c_str()) != 0) // external already renamed
							--totalordinals;
						else if (!has_user_name(flags = get_flags_novalue(export_ea))) {
							WORD type(i->type);
							if (type == IMPORT_OBJECT_CODE && !isCode(flags)) {
								msg("warning: ordinal %hu at %08a is reported as code by library but "
								"analyzed as data by IDA: type changed to IMPORT_OBJECT_DATA.\n",
									ord, export_ea);
								if (isData(flags))
									type = IMPORT_OBJECT_DATA;
								else if (isTail(flags))
									msg("warning: ordinal %hu at %08a is tail byte!\n", ord, export_ea);
							}
							if (type == IMPORT_OBJECT_CODE) {
								xrefblk_t xref;
								for (int ok = xref.first_to(export_ea, XREF_DATA); ok;
									ok = xref.next_to()) {
									if (xref.iscode) continue;
									func_t *func;
									if (isFunc(get_flags_novalue(xref.from)) && ua_ana0(xref.from) > 0
										&& (cmd.itype == NN_jmpni || cmd.itype == NN_jmpfi)
										&& (func = get_func(xref.from))
										&& xref.from + cmd.size >= func->endEA) // pure import function
										set_name(xref.from, i->importname.c_str(), SN_NOCHECK | SN_NOWARN | SN_NON_WEAK);
								}
							}
							char tmp[MAXNAMESIZE];
							if (get_name_ea(BADADDR, tmp) == export_ea
								|| qstrcpy(tmp, i->importname.c_str()) != 0 && make_unique_name(CPY(tmp)) != 0
								&& set_name(export_ea, tmp, SN_NOCHECK | SN_NOWARN | SN_NON_WEAK | SN_PUBLIC)) {
								msg("  export #%hu at %08a: %s\n", ord, export_ea, tmp);
								++totalrenamed;
							} // rename ok
						} else
							msg("export #%hu(%s) at %08a has already user defined name, not renamed\n",
								ord, i->importname.c_str(), export_ea);
					} else
						msg("export #%hu(%s) cannot be applied, address invalid ea=%08a rva=0x%08lX\n",
							ord, export_ea, *funcrva);
				} // can lookup name for this ordinal
			} // not a redirect
		} // iterate names
		retval = true;
		msg("total: %u ordinal exports named\n", totalrenamed);
	} catch (const exception &e) {
		retval = false;;
		msg("warning: %s (%s)\n", e.what(), inpath);
	} catch (...) {
		retval = false;;
		msg("warning: %s (%s)\n", "unknown error occured", inpath);
	}
	_close(modio);
	return retval;
}

static WORD get_export_ordinal(LPCSTR modname, LPCSTR impname) {
	_ASSERTE(modname != NULL && *modname != 0);
	_ASSERTE(impname != NULL && *impname != 0);
	if (modname == NULL || *modname == 0 || impname == NULL || *impname == 0) return 0;
	HMODULE hDll(LoadLibrary(modname));
	if (hDll == NULL && (hDll = LoadLibrary(modname)) == NULL) return 0; // couldnot get the module
	PIMAGE_EXPORT_DIRECTORY expdir;
	try {
		if (((PIMAGE_DOS_HEADER)hDll)->e_magic != IMAGE_DOS_SIGNATURE)
			throw logic_error("bad DOS magic");
		PIMAGE_NT_HEADERS ntheader((PIMAGE_NT_HEADERS)((int8 *)hDll +
			((PIMAGE_DOS_HEADER)hDll)->e_lfanew));
		if (ntheader->Signature != IMAGE_NT_SIGNATURE
			|| ntheader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			throw logic_error("bad NT magic");
		expdir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hDll +
			ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if ((LPCVOID)expdir <= (LPCVOID)hDll) throw logic_error("bad export directory address");
	} catch (const exception &e) {
		FreeLibrary(hDll);
		_RPT4(_CRT_WARN, "%s(\"%s\", \"%s\"): %s\n", __FUNCTION__, modname,
		 impname, e.what());
		return 0;
	}
	WORD retval(0);
	if (!_ExpByOrd) for (DWORD index = 0; index < expdir->NumberOfNames; ++index)
		if (strcmp(((LPCSTR *)((LPBYTE)hDll + expdir->AddressOfNames))[index],
			impname) == 0) {
			retval = expdir->Base + ((LPWORD)((LPBYTE)hDll +
				expdir->AddressOfNameOrdinals))[index];
			break;
		}
	FreeLibrary(hDll);
	return retval;
}

static bool get_export_name_by_ordinal(LPCSTR modname, WORD ordinal,
	char *buffer, size_t bufferlen) {
	_ASSERTE(modname != NULL && *modname != 0);
	_ASSERTE(buffer != 0);
	_ASSERTE(bufferlen > 0);
	if (modname == NULL || *modname == 0 || buffer == 0 || bufferlen <= 0) return false;
	*buffer = 0;
	HMODULE hDll(LoadLibrary(modname));
	if (hDll == NULL) {
		char appdir[QMAXPATH];
		get_input_file_path(CPY(appdir));
		char *lastbs(std::max(strrchr(appdir, '\\'), strrchr(appdir, '/')));
		if (lastbs != 0) {
			qstrncpy(lastbs + 1, modname, strlen(modname) + 1);
			hDll = LoadLibrary(appdir);
		}
		if (hDll == NULL && (hDll = LoadLibrary(modname)) == NULL) return false;
	}
	PIMAGE_EXPORT_DIRECTORY expdir;
	try {
		if (((PIMAGE_DOS_HEADER)hDll)->e_magic != IMAGE_DOS_SIGNATURE)
			throw logic_error("bad DOS magic");
		PIMAGE_NT_HEADERS ntheader((PIMAGE_NT_HEADERS)((int8 *)hDll +
			((PIMAGE_DOS_HEADER)hDll)->e_lfanew));
		if (ntheader->Signature != IMAGE_NT_SIGNATURE
			|| ntheader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			throw logic_error("bad NT magic");
		expdir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hDll +
			ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if ((LPCVOID)expdir <= (LPCVOID)hDll) throw logic_error("bad export directory address");
	} catch (const exception &e) {
		FreeLibrary(hDll);
		_RPT4(_CRT_WARN, "%s(\"%s\", %hu, ...): %s\n", __FUNCTION__, modname,
		 ordinal, e.what());
		return false;
	}
	if (!_ExpByOrd) {
		DWORD const index(distance((LPWORD)((LPBYTE)hDll +
			expdir->AddressOfNameOrdinals), find((LPWORD)((LPBYTE)hDll +
			expdir->AddressOfNameOrdinals), (LPWORD)((LPBYTE)hDll +
			expdir->AddressOfNameOrdinals) + expdir->NumberOfNames,
			ordinal - expdir->Base)));
		if (index < expdir->NumberOfNames) qstrncpy(buffer,
			((LPCSTR *)((LPBYTE)hDll + expdir->AddressOfNames))[index], bufferlen);
	}
	FreeLibrary(hDll);
	return buffer[0] != 0;
}

static long _lseek_by_rva(int fio, DWORD RVA) {
	_ASSERTE(fio != -1);
	if (fio != -1 && _lseek(fio, 0, SEEK_SET) == 0) {
		IMAGE_DOS_HEADER dosheader;
		if (_read(fio, &dosheader, sizeof dosheader) >= sizeof dosheader
			&& dosheader.e_magic == IMAGE_DOS_SIGNATURE
			&& _lseek(fio, dosheader.e_lfanew, SEEK_SET) == dosheader.e_lfanew) {
			IMAGE_NT_HEADERS ntheader;
			if (_read(fio, &ntheader, sizeof ntheader) >= sizeof ntheader
				&& ntheader.Signature == IMAGE_NT_SIGNATURE
				&& ntheader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
				size_t secoffst(dosheader.e_lfanew + sizeof IMAGE_NT_HEADERS);
				if (_lseek(fio, secoffst, SEEK_SET) == secoffst) {
					for (WORD index = 0; index < ntheader.FileHeader.NumberOfSections; ++index) {
						IMAGE_SECTION_HEADER sechdr;
						if (_read(fio, &sechdr, sizeof sechdr) < sizeof sechdr) break; // integrity broken
						if (RVA >= sechdr.VirtualAddress
							&& RVA < sechdr.VirtualAddress + sechdr.Misc.VirtualSize) {
							size_t const offset(RVA - sechdr.VirtualAddress + sechdr.PointerToRawData);
							if (_lseek(fio, offset, SEEK_SET) == offset)
								return static_cast<long>(offset);
						} // match
					}
				}
			}
		}
	}
	return -1;
}

#define PROCESS_IMPTABLE(dir, dirtype) if (dir.Size > 0 \
		&& dir.VirtualAddress != 0 && _lseek_by_rva(modio, dir.VirtualAddress) != -1) { \
		P##dirtype impdir((P##dirtype)malloc(dir.Size)); \
		if (impdir != 0) __try { \
			if (_read(modio, impdir, dir.Size) < dir.Size) __leave; \
			for (P##dirtype iter = impdir; \
				iter->dwRVAModuleName != 0 \
					&& iter->dwRVAImportAddressTable != 0 \
					&& iter->dwRVAImportNameTable != 0; \
				++iter) { \
				if (_lseek_by_rva(modio, iter->dwRVAImportAddressTable) == -1) __leave; \
				while (_read(modio, &thunk, sizeof thunk) == sizeof thunk \
					&& thunk.u1.AddressOfData != 0) \
					if (IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal)) { \
						hasordinals = true; \
						__leave; \
					} \
			} \
		} __finally { \
			free(impdir); \
		} \
	}

static int idaapi init(void) {
	if (ph.id != PLFM_386 || inf.filetype != f_PE) {
		msg("[impbyord] plugin not available for this processor or format\n");
		return PLUGIN_SKIP;
	}
	BPX;
	bool hasordinals(false);
	__try { // exception handler
		char inpath[QMAXPATH];
		get_input_file_path(CPY(inpath));
		int modio(_open(inpath, _O_BINARY | _O_RDONLY, _S_IREAD));
		if (modio == -1) throw fmt_exception("%s: %s", inpath, strerror(errno));
		__try { // termination handler
			IMAGE_DOS_HEADER dosheader;
			IMAGE_NT_HEADERS ntheader;
			if (_read(modio, &dosheader, sizeof dosheader) < sizeof dosheader
				|| dosheader.e_magic != IMAGE_DOS_SIGNATURE
				|| _lseek(modio, dosheader.e_lfanew, SEEK_SET) != dosheader.e_lfanew
				|| _read(modio, &ntheader, sizeof ntheader) < sizeof ntheader
				|| ntheader.Signature != IMAGE_NT_SIGNATURE
				|| ntheader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) throw;
			PIMAGE_EXPORT_DIRECTORY expdir;
			if (_expdir.Size > 0 && _lseek_by_rva(modio, _expdir.VirtualAddress) != -1
				&& (expdir = (PIMAGE_EXPORT_DIRECTORY)malloc(_expdir.Size)) != 0) {
				if (_read(modio, expdir, _expdir.Size) >= _expdir.Size)
					hasordinals = _ExpByOrd && expdir->NumberOfFunctions > 0;
				free(expdir);
			}
			if (!hasordinals) {
				IMAGE_THUNK_DATA thunk;
				DWORD dwRVAImportAddressTable;
				PROCESS_IMPTABLE(_impdir, IMAGE_IMPORT_DIRECTORY)
				if (!hasordinals) PROCESS_IMPTABLE(_delayimpdir, IMAGE_DELAY_IMPORT_DIRECTORY)
			} // no ordinal exports
		} __finally {
			_close(modio);
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		hasordinals = true; // don't know
	}
	if (!hasordinals) {
		//msg("[impbyord] no ordinal imports nor exports in current module, plugin disabled.\n");
		return PLUGIN_SKIP;
	}
#ifdef HOOKTOLOAD
	if (hooker.activate()) return PLUGIN_KEEP;
#endif
	return PLUGIN_OK;
}

static void idaapi term(void) {
#ifdef HOOKTOLOAD
	hooker.deactivate();
#endif
}

static void idaapi run(int arg) {
	BPX;
	try {
		switch (arg) {
			// Resolve imports
			case 0:
				if (imp_by_ord(false)) break; else return;
			// unattended ordinals fixup / this will run at on load but all data
			// exports are to be marked as functions / for more exact markup
			// call Ordinal imports resolver after autoanalysis done.
			case 1:
				imp_by_ord(true);
#ifdef HOOKTOLOAD
				if (hooker.deactivate()) PLUGIN.flags |= PLUGIN_UNL;
#endif
				return;
			// Resolve exports
			case 2:
				if (exp_by_ord()) break; else return;
			default:
				warning("this is not correct plugin parameter\n"
					"available parameters:\n"
					"0: manually resolve imports by selected implib\n"
					"1: unattended imports scan (should be called on new module only)\n"
					"2: manually resolve exports by selected implib");
				return;
		} // switch command
	} catch (const exception &e) {
		msg("%s, lame stoopid servil ;p\n", e.what());
		MessageBeep(MB_ICONERROR);
		warning("%s, lame stoopid servil ;p", e.what());
		return;
	} catch (...) {
		msg("%s, lame stoopid servil ;p\n", "unknown exception");
		MessageBeep(MB_ICONERROR);
		warning("%s, lame stoopid servil ;p", "unknown exception");
		return;
	}
	MessageBeep(MB_OK);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
#if IDP_INTERFACE_VERSION < 76
		if (ph.version != IDP_INTERFACE_VERSION) {
			char msg[MAX_PATH], tmp[MAX_PATH];
			GetModuleFileName(hinstDLL, CPY(msg));
			lstrcpyn(tmp, msg, qnumber(tmp));
			lstrcat(tmp, ".old");
			MoveFile(msg, tmp);
#ifdef wsprintfA
#undef wsprintfA
#endif // wsprintfA
			wsprintf(msg, "Cannot load plugin: this plugin is for IDP version %u (%i reported by kernel)\n\n"
				"Update or delete the plugin file", IDP_INTERFACE_VERSION, ph.version);
			MessageBox(get_ida_hwnd(), msg, PLUGINNAME " v" PLUGINVERSIONTEXT, MB_ICONEXCLAMATION | MB_OK);
			return FALSE;
		}
#endif // IDP_INTERFACE_VERSION
		DisableThreadLibraryCalls((HMODULE)hInstance = hinstDLL);
		se_exception::_set_se_translator();
#ifdef _DEBUG
		_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG);
		_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
		_CrtSetDbgFlag(/*_CRTDBG_CHECK_EVERY_1024_DF | */_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#else // !_DEBUG
		DWORD flOldProtect;
		VirtualProtect((PBYTE)hInstance + 0x16000, 0x6000, PAGE_READONLY, &flOldProtect);
#endif // _DEBUG
	}
	return TRUE;
}

// ================================ENTRY POINT================================
plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION, PLUGIN_MOD | PLUGIN_DRAW | PLUGIN_UNL,
	init, term, run,
	PLUGINNAME " v" PLUGINVERSIONTEXT, 0, "Ordinal imports resolver\x085", 0
};
// ================================ENTRY POINT================================
