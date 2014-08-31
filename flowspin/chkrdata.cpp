
#define NOMINMAX 1
#ifndef _DEBUG
#define PCRE_STATIC 1
#endif

#include <cstdlib>
#include <malloc.h>
#include "mscrtdbg.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <boost/smart_ptr.hpp>
#include <windows.h>
#pragma hdrstop
#include "../pcre.cpp"
#include "../dbgnew.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "WinMM.Lib")
#pragma comment(linker, "/subsystem:console")

using namespace std;

template<class _CharT, class _Traits>
static basic_ostream<_CharT, _Traits>& tab(basic_ostream<_CharT, _Traits>& __os) {
	__os.put(__os.widen('\t'));
	//__os.flush();
	return __os;
}

/////////////////////////////////////////////////////////////////////////////
// main function body - executable entry point
int main(int argc, char* argv[]) {
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_WNDW | _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
	_CrtSetDbgFlag(/*_CRTDBG_CHECK_EVERY_1024_DF | */_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	cout << "chkrdata v1.0 - personal tool for updating r/o attribute of .rdata section in" << endl <<
		"unpacked executable, (c) 2006-2008 servil" << endl;
	if (argc < 3) {
		cerr << "usage: chkrdata <executable> <sourcefile>" << endl <<
			tab << "<exefile> full path to compiled module quoted if spaced" << endl <<
			tab << "<sourcefile> full path to sourcefile quoted if spaced" << endl;
		return 1;
	}
	try {
		fstream pefile(argv[1], ios_base::in | ios_base::out | ios_base::binary);
		if (!pefile) throw logic_error("couldnot open binary");
		DWORD virtaddr(0);
		SIZE_T physize(0);
		IMAGE_DOS_HEADER doshdr;
		IMAGE_NT_HEADERS nthdr;
		IMAGE_SECTION_HEADER section;
		if (!pefile.seekg(0, ios_base::beg).read((char *)&doshdr, sizeof doshdr)
			|| doshdr.e_magic != IMAGE_DOS_SIGNATURE
			|| !pefile.seekg(doshdr.e_lfanew, ios_base::beg).read((char *)&nthdr, sizeof nthdr)
			|| nthdr.Signature != IMAGE_NT_SIGNATURE
			|| nthdr.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			throw logic_error("binary is not valid PE32 image");
		for (WORD index = 0; index < nthdr.FileHeader.NumberOfSections; ++index) {
			if (!pefile.read((char *)&section, sizeof section))
				throw logic_error("couldnot read section header");
			if (section.Characteristics == (IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA)) {
				physize = section.Misc.VirtualSize/*section.SizeOfRawData*/;
				virtaddr = section.VirtualAddress;
				cout << argv[1] << ": .rdata section at 0x" << hex << setfill('0') <<
					uppercase << setw(8) << section.VirtualAddress << " size=0x" << hex <<
					setw(8) << section.Misc.VirtualSize << ' ' <<
					string((const char *)section.Name, 8) << endl;
				break;
			}
		}
		if (virtaddr == 0 || physize == 0)
			throw logic_error(".rdata section not found in binary");
		ifstream srcfile(argv[2]);
		if (!srcfile) throw logic_error("couldnot open source");
		// "		VirtualProtect((LPVOID)((PBYTE)hInstance + 0xD000), 0x4000, PAGE_READONLY, &flOldProtect);"
		const PCRE::regexp linematch("^\\s*VirtualProtect\\(\\s*(.*?)\\s*,\\s*(.*?)\\s*,\\s*(?:.*?)\\s*,\\s*(?:.*?)\\s*\\)", 0, true);
		if (!linematch) throw logic_error("couldnot compile regular expression");
		const PCRE::regexp argmatch("(?:\\w+\\s*\\+\\s*)?([\\+\\-]?\\b(?i:0x)?[[:xdigit:]]+\\b)", 0, true);
		if (!argmatch) throw logic_error("couldnot compile regular expression");
		while (srcfile.good()) {
			string line;
			getline(srcfile, line);
			if (srcfile.eof()) break;
			if (srcfile.fail()) throw logic_error("couldnot read line from source");
			const PCRE::regexp::result match(linematch, line);
			if (match >= 3) {
				const PCRE::regexp::result MATCH[] = {
					PCRE::regexp::result(argmatch, match[1]),
					PCRE::regexp::result(argmatch, match[2]),
				};
				if (MATCH[0] >= 2 && MATCH[1] >= 2) {
					unsigned long rdatarva(strtoul(MATCH[0][1], 0, 0));
					if (rdatarva != virtaddr) cout << argv[2] <<
						": .rdata RVA mismatch (source:0x" << hex << uppercase <<
						rdatarva << " binary:0x" << hex << virtaddr << ')' << endl;
					unsigned long rdatasize(strtoul(MATCH[1][1], 0, 0));
					if (rdatasize != physize) cout << argv[2] <<
						": .rdata size mismatch (source:0x" << hex << uppercase <<
						rdatasize << " binary:0x" << hex << physize << ')' << endl;
					if (rdatarva == virtaddr && rdatasize == physize) {
						cout << argv[2] << ": .rdata RVA and size match (nothing to do)" << endl;
						return 0;
					}
					// locate .code section
					for (index = 0; index < nthdr.FileHeader.NumberOfSections; ++index) {
						if (!pefile.seekg(doshdr.e_lfanew + sizeof IMAGE_NT_HEADERS +
							sizeof IMAGE_SECTION_HEADER * index, ios_base::beg).read((char *)&section, sizeof section))
							throw logic_error("couldnot read section header");
						if ((section.Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE))
							== (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) {
							boost::shared_ptr<void> buf(malloc(section.Misc.VirtualSize), free);
							if (!buf) throw bad_alloc();
							if (!pefile.seekg(section.PointerToRawData,
								ios_base::beg).read((char *)buf.get(), section.Misc.VirtualSize))
								throw logic_error("couldnot read code section");
							/*
							8B15 6451E612    mov  edx,[12E65164]
							81C2 00700300    add  edx,000037000
							8D8424 08030000  lea  eax,[esp][00000308]
							50               push eax
							6A 02            push 002
							68 00C00000      push 00000C000
							52               push edx
							FF15 F871E512    call VirtualProtect ;KERNEL32
							-----------------------------------------------------
							8B15 E45EF912    mov  edx,[12F95EE4]
							81C2 00F00000    add  edx,00000F000
							8D0424           lea  eax,[esp]
							50               push eax
							6A 02            push 002
							68 00400000      push 000004000
							52               push edx
							FF15 EC00F912    call VirtualProtect ;KERNEL32
							-----------------------------------------------------
							8B15 A0EEF812    mov  edx,[12F8EEA0]
							81C2 00200500    add  edx,000052000  ---  (3)
							8D45D4           lea  eax,[ebp][-2C]
							50               push eax
							6A 02            push 002
							68 00090100      push 000010900  ---  (4)
							52               push edx
							FF15 7013F712    call VirtualProtect ;KERNEL32
							*/
							static unsigned char pattern1[] = {
								0x81, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x8D,
							};
							*(LPDWORD)((LPBYTE)pattern1 + 0x02) = rdatarva;
							static unsigned char pattern2[] = {
								0x50, 0x6A, 0x02, 0x68, 0x00, 0x00, 0x00, 0x00, 0x52, 0xFF, 0x15,
							};
							*(LPDWORD)((LPBYTE)pattern2 + 0x04) = rdatasize;
							for (unsigned long offset = 0; offset < section.Misc.VirtualSize; ++offset) {
								if (rdatarva != virtaddr
									&& memcmp((LPBYTE)buf.get() + offset, pattern1, sizeof pattern1) == 0
									&& (*((LPBYTE)buf.get() + offset + 0x08) == 0x24
									|| *((LPBYTE)buf.get() + offset + 0x08) == 0xD4)) {
									*(LPDWORD)((LPBYTE)buf.get() + offset + 0x02) = virtaddr;
									rdatarva = virtaddr;
								} else if (rdatasize != physize
									&& memcmp((LPBYTE)buf.get() + offset, pattern2, sizeof pattern2) == 0) {
									*(LPDWORD)((LPBYTE)buf.get() + offset + 0x04) = physize;
									rdatasize = physize;
								}
								if (rdatarva == virtaddr && rdatasize == physize) {
									if (!pefile.seekp(section.PointerToRawData,
										ios_base::beg).write((char *)buf.get(), section.Misc.VirtualSize))
										throw logic_error("couldnot update binary (write failed)");
									cout << argv[1] << ": executable updated successfully" << endl;
									MessageBeep(MB_ICONWARNING); //PlaySound("#1", GetModuleHandle(NULL), SND_RESOURCE | SND_ASYNC);
									return 0;
								} // match
							} // walk section
						} // code section
					} // loop sections
					throw logic_error(string(argv[1]).append(": couldnot update executable (pattern(s) not found)"));
				} // MATCH[0] >= 2 && MATCH[1] >= 2
			} // match >= 3
		} // srcfile.good()
		cerr << argv[2] << "%s: pattern not found!" << endl;
		return 0;
	} catch (const exception &e) {
		cerr << "caught exception: " << e.what() << endl;
	} catch (...) {
		cerr << "program unexpected error (blame lame servil)" << endl;
	}
	MessageBeep(MB_ICONERROR);
	return -1;
}
