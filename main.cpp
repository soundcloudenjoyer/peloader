#include <Windows.h>
#include <stdio.h>
#include <string.h>


#define DOS_HEADER_SIZE sizeof(IMAGE_DOS_HEADER)
#define FILE_HEADER_SIZE sizeof(IMAGE_FILE_HEADER)
#define SIGNATURE_SIZE sizeof(DWORD)
#define SECTION_HEADER_SIZE sizeof(IMAGE_SECTION_HEADER)

#ifdef _WIN64 
#define OPT_HEADER_SIZE sizeof(IMAGE_OPTIONAL_HEADER64)		
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPT_HEADER;
typedef _IMAGE_TLS_DIRECTORY64 TLS_DIRECTORY;
typedef DWORD(*EntryFn)();
typedef BOOL(WINAPI *DLLMain)(HINSTANCE, DWORD, LPVOID);
#else 
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPT_HEADER;
typedef _IMAGE_TLS_DIRECTORY32 TLS_DIRECTORY;
#define OPT_HEADER_SIZE sizeof(IMAGE_OPTIONAL_HEADER32)
#endif
 

BOOL readPE(FILE* inF, IMAGE_DOS_HEADER* outMZ, DWORD* sig, IMAGE_FILE_HEADER* outFL, IMAGE_OPT_HEADER* outOPT, IMAGE_SECTION_HEADER** outSEC) {
	IMAGE_DOS_HEADER MZh;
	DWORD SG;
	IMAGE_FILE_HEADER FLh;
	IMAGE_OPT_HEADER OPh;
	IMAGE_SECTION_HEADER *SCh;

	fseek(inF, 0, SEEK_END);
	long fileSize = ftell(inF);
	fseek(inF, 0, SEEK_SET);
	if (fileSize < DOS_HEADER_SIZE) { printf("Binary size is smaller than MZ_Header\n"); return FALSE; }

	
	if (fread(&MZh, DOS_HEADER_SIZE, 1, inF) != 1) {printf("DOS Header wasn't read\n"); return FALSE;}
	if (MZh.e_magic != 0x5a4d) { printf("It isn't a PE-file\n");  return FALSE; }
	if (fileSize < (MZh.e_lfanew + SIGNATURE_SIZE + FILE_HEADER_SIZE + OPT_HEADER_SIZE)) { printf("File is too small or corrupted\n");  return FALSE; }

	fseek(inF,MZh.e_lfanew, SEEK_SET);
	if (fread(&SG, SIGNATURE_SIZE, 1, inF) != 1) {printf("Signature wasn't read\n"); return FALSE;}
	if (SG != 0x4550) { printf("Siganture is broken\n"); SG = 0x4550; }
	if (fread(&FLh, FILE_HEADER_SIZE, 1, inF) != 1) {printf("File Header wasn't read\n"); return FALSE;}

	printf("Section count: %d", FLh.NumberOfSections); printf("\nOptional Header Size: %d \n", (int)FLh.SizeOfOptionalHeader);
	if (FLh.SizeOfOptionalHeader != OPT_HEADER_SIZE) { printf("Optional Header size is wrong\n");  return FALSE; }

	if (fread(&OPh, OPT_HEADER_SIZE, 1, inF) != 1) {printf("Optional Header wasn't read\n"); return FALSE;} 
	printf("Import table address = %X\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	printf("Import table size = %d\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	printf("Import address table address = %X\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	printf("Import address table address size = %d\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
	
	if (fileSize < (ftell(inF) + SECTION_HEADER_SIZE * (FLh.NumberOfSections))) { printf("File is too small (Sections)\n");  return FALSE; }
	SCh = (IMAGE_SECTION_HEADER*)malloc(SECTION_HEADER_SIZE * (FLh.NumberOfSections));
	if (fread(SCh,(SECTION_HEADER_SIZE * (FLh.NumberOfSections)), 1, inF) != 1) {printf("Sections weren't read\n"); return FALSE;}
	
	*outMZ = MZh;
	*outFL = FLh;
	*sig = SG;
	*outOPT = OPh;
 	*outSEC = SCh;

	return TRUE;
}

BOOL loadPE(FILE *fp, IMAGE_DOS_HEADER* in_MZHeader, 
	DWORD* in_Signature, IMAGE_FILE_HEADER* in_FILEHeader, 
	IMAGE_OPT_HEADER* in_OPTHeader, 
	IMAGE_SECTION_HEADER* in_SCHeader, LPVOID ImageBase) 
{

	unsigned long sizeofheaders = in_OPTHeader->SizeOfHeaders;
	size_t readSize;
	int i;

	fseek(fp, 0, SEEK_SET);

	for (i = 0; i < in_FILEHeader->NumberOfSections; ++i) {
		if (in_SCHeader[i].PointerToRawData < sizeofheaders) {
			sizeofheaders = in_SCHeader[i].PointerToRawData;
		}
	}

	readSize = fread(ImageBase, 1, sizeofheaders , fp);
	printf("Header Size = %d\n", sizeofheaders);
	if (readSize != sizeofheaders) { printf("readSize != sizeofheaders\n"); return FALSE; }
	printf("Reading headers successful!\n");


	for (i = 0; i < in_FILEHeader->NumberOfSections; ++i) {
		BYTE* dest = (BYTE*)ImageBase + in_SCHeader[i].VirtualAddress;
		if (in_SCHeader[i].SizeOfRawData > 0) {
			unsigned long toRead = in_SCHeader[i].SizeOfRawData;
			fseek(fp, in_SCHeader[i].PointerToRawData, SEEK_SET);
			readSize = fread(dest, 1, toRead, fp);
			if (readSize != toRead) { printf("Error reading section\n"); return FALSE; }
			if (in_SCHeader[i].Misc.VirtualSize > in_SCHeader[i].SizeOfRawData) {
				memset(dest + in_SCHeader[i].SizeOfRawData, 0, in_SCHeader[i].Misc.VirtualSize - in_SCHeader[i].SizeOfRawData);
			}
		}
		else {
			if (in_SCHeader[i].Misc.VirtualSize) 
			{
				memset(dest, 0, in_SCHeader[i].Misc.VirtualSize);
			}
		}
	} 

	return TRUE;
}
BOOL doImports(IMAGE_OPT_HEADER* inOPT, LPVOID ImageBase) {
	IMAGE_DATA_DIRECTORY ImportDIR = inOPT->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (ImportDIR.Size == 0) { return TRUE; }

	IMAGE_IMPORT_DESCRIPTOR* importdesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)ImageBase + ImportDIR.VirtualAddress);
	for (; importdesc->Name != 0; ++importdesc) {
		CHAR* dllname = (CHAR*)((BYTE*)ImageBase + importdesc->Name);
		HMODULE hMod = NULL;

		hMod = GetModuleHandleA(dllname);
		if (!hMod) { hMod = LoadLibraryA(dllname); }
		if (!hMod) { printf("Library %s wasn't loaded\n", dllname); return FALSE; }
		IMAGE_THUNK_DATA* ilt = (IMAGE_THUNK_DATA*)((BYTE*)ImageBase + importdesc->OriginalFirstThunk);
		IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)((BYTE*)ImageBase + importdesc->FirstThunk);

		if (importdesc->OriginalFirstThunk == 0) { ilt = iat; };

		for (; ilt->u1.AddressOfData != 0; ilt++, iat++) {
			FARPROC fn;
			if (ilt->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				WORD ord = (WORD)(ilt->u1.Ordinal & 0xFFFF);
				fn = GetProcAddress(hMod, (LPCSTR)ord);
				if (fn == NULL) { printf("GetProcAdress() for ordinal %d failed\n", ord); return FALSE; }
				iat->u1.Function = (ULONGLONG)fn;
			} else 
			{
				IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)((BYTE*)ImageBase + ilt->u1.AddressOfData);
				CHAR* funcName = (CHAR*)ibn->Name;
				fn = GetProcAddress(hMod, funcName);
				if (fn == NULL) { printf("GetProcAdress(%s) failed\n", funcName); return FALSE; }
				iat->u1.Function = (ULONGLONG)fn;
			}
		}
	}
	return TRUE;
}

BOOL doRelocs(IMAGE_OPT_HEADER *inOpt, LPVOID ImageBase) {

	if (inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) return TRUE;
	BYTE *relocStart = (BYTE*)ImageBase + inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	BYTE *relocEnd = relocStart + inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;  
	ULONGLONG delta = (ULONGLONG)((BYTE*)ImageBase - inOpt->ImageBase);
	if (delta == 0) { 
	printf("ImageBase is correct\n");
	return TRUE;}

	while (relocStart < relocEnd) {
		IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)relocStart;
		DWORD base = block->VirtualAddress;
		DWORD size = block->SizeOfBlock;
		if (size == 0) {break;} 
		if (size < sizeof(IMAGE_BASE_RELOCATION)) {printf("Inval SizeOfBlock\n"); return FALSE;}
		WORD *entries = (WORD*)(block + 1);

		DWORD count = ((size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
		for (DWORD i = 0; i < count; ++i) {
			WORD type = entries[i] >> 12;
			WORD offset = entries[i] & 0x0FFF;

			BYTE* addresstopatch = (BYTE*)ImageBase + base + offset;

			if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
			else if (type == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)addresstopatch += delta;
			else if (type == IMAGE_REL_BASED_DIR64) *(ULONGLONG*)addresstopatch += delta;
			else { printf("doRelocs failed, type is unknown\n"); return FALSE;}
		}
		relocStart = (BYTE*)block + block->SizeOfBlock;
	}
	return TRUE;
}

DWORD characteristicsToProtect(DWORD ch) {
    bool r = ch & IMAGE_SCN_MEM_READ;
    bool w = ch & IMAGE_SCN_MEM_WRITE;
    bool x = ch & IMAGE_SCN_MEM_EXECUTE;

    if (x) {
        if (w) return PAGE_EXECUTE_READWRITE;
        if (r) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    } else {
        if (w) return PAGE_READWRITE;
        if (r) return PAGE_READONLY;
        return PAGE_NOACCESS;
    }
}

BOOL changeProtection(IMAGE_SECTION_HEADER* sec, LPVOID ImageBase) {
	DWORD oldprotect;
	LPVOID secBase = (BYTE*)ImageBase + sec->VirtualAddress;
	SIZE_T size = sec->Misc.VirtualSize;

	if (size == 0) return TRUE;
	DWORD prot = characteristicsToProtect(sec->Characteristics);

	return VirtualProtect(secBase, size, prot, &oldprotect);
}

BOOL callTLScallbacks(IMAGE_OPT_HEADER *inOh, LPVOID ImageBase, DWORD dwReason) {
	 if (inOh->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0) {printf("TLS callbacks are empty!\n"); return TRUE;}
	 TLS_DIRECTORY* tlsDir = (TLS_DIRECTORY*)((BYTE*)ImageBase + inOh->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	 if (tlsDir->AddressOfCallBacks == 0) {printf("AddressOfCallback is 0!\n"); return TRUE;}
	 PIMAGE_TLS_CALLBACK *callbacks = (PIMAGE_TLS_CALLBACK*)((BYTE*)ImageBase + (tlsDir->AddressOfCallBacks - inOh->ImageBase));
	 if (callbacks == NULL) {printf("There aren't any callbacks!\n"); return TRUE;}
	 for (SIZE_T i = 0; callbacks[i]; i++) {
		callbacks[i](ImageBase, dwReason, NULL);
		printf("Callback №%d called", i);
	}
	return TRUE;
}

BOOL callDLL_EntryPoint(IMAGE_OPTIONAL_HEADER *inOh, LPVOID ImageBase) {
    DLLMain entry = (DLLMain)((BYTE*)ImageBase + inOh->AddressOfEntryPoint);
    
    printf("Calling DLL entry at %p...\n", (void*)entry);
    try {
        BOOL result = entry((HINSTANCE)ImageBase, DLL_PROCESS_ATTACH, NULL);
        if (result) {
            printf("Entry point called successfully!\n");
            return TRUE;
        } else {
            printf("DllMain returned FALSE!\n");
            return FALSE;
        }
    } 
    catch(...) {
        printf("Exception while entry point call!\n");
        return FALSE;
    }
}
BOOL callEXE_EntryPoint(IMAGE_OPT_HEADER *inOh, LPVOID ImageBase) {
	EntryFn entry = (EntryFn)((BYTE*)ImageBase + inOh->AddressOfEntryPoint);
	printf("Calling EXE entry at %p...\n", entry);
	try {
		entry();
		printf("Entry point called successfullly!\n");
		return TRUE;
	} catch(...) {
		printf("Exception while entry point call!\n");
		return FALSE;
	}
}

int main() {
	int argc = 0;
	FILE *fp;
	IMAGE_DOS_HEADER MZ_Header;
	DWORD Signature;
	IMAGE_FILE_HEADER FL_Header;
	IMAGE_OPT_HEADER OPT_Header;
	IMAGE_SECTION_HEADER *SC_Header;
	WCHAR **argv;
	WCHAR flname[MAX_PATH];
	LPVOID ImageBase;
	RtlSecureZeroMemory(flname, MAX_PATH);

	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc == 2) {
		wcscpy_s(flname, MAX_PATH, argv[1]);
		_wfopen_s(&fp, flname, L"rb");
		
		if (fp) {	
			if (readPE(fp, &MZ_Header, &Signature, &FL_Header, &OPT_Header, &SC_Header)) {
				SIZE_T imageSize = //calcTotalSizeImage(&MZ_Header, &Signature, &FL_Header, &OPT_Header, SC_Header)
									OPT_Header.SizeOfImage;
				printf("Image Size = %d\n", imageSize);
				ImageBase = VirtualAlloc(NULL, imageSize, //MEM_RESERVE |
					MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (ImageBase) {
					printf("Image Base address = %p\n", ImageBase);
					if (loadPE(fp, &MZ_Header, &Signature, &FL_Header, &OPT_Header, SC_Header, ImageBase)) {
						printf("LoadPE successful!\n");
						if (doImports(&OPT_Header, ImageBase)) {
							printf("doImports succeeded!\n");
							if (doRelocs(&OPT_Header, ImageBase)) {
								printf("Relocation patch is successful!\n"); 
								for (SIZE_T i = 0; i < FL_Header.NumberOfSections; i++) {
									if (!changeProtection(&SC_Header[i], ImageBase)) {printf("changeProtection for SC_Header[%d] failed!\n", i); return FALSE;}
								}
								if (callTLScallbacks(&OPT_Header, ImageBase, DLL_PROCESS_ATTACH)) 
								{
									callDLL_EntryPoint(&OPT_Header, ImageBase);
									//callEXE_EntryPoint(&OPT_Header, ImageBase);
								}
								else {printf("TLS Callbacks failed!\n"); return FALSE;}
							} else {printf("Relocs patch is failed!\n");}
						} else {printf("Imports failed!\n");}
					}
					else {printf("LoadPE failed!\n");}
				}
				else { printf("Allocation failed!\n"); return 1; }
			}
		}
		else { printf("File doesn't open!\n"); return 1; }
		fclose(fp);
	} 
	else { printf("Not enough args!\n"); return 1; }

	printf("Success!\n");
}
