#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <iomanip>

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
#define PAGE_SIZE 4096


FILE *fp;
IMAGE_SECTION_HEADER *SC_Header = NULL;
LPVOID ImageBase = NULL;
int section_count;
IMAGE_OPT_HEADER OPT_Header;


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
	section_count = FLh.NumberOfSections;
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
			if (strcmp((const char*)in_SCHeader[i].Name, ".text") == 0) {
				printf("Skipping section %s to lazy load, section address %p\n", (const char*)in_SCHeader[i].Name, (BYTE*)ImageBase + in_SCHeader[i].VirtualAddress);
				
				DWORD old;
				VirtualProtect(dest, in_SCHeader[i].Misc.VirtualSize, PAGE_NOACCESS, &old);
				continue;
			}
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
		if (size < sizeof(IMAGE_BASE_RELOCATION)) {printf("Invalid SizeOfBlock\n"); return FALSE;}
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
	if (strcmp((const char*)sec->Name, ".text") == 0) {
		printf("changeProtection() for .text section being skipped!\n");
		return TRUE;
	}
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

BOOL doExceptionTable(IMAGE_OPT_HEADER *inOh, LPVOID ImageBase) {
	IMAGE_DATA_DIRECTORY exceptionDir = inOh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if(exceptionDir.Size == 0 || exceptionDir.VirtualAddress == 0) {printf("exceptionDir size or address is equal to 0\n");return FALSE;}
	PIMAGE_RUNTIME_FUNCTION_ENTRY ptable = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((BYTE*)ImageBase + exceptionDir.VirtualAddress);
	
	DWORD entriesCount = (DWORD)(exceptionDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
	if(RtlAddFunctionTable((PRUNTIME_FUNCTION)ptable, entriesCount, (DWORD64)ImageBase)) {
	   printf("doExceptionTable() succeeded!\n");
	} else {printf("RtlAddFunctionTable failed!\n"); return FALSE;}

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

//NEEDS FIX
BOOL doRelocsForPage(IMAGE_OPT_HEADER *inOpt, LPVOID ImageBase, ULONG_PTR pageStart) {
	if (inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) return TRUE;
	BYTE *relocStart = (BYTE*)ImageBase + inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	BYTE *relocEnd = relocStart + inOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;  
	ULONGLONG delta = (ULONGLONG)((BYTE*)ImageBase - inOpt->ImageBase);
	if (delta == 0) { 
	printf("ImageBase is correct\n");
	return TRUE;}
	DWORD targetPageRVA = (DWORD)(pageStart - (ULONG_PTR)ImageBase);

	while (relocStart < relocEnd) {
	IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)relocStart;
	DWORD base = block->VirtualAddress;
	DWORD size = block->SizeOfBlock;
	if (size == 0) {break;} 
	if (size < sizeof(IMAGE_BASE_RELOCATION)) {printf("doRelocsForPage() Invalid SizeOfBlock\n"); return FALSE;}

	if (base <= targetPageRVA &&
    targetPageRVA < base + 0x1000) {
		WORD *entries = (WORD*)(block + 1);

		DWORD count = ((size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
		for(DWORD i = 0; i < count; ++i) {
			WORD type = entries[i] >> 12;
			WORD offset = entries[i] & 0x0FFF;

			BYTE* addresstopatch = (BYTE*)ImageBase + base + offset;

			if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                *(DWORD*)addresstopatch += (DWORD)delta;
            } else if (type == IMAGE_REL_BASED_DIR64) {
                *(ULONGLONG*)addresstopatch += delta;
            }
		}
	}
		relocStart = (BYTE*)block + block->SizeOfBlock;
	}
	return TRUE;
}
//NEEDS FIX



//NEEDS FIX
LONG CALLBACK PageFaultHandler(PEXCEPTION_POINTERS ExceptionsInfo) {
	std::ofstream os("output.txt", std::ios::app);
	os << "\n\n\n\n";
	if (ExceptionsInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
	ULONG_PTR faultAddr = ExceptionsInfo->ExceptionRecord->ExceptionInformation[1];
	
	for (int i = 0; i < section_count; ++i) {
		
		ULONG_PTR start = (ULONG_PTR)ImageBase + SC_Header[i].VirtualAddress;
		ULONG_PTR end = start + SC_Header[i].Misc.VirtualSize;

	if (faultAddr >= start && faultAddr < end) {
		os << std::hex << "Fault found, " << std::setw(16) << std::setfill('0') << faultAddr << '\n'; 
		//printf("Fault found, %p  \n", faultAddr);
		ULONG_PTR pageStart = faultAddr & ~0xFFF; 
		VirtualAlloc((LPVOID)pageStart, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);

		DWORD offset = (DWORD)(pageStart - start);
		DWORD fileOffset = SC_Header[i].PointerToRawData + offset;
		
		if (fp) {
		os << std::hex << "Writing data for" << std::setw(16) << std::setfill('0') << faultAddr << "\n";
		//printf("Writing data for %p\n", faultAddr);
		fseek(fp, fileOffset, SEEK_SET);
		os << std::hex << "FSeek for " << std::setw(16) << std::setfill('0') << faultAddr << "\n";
		//printf("FSeek for %p\n", faultAddr);
		if (size_t result = fread((LPVOID)pageStart, sizeof(BYTE), PAGE_SIZE, fp); result != PAGE_SIZE) {
			os << std::hex << "fread() for " << std::setw(16) << std::setfill('0') << faultAddr << " returned " << std::dec << result <<'/' << PAGE_SIZE << '\n'; 
			//printf("fread() for %p returned %d/%d\n", faultAddr, result, PAGE_SIZE);
		} else {
			os << std::hex << "everything is done for " << std::setw(16) << std::setfill('0') << faultAddr << '\n'; 
			//printf("everything is done for %p\n", faultAddr);
			   }
		}

		//APPLY RELOCS FOR PAGE HERE
		if (doRelocsForPage(&OPT_Header, ImageBase, pageStart)) {
			os << std::hex << "Relocations done for " << std::setw(16) << std::setfill('0') << faultAddr << '\n'; 
			//printf("Relocations done for %p!\n", faultAddr);
		}
		//APPLY RELOCS FOR PAGE HERE
		DWORD old;
		VirtualProtect((LPVOID)pageStart, PAGE_SIZE, PAGE_EXECUTE_READ, &old);
		os << std::hex << "Virtual Protect is set to PAGE_EXECUTE_READ, retrying for " << std::setw(16) << std::setfill('0') << faultAddr << '\n'; 
		//printf("Virtual Protect is set to PAGE_EXECUTE_READ, retrying for %p!\n", faultAddr);
		FlushInstructionCache(GetCurrentProcess(), (LPVOID)pageStart, PAGE_SIZE);
		return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
  }
  return EXCEPTION_CONTINUE_SEARCH;
}
//NEEDS FIX

int main() {
	int argc = 0;
	IMAGE_DOS_HEADER MZ_Header;
	DWORD Signature;
	IMAGE_FILE_HEADER FL_Header;
	//WCHAR **argv;
	WCHAR flname[MAX_PATH];
	WCHAR path[MAX_PATH] = L"D:\\!! MSVC Projects\\!! STEALER\\TEST STEALER DIR\\x64\\Release\\myprog.exe";
	RtlSecureZeroMemory(flname, MAX_PATH);

	//argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	//if (argc == 2) {
		wcscpy_s(flname, MAX_PATH, path);
		_wfopen_s(&fp, flname, L"rb");
		
		if (fp) {	
			if (readPE(fp, &MZ_Header, &Signature, &FL_Header, &OPT_Header, &SC_Header)) {
				SIZE_T imageSize = //calcTotalSizeImage(&MZ_Header, &Signature, &FL_Header, &OPT_Header, SC_Header)
									OPT_Header.SizeOfImage;
				printf("Image Size = %d\n", imageSize);
				ImageBase = VirtualAlloc(NULL, imageSize, MEM_RESERVE |
					MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (ImageBase) {
					printf("Image Base address = %p\n", ImageBase);
					if (loadPE(fp, &MZ_Header, &Signature, &FL_Header, &OPT_Header, SC_Header, ImageBase)) {
						printf("LoadPE successful!\n");
						if (doImports(&OPT_Header, ImageBase)) {
							printf("doImports succeeded!\n");
							//IMPORTANTIMPORTANTIMPORTANTIMPORTANTIMPORTANTIMPORTANTIMPORTANT
							//if (doRelocs(&OPT_Header, ImageBase)) {
								printf("Relocation patch is successful!\n"); 
								for (SIZE_T i = 0; i < FL_Header.NumberOfSections; i++) {
									if (!changeProtection(&SC_Header[i], ImageBase)) {printf("changeProtection for SC_Header[%d] failed!\n", i); return FALSE;}
								}
								if (callTLScallbacks(&OPT_Header, ImageBase, DLL_PROCESS_ATTACH)) 
								{
									if(doExceptionTable(&OPT_Header, ImageBase)) {

										if (AddVectoredExceptionHandler(1, PageFaultHandler) != NULL) {
											printf("AddVectoredExceptionHandler succeeded starting, executing!!!!\n");
											//__debugbreak();
											callDLL_EntryPoint(&OPT_Header, ImageBase);
											//callEXE_EntryPoint(&OPT_Header, ImageBase);
										} printf("AddVectoredExceptionHandler failed!\n"); fclose(fp); free(SC_Header); VirtualFree(ImageBase, 0, MEM_RELEASE);  return 1;}
									} else {printf("Exception Tables failed!\n"); fclose(fp); free(SC_Header); VirtualFree(ImageBase, 0, MEM_RELEASE);  return 1;}
								}
								else {printf("TLS Callbacks failed!\n"); fclose(fp); free(SC_Header); VirtualFree(ImageBase, 0, MEM_RELEASE);  return 1;}
							//} else {printf("Relocs patch is failed!\n"); fclose(fp); free(SC_Header); VirtualFree(ImageBase, 0, MEM_RELEASE); return 1;}
							//IMPORTANTIMPORTANTIMPORTANTIMPORTANTIMPORTANTIMPORTANTIMPORTANT
						} else {printf("Imports failed!\n"); fclose(fp);free(SC_Header); VirtualFree(ImageBase, 0, MEM_RELEASE); return 1;}
					}
					else {printf("LoadPE failed!\n"); fclose(fp); free(SC_Header); VirtualFree(ImageBase, 0, MEM_RELEASE); return 1;}
				}
				else { printf("Allocation failed!\n"); fclose(fp); free(SC_Header); VirtualFree(ImageBase, 0, MEM_RELEASE); return 1; }
			} else {printf("readPE failed!\n"); fclose(fp); free(SC_Header);  return 1;}
		//}
		//else { printf("Not enough args!\n"); return 1; }
		fclose(fp); free(SC_Header); VirtualFree(ImageBase, 0, MEM_RELEASE);

	printf("Success!\n");
}
