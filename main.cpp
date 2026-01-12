#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <iomanip>
#include <iostream>

typedef struct _SIGNATURE {
	DWORD signature;
} SIGNATURE;

#define DOS_HEADER_SIZE sizeof(IMAGE_DOS_HEADER)
#define FILE_HEADER_SIZE sizeof(IMAGE_FILE_HEADER)
#define SIGNATURE_SIZE sizeof(SIGNATURE)
#define SECTION_HEADER_SIZE sizeof(IMAGE_SECTION_HEADER)

#ifdef _WIN64 
#define OPT_HEADER_SIZE sizeof(IMAGE_OPTIONAL_HEADER64)		
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPT_HEADER;
#else 
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPT_HEADER;
#define OPT_HEADER_SIZE sizeof(IMAGE_OPTIONAL_HEADER32)
#endif

BOOL readPE(FILE* inF, IMAGE_DOS_HEADER* outMZ, SIGNATURE* sig, IMAGE_FILE_HEADER* outFL, IMAGE_OPT_HEADER* outOPT, IMAGE_SECTION_HEADER** outSEC) {
	IMAGE_DOS_HEADER MZh;
	SIGNATURE SG;
	IMAGE_FILE_HEADER FLh;
	IMAGE_OPT_HEADER OPh;
	IMAGE_SECTION_HEADER *SCh;

	fseek(inF, 0, SEEK_END);
	long fileSize = ftell(inF);
	fseek(inF, 0, SEEK_SET);
	if (fileSize < DOS_HEADER_SIZE) { printf("Binary size is smaller than MZ_Header\n"); return FALSE; }

	
	fread(&MZh, DOS_HEADER_SIZE, 1, inF);
	if (MZh.e_magic != 0x5a4d) { printf("It isn't a PE-file\n");  return FALSE; }
	if (fileSize < (MZh.e_lfanew + SIGNATURE_SIZE + FILE_HEADER_SIZE)) { printf("File is too small or corrupted\n");  return FALSE; }

	fseek(inF,MZh.e_lfanew, SEEK_SET);
	fread(&SG, SIGNATURE_SIZE, 1, inF);
	if (SG.signature != 0x4550) { printf("Siganture is broken\n"); SG.signature = 0x4550; }
	fread(&FLh, FILE_HEADER_SIZE, 1, inF);

	printf("Section count: %d", FLh.NumberOfSections); printf("\nOptional Header Size: %d \n", (int)FLh.SizeOfOptionalHeader);
	if (FLh.SizeOfOptionalHeader != OPT_HEADER_SIZE) { printf("Optional Header size is wrong\n");  return FALSE; }

	fread(&OPh, OPT_HEADER_SIZE, 1, inF);
	printf("Import table address = %X\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	printf("Import table size = %d\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	printf("Import address table address = %X\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	printf("Import address table address size = %d\n", OPh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
	
	SCh = (IMAGE_SECTION_HEADER*)malloc(SECTION_HEADER_SIZE * (FLh.NumberOfSections));
	fread(SCh,(SECTION_HEADER_SIZE * (FLh.NumberOfSections)), 1, inF);
	
	*outMZ = MZh;
	*outFL = FLh;
	*sig = SG;
	*outOPT = OPh;
 	*outSEC = SCh;

	return TRUE;
}

/*int calcTotalSizeImage(IMAGE_DOS_HEADER* inMZ, SIGNATURE* inSig, IMAGE_FILE_HEADER* inFile, IMAGE_OPT_HEADER* inOpt, IMAGE_SECTION_HEADER* inSec) {
	int result = 0;
	int v, i;
	int alignment = inOpt->SectionAlignment;

	if ((inOpt->SizeOfHeaders % alignment) == 0) {
		result += inOpt->SizeOfHeaders;
	}
	else 
	{
		v = (inOpt->SizeOfHeaders / alignment);
		v++;
		result += (v * alignment);
	}

	for (i = 0; i < inFile->NumberOfSections; i++) {
		if (inSec[i].Misc.VirtualSize) {
			if (inSec[i].Misc.VirtualSize % alignment == 0) {
				result += inSec[i].Misc.VirtualSize;
			}
			else {
				v = (inSec[i].Misc.VirtualSize / alignment);
				v++;
				result += (v * alignment);
			}
		}
	}
	return result;
}*/
unsigned long getAlignedSize(unsigned long sizeofheaders, unsigned long sectionalignment) {
	if (sizeofheaders % sectionalignment == 0) {
		return sizeofheaders;
	}
	else {
		int v = (sizeofheaders / sectionalignment);
		v++;
		return (v * sectionalignment);
	}
}

BOOL loadPE(FILE *fp, IMAGE_DOS_HEADER* in_MZHeader, 
	SIGNATURE* in_Signature, IMAGE_FILE_HEADER* in_FILEHeader, 
	IMAGE_OPT_HEADER* in_OPTHeader, 
	IMAGE_SECTION_HEADER* in_SCHeader, LPVOID ImageBase) 
{

	unsigned long sizeofheaders = in_OPTHeader->SizeOfHeaders;
	size_t readSize;
	int i;
	BYTE* ByteImageBase = (BYTE*)ImageBase;
	fseek(fp, 0, SEEK_SET);

	for (i = 0; i < in_FILEHeader->NumberOfSections; ++i) {
		if (in_SCHeader[i].PointerToRawData < sizeofheaders) {
			sizeofheaders = in_SCHeader[i].PointerToRawData;
		}
	}

	readSize = fread(ByteImageBase, 1, sizeofheaders , fp);
	printf("Header Size = %d\n", sizeofheaders);
	if (readSize != sizeofheaders) { printf("readSize != sizeofheaders\n"); return FALSE; }
	printf("Reading headers successful!\n");

	ByteImageBase += getAlignedSize(in_OPTHeader->SizeOfHeaders, in_OPTHeader->SectionAlignment);
	for (i = 0; i < in_FILEHeader->NumberOfSections; ++i) {
		BYTE* dest = (BYTE*)ImageBase + in_SCHeader[i].VirtualAddress;
		if (in_SCHeader[i].SizeOfRawData > 0) {
			unsigned long toRead = in_SCHeader[i].SizeOfRawData;
			if (in_SCHeader[i].SizeOfRawData > in_SCHeader[i].Misc.VirtualSize) {
				toRead = in_SCHeader[i].Misc.VirtualSize;
				fseek(fp, in_SCHeader[i].PointerToRawData, SEEK_SET);
				readSize = fread(dest, 1, toRead, fp);

				if (readSize != toRead) { printf("Error reading section\n"); return FALSE; }
				//ByteImageBase += getAlignedSize(in_SCHeader[i].Misc.VirtualSize, in_OPTHeader->SectionAlignment);
			}
			else 
			{
				fseek(fp, in_SCHeader[i].PointerToRawData, SEEK_SET);
				readSize = fread(dest, 1, toRead, fp);
				if (readSize != toRead) { printf("Error reading section\n"); return FALSE; }
				memset(dest + in_SCHeader[i].SizeOfRawData, 0, in_SCHeader[i].Misc.VirtualSize - in_SCHeader[i].SizeOfRawData);

				//ByteImageBase += getAlignedSize(in_SCHeader[i].Misc.VirtualSize, in_OPTHeader->SectionAlignment);
			}
		}
		else {
			if (in_SCHeader[i].Misc.VirtualSize) 
			{
				memset(dest, 0, in_SCHeader[i].Misc.VirtualSize);
				//ByteImageBase += getAlignedSize(in_SCHeader[i].Misc.VirtualSize, in_OPTHeader->SectionAlignment);
			}
		}
	} 


	return TRUE;
}

int main() {
	setlocale(LC_ALL, "");
	int argc = 0;
	FILE *fp;
	IMAGE_DOS_HEADER MZ_Header;
	SIGNATURE Signature;
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

					}
					else {
						printf("LoadPE failed\n");
					}
				}
				else { printf("Allocation failed\n"); return 1; }
			}
		}
		else { printf("File doesn't open\n"); return 1; }
	} else { printf("Not enough args\n"); return 1; }

	printf("Success!");
}
