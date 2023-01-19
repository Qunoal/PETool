#include "PE.h"
#include <iostream>




PE getPE(char* buffer) {
	PE pe;
	pe.dos = (DosHeader*)(buffer);
	pe.pe = (PeHeader*)(buffer + pe.dos->e_lfanew);
	pe.ope = (OptPeHeader*)(buffer + pe.dos->e_lfanew + 24);
	pe.sections = (Sections*)(buffer + pe.dos->e_lfanew + 24 + pe.pe->SizeOfOptionalHeader);
	return pe;
}
PE getPE(const char* filePath) {
	FILE* file = fopen(filePath, "rb");
	if (file == NULL) exit(1);
	fseek(file, 0, SEEK_END);
	int fileBufferSize = ftell(file);
	fseek(file, 0, SEEK_SET);

	// 申请堆空间,初始化：0
	char* buffer = (char*)malloc(fileBufferSize);
	memset(buffer, 0, fileBufferSize);
	// 将文件读取到 缓冲区 中
	fread(buffer, 1, fileBufferSize, file);
	// 关闭文件
	fclose(file);
	return getPE(buffer);
}




//===============================================================
void printDosHead(PE* pe) {
	DosHeader dos = *pe->dos;
	printf("==================> DosHeader Parse Total Size:64 Byte \n");
	printf("e_magic    ：%x \n", dos.e_magic);
	printf("e_cblp     ：%x \n", dos.e_cblp);
	printf("e_cp       ：%x \n", dos.e_cp);
	printf("e_crlc     ：%x \n", dos.e_crlc);
	printf("e_cparhdr  ：%x \n", dos.e_cparhdr);
	printf("e_minalloc ：%x \n", dos.e_minalloc);
	printf("e_maxalloc ：%x \n", dos.e_maxalloc);
	printf("e_ss       ：%x \n", dos.e_ss);
	printf("e_sp       ：%x \n", dos.e_sp);
	printf("e_csum     ：%x \n", dos.e_csum);
	printf("e_ip       ：%x \n", dos.e_ip);
	printf("e_cs       ：%x \n", dos.e_cs);
	printf("e_lfarlc   ：%x \n", dos.e_lfarlc);
	printf("e_ovno     ：%x \n", dos.e_ovno);
	printf("e_res[0]   : %x %x %x %x  \n", dos.e_res[0], dos.e_res[1], dos.e_res[2], dos.e_res[3]);
	printf("e_oemid    : %x \n", dos.e_oemid);
	printf("e_oeminfo  : %x \n", dos.e_oeminfo);
	printf("e_res2[10] : %x %x %x %x %x %x %x %x %x %x \n", dos.e_res2[0], dos.e_res2[1], dos.e_res2[2], dos.e_res2[3], dos.e_res2[4], dos.e_res2[5], dos.e_res2[6], dos.e_res2[7], dos.e_res2[8], dos.e_res2[9]);
	printf("e_lfanew   : %x \n", dos.e_lfanew);
}
void printPeHead(PE* pe) {
	PeHeader peh = *pe->pe;
	printf("==================> NT Header \n");
	printf("Signature            : %x \n", peh.Signature);
	printf("========================> PeHeader Total Size:20 Byte \n");
	printf("Machine              : %x \n", peh.Machine);
	printf("NumberOfSections     : %x \n", peh.NumberOfSections);
	printf("TimeDateStamp        : %x \n", peh.TimeDateStamp);
	printf("PointerToSymbolTable : %x \n", peh.PointerToSymbolTable);
	printf("NumberOfSymbols      : %x \n", peh.NumberOfSymbols);
	printf("SizeOfOptionalHeader : %x \n", peh.SizeOfOptionalHeader);
	printf("Characteristics      : %x \n", peh.Characteristics);
}
void printOptPeHead(PE* pe) {
	OptPeHeader op = *pe->ope;
	printf("========================> Optional PeHeader \n");
	printf("Magic                       : %x \n", op.Magic);
	printf("MajorLinkerVersion          : %x \n", op.MajorLinkerVersion);
	printf("MinorLinkerVersion          : %x \n", op.MinorLinkerVersion);
	printf("SizeOfCode                  : %x \n", op.SizeOfCode);
	printf("SizeOfInitializedData       : %x \n", op.SizeOfInitializedData);
	printf("SizeOfUninitializedData     : %x \n", op.SizeOfUninitializedData);
	printf("AddressOfEntryPoint         : %x \n", op.AddressOfEntryPoint);
	printf("BaseOfCode                  : %x \n", op.BaseOfCode);
	printf("BaseOfData                  : %x \n", op.BaseOfData);
	printf("ImageBase                   : %x \n", op.ImageBase);
	printf("SectionAlignment            : %x \n", op.SectionAlignment);
	printf("FileAlignment               : %x \n", op.FileAlignment);
	printf("MajorOperatingSystemVersion : %x \n", op.MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion : %x \n", op.MinorOperatingSystemVersion);
	printf("MajorImageVersion           : %x \n", op.MajorImageVersion);
	printf("MinorImageVersion           : %x \n", op.MinorImageVersion);
	printf("MajorSubsystemVersion       : %x \n", op.MajorSubsystemVersion);
	printf("MinorSubsystemVersion       : %x \n", op.MinorSubsystemVersion);
	printf("Win32VersionValue           : %x \n", op.Win32VersionValue);
	printf("SizeOfImage                 : %x \n", op.SizeOfImage);
	printf("SizeOfHeaders               : %x \n", op.SizeOfHeaders);
	printf("CheckSum                    : %x \n", op.CheckSum);
	printf("Subsystem                   : %x \n", op.Subsystem);
	printf("DllCharacteristics          : %x \n", op.DllCharacteristics);
	printf("SizeOfStackReserve          : %x \n", op.SizeOfStackReserve);
	printf("SizeOfStackCommit           : %x \n", op.SizeOfStackCommit);
	printf("SizeOfHeapReserve           : %x \n", op.SizeOfHeapReserve);
	printf("SizeOfHeapCommit            : %x \n", op.SizeOfHeapCommit);
	printf("LoaderFlags                 : %x \n", op.LoaderFlags);
	printf("NumberOfRvaAndSizes         : %x \n", op.NumberOfRvaAndSizes);
	printf("DataDirectory[16]            \n");
	for (int i = 0; i < 16; i++) {
		printf("==> ---------------------->  table:%d  \n", i + 1);
		printf("==> VirtualAddress : %x \n", op.DataDirectory[i].VirtualAddress);
		printf("==> Size           : %x \n", op.DataDirectory[i].Size);
	}
	printf("\n");
}
void printSection(PE* pe) {
	int sectionSize = pe->pe->NumberOfSections;
	Sections* nodes = pe->sections;
	printf("==================> Section Size: %d \n", sectionSize);
	for (int i = 0; i < sectionSize; i++) {
		printf("-------------------------------- node: %d --------------------------------\n", (i + 1));
		printf("name                 : %s \n", nodes->name);
		printf("VirtualSize          : %X \n", nodes->VirtualSize);
		printf("VirtualAddress       : %X \n", nodes->VirtualAddress);
		printf("SizeOfRawData        : %X \n", nodes->SizeOfRawData);
		printf("PointerToRawData     : %X \n", nodes->PointerToRawData);
		printf("PointerToRelocations : %X \n", nodes->PointerToRelocations);
		printf("PointerToLinenumbers : %X \n", nodes->PointerToLinenumbers);
		printf("NumberOfRelocations  : %X \n", nodes->NumberOfRelocations);
		printf("NumberOfLinenumbers  : %X \n", nodes->NumberOfLinenumbers);
		printf("Characteristics      : %X \n", nodes->Characteristics);
		nodes++;
	}
}
void printExportTable(PE* pe) {
}
void printRelocationTable(PE* pe); 
void printImportTable(PE* pe, int isShowRepairAfter); 
void printBoundImport(PE* pe);   
//===============================================================
void* rvaToFoa(PE* pe, int rva);
void* foaToRva(PE* pe, int foa);
void memoryInit(char* addr, int size, char value) {
	while (size--) *addr++ = value;
}
void memoryCopy(char* srcAddr, char* destAddr, int size) {
	while (size--) *destAddr++ = *srcAddr++;
}
int strEq(char* s1, char* s2) {
	while (*s1 || *s2) if (*s1++ != *s2++) return 0;
	return 1;
}
int strLen(char* s1) {
	int i = 0;
	while (*s1++) i++;
	return i;
}
void closePE(PE* pe) {
	free(pe->dos);
}