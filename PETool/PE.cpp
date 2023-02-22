#include "PE.h"
#include <iostream>




PE getPE(char* buffer) {
	PE pe;
	pe.dos = (DosHeader*)(buffer);
	pe.pe = (PeHeader*)(buffer + pe.dos->e_lfanew);
	pe.ope = (OptPeHeader*)(buffer + pe.dos->e_lfanew + 24);
	pe.sections = (Sections*)(buffer + pe.dos->e_lfanew + 24 + pe.pe->SizeOfOptionalHeader);

	Sections* lastSec = pe.sections + pe.pe->NumberOfSections - 1;
	pe.peSize = lastSec->PointerToRawData + lastSec->SizeOfRawData;
	// 校验文件合规性
	if (pe.dos->e_magic != 0x5A4D && pe.pe->Signature != 0x00004550) {
		printf("该文件不是一个有效的PE结构\n");
		exit(0);
	}

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

	PE p = getPE(buffer);
	p.peSize = fileBufferSize;
	return p ;
}
PE loadImageBuffer(PE* pe) {
	char* fileBuffer = (char*)pe->dos;
	char* impageBuffer = (char*)malloc(pe->ope->SizeOfImage);
	
	// copy handers 
	memoryInit(impageBuffer, pe->ope->SizeOfImage, 0);
	memoryCopy(fileBuffer, impageBuffer, pe->ope->SizeOfHeaders);

	// copy sections 
	Sections* s = pe->sections;
	for (int i = 0; i < pe->pe->NumberOfSections; i++) {
		char* start = s->PointerToRawData + fileBuffer;
		char* targe = s->VirtualAddress   + impageBuffer;
		int copySize = (s->SizeOfRawData > s->VirtualSize) ? s->SizeOfRawData : s->VirtualSize;
		memoryCopy(start, targe, copySize);
		s++;
	}
	PE p = getPE(impageBuffer);
	p.peSize = pe->ope->SizeOfImage;
	return p;
}
int injectShellCode(PE* pe, char* injectPoint, char* shellCode, int callAddress[], int shellCodeLen) {
	// 1.将callAddress数组中的地址填充进shellcode的 E8(call) 中
	int count = 0;
	for (int i = 0; i < shellCodeLen; i++){
		unsigned char* next = (unsigned char*)(shellCode + i);
		if (*next == 0xE8) {
			*(int*)(next + 1) = callAddress[count];
			count++;
			i += 4;
		}
	}

	// 2.Inject And Update Call(E8) 
	memoryCopy(shellCode, injectPoint, shellCodeLen);
	char* buffer = (char*)pe->dos;
	for (int i = 0; i < shellCodeLen; i++) {
		unsigned char* t = (unsigned char*)injectPoint + i;
		if (*t == 0xE8) {
			int jumAdd = *(int*)(t + 1);  // E8里面写的目标地址
			int callNextAdd = ((int)(t + 5)) - ((int)buffer) + pe->ope->ImageBase;
			int finalAdd = jumAdd - callNextAdd; // 转换成最终的地址
			*(int*)(t + 1) = finalAdd;           // 修正地址
			i += 4; // 优化循环
		}
	}

	// 3. Append Jmp old OEP Jmp到原来的程序入口
	char* last = (injectPoint + shellCodeLen);
	*last++ = 0xE9; // Jmp
	*(int*)last = (pe->ope->AddressOfEntryPoint + pe->ope->ImageBase) - (((int)(last + 4) - (int)buffer) + pe->ope->ImageBase);

	// 4.修改OEP,指向 ShellCode
	pe->ope->AddressOfEntryPoint = (injectPoint - buffer); // rva
	printf(">>>>>>>>>>>>>>>>>>>>>>> 注入成功 >>>>>>>>>>>>>>>>>>>>>>>>>\n");

	return 1;
}
PE addNewSection(PE* pe, int newSectionSize, const char* newSectionName) {
	// 检测剩余空间是否能够容纳新增节表
	int lastSectionAfter = (int)(pe->sections + pe->pe->NumberOfSections);
	int headersValidLength = pe->ope->SizeOfHeaders - (lastSectionAfter - (int)pe->dos);

	PE newPE;
	if (headersValidLength >= (2 * sizeof(Sections))) {
		int fileBufferSize = pe->peSize + newSectionSize;
		char* newBuffer = (char*)malloc(fileBufferSize);

		memoryInit(newBuffer, fileBufferSize, 0);
		memoryCopy((char*)pe->dos, newBuffer, pe->peSize);

		newPE = getPE(newBuffer);
		newPE.peSize = fileBufferSize;

		// 1.找到节点末尾,并拷贝节
		char* newSectionAfter = (char*)(newPE.sections +newPE.pe->NumberOfSections);
		memoryCopy((char*)(pe->sections), newSectionAfter, sizeof(Sections));

		// 2.修改新增节的属性
		Sections* newNode = (Sections*)newSectionAfter;
		Sections* lastNode = newNode - 1;
		char sectionName[8] = { 0 };
		int nameLen = strLen((char*)newSectionName);
		nameLen >= 8 ? memoryCopy((char*)newSectionName, sectionName, 8) : memoryCopy((char*)newSectionName, sectionName, nameLen);

		memoryCopy(sectionName, (char*)newNode->name, 8);
		newNode->VirtualSize = newSectionSize;
		newNode->VirtualAddress = lastNode->VirtualAddress + lastNode->SizeOfRawData;
		newNode->SizeOfRawData = newSectionSize;
		newNode->PointerToRawData = lastNode->PointerToRawData + lastNode->SizeOfRawData;

		// 3.修改pe头,可选pe头信息
		newPE.pe->NumberOfSections++; // 新增一个节 
		newPE.ope->SizeOfImage += newSectionSize;
	} else {
		printf("新增节失败，空余空间不足\n");
	}
	return newPE;
}
PE capacityLastSection(PE* pe, int increment) {
	int oldSizeOfImage = pe->ope->SizeOfImage;
		
	// 1、分配一块新的空间：SizeOfImage + Ex
	char* newBuffer = (char*)malloc(oldSizeOfImage + increment);
	memoryInit(newBuffer, oldSizeOfImage, 0);
	memoryCopy((char*)pe->dos, newBuffer, pe->peSize);

	PE newPE = getPE(newBuffer);
	newPE.peSize += increment;

	// 3、将最后一个节的 SizeOfRawData 和 VirtualSize 扩容 
	//    SizeOfRawData = N and VirtualSize = N 
	//    N = (SizeOfRawData或者VirtualSize 内存对齐后的值) + Ex
	Sections* lastSection = newPE.sections + (newPE.pe->NumberOfSections - 1);
	lastSection->SizeOfRawData += increment;
	lastSection->VirtualSize += increment;

	// 4、修改 SizeOfImage 大小
	newPE.ope->SizeOfImage += increment;
	return newPE;
}
PE mergeSection(PE* pe) {
	// 1、拉伸到内存
	PE loadedPE = loadImageBuffer(pe);

	// 2、将第一个节的内存大小、文件大小改成一样
	Sections* lastSec = loadedPE.sections + (loadedPE.pe->NumberOfSections - 1);
	int max = (lastSec->SizeOfRawData > lastSec->VirtualSize) ? lastSec->SizeOfRawData : lastSec->VirtualSize;
	int totalSize = lastSec->VirtualAddress + max - loadedPE.ope->SizeOfHeaders;
	
	loadedPE.sections->VirtualSize = totalSize;
	loadedPE.sections->SizeOfRawData = totalSize;

	// 3、将第一个节的属性改为包含所有节的属性,所有节的 Characteristics 全部按位或在一起
	Sections* s = loadedPE.sections;
	for (int i = 1; i < loadedPE.pe->NumberOfSections; i++) {
		s->Characteristics |= (s + i)->Characteristics;
	}
	
	// 4、修改节的数量为1
	loadedPE.pe->NumberOfSections = 1;

	return loadedPE;
}
int moveExportTable(PE* pe, char* dest){
	ExportTable* et = (ExportTable*)rvaToFoa(pe, pe->ope->DataDirectory[0].VirtualAddress);
	if (et == NULL) {
		printf("没找到导出表，导出表移动失败\n");
		return 0; // 结束该方法
	}

	// 开始移动 ==============>
	int funcAddRva = et->AddressOfFunction;
	int funcNum = et->NumberOfFunction;
	int OrdiAddRva = et->AddressOfNameOrdinals;
	int nameAddRva = et->AddressOfNames;
	int nameNum = et->NumberOfNames;
	int funcNeedSpaceSize = 4 * et->NumberOfFunction;
	int ordinalNeedSpaceSize = 2 * et->NumberOfNames;
	int namesNeedSpaceSize = 4 * et->NumberOfNames;

	// 1.先移动函数地址
	char* funcList = (char*)rvaToFoa(pe, funcAddRva);
	memoryCopy(funcList, dest, funcNeedSpaceSize);

	// 2.再移序号表
	char* ordinalList = (char*)rvaToFoa(pe, OrdiAddRva);
	memoryCopy(ordinalList, (char*)(dest + funcNeedSpaceSize), ordinalNeedSpaceSize);

	// 3.移动名字表
	// 名字地址指针
	int* nameNewRva = (int*)(dest + funcNeedSpaceSize + ordinalNeedSpaceSize);
	// 定位名字存放位置,跳过name地址表,追加在name地址表后面
	char* nameNext = (char*)(dest + funcNeedSpaceSize + ordinalNeedSpaceSize + namesNeedSpaceSize);

	// 函数名长度统计 
	int nameAllLen = 0;
	// 处理函数名表
	int* nameTableRva = (int*)rvaToFoa(pe, nameAddRva);
	for (int i = 0; i < nameNum; i++) {
		char* nameString = (char*)rvaToFoa(pe, nameTableRva[i]);
		int nameLen = strLen(nameString) + 1; // +1为了把\0也给拷过来
		memoryCopy(nameString, nameNext, nameLen);
		// 修复 AddressOfNames 表中的 rva
		*nameNewRva++ = (int)foaToRva(pe, (int)nameNext);
		nameNext += nameLen;
		
		// 统计名字占用多少空间
		nameAllLen += nameLen;
	}

	// 4.移动表结构，并修复rva
	memoryCopy((char*)et, nameNext, sizeof(ExportTable));
	ExportTable* moveAfter = (ExportTable*)nameNext;
	moveAfter->AddressOfFunction = (int)foaToRva(pe, (int)dest);
	moveAfter->AddressOfNameOrdinals = (int)foaToRva(pe, (int)(dest + funcNeedSpaceSize));
	moveAfter->AddressOfNames = (int)foaToRva(pe, (int)(dest + funcNeedSpaceSize + ordinalNeedSpaceSize));

	// 5.修改 ope目录 VirtualAddress 指向
	pe->ope->DataDirectory[0].VirtualAddress = (int)foaToRva(pe, (int)moveAfter);
	// 完成移动 ==============>

	// 记录导出表所有数据总长度,存在节点开始位置
	return nameAllLen + (sizeof(ExportTable) + funcNeedSpaceSize + ordinalNeedSpaceSize + namesNeedSpaceSize);
}
int moveRelocationTable(PE* pe, char* dest) {
	int* relocation = (int*)rvaToFoa(pe, pe->ope->DataDirectory[5].VirtualAddress);
	if (*relocation == 0) {
		printf("没有重定位表 移动失败~ \n");
		return 0;
	}

	int totalSize = 0;
	int* ip = relocation;
	int virtualAddress = 0;
	int sizeOfBlock = 0;

	do {
		virtualAddress = ip[0];
		sizeOfBlock = ip[1];
		// if防止第一次为0
		if (virtualAddress != 0 && sizeOfBlock != 0) {
			totalSize += sizeOfBlock;
			ip = (int*)(((char*)ip) + sizeOfBlock); // 切换到下一个block
		}
	} while (virtualAddress != 0 && sizeOfBlock != 0);
	// 手动加上8个结束标记
	totalSize += 8;
	memoryCopy((char*)relocation, dest, totalSize);

	// 修改目录项指向
	pe->ope->DataDirectory[5].VirtualAddress = (int)foaToRva(pe, (int)dest);

	return totalSize;
}
int moveImportTable(PE pe, char* dest) {
	return 0;
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
	int etAddr = pe->ope->DataDirectory[0].VirtualAddress;
	if (etAddr == 0) {
		printf("该pe结构没有导出表\n");
		return;
	}
	ExportTable et = *(ExportTable*)rvaToFoa(pe, etAddr);
	printf("\n");
	printf("===========================> Export Table \n");
	printf("Characteristics       : %x\n", et.Characteristics);
	printf("TimeDateStamp         : %x\n", et.TimeDateStamp);
	printf("MajorVersion          : %x\n", et.MajorVersion);
	printf("MinorVersion          : %x\n", et.MinorVersion);
	printf("Name                  : %x\n", et.Name);
	printf("Base                  : %x\n", et.Base);
	printf("NumberOfFunction      : %x\n", et.NumberOfFunction);
	printf("NumberOfNames         : %x\n", et.NumberOfNames);
	printf("AddressOfFunction     : %x\n", et.AddressOfFunction);
	printf("AddressOfNames        : %x\n", et.AddressOfNames);
	printf("AddressOfNameOrdinals : %x\n", et.AddressOfNameOrdinals);

	int* functions = (int*)rvaToFoa(pe, et.AddressOfFunction);
	short* ordinals = (short*)rvaToFoa(pe, et.AddressOfNameOrdinals);
	int* names = (int*)rvaToFoa(pe, et.AddressOfNames);

	int funcNeedSpaceSize = 4 * et.NumberOfFunction;
	int ordinalNeedSpaceSize = 2 * et.NumberOfNames;
	int namesNeedSpaceSize = 4 * et.NumberOfNames;
	int funcNameAll = 0;

	printf("========> AddressOfFunction\n");
	for (int i = 0; i < et.NumberOfFunction; i++) {
		printf("%x \n", functions[i]);
	}
	printf("========> AddressOfNames\n");
	for (int i = 0; i < et.NumberOfNames; i++) {
		char* methods = (char*)rvaToFoa(pe, names[i]);
		funcNameAll += strLen(methods) + 1;
		printf("%s \n", methods);
	}
	printf("========> AddressOfNameOrdinals\n");
	for (int i = 0; i < et.NumberOfNames; i++) {
		printf("%x \n", ordinals[i]);
	}
	
	printf("-----------------------------------------------\n");
	printf("   %-10s    %-10s    %-10s  \n", "Number", "RVA", "Function Name");
	printf("-----------------------------------------------\n");
	int ord = -1;
	for (int i = 0; i < et.NumberOfFunction; i++) {
		int addr = functions[i];
		char* name = (char*)"-";
		for (int j = 0; j < et.NumberOfNames; j++) {
			if (ordinals[j] == i) {
				ord = ordinals[j];
				name = (char*)rvaToFoa(pe, names[j]);
				break;
			}
		}
		if (addr != 0) {
			if (ord == -1) {
				printf("   %-10d    %-10X    %-10s   \n", 0, addr, name);
			}
			else {
				printf("   %-10d    %-10X    %-10s   \n", ord + et.Base, addr, name);
			}
		}
		ord = -1;
	}
	printf("-----------------------------------------------\n");
	printf("expor Table Total Size: %x \n",(funcNameAll + funcNeedSpaceSize + ordinalNeedSpaceSize + namesNeedSpaceSize + sizeof(ExportTable)));
}
void printRelocationTable(PE* pe) {
	int* rt = (int*)rvaToFoa(pe,pe->ope->DataDirectory[5].VirtualAddress);
	if (rt == 0) {
		printf("没有导入表\n");
		return;
	}
	int* ip = rt;
	int virtualAddress = 0;
	int sizeOfBlock = 0;
	int number = 0;

	do {
		virtualAddress = ip[0];
		sizeOfBlock = ip[1];
		number++;

		printf("====================  Block : %d =================\n", number);
		printf("===> VirtualAddress: %x\n", virtualAddress);
		printf("===> SizeOfBlock   : %x\n", sizeOfBlock);
		if (virtualAddress != 0 && sizeOfBlock != 0) {
			short* sp = (short*)(ip + 2);
			// 1. 高4位代表类型：
			// 	 1. 值为3 代表的是需要修改的数据
			// 	 2. 值为0	代表的是用于数据对齐的数据，可以不用修改
			// 2. 第12位开始后代表的是需要重定位的值(rva) + 结构块的 VirtualAddress = 真正要修复的地址
			for (int i = 0; i < (sizeOfBlock - 8) / 2; i++) {
				short v = *(sp + i);
				if (v != 0 && (v & 0x3FFF) == v) {
					printf("%x > %x > %x -> %x\t\t", v, (v & 0x0FFF), (v & 0x0FFF) + virtualAddress, (v & 0x0FFF) + virtualAddress + pe->ope->ImageBase);
				}else {
					printf("%x", v);
				}
				// 换行 方便阅读
				if ((i + 1) % 2 == 0) {
					printf("\n");
				}
			}
		}
		printf("=================  END Block : %d  =================\n\n", number);
		ip = (int*)(((char*)ip) + sizeOfBlock); // 切换到下一个block
	} while (virtualAddress != 0 && sizeOfBlock != 0);

}
void printImportTable(PE* pe, int isShowRepairAfter);
void printBoundImport(PE* pe);   
//===============================================================
void* rvaToFoa(PE* pe, int rva) {
	if (rva == 0) return 0;
	Sections* sec = pe->sections;
	for (int i = 0; i < pe->pe->NumberOfSections; i++){
		int start = sec->VirtualAddress;
		int end   = sec->VirtualAddress + sec->VirtualSize ;
		if (rva >= start &&  rva <= end ) {
			return (void*)(sec->PointerToRawData + (rva - start) + (char*)pe->dos);
		}
		sec++;
	}
	printf("未找到改rva对应的foa\n");
	return 0;
}
void* foaToRva(PE* pe, int foa) {
	if (foa == 0) return 0;

	foa = foa - (int)pe->dos;
	Sections* sec = pe->sections;
	for (int i = 0; i < pe->pe->NumberOfSections; i++) {
		int start = sec->PointerToRawData;
		int end   = sec->PointerToRawData + sec->VirtualSize;
		if (foa >= start && foa <= end) {
			// 找到对应文件的偏移地址
			return (void*)(sec->VirtualAddress + (foa - start));
		}
		sec++;
	}
	printf("未找到改foa对应的rva\n");
	return 0;
}
void* getFunction(PE* pe, int number) {
	ExportTable* et = (ExportTable*)rvaToFoa(pe, pe->ope->DataDirectory[0].VirtualAddress);

	int* names = (int*)rvaToFoa(pe, et->AddressOfNames);
	short* ordis = (short*)rvaToFoa(pe, et->AddressOfNameOrdinals);
	int* funcs = (int*)rvaToFoa(pe, et->AddressOfFunction);

	// 按照序号查找
	int base = number - et->Base;
	if (base < et->NumberOfFunction) {
		return (void*)(funcs[base] + pe->ope->ImageBase);
	}
	return 0; // 没找到
}
void* getFunction(PE* pe, const char* functionName) {
	ExportTable* et = (ExportTable*)rvaToFoa(pe, pe->ope->DataDirectory[0].VirtualAddress);

	int* names = (int*)rvaToFoa(pe, et->AddressOfNames);
	short* ordis = (short*)rvaToFoa(pe, et->AddressOfNameOrdinals);
	int* funcs = (int*)rvaToFoa(pe, et->AddressOfFunction);

	// 按照名字查找
	for (int i = 0; i < et->NumberOfNames; i++) {
		char* funcName = (char*)rvaToFoa(pe, *(names + i));
		if (strEq(funcName, (char*)functionName)) {
			return (void*)(funcs[ordis[i]] + pe->ope->ImageBase);
		}
	}
		
	return 0;  // 没找到
}

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
void savePEToFile(PE* pe,const char* path) {
	FILE* file = fopen(path, "wb");
	char* buffer = (char*)pe->dos;
	fwrite(buffer, 1, pe->peSize, file);
	fclose(file);
}
void closePE(PE* pe) {
	free(pe->dos);
}


 