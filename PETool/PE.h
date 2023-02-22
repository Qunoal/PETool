#pragma once

/**
 * DOS头
 */  
struct DosHeader {
	unsigned short e_magic;
	unsigned short e_cblp;
	unsigned short e_cp;
	unsigned short e_crlc;
	unsigned short e_cparhdr;
	unsigned short e_minalloc;
	unsigned short e_maxalloc;
	unsigned short e_ss;
	unsigned short e_sp;
	unsigned short e_csum;
	unsigned short e_ip;
	unsigned short e_cs;
	unsigned short e_lfarlc;
	unsigned short e_ovno;
	unsigned short e_res[4];
	unsigned short e_oemid;
	unsigned short e_oeminfo;
	unsigned short e_res2[10];
	unsigned int e_lfanew;
};
/**
 * DOS头
 */
struct PeHeader {
	unsigned int Signature;
	unsigned short Machine;
	unsigned short NumberOfSections;
	unsigned int TimeDateStamp;
	unsigned int PointerToSymbolTable;
	unsigned int NumberOfSymbols;
	unsigned short SizeOfOptionalHeader;
	unsigned short Characteristics;
};
/**
 * 可选PE头
 */
struct OptPeHeader {
	unsigned short Magic;
	unsigned char MajorLinkerVersion;
	unsigned char MinorLinkerVersion;
	unsigned int SizeOfCode;
	unsigned int SizeOfInitializedData;
	unsigned int SizeOfUninitializedData;
	unsigned int AddressOfEntryPoint;
	unsigned int BaseOfCode;
	unsigned int BaseOfData;
	unsigned int ImageBase;
	unsigned int SectionAlignment;
	unsigned int FileAlignment;
	unsigned short MajorOperatingSystemVersion;
	unsigned short MinorOperatingSystemVersion;
	unsigned short MajorImageVersion;
	unsigned short MinorImageVersion;
	unsigned short MajorSubsystemVersion;
	unsigned short MinorSubsystemVersion;
	unsigned int Win32VersionValue;
	unsigned int SizeOfImage;
	unsigned int SizeOfHeaders;
	unsigned int CheckSum;
	unsigned short Subsystem;
	unsigned short DllCharacteristics;
	unsigned int SizeOfStackReserve;
	unsigned int SizeOfStackCommit;
	unsigned int SizeOfHeapReserve;
	unsigned int SizeOfHeapCommit;
	unsigned int LoaderFlags;
	unsigned int NumberOfRvaAndSizes;
	/**
	*  0: 导出表
	*  1: 导入表
	*  2: 资源表
	*  3: 异常信息表
	*  4: 安全证书表
	*  5: 重定位表
	*  6: 调试信息表
	*  7: 版权所以表
	*  8: 全局指针表 
	*  9: TLS表
	*  10: 加载配置表
	*  11: 绑定导入表
	*  12: IAT表
	*  13: 延迟导入表
	*  14: COM表
	*  15: 保留表
	*/ 
	struct {
		unsigned int VirtualAddress;
		unsigned int Size;
	} DataDirectory[16];
	
};
/**
 * 节表
 */ 
struct Sections {
	unsigned char name[8];  // 极端情况，8个字节都被占用导致找不到00结尾，需要手动处理一下
	unsigned int VirtualSize; // 可改
	unsigned int VirtualAddress;
	unsigned int SizeOfRawData;
	unsigned int PointerToRawData;
	unsigned int PointerToRelocations;
	unsigned int PointerToLinenumbers;
	unsigned short NumberOfRelocations;
	unsigned short NumberOfLinenumbers;
	unsigned int Characteristics;
};
/**
 * 导出表
 */ 
struct ExportTable {
	unsigned int Characteristics;
	unsigned int TimeDateStamp;
	unsigned short MajorVersion;
	unsigned short MinorVersion;
	unsigned int Name;
	unsigned int Base;
	unsigned int NumberOfFunction; // 计算公式，最大序号-最小序号
	unsigned int NumberOfNames;
	unsigned int AddressOfFunction;
	unsigned int AddressOfNames;
	unsigned int AddressOfNameOrdinals;
};
/**
 * 导入表
 */ 
struct ImportTable {
	unsigned int OriginalFirstThunk;      // RVA 指向IMAGE_THUNK_DATA结构数组				
	unsigned int TimeDateStamp;           // 时间戳				
	unsigned int ForwarderChain;
	unsigned int Name;					          // RVA,指向dll名字，该名字已0结尾				
	unsigned int FirstThunk;              // RVA,指向IMAGE_THUNK_DATA结构数组				
};
/**
 * 绑定导入表
 */
struct BoundImport {
	unsigned int TimeDateStamp;
	unsigned short OffsetModuleName;
	unsigned short NumberOfModule;
};
/**
 * PE结构
 */ 
struct PE {
	DosHeader* dos;
	PeHeader* pe;
	OptPeHeader* ope;
	Sections* sections;
	int peSize;
};

// ===================================== PE Function ===============================================
PE getPE(char* buffer);
PE getPE(const char* filePath);
PE loadImageBuffer(PE* pe);
int injectShellCode(PE* pe, char* injectPoint, char* shellCode, int callAddress[], int shellCodeLen);
PE addNewSection(PE* pe, int newSectionSize, const char* newSectionName);
PE capacityLastSection(PE* pe, int increment);
/**
* @param pe 需要合并的PE结构
* @return   一个新的PE结构
*/
PE mergeSection(PE* pe);
/**
* @param pe   含导出表的PE结构
* @param dest 移动的目的地(pe结构内的地址)
* @return int 导出表共多少字节
*/
int moveExportTable(PE* pe, char* dest);
/**
* @param pe   含导出表的PE结构
* @param dest 移动的目的地(pe结构内的地址)
* @return int 导出表共多少字节
*/
int moveRelocationTable(PE* pe, char* dest);
/**
* @param pe   含导出表的PE结构
* @param dest 移动的目的地(pe结构内的地址)
* @return int 导出表共多少字节
*/
int moveImportTable(PE pe, char* dest);

void repairRelocationTable(PE pe, int newImageBase);
void repairINT(PE pe, char* dllName, int* INT, int* IAT);
int injectDllToImportTable(PE pe, char* dllName, char* functionName);

// ======================================= Print =================================================== 
void printDosHead(PE* pe);        // 打印输出：dos头
void printPeHead(PE* pe);         // 打印输出：pe头
void printOptPeHead(PE* pe);      // 打印输出：可选pe头
void printSection(PE* pe);        // 打印输出：节表
void printExportTable(PE* pe);    // 打印输出：导出表
void printRelocationTable(PE* pe);// 打印输出：重定位表
void printImportTable(PE* pe, int isShowRepairAfter);// 打印输出：导入表
void printBoundImport(PE* pe);    // 打印输出：绑定导入表

//===================================  Tools Function ==============================================
void* rvaToFoa(PE* pe, int rva);
void* foaToRva(PE* pe, int foa);
void* getFunction(PE* pe, int number);
void* getFunction(PE* pe, const char* functionName);

void memoryInit(char* addr, int size, char value);
void memoryCopy(char* srcAddr, char* destAddr,int size);
int strEq(char* s1, char* s2);
int strLen(char* s1);
void savePEToFile(PE* pe, const char* path);
void closePE(PE* pe);

