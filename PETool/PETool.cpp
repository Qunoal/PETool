
#include <iostream>
#include "PE.h"
#include <Windows.h>

#define filePath "C:\\Users\\L\\Desktop\\DLLDemo.dll"
//#define filePath "C:\\Users\\L\\Desktop\\3.exe"
#define OUTFILE "C:\\Users\\L\\Desktop\\3_ok.exe"


char shellCode[] = {
    0x6A,0x00,
    0x6A,0x00,
    0x6A,0x00,
    0x6A,0x00,
    0xE8,0x00,0x00,0x00,0x00,
    0x6A,0x00,
    0x6A,0x00,
    0x6A,0x00,
    0x6A,0x00,
    0xE8,0x00,0x00,0x00,0x00,
};
int jmpAddress[] = {
    (int)&MessageBoxA,
    (int)&MessageBoxW,
};


int main()
{
    PE p = getPE(filePath);

    // 2.新增节
    //PE newPE1 = addNewSection(&p, 0x2000, "NB!Woca1");
    //PE newPE = capacityLastSection(&newPE1, 0x8000);

    //// 1.代码节的末尾注入
    //Sections* last = (newPE.sections + newPE.pe->NumberOfSections - 1);
    //char* injectPoint = ((char*)newPE.dos) + last->PointerToRawData;
    //injectShellCode(&newPE, injectPoint, shellCode, jmpAddress, sizeof(shellCode));

    //PE newPE = mergeSection(&p);
    
    // 3.保存文件
    //savePEToFile(&newPE, OUTFILE);

    /*printDosHead(&p);
    printPeHead(&p);
    printOptPeHead(&p);
    printSection(&p);;*/
    printExportTable(&p);
    //printRelocationTable(&p);
    char* a = (char*)malloc(0x2000);
    int n = moveExportTable(&p, a);
    printf("%x\n", n);



    std::cout << "Hello World!\n";
}
 