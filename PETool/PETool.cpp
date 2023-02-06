
#include <iostream>
#include "PE.h"
#include <Windows.h>

//#define filePath "C:\\Users\\L\\Desktop\\DLLDemo.dll"
#define filePath "C:\\Users\\L\\Desktop\\3.exe"
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
    int size = 0;
    PE p = getPE(filePath,&size);

    // 1.代码节的末尾注入
    //char* injectPoint = (char*)p.dos + p.sections->PointerToRawData + p.sections->VirtualSize;
    //injectShellCode(&p, injectPoint, shellCode, jmpAddress, sizeof(shellCode));

    // 2.新增节
    PE newPE1 = addNewSection(&p,size, 0x2000,"NB!Woca1");
  
    
    // 3.保持文件
    savePEToFile(&newPE1, OUTFILE, size+0x2000);



    /*printDosHead(&p);
    printPeHead(&p);
    printOptPeHead(&p);
    printSection(&p);
    printExportTable(&p);*/
    std::cout << "Hello World!\n";
}
 