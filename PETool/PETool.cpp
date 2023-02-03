
#include <iostream>
#include "PE.h"

#define filePath "C:\\Users\\L\\Desktop\\DLLDemo.dll"
//#define filePath "C:\\Users\\L\\Desktop\\3.exe"

int main()
{
    PE p = getPE(filePath);
    /*printDosHead(&p);
    printPeHead(&p);
    printOptPeHead(&p);
    printSection(&p);*/
    printExportTable(&p);
    
     
    std::cout << "Hello World!\n";
}
 