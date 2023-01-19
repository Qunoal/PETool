
#include <iostream>
#include "PE.h"

#define filePath "C:\\Users\\L\\Desktop\\3.exe"

int main()
{   
    PE p = getPE(filePath);
    printDosHead(&p);
    printPeHead(&p);
    printOptPeHead(&p);
    printSection(&p);

     
    std::cout << "Hello World!\n";
}
