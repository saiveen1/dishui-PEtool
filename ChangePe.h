#pragma once
#include "PE_Headers.h"
/*************************************************
Function: SectionInject
Description: 向第NO个节表的结尾添加shellcode
Calls:	initializePeheader ReadPeFile
Called By: SectionAllocate
Table Accessed:
Table Updated:
Input: 文件缓冲 源文件 输出文件 节表编号 插入代码
Output: 
Return: 成功返回插入位置 否则0
Others: 可以改成开头添加 不过无所谓 懒得改了
		如果插入的PE文件结构已经被改过就没法用了 因为这个是按照标准PE头的格式来写的代码
*************************************************/
DWORD SectionInject(LPSTR inFilePath, LPSTR outFilePath, DWORD sectionNO, BYTE * shellCode, size_t sizeOfShellCode);

/*************************************************
Function: SectionAllocate
Description: 添加一个新的节表 并添加shellcode测试
Calls:	InitializePeheader ReadPeFile SectionInject BufferToFile
Called By:
Table Accessed:
Table Updated:
Input: 文件缓冲地址 新节名称 新节大小
Output:缓冲区也变为增加节后新的缓冲区!	新加节的文件地址
Return: 成功返回新的缓冲区地址, 否则NULl
Others: 新增节表的输出文件是SectionInject的输入文件
//4.29 搞了很长时间 结果是很容易的问题 保存文件一定要注意文件大小
//4.29 一旦使用malloc编译器就认定这段空间只有这么大, 没法再往后面x空间 如果想扩大空间并往里面添加数据需要再开辟另一个缓冲区(加上x)然后保存
//同样的enlarge操作也是如此 记住了
*************************************************/
DWORD AllocateNewSection(BYTE * nameOfSecton, size_t sizeOfNewSection, IN LPSTR inFilePath, OUT DWORD *addrOutFilePath);

/*************************************************
Function: EnlargeTheLastSection
Description: 扩大节表
Calls:	InitializePeheader ReadPeFile BufferToFile
Called By:
Table Accessed:
Table Updated:
Input: 文件缓冲 源文件 输出文件 扩大字节数
Output:
Return: 成功返回1 否则0
Others:
*************************************************/
DWORD EnlargeTheLastSection(LPSTR inFilePath, LPSTR outFilePath, size_t sizeOfEnlarge);

/*************************************************
Function: MergeSections
Description: 合并
Calls:	InitializePeheader ReadPeFile CopyFileBufferToImageBuffer BufferToFile
Called By:
Table Accessed:
Table Updated:
Input: 文件缓冲 源文件 输出文件
Output:
Return: 成功返回1 否则0
Others: 需要运行到内存缓冲区(拉伸) 因为每个区段的大小是不一样的,如果按照FileBuffer存 读到内存的时候程序按区段的偏移找不到了(已经合并 不存在这些信息了)
		所以就需要拉伸到内存里面然后按照FileBuffer的格式存储(这个是重点!!!!!!)
		SecitonAlignment开始的偏移存到FileAlignment里
*************************************************/
DWORD MergeSections(LPSTR inFilePath, LPSTR outFilePath);

DWORD MoveExportDirectory(LPSTR inFilePath, LPSTR outFilePath, BOOL newSection);

DWORD MoveBaseRelocation(LPSTR inFilePath, LPSTR outFilePath);

DWORD ChangeImageBase(LPSTR inFilePath, LPSTR outFilePath, DWORD newImageBase);

/*************************************************
Function: MoveImportDescriptor
Description: 移动导入表整体结构
Calls:	InitializePeheader ReadPeFile CopyFileBufferToImageBuffer BufferToFile
Called By:
Table Accessed:
Table Updated:
Input: 文件缓冲 源文件 输出文件 需要增加的新导入表(提前做准备)
Output:
Return: 成功返回导入表数量 否则需要增加新节
Others: 不能在getfreespace直接申请一个新节,因为缓冲区会发生改变, 所有相关都要重新赋值
*************************************************/
DWORD MoveImportDescriptor(LPSTR inFilePath, LPSTR outFilePath, DWORD numOfNewImportDescriptors);
DWORD MoveImportDescriptor2(LPSTR inFilePath, LPSTR outFilePath, DWORD numOfNewImportDescriptors);


//char *nameOfDataDirectory[16]

/*************************************************
Function: ImportDescriptorInject
Description: 导入表注入
Calls:	InitializePeheader ReadPeFile CopyFileBufferToImageBuffer BufferToFile
Called By:
Table Accessed:
Table Updated:
Input:源文件 输出文件 dll名称 dll中的函数名称 函数的数量
Output:
Return: 成功返回1 否则需要增加新节
Others: 不能在getfreespace直接申请一个新节,因为缓冲区会发生改变, 所有相关都要重新赋值
*************************************************/
DWORD ImportDescriptorInject(LPSTR inFilePath, LPSTR outFilePath, LPSTR nameOfDll, char **nameOfFunctions, DWORD numOfFunctions);