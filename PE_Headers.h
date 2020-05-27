#pragma once

#include "nameDefine.h"
//不能放在nameDefine会出现重定义

//以RvaDataToRawData开始使用这个结构简化代码

/*************************************************
Function: ReadPeFile
Description: 将文件以二进制读取
Calls: 
Called By: PrintNTHeaders
Table Accessed:
Table Updated:
Input: 传入标准PE文件的字符串格式 vs2017需要先用一个char temp[]接收
Output: // 对输出参数的说明。
Return: 返回文件指针
Others: // 其它说明
*************************************************/
LPVOID ReadPeFile(LPSTR lpszFile, OUT DWORD * fileSize);

/*************************************************
Function: InitializePheader
Description: 初始化PE头
Calls:	
Called By: PrintNTHeaders CopyFileBufferToImageBuffer
Table Accessed:
Table Updated:
Input:
Output:
Return:
Others:
*************************************************/
void InitializePheader(IN LPVOID pBuffer, OUT pHeader pHeader, OUT PeList PeList);

/*************************************************
Function: IsStandardPeFile
Description: 检验是否为标准PE文件
Calls:
Called By: PrintNTHeaders CopyFileBufferToImageBuffer CopyImageBufferToFileBuffer
Table Accessed:
Table Updated:
Input: pBuffer 文件缓冲区
Output:
Return: 是返回1 否则0
Others:
*************************************************/
DWORD IsStandardPeFile(LPVOID pBuffer);

/*************************************************
Function: GetFreeSpaceInSection
Description: 获取在文件中空闲的空间, 并返回偏移 创建于5.19
Calls:
Called By:
Table Accessed:
Table Updated:
Input: 文件缓冲 需要加入的数据大小 是否需要改变VirtualSize
Output:
Return: 正常返回空闲地址FOA 否则申请一个新节返回新节FOA
Others:
*************************************************/
DWORD GetFreeSpaceInSection(LPVOID pFileBuffer, size_t sizeOfAddedData, BOOL changeVirtualSize, DWORD sizeOfFile);

/*************************************************
Function: PrintNTHeaders
Description: 打印PE文件的DOS FILE OPTIONALFILE header
Calls: ReadFile
Called By:
Table Accessed:
Table Updated:
Input: filePath	标准PE文件的字符串格式
Output: pFileBuffer 文件缓冲区
Return: 无返回
Others:
*************************************************/
void PrintNTHeaders(LPSTR inFilePath);


//5.14所谓偏移偏移 是不包括缓冲区的, 之前没彻底搞懂这个概念, 写代码的时候就弄混好几次, 所以5.11的修改其实是没必要的
/*************************************************
Function: RvaDataToRawData
Description: 内存偏移转为文件偏移
Calls: 
Called By: CopyImageBufferToFileBuffer
Table Accessed: 
Table Updated: 
Input: pImageBuffer内存缓冲区 dwRvaData内存偏移
Output: 
Return: 返回在文件中的偏移 
Others: 
	//5.11在做导入表的时候 要求直接在FileBuffer里面操作 就导致不需要ImageBuffer 要换回imagebase
	//所以加了第三个参数 BOOL isImageBuffer
*************************************************/
DWORD RvaDataToFoaData(IN LPVOID pImageBuffer, IN DWORD dwRvaDataAddress);

/*************************************************
Function: RawDataToRvaData
Description: 文件偏移为内存偏移转
Calls:	InitializePheader
Called By: ReadFile
Table Accessed:
Table Updated:
Input: pImageBuffer文件缓冲区 dwRawData文件偏移
Output:
Return: 返回在内存中的!!!偏移!!!
Others:	
//5.14发现有的DLL文件会有个textbss段, 只占用内存空间 里面是未初始化的全局变量
*************************************************/
DWORD FoaDataToRvaData(IN LPVOID pFileBuffer, IN DWORD dwRawDataAddress);

/*************************************************
Function: CopyFileBufferToImageBuffer
Description: 将FileBuffer拓展到ImageBuffer 释放file buffer
Calls: IsStandardPeFile
Called By: MergeSections
Table Accessed:
Table Updated:
Input: pFileBuffer 文件缓冲区
Output: pImageBuffer 模拟的内存缓冲区
Return: 成功返回SizeOfImage
Others: 文件缓冲到内存缓冲 区段表之后的是无用数据 不加载进内存 所以后续保存的时候是没有那些无效信息的
*************************************************/
DWORD CopyFileBufferToImageBuffer(LPSTR inFilePath, OUT LPVOID *pImageBuffer);

/*************************************************
Function: CopyImageBufferToFileBuffer
Description: 将ImageBuffer还原到FileBuffer中
Calls: RvaDataToFoaData
Called By:
Table Accessed:
Table Updated:
Input: pImageBuffer模拟的内存缓冲
Output: *pFileBuffer 文件缓冲区
Return: 成功返回1 否则0
Others: 会多一个文件对齐的大小 实际运行发现有的软件会在最后加一些声明信息 PE只需有到最后一个区段表就可以执行了
		如果想要复制完全的话需要在原有FILEBUFFER的时候计算无效空间的大小 然后再添加后续的内容
*************************************************/
DWORD CopyImageBufferToFileBuffer(IN LPVOID pImageBuffer, OUT LPVOID *pFileBuffer);

/*************************************************
Function: MemeryTOFile
Description: 将内存中数据Dump
Calls:  CopyFileBufferToImageBuffer CopyImageBufferToFileBuffer
Called By:
Table Accessed:
Table Updated:
Input: pMemBuffer需要dump的区域 size大小 lpszFile输出的文件
Output: 
Return: 成功返回复制大小 否则0
Others:
*************************************************/
DWORD BufferToFile(IN LPVOID pMemBuffer, IN size_t fileSize, OUT LPSTR lpszFile);

DWORD TraverseDataDirectory(LPSTR inFilePath);


/*************************************************
Function: PrintExportDirectory
Description: 打印PE文件的导出表
Calls: ReadFile
Called By:
Table Accessed:			`````````
Table Updated:
Input: filePath	标准PE文件的字符串格式 pFileBuffer 文件缓冲区
Output: 
Return: 
Others: 需要频繁调用RVATOFOA 存储的地址均为IMAGEBUFFER中的地址
5.12没名字的函数序号找不到
*************************************************/
DWORD PrintExportDirectory(LPSTR inFilePath);

/*************************************************
Function: GetFunctionAddrByName
Description: 通过函数名字获得函数地址
Calls:
Called By:
Table Accessed:	
Table Updated:
Input: filePath	标准PE文件的字符串格式 pFileBuffer 文件缓冲区
Output:
Return:
Others: 需要频繁调用RVATOFOA 存储的地址均为IMAGEBUFFER中的地址
*************************************************/
DWORD GetFunctionAddrByName(LPVOID pFileBuffer, LPSTR functionToFind);

//不就是包含在BYNAME里面了吗 不懂 暂时就不写他了 
DWORD GetFunctionAddrByOrdinals(LPVOID pFileBuffer, DWORD ordinalOfFunction);

/*************************************************
Function: PrintBaseRelocation
Description: 打印重定位表
Calls:
Called By:
Table Accessed:
Table Updated:
Input: filePath	标准PE文件的字符串格式 pFileBuffer 文件缓冲区
Output:
Return:
Others: 
*************************************************/
DWORD PrintBaseRelocation(LPSTR inFilePath);

/*************************************************
Function: PrintImportDirectory
Description: 打印导出表
Calls:
Called By:
Table Accessed:
Table Updated:
Input: filePath	标准PE文件的字符串格式 pFileBuffer 文件缓冲区
Output:
Return:
Others:
*************************************************/
DWORD PrintImportDescriptor(LPSTR inFilePath);

DWORD PrintBoundImportDescriptor(LPSTR inFilePath);

DWORD GetSectionNum(LPVOID pFileBuffer, DWORD foaData);