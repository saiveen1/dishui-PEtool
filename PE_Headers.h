#pragma once

#include "nameDefine.h"
//���ܷ���nameDefine������ض���

//��RvaDataToRawData��ʼʹ������ṹ�򻯴���

/*************************************************
Function: ReadPeFile
Description: ���ļ��Զ����ƶ�ȡ
Calls: 
Called By: PrintNTHeaders
Table Accessed:
Table Updated:
Input: �����׼PE�ļ����ַ�����ʽ vs2017��Ҫ����һ��char temp[]����
Output: // �����������˵����
Return: �����ļ�ָ��
Others: // ����˵��
*************************************************/
LPVOID ReadPeFile(LPSTR lpszFile, OUT DWORD * fileSize);

/*************************************************
Function: InitializePheader
Description: ��ʼ��PEͷ
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
Description: �����Ƿ�Ϊ��׼PE�ļ�
Calls:
Called By: PrintNTHeaders CopyFileBufferToImageBuffer CopyImageBufferToFileBuffer
Table Accessed:
Table Updated:
Input: pBuffer �ļ�������
Output:
Return: �Ƿ���1 ����0
Others:
*************************************************/
DWORD IsStandardPeFile(LPVOID pBuffer);

/*************************************************
Function: GetFreeSpaceInSection
Description: ��ȡ���ļ��п��еĿռ�, ������ƫ�� ������5.19
Calls:
Called By:
Table Accessed:
Table Updated:
Input: �ļ����� ��Ҫ��������ݴ�С �Ƿ���Ҫ�ı�VirtualSize
Output:
Return: �������ؿ��е�ַFOA ��������һ���½ڷ����½�FOA
Others:
*************************************************/
DWORD GetFreeSpaceInSection(LPVOID pFileBuffer, size_t sizeOfAddedData, BOOL changeVirtualSize, DWORD sizeOfFile);

/*************************************************
Function: PrintNTHeaders
Description: ��ӡPE�ļ���DOS FILE OPTIONALFILE header
Calls: ReadFile
Called By:
Table Accessed:
Table Updated:
Input: filePath	��׼PE�ļ����ַ�����ʽ
Output: pFileBuffer �ļ�������
Return: �޷���
Others:
*************************************************/
void PrintNTHeaders(LPSTR inFilePath);


//5.14��νƫ��ƫ�� �ǲ�������������, ֮ǰû���׸㶮�������, д�����ʱ���Ū��ü���, ����5.11���޸���ʵ��û��Ҫ��
/*************************************************
Function: RvaDataToRawData
Description: �ڴ�ƫ��תΪ�ļ�ƫ��
Calls: 
Called By: CopyImageBufferToFileBuffer
Table Accessed: 
Table Updated: 
Input: pImageBuffer�ڴ滺���� dwRvaData�ڴ�ƫ��
Output: 
Return: �������ļ��е�ƫ�� 
Others: 
	//5.11����������ʱ�� Ҫ��ֱ����FileBuffer������� �͵��²���ҪImageBuffer Ҫ����imagebase
	//���Լ��˵��������� BOOL isImageBuffer
*************************************************/
DWORD RvaDataToFoaData(IN LPVOID pImageBuffer, IN DWORD dwRvaDataAddress);

/*************************************************
Function: RawDataToRvaData
Description: �ļ�ƫ��Ϊ�ڴ�ƫ��ת
Calls:	InitializePheader
Called By: ReadFile
Table Accessed:
Table Updated:
Input: pImageBuffer�ļ������� dwRawData�ļ�ƫ��
Output:
Return: �������ڴ��е�!!!ƫ��!!!
Others:	
//5.14�����е�DLL�ļ����и�textbss��, ֻռ���ڴ�ռ� ������δ��ʼ����ȫ�ֱ���
*************************************************/
DWORD FoaDataToRvaData(IN LPVOID pFileBuffer, IN DWORD dwRawDataAddress);

/*************************************************
Function: CopyFileBufferToImageBuffer
Description: ��FileBuffer��չ��ImageBuffer �ͷ�file buffer
Calls: IsStandardPeFile
Called By: MergeSections
Table Accessed:
Table Updated:
Input: pFileBuffer �ļ�������
Output: pImageBuffer ģ����ڴ滺����
Return: �ɹ�����SizeOfImage
Others: �ļ����嵽�ڴ滺�� ���α�֮������������� �����ؽ��ڴ� ���Ժ��������ʱ����û����Щ��Ч��Ϣ��
*************************************************/
DWORD CopyFileBufferToImageBuffer(LPSTR inFilePath, OUT LPVOID *pImageBuffer);

/*************************************************
Function: CopyImageBufferToFileBuffer
Description: ��ImageBuffer��ԭ��FileBuffer��
Calls: RvaDataToFoaData
Called By:
Table Accessed:
Table Updated:
Input: pImageBufferģ����ڴ滺��
Output: *pFileBuffer �ļ�������
Return: �ɹ�����1 ����0
Others: ���һ���ļ�����Ĵ�С ʵ�����з����е������������һЩ������Ϣ PEֻ���е����һ�����α�Ϳ���ִ����
		�����Ҫ������ȫ�Ļ���Ҫ��ԭ��FILEBUFFER��ʱ�������Ч�ռ�Ĵ�С Ȼ������Ӻ���������
*************************************************/
DWORD CopyImageBufferToFileBuffer(IN LPVOID pImageBuffer, OUT LPVOID *pFileBuffer);

/*************************************************
Function: MemeryTOFile
Description: ���ڴ�������Dump
Calls:  CopyFileBufferToImageBuffer CopyImageBufferToFileBuffer
Called By:
Table Accessed:
Table Updated:
Input: pMemBuffer��Ҫdump������ size��С lpszFile������ļ�
Output: 
Return: �ɹ����ظ��ƴ�С ����0
Others:
*************************************************/
DWORD BufferToFile(IN LPVOID pMemBuffer, IN size_t fileSize, OUT LPSTR lpszFile);

DWORD TraverseDataDirectory(LPSTR inFilePath);


/*************************************************
Function: PrintExportDirectory
Description: ��ӡPE�ļ��ĵ�����
Calls: ReadFile
Called By:
Table Accessed:			`````````
Table Updated:
Input: filePath	��׼PE�ļ����ַ�����ʽ pFileBuffer �ļ�������
Output: 
Return: 
Others: ��ҪƵ������RVATOFOA �洢�ĵ�ַ��ΪIMAGEBUFFER�еĵ�ַ
5.12û���ֵĺ�������Ҳ���
*************************************************/
DWORD PrintExportDirectory(LPSTR inFilePath);

/*************************************************
Function: GetFunctionAddrByName
Description: ͨ���������ֻ�ú�����ַ
Calls:
Called By:
Table Accessed:	
Table Updated:
Input: filePath	��׼PE�ļ����ַ�����ʽ pFileBuffer �ļ�������
Output:
Return:
Others: ��ҪƵ������RVATOFOA �洢�ĵ�ַ��ΪIMAGEBUFFER�еĵ�ַ
*************************************************/
DWORD GetFunctionAddrByName(LPVOID pFileBuffer, LPSTR functionToFind);

//�����ǰ�����BYNAME�������� ���� ��ʱ�Ͳ�д���� 
DWORD GetFunctionAddrByOrdinals(LPVOID pFileBuffer, DWORD ordinalOfFunction);

/*************************************************
Function: PrintBaseRelocation
Description: ��ӡ�ض�λ��
Calls:
Called By:
Table Accessed:
Table Updated:
Input: filePath	��׼PE�ļ����ַ�����ʽ pFileBuffer �ļ�������
Output:
Return:
Others: 
*************************************************/
DWORD PrintBaseRelocation(LPSTR inFilePath);

/*************************************************
Function: PrintImportDirectory
Description: ��ӡ������
Calls:
Called By:
Table Accessed:
Table Updated:
Input: filePath	��׼PE�ļ����ַ�����ʽ pFileBuffer �ļ�������
Output:
Return:
Others:
*************************************************/
DWORD PrintImportDescriptor(LPSTR inFilePath);

DWORD PrintBoundImportDescriptor(LPSTR inFilePath);

DWORD GetSectionNum(LPVOID pFileBuffer, DWORD foaData);