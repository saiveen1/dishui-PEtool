#pragma once
#include "PE_Headers.h"
/*************************************************
Function: SectionInject
Description: ���NO���ڱ�Ľ�β���shellcode
Calls:	initializePeheader ReadPeFile
Called By: SectionAllocate
Table Accessed:
Table Updated:
Input: �ļ����� Դ�ļ� ����ļ� �ڱ��� �������
Output: 
Return: �ɹ����ز���λ�� ����0
Others: ���Ըĳɿ�ͷ��� ��������ν ���ø���
		��������PE�ļ��ṹ�Ѿ����Ĺ���û������ ��Ϊ����ǰ��ձ�׼PEͷ�ĸ�ʽ��д�Ĵ���
*************************************************/
DWORD SectionInject(LPSTR inFilePath, LPSTR outFilePath, DWORD sectionNO, BYTE * shellCode, size_t sizeOfShellCode);

/*************************************************
Function: SectionAllocate
Description: ���һ���µĽڱ� �����shellcode����
Calls:	InitializePeheader ReadPeFile SectionInject BufferToFile
Called By:
Table Accessed:
Table Updated:
Input: �ļ������ַ �½����� �½ڴ�С
Output:������Ҳ��Ϊ���ӽں��µĻ�����!	�¼ӽڵ��ļ���ַ
Return: �ɹ������µĻ�������ַ, ����NULl
Others: �����ڱ������ļ���SectionInject�������ļ�
//4.29 ���˺ܳ�ʱ�� ����Ǻ����׵����� �����ļ�һ��Ҫע���ļ���С
//4.29 һ��ʹ��malloc���������϶���οռ�ֻ����ô��, û����������x�ռ� ���������ռ䲢���������������Ҫ�ٿ�����һ��������(����x)Ȼ�󱣴�
//ͬ����enlarge����Ҳ����� ��ס��
*************************************************/
DWORD AllocateNewSection(BYTE * nameOfSecton, size_t sizeOfNewSection, IN LPSTR inFilePath, OUT DWORD *addrOutFilePath);

/*************************************************
Function: EnlargeTheLastSection
Description: ����ڱ�
Calls:	InitializePeheader ReadPeFile BufferToFile
Called By:
Table Accessed:
Table Updated:
Input: �ļ����� Դ�ļ� ����ļ� �����ֽ���
Output:
Return: �ɹ�����1 ����0
Others:
*************************************************/
DWORD EnlargeTheLastSection(LPSTR inFilePath, LPSTR outFilePath, size_t sizeOfEnlarge);

/*************************************************
Function: MergeSections
Description: �ϲ�
Calls:	InitializePeheader ReadPeFile CopyFileBufferToImageBuffer BufferToFile
Called By:
Table Accessed:
Table Updated:
Input: �ļ����� Դ�ļ� ����ļ�
Output:
Return: �ɹ�����1 ����0
Others: ��Ҫ���е��ڴ滺����(����) ��Ϊÿ�����εĴ�С�ǲ�һ����,�������FileBuffer�� �����ڴ��ʱ��������ε�ƫ���Ҳ�����(�Ѿ��ϲ� ��������Щ��Ϣ��)
		���Ծ���Ҫ���쵽�ڴ�����Ȼ����FileBuffer�ĸ�ʽ�洢(������ص�!!!!!!)
		SecitonAlignment��ʼ��ƫ�ƴ浽FileAlignment��
*************************************************/
DWORD MergeSections(LPSTR inFilePath, LPSTR outFilePath);

DWORD MoveExportDirectory(LPSTR inFilePath, LPSTR outFilePath, BOOL newSection);

DWORD MoveBaseRelocation(LPSTR inFilePath, LPSTR outFilePath);

DWORD ChangeImageBase(LPSTR inFilePath, LPSTR outFilePath, DWORD newImageBase);

/*************************************************
Function: MoveImportDescriptor
Description: �ƶ����������ṹ
Calls:	InitializePeheader ReadPeFile CopyFileBufferToImageBuffer BufferToFile
Called By:
Table Accessed:
Table Updated:
Input: �ļ����� Դ�ļ� ����ļ� ��Ҫ���ӵ��µ����(��ǰ��׼��)
Output:
Return: �ɹ����ص�������� ������Ҫ�����½�
Others: ������getfreespaceֱ������һ���½�,��Ϊ�������ᷢ���ı�, ������ض�Ҫ���¸�ֵ
*************************************************/
DWORD MoveImportDescriptor(LPSTR inFilePath, LPSTR outFilePath, DWORD numOfNewImportDescriptors);
DWORD MoveImportDescriptor2(LPSTR inFilePath, LPSTR outFilePath, DWORD numOfNewImportDescriptors);


//char *nameOfDataDirectory[16]

/*************************************************
Function: ImportDescriptorInject
Description: �����ע��
Calls:	InitializePeheader ReadPeFile CopyFileBufferToImageBuffer BufferToFile
Called By:
Table Accessed:
Table Updated:
Input:Դ�ļ� ����ļ� dll���� dll�еĺ������� ����������
Output:
Return: �ɹ�����1 ������Ҫ�����½�
Others: ������getfreespaceֱ������һ���½�,��Ϊ�������ᷢ���ı�, ������ض�Ҫ���¸�ֵ
*************************************************/
DWORD ImportDescriptorInject(LPSTR inFilePath, LPSTR outFilePath, LPSTR nameOfDll, char **nameOfFunctions, DWORD numOfFunctions);