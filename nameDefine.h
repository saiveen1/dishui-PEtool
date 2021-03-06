#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <algorithm>
//max min sum ...函数
#include <time.h>
#include <conio.h>

#pragma warning(disable:4996)

#define XP_MESSAGEBOX 0x77d507ea
#define ADDRESSS_OF_MESSAGEBOX &MessageBox
#define SIZE_OF_SHELLCODE sizeof(shellCode) / sizeof(*shellCode)
#define SIZE_OF_SECTION 0x28
#define SIZE_OF_SECTION_NAME 0x8
#define SIZE_OF_DOSHEADER 0x40
#define SIZE_OF_EXPORTDIRECTORY 0x28
#define SIZE_OF_IMPORT_DESCRIPTOR 0x14
#define SIZE_OF_RESOURCE_DIRECTORY 0x10
#define SIZE_OF_NEWSECTION_MOVE_IMPORT 0x1000	//移动导入表新加节大小
#define SIZE_OF_NEWSECTION_MOVE_EXPORT 0x100000	//移动导出表新加节大小
#define MAX_CHAR_ARR 20
#define TODO 0
#define NEED_TO_ALLOCATE_NEW_SECTION 2			//需要添加新的节



typedef struct PeSimplifyList
{
	DWORD sizeOfOptionalHeader;	//In FileHeader
	DWORD sizeOfHeaders;		//In OptionalHeader
	DWORD sizeOfImage;
	DWORD numOfSections;		//FileHeader
	DWORD addressEntryPoint;
	DWORD imageBase;
	DWORD fileAlignment;
	DWORD sectionAlignment;
	DWORD numOfRvaAndSizes;
	//DWORD offsetOfFileHeader;	//DosHeader
	//DWORD offsetOfOptionalHeader;
	//DWORD offsetOfSectionHeader;

	//DWORD virtualAddress;
	//DWORD virtualSize;
	//DWORD sizeOfRawData;
	//DWORD pointerToRawData;//不确定是哪个节 不能这样赋值
}SList, *PeList;

typedef struct Header
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTheaders = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
}*pHeader;

//资源类型名称映射表
typedef struct tagRES_ID_NAME_TABLE
{
	LPSTR	id;
	char	name[_MAX_PATH];
}WinResource;

