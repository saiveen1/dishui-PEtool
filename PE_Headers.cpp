#include "nameDefine.h"
#include "PE_Headers.h"
const char *nameOfDataDirectory[16] =
{
	"导入表  ",
	"导入表  ",
	"资源    ",
	"异常    ",
	"安全证书",
	"重定位表",
	"调试信息",
	"版权所有",
	"全局指针",
	"TLS表   ",
	"加载配置",
	"绑定导入",
	"IAT表   ",
	"延迟导入",
	"COM     ",
	"保留    ",
};
static DWORD sizeOfFile = 0;

void InitializePheader(IN LPVOID pBuffer, OUT pHeader pHeader, OUT PeList PeList)
{
	pHeader->pDosHeader = (PIMAGE_DOS_HEADER)((DWORD)pBuffer);
	pHeader->pNTheaders = (PIMAGE_NT_HEADERS)((DWORD)pHeader->pDosHeader + pHeader->pDosHeader->e_lfanew);
	pHeader->pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pHeader->pDosHeader + pHeader->pDosHeader->e_lfanew + 0x4);
	pHeader->pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pHeader->pFileHeader + 0x14);
	pHeader->pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pHeader->pOptionalHeader + pHeader->pFileHeader->SizeOfOptionalHeader);

	PeList->numOfSections = pHeader->pFileHeader->NumberOfSections;
	PeList->sizeOfOptionalHeader = pHeader->pFileHeader->SizeOfOptionalHeader;
	PeList->sizeOfHeaders = pHeader->pOptionalHeader->SizeOfHeaders;
	PeList->sizeOfImage = pHeader->pOptionalHeader->SizeOfImage;
	PeList->addressEntryPoint = pHeader->pOptionalHeader->AddressOfEntryPoint;
	PeList->imageBase = pHeader->pOptionalHeader->ImageBase;
	PeList->sectionAlignment = pHeader->pOptionalHeader->SectionAlignment;
	PeList->numOfRvaAndSizes = pHeader->pOptionalHeader->NumberOfRvaAndSizes;
	PeList->fileAlignment = pHeader->pOptionalHeader->FileAlignment;
}

LPVOID ReadPeFile(LPSTR lpszFile, OUT DWORD * fileSize)
{
	FILE* pFile = NULL;
	LPVOID pFileBuffer = NULL;

	//Open file.
	if (!(pFile = fopen(lpszFile, "rb")))	
	{
		printf("Can't open the executable file");
		exit(0);
	}

	//Read the length of file.
	fseek(pFile, 0, SEEK_END);
	*fileSize = ftell(pFile);
	
	//Allocate memory.
	//写到sectionAllocate才发现这个问题 编译器会自动在分配空间的后面+0x30个空间
	if (!(pFileBuffer = malloc(*fileSize)))
	{
		printf("Allocate memory failed.");
		fclose(pFile);
		exit(0);
	}

	fseek(pFile, 0, SEEK_SET);
	size_t n = fread(pFileBuffer, *fileSize, 1, pFile);
	//成功返回1
	if (!n)
	{
		printf("Read data failed!");
		free(pFileBuffer);
		fclose(pFile);
		exit(0);
	}

	fclose(pFile);
	return pFileBuffer;
}

DWORD IsStandardPeFile(LPVOID pBuffer)
{	
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;

	if (*(PWORD)pBuffer != IMAGE_DOS_SIGNATURE)
	{
		printf("It's not a available MZ signature.");
		free(pBuffer);
		return FALSE;
	}

	if (*((PDWORD)((DWORD)pBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("It's not a available PE signature.");
		free(pBuffer);
		return FALSE;
	}

	return TRUE;
}

DWORD GetFreeSpaceInSection(LPVOID pFileBuffer, size_t sizeOfAddedData, BOOL changeVirtualSize, DWORD sizeOfFile)
{
	Header header;
	SList slist;
	DWORD foaFreeSpace = 0;

	InitializePheader(pFileBuffer, &header, &slist);

	PIMAGE_SECTION_HEADER pLastSectionHeader = header.pSectionHeader + slist.numOfSections - 1;
	if (pLastSectionHeader->SizeOfRawData + pLastSectionHeader->PointerToRawData < (sizeOfFile - 1))
	{
		DWORD dw_temp = pLastSectionHeader->SizeOfRawData + pLastSectionHeader->PointerToRawData + (DWORD)pFileBuffer;
		DWORD sizeOfUselessSpace = sizeOfFile - (pLastSectionHeader->SizeOfRawData + pLastSectionHeader->PointerToRawData) - 1;
		memset((LPVOID)dw_temp, 0, sizeOfUselessSpace); //内存对齐
		pLastSectionHeader->SizeOfRawData = pLastSectionHeader->SizeOfRawData + sizeOfUselessSpace;
		header.pOptionalHeader->SizeOfImage += sizeOfUselessSpace;
	}

	for (DWORD i = 0; i < slist.numOfSections; i++)
	{
		DWORD foaNextSection = header.pSectionHeader->PointerToRawData + header.pSectionHeader->SizeOfRawData;
		//花了两个小时...就因为这个地方, 要减去当前区段的文件偏移才是空闲空间
		DWORD freeSpace = foaNextSection - header.pSectionHeader->Misc.VirtualSize - header.pSectionHeader->PointerToRawData;

		if (sizeOfAddedData < freeSpace && ((int)freeSpace > 0))
		{
			foaFreeSpace = header.pSectionHeader->PointerToRawData + header.pSectionHeader->Misc.VirtualSize;
			if (changeVirtualSize)
				header.pSectionHeader->Misc.VirtualSize += sizeOfAddedData;
			
			return foaFreeSpace;
		}
		header.pSectionHeader++;
	}

	return NEED_TO_ALLOCATE_NEW_SECTION;
}

void PrintNTHeaders(LPSTR inFilePath)
{
	Header header;
	SList slist;

	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);

	if (!IsStandardPeFile(pFileBuffer))
	{
		printf("IMAGETOFILE出错.");
		free(pFileBuffer);
		return;
	}

	printf("********************DOS头********************\n");
	printf("e_magic		MZ标志: %x\n",header.pDosHeader->e_magic);
	printf("e_lfanew	PE偏移: %x\n",header.pDosHeader->e_lfanew);

	printf("\n********************NT头********************\n");
	printf("NTheaders->Signature PE标志: %x\n", header.pNTheaders->Signature);
	
	printf("\n********************PE头********************\n");
	printf("Machine: %x\n", header.pFileHeader->Machine);
	printf("NumberOfSections	节的数量: %x\n", header.pFileHeader->NumberOfSections);
	printf("SizeOfOptionalHeader头的大小OptionalHeader: %x\n", header.pFileHeader->SizeOfOptionalHeader);

	printf("\n****************optionPE头******************\n");
	printf("AddressOfEntryPoint 程序入口地址OEP: %x\n", header.pOptionalHeader->AddressOfEntryPoint);
	printf("ImageBase虚拟内存地址: %x\n", header.pOptionalHeader->ImageBase);
	printf("SectionAlignment内存对齐大小: %x\n", header.pOptionalHeader->SectionAlignment);
	printf("FileAlignment文件对齐大小: %x\n", header.pOptionalHeader->FileAlignment);

	printf("\n****************Section头******************\n");
	for (int i = 0; i < header.pFileHeader->NumberOfSections; i++)
	{
		//char *temp = (char *)pSecitonHeader->Name;
		printf("Name:");
		int j = 0;
		while (*(header.pSectionHeader->Name + j) && j != 8)
			printf("%c", *(header.pSectionHeader->Name + j++));
		puts("");

		printf("Misc		未对齐前的分区大小 可修改 没啥用: %x\n", header.pSectionHeader->Misc.VirtualSize);
		printf("VirtualAddress	节区在内存中的偏移 需要加上ImageBase: %x\n", header.pSectionHeader->VirtualAddress);
		printf("SizeOfRawData	节区在对齐后的尺寸: %x\n", header.pSectionHeader->SizeOfRawData);
		printf("PointerToRawData节区在文件中的偏移: %x\n", header.pSectionHeader->PointerToRawData);
		printf("0XC的无效数据\n");
		printf("Characteristics 节区属性: %x\n", header.pSectionHeader->Characteristics);
		puts("\n********************************************************************************");

		header.pSectionHeader++;
	}
	printf("\n\n\n\n\n\n\n\n\n\n");
	free(pFileBuffer);
}

DWORD CopyFileBufferToImageBuffer(LPSTR inFilePath,OUT LPVOID *pImageBuffer)
{
	Header header;
	SList slist;

	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);

	if (!IsStandardPeFile(pFileBuffer))
	{
		printf("IMAGETOFILE出错.");
		free(pFileBuffer);
		return 0;
	}

	*pImageBuffer = malloc(slist.sizeOfImage);
	memset(*pImageBuffer, 0, slist.sizeOfImage);
	memcpy(*pImageBuffer, pFileBuffer, slist.sizeOfHeaders);
		
	for (DWORD i = 0; i < slist.numOfSections; i++)
	{
		//大小用大的 size of raw data
		memcpy((LPVOID)((DWORD)*pImageBuffer + header.pSectionHeader->VirtualAddress), (LPVOID)((DWORD)pFileBuffer + header.pSectionHeader->PointerToRawData), header.pSectionHeader->SizeOfRawData);
		header.pSectionHeader++;
	}

	if (!IsStandardPeFile(pFileBuffer))
	{
		printf("Copy from FileBuffer to ImageBuffer failed.\n");
		free(*pImageBuffer);
		free(pFileBuffer);
		return NULL;
	}

	free(pFileBuffer);

	return slist.sizeOfImage;
}

DWORD RvaDataToFoaData(IN LPVOID pImageBuffer, IN DWORD dwRvaDataAddress)
{
	Header header;
	SList slist;
	DWORD virtualAddress = 0;
	DWORD imageSectionSize = 0;
	
	InitializePheader(pImageBuffer,&header,&slist);

	//5.18在做绑定导出表的时候 RVA 250返回0显然错的 , 没有想到在区段前的数据 如果在, 直接返回即可
	if (dwRvaDataAddress < header.pSectionHeader->PointerToRawData)
		return dwRvaDataAddress;

	for (DWORD i = 0; i < slist.numOfSections; i++)
	{
		virtualAddress = header.pSectionHeader->VirtualAddress;
		imageSectionSize = virtualAddress + header.pSectionHeader->Misc.VirtualSize;

		if (dwRvaDataAddress >= virtualAddress && dwRvaDataAddress < imageSectionSize)
			return dwRvaDataAddress - virtualAddress + header.pSectionHeader->PointerToRawData;	//fileOffset

		header.pSectionHeader++;
	}

	return 0;
}

DWORD FoaDataToRvaData(IN LPVOID pFileBuffer, IN DWORD dwRawDataAddress)
{
	Header header;
	SList slist;
	DWORD fileOffset = dwRawDataAddress;
	DWORD fileSectionOffset = 0;
	DWORD fileSectionSize = 0;

	InitializePheader(pFileBuffer, &header, &slist);
	
	//5.14发现有的DLL文件会有个textbss段, 只占用内存空间 里面是未初始化的全局变量
	//BSS: Block started by symbols
	if (!strcmp((const char *)header.pSectionHeader->Name, ".textbss"))
		header.pSectionHeader++;

	for (DWORD i =0;i<slist.numOfSections;i++)
	{
		fileSectionOffset = header.pSectionHeader->PointerToRawData;
		fileSectionSize = fileSectionOffset + header.pSectionHeader->SizeOfRawData;

		if (fileOffset >= fileSectionOffset && fileOffset < fileSectionSize)	//不能==file section size 等于的话应该算在下一个区段
			return dwRawDataAddress - fileSectionOffset + header.pSectionHeader->VirtualAddress;

		header.pSectionHeader++;
	}

	return 0;
}

DWORD CopyImageBufferToFileBuffer(IN LPVOID pImageBuffer, OUT LPVOID * pFileBuffer)
{
	Header header;
	SList slist;
	DWORD i = 0;
	DWORD sizeOfFileBuffer = 0;

	if (!IsStandardPeFile(pImageBuffer))
	{
		printf("FILETOIMAGE出错.");
		free(pImageBuffer);
		free(*pFileBuffer);
		return 0;
	}

	InitializePheader(pImageBuffer, &header,&slist);

	//printf("%x", (header.pSecitonHeader + slist.numOfSections));
	//数组-1 竟然这种问题纠结半小时...
	//直接用最后一个区段的文件偏移加大小即可
	sizeOfFileBuffer = (header.pSectionHeader + slist.numOfSections - 1)->SizeOfRawData + (header.pSectionHeader + slist.numOfSections - 1)->PointerToRawData;
	*pFileBuffer = malloc(sizeOfFileBuffer);
	memset(*pFileBuffer, 0, sizeOfFileBuffer);
	memcpy(*pFileBuffer,pImageBuffer,slist.sizeOfHeaders);	//节表需要压缩后存入FILEBUFFER

	for (; i < slist.numOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)*pFileBuffer + header.pSectionHeader->PointerToRawData), (LPVOID)((DWORD)pImageBuffer + header.pSectionHeader->VirtualAddress), header.pSectionHeader->SizeOfRawData);
		header.pSectionHeader++;	//在memcpy里(header.pSecitonHeader++).SizeOfRawData不合法
	}
	header.pSectionHeader -= i;

	if (!IsStandardPeFile(pImageBuffer))
	{
		printf("IMAGETOFILE出错.");
		free(pImageBuffer);
		free(*pFileBuffer);
		return 0;
	}

	DWORD dw_temp = (DWORD)pImageBuffer + header.pSectionHeader->VirtualAddress;
	printf("This is a test for RvaDataOffset to RawDataOffset.\n");
	printf("VirtualAddress: \n%x\nIn FileBuffer:\n%x.\n\n\n",dw_temp - (DWORD)pImageBuffer, RvaDataToFoaData(pImageBuffer, dw_temp));

	free(pImageBuffer);

	return sizeOfFileBuffer;
}

DWORD BufferToFile(IN LPVOID pMemBuffer, IN size_t fileSize, OUT LPSTR lpszFile)
{

	FILE * pfile = NULL;
	if (!(pfile = fopen(lpszFile, "wb")))
	{
		printf("Create file failed.");
		exit(0);
	}

	if (!fwrite(pMemBuffer, fileSize, 1, pfile))
	{
		printf("Create a executable file failed.");
		fclose(pfile);
		return 0;
	}

	if (!IsStandardPeFile(pMemBuffer))
	{
		printf("保存出错不是标准PE文件.");
		fclose(pfile);
		return 0;
	}
		

	fclose(pfile);
	return fileSize;
}

DWORD TraverseDataDirectory(LPSTR inFilePath)
{
	Header header;
	SList slist;
	DWORD fileSize = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;

	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);

	pDataDirectory = header.pOptionalHeader->DataDirectory;
	
	for (DWORD i = 0; i < slist.numOfRvaAndSizes; i++)
	{
		printf("%s    ", *(nameOfDataDirectory + i));
		printf("VirtualAddress: %x				",pDataDirectory[i].VirtualAddress);
		printf("Size: %x\n", pDataDirectory[i].Size);
	}

	return 0;
}

DWORD PrintExportDirectory(LPSTR inFilePath)
{
	Header header;
	SList slist;
	DWORD fileSize = 0;
	DWORD foaExportDirectory = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);
	pDataDirectory = header.pOptionalHeader->DataDirectory;
	foaExportDirectory = RvaDataToFoaData(pFileBuffer, (*pDataDirectory).VirtualAddress);
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(foaExportDirectory + (DWORD)pFileBuffer);

	printf("Characteristic: %d\n", pExportDirectory->Characteristics);
	printf("TimeDateStamp: %d\n", pExportDirectory->TimeDateStamp);
	printf("MajorVersion: %d\n", pExportDirectory->MajorVersion);
	printf("MinorVersion: %d\n", pExportDirectory->MinorVersion);

	DWORD dw_temp = RvaDataToFoaData(pFileBuffer, pExportDirectory->Name);
	printf("Name: %x	FOA: %x\n", pExportDirectory->Name, dw_temp);
	printf("String: %s\n", (char *)(DWORD(pFileBuffer) + dw_temp));

	printf("Base: %d\n", pExportDirectory->Base);
	printf("NumberOfFunctions: %d\n", pExportDirectory->NumberOfFunctions);
	printf("NumberOfNames: %d\n", pExportDirectory->NumberOfNames);

	dw_temp = RvaDataToFoaData(pFileBuffer, pExportDirectory->AddressOfFunctions);
	printf("AddressOfFunctions: %x		FOA: %X\n", pExportDirectory->AddressOfFunctions,dw_temp);
	for (DWORD i = 0; i < pExportDirectory->NumberOfFunctions; i++)
	{	//名字地址转换FOA才是真正的名字
		printf("AddressOfFuncition %d: %x\n", i,RvaDataToFoaData(pFileBuffer, *(DWORD *)((DWORD)pFileBuffer + dw_temp)));
		dw_temp += 4;
	}

	dw_temp = RvaDataToFoaData(pFileBuffer, pExportDirectory->AddressOfNames);
	printf("AddressOfNames: %x		FOA: %X\n", pExportDirectory->AddressOfNames, dw_temp);
	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
	{	//名字地址转换FOA才是真正的名字
		char *nameOfFunction = (char *)((DWORD)(pFileBuffer) + RvaDataToFoaData(pFileBuffer, *(DWORD *)((DWORD)pFileBuffer + dw_temp)));
		printf("NameOfFuncition %d: %s\n", i, nameOfFunction);
		dw_temp += 4;
	}

	dw_temp = RvaDataToFoaData(pFileBuffer, pExportDirectory->AddressOfNameOrdinals);	//Ordinals用Word存储!!!!
	printf("AddressOfNameOrdinals: %x	FOA: %x\n", pExportDirectory->AddressOfNameOrdinals, dw_temp);
	for(DWORD i=0;i<pExportDirectory->NumberOfNames;i++)
	{	
		//需要加base
		printf("OrdinalOfFunction %d: %x\n", i, *(WORD *)((DWORD)(pFileBuffer) + dw_temp) + pExportDirectory->Base);
		dw_temp += 2;
	}
	
	return 0;
}

DWORD GetFunctionAddrByName(LPVOID pFileBuffer, LPSTR functionToFind)
{
	Header header;
	SList slist;
	DWORD foaExportDirectory = 0;
	//char *nameOfFuncitons[MAX_CHAR_ARR] = {};
	DWORD i = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	DWORD currentNumOfFunction = 0;
	DWORD addrOfNamesRVA = 0;

	InitializePheader(pFileBuffer, &header, &slist);
	pDataDirectory = header.pOptionalHeader->DataDirectory;
	foaExportDirectory = RvaDataToFoaData(pFileBuffer, (*pDataDirectory).VirtualAddress);
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(foaExportDirectory + (DWORD)pFileBuffer);

	DWORD dw_temp = RvaDataToFoaData(pFileBuffer, pExportDirectory->AddressOfNames);
	for (; i < pExportDirectory->NumberOfNames; i++)
	{
		//坑爹的系统函数 相等竟然是为0
		if (!strcmp(functionToFind, (char *)((DWORD)pFileBuffer+RvaDataToFoaData(pFileBuffer,*(DWORD *)((DWORD)pFileBuffer+dw_temp)))))
			break;
		dw_temp += 4;
	}

	if (i == 4)
		return 0;

	dw_temp = RvaDataToFoaData(pFileBuffer, pExportDirectory->AddressOfNameOrdinals);
	currentNumOfFunction = *((WORD *)((DWORD)(pFileBuffer)+dw_temp) + i);

	dw_temp = RvaDataToFoaData(pFileBuffer, pExportDirectory->AddressOfFunctions);
	printf("%s 's address is: %x: ", functionToFind, RvaDataToFoaData(pFileBuffer, *((DWORD *)((DWORD)pFileBuffer + dw_temp)+currentNumOfFunction)));

	return 0;
}
//
//Header header;
//SList slist;
//DWORD fileSize = 0;
//
//pFileBuffer = ReadPeFile(inFilePath, &fileSize);
//InitializePheader(pFileBuffer, &header, &slist);

DWORD PrintBaseRelocation(LPSTR inFilePath)
{
	Header header;
	SList slist;
	DWORD fileSize = 0;
	DWORD foaBaseRelocation = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pBaseRelocation = NULL;

	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);
	pDataDirectory = header.pOptionalHeader->DataDirectory;
	foaBaseRelocation = RvaDataToFoaData(pFileBuffer, (*(pDataDirectory+5)).VirtualAddress);
	pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + foaBaseRelocation);

	DWORD i = 0;
	DWORD foaOfData = 0;
	DWORD rvaOfData = 0;
	DWORD currentBlockItems = 0;
	DWORD numOfDataToModify = 0;
	DWORD foaOfBlock = 0;
	DWORD attributeOfData = 0;
	DWORD sizeOfRelocation = 0;

	while (pBaseRelocation->SizeOfBlock)
	{
		//要修改的数据大表在文件中的偏移 大表 + word 型偏移
		foaOfBlock = (DWORD)pBaseRelocation - (DWORD)pFileBuffer;
		printf("Block %2d    RVA: %x\n", 1 + i++, pBaseRelocation->VirtualAddress);
		//printf("Block %2d    RVA: %x    FOA: %x\n", 1 + i++, pBaseRelocation->VirtualAddress, foaOfBlock);
		currentBlockItems = (pBaseRelocation->SizeOfBlock - 8) / 2;	//word 表示
		printf("Items: %2x\n", currentBlockItems);
		sizeOfRelocation = sizeOfRelocation + 8 + pBaseRelocation->SizeOfBlock;

		DWORD k = 0;
		DWORD addressOf_rvaOfData = pBaseRelocation->VirtualAddress;
		DWORD farAddress = 0;
		pBaseRelocation->VirtualAddress += 8;	//RVA start of the block data
		while (currentBlockItems--)
		{
			rvaOfData = ((*(WORD *)(foaOfBlock + (DWORD)pFileBuffer + 8)) & 0x0fff) + addressOf_rvaOfData;
			foaOfData = (DWORD)RvaDataToFoaData(pFileBuffer,rvaOfData);
			farAddress = *(DWORD *)(foaOfData + (DWORD)pFileBuffer);
			if ((*(DWORD *)(foaOfBlock + (DWORD)pFileBuffer + 8) & 0x3000) == 0x3000)
				attributeOfData = 3;
			else
				attributeOfData = 0;
			printf("NO. %2d    RVA: %2x    FOA: %2x    FarAddress: %2x  Attribute: %d\n", 1 + k++, rvaOfData, foaOfData, farAddress, attributeOfData);
			foaOfBlock += 2;
			pBaseRelocation->VirtualAddress += 2;
		}

		pBaseRelocation->VirtualAddress = pBaseRelocation->VirtualAddress - 2 * k;
		puts("");
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}

	free(pFileBuffer);
	return sizeOfRelocation;
}

DWORD PrintImportDescriptor(LPSTR inFilePath)
{
	Header header;
	SList slist;
	DWORD fileSize = 0;
	DWORD foaImportDescriptor = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;

	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);

	pDataDirectory = header.pOptionalHeader->DataDirectory;
	foaImportDescriptor = RvaDataToFoaData(pFileBuffer, (*(pDataDirectory + 1)).VirtualAddress);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + foaImportDescriptor);

	while (pImportDescriptor->OriginalFirstThunk)
	{
		DWORD rvaFirstThunk = pImportDescriptor->FirstThunk;
		DWORD rvaOriginalFirstThunk = pImportDescriptor->OriginalFirstThunk;
		printf("RVA_OriginalFirstTunk: %2x    RVA_Name: %2x    RVA_FirstThunk: %2x\n", pImportDescriptor->OriginalFirstThunk, pImportDescriptor->Name, pImportDescriptor->FirstThunk);
		DWORD FOA_Name = RvaDataToFoaData(pFileBuffer, pImportDescriptor->Name);
		printf("DLL's name: %s\n", (char *)((DWORD)pFileBuffer + FOA_Name));
		printf("-------------------------------------------------------------------------\n");

		DWORD foaOriginalFirstThunk = RvaDataToFoaData(pFileBuffer, rvaOriginalFirstThunk);
		DWORD originalThunkValue = *(DWORD *)((DWORD)pFileBuffer + foaOriginalFirstThunk);
		printf("Show the OriginalFirstThunk:\n");
		while (originalThunkValue)
		{
			printf("RVA_OriginalFirstThunk: %2x    FOA_OriginalFirstThunk: %2x", pImportDescriptor->OriginalFirstThunk, foaOriginalFirstThunk);
			printf("    OriginalThunkValue: %2x\n", originalThunkValue);
			if ((originalThunkValue & 0x80000000) == 0x80000000)
			{
				DWORD ordinalOfFunction = (originalThunkValue & 0x0FFFFFFF);
				TODO;
			}
			else
			{
				DWORD RVA_OFT_HintAndNameOfFunction = originalThunkValue;
				DWORD FOA_OFT_HintAndNameOfFunction = RvaDataToFoaData(pFileBuffer, RVA_OFT_HintAndNameOfFunction);
				WORD hint = *(WORD *)((DWORD)pFileBuffer + FOA_OFT_HintAndNameOfFunction);
				char * NameOfFunction = (char *)((DWORD)pFileBuffer + FOA_OFT_HintAndNameOfFunction + 2);
				printf("RVA_OriginalThunkNameOfFunction: %2x    FOA_NameOfFunction: %2x\n", RVA_OFT_HintAndNameOfFunction, FOA_OFT_HintAndNameOfFunction);
				printf("OriginalThunkHint: %2x\nNameOfFunction: %2s\n\n", hint, NameOfFunction);
			}
			pImportDescriptor->OriginalFirstThunk += 4;	//结束otf遍历时不用再恢复是因为不需要保存!!!
			foaOriginalFirstThunk = RvaDataToFoaData(pFileBuffer, pImportDescriptor->OriginalFirstThunk);
			originalThunkValue = *(DWORD *)((DWORD)pFileBuffer + foaOriginalFirstThunk);
		}
		puts("");

		DWORD foaFirstThunk = RvaDataToFoaData(pFileBuffer, rvaFirstThunk);
		DWORD firstThunkValue = *(DWORD *)((DWORD)pFileBuffer + foaFirstThunk);
		printf("Show the FirstThunk: \n");
		while (firstThunkValue)
		{
			printf("RVA_FirstThunk: %2x            FOA_FirstThunk: %2x", rvaFirstThunk, foaFirstThunk);
			
			printf("            FirstThunkValue: %2x\n", firstThunkValue);
			if ((firstThunkValue & 0x80000000) == 0x80000000)
			{
				DWORD ordinalOfFunction = (firstThunkValue & 0x7FFFFFFF);
				TODO;
			}
			else
			{
				DWORD RVA_FT_HintAndNameOfFunction = firstThunkValue;
				DWORD FOA_FT_HintAndNameOfFunction = RvaDataToFoaData(pFileBuffer, RVA_FT_HintAndNameOfFunction);
				WORD hint = *(WORD *)((DWORD)pFileBuffer + FOA_FT_HintAndNameOfFunction);
				char * NameOfFunction = (char *)((DWORD)pFileBuffer + FOA_FT_HintAndNameOfFunction + 2);
				printf("RVA_FirstThunkNameOfFunction: %2x    FOA_FirstThunkNameOfFunction: %2x\n", RVA_FT_HintAndNameOfFunction, FOA_FT_HintAndNameOfFunction);
				printf("FirstThunkHint: %2x\nFirstThunkNameOfFunction: %2s\n\n", hint, NameOfFunction);
			}
			pImportDescriptor->FirstThunk += 4;
			foaFirstThunk = RvaDataToFoaData(pFileBuffer, pImportDescriptor->FirstThunk);
			firstThunkValue = *(DWORD *)((DWORD)pFileBuffer + foaFirstThunk);
		}
		puts("");

		pImportDescriptor++;
		printf("-------------------------------------------------------------------------\n");
	}

	free(pFileBuffer);
	return 1;
}

DWORD PrintBoundImportDescriptor(LPSTR inFilePath)
{
	Header header;
	SList slist;
	DWORD fileSize = 0;
	DWORD foaBoundImportDescriptor = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDescriptor = NULL;
	PIMAGE_BOUND_FORWARDER_REF pBoundForwarderRef = NULL;

	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);

	pDataDirectory = header.pOptionalHeader->DataDirectory;
	foaBoundImportDescriptor = RvaDataToFoaData(pFileBuffer, (*(pDataDirectory + 11)).VirtualAddress);
	pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + foaBoundImportDescriptor);
	DWORD currentDLL_NOMFR = 0;

	while (pBoundImportDescriptor->TimeDateStamp)
	{
		if (currentDLL_NOMFR)
		{
			printf("The following %d items are ForwarderRefs\n", currentDLL_NOMFR--);
			printf("--------------------------------------------------------------------------------\n");
		}

		DWORD timeStamp = pBoundImportDescriptor->TimeDateStamp;
		DWORD offsetModuleName = pBoundImportDescriptor->OffsetModuleName;
		DWORD numOfModuleForwarderRefs = pBoundImportDescriptor->NumberOfModuleForwarderRefs;
		printf("TimeDateStamp: %x    OffsetModuleName: %x    NumOfModuleForwarderRefs: %xh\n", timeStamp, offsetModuleName, numOfModuleForwarderRefs);

		//NumOfMouleForwarderRefs
		if (numOfModuleForwarderRefs)
		{
			printf("Current DLL has forwarder_ref(s): %xh \n",numOfModuleForwarderRefs);
			currentDLL_NOMFR = numOfModuleForwarderRefs;
		}

		//TimeStamp
		time_t rawtime = timeStamp;
		struct tm* timeinfo;
		char timeStr[80];
		timeinfo = localtime((time_t *)&rawtime);
		strftime(timeStr, 80, "GMT:%Y-%m-%d %I:%M:%S\n", timeinfo);
		printf("%s", timeStr);

		//DLL' Name
		//偏移只需用第一个绑定导入表的即可 后续不变
		char *NameOfDLL = (char *)((DWORD)pFileBuffer + foaBoundImportDescriptor + offsetModuleName);
		printf("DLL's Name: %s\n\n", NameOfDLL);

		pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pBoundImportDescriptor + 0x8);
			
	}

	return 1;
}

DWORD GetSectionNum(LPVOID pFileBuffer, DWORD foaData)
{
	Header header;
	SList slist;
	DWORD fileOffset = foaData;
	DWORD fileSectionOffset = 0;
	DWORD fileSectionSize = 0;

	InitializePheader(pFileBuffer, &header, &slist);

	//5.14发现有的DLL文件会有个textbss段, 只占用内存空间 里面是未初始化的全局变量
	//BSS: Block started by symbols
	if (!strcmp((const char *)header.pSectionHeader->Name, ".textbss"))
		header.pSectionHeader++;

	for (DWORD i = 0; i < slist.numOfSections; i++)
	{
		fileSectionOffset = header.pSectionHeader->PointerToRawData;
		fileSectionSize = fileSectionOffset + header.pSectionHeader->SizeOfRawData;

		if (fileOffset >= fileSectionOffset && fileOffset < fileSectionSize)	//不能==file section size 等于的话应该算在下一个区段
			return i + 1;

		header.pSectionHeader++;
	}
	return 0;
}


