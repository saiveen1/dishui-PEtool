#include "ChangePe.h"
#include "nameDefine.h"
#include "PE_Headers.h"

DWORD sizeOfFile = 0;
BYTE nameOfNewSection[8] = { 0X2E,0X72,0X6E,0X65,0X77 };	//移动导入表需要添加节
char OUT newSectionOutFilePathForExe[] = "C:/Users/Admin/Desktop/PETEST/新加一个节.exe";
char OUT newSectionOutFilePathForDLL[] = "C:/Users/Admin/Desktop/PETEST/新加一个节.DLL";

DWORD SectionInject(LPSTR inFilePath, LPSTR outFilePath, DWORD sectionNO, BYTE * shellCode, size_t sizeOfShellCode)
{
	Header header;
	SList slist;
	DWORD imageOffset = 0;
	DWORD alertAddress = 0;
	DWORD injectAddress = 0;
	PIMAGE_SECTION_HEADER pInjectSectionHeader = NULL;
	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);

	pInjectSectionHeader = header.pSectionHeader + sectionNO - 1;

	//(pInjectSectionHeader+1)->PointerToRawData
	if ((pInjectSectionHeader->SizeOfRawData + pInjectSectionHeader->PointerToRawData - pInjectSectionHeader->Misc.VirtualSize) < sizeOfShellCode)
	{
		printf("该区段没有足够空间插入代码.\n");
		exit(0);
	}
	injectAddress = pInjectSectionHeader->SizeOfRawData + pInjectSectionHeader->PointerToRawData - sizeOfShellCode;	//区段结尾
	pInjectSectionHeader->Characteristics |= header.pSectionHeader->Characteristics;

	imageOffset = FoaDataToRvaData(pFileBuffer, injectAddress + 9);	//MessageBox E8
	alertAddress = (DWORD)ADDRESSS_OF_MESSAGEBOX - (slist.imageBase + (imageOffset + 4));
	DWORD *c_temp = (DWORD *)(shellCode + 9);
	*c_temp = alertAddress;

	imageOffset = FoaDataToRvaData(pFileBuffer, injectAddress + 14);	//JMP OEP E9
	alertAddress = header.pOptionalHeader->AddressOfEntryPoint -  (imageOffset + 4);
	c_temp = (DWORD *)(shellCode + 14);
	*c_temp = alertAddress;

	memcpy(LPVOID((DWORD)pFileBuffer+injectAddress), shellCode, 18);
	header.pOptionalHeader->AddressOfEntryPoint = FoaDataToRvaData(pFileBuffer, injectAddress);
	header.pOptionalHeader->DllCharacteristics = 0x8120;

	if (!BufferToFile(pFileBuffer, sizeOfFile, outFilePath))
		return 0;

	printf("MessageBox's address is: %x", (DWORD)ADDRESSS_OF_MESSAGEBOX);
	free(pFileBuffer);
	return injectAddress;
}

DWORD AllocateNewSection(BYTE * nameOfSecton, size_t sizeOfNewSection, IN LPSTR inFilePath, OUT DWORD *addrOutFilePath)
{
	Header header;
	SList slist;
	DWORD sizeOfAllocation = 0;
	DWORD sizeOfDosStub = 0;
	DWORD foaNewSection = 0;
	LPVOID pNewPFileBuffer = NULL;
	PIMAGE_SECTION_HEADER newSection = NULL;
	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer,&header,&slist);

	//最后一个节表后面有数据 删除DOS Stub	//如果垃圾数据也小于80bytes....应该不会碰到    这种情况 40也可用但还是写上吧
	//步骤  修改lfanew	修改OEP 剩下的头上移位	//要先修改 不然结构变了找不到原地址
	//修改NUMOFSECTIONS 修改SIZEOFIMAGE 新增一个节的数据(内存对齐的整数倍) 添加一个新的节(直接copy) 新的节后面再添加一个空节(保险起见) copy_的基础上修改节属性
	if (*(LPDWORD)(header.pSectionHeader + slist.numOfSections))	//是看里面的值!!!需要LPDWORD 两次错误了
	{
		DWORD dw_temp = header.pDosHeader->e_lfanew;
		header.pDosHeader->e_lfanew = SIZE_OF_DOSHEADER;
		header.pOptionalHeader->AddressOfEntryPoint -= sizeOfDosStub;
		sizeOfDosStub = dw_temp - SIZE_OF_DOSHEADER;
		if (sizeOfDosStub < 0x40)
		{
			printf("DosStub小于40,需要整体移动才能申请新节\n.");
			exit(0);
		}
		sizeOfAllocation = (DWORD)(header.pSectionHeader + slist.numOfSections) + SIZE_OF_SECTION - (DWORD)header.pNTheaders;
		memcpy((LPVOID)((DWORD)header.pDosHeader + SIZE_OF_DOSHEADER), (LPVOID)header.pNTheaders, sizeOfAllocation);
	}
	sizeOfAllocation = sizeOfNewSection;
	header.pFileHeader->NumberOfSections++;
	header.pOptionalHeader->SizeOfImage += sizeOfNewSection;
	slist.numOfSections++;	//定义的内容可以引用但无法更改 需要指针指向 工程量太大 不改了 因为下面还是用用到所以一起变
	slist.sizeOfImage += sizeOfNewSection;

	//printf("%x", (header.pSecitonHeader + slist.numOfSections - 2)->SizeOfRawData);
	//printf("%x", (header.pSecitonHeader + slist.numOfSections - 2)->PointerToRawData);

	foaNewSection = (header.pSectionHeader + slist.numOfSections - 2)->SizeOfRawData + (header.pSectionHeader + slist.numOfSections - 2)->PointerToRawData;
	sizeOfFile += sizeOfAllocation;
	pNewPFileBuffer = malloc(sizeOfFile);
	memset(pNewPFileBuffer, 0, sizeOfFile);
	memcpy(pNewPFileBuffer, pFileBuffer, sizeOfFile - sizeOfAllocation);
	InitializePheader(pNewPFileBuffer, &header, &slist);

	//这里的numofsections已经改变了 所以数组减1
	newSection = (PIMAGE_SECTION_HEADER)((DWORD)(header.pSectionHeader + slist.numOfSections - 1));	
	memcpy(newSection, header.pSectionHeader, SIZE_OF_SECTION);
	memset(newSection + 1, 0, SIZE_OF_SECTION);

	for (DWORD i = 0; i < SIZE_OF_SECTION_NAME; i++)
		newSection->Name[i] = nameOfSecton[i];
	newSection->SizeOfRawData = sizeOfNewSection;
	newSection->Misc.VirtualSize = 0;	//增加的新节里面应该是空的!!!
	DWORD dw_temp = ((newSection - 1)->Misc.VirtualSize / slist.sectionAlignment) + 1;
	if ((newSection - 1)->Misc.VirtualSize % slist.sectionAlignment)	//整数倍
		newSection->VirtualAddress = (newSection - 1)->VirtualAddress + dw_temp * slist.sectionAlignment;
	else
		newSection->VirtualAddress = (newSection - 1)->VirtualAddress + (dw_temp - 1) * slist.sectionAlignment;
	newSection->PointerToRawData = (newSection - 1)->PointerToRawData + (newSection - 1)->SizeOfRawData;
	//5.25太致命的错误了 section的Characteristic因为要插入dll写死了CALL地址 需要获取地址然后传入到里面 代表此块可写 然后一直没发现这个问题
	newSection->Characteristics |= 0xf0000000;

	if ((header.pFileHeader->Characteristics & 0x2000) == 0x2000)
	{
		BufferToFile(pNewPFileBuffer, sizeOfFile, newSectionOutFilePathForDLL);
		*addrOutFilePath = (DWORD)newSectionOutFilePathForDLL;
	}
	else
	{
		BufferToFile(pNewPFileBuffer, sizeOfFile, newSectionOutFilePathForExe);
		*addrOutFilePath = (DWORD)newSectionOutFilePathForExe;
	}

	free(pFileBuffer);
	free(pNewPFileBuffer);

	if (!*addrOutFilePath)
		exit(0);
	return foaNewSection;
}

DWORD EnlargeTheLastSection(LPSTR inFilePath, LPSTR outFilePath, size_t sizeOfEnlarge)
{
	Header header;
	SList slist;
	LPVOID lp_temp = NULL;
	LPVOID pNewFileBuffer = NULL;

	//步骤
	//增加空间 修改virtualsize SizeOfRawData SizeOfImage
	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);

	lp_temp=(LPVOID)((DWORD)pFileBuffer + sizeOfEnlarge);
	pNewFileBuffer = malloc((DWORD)pFileBuffer + sizeOfEnlarge);
	memset(pNewFileBuffer, 0, (DWORD)pFileBuffer + sizeOfEnlarge);
	memcpy(pNewFileBuffer, pFileBuffer, sizeOfFile);
	InitializePheader(pNewFileBuffer, &header, &slist);
	
	(header.pSectionHeader + slist.numOfSections - 1)->Misc.VirtualSize += sizeOfEnlarge;
	(header.pSectionHeader + slist.numOfSections - 1)->SizeOfRawData += sizeOfEnlarge;
	header.pOptionalHeader->SizeOfImage += sizeOfEnlarge;
	sizeOfFile += sizeOfEnlarge;

	BufferToFile(pNewFileBuffer, sizeOfFile+sizeOfEnlarge, outFilePath);
	free(pNewFileBuffer);
	free(pFileBuffer);

	return 0;
}

DWORD MergeSections(LPSTR inFilePath, LPSTR outFilePath)
{
	Header header;
	SList slist;
	DWORD i = 0;
	DWORD newCharacteristic = 0;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewFileBuffer = NULL;
	PIMAGE_SECTION_HEADER pTempSectionHeader = NULL;

	CopyFileBufferToImageBuffer(inFilePath, &pImageBuffer);
	InitializePheader(pImageBuffer, &header, &slist);
	pTempSectionHeader = header.pSectionHeader;

	pNewFileBuffer = malloc(slist.sizeOfImage);
	memset(pNewFileBuffer, 0, slist.sizeOfImage);
	memcpy(pNewFileBuffer, pImageBuffer, header.pOptionalHeader->SizeOfHeaders);
	InitializePheader(pNewFileBuffer, &header, &slist);
	//拷贝头
	DWORD sizeOfAllSections = slist.sizeOfImage - header.pSectionHeader->VirtualAddress;
	memcpy((LPVOID)((DWORD)pNewFileBuffer + header.pSectionHeader->PointerToRawData), (LPVOID)((DWORD)pImageBuffer + pTempSectionHeader->VirtualAddress), sizeOfAllSections);

	header.pSectionHeader->SizeOfRawData = sizeOfAllSections;
	header.pSectionHeader->Misc.VirtualSize = header.pSectionHeader->SizeOfRawData;
	header.pFileHeader->NumberOfSections = 1;

	for (; i < slist.numOfSections; i++)
	{
		newCharacteristic |= header.pSectionHeader->Characteristics;
		header.pSectionHeader++;	
	}
	header.pSectionHeader -= i;
	memset(header.pSectionHeader + 1, 0, SIZE_OF_SECTION * (slist.numOfSections - 1));
	header.pSectionHeader->Characteristics = newCharacteristic;
	
	BufferToFile(pNewFileBuffer, slist.sizeOfImage, outFilePath);
	free(pImageBuffer);
	return 0;
}

DWORD MoveExportDirectory(LPSTR inFilePath, LPSTR outFilePath, BOOL newSection)
{
	Header header;
	SList slist;
	DWORD foaOfNewSection = 0;
	DWORD foaExportDirectory = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);
	pDataDirectory = header.pOptionalHeader->DataDirectory;
	foaExportDirectory = RvaDataToFoaData(pFileBuffer, (*pDataDirectory).VirtualAddress);
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(foaExportDirectory + (DWORD)pFileBuffer);
	
	if (newSection)	//没用到FOA OF NEW SECTION
		TODO;//foaOfNewSection = (DWORD)pFileBuffer + SectionAllocate(pFileBuffer, inFilePath, outFilePath, nameOfNewSection, 0x10000);

	DWORD sizeOf_AddressOfFunctions = 4 * pExportDirectory->NumberOfFunctions;
	DWORD sizeOf_AddressOfNames = 4 * pExportDirectory->NumberOfFunctions;
	DWORD sizeOf_AddressOfNameOrdinals = 2 * pExportDirectory->NumberOfNames;

	DWORD copyFoa = (DWORD)pFileBuffer + (header.pSectionHeader + slist.numOfSections - 1)->PointerToRawData;
	DWORD orginalAddressOfFunctions= (DWORD)pFileBuffer + RvaDataToFoaData(pFileBuffer, pExportDirectory->AddressOfFunctions);
	DWORD foaOf_AddressOfFunctions = copyFoa - (DWORD)pFileBuffer;
	memcpy((LPVOID)copyFoa, (LPVOID)orginalAddressOfFunctions, sizeOf_AddressOfFunctions);	//复制AddressOfFunctions
	copyFoa += sizeOf_AddressOfFunctions;
	orginalAddressOfFunctions = (DWORD)pFileBuffer + RvaDataToFoaData(pFileBuffer, pExportDirectory->AddressOfNames);
	DWORD foaOf_AddressOfNames = copyFoa - (DWORD)pFileBuffer;	//为了后面修复
	memcpy((LPVOID)copyFoa, (LPVOID)orginalAddressOfFunctions, sizeOf_AddressOfNames);
	copyFoa += sizeOf_AddressOfNames;
	orginalAddressOfFunctions = (DWORD)pFileBuffer + RvaDataToFoaData(pFileBuffer, pExportDirectory->AddressOfNameOrdinals);
	DWORD foaOf_AddressOfNameOrdinals = copyFoa - (DWORD)pFileBuffer;;
	memcpy((LPVOID)copyFoa, (LPVOID)orginalAddressOfFunctions, sizeOf_AddressOfNameOrdinals);
	copyFoa += sizeOf_AddressOfNameOrdinals;

	DWORD oringinalAddressOfName = (DWORD)pFileBuffer + RvaDataToFoaData(pFileBuffer, pExportDirectory->AddressOfNames);
	DWORD sizeOfNames = 0;
	char *nameOfFunction = (char *)((DWORD)(pFileBuffer)+RvaDataToFoaData(pFileBuffer, *(DWORD *)(oringinalAddressOfName)));
	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) 
	{
		puts(nameOfFunction);
		sizeOfNames += strlen(nameOfFunction);
		memcpy((DWORD *)copyFoa, nameOfFunction, sizeOfNames);

		copyFoa = copyFoa + strlen(nameOfFunction) + 1;
		nameOfFunction = (char *)((DWORD)nameOfFunction + strlen(nameOfFunction) + 1);
	}

	DWORD foaOf_AddressOfExportDirectory = copyFoa - (DWORD)pFileBuffer;
	memcpy((PIMAGE_EXPORT_DIRECTORY)copyFoa, pExportDirectory, SIZE_OF_EXPORTDIRECTORY);

	PIMAGE_EXPORT_DIRECTORY movedExportDirectory = (PIMAGE_EXPORT_DIRECTORY)copyFoa;
	movedExportDirectory->AddressOfFunctions = FoaDataToRvaData(pFileBuffer, (DWORD)foaOf_AddressOfFunctions);
	movedExportDirectory->AddressOfNames = FoaDataToRvaData(pFileBuffer, (DWORD)foaOf_AddressOfNames);
	movedExportDirectory->AddressOfNameOrdinals = FoaDataToRvaData(pFileBuffer, (DWORD)foaOf_AddressOfNameOrdinals);

	pDataDirectory->VirtualAddress = FoaDataToRvaData(pFileBuffer, foaOf_AddressOfExportDirectory);

	printf("函数名称大小: %x\n", sizeOfNames);
	BufferToFile(pFileBuffer, sizeOfFile, outFilePath);
	free(pFileBuffer);

	return 1;
}

DWORD MoveBaseRelocation(LPSTR inFilePath, LPSTR outFilePath)
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
	foaBaseRelocation = RvaDataToFoaData(pFileBuffer, (*(pDataDirectory + 5)).VirtualAddress);
	pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + foaBaseRelocation);

	DWORD sizeOfRelocation = 0;

	while (pBaseRelocation->SizeOfBlock)
	{
		sizeOfRelocation = sizeOfRelocation + 8 + pBaseRelocation->SizeOfBlock;
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}

	DWORD copyFoa = (DWORD)pFileBuffer + (header.pSectionHeader + slist.numOfSections - 1)->PointerToRawData;
	memcpy((LPVOID)copyFoa, pBaseRelocation, sizeOfRelocation);

	(*(pDataDirectory + 5)).VirtualAddress = FoaDataToRvaData(pFileBuffer, foaBaseRelocation);
	BufferToFile(pFileBuffer, fileSize, outFilePath);

	free(pFileBuffer);
	return 1;
}

DWORD ChangeImageBase(LPSTR inFilePath, LPSTR outFilePath, DWORD newImageBase)
{
	Header header;
	SList slist;
	DWORD foaBaseRelocation = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pBaseRelocation = NULL;

	LPVOID pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);
	pDataDirectory = header.pOptionalHeader->DataDirectory;
	foaBaseRelocation = RvaDataToFoaData(pFileBuffer, (*(pDataDirectory + 5)).VirtualAddress);
	pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + foaBaseRelocation);

	DWORD i = 0;
	DWORD foaOfData = 0;
	DWORD rvaOfData = 0;
	DWORD currentBlockItems = 0;
	DWORD numOfDataToModify = 0;
	DWORD foaOfBlock = 0;
	DWORD attributeOfData = 0;

	while (pBaseRelocation->SizeOfBlock)
	{
		//要修改的数据大表在文件中的偏移 大表 + word 型偏移
		foaOfBlock = (DWORD)pBaseRelocation - (DWORD)pFileBuffer;
		printf("Block %2d    RVA: %x\n", 1 + i++, pBaseRelocation->VirtualAddress);
		currentBlockItems = (pBaseRelocation->SizeOfBlock - 8) / 2;	//word 表示
		printf("Items: %2x\n", currentBlockItems);

		DWORD k = 0;
		DWORD addressOf_rvaOfData = pBaseRelocation->VirtualAddress;
		DWORD *pFarAddress = NULL;
		DWORD differenceOfImageBase = newImageBase - slist.imageBase;
		pBaseRelocation->VirtualAddress += 8;	//RVA start of the block data
		header.pOptionalHeader->ImageBase = newImageBase;
		while (currentBlockItems--)
		{
			rvaOfData = ((*(WORD *)(foaOfBlock + (DWORD)pFileBuffer + 8)) & 0x0fff) + addressOf_rvaOfData;
			foaOfData = (DWORD)RvaDataToFoaData(pFileBuffer, rvaOfData);
			pFarAddress = (DWORD *)(foaOfData + (DWORD)pFileBuffer);
			attributeOfData = *(DWORD *)(foaOfBlock + (DWORD)pFileBuffer + 8) & 0x3000;
			if (attributeOfData == 0x3000)
			{
				attributeOfData = 3;
				*pFarAddress += differenceOfImageBase;
			}
			else
				attributeOfData = 0;
			printf("NO. %2d    RVA: %2x    FOA: %2x    FarAddress: %2x  Attribute: %d\n", 1 + k++, rvaOfData, foaOfData, *pFarAddress, attributeOfData);
			foaOfBlock += 2;
			pBaseRelocation->VirtualAddress += 2;
		}

		pBaseRelocation->VirtualAddress = pBaseRelocation->VirtualAddress - 2 * k - 8;	//还原VirtualAddress
		puts("");
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}

	BufferToFile(pFileBuffer, sizeOfFile, outFilePath);
	free(pFileBuffer);
	return 1;
}

DWORD MoveImportDescriptor(LPSTR inFilePath, LPSTR outFilePath, DWORD numOfNewImportDescriptors)
{
	Header header;
	SList slist;
	DWORD foaImportDescriptor = 0;
	LPVOID pFileBuffer = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;

	pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);

	pDataDirectory = header.pOptionalHeader->DataDirectory;
	foaImportDescriptor = RvaDataToFoaData(pFileBuffer, (*(pDataDirectory + 1)).VirtualAddress);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + foaImportDescriptor);

	DWORD sizeOfImportDescriptor = 0;
	DWORD foaFreeSpace = 0;
	while (pImportDescriptor->OriginalFirstThunk)
	{
		sizeOfImportDescriptor += SIZE_OF_IMPORT_DESCRIPTOR;

		//移动dll名字并修复NAME
		DWORD foaName = RvaDataToFoaData(pFileBuffer, pImportDescriptor->Name);
		char *NameOfCurrentDll = (char *)((DWORD)pFileBuffer + foaName);
		DWORD lengthOfCurrentDllName = strlen(NameOfCurrentDll) + 1;
		foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, lengthOfCurrentDllName, TRUE, sizeOfFile);
		if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
			return NEED_TO_ALLOCATE_NEW_SECTION;

		//sizeOfNames += lengthOfCurrentDllName;
		memcpy((LPVOID)((DWORD)pFileBuffer + foaFreeSpace), NameOfCurrentDll, lengthOfCurrentDllName);
		memset(NameOfCurrentDll, 0, lengthOfCurrentDllName);
		pImportDescriptor->Name = FoaDataToRvaData(pFileBuffer, foaFreeSpace);

		//411-430移动OriginalFirstThunk并修复




		DWORD sizeOfCurrentINT = 0;
		DWORD numOfFunctions = 0;
		DWORD sizeOfOriginalFirstThunk = 0;
		DWORD rvaOriginalFirstThunk = pImportDescriptor->OriginalFirstThunk;
		DWORD foaOriginalFirstThunk = RvaDataToFoaData(pFileBuffer, rvaOriginalFirstThunk);
		DWORD OriginalThunkValue = *(DWORD *)((DWORD)pFileBuffer + foaOriginalFirstThunk);

		//想要修改FirstThunkValue很简单
		//DWORD rvaFirstThunk = pImportDescriptor->FirstThunk;
		//DWORD foaFirstThunk = RvaDataToFoaData(pFileBuffer, rvaFirstThunk);
		//LPVOID pFirstThunkValue = (LPDWORD)((DWORD)pFileBuffer + foaFirstThunk);

		while (OriginalThunkValue)
		{
			if ((OriginalThunkValue & 0x80000000) == 0x80000000)
				DWORD ordinalOfFunction = (OriginalThunkValue & 0x0FFFFFFF);
			else
			{
				DWORD RVA_OFT_HintAndNameOfFunction = OriginalThunkValue;
				DWORD FOA_OFT_HintAndNameOfFunction = RvaDataToFoaData(pFileBuffer, RVA_OFT_HintAndNameOfFunction);
				WORD hint = *(LPWORD)((DWORD)pFileBuffer + FOA_OFT_HintAndNameOfFunction);
				char * NameOfFunction = (char *)((DWORD)pFileBuffer + FOA_OFT_HintAndNameOfFunction + 2);
				sizeOfCurrentINT = strlen(NameOfFunction) + 1 + 2;
				foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, sizeOfCurrentINT, TRUE, sizeOfFile);
				if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
					return NEED_TO_ALLOCATE_NEW_SECTION;
				memcpy((LPVOID)((DWORD)pFileBuffer + foaFreeSpace), (LPVOID)((DWORD)pFileBuffer + FOA_OFT_HintAndNameOfFunction), sizeOfCurrentINT);
				memset((LPVOID)((DWORD)pFileBuffer + FOA_OFT_HintAndNameOfFunction), 0, sizeOfCurrentINT);
				LPDWORD pOriginalThunkValue = (DWORD *)((DWORD)pFileBuffer + foaOriginalFirstThunk);
				*pOriginalThunkValue = FoaDataToRvaData(pFileBuffer, foaFreeSpace);
			}

			pImportDescriptor->OriginalFirstThunk += sizeof(DWORD);
			foaOriginalFirstThunk = RvaDataToFoaData(pFileBuffer, pImportDescriptor->OriginalFirstThunk);  
			OriginalThunkValue = *(LPDWORD)((DWORD)pFileBuffer + foaOriginalFirstThunk);
			numOfFunctions++;
		}

		pImportDescriptor->OriginalFirstThunk = rvaOriginalFirstThunk;	//复原
		sizeOfOriginalFirstThunk = (numOfFunctions + 1) * sizeof(DWORD);
		foaOriginalFirstThunk = RvaDataToFoaData(pFileBuffer, rvaOriginalFirstThunk);
		foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, sizeOfOriginalFirstThunk, TRUE, sizeOfFile);
		if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
			return NEED_TO_ALLOCATE_NEW_SECTION;
		memcpy((LPVOID)((DWORD)pFileBuffer + foaFreeSpace), (LPDWORD)((DWORD)pFileBuffer + foaOriginalFirstThunk), sizeOfOriginalFirstThunk);
		//原来的PFILEBUFFER全部消失
		pImportDescriptor->OriginalFirstThunk = FoaDataToRvaData(pFileBuffer, foaFreeSpace);

		pImportDescriptor++;
	}
	
	//382-386 454-460移动表结构并修复数据目录表
	DWORD numOfImportDescriptor = sizeOfImportDescriptor / SIZE_OF_IMPORT_DESCRIPTOR;
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImportDescriptor - sizeOfImportDescriptor);
	sizeOfImportDescriptor = sizeOfImportDescriptor + (numOfNewImportDescriptors + 1) * SIZE_OF_IMPORT_DESCRIPTOR;	//为之后添加导入表打提前量 +1是因为要有0判断导入表结束 INT用的时候加即可
	foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, sizeOfImportDescriptor, TRUE, sizeOfFile);
	if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
		return NEED_TO_ALLOCATE_NEW_SECTION;

	memcpy((LPVOID)((DWORD)pFileBuffer + foaFreeSpace), pImportDescriptor, sizeOfImportDescriptor - (numOfNewImportDescriptors + 1) * SIZE_OF_IMPORT_DESCRIPTOR);	//只需复制原来的即可
	memset(pImportDescriptor, 0, sizeOfImportDescriptor);	//原数据清0空出来
	(*(pDataDirectory + 1)).VirtualAddress = FoaDataToRvaData(pFileBuffer, foaFreeSpace);
	
	BufferToFile(pFileBuffer, sizeOfFile, outFilePath);
	//free(pFileBuffer);
	return numOfImportDescriptor;
}

DWORD MoveImportDescriptor2(LPSTR inFilePath, LPSTR outFilePath, DWORD numOfNewImportDescriptors)
{
	Header header;
	SList slist;
	DWORD foaImportDescriptor = 0;
	LPVOID pFileBuffer = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;

	pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);

	pDataDirectory = header.pOptionalHeader->DataDirectory;
	foaImportDescriptor = RvaDataToFoaData(pFileBuffer, (*(pDataDirectory + 1)).VirtualAddress);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + foaImportDescriptor);
	DWORD sizeOfImportDescriptor = 0;
	DWORD foaFreeSpace = 0;

	while (pImportDescriptor->OriginalFirstThunk)
	{
		sizeOfImportDescriptor += SIZE_OF_IMPORT_DESCRIPTOR;

		//移动dll名字并修复NAME
		DWORD foaName = RvaDataToFoaData(pFileBuffer, pImportDescriptor->Name);
		char *NameOfCurrentDll = (char *)((DWORD)pFileBuffer + foaName);
		DWORD lengthOfCurrentDllName = strlen(NameOfCurrentDll) + 1;
		foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, lengthOfCurrentDllName, TRUE, sizeOfFile);
		if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
			return NEED_TO_ALLOCATE_NEW_SECTION;

		//sizeOfNames += lengthOfCurrentDllName;
		memcpy((LPVOID)((DWORD)pFileBuffer + foaFreeSpace), NameOfCurrentDll, lengthOfCurrentDllName);
		memset(NameOfCurrentDll, 0, lengthOfCurrentDllName);
		pImportDescriptor->Name = FoaDataToRvaData(pFileBuffer, foaFreeSpace);

		//411-430移动OriginalFirstThunk并修复




		DWORD sizeOfCurrentINT = 0;
		DWORD numOfFunctions = 0;
		DWORD sizeOfOriginalFirstThunk = 0;
		DWORD rvaOriginalFirstThunk = pImportDescriptor->OriginalFirstThunk;
		DWORD foaOriginalFirstThunk = RvaDataToFoaData(pFileBuffer, rvaOriginalFirstThunk);
		DWORD OriginalThunkValue = *(DWORD *)((DWORD)pFileBuffer + foaOriginalFirstThunk);


		while (OriginalThunkValue)
		{
			if ((OriginalThunkValue & 0x80000000) == 0x80000000)
				DWORD ordinalOfFunction = (OriginalThunkValue & 0x0FFFFFFF);
			else
			{
				DWORD RVA_OFT_HintAndNameOfFunction = OriginalThunkValue;
				DWORD FOA_OFT_HintAndNameOfFunction = RvaDataToFoaData(pFileBuffer, RVA_OFT_HintAndNameOfFunction);
				WORD hint = *(LPWORD)((DWORD)pFileBuffer + FOA_OFT_HintAndNameOfFunction);
				char * NameOfFunction = (char *)((DWORD)pFileBuffer + FOA_OFT_HintAndNameOfFunction + 2);
				sizeOfCurrentINT = strlen(NameOfFunction) + 1 + 2;
				foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, sizeOfCurrentINT, TRUE, sizeOfFile);
				if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
					return NEED_TO_ALLOCATE_NEW_SECTION;
				memcpy((LPVOID)((DWORD)pFileBuffer + foaFreeSpace), (LPVOID)((DWORD)pFileBuffer + FOA_OFT_HintAndNameOfFunction), sizeOfCurrentINT);
				memset((LPVOID)((DWORD)pFileBuffer + FOA_OFT_HintAndNameOfFunction), 0, sizeOfCurrentINT);
				LPDWORD pOriginalThunkValue = (DWORD *)((DWORD)pFileBuffer + foaOriginalFirstThunk);
				*pOriginalThunkValue = FoaDataToRvaData(pFileBuffer, foaFreeSpace);
			}

			pImportDescriptor->OriginalFirstThunk += sizeof(DWORD);
			foaOriginalFirstThunk = RvaDataToFoaData(pFileBuffer, pImportDescriptor->OriginalFirstThunk);
			OriginalThunkValue = *(LPDWORD)((DWORD)pFileBuffer + foaOriginalFirstThunk);
			numOfFunctions++;
		}

		pImportDescriptor->OriginalFirstThunk = rvaOriginalFirstThunk;	//复原
		sizeOfOriginalFirstThunk = (numOfFunctions + 1) * sizeof(DWORD);
		foaOriginalFirstThunk = RvaDataToFoaData(pFileBuffer, rvaOriginalFirstThunk);
		foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, sizeOfOriginalFirstThunk, TRUE, sizeOfFile);
		if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
			return NEED_TO_ALLOCATE_NEW_SECTION;
		memcpy((LPVOID)((DWORD)pFileBuffer + foaFreeSpace), (LPDWORD)((DWORD)pFileBuffer + foaOriginalFirstThunk), sizeOfOriginalFirstThunk);
		memset((LPDWORD)((DWORD)pFileBuffer + foaOriginalFirstThunk), 0, sizeOfOriginalFirstThunk);
		//原来的PFILEBUFFER全部消失
		pImportDescriptor->OriginalFirstThunk = FoaDataToRvaData(pFileBuffer, foaFreeSpace);

		pImportDescriptor++;
	}

	//移动表结构并修复数据目录表
	DWORD numOfImportDescriptor = sizeOfImportDescriptor / SIZE_OF_IMPORT_DESCRIPTOR;
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImportDescriptor - sizeOfImportDescriptor);
	sizeOfImportDescriptor = sizeOfImportDescriptor + (numOfNewImportDescriptors + 1) * SIZE_OF_IMPORT_DESCRIPTOR;	//为之后添加导入表打提前量 +1是因为要有0判断导入表结束 INT用的时候加即可
	foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, sizeOfImportDescriptor, TRUE, sizeOfFile);
	if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
		return NEED_TO_ALLOCATE_NEW_SECTION;
	memcpy((LPVOID)((DWORD)pFileBuffer + foaFreeSpace), pImportDescriptor, sizeOfImportDescriptor - (numOfNewImportDescriptors + 1) * SIZE_OF_IMPORT_DESCRIPTOR);	//只需复制原来的即可
	memset(pImportDescriptor, 0, sizeOfImportDescriptor);	//原数据清0空出来

	(*(pDataDirectory + 1)).VirtualAddress = FoaDataToRvaData(pFileBuffer, foaFreeSpace);

	BufferToFile(pFileBuffer, sizeOfFile, outFilePath);
	//free(pFileBuffer);
	return numOfImportDescriptor;
}

DWORD ImportDescriptorInject(LPSTR inFilePath, LPSTR outFilePath, LPSTR nameOfDll, char ** nameOfFunctions, DWORD numOfFunctions)
{
	Header header;
	SList slist;
	DWORD foaImportDescriptor = 0;
	LPVOID pFileBuffer = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;

	pFileBuffer = ReadPeFile(inFilePath, &sizeOfFile);
	InitializePheader(pFileBuffer, &header, &slist);

	pDataDirectory = header.pOptionalHeader->DataDirectory;
	foaImportDescriptor = RvaDataToFoaData(pFileBuffer, (*(pDataDirectory + 1)).VirtualAddress);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + foaImportDescriptor);

	DWORD foaFreeSpace = 0;
	while (pImportDescriptor->OriginalFirstThunk)
		pImportDescriptor++;

	foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, (numOfFunctions + 1) * 0x4, TRUE, sizeOfFile);
	if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
		return NEED_TO_ALLOCATE_NEW_SECTION;
	LPDWORD pNewThunkValue = (LPDWORD)((DWORD)pFileBuffer + foaFreeSpace);
	pImportDescriptor->OriginalFirstThunk = FoaDataToRvaData(pFileBuffer, foaFreeSpace);

	foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, (numOfFunctions + 1) * 0x4, TRUE, sizeOfFile);
	if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
		return NEED_TO_ALLOCATE_NEW_SECTION;
	pImportDescriptor->FirstThunk = FoaDataToRvaData(pFileBuffer, foaFreeSpace);
	LPDWORD pNewFirstThunkValue = (LPDWORD)((DWORD)pFileBuffer + foaFreeSpace);

	foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, strlen(nameOfDll) + 1, TRUE, sizeOfFile);
	if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
		return NEED_TO_ALLOCATE_NEW_SECTION;
	memcpy((LPVOID)((DWORD)pFileBuffer + foaFreeSpace), nameOfDll, strlen(nameOfDll));
	pImportDescriptor->Name = FoaDataToRvaData(pFileBuffer, foaFreeSpace);
	
	for (DWORD i = 0; i < numOfFunctions; i++)
	{

		foaFreeSpace = GetFreeSpaceInSection(pFileBuffer, strlen(*(nameOfFunctions + i)) + 1, TRUE, sizeOfFile);
		if (foaFreeSpace == NEED_TO_ALLOCATE_NEW_SECTION)
			return NEED_TO_ALLOCATE_NEW_SECTION;
		
		PIMAGE_SECTION_HEADER pCurrentSection = header.pSectionHeader + GetSectionNum(pFileBuffer, foaFreeSpace) - 1;
		pCurrentSection->Characteristics |= 0x80000000;

		memcpy((LPVOID)((DWORD)pFileBuffer + foaFreeSpace), *(nameOfFunctions + i), strlen(*(nameOfFunctions + i)));
		*pNewThunkValue = FoaDataToRvaData(pFileBuffer, foaFreeSpace - 2); //Hint-2
		*pNewFirstThunkValue = *pNewThunkValue;
		pNewThunkValue++;
		pNewFirstThunkValue++;
	}

	BufferToFile(pFileBuffer, sizeOfFile, outFilePath);
	return 1;
}
