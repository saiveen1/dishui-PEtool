#include "iostream"
#include "PE_Headers.h"
#include "ChangePe.h"

void test() {
	int a = 1;
	int b = 2;
	int faofa = 10 - 2;
		
}



int main(void)
{

	//char temp[] = "D:\\Win10_main\\Software\\������\\Notepad++\\notepad++.exe";
	//char temp[] = "D:/Win10_main/Software/������/Notepad++/notepad++.exe"

	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;

	/*Test for Directory*/ 
	char c_inFilePath[] = "C:/Users/Admin/Desktop/PETEST/cloudtest.exe";
	char c_outFilePath[] = "C:/Users/Admin/Desktop/PETEST/����һ����.exe";
	char c_outFilePath2[] = "C:/Users/Admin/Desktop/PETEST/�ƶ�������.dll";
	char c_outFilePath3[] = "C:/Users/Admin/Desktop/PETEST/�����ƶ��ض�λ���¼ӽ�.dll";
	char c_outFilePath4[] = "C:/Users/Admin/Desktop/PETEST/�ƶ��ض�λ.dll";
	char c_outFilePath5[] = "C:/Users/Admin/Desktop/PETEST/70000000�޸�IMAGEBASE.dll";
	char c_outFilePath6[] = "C:/Users/Admin/Desktop/PETEST/�ƶ������.exe";
	DWORD addrOfNewSectionFile = 0;
	char nameOfFunction[] = "Plus";
	BYTE nameofNewSection2[8] = { 0x2E,0X6E,0X65,0X77,0x72 };
	//TraverseDataDirectory(pFileBuffer, c_inFilePath);
	
	//PrintExportDirectory(&pFileBuffer,c_inFilePath);
	//GetFunctionAddrByName(pFileBuffer, nameOfFunction);
	//free(&pFileBuffer);
	
	//PrintBaseRelocation(pFileBuffer, c_inFilePath);

	//SectionAllocate(pFileBuffer, c_inFilePath, c_outFilePath, nameOfNewSection, SIZE_OF_NEWSECTION);
	//MoveExportDirectory(pFileBuffer, c_outFilePath, c_outFilePath2, TRUE);

	//SectionAllocate(pFileBuffer, c_inFilePath, c_outFilePath3, nameofNewSection2, SIZE_OF_NEWSECTION);
	//MoveBaseRelocation(pFileBuffer, c_outFilePath3, c_outFilePath4);
	//ChangeImageBase(pFileBuffer, c_inFilePath, c_outFilePath5, 0x70000000);
	//PrintBaseRelocation(pFileBuffer, c_outFilePath5);
	//PrintImportDirectory(pFileBuffer, c_inFilePath);
	//PrintBoundImportDirectory(pFileBuffer, c_inFilePath);
	//SectionAllocate(pFileBuffer, c_inFilePath, c_outFilePath, nameofNewSection2, 0x1000);
	if (MoveImportDescriptor(c_inFilePath, c_outFilePath6, 1) == NEED_TO_ALLOCATE_NEW_SECTION)
	{
		AllocateNewSection(pFileBuffer, nameofNewSection2, SIZE_OF_NEWSECTION_MOVE_IMPORT, c_inFilePath, &addrOfNewSectionFile);
		MoveImportDescriptor((LPSTR)addrOfNewSectionFile, c_outFilePath6, 1);
	}
	//AllocateNewSection(pFileBuffer, nameofNewSection2, SIZE_OF_NEWSECTION_MOVE_IMPORT, c_inFilePath, &addrOfNewSectionFile);



	/*	Test for inject MessageBox to an executable file.*/
	//char c_inFilePath[] = "C:/Users/Admin/Desktop/PETEST/cloudmusic.exe";
	//char c_outFilePath[] = "C:/Users/Admin/Desktop/PETEST/�����½�2.exe";
	//char c_outFilePath2[] = "C:/Users/Admin/Desktop/PETEST/���½����shellcode.exe";
	//char c_outFilePath3[] = "C:/Users/Admin/Desktop/PETEST/�Ѿ����shellcode�������.exe";
	//char c_outFilePath4[] = "C:/Users/Admin/Desktop/PETEST/ԭʼ�������һ����.exe";
	//char c_outFilePath5[] = "C:/Users/Admin/Desktop/PETEST/ԭʼ�ϲ����н�.exe";
	//BYTE b_msbox[18] =
	//{
	//0x6A, 00, 0x6A, 00, 0x6A, 00, 0x6A, 00,
	//0xE8, 00, 00, 00, 00,
	//0xE9, 00, 00, 00,00
	//};	//ShellCode

	//SectionAllocate(pFileBuffer, c_inFilePath, c_outFilePath, nameofNewSection2, 0x1000);
	//SectionInject(pFileBuffer, c_outFilePath, c_outFilePath2, 5, b_msbox);
	//EnlargeTheLastSection(pFileBuffer, c_inFilePath, c_outFilePath4, 0x1000);
	//EnlargeTheLastSection(pFileBuffer, c_outFilePath2, c_outFilePath3, 0x1000);
	//MergeSections(pFileBuffer, c_inFilePath, c_outFilePath5);
	

	/*	���Ի������� 4.25*/
	//char c_temp[] = "C:/Users/Admin/Desktop/PETEST/�ڴ��ļ����벻һ��.exe";
	//char c_outFile[] = "C:/Users/Admin/Desktop/cloudtest.exe";
	//LPSTR IN inFilePath = c_temp;
	//LPSTR OUT outFilePath = c_outFile;
	//PrintNTHeaders(c_inFilePath, &pFileBuffer);
	//free(pFileBuffer);
	//CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	//BufferToFile(pFileBuffer, CopyImageBufferToFileBuffer(pImageBuffer, &pFileBuffer), OUT outFilePath);
	//PrintNTHeaders(OUT outFilePath,&pFileBuffer);
	//free(pFileBuffer);
	

	return 0;
}


