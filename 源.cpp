#include "iostream"
#include "ChangePe.h"
#include "PE_Headers.h"
#include "nameDefine.h"

void test() {
	int a = 1;
	int b = 2;
	int faofa = 10 - 2;
		
}



int main(void)
{
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;

	/*Test for Directory*/ 
	char c_inFilePath[] = "C:/Users/Admin/Desktop/PETEST/��Դ��.EXE";
	char c_outFilePath[] = "C:/Users/Admin/Desktop/PETEST/ת���������ٱ���.exe";	//��ɾ��������Ϣ
	char c_outFilePath2[] = "C:/Users/Admin/Desktop/PETEST/��ȥ������Ϣ��ϲ����н�.exe";
	char c_outFilePath3[] = "C:/Users/Admin/Desktop/PETEST/�������ڲ��������һ����.exe";
	char c_outFilePath4[] = "C:/Users/Admin/Desktop/PETEST/�����ڵĵ�һ��ע��.exe";

	DWORD addrOfNewSectionFile = 0;
	BYTE nameofNewSection2[8] = { 0x2E,0X6E,0X65,0X77,0x72 };

	/*	���Ի������� 4.25*/
	//printf("��ӡͷ��ת���ڴ滺������ת����Ȼ�󱣴�, ��ɾ��������Ϣ!\n���������\n");
	//getch();
	//PrintNTHeaders(c_inFilePath);
	//CopyFileBufferToImageBuffer(c_inFilePath, &pImageBuffer);
	//BufferToFile(pFileBuffer, CopyImageBufferToFileBuffer(pImageBuffer, &pFileBuffer), OUT c_outFilePath);
	//PrintNTHeaders(c_outFilePath);
	//printf("��ӡ��ת����� ������һ��\n���������\n");
	//getch();
	//system("cls");

	///*	Test for inject MessageBox to an executable file.*/
	//printf("��һ���½ڲ�����Ȼ�����α�ע�����ϲ���������\n���������\n");
	//getch();
	//BYTE b_msbox[18] =
	//{
	//	0x6A, 00, 0x6A, 00, 0x6A, 00, 0x6A, 00,
	//	0xE8, 00, 00, 00, 00,
	//	0xE9, 00, 00, 00,00
	//};	//ShellCode
	//MergeSections(c_outFilePath, c_outFilePath2);
	//AllocateNewSection(nameofNewSection2, 0x1000, c_outFilePath2, &addrOfNewSectionFile);
	//EnlargeTheLastSection((LPSTR)addrOfNewSectionFile, c_outFilePath3, 0x1000);
	//SectionInject(c_outFilePath3, c_outFilePath4, 1, b_msbox, 0x12);
	//printf("�ɹ� ���������\n");
	//getch();
	//system("cls");
	//
	//char c_inFilePath2[] = "C:/Users/Admin/Desktop/PETEST/twodll.dll";
	//char c_outFilePath5[] = "C:/Users/Admin/Desktop/PETEST/��һ�����ƶ�������.dll";
	//char c_outFilePath6[] = "C:/Users/Admin/Desktop/PETEST/��һ�����ƶ��ض�λ��.dll";
	//char c_outFilePath7[] = "C:/Users/Admin/Desktop/PETEST/�޸�ImageBase70000000.dll";
	//char nameOfFunction[] = "Plus";
	//printf("����Ŀ¼����� \n��ӡ����Ŀ¼�� \n");
	//getch();
	//TraverseDataDirectory(c_inFilePath2);
	//getch();
	//system("cls");
	//printf("��ӡ������\n");
	//PrintExportDirectory(c_inFilePath2);   
	//system("cls");
	//printf("ͨ����������õ�ַ,���а�����ͨ����Ż��\n");
	//printf("������Ϊ: %s\n", nameOfFunction);
	//printf("������ַ: %x(��Ϊ0�򲻴��ڴ˺�����)\n", GetFunctionAddrByName(pFileBuffer, nameOfFunction));
	//getch();
	//system("cls");
	//printf("dll ��ӡ������\n");
	//getch();
	//PrintBaseRelocation(c_inFilePath2);
	//getch();
	//system("cls");
	//printf("dll �ƶ������� �ƶ��ض�λ�� �޸�ImageBase\n");
	//AllocateNewSection(nameofNewSection2, SIZE_OF_NEWSECTION_MOVE_EXPORT, c_inFilePath2, &addrOfNewSectionFile);	//�ƶ��������ض�λ�Ŀռ�Ҫ���
	//MoveExportDirectory((LPSTR)addrOfNewSectionFile, c_outFilePath5, FALSE);
	//AllocateNewSection(nameofNewSection2, SIZE_OF_NEWSECTION_MOVE_EXPORT, c_inFilePath2, &addrOfNewSectionFile);
	//MoveBaseRelocation((LPSTR)addrOfNewSectionFile, c_outFilePath6);
	//ChangeImageBase(c_inFilePath, c_outFilePath7, 0x70000000);
	//getch();

	//system("cls");
	//printf("exe ��ӡ�������󶨵����");
	//PrintImportDescriptor(c_inFilePath);
	//PrintBoundImportDescriptor(c_inFilePath);
	//getch();

	//system("cls");
	//printf("�ƶ������ע��.\n");
	////getch();
	//char nameOfInjectDLL[] = "twodll.dll";
	//char *nameOfInjectFunctons[10] =
	//{
	//	"_ForTest@0",
	//	"_ForTestEnd@0",
	//	"",
	//	"",
	//	"",
	//	"",
	//	"",
	//	"",
	//	"",
	//	"",
	//};
	//char c_outFilePath8[] = "C:/Users/Admin/Desktop/PETEST/�ƶ������.exe";
	//char c_outFilePath9[] = "C:/Users/Admin/Desktop/PETEST/�ƶ������ע��.exe";
	//if (MoveImportDescriptor(c_inFilePath, c_outFilePath8, 1) == NEED_TO_ALLOCATE_NEW_SECTION)
	//{
	//	AllocateNewSection(nameofNewSection2, SIZE_OF_NEWSECTION_MOVE_IMPORT, c_inFilePath, &addrOfNewSectionFile);
	//	MoveImportDescriptor((LPSTR)addrOfNewSectionFile, c_outFilePath8, 1);	//����Ҫ�޸Ľ����� ��ΪֻҪThunkRva�����û��
	//	ImportDescriptorInject(c_outFilePath8, c_outFilePath9, nameOfInjectDLL, nameOfInjectFunctons, 2);
	//}
	//else
	//	ImportDescriptorInject(c_outFilePath8, c_outFilePath9, nameOfInjectDLL, nameOfInjectFunctons, 2);
	//

	//char c_outFilePath9[] = "C:/Users/Admin/Desktop/PETEST/�޸�imagebase.dll";
	//	//PrintBaseRelocation(c_inFilePath);
	//ChangeImageBase(c_inFilePath, c_outFilePath9, 0x60000000);

	PrintResourceDirectory(c_inFilePath);


	return 0;
}


