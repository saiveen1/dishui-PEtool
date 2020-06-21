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
	char c_inFilePath[] = "C:/Users/Admin/Desktop/PETEST/资源表.EXE";
	char c_outFilePath[] = "C:/Users/Admin/Desktop/PETEST/转换缓冲区再保存.exe";	//会删掉垃圾信息
	char c_outFilePath2[] = "C:/Users/Admin/Desktop/PETEST/减去垃圾信息后合并所有节.exe";
	char c_outFilePath3[] = "C:/Users/Admin/Desktop/PETEST/有两个节并扩大最后一个节.exe";
	char c_outFilePath4[] = "C:/Users/Admin/Desktop/PETEST/两个节的第一个注入.exe";

	DWORD addrOfNewSectionFile = 0;
	BYTE nameofNewSection2[8] = { 0x2E,0X6E,0X65,0X77,0x72 };

	/*	测试基础操作 4.25*/
	//printf("打印头并转到内存缓冲区再转回来然后保存, 会删掉垃圾信息!\n输入任意键\n");
	//getch();
	//PrintNTHeaders(c_inFilePath);
	//CopyFileBufferToImageBuffer(c_inFilePath, &pImageBuffer);
	//BufferToFile(pFileBuffer, CopyImageBufferToFileBuffer(pImageBuffer, &pFileBuffer), OUT c_outFilePath);
	//PrintNTHeaders(c_outFilePath);
	//printf("打印并转换完毕 进行下一项\n输入任意键\n");
	//getch();
	//system("cls");

	///*	Test for inject MessageBox to an executable file.*/
	//printf("加一个新节并扩大然后区段表注入最后合并所有区段\n输入任意键\n");
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
	//printf("成功 输入任意键\n");
	//getch();
	//system("cls");
	//
	//char c_inFilePath2[] = "C:/Users/Admin/Desktop/PETEST/twodll.dll";
	//char c_outFilePath5[] = "C:/Users/Admin/Desktop/PETEST/加一个节移动导出表.dll";
	//char c_outFilePath6[] = "C:/Users/Admin/Desktop/PETEST/加一个节移动重定位表.dll";
	//char c_outFilePath7[] = "C:/Users/Admin/Desktop/PETEST/修改ImageBase70000000.dll";
	//char nameOfFunction[] = "Plus";
	//printf("数据目录表相关 \n打印数据目录表 \n");
	//getch();
	//TraverseDataDirectory(c_inFilePath2);
	//getch();
	//system("cls");
	//printf("打印导出表\n");
	//PrintExportDirectory(c_inFilePath2);   
	//system("cls");
	//printf("通过函数名获得地址,其中包含了通过序号获得\n");
	//printf("函数名为: %s\n", nameOfFunction);
	//printf("函数地址: %x(若为0则不存在此函数名)\n", GetFunctionAddrByName(pFileBuffer, nameOfFunction));
	//getch();
	//system("cls");
	//printf("dll 打印导出表\n");
	//getch();
	//PrintBaseRelocation(c_inFilePath2);
	//getch();
	//system("cls");
	//printf("dll 移动导出表 移动重定位表 修改ImageBase\n");
	//AllocateNewSection(nameofNewSection2, SIZE_OF_NEWSECTION_MOVE_EXPORT, c_inFilePath2, &addrOfNewSectionFile);	//移动导出和重定位的空间要求大
	//MoveExportDirectory((LPSTR)addrOfNewSectionFile, c_outFilePath5, FALSE);
	//AllocateNewSection(nameofNewSection2, SIZE_OF_NEWSECTION_MOVE_EXPORT, c_inFilePath2, &addrOfNewSectionFile);
	//MoveBaseRelocation((LPSTR)addrOfNewSectionFile, c_outFilePath6);
	//ChangeImageBase(c_inFilePath, c_outFilePath7, 0x70000000);
	//getch();

	//system("cls");
	//printf("exe 打印导入表与绑定导入表");
	//PrintImportDescriptor(c_inFilePath);
	//PrintBoundImportDescriptor(c_inFilePath);
	//getch();

	//system("cls");
	//printf("移动导入表并注入.\n");
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
	//char c_outFilePath8[] = "C:/Users/Admin/Desktop/PETEST/移动导入表.exe";
	//char c_outFilePath9[] = "C:/Users/Admin/Desktop/PETEST/移动导入表并注入.exe";
	//if (MoveImportDescriptor(c_inFilePath, c_outFilePath8, 1) == NEED_TO_ALLOCATE_NEW_SECTION)
	//{
	//	AllocateNewSection(nameofNewSection2, SIZE_OF_NEWSECTION_MOVE_IMPORT, c_inFilePath, &addrOfNewSectionFile);
	//	MoveImportDescriptor((LPSTR)addrOfNewSectionFile, c_outFilePath8, 1);	//不需要修改节属性 因为只要ThunkRva不变就没事
	//	ImportDescriptorInject(c_outFilePath8, c_outFilePath9, nameOfInjectDLL, nameOfInjectFunctons, 2);
	//}
	//else
	//	ImportDescriptorInject(c_outFilePath8, c_outFilePath9, nameOfInjectDLL, nameOfInjectFunctons, 2);
	//

	//char c_outFilePath9[] = "C:/Users/Admin/Desktop/PETEST/修改imagebase.dll";
	//	//PrintBaseRelocation(c_inFilePath);
	//ChangeImageBase(c_inFilePath, c_outFilePath9, 0x60000000);

	PrintResourceDirectory(c_inFilePath);


	return 0;
}


