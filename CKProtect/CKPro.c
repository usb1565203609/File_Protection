#include "myhead.h"

static PVOID  CallBackHandle = NULL;

NTSTATUS DriverEntry
(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PUNICODE_STRING RegisterPath
)
{
	PLDR_DATA_TABLE_ENTRY64 ldr;
	DriverObject->DriverUnload = UnloadDriver;
	ldr = (PLDR_DATA_TABLE_ENTRY64)DriverObject->DriverSection;
	ldr->Flags |= 0x20;
	ProtectFileByObRegisterCallbacks();
	return STATUS_SUCCESS;
}

NTSTATUS ProtectFileByObRegisterCallbacks()
{
	OB_CALLBACK_REGISTRATION  CallBackReg;
	OB_OPERATION_REGISTRATION OperationReg;
	NTSTATUS  Status;

	EnableObType(*IoFileObjectType);      
	//开启文件对象回调
	memset(&CallBackReg, 0, sizeof(OB_CALLBACK_REGISTRATION));
	CallBackReg.Version = ObGetFilterVersion();
	CallBackReg.OperationRegistrationCount = 1;
	CallBackReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&CallBackReg.Altitude, L"321000");
	memset(&OperationReg, 0, sizeof(OB_OPERATION_REGISTRATION)); 
	//初始化结构体变量


	OperationReg.ObjectType = IoFileObjectType;
	OperationReg.Operations = 
		OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	OperationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&PreCall; 
	//在这里注册一个回调函数指针
	CallBackReg.OperationRegistration = &OperationReg; 
	//注意这一条语句   将结构体信息放入大结构体
	Status = ObRegisterCallbacks(&CallBackReg, &CallBackHandle);
	if (!NT_SUCCESS(Status))
	{
		Status = STATUS_UNSUCCESSFUL;
	}
	else
	{
		Status = STATUS_SUCCESS;
	}
	return Status;
}

OB_PREOP_CALLBACK_STATUS PreCall
(
	_In_ PVOID RegistrationContext, 
	_Out_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	UNICODE_STRING uniDosName;
	UNICODE_STRING uniFilePath;

	//获取文件对象
	PFILE_OBJECT FileObject = (PFILE_OBJECT)OperationInformation->Object;
	
	if (OperationInformation->ObjectType != *IoFileObjectType)
		return OB_PREOP_SUCCESS;

	//过滤无效指针，重要，否则会蓝屏
	if (FileObject->FileName.Buffer == NULL
		|| !MmIsAddressValid(FileObject->FileName.Buffer)
		|| FileObject->DeviceObject == NULL
		|| !MmIsAddressValid(FileObject->DeviceObject))
		return OB_PREOP_SUCCESS;

	//获取文件路径
	uniFilePath = GetFilePathforObject(FileObject);
	if (uniFilePath.Buffer == NULL || uniFilePath.Length == 0)
		return OB_PREOP_SUCCESS;

	//从路径中查找指定名称目录进行过滤
	if (wcsstr(uniFilePath.Buffer, L"CK_123390"))
	{
		//获取并判断操作权限，删除与写入权限禁止
		if (FileObject->DeleteAccess == TRUE || FileObject->WriteAccess == TRUE)
		{
			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
				OperationInformation->Parameters->
				CreateHandleInformation.DesiredAccess = 0;

			if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
				OperationInformation->Parameters->
				DuplicateHandleInformation.DesiredAccess = 0;
		}
	}
	return OB_PREOP_SUCCESS;
}

//获取路径函数
UNICODE_STRING  GetFilePathforObject
(
	_In_ PVOID FileObject
)
{
	POBJECT_NAME_INFORMATION ObjetNameInfor;
	if (NT_SUCCESS(IoQueryFileDosDeviceName((PFILE_OBJECT)FileObject, &ObjetNameInfor)))
		return ObjetNameInfor->Name;
}

//开启文件回调函数
VOID EnableObType
(
	_In_ POBJECT_TYPE ObjectType
)
{
	POBJECT_TYPE_TEMP  ObjectTypeTemp = (POBJECT_TYPE_TEMP)ObjectType;
	ObjectTypeTemp->TypeInfo.SupportsObjectCallbacks = 1;
}

//取消文件回调函数
VOID DisableObType
(
	_In_ POBJECT_TYPE ObjectType
)
{
	POBJECT_TYPE_TEMP  ObjectTypeTemp = (POBJECT_TYPE_TEMP)ObjectType;
	ObjectTypeTemp->TypeInfo.SupportsObjectCallbacks = 0;
}

NTSTATUS UnloadDriver
(
	_In_ PDRIVER_OBJECT  DriverObject
)
{
	if (CallBackHandle != NULL)
	{
		ObUnRegisterCallbacks(CallBackHandle);
	}
	DisableObType(*IoFileObjectType);

	return STATUS_SUCCESS;
}