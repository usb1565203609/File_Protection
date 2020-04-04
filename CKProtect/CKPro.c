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
	//�����ļ�����ص�
	memset(&CallBackReg, 0, sizeof(OB_CALLBACK_REGISTRATION));
	CallBackReg.Version = ObGetFilterVersion();
	CallBackReg.OperationRegistrationCount = 1;
	CallBackReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&CallBackReg.Altitude, L"321000");
	memset(&OperationReg, 0, sizeof(OB_OPERATION_REGISTRATION)); 
	//��ʼ���ṹ�����


	OperationReg.ObjectType = IoFileObjectType;
	OperationReg.Operations = 
		OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	OperationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&PreCall; 
	//������ע��һ���ص�����ָ��
	CallBackReg.OperationRegistration = &OperationReg; 
	//ע����һ�����   ���ṹ����Ϣ�����ṹ��
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

	//��ȡ�ļ�����
	PFILE_OBJECT FileObject = (PFILE_OBJECT)OperationInformation->Object;
	
	if (OperationInformation->ObjectType != *IoFileObjectType)
		return OB_PREOP_SUCCESS;

	//������Чָ�룬��Ҫ�����������
	if (FileObject->FileName.Buffer == NULL
		|| !MmIsAddressValid(FileObject->FileName.Buffer)
		|| FileObject->DeviceObject == NULL
		|| !MmIsAddressValid(FileObject->DeviceObject))
		return OB_PREOP_SUCCESS;

	//��ȡ�ļ�·��
	uniFilePath = GetFilePathforObject(FileObject);
	if (uniFilePath.Buffer == NULL || uniFilePath.Length == 0)
		return OB_PREOP_SUCCESS;

	//��·���в���ָ������Ŀ¼���й���
	if (wcsstr(uniFilePath.Buffer, L"CK_123390"))
	{
		//��ȡ���жϲ���Ȩ�ޣ�ɾ����д��Ȩ�޽�ֹ
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

//��ȡ·������
UNICODE_STRING  GetFilePathforObject
(
	_In_ PVOID FileObject
)
{
	POBJECT_NAME_INFORMATION ObjetNameInfor;
	if (NT_SUCCESS(IoQueryFileDosDeviceName((PFILE_OBJECT)FileObject, &ObjetNameInfor)))
		return ObjetNameInfor->Name;
}

//�����ļ��ص�����
VOID EnableObType
(
	_In_ POBJECT_TYPE ObjectType
)
{
	POBJECT_TYPE_TEMP  ObjectTypeTemp = (POBJECT_TYPE_TEMP)ObjectType;
	ObjectTypeTemp->TypeInfo.SupportsObjectCallbacks = 1;
}

//ȡ���ļ��ص�����
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