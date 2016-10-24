/*++
    wmi.c

Abstract: This module demonstrates how to receive WMI notification fired by
          another driver. The code here basically registers for toaster
          device arrival WMI notification fired by the toaster function driver.
          You can use similar technique to receive media sense notification
          (GUID_NDIS_STATUS_MEDIA_CONNECT/GUID_NDIS_STATUS_MEDIA_DISCONNECT)
          fired by NDIS whenever the network cable is plugged or unplugged.

Environment:

    Kernel mode


--*/

#include "toastmon.h"
#include "public.h"
#include <wmistr.h>

//
// These typedefs required to avoid compilation errors in Win2K build environment.
//
typedef
VOID
(*WMI_NOTIFICATION_CALLBACK)( // Copied from WDM.H
    PVOID Wnode,
    PVOID Context
    );

typedef
NTSTATUS
(*PFN_IO_WMI_OPEN_BLOCK)(
    IN  GUID   * DataBlockGuid,
    IN  ULONG    DesiredAccess,
    OUT PVOID  * DataBlockObject
    );

typedef
NTSTATUS
(*PFN_IO_WMI_SET_NOTIFICATION_CALLBACK)(
    IN PVOID                      Object,
    IN WMI_NOTIFICATION_CALLBACK  Callback,
    IN PVOID                      Context
    );

NTSTATUS
GetTargetFriendlyName(
    WDFIOTARGET Target,
    IN WDFMEMORY* TargetName
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, RegisterForWMINotification)
#pragma alloc_text(PAGE, UnregisterForWMINotification)
#pragma alloc_text(PAGE, GetTargetFriendlyName)
#pragma alloc_text(PAGE, WmiNotificationCallback)
#endif


NTSTATUS
RegisterForWMINotification(
    PDEVICE_EXTENSION DeviceExt
    )
{
    NTSTATUS           status = STATUS_SUCCESS;
    GUID               wmiGuid;
    UNICODE_STRING     funcName;

    PFN_IO_WMI_OPEN_BLOCK                 WmiOpenBlock;
    PFN_IO_WMI_SET_NOTIFICATION_CALLBACK  WmiSetNotificationCallback;

    PAGED_CODE();
	//------------------------------------------------------------
	// 找两个函数的执行地址
	//------------------------------------------------------------
    //
    // APIs  to open WMI interfaces are available on XP and beyond, so let us
    // first check to see whether there are exported in the kernel we are
    // running before using them.
    //
    RtlInitUnicodeString(&funcName, L"IoWMIOpenBlock");
	WmiOpenBlock = (PFN_IO_WMI_OPEN_BLOCK) (ULONG_PTR)
            MmGetSystemRoutineAddress(&funcName);//通过函数名字找函数地址

    RtlInitUnicodeString(&funcName, L"IoWMISetNotificationCallback");
    WmiSetNotificationCallback = (PFN_IO_WMI_SET_NOTIFICATION_CALLBACK) (ULONG_PTR)
            MmGetSystemRoutineAddress(&funcName);

    if(WmiOpenBlock == NULL || WmiSetNotificationCallback == NULL) {
        return STATUS_NOT_SUPPORTED;// Not available.
    }

	//------------------------------------------------------------
	// 检查本函数不会被多次调用
	//------------------------------------------------------------
    //
    // Check to make sure we are not called multiple times.
    //
    ASSERT(DeviceExt->WMIDeviceArrivalNotificationObject == NULL);

	//------------------------------------------------------------
	// 注册WMI回调函数
	//------------------------------------------------------------
    //
    // Register WMI callbacks for toaster device arrival events
    //
    wmiGuid = TOASTER_NOTIFY_DEVICE_ARRIVAL_EVENT;

	//------------------------------------------------
	//注册WMI回调函数的第一步：create a data block object
	//------------------------------------------------
    status = WmiOpenBlock(
                 &wmiGuid,
                 WMIGUID_NOTIFICATION,
                 &DeviceExt->WMIDeviceArrivalNotificationObject //输出，创建的data block object
                 );
    if (!NT_SUCCESS(status)) {

        KdPrint(("Unable to open wmi data block status 0x%x\n", status));
        DeviceExt->WMIDeviceArrivalNotificationObject = NULL;

    } else {

		//--------------------------------------------------------------------------
		//注册WMI回调函数的第二步：registers a notification callback for a WMI event.
		//--------------------------------------------------------------------------
        status = WmiSetNotificationCallback(
                     DeviceExt->WMIDeviceArrivalNotificationObject, //Pointer to a WMI data block object
                     WmiNotificationCallback, //callback，在后面
                     DeviceExt                //context，本函数的唯一输入参数
                     );
        if (!NT_SUCCESS(status)) {
            KdPrint(("Unable to register for wmi notification 0x%x\n", status));
            ObDereferenceObject(DeviceExt->WMIDeviceArrivalNotificationObject);//学习
            DeviceExt->WMIDeviceArrivalNotificationObject = NULL;              //学习
        }
    }

    return status;
}


VOID
UnregisterForWMINotification(
    PDEVICE_EXTENSION DeviceExt
)
{
    PAGED_CODE();

    if (DeviceExt->WMIDeviceArrivalNotificationObject != NULL) {
        ObDereferenceObject(DeviceExt->WMIDeviceArrivalNotificationObject);//学习
        DeviceExt->WMIDeviceArrivalNotificationObject = NULL;              //学习
    }
}

//这里用这个函数仅仅做个演示，在WmiNotificationCallback中可以换成你想用的其他任何函数
//注意：WmiNotificationCallback是通过WmiSetNotificationCallback被设置的
//就是：RegisterForWMINotification调用WmiSetNotificationCallback函数设置WmiNotificationCallback回调
//     在WmiNotificationCallback回调中执行了这个演示函数
NTSTATUS
GetTargetFriendlyName(
    WDFIOTARGET Target,
    IN WDFMEMORY* TargetName
    )
/*++

Routine Description:

    Return the friendly name associated with the given device object.

Arguments:

Return Value:

    NT status

--*/
{
    NTSTATUS status;

    PAGED_CODE();

    //
    // First get the length of the string. If the FriendlyName
    // is not there then get the lenght of device description.
    // 
    status = WdfIoTargetAllocAndQueryTargetProperty(Target,  //第一次调用获得length
                                                    DevicePropertyFriendlyName,//property枚举
                                                    NonPagedPoolNx,
                                                    WDF_NO_OBJECT_ATTRIBUTES,
                                                    TargetName); //输出

    if (!NT_SUCCESS(status) && status != STATUS_INSUFFICIENT_RESOURCES) {
        status = WdfIoTargetAllocAndQueryTargetProperty(Target, //第二次调用获得TargetName
                                                        DevicePropertyDeviceDescription, //property枚举，不一样了
                                                        NonPagedPoolNx,
                                                        WDF_NO_OBJECT_ATTRIBUTES,
                                                        TargetName); //输出

    }

    if (!NT_SUCCESS(status)) {
        KdPrint(("WdfDeviceQueryProperty returned %x\n", status));
    }

    return status;
}

//问题：什么时候被调用？谁调用？
//答案：WMI calls this function to notify the caller that the specified event has occurred.
VOID
WmiNotificationCallback(
    IN PVOID Wnode,
    IN PVOID Context
    )
/*++

Routine Description:

    WMI calls this function to notify the caller that the specified event has occurred.

Arguments:

    Wnode - points to the WNODE_EVENT_ITEM structure returned by the driver triggering the event.

    Context - points to the value specified in the Context parameter of the
                    IoWMISetNotificationCallback routine.

Return Value:

    NT status

--*/
{
    PWNODE_SINGLE_INSTANCE wnode = (PWNODE_SINGLE_INSTANCE) Wnode;
    WDFMEMORY memory;
    UNICODE_STRING deviceName;
    PDEVICE_OBJECT devobj;
    NTSTATUS status;
    PDEVICE_EXTENSION deviceExt = Context;
    WDFCOLLECTION hCollection = deviceExt->TargetDeviceCollection;
    WDFIOTARGET ioTarget;
    ULONG i;

    PAGED_CODE();

    WdfWaitLockAcquire(deviceExt->TargetDeviceCollectionLock, NULL);//拿锁

	//遍历
    for(i=0; i< WdfCollectionGetCount(hCollection); i++){

        ioTarget = WdfCollectionGetItem(hCollection, i);

        //
        // Before calling WdfIoTargetWdmGetTargetDeviceObject, make sure the target is still open.
        // The WdfIoTargetWdmGetXxxDeviceObject APIs can only be called while the target is opened, otherwise
        // they can return undefined values.
		// 为下一句函数调用做准备，必须保证target是打开的
		// GetTargetDeviceInfo是宏定义的函数：
		// WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(TARGET_DEVICE_INFO, GetTargetDeviceInfo这是宏定义的函数)
		// 通过句柄能得到宏参数1定义结构的数据
		if (GetTargetDeviceInfo(ioTarget)->Opened == FALSE) {
			KdPrint(("WDFIOTARGET %p not in an opened state.\n", ioTarget));
			continue;
		}

        devobj = WdfIoTargetWdmGetTargetDeviceObject(ioTarget);//学习如何从iotarget到传统的devobj

		//下面函数的作用：translates the specified device object into the corresponding WMI Provider ID.
        if(devobj &&
            IoWMIDeviceObjectToProviderId(devobj) == wnode->WnodeHeader.ProviderId) { 

            if( IsEqualGUID( (LPGUID)&(wnode->WnodeHeader.Guid),
                          (LPGUID)&TOASTER_NOTIFY_DEVICE_ARRIVAL_EVENT) ) {
                //
                // found the device. Just for demonstration, get the friendlyname of the
                // target device and print it.
                //
                status = GetTargetFriendlyName(ioTarget, &memory/*输出*/);//本地函数
                if (!NT_SUCCESS(status)) {
                    KdPrint(("GetDeviceFriendlyName returned %x\n", status));
                    break;
                }

                RtlInitUnicodeString(&deviceName, (PWSTR) WdfMemoryGetBuffer(memory, NULL));
                KdPrint(("%wZ fired a device arrival event\n", &deviceName));

                //
                // Free the memory allocated by GetDeviceFriendlyName.
                //
                WdfObjectDelete(memory);

                break;

            } else {
                KdPrint(("Unknown event.\n"));
            }
        }

    }

    WdfWaitLockRelease(deviceExt->TargetDeviceCollectionLock);
}
