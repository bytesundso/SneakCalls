#pragma once

#include <utility>
#include <cstdint>
#include <Windows.h>

extern "C" void executeSyscall();

class SneakHelper
{
public:
    static constexpr UINT32 hash(LPSTR functionName)
    {
        UINT32 r = 37;

        for(int i = 0; functionName[i]; i++)
            r = ((r << 5) + r) + functionName[i];

        return r;
    }

    static consteval UINT32 hash(LPCSTR functionName) 
    { 
        return hash(const_cast<LPSTR>(functionName)); 
    }

    static UINT_PTR getNtdllBase();
    static UINT32 hashToScn(UINT32 hash);
};

template <UINT32 scn, typename... ArgTypes>
class SneakCall
{
public:
    SneakCall() : UINT32(SneakHelper::hashToScn(scn)) 
    {

    }

    NTSTATUS call(ArgTypes... args)
    {
        using Executor = NTSTATUS(NTAPI*)(scn, ArgTypes...); 
        return (Executor(executeSyscall))(scn, std::forward<ArgTypes>(args)...);
    }

private:
    UINT32 scn;
};

typedef struct _PEB_LDR_DATA 
{
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct LDR_DATA_TABLE_ENTRY 
{
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct PEB 
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
	ULONG64        Version;
	UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
	PVOID pValue;
	ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _WNF_TYPE_ID
{
	GUID TypeId;
} WNF_TYPE_ID, *PWNF_TYPE_ID;

typedef enum _KCONTINUE_TYPE
{
	KCONTINUE_UNWIND,
	KCONTINUE_RESUME,
	KCONTINUE_LONGJUMP,
	KCONTINUE_SET,
	KCONTINUE_LAST
} KCONTINUE_TYPE;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID*    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName,
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE, *PPS_CREATE_STATE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _PLUGPLAY_EVENT_CATEGORY
{
	HardwareProfileChangeEvent,
	TargetDeviceChangeEvent,
	DeviceClassChangeEvent,
	CustomDeviceEvent,
	DeviceInstallEvent,
	DeviceArrivalEvent,
	PowerEvent,
	VetoEvent,
	BlockedDriverEvent,
	InvalidIDEvent,
	MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY, *PPLUGPLAY_EVENT_CATEGORY;

typedef enum _PNP_VETO_TYPE
{
	PNP_VetoTypeUnknown, // unspecified
	PNP_VetoLegacyDevice, // instance path
	PNP_VetoPendingClose, // instance path
	PNP_VetoWindowsApp, // module
	PNP_VetoWindowsService, // service
	PNP_VetoOutstandingOpen, // instance path
	PNP_VetoDevice, // instance path
	PNP_VetoDriver, // driver service name
	PNP_VetoIllegalDeviceRequest, // instance path
	PNP_VetoInsufficientPower, // unspecified
	PNP_VetoNonDisableable, // instance path
	PNP_VetoLegacyDriver, // service
	PNP_VetoInsufficientRights  // unspecified
} PNP_VETO_TYPE, *PPNP_VETO_TYPE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
	UNICODE_STRING Name;
	USHORT         ValueType;
	USHORT         Reserved;
	ULONG          Flags;
	ULONG          ValueCount;
	union
	{
		PLONG64                                      pInt64;
		PULONG64                                     pUint64;
		PUNICODE_STRING                              pString;
		PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE         pFqbn;
		PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
	} Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _WNF_STATE_NAME
{
	ULONG Data[2];
} WNF_STATE_NAME, *PWNF_STATE_NAME;

typedef struct _KEY_VALUE_ENTRY
{
	PUNICODE_STRING ValueName;
	ULONG           DataLength;
	ULONG           DataOffset;
	ULONG           Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef enum _KEY_SET_INFORMATION_CLASS
{
	KeyWriteTimeInformation,
	KeyWow64FlagsInformation,
	KeyControlFlagsInformation,
	KeySetVirtualizationInformation,
	KeySetDebugInformation,
	KeySetHandleTagsInformation,
	MaxKeySetInfoClass  // MaxKeySetInfoClass should always be the last enum.
} KEY_SET_INFORMATION_CLASS, *PKEY_SET_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemHandleInformation = 16,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

typedef struct _T2_SET_PARAMETERS_V0
{
	ULONG    Version;
	ULONG    Reserved;
	LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, *PT2_SET_PARAMETERS;

typedef struct _FILE_PATH
{
	ULONG Version;
	ULONG Length;
	ULONG Type;
	CHAR  FilePath[1];
} FILE_PATH, *PFILE_PATH;

typedef struct _FILE_USER_QUOTA_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         SidLength;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER QuotaUsed;
	LARGE_INTEGER QuotaThreshold;
	LARGE_INTEGER QuotaLimit;
	SID           Sid[1];
} FILE_USER_QUOTA_INFORMATION, *PFILE_USER_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_LIST_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG SidLength;
	SID   Sid[1];
} FILE_QUOTA_LIST_INFORMATION, *PFILE_QUOTA_LIST_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
	ULONG         Unknown;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _FILTER_BOOT_OPTION_OPERATION
{
	FilterBootOptionOperationOpenSystemStore,
	FilterBootOptionOperationSetElement,
	FilterBootOptionOperationDeleteElement,
	FilterBootOptionOperationMax
} FILTER_BOOT_OPTION_OPERATION, *PFILTER_BOOT_OPTION_OPERATION;

typedef enum _EVENT_TYPE
{
	NotificationEvent = 0,
	SynchronizationEvent = 1,
} EVENT_TYPE, *PEVENT_TYPE;

typedef struct _FILE_FULL_EA_INFORMATION
{
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION
{
	ULONG NextEntryOffset;
	BYTE  EaNameLength;
	CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

typedef struct _BOOT_OPTIONS
{
	ULONG Version;
	ULONG Length;
	ULONG Timeout;
	ULONG CurrentBootEntryId;
	ULONG NextBootEntryId;
	WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, *PBOOT_OPTIONS;

typedef ULONG WNF_CHANGE_STAMP, *PWNF_CHANGE_STAMP;

typedef enum _WNF_DATA_SCOPE
{
	WnfDataScopeSystem = 0,
	WnfDataScopeSession = 1,
	WnfDataScopeUser = 2,
	WnfDataScopeProcess = 3,
	WnfDataScopeMachine = 4
} WNF_DATA_SCOPE, *PWNF_DATA_SCOPE;

typedef enum _WNF_STATE_NAME_LIFETIME
{
	WnfWellKnownStateName = 0,
	WnfPermanentStateName = 1,
	WnfPersistentStateName = 2,
	WnfTemporaryStateName = 3
} WNF_STATE_NAME_LIFETIME, *PWNF_STATE_NAME_LIFETIME;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS, *PVIRTUAL_MEMORY_INFORMATION_CLASS;

typedef enum _IO_SESSION_EVENT
{
	IoSessionEventIgnore,
	IoSessionEventCreated,
	IoSessionEventTerminated,
	IoSessionEventConnected,
	IoSessionEventDisconnected,
	IoSessionEventLogon,
	IoSessionEventLogoff,
	IoSessionEventMax
} IO_SESSION_EVENT, *PIO_SESSION_EVENT;

typedef enum _PORT_INFORMATION_CLASS
{
	PortBasicInformation,
#if DEVL
	PortDumpInformation
#endif
} PORT_INFORMATION_CLASS, *PPORT_INFORMATION_CLASS;

typedef enum _PLUGPLAY_CONTROL_CLASS
{
	PlugPlayControlEnumerateDevice,
	PlugPlayControlRegisterNewDevice,
	PlugPlayControlDeregisterDevice,
	PlugPlayControlInitializeDevice,
	PlugPlayControlStartDevice,
	PlugPlayControlUnlockDevice,
	PlugPlayControlQueryAndRemoveDevice,
	PlugPlayControlUserResponse,
	PlugPlayControlGenerateLegacyDevice,
	PlugPlayControlGetInterfaceDeviceList,
	PlugPlayControlProperty,
	PlugPlayControlDeviceClassAssociation,
	PlugPlayControlGetRelatedDevice,
	PlugPlayControlGetInterfaceDeviceAlias,
	PlugPlayControlDeviceStatus,
	PlugPlayControlGetDeviceDepth,
	PlugPlayControlQueryDeviceRelations,
	PlugPlayControlTargetDeviceRelation,
	PlugPlayControlQueryConflictList,
	PlugPlayControlRetrieveDock,
	PlugPlayControlResetDevice,
	PlugPlayControlHaltDevice,
	PlugPlayControlGetBlockedDriverList,
	MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS, *PPLUGPLAY_CONTROL_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS, *PIO_COMPLETION_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectFlags = 1,
	MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS, *PSEMAPHORE_INFORMATION_CLASS;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef enum _VDMSERVICECLASS
{
	VdmStartExecution,
	VdmQueueInterrupt,
	VdmDelayInterrupt,
	VdmInitialize,
	VdmFeatures,
	VdmSetInt21Handler,
	VdmQueryDir,
	VdmPrinterDirectIoOpen,
	VdmPrinterDirectIoClose,
	VdmPrinterInitialize,
	VdmSetLdtEntries,
	VdmSetProcessLdtInfo,
	VdmAdlibEmulation,
	VdmPMCliControl,
	VdmQueryVdmProcess
} VDMSERVICECLASS, *PVDMSERVICECLASS;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		// PsCreateInitialState
		struct {
			union {
				ULONG InitFlags;
				struct {
					UCHAR  WriteOutputOnExit : 1;
					UCHAR  DetectManifest : 1;
					UCHAR  IFEOSkipDebugger : 1;
					UCHAR  IFEODoNotPropagateKeyState : 1;
					UCHAR  SpareBits1 : 4;
					UCHAR  SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;
		// PsCreateFailOnSectionCreate
		struct {
			HANDLE FileHandle;
		} FailSection;
		// PsCreateFailExeFormat
		struct {
			USHORT DllCharacteristics;
		} ExeFormat;
		// PsCreateFailExeName
		struct {
			HANDLE IFEOKey;
		} ExeName;
		// PsCreateSuccess
		struct {
			union {
				ULONG OutputFlags;
				struct {
					UCHAR  ProtectedProcess : 1;
					UCHAR  AddressSpaceOverride : 1;
					UCHAR  DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR  ManifestDetected : 1;
					UCHAR  ProtectedProcessLight : 1;
					UCHAR  SpareBits1 : 3;
					UCHAR  SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE    FileHandle;
			HANDLE    SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG     UserProcessParametersWow64;
			ULONG     CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG     PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG     ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef enum _MEMORY_RESERVE_TYPE
{
	MemoryReserveUserApc,
	MemoryReserveIoCompletion,
	MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE, *PMEMORY_RESERVE_TYPE;

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
	AlpcBasicInformation,
	AlpcPortInformation,
	AlpcAssociateCompletionPortInformation,
	AlpcConnectedSIDInformation,
	AlpcServerInformation,
	AlpcMessageZoneInformation,
	AlpcRegisterCompletionListInformation,
	AlpcUnregisterCompletionListInformation,
	AlpcAdjustCompletionListConcurrencyCountInformation,
	AlpcRegisterCallbackInformation,
	AlpcCompletionListRundownInformation
} ALPC_PORT_INFORMATION_CLASS, *PALPC_PORT_INFORMATION_CLASS;

typedef struct _ALPC_CONTEXT_ATTR
{
	PVOID PortContext;
	PVOID MessageContext;
	ULONG SequenceNumber;
	ULONG MessageID;
	ULONG CallbackID;
} ALPC_CONTEXT_ATTR, *PALPC_CONTEXT_ATTR;

typedef struct _ALPC_DATA_VIEW_ATTR
{
	ULONG  Flags;
	HANDLE SectionHandle;
	PVOID  ViewBase;
	SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, *PALPC_DATA_VIEW_ATTR;

typedef struct _ALPC_SECURITY_ATTR
{
	ULONG                        Flags;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	HANDLE                       ContextHandle;
	ULONG                        Reserved1;
	ULONG                        Reserved2;
} ALPC_SECURITY_ATTR, *PALPC_SECURITY_ATTR;

typedef PVOID* PPVOID;

typedef enum _KPROFILE_SOURCE
{
	ProfileTime = 0,
	ProfileAlignmentFixup = 1,
	ProfileTotalIssues = 2,
	ProfilePipelineDry = 3,
	ProfileLoadInstructions = 4,
	ProfilePipelineFrozen = 5,
	ProfileBranchInstructions = 6,
	ProfileTotalNonissues = 7,
	ProfileDcacheMisses = 8,
	ProfileIcacheMisses = 9,
	ProfileCacheMisses = 10,
	ProfileBranchMispredictions = 11,
	ProfileStoreInstructions = 12,
	ProfileFpInstructions = 13,
	ProfileIntegerInstructions = 14,
	Profile2Issue = 15,
	Profile3Issue = 16,
	Profile4Issue = 17,
	ProfileSpecialInstructions = 18,
	ProfileTotalCycles = 19,
	ProfileIcacheIssues = 20,
	ProfileDcacheAccesses = 21,
	ProfileMemoryBarrierCycles = 22,
	ProfileLoadLinkedIssues = 23,
	ProfileMaximum = 24,
} KPROFILE_SOURCE, *PKPROFILE_SOURCE;

typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
{
	AlpcMessageSidInformation,
	AlpcMessageTokenModifiedIdInformation
} ALPC_MESSAGE_INFORMATION_CLASS, *PALPC_MESSAGE_INFORMATION_CLASS;

typedef enum _WORKERFACTORYINFOCLASS
{
	WorkerFactoryTimeout,
	WorkerFactoryRetryTimeout,
	WorkerFactoryIdleTimeout,
	WorkerFactoryBindingCount,
	WorkerFactoryThreadMinimum,
	WorkerFactoryThreadMaximum,
	WorkerFactoryPaused,
	WorkerFactoryBasicInformation,
	WorkerFactoryAdjustThreadGoal,
	WorkerFactoryCallbackType,
	WorkerFactoryStackInformation,
	MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, *PWORKERFACTORYINFOCLASS;

typedef enum _MEMORY_PARTITION_INFORMATION_CLASS
{
	SystemMemoryPartitionInformation,
	SystemMemoryPartitionMoveMemory,
	SystemMemoryPartitionAddPagefile,
	SystemMemoryPartitionCombineMemory,
	SystemMemoryPartitionInitialAddMemory,
	SystemMemoryPartitionGetMemoryEvents,
	SystemMemoryPartitionMax
} MEMORY_PARTITION_INFORMATION_CLASS, *PMEMORY_PARTITION_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS
{
	MutantBasicInformation,
	MutantOwnerInformation
} MUTANT_INFORMATION_CLASS, *PMUTANT_INFORMATION_CLASS;

typedef enum _ATOM_INFORMATION_CLASS
{
	AtomBasicInformation,
	AtomTableInformation
} ATOM_INFORMATION_CLASS, *PATOM_INFORMATION_CLASS;

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef VOID(CALLBACK* PTIMER_APC_ROUTINE)(
	IN PVOID TimerContext,
	IN ULONG TimerLowValue,
	IN LONG TimerHighValue);

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation = 0,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef LANGID* PLANGID;

typedef struct _PLUGPLAY_EVENT_BLOCK
{
	GUID EventGuid;
	PLUGPLAY_EVENT_CATEGORY EventCategory;
	PULONG Result;
	ULONG Flags;
	ULONG TotalSize;
	PVOID DeviceObject;

	union
	{
		struct
		{
			GUID ClassGuid;
			WCHAR SymbolicLinkName[1];
		} DeviceClass;
		struct
		{
			WCHAR DeviceIds[1];
		} TargetDevice;
		struct
		{
			WCHAR DeviceId[1];
		} InstallDevice;
		struct
		{
			PVOID NotificationStructure;
			WCHAR DeviceIds[1];
		} CustomNotification;
		struct
		{
			PVOID Notification;
		} ProfileNotification;
		struct
		{
			ULONG NotificationCode;
			ULONG NotificationData;
		} PowerNotification;
		struct
		{
			PNP_VETO_TYPE VetoType;
			WCHAR DeviceIdVetoNameBuffer[1]; // DeviceId<null>VetoName<null><null>
		} VetoNotification;
		struct
		{
			GUID BlockedDriverGuid;
		} BlockedDriverNotification;
		struct
		{
			WCHAR ParentId[1];
		} InvalidIDNotification;
	} u;
} PLUGPLAY_EVENT_BLOCK, *PPLUGPLAY_EVENT_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _DIRECTORY_NOTIFY_INFORMATION_CLASS
{
	DirectoryNotifyInformation = 1,
	DirectoryNotifyExtendedInformation = 2,
} DIRECTORY_NOTIFY_INFORMATION_CLASS, *PDIRECTORY_NOTIFY_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS
{
	EventBasicInformation
} EVENT_INFORMATION_CLASS, *PEVENT_INFORMATION_CLASS;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	unsigned long AllocatedAttributes;
	unsigned long ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	ULONG                       Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T                      MaxMessageLength;
	SIZE_T                      MemoryBandwidth;
	SIZE_T                      MaxPoolUsage;
	SIZE_T                      MaxSectionSize;
	SIZE_T                      MaxViewSize;
	SIZE_T                      MaxTotalSectionSize;
	ULONG                       DupObjectTypes;
#ifdef _WIN64
	ULONG                       Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef enum _IO_SESSION_STATE
{
	IoSessionStateCreated = 1,
	IoSessionStateInitialized = 2,
	IoSessionStateConnected = 3,
	IoSessionStateDisconnected = 4,
	IoSessionStateDisconnectedLoggedOn = 5,
	IoSessionStateLoggedOn = 6,
	IoSessionStateLoggedOff = 7,
	IoSessionStateTerminated = 8,
	IoSessionStateMax = 9,
} IO_SESSION_STATE, *PIO_SESSION_STATE;

typedef const WNF_STATE_NAME *PCWNF_STATE_NAME;

typedef const WNF_TYPE_ID *PCWNF_TYPE_ID;

typedef struct _WNF_DELIVERY_DESCRIPTOR
{
	unsigned __int64 SubscriptionId;
	WNF_STATE_NAME   StateName;
	unsigned long    ChangeStamp;
	unsigned long    StateDataSize;
	unsigned long    EventMask;
	WNF_TYPE_ID      TypeId;
	unsigned long    StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, *PWNF_DELIVERY_DESCRIPTOR;

typedef enum _DEBUG_CONTROL_CODE
{
	SysDbgQueryModuleInformation = 0,
	SysDbgQueryTraceInformation = 1,
	SysDbgSetTracePoint = 2,
	SysDbgSetSpecialCall = 3,
	SysDbgClearSpecialCalls = 4,
	SysDbgQuerySpecialCalls = 5,
	SysDbgBreakPoint = 6,
	SysDbgQueryVersion = 7,
	SysDbgReadVirtual = 8,
	SysDbgWriteVirtual = 9,
	SysDbgReadPhysical = 10,
	SysDbgWritePhysical = 11,
	SysDbgReadControlSpace = 12,
	SysDbgWriteControlSpace = 13,
	SysDbgReadIoSpace = 14,
	SysDbgWriteIoSpace = 15,
	SysDbgReadMsr = 16,
	SysDbgWriteMsr = 17,
	SysDbgReadBusData = 18,
	SysDbgWriteBusData = 19,
	SysDbgCheckLowMemory = 20,
	SysDbgEnableKernelDebugger = 21,
	SysDbgDisableKernelDebugger = 22,
	SysDbgGetAutoKdEnable = 23,
	SysDbgSetAutoKdEnable = 24,
	SysDbgGetPrintBufferSize = 25,
	SysDbgSetPrintBufferSize = 26,
	SysDbgGetKdUmExceptionEnable = 27,
	SysDbgSetKdUmExceptionEnable = 28,
	SysDbgGetTriageDump = 29,
	SysDbgGetKdBlockEnable = 30,
	SysDbgSetKdBlockEnable = 31
} DEBUG_CONTROL_CODE, *PDEBUG_CONTROL_CODE;

typedef struct _PORT_MESSAGE
{
	union
	{
		union
		{
			struct
			{
				short DataLength;
				short TotalLength;
			} s1;
			unsigned long Length;
		};
	} u1;
	union
	{
		union
		{
			struct
			{
				short Type;
				short DataInfoOffset;
			} s2;
			unsigned long ZeroInit;
		};
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double    DoNotUseThisField;
	};
	unsigned long MessageId;
	union
	{
		unsigned __int64 ClientViewSize;
		struct
		{
			unsigned long CallbackId;
			long          __PADDING__[1];
		};
	};
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct FILE_BASIC_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _PORT_SECTION_READ
{
	ULONG Length;
	ULONG ViewSize;
	ULONG ViewBase;
} PORT_SECTION_READ, *PPORT_SECTION_READ;

typedef struct _PORT_SECTION_WRITE
{
	ULONG  Length;
	HANDLE SectionHandle;
	ULONG  SectionOffset;
	ULONG  ViewSize;
	PVOID  ViewBase;
	PVOID  TargetViewBase;
} PORT_SECTION_WRITE, *PPORT_SECTION_WRITE;

typedef enum _TIMER_TYPE
{
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE, *PTIMER_TYPE;

typedef struct _BOOT_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG BootFilePathOffset;
	ULONG OsOptionsLength;
	UCHAR OsOptions[ANYSIZE_ARRAY];
} BOOT_ENTRY, *PBOOT_ENTRY;

typedef struct _EFI_DRIVER_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG DriverFilePathOffset;
} EFI_DRIVER_ENTRY, *PEFI_DRIVER_ENTRY;

typedef USHORT RTL_ATOM, *PRTL_ATOM;

typedef enum _TIMER_SET_INFORMATION_CLASS
{
	TimerSetCoalescableTimer,
	MaxTimerInfoClass
} TIMER_SET_INFORMATION_CLASS, *PTIMER_SET_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
	FileFsVolumeInformation = 1,
	FileFsLabelInformation = 2,
	FileFsSizeInformation = 3,
	FileFsDeviceInformation = 4,
	FileFsAttributeInformation = 5,
	FileFsControlInformation = 6,
	FileFsFullSizeInformation = 7,
	FileFsObjectIdInformation = 8,
	FileFsDriverPathInformation = 9,
	FileFsVolumeFlagsInformation = 10,
	FileFsSectorSizeInformation = 11,
	FileFsDataCopyInformation = 12,
	FileFsMetadataSizeInformation = 13,
	FileFsFullSizeInformationEx = 14,
	FileFsMaximumInformation = 15,
} FSINFOCLASS, *PFSINFOCLASS;

typedef enum _WAIT_TYPE
{
	WaitAll = 0,
	WaitAny = 1
} WAIT_TYPE, *PWAIT_TYPE;

typedef struct _USER_STACK
{
	PVOID FixedStackBase;
	PVOID FixedStackLimit;
	PVOID ExpandableStackBase;
	PVOID ExpandableStackLimit;
	PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation,
} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;

typedef enum _APPHELPCACHESERVICECLASS
{
	ApphelpCacheServiceLookup = 0,
	ApphelpCacheServiceRemove = 1,
	ApphelpCacheServiceUpdate = 2,
	ApphelpCacheServiceFlush = 3,
	ApphelpCacheServiceDump = 4,
	ApphelpDBGReadRegistry = 0x100,
	ApphelpDBGWriteRegistry = 0x101,
} APPHELPCACHESERVICECLASS, *PAPPHELPCACHESERVICECLASS;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
	USHORT Version;
	USHORT Reserved;
	ULONG  AttributeCount;
	union
	{
		PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
	} Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	PVOID           KeyContext;
	PVOID           ApcContext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, *PFILE_IO_COMPLETION_INFORMATION;

typedef PVOID PT2_CANCEL_PARAMETERS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
} THREADINFOCLASS, *PTHREADINFOCLASS;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllTypesInformation,
	ObjectHandleInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation = 3,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FileInternalInformation = 6,
	FileEaInformation = 7,
	FileAccessInformation = 8,
	FileNameInformation = 9,
	FileRenameInformation = 10,
	FileLinkInformation = 11,
	FileNamesInformation = 12,
	FileDispositionInformation = 13,
	FilePositionInformation = 14,
	FileFullEaInformation = 15,
	FileModeInformation = 16,
	FileAlignmentInformation = 17,
	FileAllInformation = 18,
	FileAllocationInformation = 19,
	FileEndOfFileInformation = 20,
	FileAlternateNameInformation = 21,
	FileStreamInformation = 22,
	FilePipeInformation = 23,
	FilePipeLocalInformation = 24,
	FilePipeRemoteInformation = 25,
	FileMailslotQueryInformation = 26,
	FileMailslotSetInformation = 27,
	FileCompressionInformation = 28,
	FileObjectIdInformation = 29,
	FileCompletionInformation = 30,
	FileMoveClusterInformation = 31,
	FileQuotaInformation = 32,
	FileReparsePointInformation = 33,
	FileNetworkOpenInformation = 34,
	FileAttributeTagInformation = 35,
	FileTrackingInformation = 36,
	FileIdBothDirectoryInformation = 37,
	FileIdFullDirectoryInformation = 38,
	FileValidDataLengthInformation = 39,
	FileShortNameInformation = 40,
	FileIoCompletionNotificationInformation = 41,
	FileIoStatusBlockRangeInformation = 42,
	FileIoPriorityHintInformation = 43,
	FileSfioReserveInformation = 44,
	FileSfioVolumeInformation = 45,
	FileHardLinkInformation = 46,
	FileProcessIdsUsingFileInformation = 47,
	FileNormalizedNameInformation = 48,
	FileNetworkPhysicalNameInformation = 49,
	FileIdGlobalTxDirectoryInformation = 50,
	FileIsRemoteDeviceInformation = 51,
	FileUnusedInformation = 52,
	FileNumaNodeInformation = 53,
	FileStandardLinkInformation = 54,
	FileRemoteProtocolInformation = 55,
	FileRenameInformationBypassAccessCheck = 56,
	FileLinkInformationBypassAccessCheck = 57,
	FileVolumeNameInformation = 58,
	FileIdInformation = 59,
	FileIdExtdDirectoryInformation = 60,
	FileReplaceCompletionInformation = 61,
	FileHardLinkFullIdInformation = 62,
	FileIdExtdBothDirectoryInformation = 63,
	FileDispositionInformationEx = 64,
	FileRenameInformationEx = 65,
	FileRenameInformationExBypassAccessCheck = 66,
	FileMaximumInformation = 67,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _KEY_INFORMATION_CLASS
{
	KeyBasicInformation = 0,
	KeyNodeInformation = 1,
	KeyFullInformation = 2,
	KeyNameInformation = 3,
	KeyCachedInformation = 4,
	KeyFlagsInformation = 5,
	KeyVirtualizationInformation = 6,
	KeyHandleTagsInformation = 7,
	MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS, *PKEY_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _TIMER_INFORMATION_CLASS
{
	TimerBasicInformation
} TIMER_INFORMATION_CLASS, *PTIMER_INFORMATION_CLASS;

typedef struct _KCONTINUE_ARGUMENT
{
	KCONTINUE_TYPE ContinueType;
	ULONG          ContinueFlags;
	ULONGLONG      Reserved[2];
} KCONTINUE_ARGUMENT, *PKCONTINUE_ARGUMENT;

typedef SneakCall<SneakHelper::hash("ZwAccessCheck"), IN PSECURITY_DESCRIPTOR, IN HANDLE, IN ACCESS_MASK, IN PGENERIC_MAPPING, OUT PPRIVILEGE_SET  OPTIONAL, IN OUT PULONG, OUT PACCESS_MASK, OUT PBOOLEAN> NtAccessCheck;
typedef SneakCall<SneakHelper::hash("ZwWorkerFactoryWorkerReady"), IN HANDLE> NtWorkerFactoryWorkerReady;
typedef SneakCall<SneakHelper::hash("ZwAcceptConnectPort"), OUT PHANDLE, IN ULONG  OPTIONAL, IN PPORT_MESSAGE, IN BOOLEAN, IN OUT PPORT_SECTION_WRITE  OPTIONAL, OUT PPORT_SECTION_READ  OPTIONAL> NtAcceptConnectPort;
typedef SneakCall<SneakHelper::hash("ZwMapUserPhysicalPagesScatter"), IN PVOID, IN PULONG, IN PULONG  OPTIONAL> NtMapUserPhysicalPagesScatter;
typedef SneakCall<SneakHelper::hash("ZwWaitForSingleObject"), IN HANDLE, IN BOOLEAN, IN PLARGE_INTEGER  OPTIONAL> NtWaitForSingleObject;
typedef SneakCall<SneakHelper::hash("ZwCallbackReturn"), IN PVOID  OPTIONAL, IN ULONG, IN NTSTATUS> NtCallbackReturn;
typedef SneakCall<SneakHelper::hash("ZwReadFile"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, OUT PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, IN PVOID, IN ULONG, IN PLARGE_INTEGER  OPTIONAL, IN PULONG  OPTIONAL> NtReadFile;
typedef SneakCall<SneakHelper::hash("ZwDeviceIoControlFile"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, IN ULONG, IN PVOID  OPTIONAL, IN ULONG, OUT PVOID  OPTIONAL, IN ULONG> NtDeviceIoControlFile;
typedef SneakCall<SneakHelper::hash("ZwWriteFile"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, IN PVOID, IN ULONG, IN PLARGE_INTEGER  OPTIONAL, IN PULONG  OPTIONAL> NtWriteFile;
typedef SneakCall<SneakHelper::hash("ZwRemoveIoCompletion"), IN HANDLE, OUT PULONG, OUT PULONG, OUT PIO_STATUS_BLOCK, IN PLARGE_INTEGER  OPTIONAL> NtRemoveIoCompletion;
typedef SneakCall<SneakHelper::hash("ZwReleaseSemaphore"), IN HANDLE, IN LONG, OUT PLONG  OPTIONAL> NtReleaseSemaphore;
typedef SneakCall<SneakHelper::hash("ZwReplyWaitReceivePort"), IN HANDLE, OUT PVOID  OPTIONAL, IN PPORT_MESSAGE  OPTIONAL, OUT PPORT_MESSAGE> NtReplyWaitReceivePort;
typedef SneakCall<SneakHelper::hash("ZwReplyPort"), IN HANDLE, IN PPORT_MESSAGE> NtReplyPort;
typedef SneakCall<SneakHelper::hash("ZwSetInformationThread"), IN HANDLE, IN THREADINFOCLASS, IN PVOID, IN ULONG> NtSetInformationThread;
typedef SneakCall<SneakHelper::hash("ZwSetEvent"), IN HANDLE, OUT PULONG  OPTIONAL> NtSetEvent;
typedef SneakCall<SneakHelper::hash("ZwClose"), IN HANDLE> NtClose;
typedef SneakCall<SneakHelper::hash("ZwQueryObject"), IN HANDLE, IN OBJECT_INFORMATION_CLASS, OUT PVOID  OPTIONAL, IN ULONG, OUT PULONG  OPTIONAL> NtQueryObject;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationFile"), IN HANDLE, OUT PIO_STATUS_BLOCK, OUT PVOID, IN ULONG, IN FILE_INFORMATION_CLASS> NtQueryInformationFile;
typedef SneakCall<SneakHelper::hash("ZwOpenKey"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenKey;
typedef SneakCall<SneakHelper::hash("ZwEnumerateValueKey"), IN HANDLE, IN ULONG, IN KEY_VALUE_INFORMATION_CLASS, OUT PVOID  OPTIONAL, IN ULONG, OUT PULONG> NtEnumerateValueKey;
typedef SneakCall<SneakHelper::hash("ZwFindAtom"), IN PWSTR  OPTIONAL, IN ULONG, OUT PUSHORT  OPTIONAL> NtFindAtom;
typedef SneakCall<SneakHelper::hash("ZwQueryDefaultLocale"), IN BOOLEAN, OUT PLCID> NtQueryDefaultLocale;
typedef SneakCall<SneakHelper::hash("ZwQueryKey"), IN HANDLE, IN KEY_INFORMATION_CLASS, OUT PVOID  OPTIONAL, IN ULONG, OUT PULONG> NtQueryKey;
typedef SneakCall<SneakHelper::hash("ZwQueryValueKey"), IN HANDLE, IN PUNICODE_STRING, IN KEY_VALUE_INFORMATION_CLASS, OUT PVOID  OPTIONAL, IN ULONG, OUT PULONG> NtQueryValueKey;
typedef SneakCall<SneakHelper::hash("ZwAllocateVirtualMemory"), IN HANDLE, IN OUT PVOID *, IN ULONG, IN OUT PSIZE_T, IN ULONG, IN ULONG> NtAllocateVirtualMemory;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationProcess"), IN HANDLE, IN PROCESSINFOCLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryInformationProcess;
typedef SneakCall<SneakHelper::hash("ZwWaitForMultipleObjects32"), IN ULONG, IN PHANDLE, IN WAIT_TYPE, IN BOOLEAN, IN PLARGE_INTEGER  OPTIONAL> NtWaitForMultipleObjects32;
typedef SneakCall<SneakHelper::hash("ZwWriteFileGather"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, IN PFILE_SEGMENT_ELEMENT, IN ULONG, IN PLARGE_INTEGER, IN PULONG  OPTIONAL> NtWriteFileGather;
typedef SneakCall<SneakHelper::hash("ZwCreateKey"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG, IN PUNICODE_STRING  OPTIONAL, IN ULONG, OUT PULONG  OPTIONAL> NtCreateKey;
typedef SneakCall<SneakHelper::hash("ZwFreeVirtualMemory"), IN HANDLE, IN OUT PVOID *, IN OUT PSIZE_T, IN ULONG> NtFreeVirtualMemory;
typedef SneakCall<SneakHelper::hash("ZwImpersonateClientOfPort"), IN HANDLE, IN PPORT_MESSAGE> NtImpersonateClientOfPort;
typedef SneakCall<SneakHelper::hash("ZwReleaseMutant"), IN HANDLE, OUT PULONG  OPTIONAL> NtReleaseMutant;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationToken"), IN HANDLE, IN TOKEN_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG> NtQueryInformationToken;
typedef SneakCall<SneakHelper::hash("ZwRequestWaitReplyPort"), IN HANDLE, IN PPORT_MESSAGE, OUT PPORT_MESSAGE> NtRequestWaitReplyPort;
typedef SneakCall<SneakHelper::hash("ZwQueryVirtualMemory"), IN HANDLE, IN PVOID, IN MEMORY_INFORMATION_CLASS, OUT PVOID, IN SIZE_T, OUT PSIZE_T  OPTIONAL> NtQueryVirtualMemory;
typedef SneakCall<SneakHelper::hash("ZwOpenThreadToken"), IN HANDLE, IN ACCESS_MASK, IN BOOLEAN, OUT PHANDLE> NtOpenThreadToken;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationThread"), IN HANDLE, IN THREADINFOCLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryInformationThread;
typedef SneakCall<SneakHelper::hash("ZwOpenProcess"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN PCLIENT_ID  OPTIONAL> NtOpenProcess;
typedef SneakCall<SneakHelper::hash("ZwSetInformationFile"), IN HANDLE, OUT PIO_STATUS_BLOCK, IN PVOID, IN ULONG, IN FILE_INFORMATION_CLASS> NtSetInformationFile;
typedef SneakCall<SneakHelper::hash("ZwMapViewOfSection"), IN HANDLE, IN HANDLE, IN OUT PVOID, IN ULONG, IN SIZE_T, IN OUT PLARGE_INTEGER  OPTIONAL, IN OUT PSIZE_T, IN SECTION_INHERIT, IN ULONG, IN ULONG> NtMapViewOfSection;
typedef SneakCall<SneakHelper::hash("ZwAccessCheckAndAuditAlarm"), IN PUNICODE_STRING, IN PVOID  OPTIONAL, IN PUNICODE_STRING, IN PUNICODE_STRING, IN PSECURITY_DESCRIPTOR, IN ACCESS_MASK, IN PGENERIC_MAPPING, IN BOOLEAN, OUT PACCESS_MASK, OUT PBOOLEAN, OUT PBOOLEAN> NtAccessCheckAndAuditAlarm;
typedef SneakCall<SneakHelper::hash("ZwUnmapViewOfSection"), IN HANDLE, IN PVOID> NtUnmapViewOfSection;
typedef SneakCall<SneakHelper::hash("ZwReplyWaitReceivePortEx"), IN HANDLE, OUT PULONG  OPTIONAL, IN PPORT_MESSAGE  OPTIONAL, OUT PPORT_MESSAGE, IN PLARGE_INTEGER  OPTIONAL> NtReplyWaitReceivePortEx;
typedef SneakCall<SneakHelper::hash("ZwTerminateProcess"), IN HANDLE  OPTIONAL, IN NTSTATUS> NtTerminateProcess;
typedef SneakCall<SneakHelper::hash("ZwSetEventBoostPriority"), IN HANDLE> NtSetEventBoostPriority;
typedef SneakCall<SneakHelper::hash("ZwReadFileScatter"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, IN PFILE_SEGMENT_ELEMENT, IN ULONG, IN PLARGE_INTEGER  OPTIONAL, IN PULONG  OPTIONAL> NtReadFileScatter;
typedef SneakCall<SneakHelper::hash("ZwOpenThreadTokenEx"), IN HANDLE, IN ACCESS_MASK, IN BOOLEAN, IN ULONG, OUT PHANDLE> NtOpenThreadTokenEx;
typedef SneakCall<SneakHelper::hash("ZwOpenProcessTokenEx"), IN HANDLE, IN ACCESS_MASK, IN ULONG, OUT PHANDLE> NtOpenProcessTokenEx;
typedef SneakCall<SneakHelper::hash("ZwQueryPerformanceCounter"), OUT PLARGE_INTEGER, OUT PLARGE_INTEGER  OPTIONAL> NtQueryPerformanceCounter;
typedef SneakCall<SneakHelper::hash("ZwEnumerateKey"), IN HANDLE, IN ULONG, IN KEY_INFORMATION_CLASS, OUT PVOID  OPTIONAL, IN ULONG, OUT PULONG> NtEnumerateKey;
typedef SneakCall<SneakHelper::hash("ZwOpenFile"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, OUT PIO_STATUS_BLOCK, IN ULONG, IN ULONG> NtOpenFile;
typedef SneakCall<SneakHelper::hash("ZwDelayExecution"), IN BOOLEAN, IN PLARGE_INTEGER> NtDelayExecution;
typedef SneakCall<SneakHelper::hash("ZwQueryDirectoryFile"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, OUT PVOID, IN ULONG, IN FILE_INFORMATION_CLASS, IN BOOLEAN, IN PUNICODE_STRING  OPTIONAL, IN BOOLEAN> NtQueryDirectoryFile;
typedef SneakCall<SneakHelper::hash("ZwQuerySystemInformation"), IN SYSTEM_INFORMATION_CLASS, IN OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQuerySystemInformation;
typedef SneakCall<SneakHelper::hash("ZwOpenSection"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenSection;
typedef SneakCall<SneakHelper::hash("ZwQueryTimer"), IN HANDLE, IN TIMER_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryTimer;
typedef SneakCall<SneakHelper::hash("ZwFsControlFile"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, IN ULONG, IN PVOID  OPTIONAL, IN ULONG, OUT PVOID  OPTIONAL, IN ULONG> NtFsControlFile;
typedef SneakCall<SneakHelper::hash("ZwWriteVirtualMemory"), IN HANDLE, IN PVOID, IN PVOID, IN SIZE_T, OUT PSIZE_T  OPTIONAL> NtWriteVirtualMemory;
typedef SneakCall<SneakHelper::hash("ZwCloseObjectAuditAlarm"), IN PUNICODE_STRING, IN PVOID  OPTIONAL, IN BOOLEAN> NtCloseObjectAuditAlarm;
typedef SneakCall<SneakHelper::hash("ZwDuplicateObject"), IN HANDLE, IN HANDLE, IN HANDLE  OPTIONAL, OUT PHANDLE  OPTIONAL, IN ACCESS_MASK, IN ULONG, IN ULONG> NtDuplicateObject;
typedef SneakCall<SneakHelper::hash("ZwQueryAttributesFile"), IN POBJECT_ATTRIBUTES, OUT PFILE_BASIC_INFORMATION> NtQueryAttributesFile;
typedef SneakCall<SneakHelper::hash("ZwClearEvent"), IN HANDLE> NtClearEvent;
typedef SneakCall<SneakHelper::hash("ZwReadVirtualMemory"), IN HANDLE, IN PVOID  OPTIONAL, OUT PVOID, IN SIZE_T, OUT PSIZE_T  OPTIONAL> NtReadVirtualMemory;
typedef SneakCall<SneakHelper::hash("ZwOpenEvent"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenEvent;
typedef SneakCall<SneakHelper::hash("ZwAdjustPrivilegesToken"), IN HANDLE, IN BOOLEAN, IN PTOKEN_PRIVILEGES  OPTIONAL, IN ULONG, OUT PTOKEN_PRIVILEGES  OPTIONAL, OUT PULONG  OPTIONAL> NtAdjustPrivilegesToken;
typedef SneakCall<SneakHelper::hash("ZwDuplicateToken"), IN HANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN BOOLEAN, IN TOKEN_TYPE, OUT PHANDLE> NtDuplicateToken;
typedef SneakCall<SneakHelper::hash("ZwContinue"), IN PCONTEXT, IN BOOLEAN> NtContinue;
typedef SneakCall<SneakHelper::hash("ZwQueryDefaultUILanguage"), OUT PLANGID> NtQueryDefaultUILanguage;
typedef SneakCall<SneakHelper::hash("ZwQueueApcThread"), IN HANDLE, IN PKNORMAL_ROUTINE, IN PVOID  OPTIONAL, IN PVOID  OPTIONAL, IN PVOID  OPTIONAL> NtQueueApcThread;
typedef SneakCall<SneakHelper::hash("ZwYieldExecution")> NtYieldExecution;
typedef SneakCall<SneakHelper::hash("ZwAddAtom"), IN PWSTR  OPTIONAL, IN ULONG, OUT PUSHORT  OPTIONAL> NtAddAtom;
typedef SneakCall<SneakHelper::hash("ZwCreateEvent"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN EVENT_TYPE, IN BOOLEAN> NtCreateEvent;
typedef SneakCall<SneakHelper::hash("ZwQueryVolumeInformationFile"), IN HANDLE, OUT PIO_STATUS_BLOCK, OUT PVOID, IN ULONG, IN FSINFOCLASS> NtQueryVolumeInformationFile;
typedef SneakCall<SneakHelper::hash("ZwCreateSection"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN PLARGE_INTEGER  OPTIONAL, IN ULONG, IN ULONG, IN HANDLE  OPTIONAL> NtCreateSection;
typedef SneakCall<SneakHelper::hash("ZwFlushBuffersFile"), IN HANDLE, OUT PIO_STATUS_BLOCK> NtFlushBuffersFile;
typedef SneakCall<SneakHelper::hash("ZwApphelpCacheControl"), IN APPHELPCACHESERVICECLASS, IN PVOID> NtApphelpCacheControl;
typedef SneakCall<SneakHelper::hash("ZwCreateProcessEx"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN HANDLE, IN ULONG, IN HANDLE  OPTIONAL, IN HANDLE  OPTIONAL, IN HANDLE  OPTIONAL, IN ULONG> NtCreateProcessEx;
typedef SneakCall<SneakHelper::hash("ZwCreateThread"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN HANDLE, OUT PCLIENT_ID, IN PCONTEXT, IN PUSER_STACK, IN BOOLEAN> NtCreateThread;
typedef SneakCall<SneakHelper::hash("ZwIsProcessInJob"), IN HANDLE, IN HANDLE  OPTIONAL> NtIsProcessInJob;
typedef SneakCall<SneakHelper::hash("ZwProtectVirtualMemory"), IN HANDLE, IN OUT PVOID *, IN OUT PSIZE_T, IN ULONG, OUT PULONG> NtProtectVirtualMemory;
typedef SneakCall<SneakHelper::hash("ZwQuerySection"), IN HANDLE, IN SECTION_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQuerySection;
typedef SneakCall<SneakHelper::hash("ZwResumeThread"), IN HANDLE, IN OUT PULONG  OPTIONAL> NtResumeThread;
typedef SneakCall<SneakHelper::hash("ZwTerminateThread"), IN HANDLE, IN NTSTATUS> NtTerminateThread;
typedef SneakCall<SneakHelper::hash("ZwReadRequestData"), IN HANDLE, IN PPORT_MESSAGE, IN ULONG, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtReadRequestData;
typedef SneakCall<SneakHelper::hash("ZwCreateFile"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, OUT PIO_STATUS_BLOCK, IN PLARGE_INTEGER  OPTIONAL, IN ULONG, IN ULONG, IN ULONG, IN ULONG, IN PVOID  OPTIONAL, IN ULONG> NtCreateFile;
typedef SneakCall<SneakHelper::hash("ZwQueryEvent"), IN HANDLE, IN EVENT_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryEvent;
typedef SneakCall<SneakHelper::hash("ZwWriteRequestData"), IN HANDLE, IN PPORT_MESSAGE, IN ULONG, IN PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtWriteRequestData;
typedef SneakCall<SneakHelper::hash("ZwOpenDirectoryObject"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenDirectoryObject;
typedef SneakCall<SneakHelper::hash("ZwAccessCheckByTypeAndAuditAlarm"), IN PUNICODE_STRING, IN PVOID  OPTIONAL, IN PUNICODE_STRING, IN PUNICODE_STRING, IN PSECURITY_DESCRIPTOR, IN PSID  OPTIONAL, IN ACCESS_MASK, IN AUDIT_EVENT_TYPE, IN ULONG, IN POBJECT_TYPE_LIST  OPTIONAL, IN ULONG, IN PGENERIC_MAPPING, IN BOOLEAN, OUT PACCESS_MASK, OUT PULONG, OUT PBOOLEAN> NtAccessCheckByTypeAndAuditAlarm;
typedef SneakCall<SneakHelper::hash("ZwWaitForMultipleObjects"), IN ULONG, IN PHANDLE, IN WAIT_TYPE, IN BOOLEAN, IN PLARGE_INTEGER  OPTIONAL> NtWaitForMultipleObjects;
typedef SneakCall<SneakHelper::hash("ZwSetInformationObject"), IN HANDLE, IN OBJECT_INFORMATION_CLASS, IN PVOID, IN ULONG> NtSetInformationObject;
typedef SneakCall<SneakHelper::hash("ZwCancelIoFile"), IN HANDLE, OUT PIO_STATUS_BLOCK> NtCancelIoFile;
typedef SneakCall<SneakHelper::hash("ZwTraceEvent"), IN HANDLE, IN ULONG, IN ULONG, IN PVOID> NtTraceEvent;
typedef SneakCall<SneakHelper::hash("ZwPowerInformation"), IN POWER_INFORMATION_LEVEL, IN PVOID  OPTIONAL, IN ULONG, OUT PVOID  OPTIONAL, IN ULONG> NtPowerInformation;
typedef SneakCall<SneakHelper::hash("ZwSetValueKey"), IN HANDLE, IN PUNICODE_STRING, IN ULONG  OPTIONAL, IN ULONG, IN PVOID, IN ULONG> NtSetValueKey;
typedef SneakCall<SneakHelper::hash("ZwCancelTimer"), IN HANDLE, OUT PBOOLEAN  OPTIONAL> NtCancelTimer;
typedef SneakCall<SneakHelper::hash("ZwSetTimer"), IN HANDLE, IN PLARGE_INTEGER, IN PTIMER_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, IN BOOLEAN, IN LONG  OPTIONAL, OUT PBOOLEAN  OPTIONAL> NtSetTimer;
typedef SneakCall<SneakHelper::hash("ZwAccessCheckByType"), IN PSECURITY_DESCRIPTOR, IN PSID  OPTIONAL, IN HANDLE, IN ULONG, IN POBJECT_TYPE_LIST, IN ULONG, IN PGENERIC_MAPPING, OUT PPRIVILEGE_SET, IN OUT PULONG, OUT PACCESS_MASK, OUT PULONG> NtAccessCheckByType;
typedef SneakCall<SneakHelper::hash("ZwAccessCheckByTypeResultList"), IN PSECURITY_DESCRIPTOR, IN PSID  OPTIONAL, IN HANDLE, IN ACCESS_MASK, IN POBJECT_TYPE_LIST, IN ULONG, IN PGENERIC_MAPPING, OUT PPRIVILEGE_SET, IN OUT PULONG, OUT PACCESS_MASK, OUT PULONG> NtAccessCheckByTypeResultList;
typedef SneakCall<SneakHelper::hash("ZwAccessCheckByTypeResultListAndAuditAlarm"), IN PUNICODE_STRING, IN PVOID  OPTIONAL, IN PUNICODE_STRING, IN PUNICODE_STRING, IN PSECURITY_DESCRIPTOR, IN PSID  OPTIONAL, IN ACCESS_MASK, IN AUDIT_EVENT_TYPE, IN ULONG, IN POBJECT_TYPE_LIST  OPTIONAL, IN ULONG, IN PGENERIC_MAPPING, IN BOOLEAN, OUT PACCESS_MASK, OUT PULONG, OUT PULONG> NtAccessCheckByTypeResultListAndAuditAlarm;
typedef SneakCall<SneakHelper::hash("ZwAccessCheckByTypeResultListAndAuditAlarmByHandle"), IN PUNICODE_STRING, IN PVOID  OPTIONAL, IN HANDLE, IN PUNICODE_STRING, IN PUNICODE_STRING, IN PSECURITY_DESCRIPTOR, IN PSID  OPTIONAL, IN ACCESS_MASK, IN AUDIT_EVENT_TYPE, IN ULONG, IN POBJECT_TYPE_LIST  OPTIONAL, IN ULONG, IN PGENERIC_MAPPING, IN BOOLEAN, OUT PACCESS_MASK, OUT PULONG, OUT PULONG> NtAccessCheckByTypeResultListAndAuditAlarmByHandle;
typedef SneakCall<SneakHelper::hash("ZwAcquireProcessActivityReference")> NtAcquireProcessActivityReference;
typedef SneakCall<SneakHelper::hash("ZwAddAtomEx"), IN PWSTR, IN ULONG, IN PRTL_ATOM, IN ULONG> NtAddAtomEx;
typedef SneakCall<SneakHelper::hash("ZwAddBootEntry"), IN PBOOT_ENTRY, OUT PULONG  OPTIONAL> NtAddBootEntry;
typedef SneakCall<SneakHelper::hash("ZwAddDriverEntry"), IN PEFI_DRIVER_ENTRY, OUT PULONG  OPTIONAL> NtAddDriverEntry;
typedef SneakCall<SneakHelper::hash("ZwAdjustGroupsToken"), IN HANDLE, IN BOOLEAN, IN PTOKEN_GROUPS  OPTIONAL, IN ULONG  OPTIONAL, OUT PTOKEN_GROUPS  OPTIONAL, OUT PULONG> NtAdjustGroupsToken;
typedef SneakCall<SneakHelper::hash("ZwAdjustTokenClaimsAndDeviceGroups"), IN HANDLE, IN BOOLEAN, IN BOOLEAN, IN BOOLEAN, IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  OPTIONAL, IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  OPTIONAL, IN PTOKEN_GROUPS  OPTIONAL, IN ULONG, OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  OPTIONAL, IN ULONG, OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  OPTIONAL, IN ULONG, OUT PTOKEN_GROUPS  OPTIONAL, OUT PULONG  OPTIONAL, OUT PULONG  OPTIONAL, OUT PULONG  OPTIONAL> NtAdjustTokenClaimsAndDeviceGroups;
typedef SneakCall<SneakHelper::hash("ZwAlertResumeThread"), IN HANDLE, OUT PULONG  OPTIONAL> NtAlertResumeThread;
typedef SneakCall<SneakHelper::hash("ZwAlertThread"), IN HANDLE> NtAlertThread;
typedef SneakCall<SneakHelper::hash("ZwAlertThreadByThreadId"), IN ULONG> NtAlertThreadByThreadId;
typedef SneakCall<SneakHelper::hash("ZwAllocateLocallyUniqueId"), OUT PLUID> NtAllocateLocallyUniqueId;
typedef SneakCall<SneakHelper::hash("ZwAllocateReserveObject"), OUT PHANDLE, IN POBJECT_ATTRIBUTES, IN MEMORY_RESERVE_TYPE> NtAllocateReserveObject;
typedef SneakCall<SneakHelper::hash("ZwAllocateUserPhysicalPages"), IN HANDLE, IN OUT PULONG, OUT PULONG> NtAllocateUserPhysicalPages;
typedef SneakCall<SneakHelper::hash("ZwAllocateUuids"), OUT PLARGE_INTEGER, OUT PULONG, OUT PULONG, OUT PUCHAR> NtAllocateUuids;
typedef SneakCall<SneakHelper::hash("ZwAllocateVirtualMemoryEx"), IN HANDLE, IN OUT PPVOID, IN ULONG_PTR, IN OUT PSIZE_T, IN ULONG, IN OUT PVOID  OPTIONAL, IN ULONG> NtAllocateVirtualMemoryEx;
typedef SneakCall<SneakHelper::hash("ZwAlpcAcceptConnectPort"), OUT PHANDLE, IN HANDLE, IN ULONG, IN POBJECT_ATTRIBUTES  OPTIONAL, IN PALPC_PORT_ATTRIBUTES  OPTIONAL, IN PVOID  OPTIONAL, IN PPORT_MESSAGE, IN OUT PALPC_MESSAGE_ATTRIBUTES  OPTIONAL, IN BOOLEAN> NtAlpcAcceptConnectPort;
typedef SneakCall<SneakHelper::hash("ZwAlpcCancelMessage"), IN HANDLE, IN ULONG, IN PALPC_CONTEXT_ATTR> NtAlpcCancelMessage;
typedef SneakCall<SneakHelper::hash("ZwAlpcConnectPort"), OUT PHANDLE, IN PUNICODE_STRING, IN POBJECT_ATTRIBUTES  OPTIONAL, IN PALPC_PORT_ATTRIBUTES  OPTIONAL, IN ULONG, IN PSID  OPTIONAL, IN OUT PPORT_MESSAGE  OPTIONAL, IN OUT PULONG  OPTIONAL, IN OUT PALPC_MESSAGE_ATTRIBUTES  OPTIONAL, IN OUT PALPC_MESSAGE_ATTRIBUTES  OPTIONAL, IN PLARGE_INTEGER  OPTIONAL> NtAlpcConnectPort;
typedef SneakCall<SneakHelper::hash("ZwAlpcConnectPortEx"), OUT PHANDLE, IN POBJECT_ATTRIBUTES, IN POBJECT_ATTRIBUTES  OPTIONAL, IN PALPC_PORT_ATTRIBUTES  OPTIONAL, IN ULONG, IN PSECURITY_DESCRIPTOR  OPTIONAL, IN OUT PPORT_MESSAGE  OPTIONAL, IN OUT PSIZE_T  OPTIONAL, IN OUT PALPC_MESSAGE_ATTRIBUTES  OPTIONAL, IN OUT PALPC_MESSAGE_ATTRIBUTES  OPTIONAL, IN PLARGE_INTEGER  OPTIONAL> NtAlpcConnectPortEx;
typedef SneakCall<SneakHelper::hash("ZwAlpcCreatePort"), OUT PHANDLE, IN POBJECT_ATTRIBUTES  OPTIONAL, IN PALPC_PORT_ATTRIBUTES  OPTIONAL> NtAlpcCreatePort;
typedef SneakCall<SneakHelper::hash("ZwAlpcCreatePortSection"), IN HANDLE, IN ULONG, IN HANDLE  OPTIONAL, IN SIZE_T, OUT PHANDLE, OUT PSIZE_T> NtAlpcCreatePortSection;
typedef SneakCall<SneakHelper::hash("ZwAlpcCreateResourceReserve"), IN HANDLE, IN ULONG, IN SIZE_T, OUT PHANDLE> NtAlpcCreateResourceReserve;
typedef SneakCall<SneakHelper::hash("ZwAlpcCreateSectionView"), IN HANDLE, IN ULONG, IN OUT PALPC_DATA_VIEW_ATTR> NtAlpcCreateSectionView;
typedef SneakCall<SneakHelper::hash("ZwAlpcCreateSecurityContext"), IN HANDLE, IN ULONG, IN OUT PALPC_SECURITY_ATTR> NtAlpcCreateSecurityContext;
typedef SneakCall<SneakHelper::hash("ZwAlpcDeletePortSection"), IN HANDLE, IN ULONG, IN HANDLE> NtAlpcDeletePortSection;
typedef SneakCall<SneakHelper::hash("ZwAlpcDeleteResourceReserve"), IN HANDLE, IN ULONG, IN HANDLE> NtAlpcDeleteResourceReserve;
typedef SneakCall<SneakHelper::hash("ZwAlpcDeleteSectionView"), IN HANDLE, IN ULONG, IN PVOID> NtAlpcDeleteSectionView;
typedef SneakCall<SneakHelper::hash("ZwAlpcDeleteSecurityContext"), IN HANDLE, IN ULONG, IN HANDLE> NtAlpcDeleteSecurityContext;
typedef SneakCall<SneakHelper::hash("ZwAlpcDisconnectPort"), IN HANDLE, IN ULONG> NtAlpcDisconnectPort;
typedef SneakCall<SneakHelper::hash("ZwAlpcImpersonateClientContainerOfPort"), IN HANDLE, IN PPORT_MESSAGE, IN ULONG> NtAlpcImpersonateClientContainerOfPort;
typedef SneakCall<SneakHelper::hash("ZwAlpcImpersonateClientOfPort"), IN HANDLE, IN PPORT_MESSAGE, IN PVOID> NtAlpcImpersonateClientOfPort;
typedef SneakCall<SneakHelper::hash("ZwAlpcOpenSenderProcess"), OUT PHANDLE, IN HANDLE, IN PPORT_MESSAGE, IN ULONG, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtAlpcOpenSenderProcess;
typedef SneakCall<SneakHelper::hash("ZwAlpcOpenSenderThread"), OUT PHANDLE, IN HANDLE, IN PPORT_MESSAGE, IN ULONG, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtAlpcOpenSenderThread;
typedef SneakCall<SneakHelper::hash("ZwAlpcQueryInformation"), IN HANDLE  OPTIONAL, IN ALPC_PORT_INFORMATION_CLASS, IN OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtAlpcQueryInformation;
typedef SneakCall<SneakHelper::hash("ZwAlpcQueryInformationMessage"), IN HANDLE, IN PPORT_MESSAGE, IN ALPC_MESSAGE_INFORMATION_CLASS, OUT PVOID  OPTIONAL, IN ULONG, OUT PULONG  OPTIONAL> NtAlpcQueryInformationMessage;
typedef SneakCall<SneakHelper::hash("ZwAlpcRevokeSecurityContext"), IN HANDLE, IN ULONG, IN HANDLE> NtAlpcRevokeSecurityContext;
typedef SneakCall<SneakHelper::hash("ZwAlpcSendWaitReceivePort"), IN HANDLE, IN ULONG, IN PPORT_MESSAGE  OPTIONAL, IN OUT PALPC_MESSAGE_ATTRIBUTES  OPTIONAL, OUT PPORT_MESSAGE  OPTIONAL, IN OUT PSIZE_T  OPTIONAL, IN OUT PALPC_MESSAGE_ATTRIBUTES  OPTIONAL, IN PLARGE_INTEGER  OPTIONAL> NtAlpcSendWaitReceivePort;
typedef SneakCall<SneakHelper::hash("ZwAlpcSetInformation"), IN HANDLE, IN ALPC_PORT_INFORMATION_CLASS, IN PVOID  OPTIONAL, IN ULONG> NtAlpcSetInformation;
typedef SneakCall<SneakHelper::hash("ZwAreMappedFilesTheSame"), IN PVOID, IN PVOID> NtAreMappedFilesTheSame;
typedef SneakCall<SneakHelper::hash("ZwAssignProcessToJobObject"), IN HANDLE, IN HANDLE> NtAssignProcessToJobObject;
typedef SneakCall<SneakHelper::hash("ZwAssociateWaitCompletionPacket"), IN HANDLE, IN HANDLE, IN HANDLE, IN PVOID  OPTIONAL, IN PVOID  OPTIONAL, IN NTSTATUS, IN ULONG_PTR, OUT PBOOLEAN OPTIONAL> NtAssociateWaitCompletionPacket;
typedef SneakCall<SneakHelper::hash("ZwCallEnclave"), IN PENCLAVE_ROUTINE, IN PVOID, IN BOOLEAN, IN OUT PVOID OPTIONAL> NtCallEnclave;
typedef SneakCall<SneakHelper::hash("ZwCancelIoFileEx"), IN HANDLE, IN PIO_STATUS_BLOCK  OPTIONAL, OUT PIO_STATUS_BLOCK> NtCancelIoFileEx;
typedef SneakCall<SneakHelper::hash("ZwCancelSynchronousIoFile"), IN HANDLE, IN PIO_STATUS_BLOCK  OPTIONAL, OUT PIO_STATUS_BLOCK> NtCancelSynchronousIoFile;
typedef SneakCall<SneakHelper::hash("ZwCancelTimer2"), IN HANDLE, IN PT2_CANCEL_PARAMETERS> NtCancelTimer2;
typedef SneakCall<SneakHelper::hash("ZwCancelWaitCompletionPacket"), IN HANDLE, IN BOOLEAN> NtCancelWaitCompletionPacket;
typedef SneakCall<SneakHelper::hash("ZwCommitComplete"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtCommitComplete;
typedef SneakCall<SneakHelper::hash("ZwCommitEnlistment"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtCommitEnlistment;
typedef SneakCall<SneakHelper::hash("ZwCommitRegistryTransaction"), IN HANDLE, IN BOOL> NtCommitRegistryTransaction;
typedef SneakCall<SneakHelper::hash("ZwCommitTransaction"), IN HANDLE, IN BOOLEAN> NtCommitTransaction;
typedef SneakCall<SneakHelper::hash("ZwCompactKeys"), IN ULONG, IN HANDLE> NtCompactKeys;
typedef SneakCall<SneakHelper::hash("ZwCompareObjects"), IN HANDLE, IN HANDLE> NtCompareObjects;
typedef SneakCall<SneakHelper::hash("ZwCompareSigningLevels"), IN ULONG, IN ULONG> NtCompareSigningLevels;
typedef SneakCall<SneakHelper::hash("ZwCompareTokens"), IN HANDLE, IN HANDLE, OUT PBOOLEAN> NtCompareTokens;
typedef SneakCall<SneakHelper::hash("ZwCompleteConnectPort"), IN HANDLE> NtCompleteConnectPort;
typedef SneakCall<SneakHelper::hash("ZwCompressKey"), IN HANDLE> NtCompressKey;
typedef SneakCall<SneakHelper::hash("ZwConnectPort"), OUT PHANDLE, IN PUNICODE_STRING, IN PSECURITY_QUALITY_OF_SERVICE, IN OUT PPORT_SECTION_WRITE  OPTIONAL, IN OUT PPORT_SECTION_READ  OPTIONAL, OUT PULONG  OPTIONAL, IN OUT PVOID  OPTIONAL, IN OUT PULONG  OPTIONAL> NtConnectPort;
typedef SneakCall<SneakHelper::hash("ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter"), IN ULONG, IN ULONG, IN ULONG, IN ULONG> NtConvertBetweenAuxiliaryCounterAndPerformanceCounter;
typedef SneakCall<SneakHelper::hash("ZwCreateDebugObject"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG> NtCreateDebugObject;
typedef SneakCall<SneakHelper::hash("ZwCreateDirectoryObject"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtCreateDirectoryObject;
typedef SneakCall<SneakHelper::hash("ZwCreateDirectoryObjectEx"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN HANDLE, IN ULONG> NtCreateDirectoryObjectEx;
typedef SneakCall<SneakHelper::hash("ZwCreateEnclave"), IN HANDLE, IN OUT PVOID, IN ULONG_PTR, IN SIZE_T, IN SIZE_T, IN ULONG, IN PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtCreateEnclave;
typedef SneakCall<SneakHelper::hash("ZwCreateEnlistment"), OUT PHANDLE, IN ACCESS_MASK, IN HANDLE, IN HANDLE, IN POBJECT_ATTRIBUTES  OPTIONAL, IN ULONG  OPTIONAL, IN NOTIFICATION_MASK, IN PVOID  OPTIONAL> NtCreateEnlistment;
typedef SneakCall<SneakHelper::hash("ZwCreateEventPair"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL> NtCreateEventPair;
typedef SneakCall<SneakHelper::hash("ZwCreateIRTimer"), OUT PHANDLE, IN ACCESS_MASK> NtCreateIRTimer;
typedef SneakCall<SneakHelper::hash("ZwCreateIoCompletion"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN ULONG  OPTIONAL> NtCreateIoCompletion;
typedef SneakCall<SneakHelper::hash("ZwCreateJobObject"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL> NtCreateJobObject;
typedef SneakCall<SneakHelper::hash("ZwCreateJobSet"), IN ULONG, IN PJOB_SET_ARRAY, IN ULONG> NtCreateJobSet;
typedef SneakCall<SneakHelper::hash("ZwCreateKeyTransacted"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG, IN PUNICODE_STRING  OPTIONAL, IN ULONG, IN HANDLE, OUT PULONG  OPTIONAL> NtCreateKeyTransacted;
typedef SneakCall<SneakHelper::hash("ZwCreateKeyedEvent"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN ULONG> NtCreateKeyedEvent;
typedef SneakCall<SneakHelper::hash("ZwCreateLowBoxToken"), OUT PHANDLE, IN HANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN PSID, IN ULONG, IN PSID_AND_ATTRIBUTES  OPTIONAL, IN ULONG, IN HANDLE  OPTIONAL> NtCreateLowBoxToken;
typedef SneakCall<SneakHelper::hash("ZwCreateMailslotFile"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, OUT PIO_STATUS_BLOCK, IN ULONG, IN ULONG, IN ULONG, IN PLARGE_INTEGER> NtCreateMailslotFile;
typedef SneakCall<SneakHelper::hash("ZwCreateMutant"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN BOOLEAN> NtCreateMutant;
typedef SneakCall<SneakHelper::hash("ZwCreateNamedPipeFile"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, OUT PIO_STATUS_BLOCK, IN ULONG, IN ULONG, IN ULONG, IN BOOLEAN, IN BOOLEAN, IN BOOLEAN, IN ULONG, IN ULONG, IN ULONG, IN PLARGE_INTEGER  OPTIONAL> NtCreateNamedPipeFile;
typedef SneakCall<SneakHelper::hash("ZwCreatePagingFile"), IN PUNICODE_STRING, IN PULARGE_INTEGER, IN PULARGE_INTEGER, IN ULONG> NtCreatePagingFile;
typedef SneakCall<SneakHelper::hash("ZwCreatePartition"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN ULONG> NtCreatePartition;
typedef SneakCall<SneakHelper::hash("ZwCreatePort"), OUT PHANDLE, IN POBJECT_ATTRIBUTES  OPTIONAL, IN ULONG, IN ULONG, IN ULONG  OPTIONAL> NtCreatePort;
typedef SneakCall<SneakHelper::hash("ZwCreatePrivateNamespace"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN PVOID> NtCreatePrivateNamespace;
typedef SneakCall<SneakHelper::hash("ZwCreateProcess"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN HANDLE, IN BOOLEAN, IN HANDLE  OPTIONAL, IN HANDLE  OPTIONAL, IN HANDLE  OPTIONAL> NtCreateProcess;
typedef SneakCall<SneakHelper::hash("ZwCreateProfile"), OUT PHANDLE, IN HANDLE  OPTIONAL, IN PVOID, IN ULONG, IN ULONG, IN PULONG, IN ULONG, IN KPROFILE_SOURCE, IN ULONG> NtCreateProfile;
typedef SneakCall<SneakHelper::hash("ZwCreateProfileEx"), OUT PHANDLE, IN HANDLE  OPTIONAL, IN PVOID, IN SIZE_T, IN ULONG, IN PULONG, IN ULONG, IN KPROFILE_SOURCE, IN USHORT, IN PGROUP_AFFINITY> NtCreateProfileEx;
typedef SneakCall<SneakHelper::hash("ZwCreateRegistryTransaction"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN DWORD> NtCreateRegistryTransaction;
typedef SneakCall<SneakHelper::hash("ZwCreateResourceManager"), OUT PHANDLE, IN ACCESS_MASK, IN HANDLE, IN LPGUID, IN POBJECT_ATTRIBUTES  OPTIONAL, IN ULONG  OPTIONAL, IN PUNICODE_STRING  OPTIONAL> NtCreateResourceManager;
typedef SneakCall<SneakHelper::hash("ZwCreateSemaphore"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN LONG, IN LONG> NtCreateSemaphore;
typedef SneakCall<SneakHelper::hash("ZwCreateSymbolicLinkObject"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN PUNICODE_STRING> NtCreateSymbolicLinkObject;
typedef SneakCall<SneakHelper::hash("ZwCreateThreadEx"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN HANDLE, IN PVOID, IN PVOID  OPTIONAL, IN ULONG, IN SIZE_T, IN SIZE_T, IN SIZE_T, IN PPS_ATTRIBUTE_LIST  OPTIONAL> NtCreateThreadEx;
typedef SneakCall<SneakHelper::hash("ZwCreateTimer"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN TIMER_TYPE> NtCreateTimer;
typedef SneakCall<SneakHelper::hash("ZwCreateTimer2"), OUT PHANDLE, IN PVOID  OPTIONAL, IN PVOID  OPTIONAL, IN ULONG, IN ACCESS_MASK> NtCreateTimer2;
typedef SneakCall<SneakHelper::hash("ZwCreateToken"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN TOKEN_TYPE, IN PLUID, IN PLARGE_INTEGER, IN PTOKEN_USER, IN PTOKEN_GROUPS, IN PTOKEN_PRIVILEGES, IN PTOKEN_OWNER  OPTIONAL, IN PTOKEN_PRIMARY_GROUP, IN PTOKEN_DEFAULT_DACL  OPTIONAL, IN PTOKEN_SOURCE> NtCreateToken;
typedef SneakCall<SneakHelper::hash("ZwCreateTokenEx"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN TOKEN_TYPE, IN PLUID, IN PLARGE_INTEGER, IN PTOKEN_USER, IN PTOKEN_GROUPS, IN PTOKEN_PRIVILEGES, IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  OPTIONAL, IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  OPTIONAL, IN PTOKEN_GROUPS  OPTIONAL, IN PTOKEN_MANDATORY_POLICY  OPTIONAL, IN PTOKEN_OWNER  OPTIONAL, IN PTOKEN_PRIMARY_GROUP, IN PTOKEN_DEFAULT_DACL  OPTIONAL, IN PTOKEN_SOURCE> NtCreateTokenEx;
typedef SneakCall<SneakHelper::hash("ZwCreateTransaction"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN LPGUID  OPTIONAL, IN HANDLE  OPTIONAL, IN ULONG  OPTIONAL, IN ULONG  OPTIONAL, IN ULONG  OPTIONAL, IN PLARGE_INTEGER  OPTIONAL, IN PUNICODE_STRING  OPTIONAL> NtCreateTransaction;
typedef SneakCall<SneakHelper::hash("ZwCreateTransactionManager"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN PUNICODE_STRING  OPTIONAL, IN ULONG  OPTIONAL, IN ULONG  OPTIONAL> NtCreateTransactionManager;
typedef SneakCall<SneakHelper::hash("ZwCreateUserProcess"), OUT PHANDLE, OUT PHANDLE, IN ACCESS_MASK, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN POBJECT_ATTRIBUTES  OPTIONAL, IN ULONG, IN ULONG, IN PVOID  OPTIONAL, IN OUT PPS_CREATE_INFO, IN PPS_ATTRIBUTE_LIST  OPTIONAL> NtCreateUserProcess;
typedef SneakCall<SneakHelper::hash("ZwCreateWaitCompletionPacket"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL> NtCreateWaitCompletionPacket;
typedef SneakCall<SneakHelper::hash("ZwCreateWaitablePort"), OUT PHANDLE, IN POBJECT_ATTRIBUTES  OPTIONAL, IN ULONG, IN ULONG, IN ULONG  OPTIONAL> NtCreateWaitablePort;
typedef SneakCall<SneakHelper::hash("ZwCreateWnfStateName"), OUT PCWNF_STATE_NAME, IN WNF_STATE_NAME_LIFETIME, IN WNF_DATA_SCOPE, IN BOOLEAN, IN PCWNF_TYPE_ID  OPTIONAL, IN ULONG, IN PSECURITY_DESCRIPTOR> NtCreateWnfStateName;
typedef SneakCall<SneakHelper::hash("ZwCreateWorkerFactory"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN HANDLE, IN HANDLE, IN PVOID, IN PVOID  OPTIONAL, IN ULONG  OPTIONAL, IN SIZE_T  OPTIONAL, IN SIZE_T  OPTIONAL> NtCreateWorkerFactory;
typedef SneakCall<SneakHelper::hash("ZwDebugActiveProcess"), IN HANDLE, IN HANDLE> NtDebugActiveProcess;
typedef SneakCall<SneakHelper::hash("ZwDebugContinue"), IN HANDLE, IN PCLIENT_ID, IN NTSTATUS> NtDebugContinue;
typedef SneakCall<SneakHelper::hash("ZwDeleteAtom"), IN USHORT> NtDeleteAtom;
typedef SneakCall<SneakHelper::hash("ZwDeleteBootEntry"), IN ULONG> NtDeleteBootEntry;
typedef SneakCall<SneakHelper::hash("ZwDeleteDriverEntry"), IN ULONG> NtDeleteDriverEntry;
typedef SneakCall<SneakHelper::hash("ZwDeleteFile"), IN POBJECT_ATTRIBUTES> NtDeleteFile;
typedef SneakCall<SneakHelper::hash("ZwDeleteKey"), IN HANDLE> NtDeleteKey;
typedef SneakCall<SneakHelper::hash("ZwDeleteObjectAuditAlarm"), IN PUNICODE_STRING, IN PVOID  OPTIONAL, IN BOOLEAN> NtDeleteObjectAuditAlarm;
typedef SneakCall<SneakHelper::hash("ZwDeletePrivateNamespace"), IN HANDLE> NtDeletePrivateNamespace;
typedef SneakCall<SneakHelper::hash("ZwDeleteValueKey"), IN HANDLE, IN PUNICODE_STRING> NtDeleteValueKey;
typedef SneakCall<SneakHelper::hash("ZwDeleteWnfStateData"), IN PCWNF_STATE_NAME, IN PVOID  OPTIONAL> NtDeleteWnfStateData;
typedef SneakCall<SneakHelper::hash("ZwDeleteWnfStateName"), IN PCWNF_STATE_NAME> NtDeleteWnfStateName;
typedef SneakCall<SneakHelper::hash("ZwDisableLastKnownGood")> NtDisableLastKnownGood;
typedef SneakCall<SneakHelper::hash("ZwDisplayString"), IN PUNICODE_STRING> NtDisplayString;
typedef SneakCall<SneakHelper::hash("ZwDrawText"), IN PUNICODE_STRING> NtDrawText;
typedef SneakCall<SneakHelper::hash("ZwEnableLastKnownGood")> NtEnableLastKnownGood;
typedef SneakCall<SneakHelper::hash("ZwEnumerateBootEntries"), OUT PVOID  OPTIONAL, IN OUT PULONG> NtEnumerateBootEntries;
typedef SneakCall<SneakHelper::hash("ZwEnumerateDriverEntries"), OUT PVOID  OPTIONAL, IN OUT PULONG> NtEnumerateDriverEntries;
typedef SneakCall<SneakHelper::hash("ZwEnumerateSystemEnvironmentValuesEx"), IN ULONG, OUT PVOID, IN OUT PULONG> NtEnumerateSystemEnvironmentValuesEx;
typedef SneakCall<SneakHelper::hash("ZwEnumerateTransactionObject"), IN HANDLE  OPTIONAL, IN KTMOBJECT_TYPE, IN OUT PKTMOBJECT_CURSOR, IN ULONG, OUT PULONG> NtEnumerateTransactionObject;
typedef SneakCall<SneakHelper::hash("ZwExtendSection"), IN HANDLE, IN OUT PLARGE_INTEGER> NtExtendSection;
typedef SneakCall<SneakHelper::hash("ZwFilterBootOption"), IN FILTER_BOOT_OPTION_OPERATION, IN ULONG, IN ULONG, IN PVOID  OPTIONAL, IN ULONG> NtFilterBootOption;
typedef SneakCall<SneakHelper::hash("ZwFilterToken"), IN HANDLE, IN ULONG, IN PTOKEN_GROUPS  OPTIONAL, IN PTOKEN_PRIVILEGES  OPTIONAL, IN PTOKEN_GROUPS  OPTIONAL, OUT PHANDLE> NtFilterToken;
typedef SneakCall<SneakHelper::hash("ZwFilterTokenEx"), IN HANDLE, IN ULONG, IN PTOKEN_GROUPS  OPTIONAL, IN PTOKEN_PRIVILEGES  OPTIONAL, IN PTOKEN_GROUPS  OPTIONAL, IN ULONG, IN PUNICODE_STRING  OPTIONAL, IN ULONG, IN PUNICODE_STRING  OPTIONAL, IN PTOKEN_GROUPS  OPTIONAL, IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  OPTIONAL, IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  OPTIONAL, IN PTOKEN_GROUPS  OPTIONAL, OUT PHANDLE> NtFilterTokenEx;
typedef SneakCall<SneakHelper::hash("ZwFlushBuffersFileEx"), IN HANDLE, IN ULONG, IN PVOID, IN ULONG, OUT PIO_STATUS_BLOCK> NtFlushBuffersFileEx;
typedef SneakCall<SneakHelper::hash("ZwFlushInstallUILanguage"), IN LANGID, IN ULONG> NtFlushInstallUILanguage;
typedef SneakCall<SneakHelper::hash("ZwFlushInstructionCache"), IN HANDLE, IN PVOID  OPTIONAL, IN ULONG> NtFlushInstructionCache;
typedef SneakCall<SneakHelper::hash("ZwFlushKey"), IN HANDLE> NtFlushKey;
typedef SneakCall<SneakHelper::hash("ZwFlushProcessWriteBuffers")> NtFlushProcessWriteBuffers;
typedef SneakCall<SneakHelper::hash("ZwFlushVirtualMemory"), IN HANDLE, IN OUT PVOID, IN OUT PULONG, OUT PIO_STATUS_BLOCK> NtFlushVirtualMemory;
typedef SneakCall<SneakHelper::hash("ZwFlushWriteBuffer")> NtFlushWriteBuffer;
typedef SneakCall<SneakHelper::hash("ZwFreeUserPhysicalPages"), IN HANDLE, IN OUT PULONG, IN PULONG> NtFreeUserPhysicalPages;
typedef SneakCall<SneakHelper::hash("ZwFreezeRegistry"), IN ULONG> NtFreezeRegistry;
typedef SneakCall<SneakHelper::hash("ZwFreezeTransactions"), IN PLARGE_INTEGER, IN PLARGE_INTEGER> NtFreezeTransactions;
typedef SneakCall<SneakHelper::hash("ZwGetCachedSigningLevel"), IN HANDLE, OUT PULONG, OUT PSE_SIGNING_LEVEL, OUT PUCHAR  OPTIONAL, IN OUT PULONG  OPTIONAL, OUT PULONG  OPTIONAL> NtGetCachedSigningLevel;
typedef SneakCall<SneakHelper::hash("ZwGetCompleteWnfStateSubscription"), IN PCWNF_STATE_NAME  OPTIONAL, IN PLARGE_INTEGER  OPTIONAL, IN ULONG  OPTIONAL, IN ULONG  OPTIONAL, OUT PWNF_DELIVERY_DESCRIPTOR, IN ULONG> NtGetCompleteWnfStateSubscription;
typedef SneakCall<SneakHelper::hash("ZwGetContextThread"), IN HANDLE, IN OUT PCONTEXT> NtGetContextThread;
typedef SneakCall<SneakHelper::hash("ZwGetCurrentProcessorNumber")> NtGetCurrentProcessorNumber;
typedef SneakCall<SneakHelper::hash("ZwGetCurrentProcessorNumberEx"), OUT PULONG  OPTIONAL> NtGetCurrentProcessorNumberEx;
typedef SneakCall<SneakHelper::hash("ZwGetDevicePowerState"), IN HANDLE, OUT PDEVICE_POWER_STATE> NtGetDevicePowerState;
typedef SneakCall<SneakHelper::hash("ZwGetMUIRegistryInfo"), IN ULONG, IN OUT PULONG, OUT PVOID> NtGetMUIRegistryInfo;
typedef SneakCall<SneakHelper::hash("ZwGetNextProcess"), IN HANDLE, IN ACCESS_MASK, IN ULONG, IN ULONG, OUT PHANDLE> NtGetNextProcess;
typedef SneakCall<SneakHelper::hash("ZwGetNextThread"), IN HANDLE, IN HANDLE, IN ACCESS_MASK, IN ULONG, IN ULONG, OUT PHANDLE> NtGetNextThread;
typedef SneakCall<SneakHelper::hash("ZwGetNlsSectionPtr"), IN ULONG, IN ULONG, IN PVOID, OUT PVOID, OUT PULONG> NtGetNlsSectionPtr;
typedef SneakCall<SneakHelper::hash("ZwGetNotificationResourceManager"), IN HANDLE, OUT PTRANSACTION_NOTIFICATION, IN ULONG, IN PLARGE_INTEGER  OPTIONAL, OUT PULONG  OPTIONAL, IN ULONG, IN ULONG  OPTIONAL> NtGetNotificationResourceManager;
typedef SneakCall<SneakHelper::hash("ZwGetWriteWatch"), IN HANDLE, IN ULONG, IN PVOID, IN ULONG, OUT PULONG, IN OUT PULONG, OUT PULONG> NtGetWriteWatch;
typedef SneakCall<SneakHelper::hash("ZwImpersonateAnonymousToken"), IN HANDLE> NtImpersonateAnonymousToken;
typedef SneakCall<SneakHelper::hash("ZwImpersonateThread"), IN HANDLE, IN HANDLE, IN PSECURITY_QUALITY_OF_SERVICE> NtImpersonateThread;
typedef SneakCall<SneakHelper::hash("ZwInitializeEnclave"), IN HANDLE, IN PVOID, IN PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtInitializeEnclave;
typedef SneakCall<SneakHelper::hash("ZwInitializeNlsFiles"), OUT PVOID, OUT PLCID, OUT PLARGE_INTEGER> NtInitializeNlsFiles;
typedef SneakCall<SneakHelper::hash("ZwInitializeRegistry"), IN USHORT> NtInitializeRegistry;
typedef SneakCall<SneakHelper::hash("ZwInitiatePowerAction"), IN POWER_ACTION, IN SYSTEM_POWER_STATE, IN ULONG, IN BOOLEAN> NtInitiatePowerAction;
typedef SneakCall<SneakHelper::hash("ZwIsSystemResumeAutomatic")> NtIsSystemResumeAutomatic;
typedef SneakCall<SneakHelper::hash("ZwIsUILanguageComitted")> NtIsUILanguageComitted;
typedef SneakCall<SneakHelper::hash("ZwListenPort"), IN HANDLE, OUT PPORT_MESSAGE> NtListenPort;
typedef SneakCall<SneakHelper::hash("ZwLoadDriver"), IN PUNICODE_STRING> NtLoadDriver;
typedef SneakCall<SneakHelper::hash("ZwLoadEnclaveData"), IN HANDLE, IN PVOID, IN PVOID, IN SIZE_T, IN ULONG, IN PVOID, IN ULONG, OUT PSIZE_T  OPTIONAL, OUT PULONG  OPTIONAL> NtLoadEnclaveData;
typedef SneakCall<SneakHelper::hash("ZwLoadHotPatch"), IN PUNICODE_STRING, IN ULONG> NtLoadHotPatch;
typedef SneakCall<SneakHelper::hash("ZwLoadKey"), IN POBJECT_ATTRIBUTES, IN POBJECT_ATTRIBUTES> NtLoadKey;
typedef SneakCall<SneakHelper::hash("ZwLoadKey2"), IN POBJECT_ATTRIBUTES, IN POBJECT_ATTRIBUTES, IN ULONG> NtLoadKey2;
typedef SneakCall<SneakHelper::hash("ZwLoadKeyEx"), IN POBJECT_ATTRIBUTES, IN POBJECT_ATTRIBUTES, IN ULONG, IN HANDLE  OPTIONAL, IN HANDLE  OPTIONAL, IN ACCESS_MASK  OPTIONAL, OUT PHANDLE  OPTIONAL, OUT PIO_STATUS_BLOCK  OPTIONAL> NtLoadKeyEx;
typedef SneakCall<SneakHelper::hash("ZwLockFile"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, IN PULARGE_INTEGER, IN PULARGE_INTEGER, IN ULONG, IN BOOLEAN, IN BOOLEAN> NtLockFile;
typedef SneakCall<SneakHelper::hash("ZwLockProductActivationKeys"), IN OUT PULONG  OPTIONAL, OUT PULONG  OPTIONAL> NtLockProductActivationKeys;
typedef SneakCall<SneakHelper::hash("ZwLockRegistryKey"), IN HANDLE> NtLockRegistryKey;
typedef SneakCall<SneakHelper::hash("ZwLockVirtualMemory"), IN HANDLE, IN PVOID, IN PULONG, IN ULONG> NtLockVirtualMemory;
typedef SneakCall<SneakHelper::hash("ZwMakePermanentObject"), IN HANDLE> NtMakePermanentObject;
typedef SneakCall<SneakHelper::hash("ZwMakeTemporaryObject"), IN HANDLE> NtMakeTemporaryObject;
typedef SneakCall<SneakHelper::hash("ZwManagePartition"), IN HANDLE, IN HANDLE, IN MEMORY_PARTITION_INFORMATION_CLASS, IN OUT PVOID, IN ULONG> NtManagePartition;
typedef SneakCall<SneakHelper::hash("ZwMapCMFModule"), IN ULONG, IN ULONG, OUT PULONG  OPTIONAL, OUT PULONG  OPTIONAL, OUT PULONG  OPTIONAL, OUT PVOID  OPTIONAL> NtMapCMFModule;
typedef SneakCall<SneakHelper::hash("ZwMapUserPhysicalPages"), IN PVOID, IN PULONG, IN PULONG  OPTIONAL> NtMapUserPhysicalPages;
typedef SneakCall<SneakHelper::hash("ZwMapViewOfSectionEx"), IN HANDLE, IN HANDLE, IN OUT PLARGE_INTEGER, IN OUT PPVOID, IN OUT PSIZE_T, IN ULONG, IN ULONG, IN OUT PVOID  OPTIONAL, IN ULONG> NtMapViewOfSectionEx;
typedef SneakCall<SneakHelper::hash("ZwModifyBootEntry"), IN PBOOT_ENTRY> NtModifyBootEntry;
typedef SneakCall<SneakHelper::hash("ZwModifyDriverEntry"), IN PEFI_DRIVER_ENTRY> NtModifyDriverEntry;
typedef SneakCall<SneakHelper::hash("ZwNotifyChangeDirectoryFile"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, OUT PFILE_NOTIFY_INFORMATION, IN ULONG, IN ULONG, IN BOOLEAN> NtNotifyChangeDirectoryFile;
typedef SneakCall<SneakHelper::hash("ZwNotifyChangeDirectoryFileEx"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, OUT PVOID, IN ULONG, IN ULONG, IN BOOLEAN, IN DIRECTORY_NOTIFY_INFORMATION_CLASS  OPTIONAL> NtNotifyChangeDirectoryFileEx;
typedef SneakCall<SneakHelper::hash("ZwNotifyChangeKey"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, IN ULONG, IN BOOLEAN, OUT PVOID  OPTIONAL, IN ULONG, IN BOOLEAN> NtNotifyChangeKey;
typedef SneakCall<SneakHelper::hash("ZwNotifyChangeMultipleKeys"), IN HANDLE, IN ULONG  OPTIONAL, IN POBJECT_ATTRIBUTES  OPTIONAL, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, IN ULONG, IN BOOLEAN, OUT PVOID  OPTIONAL, IN ULONG, IN BOOLEAN> NtNotifyChangeMultipleKeys;
typedef SneakCall<SneakHelper::hash("ZwNotifyChangeSession"), IN HANDLE, IN ULONG, IN PLARGE_INTEGER, IN IO_SESSION_EVENT, IN IO_SESSION_STATE, IN IO_SESSION_STATE, IN PVOID  OPTIONAL, IN ULONG> NtNotifyChangeSession;
typedef SneakCall<SneakHelper::hash("ZwOpenEnlistment"), OUT PHANDLE, IN ACCESS_MASK, IN HANDLE, IN LPGUID, IN POBJECT_ATTRIBUTES  OPTIONAL> NtOpenEnlistment;
typedef SneakCall<SneakHelper::hash("ZwOpenEventPair"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenEventPair;
typedef SneakCall<SneakHelper::hash("ZwOpenIoCompletion"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenIoCompletion;
typedef SneakCall<SneakHelper::hash("ZwOpenJobObject"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenJobObject;
typedef SneakCall<SneakHelper::hash("ZwOpenKeyEx"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG> NtOpenKeyEx;
typedef SneakCall<SneakHelper::hash("ZwOpenKeyTransacted"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN HANDLE> NtOpenKeyTransacted;
typedef SneakCall<SneakHelper::hash("ZwOpenKeyTransactedEx"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG, IN HANDLE> NtOpenKeyTransactedEx;
typedef SneakCall<SneakHelper::hash("ZwOpenKeyedEvent"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenKeyedEvent;
typedef SneakCall<SneakHelper::hash("ZwOpenMutant"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenMutant;
typedef SneakCall<SneakHelper::hash("ZwOpenObjectAuditAlarm"), IN PUNICODE_STRING, IN PVOID  OPTIONAL, IN PUNICODE_STRING, IN PUNICODE_STRING, IN PSECURITY_DESCRIPTOR  OPTIONAL, IN HANDLE, IN ACCESS_MASK, IN ACCESS_MASK, IN PPRIVILEGE_SET  OPTIONAL, IN BOOLEAN, IN BOOLEAN, OUT PBOOLEAN> NtOpenObjectAuditAlarm;
typedef SneakCall<SneakHelper::hash("ZwOpenPartition"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenPartition;
typedef SneakCall<SneakHelper::hash("ZwOpenPrivateNamespace"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN PVOID> NtOpenPrivateNamespace;
typedef SneakCall<SneakHelper::hash("ZwOpenProcessToken"), IN HANDLE, IN ACCESS_MASK, OUT PHANDLE> NtOpenProcessToken;
typedef SneakCall<SneakHelper::hash("ZwOpenRegistryTransaction"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenRegistryTransaction;
typedef SneakCall<SneakHelper::hash("ZwOpenResourceManager"), OUT PHANDLE, IN ACCESS_MASK, IN HANDLE, IN LPGUID  OPTIONAL, IN POBJECT_ATTRIBUTES  OPTIONAL> NtOpenResourceManager;
typedef SneakCall<SneakHelper::hash("ZwOpenSemaphore"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenSemaphore;
typedef SneakCall<SneakHelper::hash("ZwOpenSession"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenSession;
typedef SneakCall<SneakHelper::hash("ZwOpenSymbolicLinkObject"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenSymbolicLinkObject;
typedef SneakCall<SneakHelper::hash("ZwOpenThread"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN PCLIENT_ID  OPTIONAL> NtOpenThread;
typedef SneakCall<SneakHelper::hash("ZwOpenTimer"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES> NtOpenTimer;
typedef SneakCall<SneakHelper::hash("ZwOpenTransaction"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN LPGUID, IN HANDLE  OPTIONAL> NtOpenTransaction;
typedef SneakCall<SneakHelper::hash("ZwOpenTransactionManager"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN PUNICODE_STRING  OPTIONAL, IN LPGUID  OPTIONAL, IN ULONG  OPTIONAL> NtOpenTransactionManager;
typedef SneakCall<SneakHelper::hash("ZwPlugPlayControl"), IN PLUGPLAY_CONTROL_CLASS, IN OUT PVOID, IN ULONG> NtPlugPlayControl;
typedef SneakCall<SneakHelper::hash("ZwPrePrepareComplete"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtPrePrepareComplete;
typedef SneakCall<SneakHelper::hash("ZwPrePrepareEnlistment"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtPrePrepareEnlistment;
typedef SneakCall<SneakHelper::hash("ZwPrepareComplete"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtPrepareComplete;
typedef SneakCall<SneakHelper::hash("ZwPrepareEnlistment"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtPrepareEnlistment;
typedef SneakCall<SneakHelper::hash("ZwPrivilegeCheck"), IN HANDLE, IN OUT PPRIVILEGE_SET, OUT PBOOLEAN> NtPrivilegeCheck;
typedef SneakCall<SneakHelper::hash("ZwPrivilegeObjectAuditAlarm"), IN PUNICODE_STRING, IN PVOID  OPTIONAL, IN HANDLE, IN ACCESS_MASK, IN PPRIVILEGE_SET, IN BOOLEAN> NtPrivilegeObjectAuditAlarm;
typedef SneakCall<SneakHelper::hash("ZwPrivilegedServiceAuditAlarm"), IN PUNICODE_STRING, IN PUNICODE_STRING, IN HANDLE, IN PPRIVILEGE_SET, IN BOOLEAN> NtPrivilegedServiceAuditAlarm;
typedef SneakCall<SneakHelper::hash("ZwPropagationComplete"), IN HANDLE, IN ULONG, IN ULONG, IN PVOID> NtPropagationComplete;
typedef SneakCall<SneakHelper::hash("ZwPropagationFailed"), IN HANDLE, IN ULONG, IN NTSTATUS> NtPropagationFailed;
typedef SneakCall<SneakHelper::hash("ZwPulseEvent"), IN HANDLE, OUT PULONG  OPTIONAL> NtPulseEvent;
typedef SneakCall<SneakHelper::hash("ZwQueryAuxiliaryCounterFrequency"), OUT PULONGLONG> NtQueryAuxiliaryCounterFrequency;
typedef SneakCall<SneakHelper::hash("ZwQueryBootEntryOrder"), OUT PULONG  OPTIONAL, IN OUT PULONG> NtQueryBootEntryOrder;
typedef SneakCall<SneakHelper::hash("ZwQueryBootOptions"), OUT PBOOT_OPTIONS  OPTIONAL, IN OUT PULONG> NtQueryBootOptions;
typedef SneakCall<SneakHelper::hash("ZwQueryDebugFilterState"), IN ULONG, IN ULONG> NtQueryDebugFilterState;
typedef SneakCall<SneakHelper::hash("ZwQueryDirectoryFileEx"), IN HANDLE, IN HANDLE  OPTIONAL, IN PIO_APC_ROUTINE  OPTIONAL, IN PVOID  OPTIONAL, OUT PIO_STATUS_BLOCK, OUT PVOID, IN ULONG, IN FILE_INFORMATION_CLASS, IN ULONG, IN PUNICODE_STRING  OPTIONAL> NtQueryDirectoryFileEx;
typedef SneakCall<SneakHelper::hash("ZwQueryDirectoryObject"), IN HANDLE, OUT PVOID  OPTIONAL, IN ULONG, IN BOOLEAN, IN BOOLEAN, IN OUT PULONG, OUT PULONG  OPTIONAL> NtQueryDirectoryObject;
typedef SneakCall<SneakHelper::hash("ZwQueryDriverEntryOrder"), IN PULONG  OPTIONAL, IN OUT PULONG> NtQueryDriverEntryOrder;
typedef SneakCall<SneakHelper::hash("ZwQueryEaFile"), IN HANDLE, OUT PIO_STATUS_BLOCK, OUT PFILE_FULL_EA_INFORMATION, IN ULONG, IN BOOLEAN, IN PFILE_GET_EA_INFORMATION  OPTIONAL, IN ULONG, IN PULONG  OPTIONAL, IN BOOLEAN> NtQueryEaFile;
typedef SneakCall<SneakHelper::hash("ZwQueryFullAttributesFile"), IN POBJECT_ATTRIBUTES, OUT PFILE_NETWORK_OPEN_INFORMATION> NtQueryFullAttributesFile;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationAtom"), IN USHORT, IN ATOM_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryInformationAtom;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationByName"), IN POBJECT_ATTRIBUTES, OUT PIO_STATUS_BLOCK, OUT PVOID, IN ULONG, IN FILE_INFORMATION_CLASS> NtQueryInformationByName;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationEnlistment"), IN HANDLE, IN ENLISTMENT_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryInformationEnlistment;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationJobObject"), IN HANDLE, IN JOBOBJECTINFOCLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryInformationJobObject;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationPort"), IN HANDLE, IN PORT_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryInformationPort;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationResourceManager"), IN HANDLE, IN RESOURCEMANAGER_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryInformationResourceManager;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationTransaction"), IN HANDLE, IN TRANSACTION_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryInformationTransaction;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationTransactionManager"), IN HANDLE, IN TRANSACTIONMANAGER_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryInformationTransactionManager;
typedef SneakCall<SneakHelper::hash("ZwQueryInformationWorkerFactory"), IN HANDLE, IN WORKERFACTORYINFOCLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryInformationWorkerFactory;
typedef SneakCall<SneakHelper::hash("ZwQueryInstallUILanguage"), OUT PLANGID> NtQueryInstallUILanguage;
typedef SneakCall<SneakHelper::hash("ZwQueryIntervalProfile"), IN KPROFILE_SOURCE, OUT PULONG> NtQueryIntervalProfile;
typedef SneakCall<SneakHelper::hash("ZwQueryIoCompletion"), IN HANDLE, IN IO_COMPLETION_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryIoCompletion;
typedef SneakCall<SneakHelper::hash("ZwQueryLicenseValue"), IN PUNICODE_STRING, OUT PULONG  OPTIONAL, OUT PVOID  OPTIONAL, IN ULONG, OUT PULONG> NtQueryLicenseValue;
typedef SneakCall<SneakHelper::hash("ZwQueryMultipleValueKey"), IN HANDLE, IN OUT PKEY_VALUE_ENTRY, IN ULONG, OUT PVOID, IN PULONG, OUT PULONG  OPTIONAL> NtQueryMultipleValueKey;
typedef SneakCall<SneakHelper::hash("ZwQueryMutant"), IN HANDLE, IN MUTANT_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQueryMutant;
typedef SneakCall<SneakHelper::hash("ZwQueryOpenSubKeys"), IN POBJECT_ATTRIBUTES, OUT PULONG> NtQueryOpenSubKeys;
typedef SneakCall<SneakHelper::hash("ZwQueryOpenSubKeysEx"), IN POBJECT_ATTRIBUTES, IN ULONG, OUT PVOID, OUT PULONG> NtQueryOpenSubKeysEx;
typedef SneakCall<SneakHelper::hash("ZwQueryPortInformationProcess")> NtQueryPortInformationProcess;
typedef SneakCall<SneakHelper::hash("ZwQueryQuotaInformationFile"), IN HANDLE, OUT PIO_STATUS_BLOCK, OUT PFILE_USER_QUOTA_INFORMATION, IN ULONG, IN BOOLEAN, IN PFILE_QUOTA_LIST_INFORMATION  OPTIONAL, IN ULONG, IN PSID  OPTIONAL, IN BOOLEAN> NtQueryQuotaInformationFile;
typedef SneakCall<SneakHelper::hash("ZwQuerySecurityAttributesToken"), IN HANDLE, IN PUNICODE_STRING  OPTIONAL, IN ULONG, OUT PVOID, IN ULONG, OUT PULONG> NtQuerySecurityAttributesToken;
typedef SneakCall<SneakHelper::hash("ZwQuerySecurityObject"), IN HANDLE, IN SECURITY_INFORMATION, OUT PSECURITY_DESCRIPTOR  OPTIONAL, IN ULONG, OUT PULONG> NtQuerySecurityObject;
typedef SneakCall<SneakHelper::hash("ZwQuerySecurityPolicy"), IN ULONG_PTR, IN ULONG_PTR, IN ULONG_PTR, IN ULONG_PTR, IN ULONG_PTR, IN ULONG_PTR> NtQuerySecurityPolicy;
typedef SneakCall<SneakHelper::hash("ZwQuerySemaphore"), IN HANDLE, IN SEMAPHORE_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQuerySemaphore;
typedef SneakCall<SneakHelper::hash("ZwQuerySymbolicLinkObject"), IN HANDLE, IN OUT PUNICODE_STRING, OUT PULONG  OPTIONAL> NtQuerySymbolicLinkObject;
typedef SneakCall<SneakHelper::hash("ZwQuerySystemEnvironmentValue"), IN PUNICODE_STRING, OUT PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtQuerySystemEnvironmentValue;
typedef SneakCall<SneakHelper::hash("ZwQuerySystemEnvironmentValueEx"), IN PUNICODE_STRING, IN LPGUID, OUT PVOID  OPTIONAL, IN OUT PULONG, OUT PULONG  OPTIONAL> NtQuerySystemEnvironmentValueEx;
typedef SneakCall<SneakHelper::hash("ZwQuerySystemInformationEx"), IN SYSTEM_INFORMATION_CLASS, IN PVOID, IN ULONG, OUT PVOID  OPTIONAL, IN ULONG, OUT PULONG  OPTIONAL> NtQuerySystemInformationEx;
typedef SneakCall<SneakHelper::hash("ZwQueryTimerResolution"), OUT PULONG, OUT PULONG, OUT PULONG> NtQueryTimerResolution;
typedef SneakCall<SneakHelper::hash("ZwQueryWnfStateData"), IN PCWNF_STATE_NAME, IN PCWNF_TYPE_ID  OPTIONAL, IN PVOID  OPTIONAL, OUT PWNF_CHANGE_STAMP, OUT PVOID  OPTIONAL, IN OUT PULONG> NtQueryWnfStateData;
typedef SneakCall<SneakHelper::hash("ZwQueryWnfStateNameInformation"), IN PCWNF_STATE_NAME, IN PCWNF_TYPE_ID, IN PVOID  OPTIONAL, OUT PVOID, IN ULONG> NtQueryWnfStateNameInformation;
typedef SneakCall<SneakHelper::hash("ZwQueueApcThreadEx"), IN HANDLE, IN HANDLE  OPTIONAL, IN PKNORMAL_ROUTINE, IN PVOID  OPTIONAL, IN PVOID  OPTIONAL, IN PVOID  OPTIONAL> NtQueueApcThreadEx;
typedef SneakCall<SneakHelper::hash("ZwRaiseException"), IN PEXCEPTION_RECORD, IN PCONTEXT, IN BOOLEAN> NtRaiseException;
typedef SneakCall<SneakHelper::hash("ZwRaiseHardError"), IN NTSTATUS, IN ULONG, IN ULONG, IN PULONG_PTR, IN ULONG, OUT PULONG> NtRaiseHardError;
typedef SneakCall<SneakHelper::hash("ZwReadOnlyEnlistment"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtReadOnlyEnlistment;
typedef SneakCall<SneakHelper::hash("ZwRecoverEnlistment"), IN HANDLE, IN PVOID  OPTIONAL> NtRecoverEnlistment;
typedef SneakCall<SneakHelper::hash("ZwRecoverResourceManager"), IN HANDLE> NtRecoverResourceManager;
typedef SneakCall<SneakHelper::hash("ZwRecoverTransactionManager"), IN HANDLE> NtRecoverTransactionManager;
typedef SneakCall<SneakHelper::hash("ZwRegisterProtocolAddressInformation"), IN HANDLE, IN LPGUID, IN ULONG, IN PVOID, IN ULONG  OPTIONAL> NtRegisterProtocolAddressInformation;
typedef SneakCall<SneakHelper::hash("ZwRegisterThreadTerminatePort"), IN HANDLE> NtRegisterThreadTerminatePort;
typedef SneakCall<SneakHelper::hash("ZwReleaseKeyedEvent"), IN HANDLE, IN PVOID, IN BOOLEAN, IN PLARGE_INTEGER  OPTIONAL> NtReleaseKeyedEvent;
typedef SneakCall<SneakHelper::hash("ZwReleaseWorkerFactoryWorker"), IN HANDLE> NtReleaseWorkerFactoryWorker;
typedef SneakCall<SneakHelper::hash("ZwRemoveIoCompletionEx"), IN HANDLE, OUT PFILE_IO_COMPLETION_INFORMATION, IN ULONG, OUT PULONG, IN PLARGE_INTEGER  OPTIONAL, IN BOOLEAN> NtRemoveIoCompletionEx;
typedef SneakCall<SneakHelper::hash("ZwRemoveProcessDebug"), IN HANDLE, IN HANDLE> NtRemoveProcessDebug;
typedef SneakCall<SneakHelper::hash("ZwRenameKey"), IN HANDLE, IN PUNICODE_STRING> NtRenameKey;
typedef SneakCall<SneakHelper::hash("ZwRenameTransactionManager"), IN PUNICODE_STRING, IN LPGUID> NtRenameTransactionManager;
typedef SneakCall<SneakHelper::hash("ZwReplaceKey"), IN POBJECT_ATTRIBUTES, IN HANDLE, IN POBJECT_ATTRIBUTES> NtReplaceKey;
typedef SneakCall<SneakHelper::hash("ZwReplacePartitionUnit"), IN PUNICODE_STRING, IN PUNICODE_STRING, IN ULONG> NtReplacePartitionUnit;
typedef SneakCall<SneakHelper::hash("ZwReplyWaitReplyPort"), IN HANDLE, IN OUT PPORT_MESSAGE> NtReplyWaitReplyPort;
typedef SneakCall<SneakHelper::hash("ZwRequestPort"), IN HANDLE, IN PPORT_MESSAGE> NtRequestPort;
typedef SneakCall<SneakHelper::hash("ZwResetEvent"), IN HANDLE, OUT PULONG  OPTIONAL> NtResetEvent;
typedef SneakCall<SneakHelper::hash("ZwResetWriteWatch"), IN HANDLE, IN PVOID, IN ULONG> NtResetWriteWatch;
typedef SneakCall<SneakHelper::hash("ZwRestoreKey"), IN HANDLE, IN HANDLE, IN ULONG> NtRestoreKey;
typedef SneakCall<SneakHelper::hash("ZwResumeProcess"), IN HANDLE> NtResumeProcess;
typedef SneakCall<SneakHelper::hash("ZwRevertContainerImpersonation")> NtRevertContainerImpersonation;
typedef SneakCall<SneakHelper::hash("ZwRollbackComplete"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtRollbackComplete;
typedef SneakCall<SneakHelper::hash("ZwRollbackEnlistment"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtRollbackEnlistment;
typedef SneakCall<SneakHelper::hash("ZwRollbackRegistryTransaction"), IN HANDLE, IN BOOL> NtRollbackRegistryTransaction;
typedef SneakCall<SneakHelper::hash("ZwRollbackTransaction"), IN HANDLE, IN BOOLEAN> NtRollbackTransaction;
typedef SneakCall<SneakHelper::hash("ZwRollforwardTransactionManager"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtRollforwardTransactionManager;
typedef SneakCall<SneakHelper::hash("ZwSaveKey"), IN HANDLE, IN HANDLE> NtSaveKey;
typedef SneakCall<SneakHelper::hash("ZwSaveKeyEx"), IN HANDLE, IN HANDLE, IN ULONG> NtSaveKeyEx;
typedef SneakCall<SneakHelper::hash("ZwSaveMergedKeys"), IN HANDLE, IN HANDLE, IN HANDLE> NtSaveMergedKeys;
typedef SneakCall<SneakHelper::hash("ZwSecureConnectPort"), OUT PHANDLE, IN PUNICODE_STRING, IN PSECURITY_QUALITY_OF_SERVICE, IN OUT PPORT_SECTION_WRITE  OPTIONAL, IN PSID  OPTIONAL, IN OUT PPORT_SECTION_READ  OPTIONAL, OUT PULONG  OPTIONAL, IN OUT PVOID  OPTIONAL, IN OUT PULONG  OPTIONAL> NtSecureConnectPort;
typedef SneakCall<SneakHelper::hash("ZwSerializeBoot")> NtSerializeBoot;
typedef SneakCall<SneakHelper::hash("ZwSetBootEntryOrder"), IN PULONG, IN ULONG> NtSetBootEntryOrder;
typedef SneakCall<SneakHelper::hash("ZwSetBootOptions"), IN PBOOT_OPTIONS, IN ULONG> NtSetBootOptions;
typedef SneakCall<SneakHelper::hash("ZwSetCachedSigningLevel"), IN ULONG, IN SE_SIGNING_LEVEL, IN PHANDLE, IN ULONG, IN HANDLE  OPTIONAL> NtSetCachedSigningLevel;
typedef SneakCall<SneakHelper::hash("ZwSetCachedSigningLevel2"), IN ULONG, IN ULONG, IN PHANDLE, IN ULONG, IN HANDLE  OPTIONAL, IN PVOID  OPTIONAL> NtSetCachedSigningLevel2;
typedef SneakCall<SneakHelper::hash("ZwSetContextThread"), IN HANDLE, IN PCONTEXT> NtSetContextThread;
typedef SneakCall<SneakHelper::hash("ZwSetDebugFilterState"), IN ULONG, IN ULONG, IN BOOLEAN> NtSetDebugFilterState;
typedef SneakCall<SneakHelper::hash("ZwSetDefaultHardErrorPort"), IN HANDLE> NtSetDefaultHardErrorPort;
typedef SneakCall<SneakHelper::hash("ZwSetDefaultLocale"), IN BOOLEAN, IN LCID> NtSetDefaultLocale;
typedef SneakCall<SneakHelper::hash("ZwSetDefaultUILanguage"), IN LANGID> NtSetDefaultUILanguage;
typedef SneakCall<SneakHelper::hash("ZwSetDriverEntryOrder"), IN PULONG, IN PULONG> NtSetDriverEntryOrder;
typedef SneakCall<SneakHelper::hash("ZwSetEaFile"), IN HANDLE, OUT PIO_STATUS_BLOCK, IN PFILE_FULL_EA_INFORMATION, IN ULONG> NtSetEaFile;
typedef SneakCall<SneakHelper::hash("ZwSetHighEventPair"), IN HANDLE> NtSetHighEventPair;
typedef SneakCall<SneakHelper::hash("ZwSetHighWaitLowEventPair"), IN HANDLE> NtSetHighWaitLowEventPair;
typedef SneakCall<SneakHelper::hash("ZwSetIRTimer"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtSetIRTimer;
typedef SneakCall<SneakHelper::hash("ZwSetInformationDebugObject"), IN HANDLE, IN DEBUGOBJECTINFOCLASS, IN PVOID, IN ULONG, OUT PULONG  OPTIONAL> NtSetInformationDebugObject;
typedef SneakCall<SneakHelper::hash("ZwSetInformationEnlistment"), IN HANDLE, IN ENLISTMENT_INFORMATION_CLASS, IN PVOID, IN ULONG> NtSetInformationEnlistment;
typedef SneakCall<SneakHelper::hash("ZwSetInformationJobObject"), IN HANDLE, IN JOBOBJECTINFOCLASS, IN PVOID, IN ULONG> NtSetInformationJobObject;
typedef SneakCall<SneakHelper::hash("ZwSetInformationKey"), IN HANDLE, IN KEY_SET_INFORMATION_CLASS, IN PVOID, IN ULONG> NtSetInformationKey;
typedef SneakCall<SneakHelper::hash("ZwSetInformationResourceManager"), IN HANDLE, IN RESOURCEMANAGER_INFORMATION_CLASS, IN PVOID, IN ULONG> NtSetInformationResourceManager;
typedef SneakCall<SneakHelper::hash("ZwSetInformationSymbolicLink"), IN HANDLE, IN ULONG, IN PVOID, IN ULONG> NtSetInformationSymbolicLink;
typedef SneakCall<SneakHelper::hash("ZwSetInformationToken"), IN HANDLE, IN TOKEN_INFORMATION_CLASS, IN PVOID, IN ULONG> NtSetInformationToken;
typedef SneakCall<SneakHelper::hash("ZwSetInformationTransaction"), IN HANDLE, IN TRANSACTIONMANAGER_INFORMATION_CLASS, IN PVOID, IN ULONG> NtSetInformationTransaction;
typedef SneakCall<SneakHelper::hash("ZwSetInformationTransactionManager"), IN HANDLE, IN TRANSACTION_INFORMATION_CLASS, IN PVOID, IN ULONG> NtSetInformationTransactionManager;
typedef SneakCall<SneakHelper::hash("ZwSetInformationVirtualMemory"), IN HANDLE, IN VIRTUAL_MEMORY_INFORMATION_CLASS, IN ULONG_PTR, IN PMEMORY_RANGE_ENTRY, IN PVOID, IN ULONG> NtSetInformationVirtualMemory;
typedef SneakCall<SneakHelper::hash("ZwSetInformationWorkerFactory"), IN HANDLE, IN WORKERFACTORYINFOCLASS, IN PVOID, IN ULONG> NtSetInformationWorkerFactory;
typedef SneakCall<SneakHelper::hash("ZwSetIntervalProfile"), IN ULONG, IN KPROFILE_SOURCE> NtSetIntervalProfile;
typedef SneakCall<SneakHelper::hash("ZwSetIoCompletion"), IN HANDLE, IN ULONG, OUT PIO_STATUS_BLOCK, IN NTSTATUS, IN ULONG> NtSetIoCompletion;
typedef SneakCall<SneakHelper::hash("ZwSetIoCompletionEx"), IN HANDLE, IN HANDLE, IN PVOID  OPTIONAL, IN PVOID  OPTIONAL, IN NTSTATUS, IN ULONG_PTR> NtSetIoCompletionEx;
typedef SneakCall<SneakHelper::hash("ZwSetLdtEntries"), IN ULONG, IN ULONG, IN ULONG, IN ULONG, IN ULONG, IN ULONG> NtSetLdtEntries;
typedef SneakCall<SneakHelper::hash("ZwSetLowEventPair"), IN HANDLE> NtSetLowEventPair;
typedef SneakCall<SneakHelper::hash("ZwSetLowWaitHighEventPair"), IN HANDLE> NtSetLowWaitHighEventPair;
typedef SneakCall<SneakHelper::hash("ZwSetQuotaInformationFile"), IN HANDLE, OUT PIO_STATUS_BLOCK, IN PFILE_USER_QUOTA_INFORMATION, IN ULONG> NtSetQuotaInformationFile;
typedef SneakCall<SneakHelper::hash("ZwSetSecurityObject"), IN HANDLE, IN SECURITY_INFORMATION, IN PSECURITY_DESCRIPTOR> NtSetSecurityObject;
typedef SneakCall<SneakHelper::hash("ZwSetSystemEnvironmentValue"), IN PUNICODE_STRING, IN PUNICODE_STRING> NtSetSystemEnvironmentValue;
typedef SneakCall<SneakHelper::hash("ZwSetSystemEnvironmentValueEx"), IN PUNICODE_STRING, IN LPGUID, IN PVOID  OPTIONAL, IN ULONG, IN ULONG> NtSetSystemEnvironmentValueEx;
typedef SneakCall<SneakHelper::hash("ZwSetSystemInformation"), IN SYSTEM_INFORMATION_CLASS, IN PVOID, IN ULONG> NtSetSystemInformation;
typedef SneakCall<SneakHelper::hash("ZwSetSystemPowerState"), IN POWER_ACTION, IN SYSTEM_POWER_STATE, IN ULONG> NtSetSystemPowerState;
typedef SneakCall<SneakHelper::hash("ZwSetSystemTime"), IN PLARGE_INTEGER, OUT PLARGE_INTEGER  OPTIONAL> NtSetSystemTime;
typedef SneakCall<SneakHelper::hash("ZwSetThreadExecutionState"), IN EXECUTION_STATE, OUT PEXECUTION_STATE> NtSetThreadExecutionState;
typedef SneakCall<SneakHelper::hash("ZwSetTimer2"), IN HANDLE, IN PLARGE_INTEGER, IN PLARGE_INTEGER  OPTIONAL, IN PT2_SET_PARAMETERS> NtSetTimer2;
typedef SneakCall<SneakHelper::hash("ZwSetTimerEx"), IN HANDLE, IN TIMER_SET_INFORMATION_CLASS, IN OUT PVOID  OPTIONAL, IN ULONG> NtSetTimerEx;
typedef SneakCall<SneakHelper::hash("ZwSetTimerResolution"), IN ULONG, IN BOOLEAN, OUT PULONG> NtSetTimerResolution;
typedef SneakCall<SneakHelper::hash("ZwSetUuidSeed"), IN PUCHAR> NtSetUuidSeed;
typedef SneakCall<SneakHelper::hash("ZwSetVolumeInformationFile"), IN HANDLE, OUT PIO_STATUS_BLOCK, IN PVOID, IN ULONG, IN FSINFOCLASS> NtSetVolumeInformationFile;
typedef SneakCall<SneakHelper::hash("ZwSetWnfProcessNotificationEvent"), IN HANDLE> NtSetWnfProcessNotificationEvent;
typedef SneakCall<SneakHelper::hash("ZwShutdownSystem"), IN SHUTDOWN_ACTION> NtShutdownSystem;
typedef SneakCall<SneakHelper::hash("ZwShutdownWorkerFactory"), IN HANDLE, IN OUT PLONG> NtShutdownWorkerFactory;
typedef SneakCall<SneakHelper::hash("ZwSignalAndWaitForSingleObject"), IN HANDLE, IN HANDLE, IN BOOLEAN, IN PLARGE_INTEGER  OPTIONAL> NtSignalAndWaitForSingleObject;
typedef SneakCall<SneakHelper::hash("ZwSinglePhaseReject"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtSinglePhaseReject;
typedef SneakCall<SneakHelper::hash("ZwStartProfile"), IN HANDLE> NtStartProfile;
typedef SneakCall<SneakHelper::hash("ZwStopProfile"), IN HANDLE> NtStopProfile;
typedef SneakCall<SneakHelper::hash("ZwSubscribeWnfStateChange"), IN PCWNF_STATE_NAME, IN WNF_CHANGE_STAMP  OPTIONAL, IN ULONG, OUT PLARGE_INTEGER  OPTIONAL> NtSubscribeWnfStateChange;
typedef SneakCall<SneakHelper::hash("ZwSuspendProcess"), IN HANDLE> NtSuspendProcess;
typedef SneakCall<SneakHelper::hash("ZwSuspendThread"), IN HANDLE, OUT PULONG> NtSuspendThread;
typedef SneakCall<SneakHelper::hash("ZwSystemDebugControl"), IN DEBUG_CONTROL_CODE, IN PVOID  OPTIONAL, IN ULONG, OUT PVOID  OPTIONAL, IN ULONG, OUT PULONG  OPTIONAL> NtSystemDebugControl;
typedef SneakCall<SneakHelper::hash("ZwTerminateEnclave"), IN PVOID, IN BOOLEAN> NtTerminateEnclave;
typedef SneakCall<SneakHelper::hash("ZwTerminateJobObject"), IN HANDLE, IN NTSTATUS> NtTerminateJobObject;
typedef SneakCall<SneakHelper::hash("ZwTestAlert")> NtTestAlert;
typedef SneakCall<SneakHelper::hash("ZwThawRegistry")> NtThawRegistry;
typedef SneakCall<SneakHelper::hash("ZwThawTransactions")> NtThawTransactions;
typedef SneakCall<SneakHelper::hash("ZwTraceControl"), IN ULONG, IN PVOID  OPTIONAL, IN ULONG, OUT PVOID  OPTIONAL, IN ULONG, OUT PULONG> NtTraceControl;
typedef SneakCall<SneakHelper::hash("ZwTranslateFilePath"), IN PFILE_PATH, IN ULONG, OUT PFILE_PATH  OPTIONAL, IN OUT PULONG  OPTIONAL> NtTranslateFilePath;
typedef SneakCall<SneakHelper::hash("ZwUmsThreadYield"), IN PVOID> NtUmsThreadYield;
typedef SneakCall<SneakHelper::hash("ZwUnloadDriver"), IN PUNICODE_STRING> NtUnloadDriver;
typedef SneakCall<SneakHelper::hash("ZwUnloadKey"), IN POBJECT_ATTRIBUTES> NtUnloadKey;
typedef SneakCall<SneakHelper::hash("ZwUnloadKey2"), IN POBJECT_ATTRIBUTES, IN ULONG> NtUnloadKey2;
typedef SneakCall<SneakHelper::hash("ZwUnloadKeyEx"), IN POBJECT_ATTRIBUTES, IN HANDLE  OPTIONAL> NtUnloadKeyEx;
typedef SneakCall<SneakHelper::hash("ZwUnlockFile"), IN HANDLE, OUT PIO_STATUS_BLOCK, IN PULARGE_INTEGER, IN PULARGE_INTEGER, IN ULONG> NtUnlockFile;
typedef SneakCall<SneakHelper::hash("ZwUnlockVirtualMemory"), IN HANDLE, IN PVOID *, IN PSIZE_T, IN ULONG> NtUnlockVirtualMemory;
typedef SneakCall<SneakHelper::hash("ZwUnmapViewOfSectionEx"), IN HANDLE, IN PVOID  OPTIONAL, IN ULONG> NtUnmapViewOfSectionEx;
typedef SneakCall<SneakHelper::hash("ZwUnsubscribeWnfStateChange"), IN PCWNF_STATE_NAME> NtUnsubscribeWnfStateChange;
typedef SneakCall<SneakHelper::hash("ZwUpdateWnfStateData"), IN PCWNF_STATE_NAME, IN PVOID  OPTIONAL, IN ULONG  OPTIONAL, IN PCWNF_TYPE_ID  OPTIONAL, IN PVOID  OPTIONAL, IN WNF_CHANGE_STAMP, IN ULONG> NtUpdateWnfStateData;
typedef SneakCall<SneakHelper::hash("ZwVdmControl"), IN VDMSERVICECLASS, IN OUT PVOID> NtVdmControl;
typedef SneakCall<SneakHelper::hash("ZwWaitForAlertByThreadId"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtWaitForAlertByThreadId;
typedef SneakCall<SneakHelper::hash("ZwWaitForDebugEvent"), IN HANDLE, IN BOOLEAN, IN PLARGE_INTEGER  OPTIONAL, OUT PVOID> NtWaitForDebugEvent;
typedef SneakCall<SneakHelper::hash("ZwWaitForKeyedEvent"), IN HANDLE, IN PVOID, IN BOOLEAN, IN PLARGE_INTEGER  OPTIONAL> NtWaitForKeyedEvent;
typedef SneakCall<SneakHelper::hash("ZwWaitForWorkViaWorkerFactory"), IN HANDLE, OUT PVOID> NtWaitForWorkViaWorkerFactory;
typedef SneakCall<SneakHelper::hash("ZwWaitHighEventPair"), IN HANDLE> NtWaitHighEventPair;
typedef SneakCall<SneakHelper::hash("ZwWaitLowEventPair"), IN HANDLE> NtWaitLowEventPair;
typedef SneakCall<SneakHelper::hash("ZwAcquireCMFViewOwnership"), OUT BOOLEAN, OUT BOOLEAN, IN BOOLEAN> NtAcquireCMFViewOwnership;
typedef SneakCall<SneakHelper::hash("ZwCancelDeviceWakeupRequest"), IN HANDLE> NtCancelDeviceWakeupRequest;
typedef SneakCall<SneakHelper::hash("ZwClearAllSavepointsTransaction"), IN HANDLE> NtClearAllSavepointsTransaction;
typedef SneakCall<SneakHelper::hash("ZwClearSavepointTransaction"), IN HANDLE, IN ULONG> NtClearSavepointTransaction;
typedef SneakCall<SneakHelper::hash("ZwRollbackSavepointTransaction"), IN HANDLE, IN ULONG> NtRollbackSavepointTransaction;
typedef SneakCall<SneakHelper::hash("ZwSavepointTransaction"), IN HANDLE, IN BOOLEAN, OUT ULONG> NtSavepointTransaction;
typedef SneakCall<SneakHelper::hash("ZwSavepointComplete"), IN HANDLE, IN PLARGE_INTEGER  OPTIONAL> NtSavepointComplete;
typedef SneakCall<SneakHelper::hash("ZwCreateSectionEx"), OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES  OPTIONAL, IN PLARGE_INTEGER  OPTIONAL, IN ULONG, IN ULONG, IN HANDLE  OPTIONAL, IN PMEM_EXTENDED_PARAMETER, IN ULONG> NtCreateSectionEx;
typedef SneakCall<SneakHelper::hash("ZwCreateCrossVmEvent")> NtCreateCrossVmEvent;
typedef SneakCall<SneakHelper::hash("ZwGetPlugPlayEvent"), IN HANDLE, IN PVOID  OPTIONAL, OUT PPLUGPLAY_EVENT_BLOCK, IN ULONG> NtGetPlugPlayEvent;
typedef SneakCall<SneakHelper::hash("ZwListTransactions")> NtListTransactions;
typedef SneakCall<SneakHelper::hash("ZwMarshallTransaction")> NtMarshallTransaction;
typedef SneakCall<SneakHelper::hash("ZwPullTransaction")> NtPullTransaction;
typedef SneakCall<SneakHelper::hash("ZwReleaseCMFViewOwnership")> NtReleaseCMFViewOwnership;
typedef SneakCall<SneakHelper::hash("ZwWaitForWnfNotifications")> NtWaitForWnfNotifications;
typedef SneakCall<SneakHelper::hash("ZwStartTm")> NtStartTm;
typedef SneakCall<SneakHelper::hash("ZwSetInformationProcess"), IN HANDLE, IN PROCESSINFOCLASS, IN PVOID, IN ULONG> NtSetInformationProcess;
typedef SneakCall<SneakHelper::hash("ZwRequestDeviceWakeup"), IN HANDLE> NtRequestDeviceWakeup;
typedef SneakCall<SneakHelper::hash("ZwRequestWakeupLatency"), IN ULONG> NtRequestWakeupLatency;
typedef SneakCall<SneakHelper::hash("ZwQuerySystemTime"), OUT PLARGE_INTEGER> NtQuerySystemTime;
typedef SneakCall<SneakHelper::hash("ZwManageHotPatch"), IN ULONG, IN ULONG, IN ULONG, IN ULONG> NtManageHotPatch;
typedef SneakCall<SneakHelper::hash("ZwContinueEx"), IN PCONTEXT, IN PKCONTINUE_ARGUMENT> NtContinueEx;