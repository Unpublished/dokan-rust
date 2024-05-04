#![cfg(windows)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![doc(html_root_url = "https://dokan-dev.github.io/dokan-rust-doc/html")]

//! Raw FFI bindings for [Dokan].
//!
//! For more information, refer to corresponding items in [Dokan's documentation].
//!
//! Consider using the high-level [`dokan`] crate.
//!
//! [Dokan]: https://github.com/dokan-dev/dokany
//! [Dokan's documentation]: https://dokan-dev.github.io/dokany-doc/html/
//! [`dokan`]: https://crates.io/crates/dokan

use std::ffi::c_void;

use libc::c_int;
use windows_sys::Win32::{
	Foundation::{BOOL, BOOLEAN, FILETIME, MAX_PATH, NTSTATUS, UNICODE_STRING},
	Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
	Storage::FileSystem::WIN32_FIND_DATAW,
};
use windows_sys::Win32::Foundation::HANDLE;

use win32::PWIN32_FIND_STREAM_DATA;

pub mod win32;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

pub const DOKAN_OPTION_DEBUG: u32 = 1 << 0;
pub const DOKAN_OPTION_STDERR: u32 = 1 << 1;
pub const DOKAN_OPTION_ALT_STREAM: u32 = 1 << 2;
pub const DOKAN_OPTION_WRITE_PROTECT: u32 = 1 << 3;
pub const DOKAN_OPTION_NETWORK: u32 = 1 << 4;
pub const DOKAN_OPTION_REMOVABLE: u32 = 1 << 5;
pub const DOKAN_OPTION_MOUNT_MANAGER: u32 = 1 << 6;
pub const DOKAN_OPTION_CURRENT_SESSION: u32 = 1 << 7;
pub const DOKAN_OPTION_FILELOCK_USER_MODE: u32 = 1 << 8;
pub const DOKAN_OPTION_CASE_SENSITIVE: u32 = 1 << 9;
pub const DOKAN_OPTION_ENABLE_UNMOUNT_NETWORK_DRIVE: u32 = 1 << 10;
pub const DOKAN_OPTION_DISPATCH_DRIVER_LOGS: u32 = 1 << 11;
pub const DOKAN_OPTION_ALLOW_IPC_BATCHING: u32 = 1 << 12;

pub type DOKAN_HANDLE = *mut libc::c_void;
pub type PDOKAN_HANDLE = *mut DOKAN_HANDLE;

pub const VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE: usize = 1024 * 16;

#[repr(C)]
#[derive(Debug)]
pub struct DOKAN_OPTIONS {
	pub Version: u16,
	pub SingleThread: BOOLEAN,
	pub Options: u32,
	pub GlobalContext: u64,
	pub MountPoint: *const u16,
	pub UNCName: *const u16,
	pub Timeout: u32,
	pub AllocationUnitSize: u32,
	pub SectorSize: u32,
	pub VolumeSecurityDescriptorLength: u32,
	pub VolumeSecurityDescriptor: [i8; VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE],
}

pub type PDOKAN_OPTIONS = *mut DOKAN_OPTIONS;

#[repr(C)]
#[derive(Debug)]
pub struct DOKAN_FILE_INFO {
	pub Context: u64,
	pub DokanContext: u64,
	pub DokanOptions: PDOKAN_OPTIONS,
	pub ProcessingContext: *mut c_void,
	pub ProcessId: u32,
	pub IsDirectory: u8,
	pub DeleteOnClose: u8,
	pub PagingIo: u8,
	pub SynchronousIo: u8,
	pub Nocache: u8,
	pub WriteToEndOfFile: u8,
}

pub type PDOKAN_FILE_INFO = *mut DOKAN_FILE_INFO;

pub type PFillFindData = unsafe extern "stdcall" fn(*mut WIN32_FIND_DATAW, PDOKAN_FILE_INFO) -> c_int;
pub type PFillFindStreamData = unsafe extern "stdcall" fn(PWIN32_FIND_STREAM_DATA, *mut c_void) -> BOOL;

#[repr(C)]
pub struct DOKAN_ACCESS_STATE {
	pub SecurityEvaluated: BOOLEAN,
	pub GenerateAudit: BOOLEAN,
	pub GenerateOnClose: BOOLEAN,
	pub AuditPrivileges: BOOLEAN,
	pub Flags: u32,
	pub RemainingDesiredAccess: u32,
	pub PreviouslyGrantedAccess: u32,
	pub OriginalDesiredAccess: u32,
	pub SecurityDescriptor: *mut c_void,
	pub ObjectName: UNICODE_STRING,
	pub ObjectType: UNICODE_STRING,
}

pub type PDOKAN_ACCESS_STATE = *mut DOKAN_ACCESS_STATE;

#[repr(C)]
pub struct DOKAN_IO_SECURITY_CONTEXT {
	pub AccessState: DOKAN_ACCESS_STATE,
	pub DesiredAccess: u32,
}

pub type PDOKAN_IO_SECURITY_CONTEXT = *mut DOKAN_IO_SECURITY_CONTEXT;

#[repr(C)]
#[derive(Clone)]
pub struct DOKAN_OPERATIONS {
	pub ZwCreateFile: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			SecurityContext: PDOKAN_IO_SECURITY_CONTEXT,
			DesiredAccess: u32,
			FileAttributes: u32,
			ShareAccess: u32,
			CreateDisposition: u32,
			CreateOptions: u32,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub Cleanup: Option<extern "stdcall" fn(FileName: *const u16, DokanFileInfo: PDOKAN_FILE_INFO)>,
	pub CloseFile: Option<extern "stdcall" fn(FileName: *const u16, DokanFileInfo: PDOKAN_FILE_INFO)>,
	pub ReadFile: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			Buffer: *mut c_void,
			BufferLength: u32,
			ReadLength: *mut u32,
			Offset: i64,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub WriteFile: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			Buffer: *const c_void,
			NumberOfBytesToWrite: u32,
			NumberOfBytesWritten: *mut u32,
			Offset: i64,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub FlushFileBuffers:
		Option<extern "stdcall" fn(FileName: *const u16, DokanFileInfo: PDOKAN_FILE_INFO) -> NTSTATUS>,
	pub GetFileInformation: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			Buffer: *mut BY_HANDLE_FILE_INFORMATION,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub FindFiles: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			FillFindData: PFillFindData,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub FindFilesWithPattern: Option<
		extern "stdcall" fn(
			PathName: *const u16,
			SearchPattern: *const u16,
			FillFindData: PFillFindData,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub SetFileAttributes: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			FileAttributes: u32,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub SetFileTime: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			creation_time: *const FILETIME,
			last_access_time: *const FILETIME,
			last_write_time: *const FILETIME,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub DeleteFile:
		Option<extern "stdcall" fn(FileName: *const u16, DokanFileInfo: PDOKAN_FILE_INFO) -> NTSTATUS>,
	pub DeleteDirectory:
		Option<extern "stdcall" fn(FileName: *const u16, DokanFileInfo: PDOKAN_FILE_INFO) -> NTSTATUS>,
	pub MoveFile: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			NewFileName: *const u16,
			ReplaceIfExisting: BOOL,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub SetEndOfFile: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			ByteOffset: i64,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub SetAllocationSize: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			AllocSize: i64,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub LockFile: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			ByteOffset: i64,
			Length: i64,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub UnlockFile: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			ByteOffset: i64,
			Length: i64,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub GetDiskFreeSpace: Option<
		extern "stdcall" fn(
			FreeBytesAvailable: *mut u64,
			TotalNumberOfBytes: *mut u64,
			TotalNumberOfFreeBytes: *mut u64,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub GetVolumeInformation: Option<
		extern "stdcall" fn(
			VolumeNameBuffer: *mut u16,
			VolumeNameSize: u32,
			VolumeSerialNumber: *mut u32,
			MaximumComponentLength: *mut u32,
			FileSystemFlags: *mut u32,
			FileSystemNameBuffer: *mut u16,
			FileSystemNameSize: u32,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub Mounted: Option<
		extern "stdcall" fn(MountPoint: *const u16, DokanFileInfo: PDOKAN_FILE_INFO) -> NTSTATUS,
	>,
	pub Unmounted: Option<extern "stdcall" fn(DokanFileInfo: PDOKAN_FILE_INFO) -> NTSTATUS>,
	pub GetFileSecurity: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			PSECURITY_INFORMATION: *mut u32,
			PSECURITY_DESCRIPTOR: *mut c_void,
			BufferLength: u32,
			LengthNeeded: *mut u32,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub SetFileSecurity: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			SecurityInformation: *mut u32,
			SecurityDescriptor: *mut c_void,
			BufferLength: u32,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub FindStreams: Option<
		extern "stdcall" fn(
			FileName: *const u16,
			FillFindStreamData: PFillFindStreamData,
			FindStreamContext: *mut c_void,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
}

pub type PDOKAN_OPERATIONS = *mut DOKAN_OPERATIONS;

pub const DOKAN_SUCCESS: c_int = 0;
pub const DOKAN_ERROR: c_int = -1;
pub const DOKAN_DRIVE_LETTER_ERROR: c_int = -2;
pub const DOKAN_DRIVER_INSTALL_ERROR: c_int = -3;
pub const DOKAN_START_ERROR: c_int = -4;
pub const DOKAN_MOUNT_ERROR: c_int = -5;
pub const DOKAN_MOUNT_POINT_ERROR: c_int = -6;
pub const DOKAN_VERSION_ERROR: c_int = -7;

#[repr(C)]
pub struct DOKAN_MOUNT_POINT_INFO {
	pub Type: u32,
	pub MountPoint: [u16; MAX_PATH as usize],
	pub UNCName: [u16; 64],
	pub DeviceName: [u16; 64],
	pub SessionId: u32,
	pub MountOptions: u32,
}

pub type PDOKAN_MOUNT_POINT_INFO = *mut DOKAN_MOUNT_POINT_INFO;

extern "stdcall" {
	pub fn DokanInit();
	pub fn DokanShutdown();
	pub fn DokanMain(DokanOptions: PDOKAN_OPTIONS, DokanOperations: PDOKAN_OPERATIONS) -> c_int;
	pub fn DokanCreateFileSystem(
		DokanOptions: PDOKAN_OPTIONS,
		DokanOperations: PDOKAN_OPERATIONS,
		DokanInstance: *mut DOKAN_HANDLE,
	) -> c_int;
	pub fn DokanIsFileSystemRunning(DokanInstance: DOKAN_HANDLE) -> BOOL;
	pub fn DokanWaitForFileSystemClosed(
		DokanInstance: DOKAN_HANDLE,
		dwMilliseconds: u32,
	) -> u32;
	pub fn DokanCloseHandle(DokanInstance: DOKAN_HANDLE);
	pub fn DokanUnmount(DriveLetter: u16) -> BOOL;
	pub fn DokanRemoveMountPoint(MountPoint: *const u16) -> BOOL;
	pub fn DokanIsNameInExpression(Expression: *const u16, Name: *const u16, IgnoreCase: BOOL) -> BOOL;
	pub fn DokanVersion() -> u32;
	pub fn DokanDriverVersion() -> u32;
	pub fn DokanResetTimeout(Timeout: u32, DokanFileInfo: PDOKAN_FILE_INFO) -> BOOL;
	pub fn DokanOpenRequestorToken(DokanFileInfo: PDOKAN_FILE_INFO) -> HANDLE;
	pub fn DokanGetMountPointList(uncOnly: BOOL, nbRead: *mut u32) -> PDOKAN_MOUNT_POINT_INFO;
	pub fn DokanReleaseMountPointList(list: PDOKAN_MOUNT_POINT_INFO);
	pub fn DokanMapKernelToUserCreateFileFlags(
		DesiredAccess: u32,
		FileAttributes: u32,
		CreateOptions: u32,
		CreateDisposition: u32,
		outDesiredAccess: *mut u32,
		outFileAttributesAndFlags: *mut u32,
		outCreationDisposition: *mut u32,
	);
	pub fn DokanNotifyCreate(
		DokanInstance: DOKAN_HANDLE,
		FilePath: *const u16,
		IsDirectory: BOOL,
	) -> BOOL;
	pub fn DokanNotifyDelete(
		DokanInstance: DOKAN_HANDLE,
		FilePath: *const u16,
		IsDirectory: BOOL,
	) -> BOOL;
	pub fn DokanNotifyUpdate(DokanInstance: DOKAN_HANDLE, FilePath: *const u16) -> BOOL;
	pub fn DokanNotifyXAttrUpdate(DokanInstance: DOKAN_HANDLE, FilePath: *const u16) -> BOOL;
	pub fn DokanNotifyRename(
		DokanInstance: DOKAN_HANDLE,
		OldPath: *const u16,
		NewPath: *const u16,
		IsDirectory: BOOL,
		IsInSameDirectory: BOOL,
	) -> BOOL;
	pub fn DokanNtStatusFromWin32(Error: u32) -> NTSTATUS;
	pub fn DokanUseStdErr(Status: BOOL);
	pub fn DokanDebugMode(Status: BOOL);
	pub fn DokanSetDebugMode(Status: BOOL) -> BOOL;
}
