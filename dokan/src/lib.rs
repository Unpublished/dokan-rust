#![cfg(windows)]
#![doc(html_root_url = "https://dokan-dev.github.io/dokan-rust-doc/html")]

//! [Dokan] is a user mode file system for Windows. It allows anyone to safely and easily develop
//! new file systems on Windows.
//!
//! This crate is a Rust-friendly wrapper for Dokan, allowing you to create file systems using Rust.
//! It builds upon the low-level [`dokan-sys`] crate.
//!
//! In general, to create a file system with this library, you need to implement the
//! [`FileSystemHandler`] trait, create a [`FileSystemMounter`], and [mount](FileSystemMounter::mount) it
//! to create a [`FileSystem`]. When dropped, the latter will block the current thread until it gets unmounted.
//! You have to call [`init`] once before, and [`shutdown`] when you're done.
//!
//! The same explanations with a few lines of code: see [the MemFS example](https://github.com/dokan-dev/dokan-rust/blob/master/dokan/examples/memfs/main.rs#L1330)!
//!
//! Please note that some of the constants from Win32 API that might be used when interacting with
//! this crate are not provided directly here. However, you can easily find them in the
//! [`winapi`] crate.
//!
//! [Dokan]: https://dokan-dev.github.io/
//! [`dokan-sys`]: https://crates.io/crates/dokan-sys
//! [`winapi`]: https://crates.io/crates/winapi

use widestring::U16CStr;
use windows_sys::Win32::{
	Foundation::{FALSE, GetLastError, NTSTATUS, TRUE},
	Storage::FileSystem::{FILE_ACCESS_RIGHTS, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES}
};

use dokan_sys::*;
/// Re-exported from `dokan-sys` for convenience.
pub use dokan_sys::{
	DOKAN_DRIVER_NAME as DRIVER_NAME, DOKAN_IO_SECURITY_CONTEXT as IO_SECURITY_CONTEXT,
	DOKAN_MAJOR_API_VERSION as MAJOR_API_VERSION, DOKAN_NP_NAME as NP_NAME,
	DOKAN_VERSION as WRAPPER_VERSION,
};

pub use crate::{data::*, file_system::*, file_system_handler::*, notify::*};

mod data;
mod file_system;
mod file_system_handler;
mod notify;
mod operations;
mod operations_helpers;
mod to_file_time;

#[cfg(test)]
mod usage_tests;

/// Initializes all required Dokan internal resources.
///
/// This needs to be called only once before trying to use other functions for the first time.
/// Otherwise they will fail and raise an exception.
pub fn init() {
	unsafe { DokanInit() }
}

/// Releases all allocated resources by [`init`] when they are no longer needed.
///
/// This should be called when the application no longer expects to create a new FileSystem and after all devices are unmount.
pub fn shutdown() {
	unsafe { DokanShutdown() }
}

/// Gets version of the loaded Dokan library.
///
/// The returned value is the version number without dots. For example, it returns `131` if Dokan
/// v1.3.1 is loaded.
pub fn get_lib_version() -> u32 {
	unsafe { DokanVersion() }
}

/// Gets version of the Dokan driver installed on the current system.
///
/// The returned value is the version number without dots.
pub fn get_driver_version() -> u32 {
	unsafe { DokanDriverVersion() }
}

#[test]
fn test_versions() {
	assert_eq!(MAJOR_API_VERSION, (get_lib_version() / 100).to_string());
	assert!(get_driver_version() < 1000);
	assert_eq!(DRIVER_NAME, format!("dokan{}.sys", MAJOR_API_VERSION));
	assert_eq!(NP_NAME, format!("Dokan{}", MAJOR_API_VERSION));
}

/// Checks whether the `name` matches the specified `expression`.
///
/// This is a helper function that can be used to implement
/// [`FileSystemHandler::find_files_with_pattern`]. It behaves like the [`FsRtlIsNameInExpression`]
/// routine provided for file system drivers by Windows.
///
/// [`FsRtlIsNameInExpression`]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-_fsrtl_advanced_fcb_header-fsrtlisnameinexpression
pub fn is_name_in_expression(
	expression: impl AsRef<U16CStr>,
	name: impl AsRef<U16CStr>,
	ignore_case: bool,
) -> bool {
	unsafe {
		DokanIsNameInExpression(
			expression.as_ref().as_ptr(),
			name.as_ref().as_ptr(),
			ignore_case.into(),
		) == TRUE
	}
}

#[test]
fn test_is_name_in_expression() {
	use usage_tests::convert_str;

	assert_eq!(
		is_name_in_expression(convert_str("foo"), convert_str("foo"), true),
		true
	);
	assert_eq!(
		is_name_in_expression(convert_str("*"), convert_str("foo"), true),
		true
	);
	assert_eq!(
		is_name_in_expression(convert_str("?"), convert_str("x"), true),
		true
	);
	assert_eq!(
		is_name_in_expression(convert_str("?"), convert_str("foo"), true),
		false
	);
	assert_eq!(
		is_name_in_expression(convert_str("F*"), convert_str("foo"), true),
		true
	);
	assert_eq!(
		is_name_in_expression(convert_str("F*"), convert_str("foo"), false),
		false
	);
}

/// Converts Win32 error (e.g. returned by [`GetLastError`]) to [`NTSTATUS`].
pub fn map_win32_error_to_ntstatus(error: u32) -> NTSTATUS {
	unsafe { DokanNtStatusFromWin32(error) }
}

#[test]
fn can_map_win32_error_to_ntstatus() {
	use windows_sys::Win32::Foundation::{ERROR_INTERNAL_ERROR, STATUS_INTERNAL_ERROR};

	assert_eq!(
		map_win32_error_to_ntstatus(ERROR_INTERNAL_ERROR),
		STATUS_INTERNAL_ERROR
	);
}

/// For convenience, returns an `Err(`[`NTSTATUS`]`)` from [`GetLastError`] if the condition is `false`.
///
/// It builds upon [`map_win32_error_to_ntstatus`].
///
/// **Warning**: success of some functions can only be known by checking `GetLastError`.
/// In such cases, **do not use this function!**
/// For instance, `ReadFile` and `WriteFile` in asynchronous mode are successful if they
/// return `FALSE` and `GetLastError` returns `ERROR_IO_PENDING`.
///
/// # Example
///
/// ```
/// # use std::ptr;
/// #
/// # use dokan::win32_ensure;
/// # use widestring::U16CString;
/// use windows_sys::Win32::{Foundation::NTSTATUS, System::Environment::GetCurrentDirectoryW };
/// #
/// fn get_current_directory() -> Result<U16CString, NTSTATUS> {
/// 	unsafe {
/// 		let len = GetCurrentDirectoryW(0, ptr::null_mut());
/// 		win32_ensure(len != 0)?;
///
/// 		let mut buffer = Vec::with_capacity(len as usize);
/// 		let actual_len = GetCurrentDirectoryW(len, buffer.as_mut_ptr());
/// 		win32_ensure(actual_len != 0)?;
/// 		assert_eq!(actual_len, len);
///
/// 		Ok(U16CString::from_vec_unchecked(buffer))
/// 	}
/// }
/// ```
pub fn win32_ensure(condition: bool) -> Result<(), NTSTATUS> {
	match condition {
		true => Ok(()),
		false => Err(map_win32_error_to_ntstatus(unsafe { GetLastError() })),
	}
}

/// Flags returned by [`map_kernel_to_user_create_file_flags`].
///
/// These flags are the same as those accepted by [`CreateFile`].
///
/// [`CreateFile`]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserCreateFileFlags {
	/// The requested access to the file.
	pub desired_access: FILE_ACCESS_RIGHTS,
	/// The file attributes and flags.
	pub flags_and_attributes: FILE_FLAGS_AND_ATTRIBUTES,
	/// The action to take on the file that exists or does not exist.
	pub creation_disposition: FILE_CREATION_DISPOSITION,
}

/// Converts the arguments passed to [`FileSystemHandler::create_file`] to flags accepted by the
/// Win32 [`CreateFile`] function.
///
/// Dokan forwards the parameters directly from [`IRP_MJ_CREATE`]. This functions converts them to
/// corresponding flags in Win32, making it easier to process them.
///
/// [`CreateFile`]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
/// [`IRP_MJ_CREATE`]: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create
pub fn map_kernel_to_user_create_file_flags(
	desired_access: FILE_ACCESS_RIGHTS,
	file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
	create_options: u32,
	create_disposition: FILE_CREATION_DISPOSITION,
) -> UserCreateFileFlags {
	let mut result = UserCreateFileFlags {
		desired_access: 0,
		flags_and_attributes: 0,
		creation_disposition: 0,
	};
	unsafe {
		DokanMapKernelToUserCreateFileFlags(
			desired_access,
			file_attributes,
			create_options,
			create_disposition,
			&mut result.desired_access,
			&mut result.flags_and_attributes,
			&mut result.creation_disposition,
		);
	}
	result
}

#[test]
fn test_map_kernel_to_user_create_file_flags() {
	use dokan_sys::win32::{FILE_OPEN, FILE_WRITE_THROUGH};
	use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
	use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_WRITE_THROUGH, OPEN_EXISTING};

	let result = map_kernel_to_user_create_file_flags(
		FILE_ALL_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		FILE_WRITE_THROUGH,
		FILE_OPEN,
	);
	assert_eq!(
		result.desired_access,
		GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL
	);
	assert_eq!(
		result.flags_and_attributes,
		FILE_FLAG_WRITE_THROUGH | FILE_ATTRIBUTE_NORMAL
	);
	assert_eq!(result.creation_disposition, OPEN_EXISTING);
}

/// Unmounts a Dokan volume from the specified mount point.
///
/// Returns whether it succeeded.
#[must_use]
pub fn unmount(mount_point: impl AsRef<U16CStr>) -> bool {
	unsafe { DokanRemoveMountPoint(mount_point.as_ref().as_ptr()) == TRUE }
}

/// Output stream to write debug messages to.
///
/// Used by [`set_debug_stream`].
pub enum DebugStream {
	/// The standard output stream.
	Stdout,
	/// The standard input stream.
	Stderr,
}

/// Sets the output stream to write debug messages to.
pub fn set_debug_stream(stream: DebugStream) {
	unsafe {
		DokanUseStdErr(if let DebugStream::Stdout = stream {
			TRUE
		} else {
			FALSE
		});
	}
}

/// Enables or disables debug mode of the user mode library.
pub fn set_lib_debug_mode(enabled: bool) {
	unsafe {
		DokanDebugMode(if enabled { TRUE } else { FALSE });
	}
}

/// Enables or disables debug mode of the kernel driver;
///
/// Returns `true` on success.
#[must_use]
pub fn set_driver_debug_mode(enabled: bool) -> bool {
	unsafe { DokanSetDebugMode(if enabled { TRUE } else { FALSE }) == TRUE }
}

#[test]
fn test_debug_mode() {
	set_debug_stream(DebugStream::Stdout);
	set_debug_stream(DebugStream::Stderr);
	set_lib_debug_mode(true);
	set_lib_debug_mode(false);
	assert!(set_driver_debug_mode(true));
	assert!(set_driver_debug_mode(false));
}
