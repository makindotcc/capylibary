use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::{intrinsics::transmute, iter, mem, ptr};

use winapi::um::winnt::ANSI_NULL;
use winapi::{
    shared::{minwindef::LPVOID, winerror::WAIT_TIMEOUT},
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        processthreadsapi::{CreateRemoteThread, OpenProcess},
        synchapi::WaitForSingleObject,
        winbase::{INFINITE, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0},
        winnt::{HANDLE, MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, PROCESS_ALL_ACCESS},
    },
};

#[cfg(not(target_os = "windows"))]
compile_error!("windows only");

pub unsafe fn inject(process_id: u32, path: &str) -> Result<(), LoadLibraryError> {
    const MAX_UNICODE_PATH: u16 = u16::MAX;
    let path = WString::from(path);
    if path.bytes_length() >= MAX_UNICODE_PATH as usize {
        return Err(LoadLibraryError::PathTooLong);
    }

    let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);
    if process_handle as usize == 0 {
        return Err(LoadLibraryError::OpenProcess {
            winapi_error: GetLastError(),
        });
    }

    let load_library_result = load_library(process_handle, &path);
    CloseHandle(process_handle);
    load_library_result
}

unsafe fn load_library(process_handle: HANDLE, path: &WString) -> Result<(), LoadLibraryError> {
    let path_address = VirtualAllocEx(
        process_handle,
        ptr::null_mut(),
        path.bytes_length(),
        MEM_COMMIT,
        PAGE_READWRITE,
    );
    if path_address as usize == 0 {
        return Err(LoadLibraryError::AllocMemory {
            winapi_error: GetLastError(),
        });
    }

    let result = load_library_allocated_arg(process_handle, path, path_address);
    if VirtualFreeEx(process_handle, path_address, 0, MEM_RELEASE) == 0 {
        return Err(LoadLibraryError::FreeArgumentMemory {
            winapi_error: GetLastError(),
        });
    }
    result
}

unsafe fn load_library_allocated_arg(
    process_handle: HANDLE,
    path: &WString,
    path_address: LPVOID,
) -> Result<(), LoadLibraryError> {
    let mut bytes_written: usize = 0;
    let write_arg_failed = WriteProcessMemory(
        process_handle,
        path_address,
        path.0.as_ptr() as _,
        path.bytes_length(),
        &mut bytes_written,
    ) == 0;
    if write_arg_failed {
        return Err(LoadLibraryError::WriteArg {
            winapi_error: GetLastError(),
        });
    }
    if bytes_written < path.bytes_length() {
        return Err(LoadLibraryError::NotEnoughBytesWritten {
            bytes_written: bytes_written as usize,
        });
    }

    let kernel32_handle = GetModuleHandleA("kernel32\0".as_ptr() as _);
    let load_libraryw_address = GetProcAddress(kernel32_handle, "LoadLibraryW\0".as_ptr() as _);

    let thread_handle = CreateRemoteThread(
        process_handle,
        ptr::null_mut(),
        0,
        Some(transmute(load_libraryw_address)),
        path_address,
        0,
        ptr::null_mut(),
    );
    let wait_result = WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
    match wait_result {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_ABANDONED => Err(LoadLibraryError::ThreadWaitAbandoned),
        WAIT_TIMEOUT => Err(LoadLibraryError::ThreadWaitTimeout),
        WAIT_FAILED => Err(LoadLibraryError::ThreadWaitFailed {
            winapi_error: GetLastError(),
        }),
        unknown => Err(LoadLibraryError::ThreadWaitUnknown {
            return_code: unknown,
        }),
    }
}

#[derive(Debug)]
struct WString(Vec<u16>);

impl WString {
    fn bytes_length(&self) -> usize {
        self.0.len() * mem::size_of::<u16>()
    }
}

impl From<&str> for WString {
    fn from(val: &str) -> Self {
        let path_wide = OsStr::new(val)
            .encode_wide()
            .chain(iter::once(ANSI_NULL as _))
            .collect::<Vec<_>>();
        Self(path_wide)
    }
}

#[derive(Debug)]
pub enum LoadLibraryError {
    PathTooLong,
    OpenProcess { winapi_error: u32 },
    AllocMemory { winapi_error: u32 },
    WriteArg { winapi_error: u32 },
    NotEnoughBytesWritten { bytes_written: usize },
    FreeArgumentMemory { winapi_error: u32 },
    ThreadWaitAbandoned,
    ThreadWaitTimeout,
    ThreadWaitFailed { winapi_error: u32 },
    ThreadWaitUnknown { return_code: u32 },
}
