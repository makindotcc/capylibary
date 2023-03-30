use capylibary::inject;
use clap::Parser;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use winapi::shared::minwindef::{DWORD, MAX_PATH};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, help = "Target process id or process name")]
    process: String,
    #[arg(short, long, help = "DLL path")]
    lib: String,
}

fn main() {
    match try_inject() {
        Ok(()) => {
            println!("Injected.");
        }
        Err(err) => {
            eprintln!("{err}");
        }
    }
}

fn try_inject() -> Result<(), String> {
    let args = Args::parse();
    let process_id = args
        .process
        .parse::<u32>()
        .ok()
        .or_else(|| find_process_by_name(&args.process))
        .ok_or_else(|| format!("Process '{}' not found", args.process))?;

    println!("Injecting to pid: {}", process_id);
    let inject_result = unsafe { inject(process_id, &args.lib) };
    if let Err(err) = inject_result {
        eprintln!("Injection failed: {:?}", err);
    }
    Ok(())
}

fn find_process_by_name(process_name: &str) -> Option<DWORD> {
    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot_handle.is_null() {
        return None;
    }
    let mut entry: PROCESSENTRY32W = PROCESSENTRY32W {
        dwSize: 0,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; MAX_PATH],
    };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    if unsafe { Process32FirstW(snapshot_handle, &mut entry) } != 0 {
        loop {
            if let Ok(process_id) = entry.th32ProcessID.try_into() {
                let name_len = entry
                    .szExeFile
                    .iter()
                    .position(|char| char == &0)
                    .unwrap_or(0);
                let other_process_name = OsString::from_wide(&entry.szExeFile[..name_len]);
                if process_name == other_process_name {
                    return Some(process_id);
                }
            }
            if unsafe { Process32NextW(snapshot_handle, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { winapi::um::handleapi::CloseHandle(snapshot_handle) };
    None
}
