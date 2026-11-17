//! Quarantined Darwin libSystem / libproc FFI bindings for zero-fork process and kernel telemetry.

use core::ffi::c_void;
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::ptr;

const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDTBSDINFO: i32 = 3;
const PROC_PIDTASKINFO: i32 = 4;
const BSD_INFO_SIZE: usize = 136;
const TASK_INFO_SIZE: usize = 96;

const CTL_KERN: i32 = 1;
const KERN_PROCARGS2: i32 = 49;

pub const PRIO_PROCESS: i32 = 0;
pub const PRIO_DARWIN_PROCESS: i32 = 4;
pub const PRIO_DARWIN_BG: i32 = 0x1000;
pub const SIGTERM: i32 = 15;
pub const SIGKILL: i32 = 9;

const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    fn proc_listpids(
        proc_type: u32,
        typeinfo: u32,
        buffer: *mut c_void,
        buffersize: i32,
    ) -> i32;
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut c_void,
        buffersize: i32,
    ) -> i32;
    fn sysctl(
        name: *mut i32,
        namelen: u32,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> i32;
    fn sysctlbyname(
        name: *const i8,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> i32;
    fn getloadavg(loadavg: *mut f64, nelem: i32) -> i32;
    fn getuid() -> u32;
    fn getpid() -> i32;
    fn setpriority(which: i32, who: u32, prio: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn flock(fd: i32, operation: i32) -> i32;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
}

#[derive(Debug, Clone)]
pub struct HostMetrics {
    pub ncpu: u32,
    pub mem_total_bytes: u64,
    pub vm_pressure_level: i32,
    pub load_1m: f64,
    pub load_5m: f64,
    pub load_15m: f64,
    pub total_pids: usize,
}

#[derive(Debug, Clone)]
pub struct ProcBasic {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub nice: i32,
    pub start_tvsec: u64,
    pub comm: String,
    pub name: String,
    pub rss_bytes: u64,
    pub cpu_total_ns: u64,
}

pub fn current_uid() -> u32 {
    // SAFETY: getuid() is thread-safe and takes no pointers.
    unsafe { getuid() }
}

pub fn current_pid() -> u32 {
    // SAFETY: getpid() is thread-safe and takes no pointers.
    unsafe { getpid() as u32 }
}

pub fn acquire_exclusive_flock(file: &File) -> bool {
    // SAFETY: file.as_raw_fd() is a valid open file descriptor owned by `file`.
    let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
    rc == 0
}

pub fn renice_process(pid: u32, nice_value: i32) -> bool {
    // SAFETY: setpriority on PRIO_PROCESS adjusts BSD nice value for target PID owned by current UID.
    unsafe { setpriority(PRIO_PROCESS, pid, nice_value) == 0 }
}

pub fn set_darwin_background_qos(pid: u32) -> bool {
    // SAFETY: setpriority with PRIO_DARWIN_PROCESS and PRIO_DARWIN_BG throttles CPU/GPU/IO QoS to Efficiency cores.
    unsafe { setpriority(PRIO_DARWIN_PROCESS, pid, PRIO_DARWIN_BG) == 0 }
}

pub fn send_process_signal(pid: u32, sig: i32) -> bool {
    if pid <= 1 {
        return false;
    }
    // SAFETY: kill sends a standard POSIX signal to a verified PID > 1.
    unsafe { kill(pid as i32, sig) == 0 }
}

fn ticks_to_nanos(ticks: u64) -> u64 {
    let mut info = MachTimebaseInfo { numer: 1, denom: 1 };
    // SAFETY: mach_timebase_info writes two u32 fields into stack-allocated `info`.
    let rc = unsafe { mach_timebase_info(&mut info as *mut MachTimebaseInfo) };
    if rc != 0 || info.denom == 0 {
        return ticks;
    }
    (ticks as u128 * info.numer as u128 / info.denom as u128) as u64
}

fn sysctl_u32(name: &str) -> Option<u32> {
    let c_name = CString::new(name).ok()?;
    let mut val: u32 = 0;
    let mut size = core::mem::size_of::<u32>();
    // SAFETY: `val` and `size` match exact 4-byte u32 sysctl output buffer.
    let rc = unsafe {
        sysctlbyname(
            c_name.as_ptr(),
            (&mut val as *mut u32).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if rc == 0 { Some(val) } else { None }
}

fn sysctl_i32(name: &str) -> Option<i32> {
    let c_name = CString::new(name).ok()?;
    let mut val: i32 = 0;
    let mut size = core::mem::size_of::<i32>();
    // SAFETY: `val` and `size` match exact 4-byte i32 sysctl output buffer.
    let rc = unsafe {
        sysctlbyname(
            c_name.as_ptr(),
            (&mut val as *mut i32).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if rc == 0 { Some(val) } else { None }
}

fn sysctl_u64(name: &str) -> Option<u64> {
    let c_name = CString::new(name).ok()?;
    let mut val: u64 = 0;
    let mut size = core::mem::size_of::<u64>();
    // SAFETY: `val` and `size` match exact 8-byte u64 sysctl output buffer.
    let rc = unsafe {
        sysctlbyname(
            c_name.as_ptr(),
            (&mut val as *mut u64).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if rc == 0 { Some(val) } else { None }
}

pub fn list_all_pids() -> Vec<i32> {
    // SAFETY: Passing null buffer queries total byte count needed for active PIDs.
    let est_bytes = unsafe { proc_listpids(PROC_ALL_PIDS, 0, ptr::null_mut(), 0) };
    if est_bytes <= 0 {
        return Vec::new();
    }
    let cap = (est_bytes as usize / core::mem::size_of::<i32>()) + 64;
    let mut pids = vec![0i32; cap];
    let buf_bytes = (cap * core::mem::size_of::<i32>()) as i32;
    // SAFETY: `pids` has `cap` elements matching `buf_bytes`.
    let actual_bytes = unsafe {
        proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast(),
            buf_bytes,
        )
    };
    if actual_bytes <= 0 {
        return Vec::new();
    }
    let count = (actual_bytes as usize / core::mem::size_of::<i32>()).min(cap);
    pids.truncate(count);
    pids.retain(|&p| p > 0);
    pids
}

pub fn read_host_metrics(total_pids: usize) -> HostMetrics {
    let ncpu = sysctl_u32("hw.ncpu").unwrap_or(8).max(1);
    let mem_total_bytes = sysctl_u64("hw.memsize").unwrap_or(0);
    let vm_pressure_level = sysctl_i32("kern.memorystatus_vm_pressure_level").unwrap_or(1);
    let mut loads = [0.0f64; 3];
    // SAFETY: `loads` has 3 f64 slots matching `nelem = 3`.
    let got = unsafe { getloadavg(loads.as_mut_ptr(), 3) };
    if got < 3 {
        loads = [0.0, 0.0, 0.0];
    }
    HostMetrics {
        ncpu,
        mem_total_bytes,
        vm_pressure_level,
        load_1m: loads[0],
        load_5m: loads[1],
        load_15m: loads[2],
        total_pids,
    }
}

fn read_cstr_bytes(slice: &[u8]) -> String {
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

pub fn inspect_pid_basic(pid: i32) -> Option<ProcBasic> {
    let mut bsd_buf = [0u8; BSD_INFO_SIZE];
    // SAFETY: `bsd_buf` is 136 bytes matching `sizeof(struct proc_bsdinfo)`.
    let bsd_rc = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            bsd_buf.as_mut_ptr().cast(),
            BSD_INFO_SIZE as i32,
        )
    };
    if bsd_rc != BSD_INFO_SIZE as i32 {
        return None;
    }

    let pbi_pid = u32::from_ne_bytes([bsd_buf[12], bsd_buf[13], bsd_buf[14], bsd_buf[15]]);
    let ppid = u32::from_ne_bytes([bsd_buf[16], bsd_buf[17], bsd_buf[18], bsd_buf[19]]);
    let uid = u32::from_ne_bytes([bsd_buf[20], bsd_buf[21], bsd_buf[22], bsd_buf[23]]);
    let comm = read_cstr_bytes(&bsd_buf[48..64]);
    let name = read_cstr_bytes(&bsd_buf[64..96]);
    let nice = i32::from_ne_bytes([bsd_buf[116], bsd_buf[117], bsd_buf[118], bsd_buf[119]]);
    let start_tvsec = u64::from_ne_bytes([
        bsd_buf[120],
        bsd_buf[121],
        bsd_buf[122],
        bsd_buf[123],
        bsd_buf[124],
        bsd_buf[125],
        bsd_buf[126],
        bsd_buf[127],
    ]);

    let mut task_buf = [0u8; TASK_INFO_SIZE];
    // SAFETY: `task_buf` is 96 bytes matching `sizeof(struct proc_taskinfo)`.
    let task_rc = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTASKINFO,
            0,
            task_buf.as_mut_ptr().cast(),
            TASK_INFO_SIZE as i32,
        )
    };

    let (rss_bytes, cpu_total_ns) = if task_rc == TASK_INFO_SIZE as i32 {
        let rss = u64::from_ne_bytes([
            task_buf[8],
            task_buf[9],
            task_buf[10],
            task_buf[11],
            task_buf[12],
            task_buf[13],
            task_buf[14],
            task_buf[15],
        ]);
        let user_ticks = u64::from_ne_bytes([
            task_buf[16],
            task_buf[17],
            task_buf[18],
            task_buf[19],
            task_buf[20],
            task_buf[21],
            task_buf[22],
            task_buf[23],
        ]);
        let sys_ticks = u64::from_ne_bytes([
            task_buf[24],
            task_buf[25],
            task_buf[26],
            task_buf[27],
            task_buf[28],
            task_buf[29],
            task_buf[30],
            task_buf[31],
        ]);
        (rss, ticks_to_nanos(user_ticks.saturating_add(sys_ticks)))
    } else {
        (0, 0)
    };

    Some(ProcBasic {
        pid: pbi_pid,
        ppid,
        uid,
        nice,
        start_tvsec,
        comm,
        name,
        rss_bytes,
        cpu_total_ns,
    })
}

pub fn read_pid_cmdline(pid: u32) -> Option<String> {
    let mut mib = [CTL_KERN, KERN_PROCARGS2, pid as i32];
    let mut size: usize = 64 * 1024;
    let mut buf = vec![0u8; size];
    // SAFETY: `mib` has 3 elements and `buf` has `size` writable bytes.
    let rc = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size < 4 {
        return None;
    }
    buf.truncate(size);
    let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if argc <= 0 {
        return None;
    }
    let mut idx = 4;
    while idx < buf.len() && buf[idx] != 0 {
        idx += 1;
    }
    while idx < buf.len() && buf[idx] == 0 {
        idx += 1;
    }
    if idx >= buf.len() {
        return None;
    }
    let mut parts: Vec<String> = Vec::with_capacity(argc as usize);
    let mut cur_start = idx;
    while idx < buf.len() && parts.len() < argc as usize {
        if buf[idx] == 0 {
            parts.push(String::from_utf8_lossy(&buf[cur_start..idx]).into_owned());
            idx += 1;
            cur_start = idx;
        } else {
            idx += 1;
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}
