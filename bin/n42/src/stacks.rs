// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Thread stacks on demand, for a node that has stopped making progress.
//!
//! [`install`] puts a `SIGUSR2` handler in place that prints the receiving
//! thread's name and backtrace; [`dump_all`] sends that signal to every
//! thread of the process in turn and waits briefly for each. The handler
//! allocates and formats, which a signal handler must not in general -- this
//! is a last-resort diagnostic for a stuck process (round 43: a leader's
//! execution layer stopped inside a build with every thread waiting on a
//! futex, and there is no debugger on the host), and a thread that cannot
//! answer within the wait is reported as such and skipped. Frames resolve
//! only with symbols: build with `--profile profiling`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Set by the handler to the thread id it ran on, so the sender knows the
/// thread answered.
static ANSWERED: AtomicU64 = AtomicU64::new(0);

extern "C" fn on_signal(_sig: libc::c_int) {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
    let mut name = [0 as libc::c_char; 32];
    let name = unsafe {
        libc::pthread_getname_np(libc::pthread_self(), name.as_mut_ptr(), name.len());
        std::ffi::CStr::from_ptr(name.as_ptr()).to_string_lossy().into_owned()
    };
    let bt = std::backtrace::Backtrace::force_capture();
    eprintln!("=== thread {tid} {name:?}\n{bt}");
    ANSWERED.store(tid, Ordering::SeqCst);
}

/// Installs the handler. Idempotent.
pub fn install() {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_signal as usize;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGUSR2, &action, std::ptr::null_mut());
    }
}

/// Prints every thread's stack to stderr, one at a time, waiting up to
/// `each` for a thread to answer. Returns how many answered.
pub fn dump_all(each: std::time::Duration) -> usize {
    let me = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
    let pid = unsafe { libc::getpid() };
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else { return 0 };
    let mut tids: Vec<u64> = tasks.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect();
    tids.sort_unstable();
    let mut answered = 0;
    eprintln!("=== stack dump: {} threads", tids.len());
    for tid in tids {
        if tid == me {
            continue;
        }
        ANSWERED.store(0, Ordering::SeqCst);
        let rc = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid as libc::pid_t, libc::SIGUSR2) };
        if rc != 0 {
            continue;
        }
        let deadline = std::time::Instant::now() + each;
        while ANSWERED.load(Ordering::SeqCst) != tid && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if ANSWERED.load(Ordering::SeqCst) == tid {
            answered += 1;
        } else {
            let comm = std::fs::read_to_string(format!("/proc/self/task/{tid}/comm")).unwrap_or_default();
            let wchan = std::fs::read_to_string(format!("/proc/self/task/{tid}/wchan")).unwrap_or_default();
            eprintln!("=== thread {tid} {:?} did not answer (wchan {})", comm.trim(), wchan.trim());
        }
    }
    eprintln!("=== stack dump done: {answered} answered");
    answered
}
