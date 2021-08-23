use anyhow::Result;
use bcc::{
    perf_event::PerfMapBuilder,
    {Tracepoint, BPF},
};
use core::sync::atomic::{AtomicBool, Ordering};
use std::{
    ptr,
    sync::Arc,
    time::{Duration, Instant},
};
use structopt::StructOpt;

#[repr(C)]
struct data_t {
    ts: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    ret: i32,
    executable: [u8; 255],
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "execsnoop",
    about = "Prints out every run of a variant of the exec* syscall is made."
)]
struct Opt {
    #[structopt(
        short = "d",
        long = "duration",
        help = "The total duration to run this tool, in seconds."
    )]
    duration: Option<u64>,
    #[structopt(
        short = "p",
        long = "ppid",
        help = "The parent process ID to the exec caller to snoop."
    )]
    ppid: Option<u64>,
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<()> {
    let opt = Opt::from_args();

    let duration: Option<Duration> = opt.duration.map(|v| Duration::new(v, 0));
    let ppid = opt.ppid.map_or(-1, |p| p as i64);

    let code = include_str!("execsnoop.c").replace("PPID_FILTER_VALUE", &ppid.to_string());
    // Compile the above BPF code
    let mut module = BPF::new(&code)?;
    // Load and attach tracepoints
    Tracepoint::new()
        .handler("trace_entry")
        .subsystem("syscalls")
        .tracepoint("sys_enter_execve")
        .attach(&mut module)?;
    Tracepoint::new()
        .handler("trace_return")
        .subsystem("syscalls")
        .tracepoint("sys_exit_execve")
        .attach(&mut module)?;

    // The "events" table is where the "open file" events get sent
    let table = module.table("events")?;
    // Install a callback to print out the file open events when they happen
    let mut perf_map = PerfMapBuilder::new(table, perf_data_callback).build()?;
    // print a header
    println!("{:<7} {:<7} {:<5} {}", "PPID", "PID", "RET", "COMMAND");
    let start = Instant::now();
    // this .poll() loop is what makes our callback get called
    while runnable.load(Ordering::SeqCst) {
        perf_map.poll(200);
        if let Some(d) = duration {
            if std::time::Instant::now() - start >= d {
                break;
            }
        }
    }
    Ok(())
}

fn perf_data_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let data = parse_struct(x);
        println!(
            "{:<7} {:<7} {:<5} {}",
            data.ppid,
            data.pid,
            data.ret,
            get_string(&data.executable),
        );
    })
}

fn parse_struct(x: &[u8]) -> data_t {
    unsafe { ptr::read(x.as_ptr() as *const data_t) }
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

fn main() -> anyhow::Result<()> {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    do_main(runnable)
}
