extern crate bcc;
extern crate byteorder;
extern crate ctrlc;
extern crate libc;
extern crate structopt_derive;

use anyhow::Result;
use bcc::perf_event::init_perf_map;
use bcc::{Kprobe, Kretprobe, BPF};
use structopt::StructOpt;

use core::sync::atomic::{AtomicBool, Ordering};
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

#[repr(C)]
struct data_t {
    id: u64,
    ts: u64,
    ret: libc::c_int,
    comm: [u8; 16],   // TASK_COMM_LEN
    fname: [u8; 255], // NAME_MAX
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "opensnoop",
    about = "Prints out filename + PID every time a file is opened."
)]
struct Opt {
    #[structopt(
        short = "d",
        long = "duration",
        help = "The total duration to run this tool, in seconds."
    )]
    duration: Option<u64>,
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<()> {
    let opt = Opt::from_args();

    let duration: Option<std::time::Duration> = opt.duration.map(|v| Duration::new(v, 0));

    let code = include_str!("opensnoop.c");
    // Compile the above BPF code
    let mut module = BPF::new(code)?;
    // Load and attach kprobes
    Kprobe::new()
        .handler("trace_entry")
        .function("do_sys_open")
        .attach(&mut module)?;
    Kretprobe::new()
        .handler("trace_return")
        .function("do_sys_open")
        .attach(&mut module)?;

    // The "events" table is where the "open file" events get sent
    let table = module.table("events")?;
    // Install a callback to print out the file open events when they happen
    let mut perf_map = init_perf_map(table, perf_data_callback)?;
    // print a header
    println!("{:-7} {:-16} {}", "PID", "COMM", "FILENAME");
    let start = std::time::Instant::now();
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
            "{:-7} {:-16} {}",
            data.id >> 32,
            get_string(&data.comm),
            get_string(&data.fname)
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

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    match do_main(runnable) {
        Err(x) => {
            eprintln!("Error: {}", x);
            eprintln!("{:?}", x.backtrace());
            std::process::exit(1);
        }
        _ => {}
    }
}
