//! The busy loop behind `run --keep-awake`: where it runs, at what priority, and that it cannot
//! outlive the harness that started it.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BENCH: &str = env!("CARGO_BIN_EXE_concord-bench");
const SCHED_IDLE: &str = "5";

fn status(pid: u32, name: &str) -> String {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let line = text.lines().find(|l| l.starts_with(name)).unwrap();
    line.split_once(':').unwrap().1.trim().to_string()
}

fn an_allowed_cpu() -> String {
    let list = status(std::process::id(), "Cpus_allowed_list");
    list.split([',', '-']).next().unwrap().to_string()
}

fn spin(cpu: &str, parent: u32) -> Child {
    Command::new(BENCH)
        .args(["spin", "--cpu", cpu, "--parent", &parent.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn gone_within(pid: u32, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        // A zombie still has a /proc entry; it has no command line left.
        match std::fs::read(format!("/proc/{pid}/cmdline")) {
            Ok(cmdline) if !cmdline.is_empty() => std::thread::sleep(Duration::from_millis(20)),
            _ => return true,
        }
    }
    false
}

#[test]
fn the_loop_runs_idle_priority_on_its_cpu() {
    let cpu = an_allowed_cpu();
    let mut child = spin(&cpu, std::process::id());
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "spinning");

    assert_eq!(status(child.id(), "Cpus_allowed_list"), cpu);
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap();
    // Fields after the command name, which may hold spaces, start at the third; policy is the 41st.
    let after_name: Vec<&str> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    assert_eq!(after_name[41 - 3], SCHED_IDLE);

    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn the_loop_refuses_a_parent_that_is_not_its_own() {
    let mut child = spin(&an_allowed_cpu(), u32::MAX);
    assert!(!child.wait().unwrap().success());
}

#[test]
fn the_loop_dies_with_the_process_that_started_it() {
    let script = r#""$0" spin --cpu "$1" --parent $$ > /dev/null & echo $!; sleep 0.3"#;
    let out = Command::new("sh")
        .args(["-c", script, BENCH, &an_allowed_cpu()])
        .stderr(Stdio::null())
        .output()
        .unwrap();
    let pid: u32 = String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(gone_within(pid, Duration::from_secs(5)));
}
