//! Offline bounded secure-trie prefix search; output remains untrusted advice.
use sha3::{Digest, Keccak256};
use std::sync::{atomic::{AtomicBool,AtomicU64,Ordering},Mutex};
use std::time::{Duration, Instant};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!((3..=4).contains(&args.len()));
    let prefix=&args[1];
    assert!(!prefix.is_empty() && prefix.len()<=7 && prefix.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    let seconds:u64=args[2].parse().unwrap();assert!((1..=60).contains(&seconds));
    let threads:usize=args.get(3).map(|v|v.parse().unwrap()).unwrap_or(4);assert!((1..=8).contains(&threads));
    let wanted=u32::from_str_radix(prefix,16).unwrap();let shift=32-4*prefix.len();
    let started=Instant::now();let stop=AtomicBool::new(false);let next=AtomicU64::new(0);let total=AtomicU64::new(0);let found=Mutex::new(None);
    const MAX:u64=1<<28;const CHUNK:u64=1024;
    std::thread::scope(|scope|{
        for _ in 0..threads {
            let(stop,next,total,found)=(&stop,&next,&total,&found);
            scope.spawn(move||{
                let mut slot=[0u8;32];
                loop {
                    if stop.load(Ordering::Relaxed) || started.elapsed()>=Duration::from_secs(seconds){stop.store(true,Ordering::Relaxed);return;}
                    let begin=next.fetch_add(CHUNK,Ordering::Relaxed);if begin>=MAX{return;}
                    let mut count=0;
                    for candidate in begin..(begin+CHUNK).min(MAX) {
                        if stop.load(Ordering::Relaxed){break;}
                        slot[24..].copy_from_slice(&candidate.to_be_bytes());let hash=Keccak256::digest(slot);count+=1;
                        if u32::from_be_bytes(hash[..4].try_into().unwrap())>>shift==wanted {
                            let mut result=found.lock().unwrap();if result.is_none(){*result=Some(candidate);}stop.store(true,Ordering::Relaxed);break;
                        }
                    }
                    total.fetch_add(count,Ordering::Relaxed);
                }
            });
        }
    });
    let result=*found.lock().unwrap();
    if let Some(candidate)=result{
        println!("{{\"candidate\":{candidate},\"attempts\":{},\"threads\":{threads},\"seconds\":{}}}",total.load(Ordering::Relaxed),started.elapsed().as_secs_f64());
    } else {eprintln!("bounded search stopped after {} hashes",total.load(Ordering::Relaxed));std::process::exit(2);}
}
