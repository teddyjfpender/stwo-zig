"""Opt-in exact-buffer and Darwin physical-memory diagnostics for owned builds."""
from __future__ import annotations


def instrument_runner(text: str) -> str:
    markers = {
        '    let public_input = runner.get_air_public_input().unwrap();':
            '    keth_memory_profile("adapter_start", runner);\n',
        '    let mem = runner.relocated_memory.iter().enumerate().filter_map(|(i, x)| {':
            '    keth_memory_profile("vm_buffers_released", runner);\n',
        '    let main_args = runner.get_program().iter_builtins().copied().collect::<Vec<_>>();':
            '    keth_memory_profile("memory_builder_ready", runner);\n'
            '    if std::env::var_os("KETH_WITNESS_MEMORY_PROFILE").is_some() {\n'
            '        eprintln!("KETH_BUFFER {{\\"stage\\":\\"memory_builder\\",\\"addresses\\":{},\\"f252\\":{},\\"small\\":{}}}",\n'
            '            mem.address_to_id.capacity() * 4, mem.f252_values.capacity() * 32, mem.small_values.capacity() * 16);\n'
            '    }\n',
        '        sonic_rs::to_writer_pretty(&mut writer, &prover_input_info)':
            '        keth_memory_profile("serialization_start", &cairo_runner_mut);\n',
        '        writer.flush()?;':
            '        keth_memory_profile("serialization_end", &cairo_runner_mut);\n',
    }
    for marker, before in markers.items():
        if text.count(marker) != 1:
            raise ValueError('memory diagnostic anchor changed: ' + marker)
        text = text.replace(marker, before + marker)
    marker = '    adapt_to_stwo_input(&trace, mem, addresses, &segments, public_segment_context).unwrap()'
    if text.count(marker) != 1:
        raise ValueError('adapter return anchor changed')
    text = text.replace(marker, '''    let input = adapt_to_stwo_input(&trace, mem, addresses, &segments, public_segment_context).unwrap();
    keth_memory_profile("adapted_input_ready", runner);
    input''')
    text += r'''

fn keth_memory_profile(stage: &str, runner: &RustCairoRunner) {
    if std::env::var_os("KETH_WITNESS_MEMORY_PROFILE").is_none() { return; }
    let (vm, relocated, trace) = runner.witness_buffer_bytes();
    let mut footprint = 0u64;
    let mut peak = 0u64;
    #[cfg(target_os = "macos")]
    {
        #[repr(align(8))]
        struct Usage([u8; 1024]);
        extern "C" { fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut u8) -> i32; }
        let mut usage = Usage([0; 1024]);
        let status = unsafe { proc_pid_rusage(std::process::id() as i32, 6, usage.0.as_mut_ptr()) };
        if status != 0 { panic!("memory profiling unavailable"); }
        footprint = u64::from_le_bytes(usage.0[72..80].try_into().unwrap());
        peak = u64::from_le_bytes(usage.0[240..248].try_into().unwrap());
    }
    let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    eprintln!("KETH_MEMORY {{\"stage\":\"{}\",\"time_ns\":{},\"footprint\":{},\"peak\":{},\"vm_buffers\":{},\"relocated_memory\":{},\"trace_buffers\":{}}}",
        stage, time, footprint, peak, vm, relocated, trace);
}
'''
    # The Rust source needs escaped JSON quotes, not escaped backslashes.
    return text.replace(r'\\\"', r'\"')
