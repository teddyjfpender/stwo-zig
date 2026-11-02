"""Consume verified VM segments directly into the unchanged witness adapter.

This removes the complete flat Option<Felt252> memory copy. Addresses, values,
iteration order, instruction classification and builtin padding stay unchanged.
"""

VM_METHOD = '''    pub fn prepare_streamed_relocation(&mut self) -> Result<Vec<usize>, MemoryError> {
        self.vm.segments.compute_effective_sizes();
        let table = self.vm.segments.relocate_segments()?;
        self.vm.relocation_table = Some(table.clone());
        Ok(table)
    }

    pub fn take_relocated_memory_entries(&mut self, table: Vec<usize>)
        -> impl Iterator<Item = Result<(usize, Felt252), MemoryError>> {
        let memory = std::mem::replace(&mut self.vm.segments.memory,
            crate::vm::vm_memory::memory::Memory::new());
        let table = std::sync::Arc::new(table);
        memory.data.into_iter().enumerate().flat_map(move |(index, segment)| {
            let table = table.clone();
            segment.into_iter().enumerate().filter_map(move |(offset, cell)| {
                cell.get_value().map(|value| {
                    let address = relocate_address((index as isize, offset).into(), &table)?;
                    let value = relocate_value(value, &table)?;
                    Ok((address, value))
                })
            })
        })
    }

'''


def adapt_runner(text):
    start = text.index('pub fn generate_trace(')
    end = text.index('\n///', start + 1)
    prefix, body, suffix = text[:start], text[start:end], text[end:]
    old = 'let (program, exec_scopes, cairo_run_config) = prepare_cairo_execution('
    if body.count(old) != 1:
        raise ValueError('unexpected trace preparation')
    body = body.replace(old, 'let (program, exec_scopes, mut cairo_run_config) = prepare_cairo_execution(')
    old = '    let run_span = tracing::span!('
    if body.count(old) != 1:
        raise ValueError('unexpected trace run boundary')
    body = body.replace(old, '''    let stream_memory = !cairo_pie && !output_trace_components;
    if stream_memory {
        // Security checks, resources and program output still use the original
        // VM. Only the subsequent relocation/export ownership changes.
        cairo_run_config.relocate_mem = false;
        cairo_run_config.relocate_trace = false;
    }
    let run_span = tracing::span!(''')
    old = 'let prover_input_info = prover_input_from_runner(&mut cairo_runner_mut, !output_trace_components);'
    if body.count(old) != 1:
        raise ValueError('unexpected consuming adapter invocation')
    body = body.replace(old, '''let prover_input_info = if stream_memory {
            prover_input_from_segments(&mut cairo_runner_mut)
        } else {
            prover_input_from_runner(&mut cairo_runner_mut, !output_trace_components)
        };''')
    return prefix + body + suffix + '''

fn prover_input_from_segments(runner: &mut RustCairoRunner) -> ProverInput {
    keth_memory_profile("adapter_start", runner);
    let table = runner.prepare_streamed_relocation().expect("validated segment sizes");
    let addresses = runner.vm.get_public_memory_addresses().expect("public addresses")
        .into_iter().map(|(address, _)| u32::try_from(address).expect("public address width")).collect();
    let segment_values = runner.get_memory_segment_addresses().expect("segment metadata");
    let segments = segment_values.iter().map(|(&name, &(begin_addr, stop_ptr))|
        (name, MemorySegmentAddresses { begin_addr, stop_ptr })).collect::<HashMap<_, _>>();
    runner.relocate_trace(&table).expect("secure trace relocation");
    let trace = runner.relocated_trace.take().unwrap().into_iter()
        .map(|x| RelocatedTraceEntry { ap: x.ap, fp: x.fp, pc: x.pc }).collect::<Vec<_>>();
    let entries = runner.take_relocated_memory_entries(table).map(|entry| {
        let (address, value) = entry.expect("secure memory relocation");
        MemoryEntry { address: address as u64,
            value: unsafe { std::mem::transmute::<[u8; 32], [u32; 8]>(value.to_bytes_le()) } }
    });
    keth_memory_profile("streamed_memory_started", runner);
    let mem = MemoryBuilder::from_iter(MemoryConfig::default(), entries);
    keth_memory_profile("memory_builder_ready", runner);
    if std::env::var_os("KETH_WITNESS_MEMORY_PROFILE").is_some() {
        eprintln!("KETH_BUFFER {{\\"stage\\":\\"memory_builder\\",\\"addresses\\":{},\\"f252\\":{},\\"small\\":{}}}",
            mem.address_to_id.capacity() * 4, mem.f252_values.capacity() * 32, mem.small_values.capacity() * 16);
    }
    let main_args = runner.get_program().iter_builtins().copied().collect::<Vec<_>>();
    let context = PublicSegmentContext::new(&main_args);
    let input = adapt_to_stwo_input(&trace, mem, addresses, &segments, context).unwrap();
    keth_memory_profile("adapted_input_ready", runner);
    input
}
'''
