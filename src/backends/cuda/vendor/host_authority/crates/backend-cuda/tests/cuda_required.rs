//! Fail-closed admission probe for GPU soundness manifests.
//!
//! This target is intentionally not part of CPU-only CI. Hardware validation
//! runs it first so later CUDA-gated tests cannot report green after executing
//! zero device assertions.

#[test]
fn cuda_kernels_must_be_linked_for_hardware_gate() {
    assert!(
        stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT,
        "GPU soundness gate requires a native CUDA build; stub kernels are not evidence"
    );
    assert_eq!(stwo_backend_cuda_kernels::BUILD_MODE, "cuda");
}

#[test]
fn execution_context_captures_independent_component_lanes() {
    use stwo_backend_cuda::CudaExecContext;

    const LEAVES: usize = 32;
    const HASH_WORDS: usize = 8;

    let context = CudaExecContext::new().unwrap();
    assert!(context.lane_count() >= 2);
    let left = context.alloc_u32(LEAVES * HASH_WORDS).unwrap();
    let right = context.alloc_u32(LEAVES * HASH_WORDS).unwrap();
    let left_parent = context.alloc_u32(LEAVES / 2 * HASH_WORDS).unwrap();
    let right_parent = context.alloc_u32(LEAVES / 2 * HASH_WORDS).unwrap();

    let capture = context.capture().unwrap();
    let left_lane = context.fork_lane(0).unwrap();
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_blake2s_leaf_init_on(
            LEAVES as u32,
            left.as_ptr().cast(),
            left_lane.stream_raw().as_ptr(),
        )
    };
    assert_eq!(code, 0);
    let right_lane = context.fork_lane(1).unwrap();
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_blake2s_leaf_init_on(
            LEAVES as u32,
            right.as_ptr().cast(),
            right_lane.stream_raw().as_ptr(),
        )
    };
    assert_eq!(code, 0);
    context.join_lane(0).unwrap();
    context.join_lane(1).unwrap();

    // Reuse the same pre-created lane events for a dependent second wave. This
    // is the exact pattern used between topological Graph-A component levels.
    let left_lane = context.fork_lane(0).unwrap();
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_blake2s_layer_on(
            left.as_ptr().cast(),
            (LEAVES / 2) as u32,
            left_parent.as_ptr().cast(),
            left_lane.stream_raw().as_ptr(),
        )
    };
    assert_eq!(code, 0);
    let right_lane = context.fork_lane(1).unwrap();
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_blake2s_layer_on(
            right.as_ptr().cast(),
            (LEAVES / 2) as u32,
            right_parent.as_ptr().cast(),
            right_lane.stream_raw().as_ptr(),
        )
    };
    assert_eq!(code, 0);
    context.join_lane(0).unwrap();
    context.join_lane(1).unwrap();
    let graph = capture.finish().unwrap();
    assert_eq!(graph.kernel_nodes(), 4);

    graph.launch(&context).unwrap();
    let mut left_words = vec![0u32; LEAVES / 2 * HASH_WORDS];
    let mut right_words = vec![0u32; LEAVES / 2 * HASH_WORDS];
    unsafe {
        context
            .memcpy_d2h_async(
                left_words.as_mut_ptr().cast(),
                left_parent.as_ptr().cast(),
                core::mem::size_of_val(left_words.as_slice()),
            )
            .unwrap();
        context
            .memcpy_d2h_async(
                right_words.as_mut_ptr().cast(),
                right_parent.as_ptr().cast(),
                core::mem::size_of_val(right_words.as_slice()),
            )
            .unwrap();
    }
    context.sync().unwrap();
    assert_eq!(left_words, right_words);
    assert!(left_words.iter().any(|&word| word != 0));
    assert!(left_words
        .chunks_exact(HASH_WORDS)
        .all(|hash| hash == &left_words[..HASH_WORDS]));

    drop(graph);
    unsafe {
        context.free_u32(left).unwrap();
        context.free_u32(right).unwrap();
        context.free_u32(left_parent).unwrap();
        context.free_u32(right_parent).unwrap();
    }
}

#[cfg(stwo_cuda_link)]
#[test]
fn borrowed_launch_sync_fences_its_selected_lane() {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use stwo_backend_cuda::CudaExecContext;

    unsafe extern "C" {
        #[link_name = "cudaLaunchHostFunc"]
        fn cuda_launch_host_func(
            stream: *mut c_void,
            function: Option<unsafe extern "C" fn(*mut c_void)>,
            user_data: *mut c_void,
        ) -> i32;
    }

    struct HostGate {
        started: AtomicBool,
        release: AtomicBool,
        finished: AtomicBool,
    }

    unsafe extern "C" fn wait_for_release(user_data: *mut c_void) {
        let gate = unsafe { &*user_data.cast::<HostGate>() };
        gate.started.store(true, Ordering::Release);
        while !gate.release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        gate.finished.store(true, Ordering::Release);
    }

    const HASH_WORDS: usize = 8;
    let context = CudaExecContext::new().unwrap();
    let reference = context.alloc_u32(HASH_WORDS).unwrap();
    let actual = context.alloc_u32(HASH_WORDS).unwrap();
    let main = context.launch_context();
    let lane = context.lane(0).unwrap();

    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_blake2s_leaf_init_on(
            1,
            reference.as_ptr().cast(),
            main.stream_raw().as_ptr(),
        )
    };
    assert_eq!(code, 0);
    context.sync().unwrap();

    let gate = Box::new(HostGate {
        started: AtomicBool::new(false),
        release: AtomicBool::new(false),
        finished: AtomicBool::new(false),
    });
    let code = unsafe {
        cuda_launch_host_func(
            lane.stream_raw().as_ptr(),
            Some(wait_for_release),
            ((&*gate) as *const HostGate).cast_mut().cast(),
        )
    };
    assert_eq!(code, 0);
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_blake2s_leaf_init_on(
            1,
            actual.as_ptr().cast(),
            lane.stream_raw().as_ptr(),
        )
    };
    assert_eq!(code, 0);

    let started_deadline = Instant::now() + Duration::from_secs(5);
    while !gate.started.load(Ordering::Acquire) {
        if Instant::now() >= started_deadline {
            gate.release.store(true, Ordering::Release);
            context.join_lane(0).unwrap();
            context.sync().unwrap();
            panic!("CUDA lane host callback did not start");
        }
        std::thread::yield_now();
    }

    let finished_at_sync = std::thread::scope(|scope| {
        let release = scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(100));
            gate.release.store(true, Ordering::Release);
        });
        lane.sync().unwrap();
        let finished = gate.finished.load(Ordering::Acquire);
        release.join().unwrap();
        // Always establish a context-owned cleanup edge before the host gate is
        // dropped, including when this assertion catches a regressed sync.
        context.join_lane(0).unwrap();
        context.sync().unwrap();
        finished
    });
    assert!(
        finished_at_sync,
        "borrowed launch sync returned before its selected lane completed"
    );

    let mut reference_words = [0u32; HASH_WORDS];
    let mut actual_words = [0u32; HASH_WORDS];
    unsafe {
        context
            .memcpy_d2h_async(
                reference_words.as_mut_ptr().cast(),
                reference.as_ptr().cast(),
                core::mem::size_of_val(&reference_words),
            )
            .unwrap();
        context
            .memcpy_d2h_async(
                actual_words.as_mut_ptr().cast(),
                actual.as_ptr().cast(),
                core::mem::size_of_val(&actual_words),
            )
            .unwrap();
    }
    context.sync().unwrap();
    assert_eq!(actual_words, reference_words);
    assert!(actual_words.iter().any(|&word| word != 0));

    unsafe {
        context.free_u32(reference).unwrap();
        context.free_u32(actual).unwrap();
    }
}
