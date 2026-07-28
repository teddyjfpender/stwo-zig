static void *create_runtime_from_source(
    const char *source_utf8,
    bool include_deferred,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device == nil) {
            write_error(error_message, error_message_len, @"No Metal device available");
            return NULL;
        }
        NSString *source = [NSString stringWithUTF8String:source_utf8];
        MTLCompileOptions *options = [MTLCompileOptions new];
        stwo_zig_configure_safe_metal_compile_options(options);
        NSError *error = nil;
        id<MTLLibrary> library = [device newLibraryWithSource:source options:options error:&error];
        if (library == nil) {
            write_error(error_message, error_message_len,
                        error.localizedDescription ?: @"Failed to compile Metal library");
            return NULL;
        }
        StwoZigMetalRuntime *runtime = create_runtime_from_library(
            device, library, include_deferred, error_message, error_message_len
        );
        return runtime == nil ? NULL : (__bridge_retained void *)runtime;
    }
}

void *stwo_zig_metal_runtime_create(
    const char *source_utf8,
    char *error_message,
    size_t error_message_len
) {
    return create_runtime_from_source(source_utf8, false, error_message, error_message_len);
}

void *stwo_zig_metal_runtime_create_full(
    const char *source_utf8,
    char *error_message,
    size_t error_message_len
) {
    return create_runtime_from_source(source_utf8, true, error_message, error_message_len);
}

void *stwo_zig_metal_runtime_create_from_metallib(
    const char *path_bytes,
    size_t path_len,
    char *error_message,
    size_t error_message_len
) {
    if (path_bytes == NULL || path_len == 0u) {
        write_error(error_message, error_message_len, @"Metal library path is empty");
        return NULL;
    }
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device == nil) {
            write_error(error_message, error_message_len, @"No Metal device available");
            return NULL;
        }
        NSString *path = [[NSString alloc] initWithBytes:path_bytes
                                                  length:path_len
                                                encoding:NSUTF8StringEncoding];
        if (path == nil) {
            write_error(error_message, error_message_len, @"Invalid Metal library path encoding");
            return NULL;
        }
        NSString *canonical_path = [[path stringByStandardizingPath] stringByResolvingSymlinksInPath];
        NSError *error = nil;
        id<MTLLibrary> library = [device newLibraryWithURL:[NSURL fileURLWithPath:canonical_path]
                                                    error:&error];
        if (library == nil) {
            write_error(error_message, error_message_len,
                        error.localizedDescription ?: @"Failed to load Metal library");
            return NULL;
        }
        StwoZigMetalRuntime *runtime = create_runtime_from_library(
            device, library, false, error_message, error_message_len
        );
        return runtime == nil ? NULL : (__bridge_retained void *)runtime;
    }
}

void *stwo_zig_metal_runtime_create_from_metallib_data(
    const uint8_t *bytes,
    size_t byte_len,
    char *error_message,
    size_t error_message_len
);

static void *create_runtime_from_metallib_data_on_device(
    id<MTLDevice> device,
    const uint8_t *bytes,
    size_t byte_len,
    char *error_message,
    size_t error_message_len
) {
    if (bytes == NULL || byte_len == 0u) {
        write_error(error_message, error_message_len, @"Metal library data is empty");
        return NULL;
    }
    @autoreleasepool {
        if (device == nil) {
            write_error(error_message, error_message_len, @"No Metal device available");
            return NULL;
        }
        void *owned_bytes = malloc(byte_len);
        if (owned_bytes == NULL) {
            write_error(error_message, error_message_len, @"Failed to copy Metal library data");
            return NULL;
        }
        memcpy(owned_bytes, bytes, byte_len);
        dispatch_data_t data = dispatch_data_create(
            owned_bytes,
            byte_len,
            dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
            ^{ free(owned_bytes); }
        );
        if (data == nil) {
            free(owned_bytes);
            write_error(error_message, error_message_len, @"Failed to wrap Metal library data");
            return NULL;
        }
        NSError *error = nil;
        id<MTLLibrary> library = [device newLibraryWithData:data error:&error];
        if (library == nil) {
            write_error(error_message, error_message_len,
                        error.localizedDescription ?: @"Failed to load Metal library data");
            return NULL;
        }
        StwoZigMetalRuntime *runtime = create_runtime_from_library(
            device, library, false, error_message, error_message_len
        );
        return runtime == nil ? NULL : (__bridge_retained void *)runtime;
    }
}

void *stwo_zig_metal_runtime_create_from_metallib_data(
    const uint8_t *bytes,
    size_t byte_len,
    char *error_message,
    size_t error_message_len
) {
    return create_runtime_from_metallib_data_on_device(
        MTLCreateSystemDefaultDevice(),
        bytes,
        byte_len,
        error_message,
        error_message_len
    );
}

void *stwo_zig_metal_runtime_create_from_metallib_data_on_device(
    void *device_handle,
    const uint8_t *bytes,
    size_t byte_len,
    char *error_message,
    size_t error_message_len
) {
    id<MTLDevice> device = device_handle == NULL
        ? nil
        : (__bridge id<MTLDevice>)device_handle;
    return create_runtime_from_metallib_data_on_device(
        device,
        bytes,
        byte_len,
        error_message,
        error_message_len
    );
}
