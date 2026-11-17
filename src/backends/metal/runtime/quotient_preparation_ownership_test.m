// Execute the actual private prepared-context ARC ownership law without a GPU.
#import <Foundation/Foundation.h>
#include "quotient_preparation_types.h"

static volatile uint32_t released_owners = 0u;
@interface StwoZigQuotientLifetimeProbe : NSObject
@end
@implementation StwoZigQuotientLifetimeProbe
- (void)dealloc { released_owners += 1u; }
@end

static bool transfer_owner(StwoZigQuotientPreparation *out, bool fail) {
    StwoZigQuotientLifetimeProbe *owner = [StwoZigQuotientLifetimeProbe new];
    if (fail) return false;
    // Three aliases retain one owner; the context must release it exactly once.
    out->flat_buffer = (id<MTLBuffer>)owner;
    out->output_buffer = (id<MTLBuffer>)owner;
    out->command = (id<MTLCommandBuffer>)owner;
    return true;
}

static bool completed_context(void) {
    const uint32_t before = released_owners;
    {
        StwoZigQuotientPreparation prepared = {0};
        if (!transfer_owner(&prepared, false)) return false;
        if (released_owners != before) return false;
        if ([prepared.flat_buffer class] != [StwoZigQuotientLifetimeProbe class] ||
            [prepared.output_buffer class] != [StwoZigQuotientLifetimeProbe class] ||
            [prepared.command class] != [StwoZigQuotientLifetimeProbe class]) return false;
    }
    return released_owners == before + 1u;
}

static bool rejected_before_transfer(void) {
    const uint32_t before = released_owners;
    {
        StwoZigQuotientPreparation prepared = {0};
        if (transfer_owner(&prepared, true)) return false;
        if (prepared.flat_buffer != nil || prepared.output_buffer != nil ||
            prepared.command != nil) return false;
    }
    return released_owners == before + 1u;
}

static void abort_after_transfer(void) {
    StwoZigQuotientPreparation prepared = {0};
    if (!transfer_owner(&prepared, false)) return;
    // A caller's failure after preparation has the same destruction obligation.
    return;
}

int main(void) {
    @autoreleasepool {
        for (uint32_t i = 0u; i < 1000u; ++i) {
            if (!completed_context() || !rejected_before_transfer()) return 1;
            const uint32_t before = released_owners;
            abort_after_transfer();
            if (released_owners != before + 1u) return 2;
        }
    }
    return released_owners == 3000u ? 0 : 3;
}
