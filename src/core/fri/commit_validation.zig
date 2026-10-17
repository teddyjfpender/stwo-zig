//! Proof-controlled FRI shape checks performed before transcript mutation.

const std = @import("std");
const config_mod = @import("config.zig");
const circle_domain = @import("../poly/circle/domain.zig");

pub fn validate(
    config: config_mod.FriConfig,
    column_bound: config_mod.CirclePolyDegreeBound,
    inner_layers: usize,
    coefficients: usize,
) config_mod.FriVerificationError!config_mod.LinePolyDegreeBound {
    @setRuntimeSafety(true);
    if (config.n_queries == 0 or config.n_queries > 1024 or
        config.fold_step == 0 or config.fold_step > column_bound.logDegreeBound() or
        config.log_blowup_factor < config_mod.FriConfig.LOG_MIN_BLOWUP_FACTOR or
        config.log_blowup_factor > config_mod.FriConfig.LOG_MAX_BLOWUP_FACTOR or
        config.log_last_layer_degree_bound > config_mod.FriConfig.LOG_MAX_LAST_LAYER_DEGREE_BOUND or
        column_bound.logDegreeBound() > circle_domain.MAX_CIRCLE_DOMAIN_LOG_SIZE or
        column_bound.logDegreeBound() + config.log_blowup_factor > circle_domain.MAX_CIRCLE_DOMAIN_LOG_SIZE)
        return error.InvalidNumFriLayers;
    const initial = column_bound.foldToLineWithStep(config.fold_step) orelse
        return error.InvalidNumFriLayers;
    const remaining = std.math.sub(u32, initial.logDegreeBound(), config.log_last_layer_degree_bound) catch
        return error.InvalidNumFriLayers;
    if (inner_layers != config_mod.nFoldSteps(remaining, config.fold_step))
        return error.InvalidNumFriLayers;
    if (coefficients == 0 or !std.math.isPowerOfTwo(coefficients) or
        coefficients > (@as(usize, 1) << @intCast(config.log_last_layer_degree_bound)))
        return error.LastLayerDegreeInvalid;
    return initial;
}
