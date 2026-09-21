//! Canonical VM claim geometry, independent of witness generation.
const std = @import("std");
const m31 = @import("stwo_core").fields.m31;

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const FIXED_CLAIM_WORDS: usize = 259;
pub const INPUT_SLOT_WORDS: usize = 3;
pub const OUTPUT_SLOT_WORDS: usize = 7;

pub const Error = error{ ArithmeticOverflow, InvalidShape, LogSizeOutOfRange };

pub const Shape = struct {
    max_input_words: u32,
    max_output_words: u32,

    pub fn init(max_input_words: u32, max_output_words: u32) Error!Shape {
        const result = Shape{
            .max_input_words = max_input_words,
            .max_output_words = max_output_words,
        };
        _ = try result.wordCount();
        return result;
    }

    pub fn wordCount(self: Shape) Error!usize {
        if (self.max_input_words >= m31.Modulus or
            self.max_output_words >= m31.Modulus)
        {
            return error.InvalidShape;
        }
        const input = std.math.mul(
            usize,
            self.max_input_words,
            INPUT_SLOT_WORDS,
        ) catch return error.ArithmeticOverflow;
        const output = std.math.mul(
            usize,
            self.max_output_words,
            OUTPUT_SLOT_WORDS,
        ) catch return error.ArithmeticOverflow;
        const count = std.math.add(
            usize,
            std.math.add(usize, FIXED_CLAIM_WORDS, input) catch
                return error.ArithmeticOverflow,
            output,
        ) catch return error.ArithmeticOverflow;
        if (count == 0 or count > (@as(usize, 1) << MAX_LOG_SIZE) or
            count - 1 >= m31.Modulus)
        {
            return error.LogSizeOutOfRange;
        }
        return count;
    }
};
