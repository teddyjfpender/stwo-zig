//! Canonical columns for the CPU-visible APU access AIR leaf.

pub const REGISTER_COUNT: usize = 48;
pub const ADDRESS_COUNT: usize = REGISTER_COUNT;
pub const VALUE_BITS: usize = 8;
pub const WAVE_BYTES: usize = 16;

pub const STATE_REGISTER_OFFSET: usize = 0;
pub const STATE_ENABLED_OFFSET: usize = STATE_REGISTER_OFFSET + REGISTER_COUNT;
pub const STATE_STATUS_KNOWN_OFFSET: usize = STATE_ENABLED_OFFSET + 1;
pub const STATE_STATUS_BITS_OFFSET: usize = STATE_STATUS_KNOWN_OFFSET + 1;
pub const STATE_WAVE_MODE_OFFSET: usize = STATE_STATUS_BITS_OFFSET + 4;
pub const STATE_WAVE_CURRENT_BITS_OFFSET: usize = STATE_WAVE_MODE_OFFSET + 4;
pub const N_STATE_COLUMNS: usize = STATE_WAVE_CURRENT_BITS_OFFSET + 4;

pub const WAVE_INACTIVE: usize = 0;
pub const WAVE_BLOCKED: usize = 1;
pub const WAVE_CURRENT: usize = 2;
pub const WAVE_UNKNOWN: usize = 3;

pub const ACTIVE_OFFSET: usize = 0;
pub const READ_ADDRESS_OFFSET: usize = ACTIVE_OFFSET + 1;
pub const WRITE_ADDRESS_OFFSET: usize = READ_ADDRESS_OFFSET + ADDRESS_COUNT;
pub const WRITE_VALUE_BITS_OFFSET: usize = WRITE_ADDRESS_OFFSET + ADDRESS_COUNT;
pub const READ_VALUE_BITS_OFFSET: usize = WRITE_VALUE_BITS_OFFSET + VALUE_BITS;
pub const WAVE_READ_TARGET_OFFSET: usize = READ_VALUE_BITS_OFFSET + VALUE_BITS;
pub const WAVE_WRITE_TARGET_OFFSET: usize = WAVE_READ_TARGET_OFFSET + WAVE_BYTES;
pub const POWER_OFF_OFFSET: usize = WAVE_WRITE_TARGET_OFFSET + WAVE_BYTES;
pub const POWER_ON_OFFSET: usize = POWER_OFF_OFFSET + 1;
pub const TRIGGER_OFFSET: usize = POWER_ON_OFFSET + 1;
pub const WAVE_TRIGGER_OFFSET: usize = TRIGGER_OFFSET + 1;
pub const DAC_DISABLE_OFFSET: usize = WAVE_TRIGGER_OFFSET + 1;
pub const HIGH_NONZERO_OFFSET: usize = DAC_DISABLE_OFFSET + 4;
pub const HIGH_INVERSE_OFFSET: usize = HIGH_NONZERO_OFFSET + 1;
pub const BEFORE_STATE_OFFSET: usize = HIGH_INVERSE_OFFSET + 1;
pub const BEFORE_REGISTER_BITS_OFFSET: usize = BEFORE_STATE_OFFSET + N_STATE_COLUMNS;
pub const AFTER_STATE_OFFSET: usize = BEFORE_REGISTER_BITS_OFFSET +
    REGISTER_COUNT * VALUE_BITS;
pub const N_MAIN_COLUMNS: usize = AFTER_STATE_OFFSET + N_STATE_COLUMNS;

pub fn stateRegister(offset: usize, register: usize) usize {
    return offset + STATE_REGISTER_OFFSET + register;
}

pub fn stateEnabled(offset: usize) usize {
    return offset + STATE_ENABLED_OFFSET;
}

pub fn stateStatusKnown(offset: usize) usize {
    return offset + STATE_STATUS_KNOWN_OFFSET;
}

pub fn stateStatusBit(offset: usize, bit: usize) usize {
    return offset + STATE_STATUS_BITS_OFFSET + bit;
}

pub fn stateWaveMode(offset: usize, mode: usize) usize {
    return offset + STATE_WAVE_MODE_OFFSET + mode;
}

pub fn stateWaveCurrentBit(offset: usize, bit: usize) usize {
    return offset + STATE_WAVE_CURRENT_BITS_OFFSET + bit;
}

pub fn beforeRegisterBit(register: usize, bit: usize) usize {
    return BEFORE_REGISTER_BITS_OFFSET + register * VALUE_BITS + bit;
}
