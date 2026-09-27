//! Legacy B5SC API, exact shared typed ownership/grammar specialization.
//! New raw/fold protocols remain distinct; no proof authority is added.
const Impl = @import("block_v5_memory_source_legacy_schema_v1.zig").Protocol;
pub const TAG = Impl.TAG;
pub const VERSION = Impl.VERSION;
pub const FIXED_COUNT = Impl.FIXED_COUNT;
pub const MAIN_COUNT = Impl.MAIN_COUNT;
pub const Limits = Impl.Limits;
pub const Page = Impl.Page;
pub const Plan = Impl.Plan;
pub const abiId = Impl.abiId;
pub const init = Impl.init;
pub const Pin = Impl.Pin;
pub const firstChannel = Impl.firstChannel;
pub const Sealed = Impl.Sealed;
pub const seal = Impl.seal;
pub const draw = Impl.draw;
pub const drawFromChannel = Impl.drawFromChannel;
pub const admitChunk = Impl.admitChunk;
pub const PageAdmission = Impl.PageAdmission;
pub const admitPage = Impl.admitPage;
