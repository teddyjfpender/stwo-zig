// xlat_difffuzz.cpp: differential fuzzer for the translated-segment dispatch (patch 0023).
//
// Extends ziskethone's cpp-guest/test/fused_dispatch_difffuzz.cpp (Apache-2.0 OR MIT): the
// same VM runs random bytecode three ways and everything observable must match:
//   xlat   dispatch_xlat (patch 0023): segment translation, per-segment gas/stack checks
//   fused  dispatch_cgoto with ziskethone's fused jumps (set_option("xlat", "no"))
//   plain  evmone's switch dispatch, per-opcode checks, no fusion (set_option("cgoto", "no"))
// Compared: status, gas_left, gas_refund, output, and the host's view (storage, transient
// storage, logs, recorded calls).
//
// The generator is biased toward what the translation changes: segment boundaries
// (JUMPDEST fall-through, splits of long runs and of runs growing the stack by more than
// 32), the fused control-flow patterns with valid and invalid targets, opcodes that take
// gas (memory growth to out-of-gas, SLOAD/SSTORE, GAS, CALL, LOG, KECCAK256, EXP), PC,
// truncated PUSH data at the code end, opcodes undefined in older revisions, deep stacks
// near 1024 and tight gas. Each program's analysis is reused for several gas limits and
// revisions, so cached translations and patched jump records are exercised too.
//
//   xlat_difffuzz ITERATIONS [SEED]     exit 0 == no divergence

#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>
#include <lib/evmone/baseline.hpp>
#include <lib/evmone/vm.hpp>

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <random>
#include <string>
#include <utility>
#include <vector>

extern "C" [[noreturn]] void stwo_guest_abort(const char* why) noexcept
{
    std::fprintf(stderr, "abort %s\n", why);
    std::abort();
}

namespace
{
using Bytes = std::vector<uint8_t>;

enum : uint8_t
{
    OP_STOP = 0x00, OP_ADD = 0x01, OP_MUL = 0x02, OP_SUB = 0x03, OP_DIV = 0x04, OP_EXP = 0x0a,
    OP_LT = 0x10, OP_GT = 0x11, OP_SLT = 0x12, OP_SGT = 0x13, OP_EQ = 0x14, OP_ISZERO = 0x15,
    OP_AND = 0x16, OP_SHL = 0x1b, OP_CLZ = 0x1e, OP_KECCAK256 = 0x20,
    OP_CALLDATALOAD = 0x35, OP_POP = 0x50, OP_MLOAD = 0x51, OP_MSTORE = 0x52, OP_MSTORE8 = 0x53,
    OP_SLOAD = 0x54, OP_SSTORE = 0x55, OP_JUMP = 0x56, OP_JUMPI = 0x57, OP_PC = 0x58,
    OP_MSIZE = 0x59, OP_GAS = 0x5a, OP_JUMPDEST = 0x5b, OP_TLOAD = 0x5c, OP_TSTORE = 0x5d,
    OP_MCOPY = 0x5e, OP_PUSH0 = 0x5f, OP_PUSH1 = 0x60, OP_PUSH2 = 0x61, OP_PUSH4 = 0x63,
    OP_PUSH32 = 0x7f, OP_DUP1 = 0x80, OP_SWAP1 = 0x90, OP_LOG0 = 0xa0, OP_DUPN = 0xe6,
    OP_CALL = 0xf1, OP_RETURN = 0xf3, OP_REVERT = 0xfd, OP_INVALID = 0xfe,
};

Bytes gen(std::mt19937_64& rng)
{
    std::uniform_int_distribution<int> pick(0, 999);
    std::uniform_int_distribution<int> byte(0, 255);
    Bytes c;
    std::vector<int> dests;
    int sp = 0;
    const int len = 10 + (int)(rng() % 300);

    auto push1 = [&](int v) { c.push_back(OP_PUSH1); c.push_back((uint8_t)v); ++sp; };
    auto need = [&](int n) { while (sp < n) push1(byte(rng)); };
    auto bin = [&](uint8_t op) { need(2); c.push_back(op); --sp; };
    auto un = [&](uint8_t op) { need(1); c.push_back(op); };
    auto pushn = [&](int n) {  // PUSHn with random data (n = 0: PUSH0)
        c.push_back((uint8_t)(OP_PUSH0 + n));
        for (int k = 0; k < n; ++k) c.push_back((uint8_t)byte(rng));
        ++sp;
    };
    auto target = [&]() -> int {
        return (!dests.empty() && pick(rng) < 750) ? dests[rng() % dests.size()]
                                                   : (int)(rng() % 400);
    };
    auto push_target = [&](int t) {
        if (t < 256 && pick(rng) < 300) push1(t);
        else { c.push_back(OP_PUSH2); c.push_back((uint8_t)(t >> 8)); c.push_back((uint8_t)t); ++sp; }
    };
    // A memory offset: small, beyond the current page, or absurd (out of gas).
    auto push_offset = [&]() {
        const int r = pick(rng);
        if (r < 700) push1(byte(rng) & ~7);
        else if (r < 850) push1(byte(rng));
        else if (r < 950) { c.push_back(OP_PUSH2); c.push_back((uint8_t)byte(rng)); c.push_back((uint8_t)byte(rng)); ++sp; }
        else { c.push_back(OP_PUSH4 + 1); for (int k = 0; k < 5; ++k) c.push_back((uint8_t)byte(rng)); ++sp; }
    };

    if (pick(rng) < 80)  // park near the 1024 limit
    {
        const int n = 990 + (int)(rng() % 40);
        for (int i = 0; i < n; ++i) push1(byte(rng));
    }

    for (int i = 0; i < len; ++i)
    {
        const int r = pick(rng);
        if (r < 130) push1(byte(rng));
        else if (r < 180) pushn((int)(rng() % 33));
        else if (r < 250) { c.push_back(OP_JUMPDEST); dests.push_back((int)c.size() - 1); }
        else if (r < 320)
        {  // PUSH1/PUSH2 <target> JUMP/JUMPI
            push_target(target());
            if (pick(rng) < 500) { need(2); c.push_back(OP_JUMPI); sp -= 2; }
            else { c.push_back(OP_JUMP); --sp; }
        }
        else if (r < 420)
        {  // <test> PUSH JUMPI
            const int k = (int)(rng() % 6);
            if (k == 0) un(OP_ISZERO);
            else
            {
                if (pick(rng) < 500) { push1((int)(rng() % 4)); push1((int)(rng() % 4)); }
                bin(k == 1 ? OP_EQ : k == 2 ? OP_LT : k == 3 ? OP_GT : k == 4 ? OP_SLT : OP_SGT);
            }
            push_target(target());
            need(2); c.push_back(OP_JUMPI); sp -= 2;
        }
        else if (r < 450)
        {  // PUSH4 <sel> EQ PUSH JUMPI
            const uint32_t sel = (uint32_t)rng();
            auto push4 = [&] { c.push_back(OP_PUSH4); for (int k = 3; k >= 0; --k) c.push_back((uint8_t)(sel >> (8 * k))); ++sp; };
            if (pick(rng) < 500) push4(); else need(1);
            push4();
            c.push_back(OP_EQ); --sp;
            push_target(target());
            c.push_back(OP_JUMPI); sp -= 2;
        }
        else if (r < 480)
        {  // dynamic JUMP/JUMPI (target computed on the stack), sometimes with high bits
            if (pick(rng) < 100) pushn(32); else { push_target(target()); c.push_back(OP_DUP1); ++sp; }
            if (pick(rng) < 500) { c.push_back(OP_JUMP); --sp; }
            else { push1(byte(rng) & 1); c.push_back(OP_SWAP1); c.push_back(OP_JUMPI); sp -= 2; }
        }
        else if (r < 560)
        {
            const uint8_t ops[] = {OP_ADD, OP_MUL, OP_SUB, OP_DIV, OP_AND, OP_SHL, OP_LT, OP_EQ};
            bin(ops[rng() % 8]);
        }
        else if (r < 620) { const int k = 1 + (int)(rng() % 16); need(k); c.push_back((uint8_t)(OP_DUP1 + k - 1)); ++sp; }
        else if (r < 680) { const int k = 1 + (int)(rng() % 16); need(k + 1); c.push_back((uint8_t)(OP_SWAP1 + k - 1)); }
        else if (r < 720) { need(1); c.push_back(OP_POP); --sp; }
        else if (r < 770)
        {  // memory: MSTORE/MSTORE8 value offset, MLOAD offset
            const int k = (int)(rng() % 3);
            if (k == 0) { need(1); push_offset(); c.push_back(OP_MSTORE); sp -= 2; }
            else if (k == 1) { need(1); push_offset(); c.push_back(OP_MSTORE8); sp -= 2; }
            else { push_offset(); c.push_back(OP_MLOAD); }
        }
        else if (r < 800)
        {
            push1((int)(rng() % 4));
            if (pick(rng) < 500) { c.push_back(OP_SLOAD); }
            else { need(2); c.push_back(OP_SSTORE); sp -= 2; }
        }
        else if (r < 810)
        {
            push1((int)(rng() % 4));
            if (pick(rng) < 500) c.push_back(OP_TLOAD);
            else { need(2); c.push_back(OP_TSTORE); sp -= 2; }
        }
        else if (r < 840)
        {
            const uint8_t ops[] = {OP_GAS, OP_PC, OP_MSIZE};
            c.push_back(ops[rng() % 3]); ++sp;
        }
        else if (r < 850) { push1(byte(rng) & 63); push_offset(); c.push_back(OP_KECCAK256); --sp; }
        else if (r < 858) { const int t = (int)(rng() % 3); need(t); push1(byte(rng) & 63); push_offset(); c.push_back((uint8_t)(OP_LOG0 + t)); sp -= 2 + t; }
        else if (r < 866)
        {  // CALL gas addr value argsOff argsSize retOff retSize
            for (int k = 0; k < 4; ++k) push1(byte(rng) & 31);
            push1(0); push1((int)(rng() % 3)); push1(byte(rng));
            if (pick(rng) < 500) c.push_back(OP_GAS);
            else push1(byte(rng));
            ++sp;
            c.push_back(OP_CALL); sp -= 6;
        }
        else if (r < 874) { push1(byte(rng) & 15); push1(byte(rng)); c.push_back(OP_EXP); --sp; }
        else if (r < 880) { push1(byte(rng)); c.push_back(OP_CALLDATALOAD); }
        else if (r < 890)
        {  // revision-gated or undefined
            const uint8_t ops[] = {OP_PUSH0, OP_TLOAD, OP_MCOPY, OP_CLZ, OP_DUPN, 0x0c, 0x21, 0x4f, 0xef, OP_INVALID};
            c.push_back(ops[rng() % 10]);
        }
        else if (r < 900)
        {  // a long straight run (split at 96 opcodes) or a deep one (growth > 32)
            const int n = 30 + (int)(rng() % 90);
            if (pick(rng) < 500) for (int k = 0; k < n; ++k) push1(byte(rng));
            else for (int k = 0; k < n; ++k) { push1(byte(rng)); bin(OP_ADD); }
        }
        else if (r < 910) { c.push_back(OP_JUMPDEST); dests.push_back((int)c.size() - 1); push1(byte(rng)); c.push_back(OP_JUMPDEST); dests.push_back((int)c.size() - 1); }
        else if (r < 920) { c.push_back((uint8_t)byte(rng)); }
        else if (r < 1000) { need(1); c.push_back(OP_ISZERO); }
    }
    const int end = pick(rng);
    if (end < 400) { push1(0x20); push1(0x00); c.push_back(OP_RETURN); }
    else if (end < 550) { push1(0x20); push1(0x00); c.push_back(OP_REVERT); }
    else if (end < 650) c.push_back(OP_STOP);
    else if (end < 800) { c.push_back(OP_PUSH32); for (int k = 0; k < (int)(rng() % 32); ++k) c.push_back((uint8_t)byte(rng)); }
    else if (end < 900) { c.push_back(OP_PUSH2); }  // truncated, then off the end
    return c;
}

struct Out
{
    evmc_status_code status;
    int64_t gas_left;
    int64_t gas_refund;
    Bytes output;
    std::string host;  // serialized host effects
};

std::string host_view(const evmc::MockedHost& h)
{
    std::string s;
    std::map<std::string, std::string> st;
    for (const auto& [addr, acc] : h.accounts)
    {
        for (const auto& [k, v] : acc.storage)
            st[std::string(reinterpret_cast<const char*>(k.bytes), 32)] =
                std::string(reinterpret_cast<const char*>(v.current.bytes), 32);
        for (const auto& [k, v] : acc.transient_storage)
            st["t" + std::string(reinterpret_cast<const char*>(k.bytes), 32)] =
                std::string(reinterpret_cast<const char*>(v.bytes), 32);
    }
    for (const auto& [k, v] : st) s += k + v;
    s += "|logs" + std::to_string(h.recorded_logs.size());
    for (const auto& l : h.recorded_logs)
    {
        s.append(reinterpret_cast<const char*>(l.data.data()), l.data.size());
        s += std::to_string(l.topics.size());
    }
    s += "|calls" + std::to_string(h.recorded_calls.size());
    for (const auto& m : h.recorded_calls)
        s += std::to_string(m.gas) + "," + std::to_string(m.input_size) + ";";
    return s;
}

Out run(evmone::VM& vm, const evmone::baseline::CodeAnalysis& analysis, int64_t gas,
    evmc_revision rev, const Bytes& calldata)
{
    evmc::MockedHost host;
    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.gas = gas;
    msg.recipient = evmc_address{{0x01}};
    msg.sender = evmc_address{{0x02}};
    msg.input_data = calldata.data();
    msg.input_size = calldata.size();
    host.accounts[msg.recipient];
    evmc::Result r{evmone::baseline::execute(
        vm, evmc::Host::get_interface(), host.to_context(), rev, msg, analysis)};
    Bytes output;
    if (r.output_size != 0)
        output.assign(r.output_data, r.output_data + r.output_size);
    return {r.status_code, r.gas_left, r.gas_refund, std::move(output), host_view(host)};
}

void dump(const char* name, const Out& o)
{
    std::printf("  %s: status=%d gas_left=%ld refund=%ld outlen=%zu hostlen=%zu\n", name,
        (int)o.status, (long)o.gas_left, (long)o.gas_refund, o.output.size(), o.host.size());
}
}  // namespace

int main(int argc, char** argv)
{
    const long iters = (argc > 1) ? std::atol(argv[1]) : 100000;
    const uint64_t seed = (argc > 2) ? std::stoull(argv[2]) : 12345;

    auto* xlat_vm = static_cast<evmone::VM*>(evmc_create_evmone());
    auto* fused_vm = static_cast<evmone::VM*>(evmc_create_evmone());
    auto* plain_vm = static_cast<evmone::VM*>(evmc_create_evmone());
    // Without the (parked, unapplied) translated-segment patch there is no "xlat"
    // option: the default VM is then the fused cgoto dispatch, and only fused vs
    // plain is compared.
    const auto xo = fused_vm->set_option(fused_vm, "xlat", "no");
    const bool has_xlat = xo == EVMC_SET_OPTION_SUCCESS;
    if ((!has_xlat && xo != EVMC_SET_OPTION_INVALID_NAME) ||
        plain_vm->set_option(plain_vm, "cgoto", "no") != EVMC_SET_OPTION_SUCCESS)
    {
        std::fprintf(stderr, "evmone built without cgoto dispatch; nothing to compare\n");
        return 2;
    }
    if (!has_xlat)
        std::printf("no xlat dispatch in this build: comparing fused cgoto vs plain switch\n");

    std::mt19937_64 rng(seed);
    long mismatches = 0, runs = 0;
    for (long i = 0; i < iters && mismatches < 5; ++i)
    {
        const auto code = gen(rng);
        const auto analysis = evmone::baseline::analyze({code.data(), code.size()});
        Bytes calldata(rng() % 80);
        for (auto& b : calldata) b = (uint8_t)rng();
        // Several gas limits (tight ones die mid-segment) and revisions on one analysis.
        for (int k = 0; k < 4; ++k)
        {
            const auto rev = static_cast<evmc_revision>(rng() % (EVMC_MAX_REVISION + 1));
            const int64_t gas = (k == 0) ? (int64_t)(rng() % 400) + 1 :
                                (k == 1) ? (int64_t)(rng() % 5000) + 1 :
                                           (int64_t)(rng() % 200000) + 1;
            const auto b = run(*plain_vm, analysis, gas, rev, calldata);
            const auto f = run(*fused_vm, analysis, gas, rev, calldata);
            const auto a = has_xlat ? run(*xlat_vm, analysis, gas, rev, calldata) : f;
            ++runs;
            const auto same = [](const Out& x, const Out& y) {
                return x.status == y.status && x.gas_left == y.gas_left &&
                       x.gas_refund == y.gas_refund && x.output == y.output && x.host == y.host;
            };
            if (!same(a, b) || !same(f, b))
            {
                ++mismatches;
                std::printf("MISMATCH iter=%ld k=%d rev=%d gas=%ld\n", i, k, (int)rev, (long)gas);
                dump("xlat ", a);
                dump("fused", f);
                dump("plain", b);
                std::printf("  code=");
                for (auto x : code) std::printf("%02x", x);
                std::printf("\n");
                std::fflush(stdout);
                break;
            }
        }
    }
    std::printf("%ld programs, %ld runs, %ld mismatches\n", iters, runs, mismatches);
    return mismatches == 0 ? 0 : 1;
}
