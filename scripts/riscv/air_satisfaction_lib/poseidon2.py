"""Small independent Poseidon2-M31 witness schedule for the infrastructure AIR.

The constants are a deliberate transcription of the pinned Stark-V parameters,
not imported from Zig.  Comparing all 445 committed cells against `fill` makes
constant, round-order, materialisation, and output-column drift observable.
"""

from __future__ import annotations

from .field import P

WIDTH = 16
N_TEMPORARIES = 426
N_MAIN_COLUMNS = 445
INPUT_START = 1
TEMP_START = INPUT_START + WIDTH
OUTPUT_START = TEMP_START + N_TEMPORARIES - WIDTH
WIDE_COLUMN = TEMP_START + N_TEMPORARIES
IO_COLUMN = WIDE_COLUMN + 1

EXTERNAL_ROUNDS = (
    (
        1988864850, 1893772157, 1025928330, 1839472709,
        1611656994, 1104858731, 1694088660, 1564660990,
        1991332205, 1875486487, 1890340790, 1658614,
        582370530, 528029397, 1196956642, 655401251,
    ),
    (
        1652877415, 26032894, 1576640243, 1277052539,
        1450142396, 697623591, 1401580866, 1568404175,
        2145004971, 265835716, 1183985610, 1031234465,
        436012490, 172735299, 352802897, 1032863094,
    ),
    (
        757665783, 1082171296, 1507509996, 309929890,
        1807683232, 43258895, 611592566, 1854193793,
        575164234, 894217817, 72613857, 1061659596,
        8921166, 1617355017, 998001536, 1800758877,
    ),
    (
        1002748055, 1935405944, 1351462722, 411368491,
        1913975372, 1956167178, 442558016, 855898408,
        699687798, 1553382248, 1708169125, 490049183,
        1251643415, 1193594742, 880473871, 511174042,
    ),
    (
        1460209171, 530850056, 398192464, 536338716,
        75179210, 1309934197, 1335920373, 127611036,
        291093831, 1832379621, 123571662, 303176864,
        2137685056, 1759609530, 1418928155, 71608334,
    ),
    (
        6616262, 1684515814, 1721194338, 720801691,
        878392254, 460379263, 87930647, 940673483,
        1136203256, 551499412, 256220454, 2007034235,
        796124985, 410436345, 1705042586, 1286336446,
    ),
    (
        1522340456, 1295296352, 309794713, 1772145068,
        956898901, 2137070800, 988829146, 2059451359,
        1846491684, 1105442551, 1236497773, 1452000568,
        549485016, 385992492, 1987107948, 1514377269,
    ),
    (
        2090065934, 1444920141, 293113979, 41120774,
        855319793, 1663284746, 1789994008, 1120509162,
        358222743, 1406256810, 735183687, 664485235,
        1331641456, 38121324, 595810771, 1234594393,
    ),
)

INTERNAL_ROUNDS = (
    2139014335, 69309039, 1368974953, 886780232, 1130937085,
    1718115455, 2027103386, 1612216449, 1994053242, 110146615,
    514413329, 1088763546, 955319292, 488794657,
)

INTERNAL_MATRIX = (
    129501892, 1809435443, 1223573407, 1331944729,
    415581875, 1526242955, 1341275624, 1333308150,
    1404946132, 1549369918, 709303410, 1284988537,
    1490838740, 115945821, 754131590, 800486749,
)


def _m4(values: list[int]) -> list[int]:
    t0 = values[0] + values[1]
    t1 = values[2] + values[3]
    t2 = 2 * values[1] + t1
    t3 = 2 * values[3] + t0
    t4 = 4 * t1 + t3
    t5 = 4 * t0 + t2
    return [(t3 + t5) % P, t5 % P, (t2 + t4) % P, t4 % P]


def _external_matrix(state: list[int]) -> None:
    for block in range(4):
        start = 4 * block
        state[start : start + 4] = _m4(state[start : start + 4])
    for lane in range(4):
        lane_sum = sum(state[lane + 4 * block] for block in range(4)) % P
        for block in range(4):
            index = lane + 4 * block
            state[index] = (state[index] + lane_sum) % P


def _internal_matrix(state: list[int]) -> None:
    state_sum = sum(state) % P
    for lane, coefficient in enumerate(INTERNAL_MATRIX):
        state[lane] = (state[lane] * coefficient + state_sum) % P


def fill(inputs: tuple[int, ...] | list[int]) -> tuple[int, ...]:
    """Return the exact active narrow-mode 445-cell row."""
    if len(inputs) != WIDTH or any(not 0 <= value < P for value in inputs):
        raise ValueError("Poseidon2 input must be sixteen canonical M31 values")

    row = [0] * N_MAIN_COLUMNS
    row[0] = 1
    row[INPUT_START : INPUT_START + WIDTH] = inputs
    state = list(inputs)
    _external_matrix(state)
    cursor = TEMP_START

    # The first full round materialises x^2 and x^4 but not x.
    sboxed = [0] * WIDTH
    for lane, constant in enumerate(EXTERNAL_ROUNDS[0]):
        x = (state[lane] + constant) % P
        x2 = x * x % P
        x4 = x2 * x2 % P
        row[cursor + 2 * lane] = x2
        row[cursor + 2 * lane + 1] = x4
        sboxed[lane] = x * x4 % P
    state = sboxed
    _external_matrix(state)
    cursor += 2 * WIDTH

    for round_constants in EXTERNAL_ROUNDS[1:4]:
        for lane, constant in enumerate(round_constants):
            x = (state[lane] + constant) % P
            x2 = x * x % P
            x4 = x2 * x2 % P
            row[cursor + 3 * lane : cursor + 3 * lane + 3] = (x, x2, x4)
            state[lane] = x * x4 % P
        _external_matrix(state)
        cursor += 3 * WIDTH

    for constant in INTERNAL_ROUNDS:
        x = (state[0] + constant) % P
        x2 = x * x % P
        x4 = x2 * x2 % P
        row[cursor : cursor + 3] = (x, x2, x4)
        state[0] = x * x4 % P
        _internal_matrix(state)
        cursor += 3

    for round_constants in EXTERNAL_ROUNDS[4:]:
        for lane, constant in enumerate(round_constants):
            x = (state[lane] + constant) % P
            x2 = x * x % P
            x4 = x2 * x2 % P
            row[cursor + 3 * lane : cursor + 3 * lane + 3] = (x, x2, x4)
            state[lane] = x * x4 % P
        _external_matrix(state)
        cursor += 3 * WIDTH

    if cursor != OUTPUT_START:
        raise AssertionError(f"Poseidon2 materialisation cursor drifted to {cursor}")
    row[cursor : cursor + WIDTH] = state
    cursor += WIDTH
    if cursor != WIDE_COLUMN:
        raise AssertionError(f"Poseidon2 output cursor drifted to {cursor}")
    return tuple(row)


def residuals(row: tuple[int, ...] | list[int], is_active: int) -> tuple[int, ...]:
    """Evaluate the 430 generated constraints plus the three protocol-shell
    constraints over M31, following committed intermediates exactly.
    """
    if len(row) != N_MAIN_COLUMNS:
        raise ValueError(f"Poseidon2 row has {len(row)} cells, expected {N_MAIN_COLUMNS}")
    enabler = row[0]
    state = list(row[INPUT_START : INPUT_START + WIDTH])
    _external_matrix(state)
    cursor = TEMP_START
    result = [enabler * (1 - enabler) % P]

    sboxed = [0] * WIDTH
    for lane, constant in enumerate(EXTERNAL_ROUNDS[0]):
        x = (state[lane] + constant) % P
        x2 = row[cursor + 2 * lane]
        x4 = row[cursor + 2 * lane + 1]
        result.append(enabler * (x2 - x * x) % P)
        result.append(enabler * (x4 - x2 * x2) % P)
        sboxed[lane] = x * x4 % P
    state = sboxed
    _external_matrix(state)
    cursor += 2 * WIDTH

    for round_constants in EXTERNAL_ROUNDS[1:4]:
        for lane, constant in enumerate(round_constants):
            x = row[cursor + 3 * lane]
            x2 = row[cursor + 3 * lane + 1]
            x4 = row[cursor + 3 * lane + 2]
            result.append(enabler * (x - state[lane] - constant) % P)
            result.append(enabler * (x2 - x * x) % P)
            result.append(enabler * (x4 - x2 * x2) % P)
            state[lane] = x * x4 % P
        _external_matrix(state)
        cursor += 3 * WIDTH

    for constant in INTERNAL_ROUNDS:
        x, x2, x4 = row[cursor : cursor + 3]
        result.append(enabler * (x - state[0] - constant) % P)
        result.append(enabler * (x2 - x * x) % P)
        result.append(enabler * (x4 - x2 * x2) % P)
        state[0] = x * x4 % P
        _internal_matrix(state)
        cursor += 3

    for round_constants in EXTERNAL_ROUNDS[4:]:
        for lane, constant in enumerate(round_constants):
            x = row[cursor + 3 * lane]
            x2 = row[cursor + 3 * lane + 1]
            x4 = row[cursor + 3 * lane + 2]
            result.append(enabler * (x - state[lane] - constant) % P)
            result.append(enabler * (x2 - x * x) % P)
            result.append(enabler * (x4 - x2 * x2) % P)
            state[lane] = x * x4 % P
        _external_matrix(state)
        cursor += 3 * WIDTH

    for lane in range(WIDTH):
        result.append(enabler * (row[cursor + lane] - state[lane]) % P)
    cursor += WIDTH
    if cursor != WIDE_COLUMN:
        raise AssertionError(f"Poseidon2 residual cursor drifted to {cursor}")

    wide, io = row[WIDE_COLUMN], row[IO_COLUMN]
    result.extend(
        (
            wide * (1 - wide) % P,
            io * (1 - io) % P,
            wide * io % P,
            (enabler - is_active) % P,
            wide % P,
            io % P,
        )
    )
    if len(result) != 433:
        raise AssertionError(f"Poseidon2 residual count drifted to {len(result)}")
    return tuple(result)
