-- GENERATED FILE. DO NOT EDIT.
-- Generator: scratch `gen_div_program.py` (O5 for issue #137), adapted from the
-- O1/O2 generators that emitted `MulProgram.lean` and `MulhProgram.lean`.
-- Data source: /tmp/tb-ir/div.json, sha256
--   430a06a8919e469251deab180b492e89a4a6452de0014b2b0c3ea6c350912e4d
-- which is the export `RiscvRefinement/Air/Family/Div.lean` pins as
-- `divIrDigest`.
--
-- The node algebra (`Node`), the field (`M31`), the localisation
-- (`Node.localise` / `localiseNodes`) and the evaluator (`nth` / `evalLoop`)
-- all come from `MulProgram.lean` unchanged, so the three families are
-- interpreted by literally the same evaluator, and `EvaluatorSpec.lean` proves
-- that evaluator equal to Team A's push-accumulator one for all three.
--
-- What this file adds on top of them:
--
-- 1. A seventh relation domain. `div` requests `range_check_8_8` in addition
--    to everything `mul` and `mulh` request. `Domain` (5 constructors) and
--    `MulhDomain` (6) are inductives and cannot be extended after the fact, so
--    the lookup/program records are re-declared as `DivLookup` / `DivCircuit`.
--    `rangeCheck88Contains` is transcribed from `checkedIndex` in
--    `src/frontends/riscv/air/lookups/tables/schema.zig`: the `range_check_8_8`
--    table accepts `(lo, hi)` with `lo < 256` and `hi < 256`.
--
-- 2. Numerator gating on fixed-table membership, exactly as `mulh` needs it.
--    Two of the 25 `div` lookups carry numerators that vanish on some rows:
--    lookup 19 (`quotient_sign_range`) is dead on unsigned rows, on
--    zero-divisor rows and on the both-operands-negative class, and lookup 21
--    (`positive_remainder_diff`) is dead on both special-case branches. A LogUp
--    term with a zero numerator contributes nothing to the bus sum, so the
--    production system does not require its tuple to be in the table -- and on
--    those rows the tuples genuinely are out of range. `fixedRequestsHold`
--    below therefore reads "every request with a non-zero numerator lands in
--    its table".
--
-- 3. The three inverse-witness tables. `div` commits five prover-chosen field
--    inverses that `DivRow` does not carry (`c_sum_inv`, `r_sum_inv`,
--    `r_inv_0..3`), and `DivBridge.divColumns` has to synthesise them. Since
--    the values being inverted are all small -- a four-byte limb sum is at most
--    1020, and `r_abs_i - 256` ranges over `2^31 - 257 .. 2^31 - 2` -- they are
--    supplied as tables and checked by evaluation rather than asserted. The
--    checker `inverseOk` walks a table once (O(n), unlike an indexed
--    `∀ i < n` sweep, which is O(n^2) in the kernel), and `inverseOk_spec`
--    turns one `decide` into the pointwise fact at every index.

-- `rangeCheckM31Contains` is already transcribed in `MulhProgram.lean`; this
-- file imports it rather than restating it, so the two families share one
-- reading of that table.
import RiscvRefinement.Air.Bridge.MulhProgram

namespace RiscvRefinement.Air.Bridge

/-! ## The `div` circuit record -/

/-- The relation domains the `div` family requests. `mul` uses five of these,
`mulh` six; `range_check_8_8` is the one this family adds. A models all
twelve. -/
inductive DivDomain where
  | programAccess
  | registersState
  | memoryAccess
  | rangeCheck20
  | rangeCheck811
  | rangeCheck88
  | rangeCheckM31
deriving DecidableEq, Repr

structure DivLookup where
  domain : DivDomain
  role : Role
  numerator : Nat
  tuple : List Nat
deriving DecidableEq, Repr

structure DivCircuit where
  family : String
  modulus : Nat
  columns : List String
  nodes : List Node
  nodeCount : Nat
  constraints : List Nat
  lookups : List DivLookup
deriving DecidableEq, Repr

/-- A's decoder side condition, verbatim from `Program.wellFormed`. -/
def DivCircuit.wellFormed (circuit : DivCircuit) : Bool :=
  let nodeCount := circuit.nodes.length
  decide (circuit.modulus = m31Modulus) &&
    decide (circuit.nodeCount = nodeCount) &&
    nodesWellFormed circuit.columns.length 0 circuit.nodes &&
    circuit.constraints.all (fun root => decide (root < nodeCount)) &&
    circuit.lookups.all (fun entry =>
      decide (entry.numerator < nodeCount) &&
        entry.tuple.all (fun node => decide (node < nodeCount)))

def DivCircuit.localise (circuit : DivCircuit) : DivCircuit :=
  { circuit with nodes := localiseNodes 0 circuit.nodes }

def DivCircuit.nodeValuesRev (circuit : DivCircuit) (columns : List M31) : List M31 :=
  evalLoop columns [] circuit.nodes

def DivCircuit.value (circuit : DivCircuit) (columns : List M31) (index : Nat) : M31 :=
  nth (circuit.nodeValuesRev columns) (circuit.nodeCount - 1 - index)

def DivCircuit.values
    (circuit : DivCircuit) (columns : List M31) (indices : List Nat) : List M31 :=
  indices.map (circuit.value columns)

def DivCircuit.constraintValues (circuit : DivCircuit) (columns : List M31) : List M31 :=
  circuit.values columns circuit.constraints

def DivCircuit.lookupTuple
    (circuit : DivCircuit) (columns : List M31) (entry : DivLookup) : List M31 :=
  circuit.values columns entry.tuple

def DivCircuit.lookupNumerator
    (circuit : DivCircuit) (columns : List M31) (entry : DivLookup) : M31 :=
  circuit.value columns entry.numerator

/-- Membership in the `range_check_8_8` preprocessed table, transcribed from
`checkedIndex` in `air/lookups/tables/schema.zig`. -/
def rangeCheck88Contains : List M31 → Bool
  | [low, high] => decide (low.toNat < 256) && decide (high.toNat < 256)
  | _ => false

/-- One request lands inside the fixed table it names. Requests against the
three bus relations are not fixed-table requests and impose nothing here. -/
def DivCircuit.fixedRequestHolds
    (circuit : DivCircuit) (columns : List M31) (entry : DivLookup) : Bool :=
  match entry.domain with
  | .rangeCheck20 => rangeCheck20Contains (circuit.lookupTuple columns entry)
  | .rangeCheck811 => rangeCheck811Contains (circuit.lookupTuple columns entry)
  | .rangeCheck88 => rangeCheck88Contains (circuit.lookupTuple columns entry)
  | .rangeCheckM31 => rangeCheckM31Contains (circuit.lookupTuple columns entry)
  | _ => true

/-- Every *live* fixed-table request lands inside its table. -/
def DivCircuit.fixedRequestsHold (circuit : DivCircuit) (columns : List M31) : Bool :=
  circuit.lookups.all fun entry =>
    decide (circuit.lookupNumerator columns entry = 0) ||
      circuit.fixedRequestHolds columns entry

/-! ## Inverse-witness tables

`DivRow` records a prover-chosen inverse only through the fact it witnesses
("this value is nonzero"), so the column assignment has to produce the inverse
itself. These tables do that, and `inverseOk` checks them. -/

/-- Read a `Nat` table at an index, `0` off the end. Structural, so the
specification below is a plain induction. -/
def tableAt : List Nat → Nat → Nat
  | [], _ => 0
  | value :: _, 0 => value
  | _ :: rest, index + 1 => tableAt rest index

/-- `inverseOk value table` says entry `i` of `table` is the `M31` inverse of
`value + i` (entry `0` of a table starting at `value = 0` is unconstrained,
because `0` has no inverse). One left-to-right walk. -/
def inverseOk (value : Nat) : List Nat → Bool
  | [] => true
  | inverse :: rest =>
      (decide (value = 0) || decide ((value * inverse) % m31Modulus = 1)) &&
        inverseOk (value + 1) rest

theorem inverseOk_spec :
    ∀ (table : List Nat) (value offset : Nat),
      inverseOk value table = true → offset < table.length → 0 < value + offset →
      ((value + offset) * tableAt table offset) % m31Modulus = 1 := by
  intro table
  induction table with
  | nil => intro _ _ _ bound _; simp at bound
  | cons entry rest ih =>
      intro value offset ok bound positive
      simp only [inverseOk, Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq] at ok
      cases offset with
      | zero =>
          rcases ok.1 with zero | inverts
          · omega
          · simpa [tableAt] using inverts
      | succ smaller =>
          have shorter : smaller < rest.length := by
            simpa [List.length_cons] using bound
          have step := ih (value + 1) smaller ok.2 shorter (by omega)
          have index : value + 1 + smaller = value + (smaller + 1) := by omega
          rw [index] at step
          simpa [tableAt] using step

/-- Entry `i` is the `M31` inverse of `i`, for every four-byte limb sum
`0 .. 1020`. Entry `0` is unconstrained and is `0`. Used for `c_sum_inv`
and `r_sum_inv`. -/
def limbSumInverseTable : List Nat := [
    0, 1, 1073741824, 1431655765,
    536870912, 858993459, 1789569706, 1840700269,
    268435456, 1908874353, 1503238553, 1952257861,
    894784853, 1486719448, 1994091958, 286331153,
    134217728, 252645135, 2028179000, 1017229096,
    1825361100, 2045222521, 2049870754, 840319688,
    1521134250, 1460288880, 743359724, 636291451,
    997045979, 296204641, 1216907400, 2078209981,
    67108864, 2082408385, 1200064391, 1656630242,
    1014089500, 406280690, 508614548, 1927228914,
    912680550, 733287099, 2096353084, 299648881,
    1024935377, 811271600, 420159844, 319837990,
    760567125, 1796874072, 730144440, 84215045,
    371679862, 1823335172, 1391887549, 1249445031,
    1572264813, 1770732130, 1221844144, 436776335,
    608453700, 1443390648, 2112846814, 2113396605,
    33554432, 726840619, 2114946016, 1314131784,
    1673774019, 995934445, 828315121, 604924971,
    507044750, 1000197863, 203140345, 486762960,
    254307274, 2119594249, 963614457, 625216758,
    456340275, 1643752915, 1440385373, 543339236,
    1048176542, 50529027, 1223566264, 1530390645,
    1586209512, 747999922, 405635800, 1132738627,
    210079922, 2124392425, 159918995, 1062439278,
    1454025386, 2081066627, 898437036, 2125791893,
    365072220, 1105635145, 1115849346, 1125865213,
    185839931, 1268037963, 911667586, 1986924122,
    1769685598, 2029273538, 1698464339, 851254779,
    1859874230, 304068481, 885366065, 597560667,
    610922072, 642409638, 1292129991, 1876792431,
    304226850, 1544058490, 721695324, 244429033,
    1056423407, 292057776, 2130440126, 304367761,
    16777216, 1531538725, 1437162133, 1344226405,
    1057473008, 1679235333, 657065892, 986251749,
    1910628833, 1206979860, 1571709046, 1761245581,
    1487899384, 1538268428, 1376204309, 1306511030,
    253522375, 918234387, 1573840755, 598958024,
    1175311996, 1758342315, 243381480, 2133261901,
    127153637, 743899564, 2133538948, 1274635455,
    1555549052, 1887597091, 312608379, 1323606273,
    1301911961, 733612426, 1895618281, 2015736184,
    1793934510, 416481677, 271669618, 424353056,
    524088271, 444745134, 1099006337, 2021899808,
    611783132, 1142014425, 1838937146, 2049312966,
    793104756, 861419994, 373999961, 1835558648,
    202817900, 1815276232, 1640111137, 481130216,
    105039961, 81256138, 2135938036, 999096670,
    1153701321, 704465535, 531219639, 1214283947,
    727012693, 1580013875, 2114275137, 1673935971,
    449218518, 1547932375, 2136637770, 97122376,
    182536110, 438043928, 1626559396, 655881705,
    557924673, 1435147608, 1636674430, 1763633913,
    1166661789, 1459055875, 1707760805, 1007587114,
    455833793, 201641657, 993462061, 918923235,
    884842799, 2137587409, 1014636769, 1049227170,
    1922973993, 845389490, 1499369213, 1714134929,
    929937115, 162254320, 1225776064, 567616823,
    1516424856, 675191365, 1372522157, 2138187181,
    305461036, 1428583542, 321204819, 63967598,
    1719806819, 208405586, 2012138039, 1868939743,
    152113425, 659393319, 772029245, 1979573403,
    360847662, 2077361732, 1195956340, 78248392,
    1601953527, 896940961, 146028888, 958239715,
    1065220063, 271618485, 1225925704, 16843009,
    8388608, 16711935, 1839511186, 978390233,
    1792322890, 510130215, 1745855026, 939013762,
    528736504, 2082653952, 1913359490, 1680989072,
    328532946, 2051685120, 1566867698, 2068240708,
    2029056240, 1809235307, 603489930, 1108882465,
    785854523, 85279134, 1954364614, 2139786573,
    743949692, 259837879, 769134214, 675357048,
    1761843978, 354146426, 653255515, 411538678,
    1200503011, 141184046, 1532859017, 1409516758,
    1860662201, 901503374, 299479012, 87355267,
    587655998, 1424425180, 1952912981, 64639976,
    121690740, 42806983, 2140372774, 1800200813,
    1137318642, 718174859, 371949782, 993298625,
    1066769474, 1806944169, 1711059551, 1595076278,
    777774526, 1392776934, 2017540369, 422679321,
    1230046013, 1456495218, 1735544960, 807830839,
    1724697804, 1378135923, 366806213, 691449843,
    2021550964, 1433858312, 1007868092, 1392252395,
    896967255, 1272824654, 1281982662, 2140995781,
    135834809, 283751593, 212176528, 1551316545,
    1335785959, 178425941, 222372567, 1533011925,
    1623244992, 2141186041, 1010949904, 256696296,
    305891566, 199186889, 1644749036, 1992765805,
    919468573, 1107584689, 1024656483, 214136546,
    396552378, 383261954, 430709997, 979978453,
    1260741804, 625597477, 917779324, 1088696445,
    101408950, 618665649, 907638116, 1946341928,
    1893797392, 629536302, 240565108, 1925128392,
    1126261804, 1513132109, 40628069, 2101176722,
    1067969018, 92117261, 499548335, 97352592,
    1650592484, 1013931271, 1425974591, 1399547390,
    1339351643, 1533111685, 1680883797, 947584168,
    1437248170, 1712409038, 1863748761, 1942168673,
    2130879392, 1170350985, 1910709809, 1691623947,
    224609259, 1879731233, 1847708011, 554540081,
    1068318885, 1314454726, 48561188, 559745111,
    91268055, 899693897, 219021964, 325053356,
    813279698, 328750583, 1401682676, 1793966683,
    1352704160, 1212881962, 717573804, 402326620,
    818337215, 1596313510, 1955558780, 967661306,
    1657072718, 2018737625, 1803269761, 1414571567,
    1927622226, 1647594342, 503793557, 1228584025,
    1301658720, 1728092723, 1174562652, 206198664,
    1570472854, 1151331559, 1533203441, 14947682,
    1516163223, 1631690808, 2142535528, 306078129,
    1581060208, 44227352, 524613585, 1115321803,
    2035228820, 915480557, 422694745, 1032537284,
    1823426430, 1867586902, 1930809288, 586114105,
    1538710381, 946997243, 81127160, 1042791394,
    612888032, 2142743065, 1357550235, 1944534643,
    758212428, 1569495707, 1411337506, 1679622286,
    1760002902, 740672234, 2142835414, 589050590,
    152730518, 424878485, 714291771, 257514099,
    1234344233, 187733112, 31983799, 2060854795,
    1933645233, 1393821310, 104202793, 641984585,
    2079810843, 441202091, 2008211695, 1439127872,
    1149798536, 2013544958, 1403438483, 1676193240,
    1459756446, 2134200243, 2063528525, 1009802372,
    180423831, 2103567826, 1038680866, 1806335532,
    597978170, 1785939747, 39124196, 854655108,
    1874718587, 86417853, 1522212304, 1846233436,
    73014444, 857278901, 1552861681, 1302152112,
    1606351855, 221127029, 1209551066, 148248378,
    612962852, 523159081, 1082163328, 142885409,
    4194304, 1389794485, 1082097791, 654669772,
    919755593, 224301967, 1562936940, 380671475,
    896161445, 317382420, 1328806931, 985460947,
    872927513, 683104322, 469506881, 2017086158,
    264368252, 1063593035, 1041326976, 287139998,
    956679745, 717170899, 840494536, 2115371742,
    164266473, 1327680765, 1025842560, 1529932691,
    783433849, 1139238090, 1034120354, 2036747842,
    1014528120, 835351437, 1978359477, 1397631039,
    301744965, 876204621, 1628183056, 1145844269,
    1466669085, 702883436, 42639567, 1458741144,
    977182307, 1364828027, 2143635110, 683814113,
    371974846, 1764687988, 1203660763, 1293067418,
    384567107, 919807155, 337678524, 234821845,
    880921989, 849180704, 177073213, 590463980,
    1400369581, 1120589198, 205769339, 1837499051,
    1673993329, 308910126, 70592023, 1242499174,
    1840171332, 384403269, 704758379, 360983529,
    2004072924, 557978657, 450751687, 2074315550,
    149739506, 448455838, 1117419457, 1947633223,
    293827999, 930696960, 712212590, 1234351945,
    2050198314, 1464029890, 32319988, 803065671,
    60845370, 443074829, 1095145315, 861842525,
    1070186387, 308811698, 1973842230, 215809724,
    568659321, 218627235, 1432829253, 1676513420,
    185974891, 511472451, 1570391136, 478382536,
    533384737, 316727734, 1977213908, 1630561089,
    1929271599, 587877971, 797538139, 720423888,
    388887263, 917405014, 696388467, 1918007723,
    2082512008, 529189134, 1285081484, 656837312,
    1688764830, 1767518136, 728247609, 919867011,
    867772480, 468603182, 1477657243, 783041768,
    862348902, 1433889237, 1762809785, 1683253123,
    1257144930, 306307745, 1419466745, 1025614292,
    1010775482, 1015835870, 716929156, 2144184901,
    503934046, 249936841, 1769868021, 268845281,
    1522225451, 349742390, 636412327, 1411017328,
    640991331, 701749573, 2144239714, 997624379,
    1141659228, 765343796, 1215617620, 1880255547,
    106088264, 1287206192, 1849400096, 912120476,
    1741634803, 382909417, 1162954794, 1485740538,
    1184928107, 1414738119, 1840247786, 1524428745,
    811622496, 905033490, 2144334844, 861508813,
    505474952, 241395972, 128348148, 1656719553,
    152945783, 635829701, 1173335268, 1594296832,
    822374518, 2144384825, 2070124726, 1211242575,
    1533476110, 1053715075, 1627534168, 476194514,
    1586070065, 1118161956, 107068273, 1942815931,
    198276189, 737150415, 191630977, 464731256,
    1289096822, 1759785612, 1563731050, 785296411,
    630370902, 650570081, 1386540562, 261302206,
    458889662, 2054635679, 1618090046, 979658743,
    50704475, 1081188022, 1383074648, 219797773,
    453819058, 1901633795, 973170964, 809367977,
    946898696, 659857801, 314768151, 1154529512,
    120282554, 1034190624, 962564196, 1408281793,
    563130902, 509918098, 1830307878, 871779559,
    1094055858, 1457738562, 1050588361, 1338203134,
    533984509, 351668463, 1119800454, 1730636085,
    1323515991, 2124546572, 48676296, 231619408,
    825296242, 1751069003, 1580707459, 1285645839,
    1786729119, 2008478761, 699773695, 90539495,
    1743417645, 888905846, 1840297666, 903462976,
    1914183722, 1437270101, 473792084, 1189935528,
    718624085, 1136574570, 856204519, 5570645,
    2005616204, 1636310308, 2044826160, 254927091,
    1065439696, 1041957960, 1658917316, 1281874064,
    2029096728, 1812025254, 1919553797, 170043405,
    1186046453, 1236512877, 2013607440, 40930438,
    1997595829, 1744660352, 1351011864, 1270571867,
    1607901266, 1432558448, 657227363, 694217984,
    24280594, 1500813540, 1353614379, 1787329944,
    1119375851, 1276157573, 1523588772, 1262281795,
    109510982, 1005715944, 162526678, 683895040,
    406639849, 868018730, 1238117115, 468686320,
    700841338, 2121069334, 1970725165, 1691637425,
    676352080, 1372076455, 606440981, 1318906318,
    358786902, 1859757458, 201163310, 1930908747,
    1482910431, 1801283253, 798156755, 1802120497,
    977779390, 694240793, 483830653, 28426378,
    828536359, 1495246717, 2083110636, 943864070,
    1975376704, 713262191, 1781027607, 744836402,
    963811113, 1195032517, 823797171, 1518268391,
    1325638602, 1377439215, 1688033836, 1754496675,
    650829360, 225119016, 1937788185, 951352920,
    587281326, 810656195, 103099332, 833876691,
    785236427, 458564186, 1649407603, 872493356,
    1840343544, 1568835324, 7473841, 418050119,
    1831823435, 228402885, 815845404, 762889231,
    1071267764, 2009095748, 1226780888, 1752997558,
    790530104, 1901494684, 22113676, 1268856052,
    1336048616, 489734013, 1631402725, 1016329007,
    1017614410, 1160274933, 1531482102, 70528908,
    1285089196, 1460774187, 516268642, 53263405,
    911713215, 657047865, 933793451, 1906464158,
    965404644, 1712215405, 1366798876, 796608459,
    1843097014, 737374541, 1547240445, 1256480977,
    40563580, 612545280, 521395697, 1445924759,
    306444016, 2081042164, 2145113356, 1932024979,
    1752516941, 1315894820, 2046009145, 1044275802,
    379106214, 49394476, 1858489677, 955219502,
    705668753, 1112382478, 839811143, 1483843434,
    880001451, 1046927424, 370336117, 1533252138,
    1071417707, 445747957, 294525295, 602314723,
    76365259, 533981402, 1286181066, 546674140,
    1430887709, 1247519975, 1202498873, 199819334,
    1690913940, 1292615557, 93866556, 464258978,
    1089733723, 141492015, 2104169221, 125250902,
    2040564440, 140893107, 696910655, 861714663,
    1125843220, 902893546, 1394734116, 485498406,
    2113647245, 1910877369, 1294342869, 1960843707,
    2077847671, 1700932711, 719563936, 1706342585,
    574899268, 829049358, 1006772479, 459378641,
    1775461065, 316002775, 838096620, 626256865,
    729878223, 230483281, 2140841945, 880225017,
    2105506086, 1171956646, 504901186, 1193780653,
    1163953739, 32970578, 1051783913, 263225779,
    519340433, 1179912014, 903167766, 932833690,
    298989085, 309586475, 1966711697, 1140102767,
    19562098, 2067143005, 427327554, 589420335,
    2011101117, 2145321025, 1116950750, 878417934,
    761106152, 1822237879, 923116718, 1526239629,
    36507222, 493427811, 1502381274, 404660428,
    1850172664, 517105515, 651076056, 1113194105,
    1876917751, 1634556433, 1184305338, 775303196,
    604775533, 142034950, 74124189, 131176341,
    306481426, 511003975, 1335321364, 560579637,
    541081664
  ]

set_option maxRecDepth 400000 in
theorem limbSumInverseTable_ok : inverseOk 0 limbSumInverseTable = true := by decide

set_option maxRecDepth 8000 in
theorem limbSumInverseTable_length : limbSumInverseTable.length = 1021 := by rfl

/-- Entry `v` is the `M31` inverse of `v - 256`, for every byte `v`. The
value `v - 256` is `2 ^ 31 - 257 .. 2 ^ 31 - 2` in the field, never zero,
which is exactly what the `r_inv_i` witnesses of `div.zig` certify. -/
def absInverseTable : List Nat := [
    2139095039, 2130640638, 921557943, 1875865162,
    1082263584, 1189243932, 2001454759, 1250542686,
    545530120, 2069235255, 951527307, 70121915,
    1786635985, 167910244, 1375454402, 1488090328,
    1995370222, 278543904, 135345608, 1939078061,
    427676828, 2083516049, 1826278828, 718900105,
    1842022611, 9296466, 774961490, 1472292282,
    631058791, 1579866824, 921707583, 1985229327,
    1217546532, 433348718, 648114434, 1302094157,
    224509654, 1098256477, 1132846878, 9896238,
    1262640848, 1228560412, 1154021586, 1945841990,
    1691649854, 1139896533, 439722842, 688427772,
    980821858, 383849734, 510809217, 712336039,
    1589558974, 1491601942, 520924251, 1709439719,
    1964947537, 2050361271, 10845877, 599551272,
    1698265129, 473547676, 33208510, 567469772,
    1420470954, 933199700, 1616264008, 1443018112,
    993782326, 1148386977, 11545611, 2066227509,
    2042443686, 1666353431, 507372510, 332207415,
    1944665747, 311924999, 1773483686, 1286063653,
    1354378891, 98170681, 308546501, 1005469222,
    1535700515, 125583839, 1048477310, 1702738513,
    1623395376, 1723130591, 1875814029, 1731001970,
    353549137, 131747463, 251865366, 1413871221,
    845571686, 823877374, 1834875268, 259886556,
    591934595, 872848192, 13944699, 1403584083,
    2020330010, 14221746, 1904102167, 389141332,
    972171651, 1548525623, 573642892, 1229249260,
    1893961272, 840972617, 771279338, 609215219,
    659584263, 386238066, 575774601, 940503787,
    236854814, 1161231898, 1490417755, 468248314,
    1090010639, 803257242, 710321514, 615944922,
    2130706431, 1843115886, 17043521, 1855425871,
    1091060240, 1903054614, 1425788323, 603425157,
    1843256797, 270691216, 855353656, 1505074009,
    1536561575, 1549922980, 1262117582, 1843415166,
    287609417, 1296228868, 449019308, 118210109,
    377798049, 160559525, 1235816061, 879445684,
    1961643716, 1021618434, 1031634301, 1041848502,
    1782411427, 21691754, 1249046611, 66417020,
    693458261, 1085044369, 1987564652, 23091222,
    1937403725, 1014745020, 1741847847, 1399483725,
    561274135, 617093002, 923917383, 2096954620,
    1099307105, 1604144411, 707098274, 503730732,
    1691143372, 1522266889, 1183869190, 27889398,
    1893176373, 1660720687, 1944343302, 1147285784,
    1640438897, 1542558676, 1319168526, 1151549202,
    473709628, 833351863, 32537631, 1420643028,
    2113929215, 34087042, 34636833, 704092999,
    1539029947, 1710707312, 925639503, 376751517,
    575218834, 898038616, 755596098, 324148475,
    1775803785, 2063268602, 1417339207, 350609575,
    1386916522, 1827645657, 1727323803, 1336212047,
    1122548270, 1847834766, 51130563, 1414196548,
    1234803097, 220254733, 1638869099, 1741202957,
    1133394147, 490853405, 947419256, 65075262,
    2080374783, 69273666, 930576247, 1851279006,
    1150437668, 1511192196, 1404123923, 687194767,
    626349397, 1307163959, 97612893, 102261126,
    322122547, 1130254551, 119304647, 1894838512,
    2013265919, 1861152494, 153391689, 660764199,
    1252698794, 195225786, 644245094, 238609294,
    1879048191, 306783378, 357913941, 1288490188,
    1610612735, 715827882, 1073741823, 2147483646
  ]

set_option maxRecDepth 400000 in
theorem absInverseTable_ok :
    inverseOk (m31Modulus - 256) absInverseTable = true := by decide

set_option maxRecDepth 8000 in
theorem absInverseTable_length : absInverseTable.length = 256 := by rfl

/-- sha256 of the export this file was generated from. `DivBridge.lean`
`#guard`s it equal to `Air.Family.divIrDigest`. -/
def divProgramIrDigest : String :=
  "430a06a8919e469251deab180b492e89a4a6452de0014b2b0c3ea6c350912e4d"

-- 73 columns, 434 nodes, 85 constraints, 25 lookups.
def divProgram : DivCircuit where
  family := "div"
  modulus := 2147483647
  columns := [
    "clock", "pc", "rd_addr", "rd_previous_0",
    "rd_previous_1", "rd_previous_2", "rd_previous_3", "rd_previous_clock",
    "rd_next_0", "rd_next_1", "rd_next_2", "rd_next_3",
    "rs1_addr", "rs1_previous_0", "rs1_previous_1", "rs1_previous_2",
    "rs1_previous_3", "rs1_previous_clock", "rs1_next_0", "rs1_next_1",
    "rs1_next_2", "rs1_next_3", "rs2_addr", "rs2_previous_0",
    "rs2_previous_1", "rs2_previous_2", "rs2_previous_3", "rs2_previous_clock",
    "rs2_next_0", "rs2_next_1", "rs2_next_2", "rs2_next_3",
    "zero_divisor", "r_zero", "q_0", "q_1",
    "q_2", "q_3", "r_0", "r_1",
    "r_2", "r_3", "b_sign", "c_sign",
    "q_sign", "sign_xor", "c_sum_inv", "r_sum_inv",
    "r_abs_0", "r_abs_1", "r_abs_2", "r_abs_3",
    "r_inv_0", "r_inv_1", "r_inv_2", "r_inv_3",
    "lt_markers_0", "lt_markers_1", "lt_markers_2", "lt_markers_3",
    "lt_diff", "is_div", "is_divu", "is_rem",
    "is_remu", "destination_nonzero", "destination_inverse", "bus_value_67",
    "bus_value_68", "bus_value_69", "bus_value_70", "bus_value_71",
    "bus_value_72"
  ]
  nodes := [
    .col 0, -- 0
    .col 1, -- 1
    .col 2, -- 2
    .col 3, -- 3
    .col 4, -- 4
    .col 5, -- 5
    .col 6, -- 6
    .col 7, -- 7
    .col 8, -- 8
    .col 9, -- 9
    .col 10, -- 10
    .col 11, -- 11
    .col 12, -- 12
    .col 13, -- 13
    .col 14, -- 14
    .col 15, -- 15
    .col 16, -- 16
    .col 17, -- 17
    .col 18, -- 18
    .col 19, -- 19
    .col 20, -- 20
    .col 21, -- 21
    .col 22, -- 22
    .col 23, -- 23
    .col 24, -- 24
    .col 25, -- 25
    .col 26, -- 26
    .col 27, -- 27
    .col 28, -- 28
    .col 29, -- 29
    .col 30, -- 30
    .col 31, -- 31
    .col 32, -- 32
    .col 33, -- 33
    .col 34, -- 34
    .col 35, -- 35
    .col 36, -- 36
    .col 37, -- 37
    .col 38, -- 38
    .col 39, -- 39
    .col 40, -- 40
    .col 41, -- 41
    .col 42, -- 42
    .col 43, -- 43
    .col 44, -- 44
    .col 45, -- 45
    .col 46, -- 46
    .col 47, -- 47
    .col 48, -- 48
    .col 49, -- 49
    .col 50, -- 50
    .col 51, -- 51
    .col 52, -- 52
    .col 53, -- 53
    .col 54, -- 54
    .col 55, -- 55
    .col 56, -- 56
    .col 57, -- 57
    .col 58, -- 58
    .col 59, -- 59
    .col 60, -- 60
    .col 61, -- 61
    .col 62, -- 62
    .col 63, -- 63
    .col 64, -- 64
    .col 65, -- 65
    .col 66, -- 66
    .const 1, -- 67
    .add 61 62, -- 68
    .add 68 63, -- 69
    .add 69 64, -- 70
    .add 61 63, -- 71
    .add 32 33, -- 72
    .add 34 35, -- 73
    .add 73 36, -- 74
    .add 74 37, -- 75
    .add 28 29, -- 76
    .add 76 30, -- 77
    .add 77 31, -- 78
    .add 38 39, -- 79
    .add 79 40, -- 80
    .add 80 41, -- 81
    .const 2, -- 82
    .mul 43 82, -- 83
    .sub 67 83, -- 84
    .sub 28 48, -- 85
    .mul 84 85, -- 86
    .mul 68 34, -- 87
    .sub 67 68, -- 88
    .mul 88 38, -- 89
    .add 87 89, -- 90
    .const 0, -- 91
    .add 91 38, -- 92
    .add 92 48, -- 93
    .const 8388608, -- 94
    .mul 93 94, -- 95
    .sub 29 49, -- 96
    .mul 84 96, -- 97
    .mul 68 35, -- 98
    .mul 88 39, -- 99
    .add 98 99, -- 100
    .add 95 39, -- 101
    .add 101 49, -- 102
    .mul 102 94, -- 103
    .sub 30 50, -- 104
    .mul 84 104, -- 105
    .mul 68 36, -- 106
    .mul 88 40, -- 107
    .add 106 107, -- 108
    .add 103 40, -- 109
    .add 109 50, -- 110
    .mul 110 94, -- 111
    .sub 31 51, -- 112
    .mul 84 112, -- 113
    .mul 68 37, -- 114
    .mul 88 41, -- 115
    .add 114 115, -- 116
    .add 111 41, -- 117
    .add 117 51, -- 118
    .mul 118 94, -- 119
    .add 72 59, -- 120
    .add 120 58, -- 121
    .add 121 57, -- 122
    .add 122 56, -- 123
    .const 255, -- 124
    .mul 43 124, -- 125
    .mul 44 124, -- 126
    .mul 42 124, -- 127
    .sub 67 33, -- 128
    .mul 42 128, -- 129
    .mul 129 124, -- 130
    .mul 28 34, -- 131
    .add 131 38, -- 132
    .sub 132 18, -- 133
    .mul 133 94, -- 134
    .mul 28 35, -- 135
    .add 134 135, -- 136
    .mul 29 34, -- 137
    .add 136 137, -- 138
    .add 138 39, -- 139
    .sub 139 19, -- 140
    .mul 140 94, -- 141
    .mul 28 36, -- 142
    .add 141 142, -- 143
    .mul 29 35, -- 144
    .add 143 144, -- 145
    .mul 30 34, -- 146
    .add 145 146, -- 147
    .add 147 40, -- 148
    .sub 148 20, -- 149
    .mul 149 94, -- 150
    .mul 28 37, -- 151
    .add 150 151, -- 152
    .mul 29 36, -- 153
    .add 152 153, -- 154
    .mul 30 35, -- 155
    .add 154 155, -- 156
    .mul 31 34, -- 157
    .add 156 157, -- 158
    .add 158 41, -- 159
    .sub 159 21, -- 160
    .mul 160 94, -- 161
    .mul 28 126, -- 162
    .add 161 162, -- 163
    .mul 29 37, -- 164
    .add 163 164, -- 165
    .mul 30 36, -- 166
    .add 165 166, -- 167
    .mul 31 35, -- 168
    .add 167 168, -- 169
    .mul 125 34, -- 170
    .add 169 170, -- 171
    .add 171 130, -- 172
    .sub 172 127, -- 173
    .mul 173 94, -- 174
    .mul 76 126, -- 175
    .add 174 175, -- 176
    .mul 30 37, -- 177
    .add 176 177, -- 178
    .mul 31 36, -- 179
    .add 178 179, -- 180
    .mul 125 73, -- 181
    .add 180 181, -- 182
    .add 182 130, -- 183
    .sub 183 127, -- 184
    .mul 184 94, -- 185
    .sub 78 31, -- 186
    .mul 186 126, -- 187
    .add 185 187, -- 188
    .mul 31 37, -- 189
    .add 188 189, -- 190
    .sub 75 37, -- 191
    .mul 125 191, -- 192
    .add 190 192, -- 193
    .add 193 130, -- 194
    .sub 194 127, -- 195
    .mul 195 94, -- 196
    .mul 78 126, -- 197
    .add 196 197, -- 198
    .mul 125 75, -- 199
    .add 198 199, -- 200
    .add 200 130, -- 201
    .sub 201 127, -- 202
    .mul 202 94, -- 203
    .sub 70 32, -- 204
    .sub 70 72, -- 205
    .const 128, -- 206
    .mul 42 206, -- 207
    .sub 21 207, -- 208
    .mul 71 208, -- 209
    .mul 209 82, -- 210
    .mul 43 206, -- 211
    .sub 31 211, -- 212
    .mul 71 212, -- 213
    .mul 213 82, -- 214
    .sub 67 70, -- 215
    .mul 70 215, -- 216
    .sub 67 61, -- 217
    .mul 61 217, -- 218
    .sub 67 62, -- 219
    .mul 62 219, -- 220
    .sub 67 63, -- 221
    .mul 63 221, -- 222
    .sub 67 64, -- 223
    .mul 64 223, -- 224
    .sub 67 32, -- 225
    .mul 32 225, -- 226
    .mul 33 128, -- 227
    .sub 67 42, -- 228
    .mul 42 228, -- 229
    .sub 67 43, -- 230
    .mul 43 230, -- 231
    .sub 67 44, -- 232
    .mul 44 232, -- 233
    .sub 67 45, -- 234
    .mul 45 234, -- 235
    .sub 67 56, -- 236
    .mul 56 236, -- 237
    .sub 67 57, -- 238
    .mul 57 238, -- 239
    .sub 67 58, -- 240
    .mul 58 240, -- 241
    .sub 67 59, -- 242
    .mul 59 242, -- 243
    .sub 67 72, -- 244
    .mul 72 244, -- 245
    .sub 67 204, -- 246
    .mul 204 246, -- 247
    .sub 67 205, -- 248
    .mul 205 248, -- 249
    .mul 32 28, -- 250
    .mul 32 29, -- 251
    .mul 32 30, -- 252
    .mul 32 31, -- 253
    .sub 34 124, -- 254
    .mul 32 254, -- 255
    .sub 35 124, -- 256
    .mul 32 256, -- 257
    .sub 36 124, -- 258
    .mul 32 258, -- 259
    .sub 37 124, -- 260
    .mul 32 260, -- 261
    .mul 78 46, -- 262
    .sub 262 67, -- 263
    .mul 204 263, -- 264
    .mul 33 38, -- 265
    .mul 33 39, -- 266
    .mul 33 40, -- 267
    .mul 33 41, -- 268
    .mul 81 47, -- 269
    .sub 269 67, -- 270
    .mul 205 270, -- 271
    .sub 67 71, -- 272
    .mul 272 42, -- 273
    .mul 272 43, -- 274
    .sub 45 42, -- 275
    .sub 275 43, -- 276
    .mul 42 43, -- 277
    .mul 277 82, -- 278
    .add 276 278, -- 279
    .mul 70 279, -- 280
    .mul 225 75, -- 281
    .sub 44 45, -- 282
    .mul 281 282, -- 283
    .mul 225 282, -- 284
    .mul 284 44, -- 285
    .sub 44 71, -- 286
    .mul 32 286, -- 287
    .sub 48 38, -- 288
    .mul 234 288, -- 289
    .mul 45 95, -- 290
    .sub 95 67, -- 291
    .mul 290 291, -- 292
    .sub 67 95, -- 293
    .mul 45 293, -- 294
    .mul 294 48, -- 295
    .const 256, -- 296
    .sub 48 296, -- 297
    .mul 297 52, -- 298
    .sub 298 67, -- 299
    .mul 45 299, -- 300
    .sub 49 39, -- 301
    .mul 234 301, -- 302
    .sub 103 95, -- 303
    .mul 45 303, -- 304
    .sub 103 67, -- 305
    .mul 304 305, -- 306
    .sub 67 103, -- 307
    .mul 45 307, -- 308
    .mul 308 49, -- 309
    .sub 49 296, -- 310
    .mul 310 53, -- 311
    .sub 311 67, -- 312
    .mul 45 312, -- 313
    .sub 50 40, -- 314
    .mul 234 314, -- 315
    .sub 111 103, -- 316
    .mul 45 316, -- 317
    .sub 111 67, -- 318
    .mul 317 318, -- 319
    .sub 67 111, -- 320
    .mul 45 320, -- 321
    .mul 321 50, -- 322
    .sub 50 296, -- 323
    .mul 323 54, -- 324
    .sub 324 67, -- 325
    .mul 45 325, -- 326
    .sub 51 41, -- 327
    .mul 234 327, -- 328
    .sub 119 111, -- 329
    .mul 45 329, -- 330
    .sub 119 67, -- 331
    .mul 330 331, -- 332
    .sub 67 119, -- 333
    .mul 45 333, -- 334
    .mul 334 51, -- 335
    .sub 51 296, -- 336
    .mul 336 55, -- 337
    .sub 337 67, -- 338
    .mul 45 338, -- 339
    .sub 67 120, -- 340
    .mul 340 113, -- 341
    .sub 60 113, -- 342
    .mul 59 342, -- 343
    .sub 67 121, -- 344
    .mul 344 105, -- 345
    .sub 60 105, -- 346
    .mul 58 346, -- 347
    .sub 67 122, -- 348
    .mul 348 97, -- 349
    .sub 60 97, -- 350
    .mul 57 350, -- 351
    .sub 67 123, -- 352
    .mul 352 86, -- 353
    .sub 60 86, -- 354
    .mul 56 354, -- 355
    .mul 70 352, -- 356
    .sub 65 67, -- 357
    .mul 65 357, -- 358
    .sub 67 65, -- 359
    .mul 2 359, -- 360
    .mul 2 66, -- 361
    .sub 361 65, -- 362
    .mul 65 90, -- 363
    .sub 8 363, -- 364
    .mul 65 100, -- 365
    .sub 9 365, -- 366
    .mul 65 108, -- 367
    .sub 10 367, -- 368
    .mul 65 116, -- 369
    .sub 11 369, -- 370
    .sub 18 13, -- 371
    .mul 70 371, -- 372
    .sub 19 14, -- 373
    .mul 70 373, -- 374
    .sub 20 15, -- 375
    .mul 70 375, -- 376
    .sub 21 16, -- 377
    .mul 70 377, -- 378
    .sub 28 23, -- 379
    .mul 70 379, -- 380
    .sub 29 24, -- 381
    .mul 70 381, -- 382
    .sub 30 25, -- 383
    .mul 70 383, -- 384
    .sub 31 26, -- 385
    .mul 70 385, -- 386
    .sub 70 67, -- 387
    .neg 70, -- 388
    .const 41, -- 389
    .mul 61 389, -- 390
    .const 42, -- 391
    .mul 62 391, -- 392
    .add 390 392, -- 393
    .const 43, -- 394
    .mul 63 394, -- 395
    .add 393 395, -- 396
    .const 44, -- 397
    .mul 64 397, -- 398
    .add 396 398, -- 399
    .const 4, -- 400
    .add 1 400, -- 401
    .add 0 67, -- 402
    .sub 0 67, -- 403
    .mul 403 400, -- 404
    .add 404 67, -- 405
    .sub 405 17, -- 406
    .sub 406 67, -- 407
    .add 404 82, -- 408
    .sub 408 27, -- 409
    .sub 409 67, -- 410
    .mul 71 204, -- 411
    .sub 411 277, -- 412
    .mul 44 206, -- 413
    .sub 37 413, -- 414
    .neg 412, -- 415
    .neg 205, -- 416
    .sub 60 67, -- 417
    .const 3, -- 418
    .add 404 418, -- 419
    .sub 419 7, -- 420
    .sub 420 67, -- 421
    .col 67, -- 422
    .sub 422 399, -- 423
    .col 68, -- 424
    .sub 424 401, -- 425
    .col 69, -- 426
    .sub 426 402, -- 427
    .col 70, -- 428
    .sub 428 405, -- 429
    .col 71, -- 430
    .sub 430 408, -- 431
    .col 72, -- 432
    .sub 432 419 -- 433
  ]
  nodeCount := 434
  constraints := [
    216, 218, 220, 222, 224, 226, 227, 229,
    231, 233, 235, 237, 239, 241, 243, 245,
    247, 249, 250, 251, 252, 253, 255, 257,
    259, 261, 264, 265, 266, 267, 268, 271,
    273, 274, 280, 283, 285, 287, 289, 292,
    295, 300, 302, 306, 309, 313, 315, 319,
    322, 326, 328, 332, 335, 339, 341, 343,
    345, 347, 349, 351, 353, 355, 356, 358,
    360, 362, 364, 366, 368, 370, 372, 374,
    376, 378, 380, 382, 384, 386, 387, 423,
    425, 427, 429, 431, 433
  ]
  lookups := [
    { domain := .programAccess, role := .request,
      numerator := 388, tuple := [1, 399, 2, 12, 22] }, -- lookup 0
    { domain := .registersState, role := .consumed,
      numerator := 388, tuple := [1, 0] }, -- lookup 1
    { domain := .registersState, role := .emitted,
      numerator := 70, tuple := [401, 402] }, -- lookup 2
    { domain := .memoryAccess, role := .consumed,
      numerator := 388, tuple := [91, 12, 17, 13, 14, 15, 16] }, -- lookup 3
    { domain := .memoryAccess, role := .emitted,
      numerator := 70, tuple := [91, 12, 405, 18, 19, 20, 21] }, -- lookup 4
    { domain := .rangeCheck20, role := .request,
      numerator := 388, tuple := [407] }, -- lookup 5
    { domain := .memoryAccess, role := .consumed,
      numerator := 388, tuple := [91, 22, 27, 23, 24, 25, 26] }, -- lookup 6
    { domain := .memoryAccess, role := .emitted,
      numerator := 70, tuple := [91, 22, 408, 28, 29, 30, 31] }, -- lookup 7
    { domain := .rangeCheck20, role := .request,
      numerator := 388, tuple := [410] }, -- lookup 8
    { domain := .rangeCheck88, role := .request,
      numerator := 388, tuple := [28, 29] }, -- lookup 9
    { domain := .rangeCheck88, role := .request,
      numerator := 388, tuple := [30, 31] }, -- lookup 10
    { domain := .rangeCheck811, role := .request,
      numerator := 388, tuple := [34, 134] }, -- lookup 11
    { domain := .rangeCheck811, role := .request,
      numerator := 388, tuple := [35, 141] }, -- lookup 12
    { domain := .rangeCheck811, role := .request,
      numerator := 388, tuple := [36, 150] }, -- lookup 13
    { domain := .rangeCheck811, role := .request,
      numerator := 388, tuple := [37, 161] }, -- lookup 14
    { domain := .rangeCheck811, role := .request,
      numerator := 388, tuple := [38, 174] }, -- lookup 15
    { domain := .rangeCheck811, role := .request,
      numerator := 388, tuple := [39, 185] }, -- lookup 16
    { domain := .rangeCheck811, role := .request,
      numerator := 388, tuple := [40, 196] }, -- lookup 17
    { domain := .rangeCheck811, role := .request,
      numerator := 388, tuple := [41, 203] }, -- lookup 18
    { domain := .rangeCheckM31, role := .request,
      numerator := 415, tuple := [91, 414] }, -- lookup 19
    { domain := .rangeCheck88, role := .request,
      numerator := 388, tuple := [210, 214] }, -- lookup 20
    { domain := .rangeCheck20, role := .request,
      numerator := 416, tuple := [417] }, -- lookup 21
    { domain := .memoryAccess, role := .consumed,
      numerator := 388, tuple := [91, 2, 7, 3, 4, 5, 6] }, -- lookup 22
    { domain := .memoryAccess, role := .emitted,
      numerator := 70, tuple := [91, 2, 419, 8, 9, 10, 11] }, -- lookup 23
    { domain := .rangeCheck20, role := .request,
      numerator := 388, tuple := [421] } -- lookup 24
  ]

-- The same circuit with every node argument rewritten to its offset from
-- the head of the reversed memo table. This is the table the proofs in
-- DivBridge.lean evaluate; `divProgramCompiled_eq_localise` there is what
-- ties it to the verbatim export above.
def divProgramCompiled : DivCircuit where
  family := "div"
  modulus := 2147483647
  columns := divProgram.columns
  nodes := [
    .col 0, -- 0
    .col 1, -- 1
    .col 2, -- 2
    .col 3, -- 3
    .col 4, -- 4
    .col 5, -- 5
    .col 6, -- 6
    .col 7, -- 7
    .col 8, -- 8
    .col 9, -- 9
    .col 10, -- 10
    .col 11, -- 11
    .col 12, -- 12
    .col 13, -- 13
    .col 14, -- 14
    .col 15, -- 15
    .col 16, -- 16
    .col 17, -- 17
    .col 18, -- 18
    .col 19, -- 19
    .col 20, -- 20
    .col 21, -- 21
    .col 22, -- 22
    .col 23, -- 23
    .col 24, -- 24
    .col 25, -- 25
    .col 26, -- 26
    .col 27, -- 27
    .col 28, -- 28
    .col 29, -- 29
    .col 30, -- 30
    .col 31, -- 31
    .col 32, -- 32
    .col 33, -- 33
    .col 34, -- 34
    .col 35, -- 35
    .col 36, -- 36
    .col 37, -- 37
    .col 38, -- 38
    .col 39, -- 39
    .col 40, -- 40
    .col 41, -- 41
    .col 42, -- 42
    .col 43, -- 43
    .col 44, -- 44
    .col 45, -- 45
    .col 46, -- 46
    .col 47, -- 47
    .col 48, -- 48
    .col 49, -- 49
    .col 50, -- 50
    .col 51, -- 51
    .col 52, -- 52
    .col 53, -- 53
    .col 54, -- 54
    .col 55, -- 55
    .col 56, -- 56
    .col 57, -- 57
    .col 58, -- 58
    .col 59, -- 59
    .col 60, -- 60
    .col 61, -- 61
    .col 62, -- 62
    .col 63, -- 63
    .col 64, -- 64
    .col 65, -- 65
    .col 66, -- 66
    .const 1, -- 67
    .add 6 5, -- 68
    .add 0 5, -- 69
    .add 0 5, -- 70
    .add 9 7, -- 71
    .add 39 38, -- 72
    .add 38 37, -- 73
    .add 0 37, -- 74
    .add 0 37, -- 75
    .add 47 46, -- 76
    .add 0 46, -- 77
    .add 0 46, -- 78
    .add 40 39, -- 79
    .add 0 39, -- 80
    .add 0 39, -- 81
    .const 2, -- 82
    .mul 39 0, -- 83
    .sub 16 0, -- 84
    .sub 56 36, -- 85
    .mul 1 0, -- 86
    .mul 18 52, -- 87
    .sub 20 19, -- 88
    .mul 0 50, -- 89
    .add 2 0, -- 90
    .const 0, -- 91
    .add 0 53, -- 92
    .add 0 44, -- 93
    .const 8388608, -- 94
    .mul 1 0, -- 95
    .sub 66 46, -- 96
    .mul 12 0, -- 97
    .mul 29 62, -- 98
    .mul 10 59, -- 99
    .add 1 0, -- 100
    .add 5 61, -- 101
    .add 0 52, -- 102
    .mul 0 8, -- 103
    .sub 73 53, -- 104
    .mul 20 0, -- 105
    .mul 37 69, -- 106
    .mul 18 66, -- 107
    .add 1 0, -- 108
    .add 5 68, -- 109
    .add 0 59, -- 110
    .mul 0 16, -- 111
    .sub 80 60, -- 112
    .mul 28 0, -- 113
    .mul 45 76, -- 114
    .mul 26 73, -- 115
    .add 1 0, -- 116
    .add 5 75, -- 117
    .add 0 66, -- 118
    .mul 0 24, -- 119
    .add 47 60, -- 120
    .add 0 62, -- 121
    .add 0 64, -- 122
    .add 0 66, -- 123
    .const 255, -- 124
    .mul 81 0, -- 125
    .mul 81 1, -- 126
    .mul 84 2, -- 127
    .sub 60 94, -- 128
    .mul 86 0, -- 129
    .mul 0 5, -- 130
    .mul 102 96, -- 131
    .add 0 93, -- 132
    .sub 0 114, -- 133
    .mul 0 39, -- 134
    .mul 106 99, -- 135
    .add 1 0, -- 136
    .mul 107 102, -- 137
    .add 1 0, -- 138
    .add 0 99, -- 139
    .sub 0 120, -- 140
    .mul 0 46, -- 141
    .mul 113 105, -- 142
    .add 1 0, -- 143
    .mul 114 108, -- 144
    .add 1 0, -- 145
    .mul 115 111, -- 146
    .add 1 0, -- 147
    .add 0 107, -- 148
    .sub 0 128, -- 149
    .mul 0 55, -- 150
    .mul 122 113, -- 151
    .add 1 0, -- 152
    .mul 123 116, -- 153
    .add 1 0, -- 154
    .mul 124 119, -- 155
    .add 1 0, -- 156
    .mul 125 122, -- 157
    .add 1 0, -- 158
    .add 0 117, -- 159
    .sub 0 138, -- 160
    .mul 0 66, -- 161
    .mul 133 35, -- 162
    .add 1 0, -- 163
    .mul 134 126, -- 164
    .add 1 0, -- 165
    .mul 135 129, -- 166
    .add 1 0, -- 167
    .mul 136 132, -- 168
    .add 1 0, -- 169
    .mul 44 135, -- 170
    .add 1 0, -- 171
    .add 0 41, -- 172
    .sub 0 45, -- 173
    .mul 0 79, -- 174
    .mul 98 48, -- 175
    .add 1 0, -- 176
    .mul 146 139, -- 177
    .add 1 0, -- 178
    .mul 147 142, -- 179
    .add 1 0, -- 180
    .mul 55 107, -- 181
    .add 1 0, -- 182
    .add 0 52, -- 183
    .sub 0 56, -- 184
    .mul 0 90, -- 185
    .sub 107 154, -- 186
    .mul 0 60, -- 187
    .add 2 0, -- 188
    .mul 157 151, -- 189
    .add 1 0, -- 190
    .sub 115 153, -- 191
    .mul 66 0, -- 192
    .add 2 0, -- 193
    .add 0 63, -- 194
    .sub 0 67, -- 195
    .mul 0 101, -- 196
    .mul 118 70, -- 197
    .add 1 0, -- 198
    .mul 73 123, -- 199
    .add 1 0, -- 200
    .add 0 70, -- 201
    .sub 0 74, -- 202
    .mul 0 108, -- 203
    .sub 133 171, -- 204
    .sub 134 132, -- 205
    .const 128, -- 206
    .mul 164 0, -- 207
    .sub 186 0, -- 208
    .mul 137 0, -- 209
    .mul 0 127, -- 210
    .mul 167 4, -- 211
    .sub 180 0, -- 212
    .mul 141 0, -- 213
    .mul 0 131, -- 214
    .sub 147 144, -- 215
    .mul 145 0, -- 216
    .sub 149 155, -- 217
    .mul 156 0, -- 218
    .sub 151 156, -- 219
    .mul 157 0, -- 220
    .sub 153 157, -- 221
    .mul 158 0, -- 222
    .sub 155 158, -- 223
    .mul 159 0, -- 224
    .sub 157 192, -- 225
    .mul 193 0, -- 226
    .mul 193 98, -- 227
    .sub 160 185, -- 228
    .mul 186 0, -- 229
    .sub 162 186, -- 230
    .mul 187 0, -- 231
    .sub 164 187, -- 232
    .mul 188 0, -- 233
    .sub 166 188, -- 234
    .mul 189 0, -- 235
    .sub 168 179, -- 236
    .mul 180 0, -- 237
    .sub 170 180, -- 238
    .mul 181 0, -- 239
    .sub 172 181, -- 240
    .mul 182 0, -- 241
    .sub 174 182, -- 242
    .mul 183 0, -- 243
    .sub 176 171, -- 244
    .mul 172 0, -- 245
    .sub 178 41, -- 246
    .mul 42 0, -- 247
    .sub 180 42, -- 248
    .mul 43 0, -- 249
    .mul 217 221, -- 250
    .mul 218 221, -- 251
    .mul 219 221, -- 252
    .mul 220 221, -- 253
    .sub 219 129, -- 254
    .mul 222 0, -- 255
    .sub 220 131, -- 256
    .mul 224 0, -- 257
    .sub 221 133, -- 258
    .mul 226 0, -- 259
    .sub 222 135, -- 260
    .mul 228 0, -- 261
    .mul 183 215, -- 262
    .sub 0 195, -- 263
    .mul 59 0, -- 264
    .mul 231 226, -- 265
    .mul 232 226, -- 266
    .mul 233 226, -- 267
    .mul 234 226, -- 268
    .mul 187 221, -- 269
    .sub 0 202, -- 270
    .mul 65 0, -- 271
    .sub 204 200, -- 272
    .mul 0 230, -- 273
    .mul 1 230, -- 274
    .sub 229 232, -- 275
    .sub 0 232, -- 276
    .mul 234 233, -- 277
    .mul 0 195, -- 278
    .add 2 0, -- 279
    .mul 209 0, -- 280
    .mul 55 205, -- 281
    .sub 237 236, -- 282
    .mul 1 0, -- 283
    .mul 58 1, -- 284
    .mul 0 240, -- 285
    .sub 241 214, -- 286
    .mul 254 0, -- 287
    .sub 239 249, -- 288
    .mul 54 0, -- 289
    .mul 244 194, -- 290
    .sub 195 223, -- 291
    .mul 1 0, -- 292
    .sub 225 197, -- 293
    .mul 248 0, -- 294
    .mul 0 246, -- 295
    .const 256, -- 296
    .sub 248 0, -- 297
    .mul 0 245, -- 298
    .sub 0 231, -- 299
    .mul 254 0, -- 300
    .sub 251 261, -- 301
    .mul 67 0, -- 302
    .sub 199 207, -- 303
    .mul 258 0, -- 304
    .sub 201 237, -- 305
    .mul 1 0, -- 306
    .sub 239 203, -- 307
    .mul 262 0, -- 308
    .mul 0 259, -- 309
    .sub 260 13, -- 310
    .mul 0 257, -- 311
    .sub 0 244, -- 312
    .mul 267 0, -- 313
    .sub 263 273, -- 314
    .mul 80 0, -- 315
    .sub 204 212, -- 316
    .mul 271 0, -- 317
    .sub 206 250, -- 318
    .mul 1 0, -- 319
    .sub 252 208, -- 320
    .mul 275 0, -- 321
    .mul 0 271, -- 322
    .sub 272 26, -- 323
    .mul 0 269, -- 324
    .sub 0 257, -- 325
    .mul 280 0, -- 326
    .sub 275 285, -- 327
    .mul 93 0, -- 328
    .sub 209 217, -- 329
    .mul 284 0, -- 330
    .sub 211 263, -- 331
    .mul 1 0, -- 332
    .sub 265 213, -- 333
    .mul 288 0, -- 334
    .mul 0 283, -- 335
    .sub 284 39, -- 336
    .mul 0 281, -- 337
    .sub 0 270, -- 338
    .mul 293 0, -- 339
    .sub 272 219, -- 340
    .mul 0 227, -- 341
    .sub 281 228, -- 342
    .mul 283 0, -- 343
    .sub 276 222, -- 344
    .mul 0 239, -- 345
    .sub 285 240, -- 346
    .mul 288 0, -- 347
    .sub 280 225, -- 348
    .mul 0 251, -- 349
    .sub 289 252, -- 350
    .mul 293 0, -- 351
    .sub 284 228, -- 352
    .mul 0 266, -- 353
    .sub 293 267, -- 354
    .mul 298 0, -- 355
    .mul 285 3, -- 356
    .sub 291 289, -- 357
    .mul 292 0, -- 358
    .sub 291 293, -- 359
    .mul 357 0, -- 360
    .mul 358 294, -- 361
    .sub 0 296, -- 362
    .mul 297 272, -- 363
    .sub 355 0, -- 364
    .mul 299 264, -- 365
    .sub 356 0, -- 366
    .mul 301 258, -- 367
    .sub 357 0, -- 368
    .mul 303 252, -- 369
    .sub 358 0, -- 370
    .sub 352 357, -- 371
    .mul 301 0, -- 372
    .sub 353 358, -- 373
    .mul 303 0, -- 374
    .sub 354 359, -- 375
    .mul 305 0, -- 376
    .sub 355 360, -- 377
    .mul 307 0, -- 378
    .sub 350 355, -- 379
    .mul 309 0, -- 380
    .sub 351 356, -- 381
    .mul 311 0, -- 382
    .sub 352 357, -- 383
    .mul 313 0, -- 384
    .sub 353 358, -- 385
    .mul 315 0, -- 386
    .sub 316 319, -- 387
    .neg 317, -- 388
    .const 41, -- 389
    .mul 328 0, -- 390
    .const 42, -- 391
    .mul 329 0, -- 392
    .add 2 0, -- 393
    .const 43, -- 394
    .mul 331 0, -- 395
    .add 2 0, -- 396
    .const 44, -- 397
    .mul 333 0, -- 398
    .add 2 0, -- 399
    .const 4, -- 400
    .add 399 0, -- 401
    .add 401 334, -- 402
    .sub 402 335, -- 403
    .mul 0 3, -- 404
    .add 0 337, -- 405
    .sub 0 388, -- 406
    .sub 0 339, -- 407
    .add 3 325, -- 408
    .sub 0 381, -- 409
    .sub 0 342, -- 410
    .mul 339 206, -- 411
    .sub 0 134, -- 412
    .mul 368 206, -- 413
    .sub 376 0, -- 414
    .neg 2, -- 415
    .neg 210, -- 416
    .sub 356 349, -- 417
    .const 3, -- 418
    .add 14 0, -- 419
    .sub 0 412, -- 420
    .sub 0 353, -- 421
    .col 67, -- 422
    .sub 0 23, -- 423
    .col 68, -- 424
    .sub 0 23, -- 425
    .col 69, -- 426
    .sub 0 24, -- 427
    .col 70, -- 428
    .sub 0 23, -- 429
    .col 71, -- 430
    .sub 0 22, -- 431
    .col 72, -- 432
    .sub 0 13 -- 433
  ]
  nodeCount := 434
  constraints := divProgram.constraints
  lookups := divProgram.lookups

-- Sanity: the table is the size the export reports.
#guard divProgram.columns.length == 73
#guard divProgram.nodes.length == 434
#guard divProgram.constraints.length == 85
#guard divProgram.lookups.length == 25

-- A concrete satisfying `divu` row (7 / 2 = 3 remainder 1) and the values
-- an independent evaluator -- the generator, walking the same JSON --
-- computes for it. This is the differential test between this interpreter
-- and that one. `DivBridge.lean` checks `divColumns divWitnessRow` against
-- the list below, which is what pins the hand-written column assignment.
def divWitnessColumns : List M31 := [
    M31.reduce 5, M31.reduce 100, M31.reduce 7, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 3, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 1, M31.reduce 7, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 3, M31.reduce 7, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 2, M31.reduce 2,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 2, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 3, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 1, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 1073741824, M31.reduce 1,
    M31.reduce 1, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 2130640638, M31.reduce 2139095039, M31.reduce 2139095039, M31.reduce 2139095039,
    M31.reduce 1, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 1, M31.reduce 0, M31.reduce 1, M31.reduce 0,
    M31.reduce 0, M31.reduce 1, M31.reduce 1840700269, M31.reduce 42,
    M31.reduce 104, M31.reduce 6, M31.reduce 17, M31.reduce 18,
    M31.reduce 19
  ]

set_option maxRecDepth 40000 in
#guard divProgramCompiled.constraintValues divWitnessColumns ==
  List.replicate 85 0

set_option maxRecDepth 40000 in
#guard divProgramCompiled.fixedRequestsHold divWitnessColumns

set_option maxRecDepth 40000 in
#guard (divProgramCompiled.lookups.map fun entry =>
    (divProgramCompiled.lookupTuple divWitnessColumns entry).map M31.toNat) ==
  [
    [100, 42, 7, 1, 2],
    [100, 5],
    [104, 6],
    [0, 1, 3, 7, 0, 0, 0],
    [0, 1, 17, 7, 0, 0, 0],
    [13],
    [0, 2, 3, 2, 0, 0, 0],
    [0, 2, 18, 2, 0, 0, 0],
    [14],
    [2, 0],
    [0, 0],
    [3, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [1, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [0],
    [0, 7, 3, 0, 0, 0, 0],
    [0, 7, 19, 3, 0, 0, 0],
    [15]
  ]

set_option maxRecDepth 40000 in
#guard (divProgramCompiled.lookups.map fun entry =>
    (divProgramCompiled.lookupNumerator divWitnessColumns entry).toNat) ==
  [2147483646, 2147483646, 1, 2147483646, 1, 2147483646, 2147483646, 1, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 0, 2147483646, 2147483646, 2147483646, 1, 2147483646]

end RiscvRefinement.Air.Bridge
