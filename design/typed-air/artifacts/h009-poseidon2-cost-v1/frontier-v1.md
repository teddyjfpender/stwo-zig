# H-009 Poseidon2 materialization cost frontier

> Experimental proposal evidence only. This artifact changes no production layout, proof statement, prover, verifier, or transcript.

The bounded deterministic search completed **1** pass over **1124** candidate edits and retained **126** non-seed Pareto proposals. It makes no global-optimality claim.

## Identity

| Field | Value |
| --- | --- |
| Cost scope | `stwo.typed-air.cost.poseidon2-permutation-direct` |
| Semantic digest | `9e8c3b5accdc2be31cf8ca128b5b27c87613f691ee8fd25e031f4286ceac81ed` |
| Cost-model digest | `12670408a3c3020c62d279c997338d9c427d0755697aca2a954f6a1d88a9ba11` |
| Search configuration | `32dc4c0b5e265c74b159a6e661d4f6f0b06f3b54d62efe286364b5dae92db8ed` |
| Result digest | `7948117553242d3154a8bd09ca1664c4bf6e5cbcc515a4ce80461cf544d39193` |
| Fixed/equality direct roots | 4 + 426 = 430 |
| Main / interaction columns | 445 / 8 |

The fixed scope is the 430-root Poseidon permutation direct AIR: enabler booleanity, 426 candidate equalities, wide/io booleanity, and mutual exclusion. The surrounding hash-component shell and LogUp algebra are outside this cost scope.

## Baseline structural vector

| Coordinate | Value |
| --- | ---: |
| `materialization_count` | 426 |
| `base_main_columns` | 19 |
| `candidate_main_columns` | 445 |
| `direct_roots` | 430 |
| `interaction_columns` | 8 |
| `canonical_direct_nodes` | 3460 |
| `canonical_direct_additions` | 1346 |
| `canonical_direct_subtractions` | 429 |
| `canonical_direct_negations` | 0 |
| `canonical_direct_multiplications` | 1080 |
| `unique_committed_column_reads` | 445 |
| `canonical_streaming_peak_live_nodes` | 39 |
| `semantic_witness_nodes` | 2171 |

`canonical_streaming_peak_live_nodes` is an idealized root-folding schedule for the modeled proposal DAG. `canonical_direct_nodes` is the size of that DAG, not observed backend scratch. The production Poseidon component uses a separate static evaluator, and no alternative proposal currently executes on CPU or Metal. H-010 must build and measure one common candidate evaluator before comparing work or memory.

## Frontier

**126/126** retained proposals have the exact baseline structural and scenario vector. Equal objective points remain separate because they name different authenticated cut sets.

| # | Proposal digest | Edit | Pass | Removed | Added | Materials | Direct nodes | Baseline-equivalent |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 0 | `009f28b183b765331f19cb21f939aa2c08c58fe0ab5b133476d713e897919ab1` | swap | 1 | 1689 | 1656 | 426 | 3460 | yes |
| 1 | `04d0f10d3fd29f0b58ec5d642aead8f3d6e94e45a92b771f8a92e3f59e631de6` | swap | 1 | 1699 | 1664 | 426 | 3460 | yes |
| 2 | `055a8194272e58abd73a54ab0db175d1b166c09e4879ca1fe5c8525a8b9c2c62` | swap | 1 | 272 | 261 | 426 | 3460 | yes |
| 3 | `05c552951aad8dc170c48275099e445f51be7691e497714da7c79ae106b7d7af` | swap | 1 | 432 | 411 | 426 | 3460 | yes |
| 4 | `070c78cafec05bec36429ee61bea71f556929de100557724e837ff08167ab081` | swap | 1 | 2029 | 1999 | 426 | 3460 | yes |
| 5 | `07deecb5e1c48cb505ebd49cfa3fb90f08c22c39790454be7a2db70759ed3126` | swap | 1 | 1521 | 1489 | 426 | 3460 | yes |
| 6 | `095f6f1d67f91d326aa1ae0d207f96b527952352254aaf246b6d3a340e38279f` | swap | 1 | 450 | 420 | 426 | 3460 | yes |
| 7 | `09d7678322e3183829763fc388900e786bd1ee9b4d9ffe0207c920650f967026` | swap | 1 | 1863 | 1828 | 426 | 3460 | yes |
| 8 | `0a545ae65e565f4b06d6dba3ed68ad250fe60e8caf70cabcc2f64554029b0714` | swap | 1 | 758 | 732 | 426 | 3460 | yes |
| 9 | `0b6a401eb335d74495953d60d62f41ced35dae157ad21fbd1c1eb33cd36a540f` | swap | 1 | 1691 | 1663 | 426 | 3460 | yes |
| 10 | `0c0d9bf61cf838450cbd845709a25b42f63a0c31aa3450513c17b092ce011ab1` | swap | 1 | 458 | 421 | 426 | 3460 | yes |
| 11 | `0cfddb8a17fc0005994ae44da83f91566bdea981a2c5639c73da67990ddc2ee9` | swap | 1 | 460 | 428 | 426 | 3460 | yes |
| 12 | `119e544c7142175a252271aba5e5f796bb32c4b9e7dafe369480ffe1844fe2a9` | swap | 1 | 1875 | 1843 | 426 | 3460 | yes |
| 13 | `130fe2db9469fece19a5ac02023979992824c2e90617de847d2ed552bc00fa64` | swap | 1 | 1857 | 1834 | 426 | 3460 | yes |
| 14 | `149726246333717d009c7eeb9fda7eaab39210d1f164312edaa8373288e83d0c` | swap | 1 | 1695 | 1677 | 426 | 3460 | yes |
| 15 | `14e6a8c3e82354d400cd7210972396fc460082940c23e0f2deef449c4f2ac22c` | swap | 1 | 1705 | 1658 | 426 | 3460 | yes |
| 16 | `15308c0aea4b86ee84e2d9f2e6cc0ef09bcfbbb28af9c4de3e0e62b5e2c8ee3b` | swap | 1 | 1040 | 1008 | 426 | 3460 | yes |
| 17 | `154a3d7fd3b8f2f6ebdfbb6f6e45789199314751c6e1bf8f9f2d06676eab6279` | swap | 1 | 1693 | 1670 | 426 | 3460 | yes |
| 18 | `15aa354034a97e7368a4495aff76ed3bb84679daff77b95e8efe57621871621d` | swap | 1 | 618 | 571 | 426 | 3460 | yes |
| 19 | `185efa5069bb5795ed74904d2d346db54866196a1355558be3d02fd47b3276cd` | swap | 1 | 624 | 592 | 426 | 3460 | yes |
| 20 | `1861bdea7926b190fa7dade30069a1df076284cf6ea1a54d4ee36b0dc31e718f` | swap | 1 | 1853 | 1820 | 426 | 3460 | yes |
| 21 | `1a9070297dacd235f3f8c11f5f5f7638f48dcadf230e955ca5197fc1f06f9417` | swap | 1 | 2027 | 1992 | 426 | 3460 | yes |
| 22 | `1b9bbb2324c9cd3a03d5ff8494dcda6dc443971cf303eab7492cb9639bdfccc9` | swap | 1 | 1867 | 1842 | 426 | 3460 | yes |
| 23 | `1c75845b41ffd93edf3bba2812ad86884407f3ab489b82059ae58472b8cc76ef` | swap | 1 | 1523 | 1491 | 426 | 3460 | yes |
| 24 | `1cf2e5c0ea778f182ee18c1ee2a1accac772ed0dd0f5d231cbbdf1a56843ffed` | swap | 1 | 444 | 426 | 426 | 3460 | yes |
| 25 | `1cfa622d2bf073589967edc4840c0c7ddebf95d0ac68b7e672e4f5eb4d361854` | swap | 1 | 2033 | 1986 | 426 | 3460 | yes |
| 26 | `1d5ca83de1406ed8e2f2a6aa590fe134ef4774107c60c5d5385eac8d7842d917` | swap | 1 | 1681 | 1655 | 426 | 3460 | yes |
| 27 | `253c19069266b0ae1c37dd07254d5c031c70787f1a7c7aa376d0053bb9ef8908` | swap | 1 | 1411 | 1379 | 426 | 3460 | yes |
| 28 | `25cabab98f4ed4b25ff1dd987379090cc3b311ef0fda9474cda5981703354c80` | swap | 1 | 606 | 583 | 426 | 3460 | yes |
| 29 | `281a5d1c8a9790333e911cff76d19140d63af4a7323b5da80d626ad425384677` | swap | 1 | 278 | 255 | 426 | 3460 | yes |
| 30 | `29c2b2f871fce9582d35e9fcdc65f61ac47dfa2cdec6e1355565370c227dff8d` | swap | 1 | 1519 | 1487 | 426 | 3460 | yes |
| 31 | `29d8a275cf600cdf30ea5a25ce189b2caf45e5472aafbf842e3fe99deffa90fe` | swap | 1 | 434 | 418 | 426 | 3460 | yes |
| 32 | `2aeed77325efedf02641bcc1768defe6df8d337894d98a2bed7da9d5a483826f` | swap | 1 | 1531 | 1499 | 426 | 3460 | yes |
| 33 | `3343b9c9a7937fdca26182cad81c06148a102254efbe54c00b359d09e391956b` | swap | 1 | 1851 | 1840 | 426 | 3460 | yes |
| 34 | `36e00db604f73d7065f7b83dd589873eda79496fb3c9c0e8cca2280febc5ed30` | swap | 1 | 284 | 249 | 426 | 3460 | yes |
| 35 | `389e100e3295cf84bf82dfc536fb91e30b52c182b239c765a75a651379e968ee` | swap | 1 | 610 | 570 | 426 | 3460 | yes |
| 36 | `41de317070773f89600a61f69fe9109ed67202f9b3e4362dc37971924ce11b10` | swap | 1 | 2011 | 1990 | 426 | 3460 | yes |
| 37 | `44b8efedac158c646843723ef00f0dc227d594d840145e27f1c99997ad94e20c` | swap | 1 | 436 | 425 | 426 | 3460 | yes |
| 38 | `45972479847f9f94154c5a8944c322148e93f6c6033f0d299d5781f986955235` | swap | 1 | 1547 | 1515 | 426 | 3460 | yes |
| 39 | `4665ccad134d52c748d4becbba82a7ac097ed6c0af9048827e6469859a456d29` | swap | 1 | 881 | 849 | 426 | 3460 | yes |
| 40 | `46864f46a657fbfb9ac647e8fbc004d14eeab3815ff5cf6673c7ca2e30426e88` | swap | 1 | 1093 | 1061 | 426 | 3460 | yes |
| 41 | `47625feae241162b0f255803d76808f78c1b7932fe635f1f64ad177512f7c4df` | swap | 1 | 1701 | 1671 | 426 | 3460 | yes |
| 42 | `49d4de3ae4c1c6752ed3eb2d0230f75ff2ecdd45c9876d790a4a5aa9a76246b0` | swap | 1 | 616 | 591 | 426 | 3460 | yes |
| 43 | `4bbb9be072d6a50ef17cba68bb5fd688eb720b3f12e33a33f20fd685d61742c3` | swap | 1 | 448 | 413 | 426 | 3460 | yes |
| 44 | `4dbb75847453cfbda36d2abb9fe1d390895271297e04276d522ec20fd688cfae` | swap | 1 | 1537 | 1505 | 426 | 3460 | yes |
| 45 | `510a3e642235e9a356e652f06ab403843c475b88cea7f19b3300496d3e75c317` | swap | 1 | 1685 | 1669 | 426 | 3460 | yes |
| 46 | `522c5700cf81157252143b1df2453ffc6bd98a51955a1e2b7a6b3ea5966afaf6` | swap | 1 | 1535 | 1503 | 426 | 3460 | yes |
| 47 | `534d385b9641a867ef262c566cb614277178cd99c19379be82da44b3e43a9ded` | swap | 1 | 828 | 781 | 426 | 3460 | yes |
| 48 | `561c0ca27d8f9712abbeb8556e7d5a8cd26ea5588d341f7f1abad193f12491d4` | swap | 1 | 268 | 247 | 426 | 3460 | yes |
| 49 | `56e146c5eacea4076e0586ebd33411e935cdeb7bd3971878e295006c558cc202` | swap | 1 | 452 | 427 | 426 | 3460 | yes |
| 50 | `5856c773e749dc4fbf57e961d9d3b40a141c07e417bbfd9c7ae751c8c6a55d37` | swap | 1 | 622 | 585 | 426 | 3460 | yes |
| 51 | `5a4e15b0e917a310daa140e83b7d7073b093daacdd28a3e90cdf24e892ecbfbd` | swap | 1 | 2019 | 1991 | 426 | 3460 | yes |
| 52 | `5a7690cc2435b89d5a8ebe64a6402f89d44dede3670ad975f7f1700b875089c6` | swap | 1 | 454 | 407 | 426 | 3460 | yes |
| 53 | `5c03c4fc977f12ba84f96e1b3443c400d885ed955608649f02e68606af837f37` | swap | 1 | 2021 | 1998 | 426 | 3460 | yes |
| 54 | `5f90fdb98695ca4f111f49208ce36a232be7dd574e97eaa8235869319e805311` | swap | 1 | 608 | 590 | 426 | 3460 | yes |
| 55 | `60a6974909e6ee6ae2fbdabc6efd73f834af25f37907d182ebd4841ee27c9525` | swap | 1 | 604 | 576 | 426 | 3460 | yes |
| 56 | `60f6c45fc4e70c458ca2d1a719d319a7b9e52ccac11d243622c1faaea2a18802` | swap | 1 | 438 | 405 | 426 | 3460 | yes |
| 57 | `6233cc0cd63b1a3a0740a7128f1c8b54116d707b91aec73bd6c12c65d3a5b252` | swap | 1 | 1707 | 1665 | 426 | 3460 | yes |
| 58 | `65867e4e345a859df0b9f9c853ed90917cae1e0b4dabec91111975378f3c1542` | swap | 1 | 1865 | 1835 | 426 | 3460 | yes |
| 59 | `661a172515a254cef806bef7a5d97120e33b4a609056b06c8fa2e1eff9248fbe` | swap | 1 | 1869 | 1822 | 426 | 3460 | yes |
| 60 | `662338db02cbb0e7e1e4eb7f486b2f6a05087e96f8d3597ca50dd667faa9ae6a` | swap | 1 | 2039 | 2007 | 426 | 3460 | yes |
| 61 | `6748627bf283b279124ba4a9111b258023fa0b31c8719bf31a5ccc7616aa135b` | swap | 1 | 270 | 254 | 426 | 3460 | yes |
| 62 | `6c2df8fa3fa425d2ecf0cb3eb6167712482db4480e2424eb4fd7b612616a764d` | swap | 1 | 1861 | 1821 | 426 | 3460 | yes |
| 63 | `7005f287f9ce4a822f915e13a29690d4e2850078f85f98334c6625b3ced2f0a8` | swap | 1 | 286 | 256 | 426 | 3460 | yes |
| 64 | `73431e1338375beec9132cf57378a18fa7cd9b97742fd8fc76c3e96c8513f082` | swap | 1 | 1305 | 1273 | 426 | 3460 | yes |
| 65 | `74a497f7530d2c7eaad940f8a77842b1aeea99a35d657d5a26d71da5215c85eb` | swap | 1 | 276 | 248 | 426 | 3460 | yes |
| 66 | `74ef29741484878bc453fa24ef8cba3320791a6c4af8a8195c2d2fc9862133fb` | swap | 1 | 602 | 569 | 426 | 3460 | yes |
| 67 | `75d12ee4967cce8594a47e9a7180adbc1b3b298f574eb7ed7e9355edf3d81a80` | swap | 1 | 2013 | 1997 | 426 | 3460 | yes |
| 68 | `78356c457a3ea68fd49dc6112c9a1927e1ec647a756518b914fd0dc872e9e049` | swap | 1 | 1525 | 1493 | 426 | 3460 | yes |
| 69 | `7a022598fb8a8be9f3c05361439c0a23a0789daff54c1d399f50e49a61568243` | swap | 1 | 1873 | 1836 | 426 | 3460 | yes |
| 70 | `7a977e12c2aa83b5d4d8e28e0dc1b86eadeee5d0e09f8269c4b953dc7e1e8471` | swap | 1 | 2037 | 2000 | 426 | 3460 | yes |
| 71 | `7c7f17a9c7767dba67b33abe291b698502c9daf6c32eaf747fce61ac7b63f4f4` | swap | 1 | 1527 | 1495 | 426 | 3460 | yes |
| 72 | `7ea40c1ed22b8f1563b6a58877cb51ddcab1d36f716fed74ed0f7dd5dd7d1675` | swap | 1 | 620 | 578 | 426 | 3460 | yes |
| 73 | `7f833feefc574084b3828bd979badfac5e2d663d282380515b1ef41dff70d0f3` | swap | 1 | 2035 | 1993 | 426 | 3460 | yes |
| 74 | `800ede0ea1ca64ba8b655baf09b693de6587cf2ce6ae8015f9c61894693aa06a` | swap | 1 | 598 | 582 | 426 | 3460 | yes |
| 75 | `807184a7d1fad117afd46dc7baa9fe35a8246b254551f94f354433a63b9c90ed` | swap | 1 | 2025 | 1985 | 426 | 3460 | yes |
| 76 | `822f53884c4d7a5e649260593485262a0237af60d0fcd0a29650e86fb870ce90` | swap | 1 | 442 | 419 | 426 | 3460 | yes |
| 77 | `84d3cb25a6b58eb3915bb783a86e8e81fee2047fcfabb8db35d584440c5d72ef` | swap | 1 | 288 | 263 | 426 | 3460 | yes |
| 78 | `876088dfc82a2afe7b7409b48220a4509d89bcf50f70d5caa7091fb25c093b18` | swap | 1 | 1697 | 1657 | 426 | 3460 | yes |
| 79 | `88c218d232e3e7322690e31eebbde1cb2889e7a67859dbeb45580947dd3e9352` | swap | 1 | 1845 | 1819 | 426 | 3460 | yes |
| 80 | `89c318737b943a48ff747dbf9222c442d01d15d2c9c113c82ebca07cfc0a1337` | swap | 1 | 1539 | 1507 | 426 | 3460 | yes |
| 81 | `8e6c68f4095faeefc8304520a9e792bf3721f08e402a9a23672d3707081d3ece` | swap | 1 | 1146 | 1114 | 426 | 3460 | yes |
| 82 | `916e5e7d53ca05890f37e927bb6993909925c61c5a80a5e63928d69d78b0a798` | swap | 1 | 1252 | 1220 | 426 | 3460 | yes |
| 83 | `9350408911b0e8f9135c4b0e601f01c88fb3ba1ccfba2969756ca6973d63cace` | swap | 1 | 296 | 264 | 426 | 3460 | yes |
| 84 | `94bded1207a30b47f2e1811a7f4b30b249a0b4da2400271d72fa62ea93966fb2` | swap | 1 | 614 | 584 | 426 | 3460 | yes |
| 85 | `997d7236203de34953b8479ea2773a0772737d6e7f81c08537f8bd744f5ccd44` | swap | 1 | 266 | 240 | 426 | 3460 | yes |
| 86 | `9b9558c815c9cdbb37e906088ab79ff47867de828fa4120c94da6d5a7d0b2a7b` | swap | 1 | 612 | 577 | 426 | 3460 | yes |
| 87 | `a272d607e5c3d616f0c01250dd3218549b2ede9eacce8462f34bc1fde4e71a63` | swap | 1 | 1199 | 1167 | 426 | 3460 | yes |
| 88 | `a27f2c3195d32cd583a89ffacf922938d7ee11456ad3571bc6c95d358f43f09c` | swap | 1 | 280 | 262 | 426 | 3460 | yes |
| 89 | `a79dec7ac41f53cd7891508b65d3c6feeb84167c2cc6a284979d1e05c1d4e2af` | swap | 1 | 987 | 955 | 426 | 3460 | yes |
| 90 | `aa9e3226cf32739415849762103c937518d5405f14f5182f6993fcf95635e03a` | swap | 1 | 290 | 243 | 426 | 3460 | yes |
| 91 | `aaaeeaf4cc5078970691227b481b56d7cb13222ce6f51f702ef944693f464b4c` | swap | 1 | 1545 | 1513 | 426 | 3460 | yes |
| 92 | `ae33d31eab62c10a8be6826a6e739c6e30dddf154eec22d10194e3583fa37e23` | swap | 1 | 1517 | 1485 | 426 | 3460 | yes |
| 93 | `aefbf8774e7fdd9a49b8477d7b58a56b3ec01a8ab5ca5639dc965faf4f711feb` | swap | 1 | 282 | 242 | 426 | 3460 | yes |
| 94 | `b1b250d7fcb11c78f676eb8a746b507424a64a0f7787227825b268f8cac9bc36` | swap | 1 | 1849 | 1833 | 426 | 3460 | yes |
| 95 | `b276e16afdbdbed97a3f61b9e046bce33eff54ed3ce543400544b0a025e20445` | swap | 1 | 292 | 250 | 426 | 3460 | yes |
| 96 | `b4484476e26c2379c4a2d3a5c73685202f71a075b2123c1f8909aad12c84b5a9` | swap | 1 | 600 | 589 | 426 | 3460 | yes |
| 97 | `b4afde12851fec7f441c576d23ec196847f1f6f640b8a37d10c1628cbc1b8be8` | swap | 1 | 1859 | 1841 | 426 | 3460 | yes |
| 98 | `b4b71198bb8d01c6a3d1b7d19e337464cfdfc4f42154f4d6d48fb9d1be199eb5` | swap | 1 | 430 | 404 | 426 | 3460 | yes |
| 99 | `b7b765ff49c204e7f5260099dad6a9d803fcd7013eb159cae64a6dbb10c1ae6a` | swap | 1 | 594 | 568 | 426 | 3460 | yes |
| 100 | `b7fe06df5869095f171362a11080d7c2255bba39b199ee953504b8f5347babc7` | swap | 1 | 1703 | 1678 | 426 | 3460 | yes |
| 101 | `b8aa5d5e554cfaca5dd3b3b2d0aee8a457d9105047b99ee67c32b4ddc4b52a8e` | swap | 1 | 1543 | 1511 | 426 | 3460 | yes |
| 102 | `b9558ae589f8ead1630fef34adac87d32172049299598b257b0fabdf0b4c602b` | swap | 1 | 274 | 241 | 426 | 3460 | yes |
| 103 | `b972642a8a37a8bdc3e668dd81f8fbeae50f2fee6dbda65c79654299072b9485` | swap | 1 | 1464 | 1432 | 426 | 3460 | yes |
| 104 | `ba7af425882afca6432a1b656ec5e471ef2ca093d69a2075772fe2c73f1466a4` | swap | 1 | 1711 | 1679 | 426 | 3460 | yes |
| 105 | `ba9cca3741f74d593ee6f825cef310621a5c47d0a4bec9b09a806de5d2f8bdbf` | swap | 1 | 456 | 414 | 426 | 3460 | yes |
| 106 | `c1cb8c0d0f8fc31140f77192c7f4e6f8b340922859b6277e0d030255edaca355` | swap | 1 | 1847 | 1826 | 426 | 3460 | yes |
| 107 | `c8a0163b097ecaf3471cc7ae3f222677eae275bfab0347a9614d1eb5c88bd4cb` | swap | 1 | 1871 | 1829 | 426 | 3460 | yes |
| 108 | `c9a2d974dcc2028d902398c143b80eec377e37e7aa535765443370863158106a` | swap | 1 | 1683 | 1662 | 426 | 3460 | yes |
| 109 | `cb20e0e32ce742b73b8af7ef85372d0e7ff4c8b512fa9b4d746a1bb49f47c660` | swap | 1 | 1533 | 1501 | 426 | 3460 | yes |
| 110 | `cc45c3036ac184264a8456c2c157c52a5c4ab6b909dfbdafbb2d8fcf5c6f617c` | swap | 1 | 1709 | 1672 | 426 | 3460 | yes |
| 111 | `d07764abd0419193f20e55a55ba579995676ecacd60cfb0fbd124750199bfe79` | swap | 1 | 2009 | 1983 | 426 | 3460 | yes |
| 112 | `d5bd7647d1e3abf373a450a268798bcc446753ffdfa50623553a979fbf309b03` | swap | 1 | 596 | 575 | 426 | 3460 | yes |
| 113 | `d9035daa8b4d8cca4fcc91c343b4e424b3189e7061dcc0362f7b4843569c8a7b` | swap | 1 | 1855 | 1827 | 426 | 3460 | yes |
| 114 | `dc85219b30d475f9ae142bc716b58f7207207b5d166848056e625c3057fdb414` | swap | 1 | 1529 | 1497 | 426 | 3460 | yes |
| 115 | `e3185b817e4e2b484717c6baede84ec844acb6146fb0031c6294bf9f01b5d5f4` | swap | 1 | 934 | 902 | 426 | 3460 | yes |
| 116 | `e615bffe81d30bae56aa9d4f55fdddfb408f47253cc374eee1a38bcc6043e4f7` | swap | 1 | 2023 | 2005 | 426 | 3460 | yes |
| 117 | `e8a6d36bdaa96d41f772cd545d8c88830d047d2d77ccc909da7521eb86764e68` | swap | 1 | 446 | 406 | 426 | 3460 | yes |
| 118 | `e979db07247a7167cd1cebb547c62d16ae76b0a125c3d376212dddc46cf856ad` | swap | 1 | 2015 | 2004 | 426 | 3460 | yes |
| 119 | `eb80f5747dadc02e7913e56bd025d97ff619a462dec6a919f870eed63f00699e` | swap | 1 | 2017 | 1984 | 426 | 3460 | yes |
| 120 | `ed4cad2c6cc6c40362dd3087170c254b6eb38d42728bdcb1bc0c137aee92d4e5` | swap | 1 | 1687 | 1676 | 426 | 3460 | yes |
| 121 | `ef8752ff3a308f1417b2159a89844901d732ae6ebe342cfb4ca71c3bd4e9c9d7` | swap | 1 | 1541 | 1509 | 426 | 3460 | yes |
| 122 | `f4b69f8f89376df625ea339f7779590b1b911e29a22a25f5306c13a97b93471c` | swap | 1 | 2031 | 2006 | 426 | 3460 | yes |
| 123 | `f4c6ff5a075d73dbf90f0d664a4117ba8564348112d0f198b15fd3c5326dc089` | swap | 1 | 294 | 257 | 426 | 3460 | yes |
| 124 | `fd9c6af138414964c2a6962231a2952143e6c9febe0bfac8554b2f64f85a91c0` | swap | 1 | 440 | 412 | 426 | 3460 | yes |
| 125 | `feb957cf4784a7c2a062b4e16e58ee1708fe06b11062d0eee2a8aaa0ec05970e` | swap | 1 | 1358 | 1326 | 426 | 3460 | yes |
