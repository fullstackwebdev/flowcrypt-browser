# FlowCrypt: Encrypt Gmail with PGP


[FlowCrypt](https://flowcrypt.com/) Chrome plugin available at: https://chrome.google.com/webstore/detail/bnjglocicdkmhmoohhfkfkbbkejdhdgc/


20msgs

heavy+bg: 
12.7
12.7

heavy+local:
14.2
14.2

light+bg:
11.56
11.96
11.64

heavy+webworker:
13.54
13.50

light+bg+webworker:
11.63
11.63

light+bg+4webworkers:
9.31
8.49
8.81

light+bg+8webworkers:
8.37
7.78
7.75

light+bg+8workers+nodb:
8.69
7.60
7.75

light+bg+8workers+nodb+pruneapi:
8.68
8.59
8.55

light+bg+8workers+nodb+pruneapi+nostorage: !!! best about double speed / half exec time
7.07
7.10
7.06


light+bg+8workers+nodb+pruneapi+nostorage+zepto:
7.33
7.35
7.54

light+bg+8workers+nodb+pruneapi+nostorage+zepto+optimize$:
7.68
7.62
7.69

light+bg+8workers+nodb+pruneapi+nostorage+optimize$:
7.90
7.77
8.26

light+bg+8workers+nodb+pruneapi+nostorage+norequire:
7.62
7.67
7.70

light+bg+8workers+nodb+pruneapi+nostorage+norequire+zepto:
7.29
7.30
7.52




20 msgs - light+bg+nodb+pruneapi+nostorage
1 worker	9.31	9.20	9.17
8 workers	7.09	6.42	6.35

50msgs - light+bg+nodb+pruneapi+nostorage
1 worker	33.51	24.12	24.13
8 workers	15.25	15.44	15.41




random samples below (not definitive - tends to have large variance between runs)

----------------------- using jquery
0 | 0 | start
3 | 3 | anchorme.js
908 | 911 | jquery
26 | 937 | iso
9 | 946 | require.js
1 | 947 | lang
1 | 948 | factory
19 | 967 | mnemonic
2 | 969 | storage
66 | 1035 | common
4 | 1039 | pgp_block.js before db open
0 | 1039 | pgp_block.js after db open
19 | 1058 | pgp_block.js storage before
0 | 1058 | pgp_block.js storage after
1 | 1059 | pgp_block.js initialize
0 | 1059 | pgp_block.js decrypt and render start
2 | 1061 | pgp_block.js
0 | 1061 | end
3315 | 4376 | pgp_block.js decrypted
1 | 4377 | pgp_block.js rendering
699 | 5076 | pgp_block.js rendered


--------------------- using zepto: faster zepto load but longer overall execution
0 | 0 | start
3 | 3 | anchorme.js
5 | 8 | zepto
24 | 32 | iso
966 | 998 | require.js
1 | 999 | lang
1 | 1000 | factory
3 | 1003 | mnemonic
1 | 1004 | storage
43 | 1047 | common
6 | 1053 | pgp_block.js before db open
0 | 1053 | pgp_block.js after db open
21 | 1074 | pgp_block.js storage before
0 | 1074 | pgp_block.js storage after
0 | 1074 | pgp_block.js initialize
1 | 1075 | pgp_block.js decrypt and render start
2 | 1077 | pgp_block.js
0 | 1077 | end
4437 | 5514 | pgp_block.js decrypted
3 | 5517 | pgp_block.js rendering
139 | 5656 | pgp_block.js rendered

----------------- jquery + no require
0 | 0 | start
4 | 4 | anchorme.js
994 | 998 | jquery
2 | 1000 | iso
1 | 1001 | lang
1 | 1002 | factory
2 | 1004 | mnemonic
2 | 1006 | storage
21 | 1027 | common
5 | 1032 | pgp_block.js before db open
0 | 1032 | pgp_block.js after db open
3 | 1035 | pgp_block.js storage before
0 | 1035 | pgp_block.js storage after
0 | 1035 | pgp_block.js initialize
1 | 1036 | pgp_block.js decrypt and render start
1 | 1037 | pgp_block.js
1 | 1038 | end
4297 | 5335 | pgp_block.js decrypted
2 | 5337 | pgp_block.js rendering
494 | 5831 | pgp_block.js rendered

--------------------- zepto + no require
0 | 0 | start
3 | 3 | anchorme.js
5 | 8 | zepto
3 | 11 | iso
1 | 12 | lang
1 | 13 | factory
3 | 16 | mnemonic
2 | 18 | storage
564 | 582 | common
4 | 586 | pgp_block.js before db open
0 | 586 | pgp_block.js after db open
3 | 589 | pgp_block.js storage before
0 | 589 | pgp_block.js storage after
0 | 589 | pgp_block.js initialize
0 | 589 | pgp_block.js decrypt and render start
1 | 590 | pgp_block.js
0 | 590 | end
3829 | 4419 | pgp_block.js decrypted
3 | 4422 | pgp_block.js rendering
638 | 5060 | pgp_block.js rendered