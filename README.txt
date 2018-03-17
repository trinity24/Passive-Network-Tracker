The program mydump sniffs the network and prints network packets.

For each packet, mydump prints a record containing the timestamp, source and
destination MAC address, EtherType, packet length, source and destination IP
address and port, protocol type (e.g., "TCP", "UDP", "ICMP", "OTHER"), and the
raw content of the packet payload. 

The device which we want to sniff on can be given using -i device
If we want to read a pcap file, then it can be mentioned using -r filename.pcap
We can also use filters on the packets and its payload.
We can use -s string to filter the packets with payload containing "string". 

A BPF filter can also be given which filters the packets which satisfies this filter
and rest of the packets are dumped. 



So, below command line can be used to run this file. 

mydump [-i interface] [-r file] [-s string] expression

-i  Live capture from the network device <interface> (e.g., eth0). If not
    specified, mydump should automatically select a default interface to
    listen on (hint 1). Capture should continue indefinitely until the user
    terminates the program.

-r  Read packets from <file> in tcpdump format (hint 2).

-s  Keep only packets that contain <string> in their payload (after any BPF
    filter is applied). You are not required to implement wildcard or regular
    expression matching. A simple string matching operation should suffice
    (hint 3).

<expression> is a BPF filter that specifies which packets will be dumped. If
no filter is given, all packets seen on the interface (or contained in the
trace) should be dumped. Otherwise, only packets matching <expression> should
be dumped.

Follow below instructions to run the code: 
make

Example : 

mydump -i en0 -s http ip

2017-10-14 23:19:53.500251 b8:af:67:63:a3:28->8c:85:90:6:aa:c1 34.232.91.193:443->172.24.18.189:53488   TCP type 0x8 len 761 
00000   78 74 65 72 6e 61 6c 43  41 52 6f 6f 74 2e 63 72    xternalCARoot.cr
00016   6c 30 35 06 08 2b 06 01  05 05 07 01 01 04 29 30    l05..+........)0
00032   27 30 25 06 08 2b 06 01  05 05 07 30 01 86 19 68    '0%..+.....0...h
00048   74 74 70 3a 2f 2f 6f 63  73 70 2e 75 73 65 72 74    ttp://ocsp.usert
00064   72 75 73 74 2e 63 6f 6d  30 0d 06 09 2a 86 48 86    rust.com0...*.H.
00080   f7 0d 01 01 0c 05 00 03  82 01 01 00 64 bf 83 f1    ............d...
00096   5f 9a 85 d0 cd b8 a1 29  57 0d e8 5a f7 d1 e9 3e    _......)W..Z...>
00112   f2 76 04 6e f1 52 70 bb  1e 3c ff 4d 0d 74 6a cc    .v.n.Rp..<.M.tj.
00128   81 82 25 d3 c3 a0 2a 5d  4c f5 ba 8b a1 6d c4 54    ..%...*]L....m.T
00144   09 75 c7 e3 27 0e 5d 84  79 37 40 13 77 f5 b4 ac    .u..'.].y7@.w...
00160   1c d0 3b ab 17 12 d6 ef  34 18 7e 2b e9 79 d3 ab    ..;.....4.~+.y..
00176   57 45 0c af 28 fa d0 db  e5 50 95 88 bb df 85 57    WE..(....P.....W
00192   69 7d 92 d8 52 ca 73 81  bf 1c f3 e6 b8 6e 66 11    i}..R.s......nf.
00208   05 b3 1e 94 2d 7f 91 95  92 59 f1 4c ce a3 91 71    ....-....Y.L...q
00224   4c 7c 47 0c 3b 0b 19 f6  a1 b1 6c 86 3e 5c aa c4    L|G.;.....l.>\..
00240   2e 82 cb f9 07 96 ba 48  4d 90 f2 94 c8 a9 73 a2    .......HM.....s.
00256   eb 06 7b 23 9d de a2 f3  4d 55 9f 7a 61 45 98 18    ..{#....MU.zaE..
00272   68 c7 5e 40 6b 23 f5 79  7a ef 8c b5 6b 8b b7 6f    h.^@k#.yz...k..o
00288   46 f4 7b f1 3d 4b 04 d8  93 80 59 5a e0 41 24 1d    F.{.=K....YZ.A$.
00304   b2 8f 15 60 58 47 db ef  6e 46 fd 15 f5 d9 5f 9a    ...`XG..nF...._.
00320   b3 db d8 b8 e4 40 b3 cd  97 39 ae 85 bb 1d 8e bc    .....@...9......
00336   dc 87 9b d1 a6 ef f1 3b  6f 10 38 6f 16 03 03 01    .......;o.8o....
00352   4d 0c 00 01 49 03 00 17  41 04 ea 69 71 13 2d b4    M...I...A..iq.-.
00368   5a 87 7e b8 77 5a 86 2b  68 31 14 6a 2e a9 79 2d    Z.~.wZ.+h1.j..y-
00384   77 98 c3 b3 cd f3 9c bd  c3 09 c3 cb 4b c9 f2 44    w...........K..D
00400   45 b0 8b 54 e9 81 84 a6  1f 1c 2c a5 73 09 2a bd    E..T......,.s.*.
00416   42 10 af 52 19 d1 e1 53  f3 77 06 01 01 00 73 96    B..R...S.w....s.
00432   51 fb 97 f5 86 17 21 10  57 1d da af 21 af cf 29    Q.....!.W...!..)
00448   43 ef a9 82 77 68 38 d9  75 60 81 ed 38 8f 05 b5    C...wh8.u`..8...
00464   4b 76 96 75 3a d5 6a a2  71 59 8f e6 9c 9c 74 ad    Kv.u:.j.qY....t.
00480   06 af 39 2a fe 77 88 5a  3b fa 75 6e c8 3d a0 7c    ..9*.w.Z;.un.=.|
00496   bd 07 92 0c 22 2d 7c b2  9c c9 6c c4 3d 91 9c 49    ...."-|...l.=..I
00512   25 85 41 ac c4 1c 08 bd  23 56 44 7d ad 2c e2 13    %.A.....#VD}.,..
00528   24 cb 9b 37 ca 19 c2 2f  fd 9a 64 e3 0e 07 51 93    $..7.../..d...Q.
00544   77 18 6e 5b 78 28 f8 60  af a8 b8 6b d0 f5 41 5b    w.n[x(.`...k..A[
00560   05 e8 2a b4 e6 1e d6 a7  d2 99 aa 43 c6 ee 97 90    ..*........C....
00576   7d c1 1b 3b 69 3e c7 af  96 8e e5 9e d5 86 a6 5f    }..;i>........._
00592   ff 12 74 51 33 75 9f c0  66 46 5a 71 82 09 f6 42    ..tQ3u..fFZq...B
00608   75 94 29 d3 82 37 28 9a  00 52 ac d6 fc 24 29 c6    u.)..7(..R...$).
00624   0f 60 74 70 5d d7 e5 39  82 6c 27 38 6d 9b c6 23    .`tp]..9.l'8m..#
00640   98 48 05 da 88 bd 81 3f  62 64 d7 65 a0 a9 0b 3a    .H.....?bd.e...:
00656   68 a8 f5 7d 5d fd fc 54  d6 c3 02 8d 0f f0 68 18    h..}]..T......h.
00672   4b 12 80 a2 5f ef 18 70  ce 73 c5 e3 f4 99 16 03    K..._..p.s......
00688   03 00 04 0e 00 00 00                                .......

2017-10-14 23:22:06.162049 b8:af:67:63:a3:28->8c:85:90:6:aa:c1 172.217.12.142:443->172.24.18.189:53503   TCP type 0x8 len 1440 
00000   16 2a 2e 79 6f 75 74 75  62 65 2d 6e 6f 63 6f 6f    .*.youtube-nocoo
00016   6b 69 65 2e 63 6f 6d 82  0d 2a 2e 79 6f 75 74 75    kie.com..*.youtu
00032   62 65 2e 63 6f 6d 82 16  2a 2e 79 6f 75 74 75 62    be.com..*.youtub
00048   65 65 64 75 63 61 74 69  6f 6e 2e 63 6f 6d 82 07    eeducation.com..
00064   2a 2e 79 74 2e 62 65 82  0b 2a 2e 79 74 69 6d 67    *.yt.be..*.ytimg
00080   2e 63 6f 6d 82 1a 61 6e  64 72 6f 69 64 2e 63 6c    .com..android.cl
00096   69 65 6e 74 73 2e 67 6f  6f 67 6c 65 2e 63 6f 6d    ients.google.com
00112   82 0b 61 6e 64 72 6f 69  64 2e 63 6f 6d 82 1b 64    ..android.com..d
00128   65 76 65 6c 6f 70 65 72  2e 61 6e 64 72 6f 69 64    eveloper.android
00144   2e 67 6f 6f 67 6c 65 2e  63 6e 82 1c 64 65 76 65    .google.cn..deve
00160   6c 6f 70 65 72 73 2e 61  6e 64 72 6f 69 64 2e 67    lopers.android.g
00176   6f 6f 67 6c 65 2e 63 6e  82 04 67 2e 63 6f 82 06    oogle.cn..g.co..
00192   67 6f 6f 2e 67 6c 82 14  67 6f 6f 67 6c 65 2d 61    goo.gl..google-a
00208   6e 61 6c 79 74 69 63 73  2e 63 6f 6d 82 0a 67 6f    nalytics.com..go
00224   6f 67 6c 65 2e 63 6f 6d  82 12 67 6f 6f 67 6c 65    ogle.com..google
00240   63 6f 6d 6d 65 72 63 65  2e 63 6f 6d 82 18 73 6f    commerce.com..so
00256   75 72 63 65 2e 61 6e 64  72 6f 69 64 2e 67 6f 6f    urce.android.goo
00272   67 6c 65 2e 63 6e 82 0a  75 72 63 68 69 6e 2e 63    gle.cn..urchin.c
00288   6f 6d 82 0a 77 77 77 2e  67 6f 6f 2e 67 6c 82 08    om..www.goo.gl..
00304   79 6f 75 74 75 2e 62 65  82 0b 79 6f 75 74 75 62    youtu.be..youtub
00320   65 2e 63 6f 6d 82 14 79  6f 75 74 75 62 65 65 64    e.com..youtubeed
00336   75 63 61 74 69 6f 6e 2e  63 6f 6d 82 05 79 74 2e    ucation.com..yt.
00352   62 65 30 68 06 08 2b 06  01 05 05 07 01 01 04 5c    be0h..+........\
00368   30 5a 30 2b 06 08 2b 06  01 05 05 07 30 02 86 1f    0Z0+..+.....0...
00384   68 74 74 70 3a 2f 2f 70  6b 69 2e 67 6f 6f 67 6c    http://pki.googl
00400   65 2e 63 6f 6d 2f 47 49  41 47 32 2e 63 72 74 30    e.com/GIAG2.crt0
00416   2b 06 08 2b 06 01 05 05  07 30 01 86 1f 68 74 74    +..+.....0...htt
00432   70 3a 2f 2f 63 6c 69 65  6e 74 73 31 2e 67 6f 6f    p://clients1.goo
00448   67 6c 65 2e 63 6f 6d 2f  6f 63 73 70 30 1d 06 03    gle.com/ocsp0...
00464   55 1d 0e 04 16 04 14 11  9e 3a e3 ba 68 be d7 b6    U........:..h...
00480   eb cf 46 8a 20 92 a0 a7  3b e3 42 30 0c 06 03 55    ..F. ...;.B0...U
00496   1d 13 01 01 ff 04 02 30  00 30 1f 06 03 55 1d 23    .......0.0...U.#
00512   04 18 30 16 80 14 4a dd  06 16 1b bc f6 68 b5 76    ..0...J......h.v
00528   f5 81 b6 bb 62 1a ba 5a  81 2f 30 21 06 03 55 1d    ....b..Z./0!..U.
00544   20 04 1a 30 18 30 0c 06  0a 2b 06 01 04 01 d6 79     ..0.0...+.....y
00560   02 05 01 30 08 06 06 67  81 0c 01 02 02 30 30 06    ...0...g.....00.
00576   03 55 1d 1f 04 29 30 27  30 25 a0 23 a0 21 86 1f    .U...)0'0%.#.!..
00592   68 74 74 70 3a 2f 2f 70  6b 69 2e 67 6f 6f 67 6c    http://pki.googl
00608   65 2e 63 6f 6d 2f 47 49  41 47 32 2e 63 72 6c 30    e.com/GIAG2.crl0
00624   0d 06 09 2a 86 48 86 f7  0d 01 01 0b 05 00 03 82    ...*.H..........
00640   01 01 00 38 20 b2 c6 f2  0b 5e ca e3 dc 6f b4 04    ...8 ....^...o..
00656   d5 58 f2 ef 82 ce a3 81  9e 51 c4 c6 73 62 4f a4    .X.......Q..sbO.
00672   ee f4 dc b2 13 ac 6a d4  8f d1 c7 f7 ab 75 1a f5    ......j......u..
00688   47 c6 46 cf 48 27 68 ba  e8 7b 51 a8 bb b0 22 5d    G.F.H'h..{Q..."]
00704   8e 75 ca 61 b1 44 ba 04  c3 e5 dc 1d db c5 85 1b    .u.a.D..........
00720   a3 d5 7f c7 c3 31 6c 19  f8 68 db 22 b9 0f ca 4b    .....1l..h."...K
00736   84 ea 9a 79 38 7b c2 1c  49 df 90 89 83 a4 83 50    ...y8{..I......P
00752   11 55 ff a3 c2 9b b3 b0  ef e3 76 6c 9c 63 d0 18    .U........vl.c..
00768   18 de 45 c9 8a 3c 40 96  ed 56 04 08 a9 31 4e f7    ..E..<@..V...1N.
00784   3f 30 30 7d 14 48 1d 66  be 32 df da ee 31 17 a3    ?00}.H.f.2...1..
00800   e4 5a 03 af dc f1 b1 c2  ad 52 80 7b d6 54 30 8f    .Z.......R.{.T0.
00816   a1 a1 b1 0c e8 94 e0 6a  50 f0 7c 6b e4 43 1d e9    .......jP.|k.C..
00832   1b ca 50 af 08 6d c2 b4  7e 2f 37 66 af c8 19 8e    ..P..m..~/7f....
00848   1c 15 b7 1b ae 4b 84 ce  53 bb 7b 7f 1c 03 47 ae    .....K..S.{...G.
00864   f6 5d 83 50 4e 3f ef b3  00 f8 7b 6e 62 56 4e 45    .].PN?....{nbVNE
00880   77 7c 0c c3 37 37 36 34  14 0a 77 95 b3 f3 a9 5d    w|..7764..w....]
00896   30 f3 a3 00 04 2c 30 82  04 28 30 82 03 10 a0 03    0....,0..(0.....
00912   02 01 02 02 10 01 00 21  25 88 b0 fa 59 a7 77 ef    .......!%...Y.w.
00928   05 7b 66 27 df 30 0d 06  09 2a 86 48 86 f7 0d 01    .{f'.0...*.H....
00944   01 0b 05 00 30 42 31 0b  30 09 06 03 55 04 06 13    ....0B1.0...U...
00960   02 55 53 31 16 30 14 06  03 55 04 0a 13 0d 47 65    .US1.0...U....Ge
00976   6f 54 72 75 73 74 20 49  6e 63 2e 31 1b 30 19 06    oTrust Inc.1.0..
00992   03 55 04 03 13 12 47 65  6f 54 72 75 73 74 20 47    .U....GeoTrust G
01008   6c 6f 62 61 6c 20 43 41  30 1e 17 0d 31 37 30 35    lobal CA0...1705
01024   32 32 31 31 33 32 33 37  5a 17 0d 31 38 31 32 33    22113237Z..18123
01040   31 32 33 35 39 35 39 5a  30 49 31 0b 30 09 06 03    1235959Z0I1.0...
01056   55 04 06 13 02 55 53 31  13 30 11 06 03 55 04 0a    U....US1.0...U..
01072   13 0a 47 6f 6f 67 6c 65  20 49 6e 63 31 25 30 23    ..Google Inc1%0#
01088   06 03 55 04 03 13 1c 47  6f 6f 67 6c 65 20 49 6e    ..U....Google In
01104   74 65 72 6e 65 74 20 41  75 74 68 6f 72 69 74 79    ternet Authority
01120   20 47 32 30 82 01 22 30  0d 06 09 2a 86 48 86 f7     G20.."0...*.H..
01136   0d 01 01 01 05 00 03 82  01 0f 00 30 82 01 0a 02    ...........0....
01152   82 01 01 00 9c 2a 04 77  5c d8 50 91 3a 06 a3 82    .....*.w\.P.:...
01168   e0 d8 50 48 bc 89 3f f1  19 70 1a 88 46 7e e0 8f    ..PH..?..p..F~..
01184   c5 f1 89 ce 21 ee 5a fe  61 0d b7 32 44 89 a0 74    ....!.Z.a..2D..t
01200   0b 53 4f 55 a4 ce 82 62  95 ee eb 59 5f c6 e1 05    .SOU...b...Y_...
01216   80 12 c4 5e 94 3f bc 5b  48 38 f4 53 f7 24 e6 fb    ...^.?.[H8.S.$..
01232   91 e9 15 c4 cf f4 53 0d  f4 4a fc 9f 54 de 7d be    ......S..J..T.}.
01248   a0 6b 6f 87 c0 d0 50 1f  28 30 03 40 da 08 73 51    .ko...P.(0.@..sQ
01264   6c 7f ff 3a 3c a7 37 06  8e bd 4b 11 04 eb 7d 24    l..:<.7...K...}$
01280   de e6 f9 fc 31 71 fb 94  d5 60 f3 2e 4a af 42 d2    ....1q...`..J.B.
01296   cb ea c4 6a 1a b2 cc 53  dd 15 4b 8b 1f c8 19 61    ...j...S..K....a
01312   1f cd 9d a8 3e 63 2b 84  35 69 65 84 c8 19 c5 46    ....>c+.5ie....F
01328   22 f8 53 95 be e3 80 4a  10 c6 2a ec ba 97 20 11    ".S....J..*... .
01344   c7 39 99 10 04 a0 f0 61  7a 95 25 8c 4e 52 75 e2    .9.....az.%.NRu.
01360   b6 ed 08 ca 14 fc ce 22  6a b3 4e cf 46 03          ......."j.N.F.


