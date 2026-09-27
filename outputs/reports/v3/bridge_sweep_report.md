# Bridge-Count Sweep: Topological Graph Attack vs GraphRAG

Korpus: 24,000 dokumentow | Zapytania: 150 | Budzet B=1

Mediana stopnia encji zapytania: **12**, stad przewidywany prog przejscia: **n > 155** (warunek samouzgodniony: n/(6*(deg0+n)) > 2.0/sqrt(deg0+n), czyli n > 72 + sqrt(5184 + 144*deg0); kazdy most ma stopien 3, a wynik ladunku przez jedna kotwice nie przekracza 1/6. Naiwne n > 12*sqrt(deg) pomija to, ze wstrzykniete krawedzie same podnosza stopien encji kotwiczacej).

|   bridge_count | poison@1   | poison@5   | poison@1 per stratum              |   median deg (attack won) |   median deg (attack lost) | time   |
|----------------|------------|------------|-----------------------------------|---------------------------|----------------------------|--------|
|             10 | 17.3%      | 80.0%      | attack=0%  descr=52%  exact=0%    |                       112 |                          7 | 37.6s  |
|             20 | 18.0%      | 80.7%      | attack=0%  descr=54%  exact=0%    |                        80 |                          7 | 39.5s  |
|             40 | 18.0%      | 82.0%      | attack=0%  descr=54%  exact=0%    |                        80 |                          7 | 39.3s  |
|             80 | 18.0%      | 86.7%      | attack=0%  descr=54%  exact=0%    |                        80 |                          7 | 42.4s  |
|            100 | 18.0%      | 88.7%      | attack=0%  descr=54%  exact=0%    |                        80 |                          7 | 43.1s  |
|            120 | 18.0%      | 89.3%      | attack=0%  descr=54%  exact=0%    |                        80 |                          7 | 42.1s  |
|            140 | 18.0%      | 89.3%      | attack=0%  descr=54%  exact=0%    |                        80 |                          7 | 45.4s  |
|            146 | 18.0%      | 89.3%      | attack=0%  descr=54%  exact=0%    |                        80 |                          7 | 44.2s  |
|            147 | 51.3%      | 89.3%      | attack=0%  descr=54%  exact=100%  |                         3 |                         21 | 43.7s  |
|            150 | 52.0%      | 89.3%      | attack=2%  descr=54%  exact=100%  |                         3 |                         22 | 43.5s  |
|            160 | 63.3%      | 90.0%      | attack=36%  descr=54%  exact=100% |                         3 |                         34 | 45.1s  |
|            320 | 76.0%      | 90.0%      | attack=74%  descr=54%  exact=100% |                        10 |                         30 | 54.2s  |

Pojedyncza wartosc `bridge_count` nie opisuje odpornosci architektury, tylko polozenie wzgledem tego progu. Kolumna per stratum jest tu istotniejsza niz mediana stopnia: ladunek na pozycji 1 w stratum, w ktorym czysty silnik i tak nie znajdowal odpowiedzi, to inne zdarzenie niz wyparcie realnej odpowiedzi -- mediany stopnia nalezy czytac dopiero po tym rozbiciu.
