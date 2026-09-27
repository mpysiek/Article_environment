# Bridge-Count Sweep: Topological Graph Attack vs GraphRAG

Korpus: 24,000 dokumentow | Zapytania: 150 | Budzet B=1

Mediana stopnia encji zapytania: **12**, stad przewidywany prog przejscia: **n > 75** (warunek samouzgodniony: 0.25*n/(deg0+n) > 2.0/sqrt(deg0+n), czyli n > 32 + sqrt(1024 + 64*deg0). Naiwne n > 8*sqrt(deg) pomija to, ze wstrzykniete krawedzie same podnosza stopien encji kotwiczacej).

|   bridge_count | poison@1   | poison@5   | poison@1 per stratum              |   median deg (attack won) |   median deg (attack lost) | time   |
|----------------|------------|------------|-----------------------------------|---------------------------|----------------------------|--------|
|             10 | 17.3%      | 76.0%      | attack=0%  descr=52%  exact=0%    |                       112 |                          6 | 35.5s  |
|             20 | 18.0%      | 77.3%      | attack=0%  descr=54%  exact=0%    |                        80 |                          6 | 35.8s  |
|             40 | 18.0%      | 79.3%      | attack=0%  descr=54%  exact=0%    |                        80 |                          6 | 36.2s  |
|             80 | 18.0%      | 84.0%      | attack=0%  descr=54%  exact=0%    |                        80 |                          6 | 38.1s  |
|            160 | 54.0%      | 88.7%      | attack=8%  descr=54%  exact=100%  |                         3 |                         23 | 41.3s  |
|            320 | 63.3%      | 90.0%      | attack=36%  descr=54%  exact=100% |                         3 |                         18 | 49.7s  |

Pojedyncza wartosc `bridge_count` nie opisuje odpornosci architektury, tylko polozenie wzgledem tego progu. Kolumna per stratum jest tu istotniejsza niz mediana stopnia: ladunek na pozycji 1 w stratum, w ktorym czysty silnik i tak nie znajdowal odpowiedzi, to inne zdarzenie niz wyparcie realnej odpowiedzi -- mediany stopnia nalezy czytac dopiero po tym rozbiciu.
