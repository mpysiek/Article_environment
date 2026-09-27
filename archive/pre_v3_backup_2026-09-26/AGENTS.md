# Instrukcja dla agentów AI pracujących w repozytorium (AGENTS.md)

Repozytorium zawiera benchmark odporności warstwy wyszukiwania RAG na zatruwanie korpusu
(*corpus poisoning*) w domenie CTI. Ten plik opisuje **stan faktyczny** projektu i reguły
metodologiczne, które kod egzekwuje automatycznie.

> [!IMPORTANT]
> **Raport w `outputs/reports/v2/` podlega weryfikacji jak każdy inny artefakt.** Jeżeli
> zauważysz w nim błąd metodologiczny, sprzeczność albo tezę bez pokrycia w danych —
> zgłoś to. Nie ma tu treści wyłączonych spod recenzji. Wcześniejsza wersja tego pliku
> zawierała dyrektywę zakazującą analizy raportu; została usunięta, ponieważ dokładnie te
> punkty, których zakazywała oceniać, okazały się najsłabszymi miejscami badania.

---

## 1. Co ten benchmark mierzy (i czego nie)

* **Wyłącznie warstwa wyszukiwania.** Etap LLM nie jest uruchamiany (`llm_stage_ran = False`).
  To świadoma granica zakresu — badanie ma być deterministyczne i bezkosztowe. Nie raportuj
  braku generacji jako defektu implementacji, ale **nie nazywaj też metryk „ASR"**: w
  literaturze (PoisonedRAG, Zou i in.) ASR jest wielkością generacyjną. Tu obowiązują nazwy
  `poison@1` / `poison@5`.
* **Brak obrony jest założeniem.** Żaden filtr wejściowy, deduplikacja ani higiena indeksu
  nie są włączone. Wszystkie liczby opisują system niezabezpieczony i są górnym
  ograniczeniem. Nie są porównywalne z pracami raportującymi pipeline'y z obroną.
* **Protokół izolowany per zapytanie** (`--isolated-targets`): indeks dla zapytania $Q_i$
  zawiera czysty korpus plus wyłącznie ładunki wygenerowane dla $Q_i$. Zerowe
  zanieczyszczenie obce (`retrieval_asr_untargeted = 0.0`) jest **inwariantem
  konstrukcyjnym**, więc należy do asercji poprawności, a nie do wniosków empirycznych.

---

## 2. Reguły metodologiczne egzekwowane przez kod

Te cztery reguły są zaimplementowane, nie tylko zapisane. Jeśli zmieniasz warstwę
raportowania, musisz je utrzymać.

### 2.1 Tezę o skuteczności ataku niosą `GT displaced@5` i `poison@1 cond`

`poison@1` mówi wyłącznie, gdzie w rankingu wylądował ładunek. Ładunek na pozycji 1 przy
odpowiedzi wciąż obecnej na pozycji 2 nie odbiera generatorowi dostępu do prawdy. Każde
zdanie o tym, że atak „działa", musi być oparte na wyparciu odpowiedzi.

### 2.2 Próg użyteczności obowiązuje **per stratum**, nie tylko per silnik

Ładunek na pozycji 1 w stratum, w którym czysty silnik i tak nie znajdował odpowiedzi, nie
wypiera niczego — jego `poison@1` opisuje zdegenerowany ranking, a nie odporność. Dlatego
wszystkie średnie międzyscenariuszowe (Sekcje 3 i 4 raportu) liczone są wyłącznie na
stratach, gdzie dany silnik ma Clean Recall@5 ≥ 50%.

Skala efektu tej reguły na przebiegu v2 (średni `poison@1` po 36 scenariuszach):

| Silnik | bez ograniczenia | na stratach użytecznych | stratum odrzucone |
|---|---|---|---|
| Sparse-BM25 | 39,4% | **30,5%** | ATT&CK Relational |
| Dense-FAISS | 20,8% | **16,0%** | ATT&CK Relational, CVE Exact-Match |
| Hybrid-Reranker | 19,7% | **11,7%** | ATT&CK Relational |
| GraphRAG | 34,4% | **15,2%** | CVE Descriptive |

Implementacja: `viable_strata_for()` i `restricted_poison_rates()` w
`src/visualization/reporter.py`; strażnik: check **K3** w `scripts/audit_checks.py`.

### 2.3 `poison@1` nie jest estymatorem punktowym dla silników remisujących

GraphRAG przypisuje wielu dokumentom identyczny wynik, a `sorted(key=(-score, doc_id))`
rozstrzyga remis kolejnością identyfikatorów. Dla remisu przecinającego granicę
poison/clean o wartości metryki decyduje więc porządek alfabetyczny (`POISON_…` vs `CVE-…`).
W przebiegu v2 dotyczy to do **42,7%** zapytań w scenariuszu, co daje przedział
**33,3%–76,0%** wokół raportowanych 40,0%. Przedział Wilsona **nie** obejmuje tej
nieoznaczoności — obejmuje wyłącznie błąd próbkowania.

Metryki `poison_at_1_tie_lower` / `poison_at_1_tie_upper` liczy `Evaluator`; raport
publikuje je jako osobną kolumnę i tabelę w Sekcji 6. Strażnik: check **TIE**.

### 2.4 Ramię `query_echo` jest osobnym testem skrajnym

Domyślnym trybem referencyjnym jest `query_echo=False`, w którym wektory zachowują swoją
specyfikę techniczną. Dosłowne doklejenie pytania ofiary (`dense_echo`) to konstrukcja
bazowa PoisonedRAG i jednocześnie górne ograniczenie — **nie wchodzi do uśrednionej
odporności w rankingu**, ma własną kolumnę. Różnica jest istotna: dla Hybrid-Reranker
`poison@1` na ramieniu echo wynosi 100,0% przy 0,7% na ramieniu referencyjnym.

---

## 3. Stan faktyczny przebiegu v2 (`outputs/reports/v2/`)

### Korpus: 24 000 dokumentów, silnie niejednorodny

| doc_type | liczba | udział |
|---|---|---|
| cve | 22 158 | 92,3% |
| malware | 724 | 3,0% |
| mitre_technique | 697 | 2,9% |
| threat_actor | 176 | 0,7% |
| tool / campaign / threat_report / mitigation | 245 | 1,0% |

Konsekwencja: stratum ATT&CK to wyszukiwanie w puli ~1,8 tys. dokumentów utopionych w
szumie CVE, a oba strata CVE celują w podpulę 1 000 rekordów CTIBench RCM. „24 000
dokumentów" nie opisuje efektywnej trudności żadnego z zadań.

### Zapytania: 150 w trzech rozłącznych stratach po 50

1. **CVE Exact-Match** — identyfikator odpowiedzi występuje dosłownie w pytaniu. To
   wyszukiwanie po kluczu, nie zadanie semantyczne.
2. **CVE Descriptive** — pytanie jest **dosłownym podciągiem** dokumentu docelowego
   (zweryfikowane: 50/50). To dopasowanie near-duplicate, nie klasyfikacja przyczyny
   źródłowej z CTIBench.
3. **ATT&CK Relational** — wymaga przejścia po grafie. Zbiór odpowiedzi wyprowadzono z
   **tych samych krawędzi STIX, po których chodzi GraphRAG**, więc przewaga wyszukiwania
   grafowego jest tu częściowo wbudowana w konstrukcję zadania. Pula jest dodatkowo
   filtrowana do krawędzi o ≤ 3 dokumentach odpowiedzi (`MAX_ANSWER_DOCS`).

Dwa z trzech strat są więc zadaniami dopasowania łańcuchów znaków. Próg użyteczności ≥ 50%
i front Pareto rozstrzygają się w dużej mierze na nich.

### Użyteczność bazowa (Clean Recall@5)

| Silnik | Ogółem | CVE Exact | CVE Descr. | ATT&CK Rel. |
|---|---|---|---|---|
| Sparse-BM25 | 68,1% | 100,0% | 100,0% | 4,3% |
| Hybrid-Reranker | 68,2% | 100,0% | 100,0% | 4,7% |
| GraphRAG | 55,8% | 100,0% | **0,0%** | 67,3% |
| Dense-FAISS | 34,4% | **0,0%** | 96,0% | 7,3% |

`Dense-FAISS` jest poniżej progu użyteczności i oznaczony jako **diagnostyczny**: wyłączony
z międzysilnikowych średnich i z testów istotności. Uwaga interpretacyjna: przypisywanie
wyniku 0,0% na CVE Exact-Match właściwościom bi-enkodera jest **nierozstrzygnięte** —
dokumenty CVE budowane są z jednego szablonu (19 464 z identycznym prefiksem „CVE Program
record"), więc hipoteza „model nie koduje identyfikatorów" jest nieodróżnialna od hipotezy
„jednorodny szablon dominuje w embeddingu". Rozstrzygnięcie wymaga wariantu korpusu bez
wspólnego prefiksu.

---

## 4. Model zagrożeń — co atakujący faktycznie wie

Scenariusze celowane operują w reżimie wyroczni (*Worst-Case / Oracle*). Atakujący zna:

* treść zapytania ofiary,
* docelową asercję fałszującą,
* **oraz `key_terms`, które dla zapytań relacyjnych zawierają nazwy dokumentów-odpowiedzi**
  (`real_query_loader.py` buduje je jako `[encja] + gold`).

Ostatni punkt jest silniejszy niż zwykły dostęp do zapytania i trzeba go wymieniać jawnie:
`SparseKeywordStuffingAttacker` powtarza `key_terms` 8–18 razy, czyli wstrzykuje do korpusu
nazwy prawidłowych odpowiedzi. `EntitySwapPoisonAttacker` celowo je odfiltrowuje
(`_anchors`), więc **część różnicy między tymi wektorami to różnica w wycieku odpowiedzi, a
nie w konstrukcji ataku**.

`blackbox_category` jest najsłabszym testowanym adwersarzem (zna tylko kategorię pytań).
Nie używaj sformułowań „górna/dolna granica" jako opisu porządku zmierzonych wartości —
opisują one siłę modelu zagrożeń, a wektory white-box o innej konstrukcji (`entity_swap`,
`pure_topological`) wypadają miejscami niżej niż `blackbox_category`.

### `bridge_count` to wolny parametr ataku, nie własność architektury

`GraphLogicPoisonAttacker` i `PureTopologicalPoisonAttacker` mają jeden wolny parametr —
`bridge_count` (domyślnie **40**, flaga `--bridge-count`) — i to on decyduje o wyniku:

| bridge_count | 10 | 20 | 40 | 80 | 160 | 320 |
|---|---|---|---|---|---|---|
| poison@1 | 17,3% | 18,0% | 18,0% | 18,0% | **54,0%** | **63,3%** |

Próg przejścia to `n > 32 + sqrt(1024 + 64·deg0)` (≈ 75 dla mediany stopnia 12). **Nigdy nie
raportuj pojedynczej wartości `bridge_count` jako charakterystyki odporności GraphRAG** —
cytuj sweep (`scripts/run_bridge_sweep.py`, `outputs/reports/v2/bridge_sweep_report.md`).

---

## 5. Bramka metodologiczna (`scripts/audit_checks.py`)

Checki K1–K9 + TIE przekładają ustalenia audytu na asercje weryfikowalne maszynowo.
Bramka uruchamia się automatycznie na końcu `run_comparison_benchmark.py` i jest
importowalna jako `run_audit(in_dir)`.

```bash
python scripts/audit_checks.py --in-dir outputs/reports/v2
```

**Stan na przebiegu v2: 9 PASS, 1 FAIL.**

Otwarte ustalenie **K4** — stałe sloty kontekstu. W stratum CVE Exact-Match jeden dokument
zajmuje slot top-5 dla 100% zapytań u trzech silników (Sparse `CVE-2025-3385`, Dense
`CVE-2023-48243`, Hybrid `CVE-2026-2636`). Przyczyna jest zdiagnozowana i **nie leży po
stronie silników**: wszystkie 50 pytań tego stratum ma identyczne brzmienie szablonu, a
rzadkie tokeny tego szablonu mają skrajnie wysokie IDF — `classification` występuje w 5/24000
dokumentów, `cwe` w 8/24000, `weakness` w 70/24000. Nieliczne dokumenty zawierające taki
token dostają stałą premię przy każdym zapytaniu. Skutek pomiarowy jest realny: efektywne
okno w tym stratum wynosi 4, a nie 5, co dotyczy wprost argumentu „arytmetyki okna".
**Naprawa należy do generatora zapytań** (parafraza szablonu albo usunięcie z niego tokenów
rzadkich w korpusie), nie do silników. Wymaga ponownego przebiegu.

---

## 6. Praktyka pracy w repozytorium

* **Zmiany w warstwie raportowania weryfikuj bez ponownego uruchamiania benchmarku:**
  ```bash
  python scripts/regenerate_report.py --in-dir outputs/reports/v2 --corpus-size 24000
  ```
  Raport odtwarza się z zapisanych śladów w `comparison_benchmark_results.json`.
* **Po zmianach uruchom testy** — `pytest tests/ -q` (397 testów, ok. 2 min).
* **Każdy przebieg zapisuje `run_manifest.json`** (odcisk korpusu, wersje pakietów,
  `bridge_count`, seed, platforma). Deklaracja „exact reproducibility" jest ważna **lokalnie
  wobec zapisanego korpusu**: zależności są przypięte tylko od dołu (`>=`), korpus MITRE
  pochodzi z ruchomej gałęzi, a próbka cvelistV5 z „latest release". Replikacja bit-w-bit
  przez osobę trzecią nie jest deklarowana.
* **Nie usuwaj przypisów o naturze strat i o wycieku odpowiedzi** przy przepisywaniu
  raportu. To one odróżniają wynik od artefaktu konstrukcji zadania.
* **Nie dopisuj do raportu tez, których nie da się odczytać z tabel.** Sekcja 5 jest
  generowana z danych (`reporter.py`), a nie pisana ręcznie — jeśli zdanie ma się pojawić,
  musi wynikać z policzonej wielkości.
