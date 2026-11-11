# Instrukcja dla agentów AI pracujących w repozytorium (AGENTS.md)

Repozytorium zawiera benchmark odporności warstwy wyszukiwania RAG na zatruwanie korpusu
(*corpus poisoning*) w domenie CTI. Ten plik opisuje **stan faktyczny** projektu i reguły
metodologiczne, które kod egzekwuje automatycznie.

Stan na 11.11.2026 (przebiegi z 27.09.2026): przebiegiem głównym jest **v3**
(`outputs/reports/v3/`). Przebieg v2 i jego powtórzenie kontrolne służą do porównania
(Sekcja 3.1).

> [!IMPORTANT]
> **Raporty w `outputs/reports/` (v2, v2_rerun, v3) podlegają weryfikacji jak każdy inny
> artefakt.** Jeżeli zauważysz w nich błąd metodologiczny, sprzeczność albo tezę bez pokrycia
> w danych — zgłoś to. Nie ma tu treści wyłączonych spod recenzji. Wcześniejsza wersja tego
> pliku zawierała dyrektywę zakazującą analizy raportu; została usunięta, ponieważ dokładnie
> te punkty, których zakazywała oceniać, okazały się najsłabszymi miejscami badania.

---

## 0. Artykuł jest źródłem prawdy

Opisem badania jest artykuł („Rank Placement Is Not Displacement…"). Kod i raporty mają go
odtwarzać. Jeżeli repozytorium mówi co innego niż artykuł, poprawia się repozytorium; jeżeli
ustalenie dotyczy treści artykułu, zgłasza się je autorowi i nie „naprawia" w kodzie.

* **Żadna zmiana nie może ruszyć liczby z artykułu.** Po zmianie w warstwie raportu porównaj
  raport v3 przed i po: komórki tabel muszą być identyczne.
* **Raport nie rankinguje silników i nie wyznacza frontu Pareto.** Artykuł tego nie robi:
  strata użyteczne różnią się między silnikami, więc ich średnie opisują różne grupy pytań.
* **Nazwy.** Silnik `GraphRAG` (pole `engine_name` w danych) nosi w artykule nazwę
  *Graph-Traversal*. Artykuł podaje 429 testów — to stan z commitu `1824048`. Później
  doszły 4 testy manifestu korpusu (433), a po usunięciu etapu LLM i filtrów obronnych
  zostały 333; testy pomiaru wyszukiwania są te same.
* **Pula kandydatów Hybrid-Reranker** (`candidate_k = 10`, `retrievers.py`): reranker ocenia
  10 kandydatów po fuzji RRF z list top-10 BM25 i dense. Przy rozłącznych listach każdy
  składnik wnosi pozycje 1–5, więc pięć ładunków usuwa odpowiedź z puli przed rerankingiem.
  Wyparcie Hybrid-Reranker przy B = 5 opisuje tę pulę, nie reranker.

---

## 1. Co ten benchmark mierzy (i czego nie)

* **Wyłącznie warstwa wyszukiwania.** Etapu LLM nie ma (`llm_stage_ran = False`); jego kod
  (generator, sędzia, Batch API) usunięto w wydaniu 1.3.2, a pola generacyjne zostały w schemacie
  wyników tylko po to, żeby dało się wczytać zapisane przebiegi.
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

## 2. Reguły metodologiczne

Reguły 2.1–2.4 są zaimplementowane, nie tylko zapisane. Jeśli zmieniasz warstwę
raportowania, musisz je utrzymać. Punkt 2.5 jest ostrzeżeniem interpretacyjnym, które wynika
z porównania przebiegów v2 i v3.

### 2.1 Tezę o skuteczności ataku niosą `GT displaced@5` i `poison@1 cond`

`poison@1` mówi wyłącznie, gdzie w rankingu wylądował ładunek. Ładunek na pozycji 1 przy
odpowiedzi wciąż obecnej na pozycji 2 nie odbiera generatorowi dostępu do prawdy. Każde
zdanie o tym, że atak „działa", musi być oparte na wyparciu odpowiedzi.

### 2.2 Próg użyteczności obowiązuje **per stratum**, nie tylko per silnik

Ładunek na pozycji 1 w stratum, w którym czysty silnik i tak nie znajdował odpowiedzi, nie
wypiera niczego — jego `poison@1` opisuje zdegenerowany ranking, a nie odporność. Dlatego
wszystkie średnie międzyscenariuszowe (Sekcje 3 i 4 raportu) liczone są wyłącznie na
stratach, gdzie dany silnik ma Clean Recall@5 ≥ 50%.

Skala efektu tej reguły (średni `poison@1` po 36 scenariuszach, czyli 9 wektorów z ramieniem
echo × 4 budżety; check K3):

| Silnik | v2: bez ograniczenia | v2: strata użyteczne | v3: bez ograniczenia | v3: strata użyteczne | stratum odrzucone |
|---|---|---|---|---|---|
| Sparse-BM25 | 39,4% | **30,5%** | 25,4% | **6,1%** | ATT&CK Relational |
| Dense-FAISS | 20,8% | **16,0%** | 17,9% | **16,0%** | ATT&CK Relational, CVE Exact-Match |
| Hybrid-Reranker | 19,7% | **11,7%** | 24,4% | **11,7%** | ATT&CK Relational |
| GraphRAG | 34,4% | **15,2%** | 35,7% | **17,1%** | CVE Descriptive |

Implementacja: `viable_strata_for()` i `restricted_poison_rates()` w
`src/visualization/reporter.py`; strażnik: check **K3** w `scripts/audit_checks.py`.

### 2.3 `poison@1` nie jest estymatorem punktowym dla silników remisujących

GraphRAG przypisuje wielu dokumentom identyczny wynik, a `sorted(key=(-score, doc_id))`
rozstrzyga remis kolejnością identyfikatorów. Dla remisu przecinającego granicę
poison/clean o wartości metryki decyduje więc porządek alfabetyczny (`POISON_…` vs `CVE-…`).
Przedział Wilsona **nie** obejmuje tej nieoznaczoności — obejmuje wyłącznie błąd próbkowania.

**Zakresy liczy się na pełnych grupach remisowych.** Porównanie tylko pozycji 1 i 2 (flaga
`top1_is_score_tie`, jedyna zapisana w śladach archiwalnego v2) zaniża zakres: grupa remisowa
na pozycji 1 bywa dłuższa niż 2, a `GT displaced@5`, Hit@5 i Recall@5 zależą od grupy na
granicy pozycji 5. Przebieg z `--log-ties` zapisuje dla każdego zapytania głęboki, niemierzony
czasowo ranking (`stages.deep_retrieve`) i granice każdej z tych metryk przy dowolnym
uporządkowaniu remisów (pola `tie_*` w śladzie, `*_tie_lower/upper` w wyniku,
`tie_bounds_source = "full_group"`).

| GraphRAG, SPARSE_B1 (wszystkie strata) | poison@1 | zakres: pozycje 1–2 | zakres: pełne grupy |
|---|---|---|---|
| v2 (przebieg kontrolny) | 40,0% | 33,3%–76,0% | **33,3%–78,7%** |
| v3 | 41,3% | 33,3%–81,3% | **33,3%–91,3%** |

Remisy przecinające granicę poison/clean dotyczą w GraphRAG do **48,0%** zapytań w scenariuszu
(v2) i **60,7%** (v3; oba maksima dla BLACKBOX_B1). W Dense-FAISS i Hybrid-Reranker remisy
występują wyłącznie między tekstowo identycznymi wariantami ładunku GRAPH, a w Sparse-BM25
także w innych scenariuszach. **Żaden z nich nie zmienia `poison@1`, `poison@5`, wyparcia,
Hit@5 ani Recall@5** z jednym wyjątkiem: złoty rekord zapytania CVE Descriptive
`DESC-CVE-2024-23874` remisuje w Sparse-BM25 na granicy pozycji 5, więc jego trafienie i
wyparcie zależą od uporządkowania remisów. Liczby wyparcia Sparse-BM25 mogą więc być o jeden
wyższe (np. 0/100, zakres 0–1).

**MRR też zależy od remisów, a pola `tie_*` go nie obejmują**, bo MRR zależy od kolejności
wewnątrz top-5, a nie tylko od grup na pozycji 1 i na granicy pozycji 5. Zakresy dla przebiegu
v3, policzone z pełnych rankingów przebudowanych indeksów (odtwarzają one zapisane listy
top-5 czystego przebiegu 150/150):

* GraphRAG: 0,48 (0,41–0,54);
* Sparse-BM25: 0,66 (0,66–0,67; dwa zapytania CVE Descriptive);
* Dense-FAISS i Hybrid-Reranker nie mają remisów w przebiegu czystym.

Raport publikuje zakresy jako osobną kolumnę i tabele w Sekcji 6. Strażnik: check **TIE**.

### 2.4 Ramię `query_echo` jest osobnym testem skrajnym

Domyślnym trybem referencyjnym jest `query_echo=False`, w którym wektory zachowują swoją
specyfikę techniczną. Dosłowne doklejenie pytania ofiary (`dense_echo`) to konstrukcja
bazowa PoisonedRAG i jednocześnie górne ograniczenie — **nie wchodzi do żadnej uśrednionej
wartości**, ma własną kolumnę. Różnica jest istotna: dla Hybrid-Reranker
`poison@1` na ramieniu echo wynosi 100,0% przy każdym budżecie, a na ramieniu referencyjnym
średnio 0,7% (strata użyteczne, 32 scenariusze; tak samo w v2 i v3).

### 2.5 Wyniki zależą od brzmienia pytań

Przebiegi v2 i v3 różnią się wyłącznie szablonami pytań i jednym wymienionym pytaniem
(Sekcja 3.3). Ładunki, silniki i protokół są te same. Zmiana brzmienia pytań działa przez
dwa mechanizmy.

1. **Wspólne rzadkie słowa pytania i asercji (silniki leksykalne).**
   * Skutek: `poison@1` Sparse-BM25 na stratach użytecznych dla czterech wektorów niosących
     asercję w tekście (SPARSE, DENSE, HYBRID, GRAPH) spada z **50–55%** (v2, B = 1) do
     **0–10%** (v3).
   * Asercja fałszująca dla CVE Exact-Match brzmi „…carries no CWE classification…", a
     szablon v2 pytał o „weakness (CWE) classification".
   * Tokeny `cwe` (df 8/24 000) i `classification` (df 5/24 000) mają skrajne IDF, a złoty
     rekord nie zawiera żadnego z nich. Każdy ładunek z asercją dostawał więc premię przy
     każdym pytaniu v2 (np. RCM-CVE-2024-22211: 7,5 + 7,9 pkt, ładunek 35,4 wobec 18,7 dla
     złotego rekordu).
2. **Słowa szablonu pasujące do encji grafu o niskim stopniu (GraphRAG).**
   * Słowa „malware" i „tool" szablonów v2 dopasowywały encje `Malware` (stopień 4) i `Tool`
     (stopień 2). Dopasowywały też węzły typu `malware` i `tool` (stopnie 1 448 i 190), które
     łączą wszystkie dokumenty malware i wszystkie dokumenty narzędzi.
   * Techniki T1587.001 i T1588.001 dostawały przez to wynik 1,0 i zajmowały pozycje 1–2
     każdego pytania o malware, a T1588.002 (1,41) pozycję 1 obu pytań o narzędzia.
   * Skutki w v2: wyparcie pod wektorem GRAPH przy B = 3 wynosiło **33,7%** (v3: **14,0%**),
     a atak topologiczny miał sufit w 19 pytaniach (Sekcja 4).
   * Słowo „campaign" dopasowywało encję `Campaign` (stopień 2).

`GT displaced@5` silników leksykalnego i hybrydowego przy B ≤ 3 wynosi w obu przebiegach 0–1
na 100 (do 2 przy dowolnym uporządkowaniu remisów).

Zanim zinterpretujesz `poison@1` albo wyparcie, sprawdź, czy słowa szablonu nie pokrywają
się z tekstem ładunku albo z encjami o niskim stopniu. Check K4 wykrywa skutek drugiego
rodzaju (stałe sloty), a skutku pierwszego rodzaju nie wykrywa żaden check.

---

## 3. Stan faktyczny przebiegów

### 3.1 Przebiegi i ich rola

| Folder | Data | Pytania | Rola |
|---|---|---|---|
| `outputs/reports/v2/` | 8.09.2026 | v2 | archiwum; opisany w manuskryptach v2 i v3; **nie nadpisywać** |
| `outputs/reports/v2_rerun/` | 27.09.2026 | v2 | przebieg kontrolny z `--log-ties`, identyczny z v2; w manuskrypcie v4 analiza wrażliwości na szablony |
| `outputs/reports/v3/` | 27.09.2026 | v3 | **przebieg główny** (manuskrypt v4) ze sweepem, audytem remisów i testami McNemara |

Logi i stan potoku z 27.09.2026 są w `outputs/logs/`.

### 3.2 Korpus: 24 000 dokumentów, silnie niejednorodny

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

### 3.3 Zapytania: 150 w trzech rozłącznych stratach po 50

1. **CVE Exact-Match** — identyfikator odpowiedzi występuje dosłownie w pytaniu. To
   wyszukiwanie po kluczu, nie zadanie semantyczne.
2. **CVE Descriptive** — pytanie jest **dosłownym podciągiem** dokumentu docelowego
   (zweryfikowane: 50/50). To dopasowanie near-duplicate, nie klasyfikacja przyczyny
   źródłowej z CTIBench. `key_terms` to 7 wyrazistych tokenów opisu (we wszystkich 50 pytaniach).
3. **ATT&CK Relational** — wymaga przejścia po grafie: 20 pytań atrybucji (17 malware,
   2 narzędzia, 1 kampania), 16 o sub-techniki i 14 o mitygacje.
   * Zbiór odpowiedzi wyprowadzono z **tych samych krawędzi STIX, po których chodzi
     GraphRAG**, więc przewaga wyszukiwania grafowego jest tu częściowo wbudowana w
     konstrukcję zadania.
   * Pula jest filtrowana do krawędzi o ≤ 3 dokumentach odpowiedzi (`MAX_ANSWER_DOCS`).
   * W 16 pytaniach o sub-techniki identyfikator techniki nadrzędnej (odpowiedź) jest
     prefiksem identyfikatora w pytaniu.

Dwa z trzech strat są więc zadaniami dopasowania łańcuchów znaków. Próg użyteczności ≥ 50%
i zależne od niego porównania rozstrzygają się w dużej mierze na nich.

Szablony pytań (`QUERY_TEMPLATES` w `src/corpus/real_query_loader.py`, flaga `--query-set`):

| Szablon | v2 | v3 |
|---|---|---|
| CVE Exact-Match (50) | What is the root cause weakness (CWE) classification for {cve}? | What is the root cause of {cve}? |
| Malware (17) | Which threat group is known to operate the malware family {name}? | Which threat group is known to operate {name}? |
| Narzędzie (2) | Which threat group is documented using the tool {name} in intrusions? | Which threat group is documented using {name} in intrusions? |
| Kampania (1) | Which threat group is the ATT&CK campaign {name} attributed to? | Which threat group is {name} attributed to? |

Szablony CVE Descriptive, sub-technik i mitygacji są w obu zestawach takie same. Pytania
atrybucji zawierające własną odpowiedź są w v3 wymieniane na kolejne z puli
(`answer_in_question`). Dotyczy to jednego pytania: INC Ransomware → Caminho. Pozostałe
149 pytań ma te same identyfikatory i tę samą kolejność co w v2.

### 3.4 Użyteczność bazowa (Clean Recall@5, przebieg v3)

| Silnik | Ogółem | CVE Exact | CVE Descr. | ATT&CK Rel. |
|---|---|---|---|---|
| Sparse-BM25 | 67,4% (66,8–67,4%) | 100,0% | 100,0% (98,0–100,0%) | 2,3% |
| Hybrid-Reranker | 67,6% | 100,0% | 100,0% | 2,7% |
| GraphRAG | 55,8% (50,7–60,9%) | 100,0% | **0,0%** (0,0–14,0%) | 67,3% (52,0–68,7%) |
| Dense-FAISS | 33,8% | **0,0%** | 96,0% | 5,3% |

W nawiasach podano zakresy remisowe. W v2 wartości są takie same poza stratum relacyjnym
Sparse-BM25 (4,3%), Hybrid-Reranker (4,7%) i Dense-FAISS (7,3%) oraz wartościami ogółem
(68,1%, 68,2%, 34,4%). Różnica wynika tylko z wymiany pytania INC Ransomware: odpowiadały na
nie wszystkie silniki, a na Caminho odpowiada tylko GraphRAG. Strata użyteczne są w obu
przebiegach te same. MRR rośnie w v3: Sparse-BM25 w CVE Exact-Match 0,96 → 1,00,
Hybrid-Reranker 0,79 → 0,95, GraphRAG w ATT&CK Relational 0,26 → 0,44.

`Dense-FAISS` jest poniżej progu użyteczności i oznaczony jako **diagnostyczny**: wyłączony
z międzysilnikowych średnich i z testów istotności. Uwaga interpretacyjna: przypisywanie
wyniku 0,0% na CVE Exact-Match właściwościom bi-enkodera jest **nierozstrzygnięte** —
dokumenty CVE budowane są z jednego szablonu (19 464 z identycznym prefiksem „CVE Program
record"), więc hipoteza „model nie koduje identyfikatorów" jest nieodróżnialna od hipotezy
„jednorodny szablon dominuje w embeddingu". Rozstrzygnięcie wymaga wariantu korpusu bez
wspólnego prefiksu.

### 3.5 Porównanie v2 → v3 (strata użyteczne, ramię referencyjne)

| Wielkość | v2 | v3 |
|---|---|---|
| Sparse-BM25 `poison@1`, B = 1, SPARSE / DENSE / HYBRID / GRAPH | 55 / 50 / 50 / 50% | 10 / 1 / 1 / 0% |
| Sparse-BM25, średni `poison@1` (8 wektorów × B = 1–3) | 25,6% | 1,7% |
| Hybrid-Reranker, średni `poison@1` (8 wektorów × B = 1–3) | 0,6% | 0,6% |
| `GT displaced@5`, B ≤ 3, najwięcej na 100: Sparse-BM25 / Hybrid-Reranker | 1 (1–2) / 1 | 0 (0–1) / 0 |
| Sparse-BM25 `GT displaced@5`, B = 5 (SPARSE; DENSE, HYBRID; GRAPH) | 53; 50; 50/100 | 8; 1; 0/100 |
| Hybrid-Reranker `GT displaced@5`, B = 5 (SPARSE; DENSE; HYBRID; GRAPH) | 5; 44; 50; 50/100 | 5; 1; 1; 0/100 |
| GraphRAG `poison@1`, SPARSE / DENSE / HYBRID, każdy B | 10% (0–68%) | 12% (0–87%) |
| GraphRAG GRAPH `GT displaced@5`, B = 3 | 29/86 = 33,7% (31,4–38,4%) | 12/86 = 14,0% (11,6–20,9%) |
| GraphRAG ENTITY_SWAP / BLACKBOX `GT displaced@5`, B = 3 | 11,6% / 11,6% (9,3–32,6% / 9,3–33,7%) | 9,3% / 9,3% (9,3–15,1% / 9,3–16,3%) |
| McNemar (rodzina 43 testów): istotne po Holmie | 8 | 2 |

W v2 wektor GRAPH przy B = 3 wypierał odpowiedź we wszystkich 17 pytaniach o malware i
narzędzia z trafieniem bazowym (16 o malware i 1 o narzędzie). Szesnaście z nich występuje
w v3 i żadne nie jest wypierane. Siedemnaste (INC Ransomware) zastąpiono pytaniem o Caminho,
które też nie jest wypierane. Wyparcia w pozostałych pytaniach (sub-techniki, mitygacje,
kampania) są przy B = 3 identyczne we wszystkich wektorach referencyjnych.

Przyczyną były stałe sloty z Sekcji 2.5: w pytaniach o malware okno miało 3 wolne miejsca,
więc trzy ładunki wystarczały do wyparcia.

### 3.6 Odtwarzalność

* Przebieg kontrolny (`--query-set v2 --log-ties`) na tym samym komputerze i w tym samym
  `.venv` odtworzył archiwalny v2 **dokładnie**: 148 scenariuszy, 22 200 list top-5, 0 różnic
  w metrykach punktowych i w polach śladów (poza latencjami).
* Granice remisowe zapisane przez ten przebieg dla GraphRAG i Sparse-BM25 zgadzają się rekord
  w rekord (2 × 5 550) z niezależnym audytem `scripts/tie_audit.py` wykonanym wcześniej na
  Linuksie (Python 3.11). Na Linuksie (Python 3.13) odtworzono też czyste rankingi Dense-FAISS
  i Hybrid-Reranker v2 (150/150).
* Zrekonstruowany `outputs/reports/v2/run_manifest.json` podaje `numpy 2.5.3`, ale `.venv`
  zawiera `numpy 2.5.2`, zainstalowane 8.09.2026 o 15:17 UTC, czyli przed przebiegiem v2
  (wyniki zapisane o 17:43 UTC). Manifesty v2_rerun i v3 podają 2.5.2. Folderu `v2` nie
  poprawiamy — jest archiwum.

---

## 4. Model zagrożeń — co atakujący faktycznie wie

Scenariusze celowane operują w reżimie wyroczni (*Worst-Case / Oracle*). Atakujący zna:

* treść zapytania ofiary,
* docelową asercję fałszującą,
* **oraz `key_terms`, które dla zapytań relacyjnych zawierają nazwy dokumentów-odpowiedzi**
  (`real_query_loader.py` buduje je jako `[encja] + gold`), a dla CVE Exact-Match — złotą
  etykietę CWE (`[cve_id, gt_cwe]`).

Ostatni punkt jest silniejszy niż zwykły dostęp do zapytania i trzeba go wymieniać jawnie.
`SparseKeywordStuffingAttacker` powtarza `key_terms` 8–16 razy (8 + 2b dla wariantu
b = 0…4), czyli wstrzykuje do korpusu nazwy prawidłowych odpowiedzi.

`EntitySwapPoisonAttacker` usuwa z kotwic identyfikatory dokumentów-odpowiedzi (`_anchors`),
ale skutek zależy od stratum:

* **ATT&CK Relational:** kotwicą jest encja z pytania, a wabikiem istniejący dokument tego
  samego typu. Oba końce relacji są istniejącymi węzłami. Tu część różnicy względem wektorów
  leksykalnych to **różnica w wycieku odpowiedzi, a nie w konstrukcji ataku**.
* **CVE Exact-Match:** identyfikator CVE jest identyfikatorem złotego dokumentu, więc jedyną
  kotwicą zostaje **złota etykieta CWE — czyli sama odpowiedź**. Ładunek w ogóle nie wymienia
  pytanego CVE.
* **CVE Descriptive:** kotwicami są 4 tokeny opisu. W większości nie są encjami korpusu,
  więc ładunek dodaje nowe węzły encji (w każdym z 50 pytań co najmniej jeden).

`blackbox_category` jest najsłabszym testowanym adwersarzem (zna tylko kategorię pytań).
Nie używaj sformułowań „górna/dolna granica" jako opisu porządku zmierzonych wartości —
opisują one siłę modelu zagrożeń, a wektory white-box o innej konstrukcji (`entity_swap`,
`pure_topological`) wypadają miejscami niżej niż `blackbox_category`.

### `bridge_count` to wolny parametr ataku, nie własność architektury

`GraphLogicPoisonAttacker` i `PureTopologicalPoisonAttacker` mają jeden wolny parametr —
`bridge_count` (domyślnie **40**, flaga `--bridge-count`) — i to on decyduje o wyniku
(PURE_TOPOLOGICAL, B = 1, `poison@1` na wszystkich 150 pytaniach):

| bridge_count | 10 | 20 | 40 | 80 | 146 | 147 | 150 | 160 | 320 |
|---|---|---|---|---|---|---|---|---|---|
| v2 | 17,3% | 18,0% | 18,0% | 18,0% | 18,0% | **51,3%** | 51,3% | 54,0% | 63,3% |
| v3 | 17,3% | 18,0% | 18,0% | 18,0% | 18,0% | **51,3%** | 52,0% | 63,3% | 76,0% |

**Próg przejścia** to `n > 72 + sqrt(5184 + 144·deg0)`.

* Każdy most ma w skierowanym multigrafie stopień 3 (term → most, most → ładunek i krawędź
  zwrotna), więc ładunek zbiera `n/(6(deg0+n))`, czyli najwyżej 1/6 na jedną kotwicę.
* Dla kotwic CVE Exact-Match (deg0 = 3) próg wynosi 146,9. Wszystkie 50 pytań przełącza się
  dokładnie między 146 a 147 mostami w obu przebiegach.
* Wersje sprzed v3 podawały błędne `n > 32 + sqrt(1024 + 64·deg0)` (most o stopniu 2), co
  zaniżało próg mniej więcej dwukrotnie.

**Sufit ataku.** Pozycja 1 jest nieosiągalna przy dowolnej liczbie mostów, gdy inny dokument
zbiera przez dopasowaną encję więcej niż 1/6.

* W v2 dotyczyło to 19 pytań o malware i narzędzia: dokumenty technik dopasowanych przez
  słowa „malware" i „tool" miały wynik 1,0 i 1,41.
* W v3 stratum relacyjne osiąga 74% przy 320 mostach (v2: 36%). Różnica to dokładnie te
  19 pytań.
* Pozostałe 13 pytań relacyjnych opiera się także przy 320 mostach. Każde dopasowuje drugą
  encję, niebędącą key termem: w 12 pytaniach o mitygacje jest to identyfikator techniki
  nadrzędnej zawarty w identyfikatorze sub-techniki, a w pytaniu o kampanię Operation Ghost —
  encja `Ghost`. Mosty podnoszą więc tylko jedną kotwicę.
* Dla 11 z tych 13 pytań równanie daje próg poniżej 320 mostów, więc o oporze decyduje druga
  encja, a nie stopień kotwicy.

**Nigdy nie raportuj pojedynczej wartości `bridge_count` jako charakterystyki odporności
GraphRAG** — cytuj sweep (`scripts/run_bridge_sweep.py`,
`outputs/reports/v3/bridge_sweep_report.md`; wersja z remisami: `bridge_sweep_tieaware.json`
z `scripts/tie_audit.py --sweep-only`).

**Warianty budżetowe ładunków:**

* GRAPH: identyczny tytuł i tekst we wszystkich 150 pytaniach; warianty różnią się tylko
  identyfikatorem i nazwami mostów. Dla silników tekstowych kolejne warianty GRAPH są więc
  duplikatami tego samego dokumentu.
* PURE_TOPOLOGICAL: identyczny tekst; warianty różnią się przyrostkiem tytułu i mostami.
* ENTITY_SWAP: powtarza wabik w 5 na 150 pytań przy B = 5 (w obu zestawach pytań).

---

## 5. Bramka metodologiczna (`scripts/audit_checks.py`)

Checki K1–K9 + TIE przekładają ustalenia audytu na asercje weryfikowalne maszynowo.
Bramka uruchamia się automatycznie na końcu `run_comparison_benchmark.py` i jest
importowalna jako `run_audit(in_dir)`. Nie zapisuje żadnych plików.

```bash
python scripts/audit_checks.py --in-dir outputs/reports/v3
```

**Check K4 — stałe sloty kontekstu.** Od v3 liczony w grupach pytań jednego szablonu (nie
w całym stratum) i rozstrzygany według tego, czy stały dokument stoi **nad** złotym:

* dokument obecny w > 90% pytań grupy, ale zawsze pod złotym dokumentem → **INFO**. Przy
  wyszukiwaniu po kluczu z jednym złotym dokumentem pozostałe sloty zawsze zajmują dokumenty
  najlepiej pasujące do wspólnych słów pytania, więc są stałe przy każdym szablonie;
* stały dokument nad złotym w stratum użytecznym → **FAIL**: odbiera odpowiedzi miejsce w
  oknie, a atakujący potrzebuje o jeden ładunek mniej.

Stara wersja K4 brała tylko najczęstszy dokument na parę silnik–stratum i próg 90% całego
stratum, więc nie widziała artefaktu ograniczonego do jednego szablonu (GraphRAG, 17 z 50
pytań relacyjnych).

| Przebieg | Wynik bramki | Uwagi |
|---|---|---|
| v2 (stara K4) | 9 PASS, 1 FAIL | K4 FAIL |
| v2_rerun (nowa K4) | 8 PASS, 2 FAIL | K4 FAIL: Sparse-BM25 i Hybrid-Reranker w CVE Exact-Match (stały dokument nad złotym w 3 i 20 pytaniach), GraphRAG w pytaniach o malware (17/17). K2 FAIL tylko dlatego, że w tym folderze nie ma sweepu |
| v3 (nowa K4) | 9 PASS, 0 FAIL, 1 INFO | K4 INFO: Sparse-BM25 ma w CVE Exact-Match cztery stałe dokumenty, ale żaden nie stoi nad złotym (0/50). Pozostałe zgłoszenia INFO dotyczą stratum relacyjnego, które nie jest użyteczne dla Sparse-BM25, Dense-FAISS i Hybrid-Reranker |

---

## 6. Praktyka pracy w repozytorium

**Raporty i testy**

* **Zmiany w warstwie raportowania weryfikuj bez ponownego uruchamiania benchmarku:**
  ```bash
  python scripts/regenerate_report.py --in-dir outputs/reports/v3 --corpus-size 24000
  ```
  Raport odtwarza się z zapisanych śladów w `comparison_benchmark_results.json`.
* **`regenerate_report.py`, `mcnemar_restricted.py` i `tie_audit.py` (bez `--out-dir`) zapisują
  wynik do `--in-dir`.** `--in-dir` jest wymagane (także w `audit_checks.py`), a zapis do
  `outputs/reports/v2/` kończy się odmową (`refuse_archive_dir()` w `src/config.py`). Żeby
  przeliczyć archiwum, podaj `--out-dir` albo skopiuj je do osobnego folderu.
* **Strata, próg użyteczności i wykrywanie stałych slotów mają jedną definicję:**
  `src/evaluation/strata.py`. Korzystają z niej raporter, `audit_checks.py`,
  `mcnemar_restricted.py` i `tie_audit.py`. Nie kopiuj tych reguł do skryptów.
* **Po zmianach uruchom testy:** `pytest tests/ -q -p no:cacheprovider` (333 testy,
  ok. pół minuty). Flaga `-p no:cacheprovider` nie tworzy `.pytest_cache`. Bez zbudowanego
  korpusu `test_data_integrity.py` nie przejdzie; CI go pomija. Opis plików testów:
  `tests/README.md`.

**Przebiegi**

* **Pełny przebieg:** `scripts\run_v3_pipeline.bat` (dwuklik; Windows) albo
  `python scripts/run_v3_pipeline.py [--from KROK | --only KROK ...]`.
  * Kolejno: testy, przebieg kontrolny v2, porównanie z v2 (`scripts/compare_runs.py`),
    przebieg v3, sweep, sweep z remisami, raport, bramka, McNemar.
  * Logi i stan są w `outputs/logs/`; całość trwa ok. 3,5 h.
  * Potok odmawia zapisu do `outputs/reports/v2/`.
* **Folder `outputs/reports/v2/` jest archiwum** przebiegu opisanego w manuskryptach v2 i v3.
  Nie nadpisuj go; nowe przebiegi zapisuj do osobnych folderów (`--out-dir`).
* **`--query-set v2|v3`** wybiera szablony pytań. Domyślnie jest `v2`, żeby stare polecenia
  dawały stare wyniki. Przebieg główny to `v3`.
* **`--log-ties`** zapisuje pełne grupy remisowe i pulę kandydatów Hybrid-Reranker
  (`candidate_pool`: pozycje BM25 i dense, wynik RRF). Metryki punktowe i latencje nie zależą
  od tej flagi (sprawdzone: 0 różnic na 22 200 listach).
* **Każdy przebieg zapisuje `run_manifest.json`** (odcisk korpusu i pytań, wersje pakietów,
  `bridge_count`, seed, platforma). Deklaracja „exact reproducibility" jest ważna **lokalnie
  wobec zapisanego korpusu**: zależności są przypięte tylko od dołu (`>=`), korpus MITRE
  pochodzi z ruchomej gałęzi, a próbka cvelistV5 z „latest release". Replikacja bit-w-bit
  przez osobę trzecią nie jest deklarowana.

**Porządek w repozytorium**

* `__pycache__/`, `.pytest_cache/`, `.venv/`, `data/raw/`, `data/processed/` i `data/cache/`
  są w `.gitignore`. Z `outputs/` śledzone są tylko logi i foldery v2, v2_rerun i v3, a w nich
  duże pliki wyłącznie jako `*.json.xz`.
* Materiał nieużywany usuwaj i odnotuj w `CHANGELOG.md`, z którego commitu da się go odzyskać.
  Folder `archive/` usunięto w wydaniu 1.3.2; jego ostatni stan jest w commicie `bee8fe6`.
* Dokumentacja: `README.md`, `data/README.md` i `tests/README.md` są po angielsku (dla
  czytelników artykułu), `AGENTS.md` i `CHANGELOG.md` po polsku. Liczby powtarzane w kilku
  plikach (np. liczbę testów) zmieniaj we wszystkich naraz.

**Raport**

* **Nie usuwaj przypisów o naturze strat i o wycieku odpowiedzi** przy przepisywaniu
  raportu. To one odróżniają wynik od artefaktu konstrukcji zadania.
* **Nie dopisuj do raportu tez, których nie da się odczytać z tabel.** Sekcja 5 jest
  generowana z danych (`reporter.py`), a nie pisana ręcznie — jeśli zdanie ma się pojawić,
  musi wynikać z policzonej wielkości.
