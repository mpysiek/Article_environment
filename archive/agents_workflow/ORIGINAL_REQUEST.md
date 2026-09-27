# Original User Request

## 2026-09-06T19:53:13Z

Implementacja pełnego programu naprawczego (P1 + P2) dla benchmarku podatności na zatruwanie korpusu CTI RAG, usuwająca błędy metodologiczne unieważniające wyniki (Klasa A) oraz wady przyrządu pomiarowego (Klasa B).

Working directory: d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark
Integrity mode: development

## Requirements

### R1. Targeting-Aware Evaluation and Context Contamination Separation (A1, A6)
System ewaluacyjny musi rozróżniać zatrucie celowane w dane zapytanie od obcego zanieczyszczenia puli.
- Identyfikator zapytania docelowego (`poison_target_query`) z definicji dokumentu zatrutego musi być zachowywany w wynikach wyszukiwania (`RetrievalResult`).
- Podstawową raportowaną metryką sukcesu ataku ma być `retrieval_asr_targeted` (odsetek zapytań, gdzie w Top-k pojawił się dokument dedykowany dla tego konkretnego pytania).
- Zanieczyszczenie nietrafione (`retrieval_asr_untargeted` lub ogólna obecność dowolnego zatrucia `retrieval_asr_any`) musi być mierzone i raportowane jako odrębna miara zanieczyszczenia tła.
- Ewaluacja zapytań nie może powodować nierealistycznej saturacji okna kontekstowego obcymi ładunkami (izolacja indeksu per zapytanie testowe lub formalne modelowanie i kontrola gęstości zanieczyszczenia).

### R2. Naprawa Ekstrakcji Encji i Separacja Przestrzeni Nazw GraphRAG (A4, B4, B3)
Architektura GraphRAG musi poprawnie identyfikować encje startowe zapytań i traversować podgraf powiązań CTI/STIX bez sztucznego tłumienia jej skuteczności.
- Identyfikatory węzłów encji oraz węzłów dokumentów w grafie relacji muszą funkcjonować w odrębnych przestrzeniach nazw (np. poprzez dedykowany prefiks typu węzła), eliminując kolizje stopni węzłów przy normalizacji.
- Ekstrakcja encji z zapytania nie może odrzucać terminów kluczowych (CVE, nazwy szkodliwego oprogramowania, identyfikatory ATT&CK) tylko dlatego, że w korpusie istnieje dokument o tej samej nazwie.
- Wyszukiwanie grafowe nie może po cichu degradować się do niesprawdzonego przeszukiwania podciągów tekstowych; każde użycie ścieżki rezerwowej (fallback) musi być jawnie rejestrowane w metrykach i logowane.

### R3. Różnicowanie Czynników Eksperymentalnych: Zmienność Budżetu i Separowalność Ataków (A3, A5)
Czynniki eksperymentalne w benchmarku muszą odpowiadać rzeczywistym zmiennym niezależnym.
- Zwiększanie budżetu ataku (1, 3, 5) musi generować zróżnicowane ładunki (odmienne parafrazy tekstu, różne techniki kotwiczenia semantycznego lub wielopunktowe mostki relacyjne), zamiast wstrzykiwania bitowo identycznych duplikatów tekstu.
- Wektory ataku muszą być metodologicznie rozłączne. Należy wprowadzić warianty badawcze z wyłączonym dosłownym echem pytania (`query_echo=False`) jako główną próbę referencyjną sprawdzającą selektywność semantyczną i grafową.

### R4. Odporność i Niezawodność Ewaluacji LLM (A8, A9, B8, B9)
Moduł oceny odpowiedzi przez sędziego LLM musi być spójny statystycznie i logicznie.
- Błędy parsowania JSON oraz brakujące odpowiedzi sędziego nie mogą zniekształcać wyników (brakujące dane muszą być wykluczane z mianownika i raportowane jako wskaźnik pokrycia `coverage_rate`, a nie traktowane jako sukces czystego RAG).
- Dla ataków typu BlackBox oraz Topological sprawdzana asercja sędziego musi odpowiadać faktycznie wstrzykniętej treści (brak rozbieżności między wstrzyknięciem a pytaniem sędziego).
- Przypadek, w którym żaden model nie uległ zatruciu (`ASR = 0.0`), musi być poprawnie odróżniany od braku uruchomienia etapu LLM (flaga `llm_stage_ran`).
- Deduplikacja zapytań do sędziego nie może sztucznie redukować wariancji ani degenerować sparowanych testów statystycznych.

### R5. Metrologiczna Uczciwość Raportowania, Analiza Pareto i Poprawność Statystyczna (A2, A10, B1, B2, B5, B10)
System raportowania musi opierać się wyłącznie na danych wynikowych i rygorze metrologicznym.
- Wyeliminować skalarny ranking oparty na samym ASR; zastąpić go analizą frontu Pareto (Clean Utility / Recall@5 vs ASR) z bezwzględnym progiem minimalnej użyteczności (silniki o recallu poniżej progu nie mogą być uznawane za odporne).
- Wszelkie wnioski naukowe, syntezy i rozmiary korpusu w generatorze raportu (`src/visualization/reporter.py`) muszą być wyliczane dynamicznie z faktycznych danych, bez stałych literałów tekstowych.
- Wprowadzić deterministyczną i udokumentowaną politykę rozstrzygania remisów (stable tie-breaking) oraz ujednolicić progi odcięcia $k$ dla wszystkich metryk.
- Zastąpić pomiar opóźnień funkcją `time.perf_counter()` z odrzuceniem fazy rozgrzewki (warm-up) oraz raportowaniem mediany i rozstępu IQR.
- Stosować dokładny test dwumianowy McNemara dla małych prób rozbieżnych ($b+c < 25$) oraz nienumeryczny zapis bardzo małych wartości $p$ ($p < 10^{-4}$).

## Acceptance Criteria

### Integralność i Testy Jednostkowe
- [ ] Zestaw testów weryfikacyjnych (`pytest tests/`) wykonuje się w 100% sukcesem, obejmując nowe testy sprawdzające poprawność propagacji `poison_target_query`, rozdzielenie przestrzeni nazw GraphRAG oraz dynamiczne generowanie raportu.

### Poprawność Działania Architektury GraphRAG
- [ ] Na czystym korpusie CTI zoptymalizowany silnik GraphRAG osiąga Clean Recall@5 na poziomie co najmniej 70% (weryfikacja usunięcia błędu blokowania encji).
- [ ] Wektor `pure_topological` faktycznie wchodzi w interakcję z grafem zapytań (odnotowany niezerowy wpływ na ścieżki grafowe lub jawnie zweryfikowana odporność dynamiczna).

### Rzetelność Metryczna ASR i Budżetów
- [ ] W plikach wynikowych i raportach metryka `retrieval_asr_targeted` wykazuje wyraźne oddzielenie od `retrieval_asr_any` (eliminacja błędu fałszywych sukcesów z obcego zatrucia).
- [ ] Krzywe budżetowe dla poziomów 1, 3 i 5 wykazują zmienność ładunków i nie składają się z bitowo identycznych wyników punktowych.

### Raportowanie i Statystyka
- [ ] Wygenerowany raport Markdown nie zawiera zahardkodowanych wniosków tekstowych ani stałego stringa o 24 000 dokumentach; wnioski są w 100% syntetyzowane z macierzy wyników.
- [ ] Ranking silników prezentuje analizę Pareto (Recall vs ASR) z wyraźnym oznaczeniem silników niespełniających progu użyteczności.
- [ ] Wszystkie wartości $p$ są rzetelnie sformatowane (brak fałszywych zer `0.0000`), a test McNemara stosuje wariant dokładny dla małych liczności.

## 2026-09-07T10:52:30Z

Dokończenie wdrożenia Rekomendacji 3 z audytu metodologicznego (protokół izolowanej ewaluacji per zapytanie „1 target query per index instance”) w projekcie CTI RAG poisoning benchmark, usuwającej problem saturacji okna kontekstowego przez obce zatrucia oraz przywracającej wrażliwość metryczną na budżety ataku.

Working directory: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark`
Integrity mode: development

## Requirements

### R1. Integracja Protokołu Izolowanego w Benchmarku (Rekomendacja 3)
- Zapewnić pełną integrację flagi `--isolated-targets` (lub trybu izolowanego) w skrypcie benchmarkowym `scripts/run_comparison_benchmark.py`.
- W trybie izolowanym, dla każdego zapytania testowego $Q_i$, indeks wyszukiwawczy zawiera czysty korpus oraz WYŁĄCZNIE ładunki zatrute wygenerowane dla tego konkretnego zapytania ($B \in \{1, 3, 5\}$). Żadne ładunki zaadresowane do innych zapytań nie mogą znajdować się w indeksie podczas ewaluacji $Q_i$.
- Wykorzystać już zaimplementowane funkcje w `src/attacks/poisoning.py` (`generate_isolated_poison_payloads`, `generate_poison_payloads_for_query`) oraz w `src/evaluation/stages.py` (`execute_isolated_retrieval`).
- Zapewnić, że generator raportów `src/visualization/reporter.py` poprawnie prezentuje i opisuje wyniki trybu izolowanego (dynamika budżetowa, brak sztucznej saturacji tła).

### R2. Testy Jednostkowe i Integracyjne dla Rekomendacji 3
- Utworzyć dedykowany zestaw testów (np. `tests/test_isolated_protocol.py`), który weryfikuje:
  1. Całkowity brak obcych zatruć w wynikach Top-k dla testowanego zapytania $Q_i$ przy włączonym trybie izolowanym.
  2. Wrażliwość metryk `retrieval_asr_targeted` na stopniowanie budżetu ($B=1, 3, 5$).
  3. Poprawne zachowanie wskaźnika czystego recallu (`clean_recall_top5`) przy obecności wyłącznie docelowych ładunków.
  4. Kompatybilność wsteczną z trybem współdzielonym (shared index).

### R3. Integralność i Weryfikacja Całego Pakietu Testów
- Wszystkie testy w projekcie (`pytest tests/`) muszą przechodzić w 100% (dotychczasowe 328 testów + nowe testy dla Rekomendacji 3).
- Pozostawić wszystkie modyfikacje w wyznaczonym katalogu roboczym `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark` (bez synchronizacji z zewnętrznymi katalogami).

## Acceptance Criteria

### Poprawność Działania Rekomendacji 3
- [ ] Opcja `--isolated-targets` działa poprawnie w `scripts/run_comparison_benchmark.py` (zarówno w trybie syntetycznym, jak i realnym korpusie CTI).
- [ ] Przy ewaluacji zapytania $Q_i$ żaden dokument zatruty zaadresowany do $Q_j$ ($j \ne i$) nie pojawia się w indeksie ani w wynikach wyszukiwania.
- [ ] Zwiększanie budżetu $B \in \{1, 3, 5\}$ wykazuje zróżnicowany wpływ na wskaźniki przejęcia bez 100% saturacji kontekstu obcym zanieczyszczeniem.

### Pokrycie Testowe i Jakość Kodu
- [ ] Zestaw `pytest tests/` wykonuje się w 100% sukcesem bez błędów i regresji.
- [ ] Nowe testy protokołu izolowanego weryfikują asercje metryczne oraz brak obcego zatrucia.

