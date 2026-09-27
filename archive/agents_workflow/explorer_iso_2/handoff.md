# Handoff Report: Explorer ISO 2 (Reporting & Visualization for Recommendation 3)

## 1. Observation

1. **Brak obsługi protokołu izolowanego w generatorze raportu:**
   - Plik `src/visualization/reporter.py`:
     W sygnaturze `generate_markdown_report` (linie 188-193):
     ```python
     def generate_markdown_report(
         results: List[EngineBenchmarkResult],
         output_file: Path,
         corpus_type: str = "real",
         corpus_size: int | None = None
     ) -> str:
     ```
     Brak parametru `isolated_targets` lub wykrywania trybu izolowanego z metadanych wyników.
   - W Sekcji 1 raportu Markdown (linie 546-566):
     Brak jakiegokolwiek opisu Protokołu Izolowanego (*„1 target query per index instance”*, Rekomendacja 3).
   - W Sekcji 2.3 (linie 593-598):
     Tabela `budget_curves_table` wypisuje wyłącznie suche wartości ASR@1 bez syntezy analitycznej i bez wyjaśnienia braku saturacji kontekstu obcym szumem w trybie izolowanym.

2. **Zahardkodowane literały w Sekcji 5 raportu (Naruszenie F-R5-01):**
   - W `src/visualization/reporter.py` (linie 525-541):
     ```python
     graph_clean_rec_str = f"{clean_map['GraphRAG'].clean_recall_top5 * 100:.1f}%" if "GraphRAG" in clean_map else "85.3%"
     graph_sparse_asr_str = f"{sparse_b1_map['GraphRAG'].retrieval_asr_top1 * 100:.1f}%" if "GraphRAG" in sparse_b1_map else "1.0%"
     graph_topo_asr1_str = f"{topo_b1_map['GraphRAG'].retrieval_asr_top1 * 100:.1f}%" if "GraphRAG" in topo_b1_map else "67.0%"
     graph_topo_asr5_str = f"{topo_b1_map['GraphRAG'].retrieval_asr_top5 * 100:.1f}%" if "GraphRAG" in topo_b1_map else "93.0%"

     sec5_obs = [
         f"1. **Analiza Użyteczności i Frontu Pareto:** Zgodnie z rygorystycznym kryterium użyteczności bazowej (Clean Recall@5 >= 50%), jedyną architekturą spełniającą próg użyteczności w domenie CTI jest **`GraphRAG`** (Clean Recall@5 = **{graph_clean_rec_str}**). Pozostałe silniki (Sparse: 22.2%, Dense: 3.7%, Hybrid: 22.3%) zostały sklasyfikowane jako `NON_VIABLE` z powodu niewystarczającej zdolności do odnajdywania wiedzy bazowej.",
         f"2. **Retrakcja Tezy o Niskiej Użyteczności GraphRAG (Inwersja Wyników):** Wcześniejsze doniesienia o rzekomo znikomej użyteczności GraphRAG (Recall@5 ~1.0%) zostały definitywnie obalone jako rezultat błędu kolizji przestrzeni nazw encji i dokumentów (`doc:` vs `ent:`) oraz blokowania ekstrakcji encji. Po usunięciu usterki GraphRAG osiąga bezapelacyjnie najwyższy Recall@5 ({graph_clean_rec_str}) oraz MRR (0.62), perfekcyjnie realizując zapytania CVE (100%) oraz ATT&CK (72%).",
         f"3. **Asymetryczny Profil Odporności GraphRAG (Odporność Leksykalna vs Podatność Grafowa):**",
         f"   * **Odporność na Keyword Stuffing:** GraphRAG wykazuje niemal całkowitą odporność na upychanie słów kluczowych BM25 (ASR@1 = **{graph_sparse_asr_str}**), podczas gdy silniki BM25, Dense i Hybrid kapitulują w 100.0%. Czysty szum tekstowy bez poprawnych relacji STIX 2.1 nie jest w stanie zakotwiczyć się w grafie wiedzy.",
     ...
     ```
     Literały `(Sparse: 22.2%, Dense: 3.7%, Hybrid: 22.3%)`, `MRR (0.62), perfekcyjnie realizując zapytania CVE (100%) oraz ATT&CK (72%)`, `kapitulują w 100.0%` są wstrzyknięte na sztywno, łamiąc kryterium akceptacji mówiące o 100% dynamicznej syntezie wniosków z macierzy wyników.

3. **Rozbieżność między implementacją Pareto a tabelą rankingową w Sekcji 3:**
   - W `reporter.py` zdefiniowano `compute_pareto_ranking` (linie 51-93), która prawidłowo kategoryzuje silniki na `VIABLE` i `NON_VIABLE` z progiem użyteczności `utility_threshold=0.50`.
   - Jednak tabela rankingowa w Sekcji 3 (linie 360-376) sortuje silniki oddzielnie za pomocą ad-hoc lambdy (`rankings.sort(key=...)`) i nie wyświetla statusu Pareto (`VIABLE`/`NON_VIABLE`), co narusza Requirement R5 i Acceptance Criteria.

4. **Struktury danych i serializacja:**
   - W `src/evaluation/metrics.py`: Dataclass `EngineBenchmarkResult` (linie 33-63) nie posiada pola `isolated_targets: bool = False`.
   - W `src/evaluation/stages.py`: `make_stage_a_record` (linia 70) posiada już parametr `isolated_target: bool = False` i zapisuje go w rekordzie JSONL (linia 87).
   - W `scripts/run_comparison_benchmark.py`: Brak flagi `--isolated-targets` w `argparse` (linie 244-260).

5. **Środowisko wizualizacji:**
   - W `src/visualization/` brak jakichkolwiek zależności plottingowych (`matplotlib`, `seaborn`, `plotly`). Całość wizualizacji opiera się na `rich` (konsola) i `tabulate` (Markdown GitHub-flavored) oraz zrzutach JSON.

---

## 2. Logic Chain

1. **Z Obserwacji 1 i 4:** Ponieważ `EngineBenchmarkResult` nie rejestruje flagi izolacji, a `generate_markdown_report` nie przyjmuje parametru `isolated_targets`, generator raportu nie ma możliwości odróżnienia protokołu izolowanego od współdzielonego. W konsekwencji raport generowany po ewaluacji izolowanej nie wyjaśnia, dlaczego `retrieval_asr_untargeted = 0.0%`, ani jak interpretować krzywe budżetowe $B \in \{1, 3, 5\}$.
2. **Z Obserwacji 2:** Sztywne ciągi liczbowe w Sekcji 5 powodują, że uruchomienie benchmarku na innych podzbiorach danych (np. syntetycznym, 5 zapytań, inne silniki) generuje sprzeczne lub fałszywe wnioski naukowe (np. wypisuje wyniki dla silników, które w ogóle nie brały udziału w przebiegu). Zastąpienie ich dynamicznym wyliczaniem z `pareto_ranking`, `clean_map` i śladów `traces` w pełni eliminuje tę wadę metrologiczną.
3. **Z Obserwacji 3:** Tabela rankingowa w Sekcji 3 powinna być generowana bezpośrednio z `compute_pareto_ranking`, dzięki czemu silniki o recallu poniżej progu 50% są jednoznacznie i czytelnie oznaczone jako `NON_VIABLE`, spełniając wymogi R5.
4. **Z Obserwacji 1 i 5:** Włączenie dynamicznego opisu Rekomendacji 3 do Sekcji 1, dynamicznej notatki w Sekcji 2, syntezy przyrostów budżetowych $\Delta_{B=1 \to B=5}$ w Sekcji 2.3, nowej dynamicznej obserwacji w Sekcji 5 oraz sekcji walidacyjnej w Sekcji 6 pozwoli w 100% zrealizować wymagania Rekomendacji 3 bez modyfikacji interfejsów psujących istniejące 328 testów.

---

## 3. Caveats

- Nie modyfikowano plików w `src/` ani `tests/` – rola agenta to wyłącznie eksploracja i analiza (read-only).
- Uruchomienie komendy `pytest tests/` w powłoce wymagało interaktywnej zgody użytkownika i przekroczyło limit czasu oczekiwania. Weryfikację przeprowadzono poprzez szczegółową analizę kodu źródłowego, definicji testów w `tests/test_e2e_remediation.py` oraz `tests/test_comparison_system.py`.
- Inne interpretacje: Rozważano możliwość automatycznego wykrywania trybu izolowanego wyłącznie na podstawie wartości `all(r.retrieval_asr_untargeted == 0.0)`. Odrzucono tę opcję jako zawodną (w małej próbie współdzielonej zanieczyszczenie nietrafione mogłoby przypadkowo wynosić 0.0); rekomendowane jest jawne przekazywanie parametru `isolated_targets` i/lub atrybutu na obiekcie `EngineBenchmarkResult`.

---

## 4. Conclusion

Do pełnego spełnienia wymagań Rekomendacji 3 w warstwie raportowania i wizualizacji niezbędne są następujące, precyzyjnie określone modyfikacje:

1. **W `src/visualization/reporter.py`:**
   - Dodać stałą `MIN_UTILITY_THRESHOLD = 0.50` oraz funkcję `is_isolated_run(results, explicit_flag=None)`.
   - Zaktualizować `generate_markdown_report` o parametr `isolated_targets: Optional[bool] = None`.
   - Zastąpić statyczny opis Sekcji 1 dynamicznym akapitem metodologicznym prezentującym protokół izolowany vs współdzielony.
   - Połączyć tabelę rankingową Sekcji 3 z wynikami `compute_pareto_ranking`, eksponując status Pareto (`VIABLE` vs `NON_VIABLE`).
   - Usunąć wszystkie zahardkodowane literały w Sekcji 5 (zastępując je w 100% dynamiczną syntezą).
   - Dodać w Sekcji 5 dynamiczny punkt 5 opisujący eliminację zanieczyszczenia tła i zachowanie krzywych budżetowych $B \in \{1, 3, 5\}$.
   - Dodać w Sekcji 6 dynamiczny punkt 5 dotyczący trafności wewnętrznej protokołu.
2. **W `src/evaluation/metrics.py`:**
   - Dodać pole `isolated_targets: bool = False` do `EngineBenchmarkResult`.
3. **W `scripts/run_comparison_benchmark.py`:**
   - Dodać opcję CLI `--isolated-targets` i przekazać ją do `BenchmarkReporter.generate_markdown_report(..., isolated_targets=args.isolated_targets)`.

---

## 5. Verification Method

1. **Weryfikacja statyczna sygnatur i zmiennych:**
   Sprawdzić czy sygnatura `generate_markdown_report` zawiera `corpus_size` i `isolated_targets`:
   ```python
   import inspect
   from src.visualization.reporter import BenchmarkReporter
   sig = inspect.signature(BenchmarkReporter.generate_markdown_report)
   assert "corpus_size" in sig.parameters
   assert "isolated_targets" in sig.parameters
   ```
2. **Weryfikacja braku hardkodowanych literałów:**
   Wygenerować raport dla sztucznego silnika o małej liczbie zapytań i sprawdzić, że w wyjściu nie występują stałe ciągi `22.2%`, `3.7%`, `22.3%`, `0.62`, `72%`:
   ```python
   r = EngineBenchmarkResult("TestEngine", "sparse", 5, 0.1, 0.1, 0.1, 0.9, 0.9, 0, 0, 0)
   content = BenchmarkReporter.generate_markdown_report([r], tmp_path / "rep.md")
   assert "22.2%" not in content
   assert "3.7%" not in content
   ```
3. **Weryfikacja dynamicznego opisu protokołu izolowanego:**
   Sprawdzić czy przy `isolated_targets=True` wygenerowany raport zawiera frazy:
   `assert "Protokół Ewaluacji: Izolowany Indeks per Zapytanie" in content`
   `assert "retrieval_asr_untargeted = 0.0%" in content`
4. **Weryfikacja pakietu testów:**
   Po implementacji przez agenta Builder uruchomić:
   `pytest tests/`
   Wszystkie testy muszą zakończyć się sukcesem (100% pass).
