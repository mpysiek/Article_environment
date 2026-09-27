# Raport Badawczy: Raportowanie i Wizualizacja Protokołu Izolowanego (Rekomendacja 3)

**Data sporządzenia:** 2026-09-07  
**Autor:** explorer_iso_2  
**Obszar badawczy:** `src/visualization/reporter.py`, `src/visualization/`, struktury serializacji wyników, prezentacja protokołu izolowanego vs współdzielonego, dynamika budżetowa $B \in \{1, 3, 5\}$, eliminacja twardych literałów.

---

## 1. Executive Summary

Niniejsze dochodzenie bada aspekty raportowania, wizualizacji oraz serializacji metryk w kontekście wdrożenia **Rekomendacji 3** z audytu metodologicznego (Protokół Izolowanej Ewaluacji: *„1 target query per index instance”*). Protokół ten eliminuje artefakt nierealistycznej saturacji okna kontekstowego obcym zanieczyszczeniem (`retrieval_asr_untargeted`) i przywraca czułość metryczną benchmarku na stopniowanie budżetu atakującego $B \in \{1, 3, 5\}$.

### Kluczowe ustalenia dochodzenia:
1. **Brak wsparcia dla protokołu izolowanego w generatorze raportów:** Obecny kod `src/visualization/reporter.py` nie posiada wiedzy o trybie `--isolated-targets`. Raport Markdown i widoki terminalowe (`print_terminal_results`) nie informują odbiorcy, czy dany przebieg odbył się w reżimie izolowanym (0% obcego szumu), czy w reżimie współdzielonym (obecność obcego zanieczyszczenia tła).
2. **Ukrycie metryk celowania w głównej tabeli:** Chociaż `EngineBenchmarkResult` posiada pola `retrieval_asr_targeted`, `retrieval_asr_untargeted` i `retrieval_asr_any`, główna tabela wyników Markdown (`md_table` w Sekcji 2) oraz terminalowa prezentują wyłącznie generyczne `retrieval_asr_top1` i `retrieval_asr_top5`. W trybie współdzielonym wprowadza to czytelnika w błąd (sukces z obcego zatrucia traktowany jest jak sukces ataku), natomiast w trybie izolowanym nie akcentuje faktu, że 100% obserwowanego przejęcia stanowi zatrucie celowane.
3. **Uproszczona interpretacja krzywych budżetowych ($B \in \{1, 3, 5\}$):** Tabela Sekcji 2.3 (`budget_curves_table`) prezentuje suche wartości ASR@1 bez dynamicznej analizy zróżnicowania wpływu budżetu oraz bez wyjaśnienia mechanizmu saturacji tła w trybie współdzielonym vs rzeczywistego przyrostu siły ataku w trybie izolowanym.
4. **Pominięcie frontu Pareto w tabeli rankingowej Sekcji 3:** Funkcja `compute_pareto_ranking` (zgodna z F-R5-02 i progiem $Clean\ Recall@5 \ge 50\%$) została zaimplementowana w module, jednak tabela w Sekcji 3 raportu (`ranking_table`) sortuje silniki tradycyjnie (według ASR lub Recall), pomijając status `VIABLE` / `NON_VIABLE` oraz kolumnę statusu Pareto.
5. **Naruszenie wymogu F-R5-01 (zahardkodowane literały w Sekcji 5):** W Sekcji 5 raportu (`Kluczowe Obserwacje i Wnioski Naukowe`) znajdują się stałe ciągi liczbowe (np. `(Sparse: 22.2%, Dense: 3.7%, Hybrid: 22.3%)`, `MRR (0.62), perfekcyjnie realizując zapytania CVE (100%) oraz ATT&CK (72%)`, `podczas gdy silniki BM25, Dense i Hybrid kapitulują w 100.0%`). Narusza to kryterium akceptacji dotyczące 100% dynamicznej syntezy z macierzy wyników.
6. **Brak graficznych bibliotek plottingu:** Moduł `src/visualization/` opiera się wyłącznie na formatowaniu terminalowym `rich` oraz tabelarycznym Markdown `tabulate`. W repozytorium nie ma i nie powinno być zależności od `matplotlib`/`seaborn` (zgodnie z założeniem minimalnych zależności CPU-only).

---

## 2. Architektura `src/visualization/` i Formatowanie Wyników

### 2.1 Struktura katalogu i zależności
Katalog `src/visualization/` zawiera:
- `__init__.py`: pusty plik inicjalizacyjny pakietu.
- `reporter.py` (647 linii): monolityczny moduł odpowiedzialny za:
  - Obliczenia statystyczne (`wilson_interval`, `format_p_value`, `mcnemar_test`, `compute_pareto_ranking`).
  - Drukowanie tabel terminalowych za pomocą `rich.table.Table` i `rich.console.Console` (`BenchmarkReporter.print_terminal_results`).
  - Kompilację pełnego raportu Markdown za pomocą `tabulate(..., tablefmt="github")` (`BenchmarkReporter.generate_markdown_report`).
  - Zrzut śladów generacji i wyszukiwania do formatu JSON (`BenchmarkReporter.save_generation_traces`).

W projekcie nie występują wykresy rastrowe (`.png`) ani wektorowe (`.svg`). Wszystkie „krzywe ataku” (Attack Budget Curves) oraz „macierze podatności” (Cross-Vulnerability Matrix) reprezentowane są jako strukturyzowane tabele Markdown i tabele konsolowe. Jest to w pełni zamierzone i spójne ze specyfikacją lekkości środowiska (CPU-only, `rich`, `tabulate`).

### 2.2 Przepływ danych w `reporter.py`
Wejściem dla generatora raportu jest lista obiektów `EngineBenchmarkResult` (`results: List[EngineBenchmarkResult]`). Każdy obiekt reprezentuje ewaluację pojedynczego silnika RAG (np. `Sparse-BM25`, `Dense-FAISS`, `Hybrid-Reranker`, `GraphRAG`) w określonym scenariuszu (`clean_baseline`, `sparse_b1`, `sparse_b3`, `sparse_b5`, `dense_b1`, itd.).

Obiekt ten zawiera listę szczegółowych śladów `traces: List[GenerationTrace]` dla każdego zapytania testowego $Q_i$.

---

## 3. Analiza Reprezentacji Metadanych i Serializacji Wyników

### 3.1 Stan obecny metadanych w strukturach danych

1. **W `src/evaluation/metrics.py` (`EngineBenchmarkResult`):**
   ```python
   @dataclass
   class EngineBenchmarkResult:
       engine_name: str
       attack_type: str
       total_queries: int
       retrieval_asr_top1: float
       ...
       retrieval_asr_targeted: float = 0.0
       retrieval_asr_untargeted: float = 0.0
       retrieval_asr_any: float = 0.0
       retrieval_asr_targeted_top1: float = 0.0
       retrieval_asr_targeted_top5: float = 0.0
       ...
       traces: List[GenerationTrace] = field(default_factory=list)
   ```
   **Obserwacja:** Klasa `EngineBenchmarkResult` **nie posiada** pola `isolated_targets: bool` ani `evaluation_protocol: str`. O ile metryka `retrieval_asr_untargeted` wynosi `0.0` w trybie izolowanym, o tyle brak jawnego atrybutu uniemożliwia bezwzględne odróżnienie trybu izolowanego od przypadku zbiegu okoliczności w małej próbie.

2. **W `src/evaluation/stages.py`:**
   - W `make_stage_a_record`:
     ```python
     def make_stage_a_record(..., isolated_target: bool = False) -> Dict[str, Any]:
         return { ... "isolated_target": isolated_target, ... }
     ```
     Atrybut `isolated_target` jest już serializowany w pojedynczych rekordach JSONL pliku `stage_a_<run_id>.jsonl`!
   - W nagłówku `write_stage_a`:
     Nagłówek `_header` może i powinien przenosić flagę `isolated_targets: bool`.

3. **W `scripts/run_comparison_benchmark.py`:**
   - Aktualnie skrypt **nie posiada** argumentu `--isolated-targets` w `argparse` ani w sygnaturze `run_benchmark_matrix`.
   - Serializacja do `comparison_benchmark_results.json` odbywa się poprzez:
     ```python
     summary_data = []
     for r in all_results:
         d = dict(r.__dict__)
         d["traces"] = [t.__dict__ for t in r.traces]
         summary_data.append(d)
     ```
     Jeśli dodamy `isolated_targets: bool = False` do `EngineBenchmarkResult`, pole to automatycznie trafi do pliku JSON bez konieczności modyfikowania pętli serializującej!

---

## 4. Opis Protokołu w `reporter.py` (Stan Obecny vs Wymagany)

### 4.1 Sekcja 1: Wstęp i Metodologia Badawcza
- **Stan obecny:** Sekcja 1 wymienia 4 silniki RAG, 5 wektorów ataku, typ korpusu oraz jedno zdanie:
  *„Procedura pomiarowa została zremediowana metrologicznie: wyeliminowano błędy kolizji przestrzeni nazw GraphRAG, zaimplementowano separację celowanego przejęcia (`retrieval_asr_targeted`) od obcego zanieczyszczenia...”*
- **Braki:** Brak jakiejkolwiek wzmianki o **Protokole Izolowanym (Rekomendacja 3)** vs **Protokole Współdzielonym**. Użytkownik czytający raport nie wie, czy w testowanym eksperymencie indeks zawierał ładunki dla 100 zapytań naraz (powodując saturację okna kontekstowego), czy też każde zapytanie testowano w odrębnym, czystym indeksie z dedykowanymi ładunkami.
- **Wymagana zmiana:** Wprowadzenie dynamicznego paragrafu metodologicznego:
  - W trybie izolowanym: precyzyjne wyjaśnienie zasady *„1 target query per index instance”*, wskazanie że w indeksie podczas testu $Q_i$ znajdowało się wyłącznie $B \in \{1, 3, 5\}$ dedykowanych ładunków oraz $0$ ładunków obcych, a wskaźnik obcego szumu wynosił $0.0\%$.
  - W trybie współdzielonym: jawne ostrzeżenie o obecności zanieczyszczenia tła i konieczności interpretacji wyników w kontekście `retrieval_asr_untargeted`.

### 4.2 Sekcja 2 i 2.3: Dynamika Budżetowa $B \in \{1, 3, 5\}$ i Saturacja Kontekstu
- **Stan obecny Sekcji 2.3:**
  ```markdown
  ## 2.3 Krzywe Ataku (Attack Budget Curves)
  Wpływ budżetu atakującego (liczby wstrzykniętych dokumentów per zapytanie) na szansę przejęcia top-1 kontekstu:
  {budget_curves_table}
  ```
  Tabela prezentuje kolumny `Budget=1 (ASR@1)`, `Budget=3 (ASR@1)`, `Budget=5 (ASR@1)`.
- **Braki:**
  1. Brak dynamicznej syntezy analitycznej pod tabelą: czy zwiększenie budżetu z $B=1$ do $B=5$ zwiększa ASR, czy następuje saturacja?
  2. Brak wyjaśnienia zależności od protokołu:
     - W protokole współdzielonym wzrost budżetu $B=5$ oznacza wstrzyknięcie $5 \times |Q|$ dokumentów (np. 500 zatrutych dokumentów do bazy), co sztucznie zapycha okno Top-5 obcymi śmieciami i prowadzi do fałszywych 100% ASR.
     - W protokole izolowanym baza dla $Q_i$ zawiera dokładnie $5$ dokumentów zatrutych, więc obserwowany wzrost ASR jest czystą, rzetelną miarą skuteczności ataku wielodokumentowego (np. zróżnicowanych parafraz, kotwiczenia semantycznego, mostkowania relacyjnego).
- **Wymagana zmiana:**
  - Pod tabelą budżetową należy dodać dynamiczną analizę przyrostów $\Delta_{B=1 \to B=5}$ dla każdego wektora ataku oraz akapit metodologiczny wyjaśniający fizyczne znaczenie krzywej w zależności od flagi `isolated_targets`.

---

## 5. Identyfikacja Zahardkodowanych Treści do Usunięcia (Zgodność z F-R5-01 i Kryteriami Akceptacji)

Kryterium akceptacji projektu jednoznacznie stanowi:
> *„Wygenerowany raport Markdown nie zawiera zahardkodowanych wniosków tekstowych ani stałego stringa o 24 000 dokumentach; wnioski są w 100% syntetyzowane z macierzy wyników.”*

W obecnym kodzie `reporter.py` zidentyfikowano następujące zahardkodowane elementy:

| Nr | Lokalizacja w `reporter.py` | Zahardkodowany fragment | Problem metodologiczny | Dynamiczny zamiennik |
|---|---|---|---|---|
| 1 | Linia 535 | `Pozostałe silniki (Sparse: 22.2%, Dense: 3.7%, Hybrid: 22.3%) zostały sklasyfikowane jako NON_VIABLE` | Sztywne liczby i nazwy silników. Przy uruchomieniu na podzbiorze danych lub innych silnikach raport wypisuje nieprawdę. | Formatowanie listy silników `NON_VIABLE` z ich rzeczywistymi wartościami `avg_recall` z `compute_pareto_ranking`. |
| 2 | Linia 536 | `oraz MRR (0.62), perfekcyjnie realizując zapytania CVE (100%) oraz ATT&CK (72%)` | Sztywne liczby `0.62`, `100%`, `72%`. | Dynamiczny odczyt MRR z `clean_map['GraphRAG'].clean_mrr` oraz obliczenie recallu z podziału `cve_lookup` vs `att&ck` ze śladów `traces`. |
| 3 | Linia 538 | `podczas gdy silniki BM25, Dense i Hybrid kapitulują w 100.0%` | Sztywne `100.0%`. | Dynamiczne wyliczenie średniej lub zakresu ASR dla pozostałych silników pod atakiem `sparse_b1`. |
| 4 | Linie 529-532 | `85.3%`, `1.0%`, `67.0%`, `93.0%` | Sztywne wartości awaryjne (fallbacks) w przypadku braku GraphRAG w wynikach. | Jeśli GraphRAG nie występuje w wynikach, sekcja powinna adaptować się do faktycznie obecnych silników, a nie wstawiać fikcyjne dane. |
| 5 | Linia 631 | `Pure Topological ASR@1 = 67.0%, ASR@5 = 93.0%`, `ASR@1 = 1.0%` | Sztywne literały liczbowe w Sekcji 6 (Threats to Validity). | Dynamiczne podstawienie wartości z `topo_b1_map` i `sparse_b1_map` lub opis jakościowy w oparciu o macierz. |

---

## 6. Propozycja Zmian w Podziale Tabel i Sekcji `reporter.py`

### 6.1 Stała modułowa i detekcja trybu
W `reporter.py` należy zdefiniować:
```python
MIN_UTILITY_THRESHOLD = 0.50

def is_isolated_run(results: List[EngineBenchmarkResult], explicit_flag: Optional[bool] = None) -> bool:
    if explicit_flag is not None:
        return explicit_flag
    return any(getattr(r, "isolated_targets", False) for r in results)
```

### 6.2 Aktualizacja `compute_pareto_ranking`
Rozbudować słownik zwracany przez `compute_pareto_ranking` o metryki LLM, zachowując 100% zgodności wstecznej:
```python
ranking.append({
    "engine": eng,
    "avg_recall": avg_rec,
    "avg_targeted_asr": avg_asr,
    "avg_top1_asr": avg_top1,
    "avg_gen_asr": float(np.mean(stats["gen_asr"])) if stats["gen_asr"] else 0.0,
    "avg_gt_ret": float(np.mean(stats["gt_ret"])) if stats["gt_ret"] else 0.0,
    "is_viable": is_viable,
    "viability": viability
})
```

### 6.3 Aktualizacja tabeli rankingowej w Sekcji 3
Zamiast niepowiązanego sortowania w liniach 355-376, tabela powinna wprost odzwierciedlać ranking Pareto:
```markdown
| Rank | RAG Engine | Status Pareto (Próg Utility >= 50%) | Clean Recall@5 | Targeted ASR@1 | LLM Gen ASR | GT Retention |
|:-----|:-----------|:-----------------------------------|:---------------|:---------------|:------------|:-------------|
| #1   | GraphRAG   | VIABLE                             | 85.3%          | 1.0%           | N/A         | N/A          |
| #2   | Hybrid     | NON_VIABLE (Poniżej progu)          | 22.3%          | 100.0%         | N/A         | N/A          |
...
```

### 6.4 Główna Tabela Wyników (Sekcja 2)
W tabeli zbiorczej:
- Kolumna `ASR_cond (95% CI)` pozostaje nienaruszona (wymóg testów).
- Nagłówki kolumn ASR powinny precyzować, czy mierzą zatrucie celowane:
  `Targeted ASR@1 (95% CI)`, `Targeted ASR@5`.
- W trybie współdzielonym (lub gdy w wynikach pojawia się obcy szum) dodawana jest kolumna `Untargeted ASR@5`.
- W trybie izolowanym pod tabelą umieszczona zostaje notatka:
  *„*Protokół izolowany (Recommendation 3): Indeks dla każdego zapytania testowego zawierał wyłącznie czysty korpus i ładunki wygenerowane dla tego zapytania. Wskaźnik zanieczyszczenia tła (`retrieval_asr_untargeted`) wynosi 0.0%.*”*

### 6.5 Nowa Obserwacja w Sekcji 5 (Wnioski Naukowe)
Dodać punkt 5 syntetyzowany dynamicznie:
- Jeśli `isolated_targets == True`:
  Raportuje potwierdzenie eliminacji obcego szumu (0.0% w poprzek wszystkich zapytań) oraz podsumowuje zaobserwowaną czułość silników na stopniowanie budżetu $B \in \{1, 3, 5\}$.
- Jeśli `isolated_targets == False`:
  Raportuje średnie zanieczyszczenie tła korpusu oraz wskazuje, że w trybie współdzielonym wskaźniki ASR przy budżecie $B=5$ mogą być zawyżone przez saturację kontekstu obcym szumem.

### 6.6 Sekcja 6: Zagrożenia dla Trafności (Threats to Validity)
Dodać dynamiczny punkt 5 wyjaśniający wpływ protokołu ewaluacji na wiarygodność pomiaru.

---

## 7. Dokładna Specyfikacja Modyfikacji w `src/visualization/reporter.py`

Poniżej przedstawiono kompletny projekt kodu wymaganych zmian w `src/visualization/reporter.py`:

```python
# =====================================================================
# 1. Definicje stałych i funkcji pomocniczych
# =====================================================================
MIN_UTILITY_THRESHOLD = 0.50

def is_isolated_run(results: List[EngineBenchmarkResult], explicit_flag: Optional[bool] = None) -> bool:
    """Detects whether benchmark results were executed under isolated targets protocol."""
    if explicit_flag is not None:
        return explicit_flag
    return any(getattr(r, "isolated_targets", False) for r in results)

# =====================================================================
# 2. Sygnatura generate_markdown_report
# =====================================================================
@staticmethod
def generate_markdown_report(
    results: List[EngineBenchmarkResult],
    output_file: Path,
    corpus_type: str = "real",
    corpus_size: int | None = None,
    isolated_targets: Optional[bool] = None
) -> str:
    isolated = is_isolated_run(results, isolated_targets)
    has_llm_metrics = any(getattr(r, "llm_stage_ran", False) or r.generation_asr > 0 or r.ground_truth_retention > 0 for r in results)
    pareto_ranking = compute_pareto_ranking(results, utility_threshold=MIN_UTILITY_THRESHOLD) if results else []

    # =====================================================================
    # 3. Dynamiczny opis protokołu w Sekcji 1
    # =====================================================================
    protocol_desc = (
        "**Protokół Ewaluacji: Izolowany Indeks per Zapytanie (Recommendation 3 / Isolated Target Protocol)**. "
        "Dla każdego zapytania testowego $Q_i$ indeks wyszukiwania zawiera wyłącznie czysty korpus oraz dedykowane "
        "ładunki zatrute wygenerowane dla tego zapytania ($B \\in \\{1, 3, 5\\}$). W indeksie nie znajdują się żadne ładunki "
        "zaadresowane do innych zapytań ($Q_j, j \\ne i$), co całkowicie eliminuje sztuczną saturację okna kontekstowego "
        "obcym szumem (`retrieval_asr_untargeted = 0.0%`) i zapewnia niezakłócony pomiar wrażliwości na budżet ataku."
        if isolated else
        "**Protokół Ewaluacji: Współdzielony Indeks Korpusu (Shared Corpus Index)**. "
        "Wszystkie wygenerowane ładunki zatrute dla wszystkich zapytań umieszczone są w jednej współdzielonej bazie. "
        "W celu rzetelności pomiaru sukces ataku mierzony jest jako celowane przejęcie `retrieval_asr_targeted`, "
        "a zanieczyszczenie obcymi ładunkami raportowane jest odrębnie jako `retrieval_asr_untargeted`."
    )

    # =====================================================================
    # 4. Tabela rankingowa Sekcji 3 oparta o Pareto
    # =====================================================================
    ranking_rows = []
    for rank, item in enumerate(pareto_ranking, 1):
        gen_str = f"{item.get('avg_gen_asr', 0.0):.1%}" if has_llm_metrics else "N/A"
        gt_str = f"{item.get('avg_gt_ret', 0.0):.1%}" if has_llm_metrics else "N/A"
        viability_badge = "VIABLE" if item["is_viable"] else "NON_VIABLE"
        ranking_rows.append([
            f"#{rank}",
            item["engine"],
            viability_badge,
            f"{item['avg_recall']:.1%}",
            f"{item['avg_targeted_asr']:.1%}",
            gen_str,
            gt_str
        ])
    ranking_table = tabulate(
        ranking_rows,
        headers=["Rank", "Engine", "Status Pareto (Recall >= 50%)", "Avg Recall@5 (Higher=Better)", "Avg Targeted ASR@1 (Lower=Better)", "Avg LLM Gen ASR", "Avg GT Retention"],
        tablefmt="github"
    )

    # =====================================================================
    # 5. 100% dynamiczna synteza Sekcji 5 (brak hardkodowanych liczb)
    # =====================================================================
    viable_engines = [p["engine"] for p in pareto_ranking if p.get("is_viable", False)]
    non_viable_engines = [p for p in pareto_ranking if not p.get("is_viable", False)]

    if viable_engines:
        v_str = ", ".join(f"**`{e}`**" for e in viable_engines)
        obs1 = f"1. **Analiza Użyteczności i Frontu Pareto:** Zgodnie z bezwzględnym progiem użyteczności bazowej (Clean Recall@5 >= 50%), architekturami spełniającymi kryterium użyteczności w domenie CTI są: {v_str}."
    else:
        obs1 = "1. **Analiza Użyteczności i Frontu Pareto:** Żaden z testowanych silników nie przekroczył bezwzględnego progu minimalnej użyteczności bazowej (Clean Recall@5 >= 50%)."

    if non_viable_engines:
        nv_str = ", ".join(f"{p['engine']} ({p['avg_recall']:.1%})" for p in non_viable_engines)
        obs1 += f" Pozostałe silniki ({nv_str}) zostały sklasyfikowane jako `NON_VIABLE`."

    clean_map = {r.engine_name: r for r in results if r.attack_type.lower() == "clean_baseline"}
    if "GraphRAG" in clean_map:
        gr_clean = clean_map["GraphRAG"]
        cve_hits = sum(1 for t in gr_clean.traces if getattr(t, 'query_category', '') == 'cve_lookup' and getattr(t, 'clean_ground_truth_hit', False))
        cve_total = sum(1 for t in gr_clean.traces if getattr(t, 'query_category', '') == 'cve_lookup')
        stix_hits = sum(1 for t in gr_clean.traces if getattr(t, 'query_category', '') != 'cve_lookup' and getattr(t, 'clean_ground_truth_hit', False))
        stix_total = sum(1 for t in gr_clean.traces if getattr(t, 'query_category', '') != 'cve_lookup')
        cve_rec_str = f"{cve_hits / max(1, cve_total):.1%}" if cve_total > 0 else "N/A"
        stix_rec_str = f"{stix_hits / max(1, stix_total):.1%}" if stix_total > 0 else "N/A"
        obs2 = (
            f"2. **Użyteczność GraphRAG:** Po eliminacji błędu kolizji przestrzeni nazw (`doc:` vs `ent:`) "
            f"GraphRAG osiąga Clean Recall@5 = **{gr_clean.clean_recall_top5:.1%}** oraz MRR = **{gr_clean.clean_mrr:.2f}**, "
            f"realizując zapytania CVE na poziomie {cve_rec_str} oraz zapytania ATT&CK na poziomie {stix_rec_str}."
        )
    else:
        obs2 = "2. **Retrakcja Tezy o Niskiej Użyteczności GraphRAG:** Potwierdzono usunięcie błędu kolizji przestrzeni nazw dokumentów i encji w grafie wiedzy STIX 2.1."

    sparse_b1_map = {r.engine_name: r for r in results if r.attack_type.lower() == "sparse_b1"}
    topo_b1_map = {r.engine_name: r for r in results if r.attack_type.lower() == "pure_topological_b1"}

    if "GraphRAG" in sparse_b1_map and "GraphRAG" in topo_b1_map:
        gr_sp = sparse_b1_map["GraphRAG"]
        gr_tp = topo_b1_map["GraphRAG"]
        other_sp = [r for r in results if r.engine_name != "GraphRAG" and r.attack_type.lower() == "sparse_b1"]
        other_sp_str = f"średnio {sum(r.retrieval_asr_top1 for r in other_sp)/len(other_sp):.1%}" if other_sp else "wysoki"
        obs3 = (
            f"3. **Asymetryczny Profil Odporności GraphRAG (Odporność Leksykalna vs Podatność Grafowa):**\n"
            f"   * **Odporność na Keyword Stuffing:** GraphRAG wykazuje wysoką odporność na upychanie słów kluczowych BM25 (ASR@1 = **{gr_sp.retrieval_asr_top1:.1%}**), podczas gdy inne silniki ulegają przejęciu ({other_sp_str}).\n"
            f"   * **Podatność na Ataki Topologiczne:** Pod wpływem celowanego ataku strukturalnego (`PureTopologicalPoisonAttacker`), GraphRAG ulega przejęciu w **{gr_tp.retrieval_asr_top1:.1%}** na pozycji Top-1 oraz **{gr_tp.retrieval_asr_top5:.1%}** w Top-5."
        )
    else:
        obs3 = "3. **Asymetryczny Profil Odporności:** Potwierdzono zróżnicowanie podatności na wektory leksykalne i strukturalne."

    attack_results = [r for r in results if r.attack_type.lower() != "clean_baseline"]
    avg_targeted = sum(getattr(r, "retrieval_asr_targeted", 0.0) for r in attack_results) / len(attack_results) if attack_results else 0.0
    avg_untargeted = sum(getattr(r, "retrieval_asr_untargeted", 0.0) for r in attack_results) / len(attack_results) if attack_results else 0.0

    obs4 = (
        f"4. **Separacja Celowanego Przejęcia i Rozdzielczość Pomiaru:** Wdrożenie metryki `retrieval_asr_targeted` (średnio **{avg_targeted:.1%}**) "
        f"rozdziela sukces celowanego ataku od zanieczyszczenia tła (`retrieval_asr_untargeted`: średnio **{avg_untargeted:.1%}**)."
    )

    if isolated:
        obs5 = (
            f"5. **Weryfikacja Protokołu Izolowanego (Recommendation 3) i Wrażliwości Budżetowej:** Eksperyment przeprowadzono w reżimie izolacji per zapytanie. "
            f"Zanieczyszczenie tła wynosi dokładnie **0.0%** we wszystkich scenariuszach. "
            f"Krzywe budżetowe $B \\in \\{1, 3, 5\\}$ odzwierciedlają czysty marginalny przyrost siły ataku, bez sztucznej saturacji kontekstu."
        )
    else:
        obs5 = (
            f"5. **Analiza Zanieczyszczenia Tła w Reżimie Współdzielonym:** Zaobserwowano obecność obcego szumu (`retrieval_asr_untargeted` = **{avg_untargeted:.1%}**). "
            f"W celu uzyskania nieskażonych krzywych budżetowych zaleca się powtórzenie benchmarku z opcją `--isolated-targets`."
        )

    sec5_obs = [obs1, obs2, obs3, obs4, obs5]
    sec5_text = "\n".join(sec5_obs)
```

---

## 8. Wnioski i Rekomendacje dla Implementacji (Handoff dla Buildera)

1. **W `src/visualization/reporter.py`:**
   - Dodać `MIN_UTILITY_THRESHOLD = 0.50` na poziomie modułu.
   - Dodać funkcję pomocniczą `is_isolated_run`.
   - Zaktualizować sygnaturę `generate_markdown_report` o opcjonalny parametr `isolated_targets: Optional[bool] = None`.
   - Wdrożyć dynamiczne generowanie Sekcji 1, tabeli Pareto w Sekcji 3, Sekcji 5 oraz Sekcji 6 bez jakichkolwiek zahardkodowanych literałów.
2. **W `src/evaluation/metrics.py`:**
   - Dodać pole `isolated_targets: bool = False` do dataclass `EngineBenchmarkResult`.
   - Zapewnić propagację tej flagi z parametrów ewaluacji do zwracanego obiektu wyniku.
3. **W `scripts/run_comparison_benchmark.py`:**
   - Dodać argument CLI `--isolated-targets` (store_true, default False).
   - Przekazywać flagę do `BenchmarkReporter.generate_markdown_report(..., isolated_targets=args.isolated_targets)`.
4. **Weryfikacja:**
   - Wszystkie istniejące 328 testów zachowują 100% kompatybilności wstecznej.
   - Nowy test weryfikujący dynamiczne raportowanie w `tests/test_isolated_protocol.py` potwierdzi obecność fraz protokołu izolowanego oraz brak twardych literałów.
