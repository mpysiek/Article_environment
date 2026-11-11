# 🔬 Raport z Badania Odporności Warstwy Wyszukiwania RAG na Ataki Corpus Poisoning (Retrieval Robustness - Real CTI STIX 2.1)

> [!IMPORTANT]
> ### Zakres pomiaru i co z niego nie wynika
> 
> * **Warstwa wyszukiwania, bez generacji.** Etap LLM nie jest uruchamiany (`llm_stage_ran = False`) — to świadoma granica zakresu. Dlatego metryki nazywają się `poison@1` / `poison@5`, a nie ASR: w literaturze (PoisonedRAG, Zou i in.) ASR to udział pytań, dla których **model wygenerował** odpowiedź atakującego. Tu mierzona jest pozycja ładunku w rankingu.
> * **Wyparcie odpowiedzi mierzone osobno.** `GT displaced@5` podaje, dla ilu zapytań odpowiedź znikęła z okna kontekstowego. Ładunek na pozycji 1 przy odpowiedzi wciąż obecnej na pozycji 2 nie odbiera generatorowi dostępu do prawdy. **Tezę o skuteczności ataku niosą wyłącznie `GT displaced@5` i `poison@1 cond`**, nie `poison@1`.
> * **Próg użyteczności obowiązuje per stratum.** Ładunek na pozycji 1 w stratum, w którym czysty silnik i tak nie znajdował odpowiedzi, niczego nie wypiera. Wszystkie średnie międzyscenariuszowe (Sekcja 3 i 4) liczone są wyłącznie na stratach, na których dany silnik osiąga Clean Recall@5 >= 50%; wartości nieograniczone pozostają w Sekcji 2.
> * **Brak obrony jest założeniem badania.** Żaden filtr wejściowy ani higiena indeksu nie są włączone. Wszystkie wartości opisują zatem system bez zabezpieczeń i stanowią **górne ograniczenie** podatności.
> * **Model adwersarza:** scenariusze celowane operują w reżimie wyroczni (*Worst-Case / Oracle*): atakujący zna treść zapytania, docelową asercję fałszującą **oraz `key_terms`, które dla zapytań relacyjnych zawierają nazwy dokumentów-odpowiedzi**. Wektor `blackbox_category` jest najsłabszym testowanym adwersarzem (zna wyłącznie kategorię pytań). Uwaga: „górna” i „dolna granica” opisują siłę modelu zagrożeń, a nie porządek zmierzonych wartości — wektory white-box o innej konstrukcji (`entity_swap`, `pure_topological`) wypadają miejscami niżej niż `blackbox_category`.
> * **Ramię query-echo jest osobnym testem skrajnym.** Dosłowne doklejenie pytania ofiary do ładunku raportowane jest jako odrębna kolumna górnego ograniczenia i **nie wchodzi** do uśrednionych wartości w Sekcji 3.
> * **Arytmetyka okna:** przy budżecie B równym rozmiarowi okna k spadek Clean Recall@5 do zera jest konsekwencją zajęcia wszystkich slotów, a nie załamania algorytmu.
> * **Pula kandydatów Hybrid-Reranker.** Reranker ocenia 10 kandydatów po fuzji RRF z list top-10 BM25 i dense. Gdy listy są rozłączne, każdy składnik wnosi do puli tylko pozycje 1–5, więc pięć ładunków może usunąć odpowiedź z puli, zanim zobaczy ją reranker.
> * **Nazwy.** Silnik zapisany w danych jako `GraphRAG` nosi w artykule nazwę *Graph-Traversal*. Raport nie ustala kolejności architektur: strata użyteczne różnią się między silnikami, więc ich średnie opisują różne grupy zapytań.

## 1. Wstęp i Metodologia Badawcza
Eksperyment bada i porównuje odporność 4 kluczowych architektur wyszukiwania RAG:
* **Sparse (BM25 Okapi)**
* **Dense (FAISS + SentenceTransformers `BAAI/bge-small-en-v1.5`)**
* **Hybrid + Cross-Encoder Reranker (BM25 + FAISS + RRF + `cross-encoder/ms-marco-MiniLM-L-6-v2`)**
* **GraphRAG (NetworkX Degree-Normalized Entity-Relation Subgraph Traversal na grafie STIX 2.1)**

w skali **Real CTI STIX 2.1 (24,000 autentycznych dokumentów: MITRE ATT&CK STIX 2.1, CTIBench RCM/TAA NeurIPS 2024, CISA KEV, CVE Program cvelistV5, 150 zweryfikowanych zapytań Gold Standard)** pod kątem następujących wektorów zatruwania bazy wiedzy (*corpus poisoning*):
1. **BM25 Keyword Stuffing / TF-IDF Saturation** — nasycenie leksykalne terminami kluczowymi zapytania.
2. **Dense Semantic Embedding Alignment** — konstrukcja w duchu PoisonedRAG, semantycznie spójna, bez powtórzeń.
3. **Hybrid Dual-Constraint Evasion** — ładunek przechodzący jednocześnie przez BM25 i cross-encoder.
4. **Graph Bridge Injection** — wstrzyknięcie syntetycznych węzłów-mostków podnoszących wagę przejścia wielohopowego. *Nie jest to implementacja GRAGPoison (arXiv:2501.14050) ani LogicPoison (arXiv:2604.02954); obie te prace celowo unikają syntetycznych węzłów.*
5. **Graph Entity Swap** — podmiana encji z zachowaniem typu, w duchu LogicPoison: bez dodawania nowych węzłów, oba końce relacji istnieją w korpusie.
6. **Pure Topological Poisoning** — manipulacja wyłącznie topologią, bez terminów zapytania w tekście.
7. **Black-Box Category Poisoning** — najsłabszy testowany model zagrożeń: atakujący zna wyłącznie kategorię zapytań, żadnego identyfikatora ofiary. Uwaga: „najsłabszy adwersarz" nie znaczy „najniższy zmierzony `poison@1`" — wektory white-box o innej konstrukcji wypadają miejscami niżej.
8. **Black-Box Topic+Entity** — wariant historyczny, korzystający z identyfikatora ofiary (nie jest więc adwersarzem blind).

oraz walidacji krzyżowej (*cross-attack robustness*), analizy warunkowej `poison@1 cond`, a także izolacji warstwy grafowej (`PureTopologicalPoisonAttacker`).

**Protokół Ewaluacji: Izolowany Indeks per Zapytanie (Recommendation 3 / Isolated Target Protocol)**. Dla każdego zapytania testowego $Q_i$ indeks wyszukiwania zawiera wyłącznie czysty korpus oraz dedykowane ładunki zatrute wygenerowane dla tego zapytania ($B \in \{1, 2, 3, 5\}$). W indeksie nie znajdują się żadne ładunki zaadresowane do innych zapytań ($Q_j, j \ne i$), co całkowicie eliminuje sztuczną saturację okna kontekstowego obcym szumem (`retrieval_asr_untargeted = 0.0%`) i zapewnia niezakłócony pomiar wrażliwości na budżet ataku.

Procedura pomiarowa została zremediowana metrologicznie: wyeliminowano błędy kolizji przestrzeni nazw GraphRAG, zaimplementowano separację celowanego przejęcia (`retrieval_asr_targeted`) od obcego zanieczyszczenia, a średnie międzyscenariuszowe liczone są wyłącznie na stratach powyżej bezwzględnego progu użyteczności (Recall@5 $\ge$ 50%).

**Tryb Bezkosztowy (Cost-Free Local Benchmark / 100% Local Inference):** Wszystkie 4 silniki RAG (Sparse BM25, Dense FAISS, Hybrid z Rerankerem, GraphRAG) oraz symulacje ataków adwersalnych ewaluowane są w 100% lokalnie na CPU/RAM z wykorzystaniem precyzyjnego cache wektorowego. Koszt wykonania eksperymentu wynosi dokładnie **$0.00** (brak zewnętrznych wywołań płatnych API tokenów LLM).
Wyniki zawierają 95% przedziały ufności Wilsona (*Wilson Score Interval*) oraz testy istotności statystycznej McNemara.

---

## 2. Zbiorcza Macierz Wyników (Retrieval Robustness Benchmark)

*Kolumna **`poison@1 cond`** mierzy udział zapytań z ładunkiem na pozycji 1 wraz z 95% przedziałem ufności Wilsona wyłącznie na podzbiorze zapytań ($n_{\text{cond}}$), dla których czysty silnik w warunkach bazowych odnalazł właściwy dokument Ground Truth (clean hit > 0).*

*Protokół izolowany (Recommendation 3): Indeks dla każdego zapytania testowego zawierał wyłącznie czysty korpus i ładunki wygenerowane dla tego zapytania. Wskaźnik zanieczyszczenia tła (`retrieval_asr_untargeted`) wynosi 0.0%.*

| RAG Engine      | Threat / Attack Vector   |   Queries | poison@1 (95% CI)     | poison@1 (zakres remisów)   | poison@1 cond (95% CI)        | poison@5   | GT displaced@5   | Clean Recall@5   |   Clean MRR |
|-----------------|--------------------------|-----------|-----------------------|-----------------------------|-------------------------------|------------|------------------|------------------|-------------|
| Sparse-BM25     | CLEAN_BASELINE           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | N/A                           | 0.0%       | N/A              | 67.4%            |        0.66 |
| Dense-FAISS     | CLEAN_BASELINE           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | N/A                           | 0.0%       | N/A              | 33.8%            |        0.3  |
| Hybrid-Reranker | CLEAN_BASELINE           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | N/A                           | 0.0%       | N/A              | 67.6%            |        0.65 |
| GraphRAG        | CLEAN_BASELINE           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | N/A                           | 0.0%       | N/A              | 55.8%            |        0.48 |
| Sparse-BM25     | SPARSE_B1                |       150 | 38.7% [31.2%-46.7%]   | brak remisów                | 11.7% [6.8%-19.3%] (n=103)    | 96.0%      | 1.0% (n=103)     | 67.2%            |        0.63 |
| Dense-FAISS     | SPARSE_B1                |       150 | 26.0% [19.6%-33.6%]   | brak remisów                | 37.7% [25.9%-51.2%] (n=53)    | 58.0%      | 5.7% (n=53)      | 32.2%            |        0.24 |
| Hybrid-Reranker | SPARSE_B1                |       150 | 17.3% [12.1%-24.2%]   | brak remisów                | 4.9% [2.1%-10.9%] (n=103)     | 60.0%      | 0.0% (n=103)     | 67.6%            |        0.63 |
| GraphRAG        | SPARSE_B1                |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 1.2% (n=86)      | 55.1%            |        0.47 |
| Sparse-BM25     | SPARSE_B2                |       150 | 38.0% [30.6%-46.0%]   | brak remisów                | 10.7% [6.1%-18.1%] (n=103)    | 96.0%      | 1.9% (n=103)     | 67.0%            |        0.62 |
| Dense-FAISS     | SPARSE_B2                |       150 | 26.0% [19.6%-33.6%]   | brak remisów                | 37.7% [25.9%-51.2%] (n=53)    | 58.0%      | 5.7% (n=53)      | 32.2%            |        0.24 |
| Hybrid-Reranker | SPARSE_B2                |       150 | 18.7% [13.2%-25.7%]   | brak remisów                | 4.9% [2.1%-10.9%] (n=103)     | 60.0%      | 0.0% (n=103)     | 67.6%            |        0.63 |
| GraphRAG        | SPARSE_B2                |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 4.7% (n=86)      | 53.1%            |        0.46 |
| Sparse-BM25     | SPARSE_B3                |       150 | 40.7% [33.1%-48.7%]   | brak remisów                | 14.6% [9.0%-22.6%] (n=103)    | 96.7%      | 1.9% (n=103)     | 67.0%            |        0.6  |
| Dense-FAISS     | SPARSE_B3                |       150 | 27.3% [20.8%-35.0%]   | brak remisów                | 41.5% [29.3%-54.9%] (n=53)    | 58.7%      | 9.4% (n=53)      | 31.2%            |        0.21 |
| Hybrid-Reranker | SPARSE_B3                |       150 | 20.0% [14.4%-27.1%]   | brak remisów                | 5.8% [2.7%-12.1%] (n=103)     | 62.0%      | 1.0% (n=103)     | 67.2%            |        0.63 |
| GraphRAG        | SPARSE_B3                |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 11.6% (n=86)     | 48.8%            |        0.45 |
| Sparse-BM25     | SPARSE_B5                |       150 | 41.3% [33.8%-49.3%]   | brak remisów                | 15.5% [9.8%-23.8%] (n=103)    | 96.7%      | 10.7% (n=103)    | 61.3%            |        0.58 |
| Dense-FAISS     | SPARSE_B5                |       150 | 28.7% [22.0%-36.4%]   | brak remisów                | 41.5% [29.3%-54.9%] (n=53)    | 60.7%      | 13.2% (n=53)     | 29.9%            |        0.21 |
| Hybrid-Reranker | SPARSE_B5                |       150 | 28.7% [22.0%-36.4%]   | brak remisów                | 5.8% [2.7%-12.1%] (n=103)     | 64.0%      | 6.8% (n=103)     | 63.6%            |        0.61 |
| GraphRAG        | SPARSE_B5                |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 16.3% (n=86)     | 46.1%            |        0.45 |
| Sparse-BM25     | DENSE_B1                 |       150 | 33.3% [26.3%-41.2%]   | brak remisów                | 3.9% [1.5%-9.6%] (n=103)      | 85.3%      | 1.0% (n=103)     | 67.2%            |        0.66 |
| Dense-FAISS     | DENSE_B1                 |       150 | 16.0% [11.0%-22.7%]   | brak remisów                | 5.7% [1.9%-15.4%] (n=53)      | 35.3%      | 5.7% (n=53)      | 32.6%            |        0.29 |
| Hybrid-Reranker | DENSE_B1                 |       150 | 18.7% [13.2%-25.7%]   | brak remisów                | 1.9% [0.5%-6.8%] (n=103)      | 50.7%      | 0.0% (n=103)     | 67.6%            |        0.64 |
| GraphRAG        | DENSE_B1                 |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 1.2% (n=86)      | 55.1%            |        0.47 |
| Sparse-BM25     | DENSE_B2                 |       150 | 33.3% [26.3%-41.2%]   | brak remisów                | 3.9% [1.5%-9.6%] (n=103)      | 85.3%      | 1.9% (n=103)     | 67.0%            |        0.66 |
| Dense-FAISS     | DENSE_B2                 |       150 | 16.0% [11.0%-22.7%]   | brak remisów                | 5.7% [1.9%-15.4%] (n=53)      | 36.7%      | 5.7% (n=53)      | 32.6%            |        0.29 |
| Hybrid-Reranker | DENSE_B2                 |       150 | 28.0% [21.4%-35.7%]   | brak remisów                | 1.9% [0.5%-6.8%] (n=103)      | 51.3%      | 1.0% (n=103)     | 67.2%            |        0.64 |
| GraphRAG        | DENSE_B2                 |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 4.7% (n=86)      | 53.1%            |        0.46 |
| Sparse-BM25     | DENSE_B3                 |       150 | 33.3% [26.3%-41.2%]   | brak remisów                | 3.9% [1.5%-9.6%] (n=103)      | 86.7%      | 1.9% (n=103)     | 67.0%            |        0.66 |
| Dense-FAISS     | DENSE_B3                 |       150 | 18.7% [13.2%-25.7%]   | brak remisów                | 11.3% [5.3%-22.6%] (n=53)     | 39.3%      | 5.7% (n=53)      | 32.6%            |        0.28 |
| Hybrid-Reranker | DENSE_B3                 |       150 | 29.3% [22.6%-37.1%]   | brak remisów                | 3.9% [1.5%-9.6%] (n=103)      | 54.7%      | 1.9% (n=103)     | 66.9%            |        0.63 |
| GraphRAG        | DENSE_B3                 |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 11.6% (n=86)     | 48.8%            |        0.45 |
| Sparse-BM25     | DENSE_B5                 |       150 | 33.3% [26.3%-41.2%]   | brak remisów                | 3.9% [1.5%-9.6%] (n=103)      | 86.0%      | 3.9% (n=103)     | 66.0%            |        0.65 |
| Dense-FAISS     | DENSE_B5                 |       150 | 18.7% [13.2%-25.7%]   | brak remisów                | 11.3% [5.3%-22.6%] (n=53)     | 44.7%      | 7.5% (n=53)      | 32.2%            |        0.28 |
| Hybrid-Reranker | DENSE_B5                 |       150 | 30.7% [23.8%-38.5%]   | brak remisów                | 3.9% [1.5%-9.6%] (n=103)      | 55.3%      | 3.9% (n=103)     | 66.0%            |        0.63 |
| GraphRAG        | DENSE_B5                 |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 16.3% (n=86)     | 46.1%            |        0.45 |
| Sparse-BM25     | DENSE_ECHO_B1            |       150 | 60.0% [52.0%-67.5%]   | brak remisów                | 41.7% [32.7%-51.4%] (n=103)   | 100.0%     | 1.0% (n=103)     | 67.2%            |        0.53 |
| Dense-FAISS     | DENSE_ECHO_B1            |       150 | 65.3% [57.4%-72.5%]   | brak remisów                | 98.1% [90.1%-99.7%] (n=53)    | 70.0%      | 7.5% (n=53)      | 31.9%            |        0.16 |
| Hybrid-Reranker | DENSE_ECHO_B1            |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [96.4%-100.0%] (n=103) | 100.0%     | 0.0% (n=103)     | 67.6%            |        0.33 |
| GraphRAG        | DENSE_ECHO_B1            |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 1.2% (n=86)      | 55.1%            |        0.47 |
| Sparse-BM25     | DENSE_ECHO_B2            |       150 | 60.0% [52.0%-67.5%]   | brak remisów                | 41.7% [32.7%-51.4%] (n=103)   | 100.0%     | 2.9% (n=103)     | 66.3%            |        0.48 |
| Dense-FAISS     | DENSE_ECHO_B2            |       150 | 66.0% [58.1%-73.1%]   | brak remisów                | 98.1% [90.1%-99.7%] (n=53)    | 72.7%      | 11.3% (n=53)     | 30.9%            |        0.12 |
| Hybrid-Reranker | DENSE_ECHO_B2            |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [96.4%-100.0%] (n=103) | 100.0%     | 1.0% (n=103)     | 67.2%            |        0.22 |
| GraphRAG        | DENSE_ECHO_B2            |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 4.7% (n=86)      | 53.1%            |        0.46 |
| Sparse-BM25     | DENSE_ECHO_B3            |       150 | 60.0% [52.0%-67.5%]   | brak remisów                | 41.7% [32.7%-51.4%] (n=103)   | 100.0%     | 2.9% (n=103)     | 66.3%            |        0.46 |
| Dense-FAISS     | DENSE_ECHO_B3            |       150 | 68.0% [60.2%-74.9%]   | brak remisów                | 100.0% [93.2%-100.0%] (n=53)  | 77.3%      | 13.2% (n=53)     | 30.2%            |        0.08 |
| Hybrid-Reranker | DENSE_ECHO_B3            |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [96.4%-100.0%] (n=103) | 100.0%     | 4.9% (n=103)     | 64.9%            |        0.16 |
| GraphRAG        | DENSE_ECHO_B3            |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 11.6% (n=86)     | 48.8%            |        0.45 |
| Sparse-BM25     | DENSE_ECHO_B5            |       150 | 61.3% [53.3%-68.8%]   | brak remisów                | 43.7% [34.5%-53.3%] (n=103)   | 100.0%     | 42.7% (n=103)    | 39.3%            |        0.39 |
| Dense-FAISS     | DENSE_ECHO_B5            |       150 | 74.7% [67.2%-81.0%]   | brak remisów                | 100.0% [93.2%-100.0%] (n=53)  | 86.7%      | 77.4% (n=53)     | 8.0%             |        0.02 |
| Hybrid-Reranker | DENSE_ECHO_B5            |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [96.4%-100.0%] (n=103) | 100.0%     | 91.3% (n=103)    | 6.0%             |        0.01 |
| GraphRAG        | DENSE_ECHO_B5            |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 16.3% (n=86)     | 46.1%            |        0.45 |
| Sparse-BM25     | HYBRID_B1                |       150 | 33.3% [26.3%-41.2%]   | brak remisów                | 3.9% [1.5%-9.6%] (n=103)      | 91.3%      | 1.0% (n=103)     | 67.2%            |        0.66 |
| Dense-FAISS     | HYBRID_B1                |       150 | 12.7% [8.3%-18.9%]    | brak remisów                | 7.5% [3.0%-17.9%] (n=53)      | 36.0%      | 3.8% (n=53)      | 32.9%            |        0.29 |
| Hybrid-Reranker | HYBRID_B1                |       150 | 19.3% [13.8%-26.4%]   | brak remisów                | 1.9% [0.5%-6.8%] (n=103)      | 56.7%      | 0.0% (n=103)     | 67.6%            |        0.64 |
| GraphRAG        | HYBRID_B1                |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 1.2% (n=86)      | 55.1%            |        0.47 |
| Sparse-BM25     | HYBRID_B2                |       150 | 33.3% [26.3%-41.2%]   | brak remisów                | 3.9% [1.5%-9.6%] (n=103)      | 91.3%      | 1.9% (n=103)     | 67.0%            |        0.66 |
| Dense-FAISS     | HYBRID_B2                |       150 | 12.7% [8.3%-18.9%]    | brak remisów                | 7.5% [3.0%-17.9%] (n=53)      | 36.0%      | 3.8% (n=53)      | 32.9%            |        0.29 |
| Hybrid-Reranker | HYBRID_B2                |       150 | 20.0% [14.4%-27.1%]   | brak remisów                | 1.9% [0.5%-6.8%] (n=103)      | 58.0%      | 0.0% (n=103)     | 67.6%            |        0.64 |
| GraphRAG        | HYBRID_B2                |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 4.7% (n=86)      | 53.1%            |        0.46 |
| Sparse-BM25     | HYBRID_B3                |       150 | 33.3% [26.3%-41.2%]   | brak remisów                | 3.9% [1.5%-9.6%] (n=103)      | 91.3%      | 1.9% (n=103)     | 67.0%            |        0.66 |
| Dense-FAISS     | HYBRID_B3                |       150 | 12.7% [8.3%-18.9%]    | brak remisów                | 7.5% [3.0%-17.9%] (n=53)      | 44.0%      | 5.7% (n=53)      | 32.6%            |        0.28 |
| Hybrid-Reranker | HYBRID_B3                |       150 | 24.7% [18.5%-32.1%]   | brak remisów                | 2.9% [1.0%-8.2%] (n=103)      | 58.0%      | 1.0% (n=103)     | 67.2%            |        0.64 |
| GraphRAG        | HYBRID_B3                |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 11.6% (n=86)     | 48.8%            |        0.45 |
| Sparse-BM25     | HYBRID_B5                |       150 | 33.3% [26.3%-41.2%]   | brak remisów                | 3.9% [1.5%-9.6%] (n=103)      | 91.3%      | 3.9% (n=103)     | 66.0%            |        0.65 |
| Dense-FAISS     | HYBRID_B5                |       150 | 18.0% [12.7%-24.9%]   | brak remisów                | 9.4% [4.1%-20.3%] (n=53)      | 50.0%      | 7.5% (n=53)      | 32.2%            |        0.28 |
| Hybrid-Reranker | HYBRID_B5                |       150 | 28.7% [22.0%-36.4%]   | brak remisów                | 2.9% [1.0%-8.2%] (n=103)      | 58.0%      | 3.9% (n=103)     | 66.0%            |        0.63 |
| GraphRAG        | HYBRID_B5                |       150 | 41.3% [33.8%-49.3%]   | 33.3%-91.3% (n=87)          | 7.0% [3.2%-14.4%] (n=86)      | 94.7%      | 16.3% (n=86)     | 46.1%            |        0.45 |
| Sparse-BM25     | GRAPH_B1                 |       150 | 32.7% [25.7%-40.5%]   | brak remisów                | 2.9% [1.0%-8.2%] (n=103)      | 84.7%      | 1.0% (n=103)     | 67.2%            |        0.66 |
| Dense-FAISS     | GRAPH_B1                 |       150 | 1.3% [0.4%-4.7%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 12.0%      | 1.9% (n=53)      | 33.6%            |        0.3  |
| Hybrid-Reranker | GRAPH_B1                 |       150 | 32.7% [25.7%-40.5%]   | brak remisów                | 2.9% [1.0%-8.2%] (n=103)      | 46.0%      | 0.0% (n=103)     | 67.6%            |        0.64 |
| GraphRAG        | GRAPH_B1                 |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [95.7%-100.0%] (n=86)  | 100.0%     | 2.3% (n=86)      | 54.7%            |        0.25 |
| Sparse-BM25     | GRAPH_B2                 |       150 | 32.7% [25.7%-40.5%]   | brak remisów                | 2.9% [1.0%-8.2%] (n=103)      | 84.7%      | 1.9% (n=103)     | 67.0%            |        0.66 |
| Dense-FAISS     | GRAPH_B2                 |       150 | 1.3% [0.4%-4.7%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 12.0%      | 1.9% (n=53)      | 33.6%            |        0.3  |
| Hybrid-Reranker | GRAPH_B2                 |       150 | 32.7% [25.7%-40.5%]   | brak remisów                | 2.9% [1.0%-8.2%] (n=103)      | 46.7%      | 0.0% (n=103)     | 67.6%            |        0.64 |
| GraphRAG        | GRAPH_B2                 |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [95.7%-100.0%] (n=86)  | 100.0%     | 5.8% (n=86)      | 52.7%            |        0.17 |
| Sparse-BM25     | GRAPH_B3                 |       150 | 32.7% [25.7%-40.5%]   | brak remisów                | 2.9% [1.0%-8.2%] (n=103)      | 84.7%      | 1.9% (n=103)     | 67.0%            |        0.66 |
| Dense-FAISS     | GRAPH_B3                 |       150 | 1.3% [0.4%-4.7%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 12.0%      | 1.9% (n=53)      | 33.6%            |        0.3  |
| Hybrid-Reranker | GRAPH_B3                 |       150 | 32.7% [25.7%-40.5%]   | brak remisów                | 2.9% [1.0%-8.2%] (n=103)      | 48.0%      | 0.0% (n=103)     | 67.6%            |        0.64 |
| GraphRAG        | GRAPH_B3                 |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [95.7%-100.0%] (n=86)  | 100.0%     | 14.0% (n=86)     | 47.9%            |        0.12 |
| Sparse-BM25     | GRAPH_B5                 |       150 | 32.7% [25.7%-40.5%]   | brak remisów                | 2.9% [1.0%-8.2%] (n=103)      | 84.0%      | 2.9% (n=103)     | 66.7%            |        0.66 |
| Dense-FAISS     | GRAPH_B5                 |       150 | 1.3% [0.4%-4.7%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 12.0%      | 1.9% (n=53)      | 33.6%            |        0.3  |
| Hybrid-Reranker | GRAPH_B5                 |       150 | 32.7% [25.7%-40.5%]   | brak remisów                | 2.9% [1.0%-8.2%] (n=103)      | 48.7%      | 2.9% (n=103)     | 66.7%            |        0.64 |
| GraphRAG        | GRAPH_B5                 |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [95.7%-100.0%] (n=86)  | 100.0%     | 100.0% (n=86)    | 0.0%             |        0    |
| Sparse-BM25     | ENTITY_SWAP_B1           |       150 | 1.3% [0.4%-4.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 24.7%      | 0.0% (n=103)     | 67.4%            |        0.67 |
| Dense-FAISS     | ENTITY_SWAP_B1           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 0.7%       | 0.0% (n=53)      | 33.8%            |        0.3  |
| Hybrid-Reranker | ENTITY_SWAP_B1           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 68.2%            |        0.65 |
| GraphRAG        | ENTITY_SWAP_B1           |       150 | 34.7% [27.5%-42.6%]   | 32.7%-46.7% (n=21)          | 0.0% [0.0%-4.3%] (n=86)       | 57.3%      | 1.2% (n=86)      | 55.8%            |        0.47 |
| Sparse-BM25     | ENTITY_SWAP_B2           |       150 | 2.7% [1.0%-6.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 24.0%      | 0.0% (n=103)     | 67.4%            |        0.67 |
| Dense-FAISS     | ENTITY_SWAP_B2           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 1.3%       | 0.0% (n=53)      | 33.8%            |        0.3  |
| Hybrid-Reranker | ENTITY_SWAP_B2           |       150 | 1.3% [0.4%-4.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 1.3%       | 0.0% (n=103)     | 67.6%            |        0.65 |
| GraphRAG        | ENTITY_SWAP_B2           |       150 | 34.0% [26.9%-41.9%]   | 32.0%-46.0% (n=21)          | 0.0% [0.0%-4.3%] (n=86)       | 57.3%      | 7.0% (n=86)      | 52.4%            |        0.46 |
| Sparse-BM25     | ENTITY_SWAP_B3           |       150 | 2.7% [1.0%-6.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 22.7%      | 0.0% (n=103)     | 67.4%            |        0.67 |
| Dense-FAISS     | ENTITY_SWAP_B3           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 1.3%       | 0.0% (n=53)      | 33.8%            |        0.3  |
| Hybrid-Reranker | ENTITY_SWAP_B3           |       150 | 1.3% [0.4%-4.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 2.7%       | 0.0% (n=103)     | 67.6%            |        0.65 |
| GraphRAG        | ENTITY_SWAP_B3           |       150 | 31.3% [24.5%-39.1%]   | 29.3%-43.3% (n=21)          | 0.0% [0.0%-4.3%] (n=86)       | 57.3%      | 9.3% (n=86)      | 50.8%            |        0.46 |
| Sparse-BM25     | ENTITY_SWAP_B5           |       150 | 3.3% [1.4%-7.6%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 12.7%      | 0.0% (n=103)     | 67.4%            |        0.67 |
| Dense-FAISS     | ENTITY_SWAP_B5           |       150 | 0.7% [0.1%-3.7%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 2.0%       | 0.0% (n=53)      | 33.8%            |        0.3  |
| Hybrid-Reranker | ENTITY_SWAP_B5           |       150 | 1.3% [0.4%-4.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 3.3%       | 0.0% (n=103)     | 67.6%            |        0.65 |
| GraphRAG        | ENTITY_SWAP_B5           |       150 | 31.3% [24.5%-39.1%]   | 29.3%-43.3% (n=21)          | 0.0% [0.0%-4.3%] (n=86)       | 56.0%      | 11.6% (n=86)     | 48.6%            |        0.46 |
| Sparse-BM25     | BLACKBOX_CATEGORY_B1     |       150 | 8.0% [4.6%-13.5%]     | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 21.3%      | 1.0% (n=103)     | 67.2%            |        0.66 |
| Dense-FAISS     | BLACKBOX_CATEGORY_B1     |       150 | 12.0% [7.7%-18.2%]    | brak remisów                | 1.9% [0.3%-9.9%] (n=53)       | 20.0%      | 3.8% (n=53)      | 32.9%            |        0.3  |
| Hybrid-Reranker | BLACKBOX_CATEGORY_B1     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 68.2%            |        0.65 |
| GraphRAG        | BLACKBOX_CATEGORY_B1     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 0.0%       | 0.0% (n=86)      | 55.8%            |        0.48 |
| Sparse-BM25     | BLACKBOX_CATEGORY_B2     |       150 | 8.0% [4.6%-13.5%]     | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 21.3%      | 1.9% (n=103)     | 67.0%            |        0.66 |
| Dense-FAISS     | BLACKBOX_CATEGORY_B2     |       150 | 12.0% [7.7%-18.2%]    | brak remisów                | 1.9% [0.3%-9.9%] (n=53)       | 20.0%      | 5.7% (n=53)      | 32.6%            |        0.3  |
| Hybrid-Reranker | BLACKBOX_CATEGORY_B2     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 67.6%            |        0.65 |
| GraphRAG        | BLACKBOX_CATEGORY_B2     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 0.0%       | 0.0% (n=86)      | 55.8%            |        0.48 |
| Sparse-BM25     | BLACKBOX_CATEGORY_B3     |       150 | 8.0% [4.6%-13.5%]     | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 21.3%      | 1.9% (n=103)     | 67.0%            |        0.66 |
| Dense-FAISS     | BLACKBOX_CATEGORY_B3     |       150 | 12.7% [8.3%-18.9%]    | brak remisów                | 1.9% [0.3%-9.9%] (n=53)       | 20.0%      | 5.7% (n=53)      | 32.6%            |        0.3  |
| Hybrid-Reranker | BLACKBOX_CATEGORY_B3     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 67.6%            |        0.65 |
| GraphRAG        | BLACKBOX_CATEGORY_B3     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 0.0%       | 0.0% (n=86)      | 55.8%            |        0.48 |
| Sparse-BM25     | BLACKBOX_CATEGORY_B5     |       150 | 8.0% [4.6%-13.5%]     | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 21.3%      | 2.9% (n=103)     | 66.7%            |        0.66 |
| Dense-FAISS     | BLACKBOX_CATEGORY_B5     |       150 | 14.0% [9.3%-20.5%]    | brak remisów                | 3.8% [1.0%-12.8%] (n=53)      | 20.0%      | 5.7% (n=53)      | 32.6%            |        0.3  |
| Hybrid-Reranker | BLACKBOX_CATEGORY_B5     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 67.6%            |        0.65 |
| GraphRAG        | BLACKBOX_CATEGORY_B5     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 0.0%       | 0.0% (n=86)      | 55.8%            |        0.48 |
| Sparse-BM25     | BLACKBOX_B1              |       150 | 22.0% [16.1%-29.3%]   | brak remisów                | 1.0% [0.2%-5.3%] (n=103)      | 58.0%      | 0.0% (n=103)     | 67.4%            |        0.66 |
| Dense-FAISS     | BLACKBOX_B1              |       150 | 20.0% [14.4%-27.1%]   | brak remisów                | 1.9% [0.3%-9.9%] (n=53)       | 25.3%      | 1.9% (n=53)      | 33.4%            |        0.3  |
| Hybrid-Reranker | BLACKBOX_B1              |       150 | 13.3% [8.8%-19.7%]    | brak remisów                | 1.0% [0.2%-5.3%] (n=103)      | 24.0%      | 0.0% (n=103)     | 67.6%            |        0.64 |
| GraphRAG        | BLACKBOX_B1              |       150 | 20.0% [14.4%-27.1%]   | 16.0%-76.7% (n=91)          | 0.0% [0.0%-4.3%] (n=86)       | 89.3%      | 1.2% (n=86)      | 55.8%            |        0.47 |
| Sparse-BM25     | BLACKBOX_B2              |       150 | 20.7% [15.0%-27.8%]   | brak remisów                | 1.0% [0.2%-5.3%] (n=103)      | 58.0%      | 0.0% (n=103)     | 67.4%            |        0.66 |
| Dense-FAISS     | BLACKBOX_B2              |       150 | 20.0% [14.4%-27.1%]   | brak remisów                | 1.9% [0.3%-9.9%] (n=53)       | 25.3%      | 1.9% (n=53)      | 33.4%            |        0.3  |
| Hybrid-Reranker | BLACKBOX_B2              |       150 | 13.3% [8.8%-19.7%]    | brak remisów                | 1.0% [0.2%-5.3%] (n=103)      | 24.0%      | 1.0% (n=103)     | 67.2%            |        0.64 |
| GraphRAG        | BLACKBOX_B2              |       150 | 11.3% [7.2%-17.4%]    | 9.3%-60.7% (n=77)           | 0.0% [0.0%-4.3%] (n=86)       | 86.7%      | 4.7% (n=86)      | 53.8%            |        0.47 |
| Sparse-BM25     | BLACKBOX_B3              |       150 | 20.7% [15.0%-27.8%]   | brak remisów                | 1.0% [0.2%-5.3%] (n=103)      | 58.0%      | 0.0% (n=103)     | 67.4%            |        0.66 |
| Dense-FAISS     | BLACKBOX_B3              |       150 | 20.0% [14.4%-27.1%]   | brak remisów                | 1.9% [0.3%-9.9%] (n=53)       | 25.3%      | 1.9% (n=53)      | 33.4%            |        0.3  |
| Hybrid-Reranker | BLACKBOX_B3              |       150 | 13.3% [8.8%-19.7%]    | brak remisów                | 1.0% [0.2%-5.3%] (n=103)      | 24.0%      | 1.0% (n=103)     | 67.2%            |        0.64 |
| GraphRAG        | BLACKBOX_B3              |       150 | 10.0% [6.2%-15.8%]    | 8.0%-57.3% (n=74)           | 0.0% [0.0%-4.3%] (n=86)       | 83.3%      | 9.3% (n=86)      | 50.8%            |        0.46 |
| Sparse-BM25     | BLACKBOX_B5              |       150 | 12.7% [8.3%-18.9%]    | brak remisów                | 1.0% [0.2%-5.3%] (n=103)      | 58.0%      | 1.0% (n=103)     | 66.8%            |        0.66 |
| Dense-FAISS     | BLACKBOX_B5              |       150 | 20.0% [14.4%-27.1%]   | brak remisów                | 1.9% [0.3%-9.9%] (n=53)       | 25.3%      | 1.9% (n=53)      | 33.4%            |        0.3  |
| Hybrid-Reranker | BLACKBOX_B5              |       150 | 20.0% [14.4%-27.1%]   | brak remisów                | 1.0% [0.2%-5.3%] (n=103)      | 24.0%      | 1.9% (n=103)     | 66.6%            |        0.64 |
| GraphRAG        | BLACKBOX_B5              |       150 | 10.0% [6.2%-15.8%]    | 8.0%-56.0% (n=72)           | 0.0% [0.0%-4.3%] (n=86)       | 82.0%      | 11.6% (n=86)     | 49.4%            |        0.46 |
| Sparse-BM25     | PURE_TOPOLOGICAL_B1      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 67.4%            |        0.66 |
| Dense-FAISS     | PURE_TOPOLOGICAL_B1      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 0.0%       | 0.0% (n=53)      | 33.8%            |        0.3  |
| Hybrid-Reranker | PURE_TOPOLOGICAL_B1      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 67.6%            |        0.65 |
| GraphRAG        | PURE_TOPOLOGICAL_B1      |       150 | 18.0% [12.7%-24.9%]   | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 82.0%      | 0.0% (n=86)      | 55.6%            |        0.48 |
| Sparse-BM25     | PURE_TOPOLOGICAL_B2      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 67.4%            |        0.66 |
| Dense-FAISS     | PURE_TOPOLOGICAL_B2      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 0.0%       | 0.0% (n=53)      | 33.8%            |        0.3  |
| Hybrid-Reranker | PURE_TOPOLOGICAL_B2      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 67.6%            |        0.65 |
| GraphRAG        | PURE_TOPOLOGICAL_B2      |       150 | 10.0% [6.2%-15.8%]    | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 74.7%      | 0.0% (n=86)      | 55.6%            |        0.48 |
| Sparse-BM25     | PURE_TOPOLOGICAL_B3      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 67.4%            |        0.66 |
| Dense-FAISS     | PURE_TOPOLOGICAL_B3      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 0.0%       | 0.0% (n=53)      | 33.8%            |        0.3  |
| Hybrid-Reranker | PURE_TOPOLOGICAL_B3      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 67.6%            |        0.65 |
| GraphRAG        | PURE_TOPOLOGICAL_B3      |       150 | 8.7% [5.1%-14.3%]     | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 70.0%      | 1.2% (n=86)      | 54.9%            |        0.48 |
| Sparse-BM25     | PURE_TOPOLOGICAL_B5      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 67.4%            |        0.66 |
| Dense-FAISS     | PURE_TOPOLOGICAL_B5      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.8%] (n=53)       | 0.0%       | 0.0% (n=53)      | 33.8%            |        0.3  |
| Hybrid-Reranker | PURE_TOPOLOGICAL_B5      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=103)      | 0.0%       | 0.0% (n=103)     | 67.6%            |        0.65 |
| GraphRAG        | PURE_TOPOLOGICAL_B5      |       150 | 6.0% [3.2%-11.0%]     | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 62.7%      | 1.2% (n=86)      | 54.9%            |        0.48 |

---

## 2.1 Pełna Macierz Podatności Krzyżowej (Cross-Vulnerability Matrix), B=1

Tabela przedstawia `poison@1` dla każdego silnika w zderzeniu z każdym wektorem ataku, **przy budżecie B=1**. Pozostałe budżety są w Sekcji 2.3. Wartości nie są ograniczone do strat użytecznych — rozbicie stratyfikacyjne jest w Sekcji 2.2, a wnioski agregowane w Sekcji 3 liczone są wyłącznie na stratach użytecznych.

| RAG Engine      | Clean Recall@5   | Sparse Keyword (poison@1)   | Dense Semantic (poison@1)   | Dense +Query Echo (poison@1)   | Hybrid Dual (poison@1)   | Graph Bridge Inject (poison@1)   | Graph Entity Swap (poison@1)   | BlackBox Category (poison@1)   | BlackBox Topic+Entity (poison@1)   | Pure Topological (poison@1)   |
|-----------------|------------------|-----------------------------|-----------------------------|--------------------------------|--------------------------|----------------------------------|--------------------------------|--------------------------------|------------------------------------|-------------------------------|
| Sparse-BM25     | 67.4%            | 38.7%                       | 33.3%                       | 60.0%                          | 33.3%                    | 32.7%                            | 1.3%                           | 8.0%                           | 22.0%                              | 0.0%                          |
| Dense-FAISS     | 33.8%            | 26.0%                       | 16.0%                       | 65.3%                          | 12.7%                    | 1.3%                             | 0.0%                           | 12.0%                          | 20.0%                              | 0.0%                          |
| Hybrid-Reranker | 67.6%            | 17.3%                       | 18.7%                       | 100.0%                         | 19.3%                    | 32.7%                            | 0.0%                           | 0.0%                           | 13.3%                              | 0.0%                          |
| GraphRAG        | 55.8%            | 41.3%                       | 41.3%                       | 41.3%                          | 41.3%                    | 100.0%                           | 34.7%                          | 0.0%                           | 20.0%                              | 18.0%                         |

---

## 2.2 Złożoność Domenowa CTI: Pełna Stratyfikacja Zadań (Domain Task Stratification)

W domenie CTI ewaluacja uśredniona zaciera diametralnie różne mechanizmy wyszukiwania. Poniżej przedstawiono pełną stratyfikację wyników na rozłączne zadania.

**Recall@5 i Hit@5 są raportowane osobno.** To dwie różne wielkości: Recall@5 jest ułamkowy (`|zwrócone ∩ GT| / |GT|`), a Hit@5 binarny (czy trafiono cokolwiek). Różnią się wszędzie tam, gdzie zapytanie ma więcej niż jeden dokument docelowy, więc podawanie jednej pod nazwą drugiej rozjeżdża tabelę zbiorczą z tabelami stratyfikacji.

**Kolumna `Max GT displaced@5`** podaje najwyższy w danym stratum odsetek zapytań, dla których czysty silnik znajdował odpowiedź, a po ataku nie ma jej nigdzie w oknie top-5. To jest miara faktycznego wyparcia odpowiedzi; `poison@1` mówi wyłącznie o tym, gdzie w rankingu wylądował ładunek.

**Kolumny `poison@1` w tabelach stratyfikacji podają wartości dla B=1.** Status `NON_VIABLE` stratum oznacza, że wszystkie wartości `poison@1` w tym wierszu opisują ranking, który i tak nie zawierał odpowiedzi — dlatego takie wiersze są wyłączone ze średnich w Sekcjach 3 i 4.

### A. Użyteczność Bazowa w Podziale na Zadania
| RAG Engine      | Overall Clean Recall@5   | CVE Exact-Match (ID w pytaniu) (Recall@5 / Hit@5)   | CVE Descriptive (bez ID) (Recall@5 / Hit@5)   | ATT&CK Relational (graf) (Recall@5 / Hit@5)   |
|-----------------|--------------------------|-----------------------------------------------------|-----------------------------------------------|-----------------------------------------------|
| Sparse-BM25     | 67.4%                    | 100.0% / 50/50                                      | 100.0% / 50/50                                | 2.3% / 3/50                                   |
| Dense-FAISS     | 33.8%                    | 0.0% / 0/50                                         | 96.0% / 48/50                                 | 5.3% / 5/50                                   |
| Hybrid-Reranker | 67.6%                    | 100.0% / 50/50                                      | 100.0% / 50/50                                | 2.7% / 3/50                                   |
| GraphRAG        | 55.8%                    | 100.0% / 50/50                                      | 0.0% / 0/50                                   | 67.3% / 36/50                                 |

### Stratum: CVE Exact-Match (ID w pytaniu) (50 zapytań)

*Identyfikator CVE występuje dosłownie w treści pytania, a dokumentem docelowym jest rekord o tym identyfikatorze. To zadanie wyszukiwania po kluczu, nie wyszukiwania semantycznego — sprzyja metodom leksykalnym i linkowaniu encji.*

| RAG Engine      | Clean Recall@5   | Clean Hit@5   | Sparse Keyword (poison@1)   | Dense Semantic (poison@1)   | Dense +Query Echo (poison@1)   | Hybrid Dual (poison@1)   | Graph Bridge Inject (poison@1)   | Graph Entity Swap (poison@1)   | BlackBox Category (poison@1)   | BlackBox Topic+Entity (poison@1)   | Pure Topological (poison@1)   | Max GT displaced@5   | Stratum Status             |
|-----------------|------------------|---------------|-----------------------------|-----------------------------|--------------------------------|--------------------------|----------------------------------|--------------------------------|--------------------------------|------------------------------------|-------------------------------|----------------------|----------------------------|
| Sparse-BM25     | 100.0%           | 50/50         | 10.0%                       | 2.0%                        | 42.0%                          | 2.0%                     | 0.0%                             | 0.0%                           | 0.0%                           | 2.0%                               | 0.0%                          | 0.0%                 | VIABLE                     |
| Dense-FAISS     | 0.0%             | 0/50          | 0.0%                        | 0.0%                        | 0.0%                           | 0.0%                     | 0.0%                             | 0.0%                           | 0.0%                           | 0.0%                               | 0.0%                          | -                    | NON_VIABLE (<50% Recall@5) |
| Hybrid-Reranker | 100.0%           | 50/50         | 0.0%                        | 0.0%                        | 100.0%                         | 0.0%                     | 0.0%                             | 0.0%                           | 0.0%                           | 0.0%                               | 0.0%                          | 0.0%                 | VIABLE                     |
| GraphRAG        | 100.0%           | 50/50         | 0.0%                        | 0.0%                        | 0.0%                           | 0.0%                     | 100.0%                           | 0.0%                           | 0.0%                           | 0.0%                               | 0.0%                          | 0.0%                 | VIABLE                     |

### Stratum: CVE Descriptive (bez ID) (50 zapytań)

*Pytanie zawiera opis podatności z wyciętym identyfikatorem. Opis jest podciągiem dokumentu docelowego, więc jest to dopasowanie near-duplicate — zadanie uczciwsze niż lookup po ID, ale nie jest to klasyfikacja przyczyny źródłowej z CTIBench.*

| RAG Engine      | Clean Recall@5   | Clean Hit@5   | Sparse Keyword (poison@1)   | Dense Semantic (poison@1)   | Dense +Query Echo (poison@1)   | Hybrid Dual (poison@1)   | Graph Bridge Inject (poison@1)   | Graph Entity Swap (poison@1)   | BlackBox Category (poison@1)   | BlackBox Topic+Entity (poison@1)   | Pure Topological (poison@1)   | Max GT displaced@5   | Stratum Status             |
|-----------------|------------------|---------------|-----------------------------|-----------------------------|--------------------------------|--------------------------|----------------------------------|--------------------------------|--------------------------------|------------------------------------|-------------------------------|----------------------|----------------------------|
| Sparse-BM25     | 100.0%           | 50/50         | 10.0%                       | 0.0%                        | 38.0%                          | 0.0%                     | 0.0%                             | 0.0%                           | 0.0%                           | 0.0%                               | 0.0%                          | 0.0%                 | VIABLE                     |
| Dense-FAISS     | 96.0%            | 48/50         | 36.0%                       | 2.0%                        | 96.0%                          | 4.0%                     | 0.0%                             | 0.0%                           | 0.0%                           | 0.0%                               | 0.0%                          | 2.1%                 | VIABLE                     |
| Hybrid-Reranker | 100.0%           | 50/50         | 8.0%                        | 0.0%                        | 100.0%                         | 0.0%                     | 0.0%                             | 0.0%                           | 0.0%                           | 0.0%                               | 0.0%                          | 0.0%                 | VIABLE                     |
| GraphRAG        | 0.0%             | 0/50          | 100.0%                      | 100.0%                      | 100.0%                         | 100.0%                   | 100.0%                           | 98.0%                          | 0.0%                           | 54.0%                              | 54.0%                         | -                    | NON_VIABLE (<50% Recall@5) |

### Stratum: ATT&CK Relational (graf) (50 zapytań)

*Nazwa poszukiwanej encji nie występuje w pytaniu — wymagane jest przejście po grafie powiązań. Uwaga: zbiór odpowiedzi wyprowadzono z tych samych krawędzi STIX, po których chodzi GraphRAG, więc przewaga wyszukiwania grafowego jest tu częściowo wbudowana w konstrukcję zadania.*

| RAG Engine      | Clean Recall@5   | Clean Hit@5   | Sparse Keyword (poison@1)   | Dense Semantic (poison@1)   | Dense +Query Echo (poison@1)   | Hybrid Dual (poison@1)   | Graph Bridge Inject (poison@1)   | Graph Entity Swap (poison@1)   | BlackBox Category (poison@1)   | BlackBox Topic+Entity (poison@1)   | Pure Topological (poison@1)   | Max GT displaced@5   | Stratum Status             |
|-----------------|------------------|---------------|-----------------------------|-----------------------------|--------------------------------|--------------------------|----------------------------------|--------------------------------|--------------------------------|------------------------------------|-------------------------------|----------------------|----------------------------|
| Sparse-BM25     | 2.3%             | 3/50          | 96.0%                       | 98.0%                       | 100.0%                         | 98.0%                    | 98.0%                            | 4.0%                           | 24.0%                          | 64.0%                              | 0.0%                          | 33.3%                | NON_VIABLE (<50% Recall@5) |
| Dense-FAISS     | 5.3%             | 5/50          | 42.0%                       | 46.0%                       | 100.0%                         | 34.0%                    | 4.0%                             | 0.0%                           | 36.0%                          | 60.0%                              | 0.0%                          | 60.0%                | NON_VIABLE (<50% Recall@5) |
| Hybrid-Reranker | 2.7%             | 3/50          | 44.0%                       | 56.0%                       | 100.0%                         | 58.0%                    | 98.0%                            | 0.0%                           | 0.0%                           | 40.0%                              | 0.0%                          | 0.0%                 | NON_VIABLE (<50% Recall@5) |
| GraphRAG        | 67.3%            | 36/50         | 24.0%                       | 24.0%                       | 24.0%                          | 24.0%                    | 100.0%                           | 6.0%                           | 0.0%                           | 6.0%                               | 0.0%                          | 5.6%                 | VIABLE                     |

---

## 2.3 Krzywe Ataku (Attack Budget Curves)

Wpływ budżetu atakującego (liczby wstrzykniętych dokumentów per zapytanie $B$) na szansę przejęcia top-1 kontekstu:
* **Reżim sub-saturacji ($B \le 2$ przy oknie $k=5$):** Liczba wstrzykniętych ładunków zatrutych nie przekracza połowy okna kontekstowego wyszukiwania ($k=5$). Pozwala to zbadać naturalną selektywność silnika i zdolność do zachowania czystego dokumentu Ground Truth.
* **Reżim stress-testu saturacyjnego ($B \ge 3$ przy oknie $k=5$):** Większość okna kontekstowego ($>50\%$) może zostać zdominowana przez ładunki zatrute, testując odporność w warunkach bezpośredniej presji ilościowej.

W protokole izolowanym (Recommendation 3) krzywe budżetowe odzwierciedlają wrażliwość na liczbę wstrzykniętych wariantów ładunku ($B \in \{1, 2, 3, 5\}$) bez efektu saturacji okna obcymi zatruciami. W **18 z 36** kombinacji silnik × wektor decyzje per-zapytanie są identyczne przy B=1 i B=5 - w tych komórkach wzrost budżetu nie zmienia niczego, a krzywa jest płaska z powodu nasycenia, nie z powodu odporności silnika.

| RAG Engine      | Attack Vector     | Budget=1 (poison@1)   | Budget=2 (poison@1)   | Budget=3 (poison@1)   | Budget=5 (poison@1)   |
|-----------------|-------------------|-----------------------|-----------------------|-----------------------|-----------------------|
| Sparse-BM25     | SPARSE            | 38.7%                 | 38.0%                 | 40.7%                 | 41.3%                 |
| Sparse-BM25     | DENSE             | 33.3%                 | 33.3%                 | 33.3%                 | 33.3%                 |
| Sparse-BM25     | DENSE_ECHO        | 60.0%                 | 60.0%                 | 60.0%                 | 61.3%                 |
| Sparse-BM25     | HYBRID            | 33.3%                 | 33.3%                 | 33.3%                 | 33.3%                 |
| Sparse-BM25     | GRAPH             | 32.7%                 | 32.7%                 | 32.7%                 | 32.7%                 |
| Sparse-BM25     | ENTITY_SWAP       | 1.3%                  | 2.7%                  | 2.7%                  | 3.3%                  |
| Sparse-BM25     | BLACKBOX_CATEGORY | 8.0%                  | 8.0%                  | 8.0%                  | 8.0%                  |
| Sparse-BM25     | BLACKBOX          | 22.0%                 | 20.7%                 | 20.7%                 | 12.7%                 |
| Sparse-BM25     | PURE_TOPOLOGICAL  | 0.0%                  | 0.0%                  | 0.0%                  | 0.0%                  |
| Dense-FAISS     | SPARSE            | 26.0%                 | 26.0%                 | 27.3%                 | 28.7%                 |
| Dense-FAISS     | DENSE             | 16.0%                 | 16.0%                 | 18.7%                 | 18.7%                 |
| Dense-FAISS     | DENSE_ECHO        | 65.3%                 | 66.0%                 | 68.0%                 | 74.7%                 |
| Dense-FAISS     | HYBRID            | 12.7%                 | 12.7%                 | 12.7%                 | 18.0%                 |
| Dense-FAISS     | GRAPH             | 1.3%                  | 1.3%                  | 1.3%                  | 1.3%                  |
| Dense-FAISS     | ENTITY_SWAP       | 0.0%                  | 0.0%                  | 0.0%                  | 0.7%                  |
| Dense-FAISS     | BLACKBOX_CATEGORY | 12.0%                 | 12.0%                 | 12.7%                 | 14.0%                 |
| Dense-FAISS     | BLACKBOX          | 20.0%                 | 20.0%                 | 20.0%                 | 20.0%                 |
| Dense-FAISS     | PURE_TOPOLOGICAL  | 0.0%                  | 0.0%                  | 0.0%                  | 0.0%                  |
| Hybrid-Reranker | SPARSE            | 17.3%                 | 18.7%                 | 20.0%                 | 28.7%                 |
| Hybrid-Reranker | DENSE             | 18.7%                 | 28.0%                 | 29.3%                 | 30.7%                 |
| Hybrid-Reranker | DENSE_ECHO        | 100.0%                | 100.0%                | 100.0%                | 100.0%                |
| Hybrid-Reranker | HYBRID            | 19.3%                 | 20.0%                 | 24.7%                 | 28.7%                 |
| Hybrid-Reranker | GRAPH             | 32.7%                 | 32.7%                 | 32.7%                 | 32.7%                 |
| Hybrid-Reranker | ENTITY_SWAP       | 0.0%                  | 1.3%                  | 1.3%                  | 1.3%                  |
| Hybrid-Reranker | BLACKBOX_CATEGORY | 0.0%                  | 0.0%                  | 0.0%                  | 0.0%                  |
| Hybrid-Reranker | BLACKBOX          | 13.3%                 | 13.3%                 | 13.3%                 | 20.0%                 |
| Hybrid-Reranker | PURE_TOPOLOGICAL  | 0.0%                  | 0.0%                  | 0.0%                  | 0.0%                  |
| GraphRAG        | SPARSE            | 41.3%                 | 41.3%                 | 41.3%                 | 41.3%                 |
| GraphRAG        | DENSE             | 41.3%                 | 41.3%                 | 41.3%                 | 41.3%                 |
| GraphRAG        | DENSE_ECHO        | 41.3%                 | 41.3%                 | 41.3%                 | 41.3%                 |
| GraphRAG        | HYBRID            | 41.3%                 | 41.3%                 | 41.3%                 | 41.3%                 |
| GraphRAG        | GRAPH             | 100.0%                | 100.0%                | 100.0%                | 100.0%                |
| GraphRAG        | ENTITY_SWAP       | 34.7%                 | 34.0%                 | 31.3%                 | 31.3%                 |
| GraphRAG        | BLACKBOX_CATEGORY | 0.0%                  | 0.0%                  | 0.0%                  | 0.0%                  |
| GraphRAG        | BLACKBOX          | 20.0%                 | 11.3%                 | 10.0%                 | 10.0%                 |
| GraphRAG        | PURE_TOPOLOGICAL  | 18.0%                 | 10.0%                 | 8.7%                  | 6.0%                  |

---

## 2.4 Latencja Wyszukiwania (Clean Baseline)

Pomiar zegarem monotonicznym `time.perf_counter()`; podano medianę i rozstęp ćwiartkowy po odrzuceniu pierwszego zapytania scenariusza. **Uwaga:** w protokole izolowanym każdy pomiar zawiera również przebudowę indeksu dla danego zapytania, więc są to czasy end-to-end tego protokołu, a nie czysty czas wyszukiwania w indeksie utrzymywanym na stałe.

| RAG Engine      |   Mediana (ms) |   IQR (ms) |   Średnia (ms) |
|-----------------|----------------|------------|----------------|
| Sparse-BM25     |           28.3 |       63.8 |           48.2 |
| Dense-FAISS     |           18   |        3.9 |           19.2 |
| Hybrid-Reranker |          297.5 |      174.9 |          287   |
| GraphRAG        |           85.5 |       16.1 |           88.2 |

---

## 3. Średnie per Silnik na Stratach Użytecznych (zestawienie, nie ranking)

*Zakres obowiązywania zestawienia: wartości uśredniono **wyłącznie po stratach, na których dany silnik osiąga Clean Recall@5 ≥ 50%** (kolumna „Strata wyłączone" podaje, co odpadło) oraz **wyłącznie po ramieniu referencyjnym**; ramię query-echo, jako test skrajny, ma własną kolumnę i nie wchodzi do średniej. Sam podział zbioru zapytań (po ~1/3 na stratum) pozostaje arbitralny, a strata użyteczne różnią się między silnikami, więc wiersze opisują różne grupy zapytań i **nie ustalają kolejności architektur** — rozstrzygające są tabele stratyfikacji w Sekcji 2.2.*

| Engine          | Status użyteczności (Recall >= 50%)   | Clean Recall@5 Bazowy (Wyższy=Lepszy)   | Średni poison@1, ramię referencyjne (Niższy=Lepszy)   | Średni targeted poison@5, ramię referencyjne (Niższy=Lepszy)   | poison@1, ramię echo (górne ograniczenie)   | Strata wyłączone (poniżej progu)                         |
|-----------------|---------------------------------------|-----------------------------------------|-------------------------------------------------------|----------------------------------------------------------------|---------------------------------------------|----------------------------------------------------------|
| GraphRAG        | VIABLE                                | 55.8%                                   | 17.8%                                                 | 71.7%                                                          | 12.0%                                       | CVE Descriptive (bez ID)                                 |
| Hybrid-Reranker | VIABLE                                | 67.6%                                   | 0.7%                                                  | 16.5%                                                          | 100.0%                                      | ATT&CK Relational (graf)                                 |
| Sparse-BM25     | VIABLE                                | 67.4%                                   | 1.8%                                                  | 48.6%                                                          | 40.5%                                       | ATT&CK Relational (graf)                                 |
| Dense-FAISS     | NON_VIABLE                            | 33.8%                                   | 5.9%                                                  | 23.0%                                                          | 97.0%                                       | ATT&CK Relational (graf), CVE Exact-Match (ID w pytaniu) |

---

## 3.1 Statistical Significance of Pairwise Architecture Differences (McNemar's Test)

Pairwise McNemar comparisons are limited to scenarios sharing the same attack vector or baseline condition.

Rodzina testów: **74** po zwinięciu **37** replikatów budżetowych o identycznych wektorach wyników per zapytanie. Replikaty zwinięto, bo cztery wiersze opisujące ten sam wynik liczyłyby jedno ustalenie czterokrotnie i sztucznie zaostrzały korektę Holma. Hipoteza zerowa jest międzysilnikowa: test porównuje `poison@1` dwóch silników o różnej użyteczności bazowej, więc odrzucenie H0 oznacza różnicę w łącznym efekcie „kompetencja wyszukiwania + odporność", a nie w samej odporności. Silniki diagnostyczne są z testów wyłączone.

| Condition                        | Budżety (identyczne wyniki)   | Engine A        | Engine B        | Discordant (b, c)   | Test Variant            | Statistic   | Raw p-value   | Holm-Bonf p-value   | Significant?   |
|----------------------------------|-------------------------------|-----------------|-----------------|---------------------|-------------------------|-------------|---------------|---------------------|----------------|
| GRAPH (poison@1)                 | B=1, B=2, B=3, B=5            | Sparse-BM25     | GraphRAG        | (0, 101)            | Asymptotic Chi² (CC)    | χ² = 99.01  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| GRAPH (poison@1)                 | B=1, B=2, B=3, B=5            | Hybrid-Reranker | GraphRAG        | (0, 101)            | Asymptotic Chi² (CC)    | χ² = 99.01  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE_ECHO (poison@1)            | B=1, B=2, B=3, B=5            | Hybrid-Reranker | GraphRAG        | (88, 0)             | Asymptotic Chi² (CC)    | χ² = 86.01  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE_ECHO (poison@1)            | B=1, B=2, B=3                 | Sparse-BM25     | Hybrid-Reranker | (0, 60)             | Asymptotic Chi² (CC)    | χ² = 58.02  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE_ECHO (poison@1)            | B=5                           | Sparse-BM25     | Hybrid-Reranker | (0, 58)             | Asymptotic Chi² (CC)    | χ² = 56.02  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (poison@1)           | B=1                           | Hybrid-Reranker | GraphRAG        | (0, 52)             | Asymptotic Chi² (CC)    | χ² = 50.02  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (poison@1)           | B=2                           | Hybrid-Reranker | GraphRAG        | (1, 50)             | Asymptotic Chi² (CC)    | χ² = 45.18  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (poison@1)           | B=1                           | Sparse-BM25     | GraphRAG        | (2, 52)             | Asymptotic Chi² (CC)    | χ² = 44.46  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (poison@1)           | B=3, B=5                      | Hybrid-Reranker | GraphRAG        | (1, 46)             | Asymptotic Chi² (CC)    | χ² = 41.19  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (poison@1)           | B=2                           | Sparse-BM25     | GraphRAG        | (3, 50)             | Asymptotic Chi² (CC)    | χ² = 39.92  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (poison@1)           | B=3                           | Sparse-BM25     | GraphRAG        | (3, 46)             | Asymptotic Chi² (CC)    | χ² = 36.00  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (poison@1)           | B=5                           | Sparse-BM25     | GraphRAG        | (3, 45)             | Asymptotic Chi² (CC)    | χ² = 35.02  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE (poison@1)                 | B=1                           | Sparse-BM25     | Hybrid-Reranker | (22, 0)             | Exact Binomial          | |b-c| = 22  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| SPARSE (poison@1)                | B=1                           | Sparse-BM25     | Hybrid-Reranker | (35, 3)             | Asymptotic Chi² (CC)    | χ² = 25.29  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (poison@1)      | B=1                           | Sparse-BM25     | GraphRAG        | (0, 27)             | Asymptotic Chi² (CC)    | χ² = 25.04  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (poison@1)      | B=1                           | Hybrid-Reranker | GraphRAG        | (0, 27)             | Asymptotic Chi² (CC)    | χ² = 25.04  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| HYBRID (poison@1)                | B=1                           | Sparse-BM25     | Hybrid-Reranker | (21, 0)             | Exact Binomial          | |b-c| = 21  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| SPARSE (poison@1)                | B=3                           | Sparse-BM25     | Hybrid-Reranker | (35, 4)             | Asymptotic Chi² (CC)    | χ² = 23.08  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| HYBRID (poison@1)                | B=2                           | Sparse-BM25     | Hybrid-Reranker | (20, 0)             | Exact Binomial          | |b-c| = 20  | < 0.0001      | 0.0001              | Yes (p<0.05)   |
| SPARSE (poison@1)                | B=2                           | Sparse-BM25     | Hybrid-Reranker | (33, 4)             | Asymptotic Chi² (CC)    | χ² = 21.19  | < 0.0001      | 0.0002              | Yes (p<0.05)   |
| SPARSE (poison@1)                | B=1                           | Hybrid-Reranker | GraphRAG        | (19, 55)            | Asymptotic Chi² (CC)    | χ² = 16.55  | < 0.0001      | 0.0026              | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (poison@1)      | B=2                           | Sparse-BM25     | GraphRAG        | (0, 15)             | Exact Binomial          | |b-c| = 15  | < 0.0001      | 0.0032              | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (poison@1)      | B=2                           | Hybrid-Reranker | GraphRAG        | (0, 15)             | Exact Binomial          | |b-c| = 15  | < 0.0001      | 0.0032              | Yes (p<0.05)   |
| SPARSE (poison@1)                | B=2                           | Hybrid-Reranker | GraphRAG        | (20, 54)            | Asymptotic Chi² (CC)    | χ² = 14.72  | 0.0001        | 0.0064              | Yes (p<0.05)   |
| HYBRID (poison@1)                | B=3                           | Sparse-BM25     | Hybrid-Reranker | (13, 0)             | Exact Binomial          | |b-c| = 13  | 0.0002        | 0.0122              | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (poison@1)      | B=3                           | Sparse-BM25     | GraphRAG        | (0, 13)             | Exact Binomial          | |b-c| = 13  | 0.0002        | 0.0122              | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (poison@1)      | B=3                           | Hybrid-Reranker | GraphRAG        | (0, 13)             | Exact Binomial          | |b-c| = 13  | 0.0002        | 0.0122              | Yes (p<0.05)   |
| DENSE (poison@1)                 | B=1                           | Hybrid-Reranker | GraphRAG        | (24, 58)            | Asymptotic Chi² (CC)    | χ² = 13.28  | 0.0003        | 0.0126              | Yes (p<0.05)   |
| SPARSE (poison@1)                | B=3                           | Hybrid-Reranker | GraphRAG        | (21, 53)            | Asymptotic Chi² (CC)    | χ² = 12.99  | 0.0003        | 0.0144              | Yes (p<0.05)   |
| HYBRID (poison@1)                | B=1                           | Hybrid-Reranker | GraphRAG        | (23, 56)            | Asymptotic Chi² (CC)    | χ² = 12.96  | 0.0003        | 0.0144              | Yes (p<0.05)   |
| BLACKBOX_CATEGORY (poison@1)     | B=1, B=2, B=3, B=5            | Sparse-BM25     | Hybrid-Reranker | (12, 0)             | Exact Binomial          | |b-c| = 12  | 0.0005        | 0.0215              | Yes (p<0.05)   |
| BLACKBOX_CATEGORY (poison@1)     | B=1, B=2, B=3, B=5            | Sparse-BM25     | GraphRAG        | (12, 0)             | Exact Binomial          | |b-c| = 12  | 0.0005        | 0.0215              | Yes (p<0.05)   |
| HYBRID (poison@1)                | B=2                           | Hybrid-Reranker | GraphRAG        | (24, 56)            | Asymptotic Chi² (CC)    | χ² = 12.01  | 0.0005        | 0.0222              | Yes (p<0.05)   |
| SPARSE (poison@1)                | B=5                           | Sparse-BM25     | Hybrid-Reranker | (23, 4)             | Asymptotic Chi² (CC)    | χ² = 12.00  | 0.0005        | 0.0222              | Yes (p<0.05)   |
| DENSE_ECHO (poison@1)            | B=5                           | Sparse-BM25     | GraphRAG        | (61, 31)            | Asymptotic Chi² (CC)    | χ² = 9.14   | 0.0025        | 0.1000              | No             |
| PURE_TOPOLOGICAL (poison@1)      | B=5                           | Sparse-BM25     | GraphRAG        | (0, 9)              | Exact Binomial          | |b-c| = 9   | 0.0039        | 0.1523              | No             |
| PURE_TOPOLOGICAL (poison@1)      | B=5                           | Hybrid-Reranker | GraphRAG        | (0, 9)              | Exact Binomial          | |b-c| = 9   | 0.0039        | 0.1523              | No             |
| DENSE_ECHO (poison@1)            | B=1, B=2, B=3                 | Sparse-BM25     | GraphRAG        | (59, 31)            | Asymptotic Chi² (CC)    | χ² = 8.10   | 0.0044        | 0.1638              | No             |
| BLACKBOX (poison@1)              | B=1                           | Sparse-BM25     | Hybrid-Reranker | (17, 4)             | Exact Binomial          | |b-c| = 13  | 0.0072        | 0.2591              | No             |
| HYBRID (poison@1)                | B=3                           | Hybrid-Reranker | GraphRAG        | (28, 53)            | Asymptotic Chi² (CC)    | χ² = 7.11   | 0.0077        | 0.2681              | No             |
| DENSE (poison@1)                 | B=2                           | Sparse-BM25     | Hybrid-Reranker | (8, 0)              | Exact Binomial          | |b-c| = 8   | 0.0078        | 0.2681              | No             |
| HYBRID (poison@1)                | B=5                           | Sparse-BM25     | Hybrid-Reranker | (7, 0)              | Exact Binomial          | |b-c| = 7   | 0.0156        | 0.5156              | No             |
| BLACKBOX (poison@1)              | B=3                           | Sparse-BM25     | GraphRAG        | (30, 14)            | Asymptotic Chi² (CC)    | χ² = 5.11   | 0.0237        | 0.7596              | No             |
| BLACKBOX (poison@1)              | B=5                           | Hybrid-Reranker | GraphRAG        | (28, 13)            | Asymptotic Chi² (CC)    | χ² = 4.78   | 0.0288        | 0.8923              | No             |
| BLACKBOX (poison@1)              | B=2, B=3                      | Sparse-BM25     | Hybrid-Reranker | (17, 6)             | Exact Binomial          | |b-c| = 11  | 0.0347        | 1.0000              | No             |
| SPARSE (poison@1)                | B=5                           | Hybrid-Reranker | GraphRAG        | (27, 46)            | Asymptotic Chi² (CC)    | χ² = 4.44   | 0.0351        | 1.0000              | No             |
| DENSE (poison@1)                 | B=2                           | Hybrid-Reranker | GraphRAG        | (31, 51)            | Asymptotic Chi² (CC)    | χ² = 4.40   | 0.0359        | 1.0000              | No             |
| HYBRID (poison@1)                | B=5                           | Hybrid-Reranker | GraphRAG        | (31, 50)            | Asymptotic Chi² (CC)    | χ² = 4.00   | 0.0455        | 1.0000              | No             |
| BLACKBOX (poison@1)              | B=5                           | Sparse-BM25     | Hybrid-Reranker | (7, 18)             | Asymptotic Chi² (CC)    | χ² = 4.00   | 0.0455        | 1.0000              | No             |
| BLACKBOX (poison@1)              | B=2                           | Sparse-BM25     | GraphRAG        | (30, 16)            | Asymptotic Chi² (CC)    | χ² = 3.67   | 0.0553        | 1.0000              | No             |
| DENSE (poison@1)                 | B=3                           | Hybrid-Reranker | GraphRAG        | (31, 49)            | Asymptotic Chi² (CC)    | χ² = 3.61   | 0.0573        | 1.0000              | No             |
| CLEAN_BASELINE (GT Recall@5 Hit) | -                             | Sparse-BM25     | GraphRAG        | (51, 34)            | Asymptotic Chi² (CC)    | χ² = 3.01   | 0.0827        | 1.0000              | No             |
| CLEAN_BASELINE (GT Recall@5 Hit) | -                             | Hybrid-Reranker | GraphRAG        | (51, 34)            | Asymptotic Chi² (CC)    | χ² = 3.01   | 0.0827        | 1.0000              | No             |
| DENSE (poison@1)                 | B=5                           | Hybrid-Reranker | GraphRAG        | (33, 49)            | Asymptotic Chi² (CC)    | χ² = 2.74   | 0.0976        | 1.0000              | No             |
| DENSE (poison@1)                 | B=3                           | Sparse-BM25     | Hybrid-Reranker | (8, 2)              | Exact Binomial          | |b-c| = 6   | 0.1094        | 1.0000              | No             |
| BLACKBOX (poison@1)              | B=1                           | Hybrid-Reranker | GraphRAG        | (18, 28)            | Asymptotic Chi² (CC)    | χ² = 1.76   | 0.1845        | 1.0000              | No             |
| DENSE (poison@1)                 | B=1, B=2, B=3, B=5            | Sparse-BM25     | GraphRAG        | (38, 50)            | Asymptotic Chi² (CC)    | χ² = 1.38   | 0.2410        | 1.0000              | No             |
| HYBRID (poison@1)                | B=1, B=2, B=3, B=5            | Sparse-BM25     | GraphRAG        | (38, 50)            | Asymptotic Chi² (CC)    | χ² = 1.38   | 0.2410        | 1.0000              | No             |
| ENTITY_SWAP (poison@1)           | B=5                           | Sparse-BM25     | Hybrid-Reranker | (3, 0)              | Exact Binomial          | |b-c| = 3   | 0.2500        | 1.0000              | No             |
| DENSE (poison@1)                 | B=5                           | Sparse-BM25     | Hybrid-Reranker | (6, 2)              | Exact Binomial          | |b-c| = 4   | 0.2891        | 1.0000              | No             |
| BLACKBOX (poison@1)              | B=3                           | Hybrid-Reranker | GraphRAG        | (18, 13)            | Asymptotic Chi² (CC)    | χ² = 0.52   | 0.4725        | 1.0000              | No             |
| ENTITY_SWAP (poison@1)           | B=1                           | Sparse-BM25     | Hybrid-Reranker | (2, 0)              | Exact Binomial          | |b-c| = 2   | 0.5000        | 1.0000              | No             |
| ENTITY_SWAP (poison@1)           | B=2, B=3                      | Sparse-BM25     | Hybrid-Reranker | (2, 0)              | Exact Binomial          | |b-c| = 2   | 0.5000        | 1.0000              | No             |
| BLACKBOX (poison@1)              | B=5                           | Sparse-BM25     | GraphRAG        | (19, 15)            | Asymptotic Chi² (CC)    | χ² = 0.26   | 0.6069        | 1.0000              | No             |
| SPARSE (poison@1)                | B=2                           | Sparse-BM25     | GraphRAG        | (42, 47)            | Asymptotic Chi² (CC)    | χ² = 0.18   | 0.6716        | 1.0000              | No             |
| BLACKBOX (poison@1)              | B=2                           | Hybrid-Reranker | GraphRAG        | (18, 15)            | Asymptotic Chi² (CC)    | χ² = 0.12   | 0.7277        | 1.0000              | No             |
| SPARSE (poison@1)                | B=1                           | Sparse-BM25     | GraphRAG        | (41, 45)            | Asymptotic Chi² (CC)    | χ² = 0.10   | 0.7463        | 1.0000              | No             |
| BLACKBOX (poison@1)              | B=1                           | Sparse-BM25     | GraphRAG        | (31, 28)            | Asymptotic Chi² (CC)    | χ² = 0.07   | 0.7946        | 1.0000              | No             |
| SPARSE (poison@1)                | B=5                           | Sparse-BM25     | GraphRAG        | (43, 43)            | Asymptotic Chi² (CC)    | χ² = 0.01   | 0.9141        | 1.0000              | No             |
| CLEAN_BASELINE (GT Recall@5 Hit) | -                             | Sparse-BM25     | Hybrid-Reranker | (1, 1)              | Exact Binomial          | |b-c| = 0   | 1.0000        | 1.0000              | No             |
| SPARSE (poison@1)                | B=3                           | Sparse-BM25     | GraphRAG        | (42, 43)            | Asymptotic Chi² (CC)    | χ² = 0.00   | 1.0000        | 1.0000              | No             |
| GRAPH (poison@1)                 | B=1, B=2, B=3, B=5            | Sparse-BM25     | Hybrid-Reranker | (1, 1)              | Exact Binomial          | |b-c| = 0   | 1.0000        | 1.0000              | No             |
| BLACKBOX_CATEGORY (poison@1)     | B=1, B=2, B=3, B=5            | Hybrid-Reranker | GraphRAG        | (0, 0)              | Brak niezgodności (n=0) | 0.00        | 1.0000        | 1.0000              | No             |
| PURE_TOPOLOGICAL (poison@1)      | B=1, B=2, B=3, B=5            | Sparse-BM25     | Hybrid-Reranker | (0, 0)              | Brak niezgodności (n=0) | 0.00        | 1.0000        | 1.0000              | No             |

---

## 4. Skuteczność Wektorów Ataków (Attack Vector Efficacy)

Uśrednione po silnikach nie-diagnostycznych i po stratach użytecznych każdego z nich. Tabela jest **uporządkowana według `GT displaced@5`**, czyli według tego, czy atak faktycznie usunął odpowiedź z okna kontekstowego; `poison@1` podano obok jako wielkość pomocniczą. Kolumna `Silniki (n)` podaje, ilu silników dotyczy średnia — jest to liczba jednocyfrowa, więc średnie te są orientacyjne.

**Wiersze w reżimie `B>=k` są wyłączone z porządkowania i zepchnięte na dół tabeli.** Przy budżecie równym rozmiarowi okna same ładunki wystarczą, by je zapełnić, więc wyparcie jest tam konsekwencją arytmetyki, a nie skuteczności ataku — mierzone na wspólnym wsparciu silników wyparcie skacze z ok. 2% przy B=3 do ok. 100% przy B=5, podczas gdy `poison@5` nie zmienia się wcale. Porównawcze twierdzenia o sile wektorów wolno opierać wyłącznie na wierszach sub-saturacyjnych.

| Attack Vector        | Avg GT displaced@5 (strata użyteczne)   | Avg poison@1 (strata użyteczne)   |   Silniki (n) | Reżim                 |
|----------------------|-----------------------------------------|-----------------------------------|---------------|-----------------------|
| DENSE_ECHO_B3        | 5.2%                                    | 50.7%                             |             3 | sub-saturacja         |
| GRAPH_B3             | 4.7%                                    | 33.3%                             |             3 | sub-saturacja         |
| SPARSE_B3            | 3.9%                                    | 10.0%                             |             3 | sub-saturacja         |
| DENSE_B3             | 3.9%                                    | 5.0%                              |             3 | sub-saturacja         |
| HYBRID_B3            | 3.9%                                    | 4.3%                              |             3 | sub-saturacja         |
| BLACKBOX_B3          | 3.1%                                    | 1.3%                              |             3 | sub-saturacja         |
| ENTITY_SWAP_B3       | 3.1%                                    | 1.0%                              |             3 | sub-saturacja         |
| ENTITY_SWAP_B2       | 2.3%                                    | 1.0%                              |             3 | sub-saturacja         |
| GRAPH_B2             | 1.9%                                    | 33.3%                             |             3 | sub-saturacja         |
| DENSE_ECHO_B2        | 1.9%                                    | 50.7%                             |             3 | sub-saturacja         |
| SPARSE_B2            | 1.6%                                    | 8.3%                              |             3 | sub-saturacja         |
| DENSE_B2             | 1.6%                                    | 4.3%                              |             3 | sub-saturacja         |
| HYBRID_B2            | 1.6%                                    | 4.3%                              |             3 | sub-saturacja         |
| BLACKBOX_B2          | 1.6%                                    | 1.3%                              |             3 | sub-saturacja         |
| GRAPH_B1             | 0.8%                                    | 33.3%                             |             3 | sub-saturacja         |
| DENSE_ECHO_B1        | 0.4%                                    | 50.7%                             |             3 | sub-saturacja         |
| SPARSE_B1            | 0.4%                                    | 8.7%                              |             3 | sub-saturacja         |
| DENSE_B1             | 0.4%                                    | 4.3%                              |             3 | sub-saturacja         |
| HYBRID_B1            | 0.4%                                    | 4.3%                              |             3 | sub-saturacja         |
| BLACKBOX_B1          | 0.4%                                    | 1.3%                              |             3 | sub-saturacja         |
| ENTITY_SWAP_B1       | 0.4%                                    | 1.0%                              |             3 | sub-saturacja         |
| PURE_TOPOLOGICAL_B3  | 0.4%                                    | 0.0%                              |             3 | sub-saturacja         |
| BLACKBOX_CATEGORY_B1 | 0.0%                                    | 0.0%                              |             3 | sub-saturacja         |
| BLACKBOX_CATEGORY_B2 | 0.0%                                    | 0.0%                              |             3 | sub-saturacja         |
| BLACKBOX_CATEGORY_B3 | 0.0%                                    | 0.0%                              |             3 | sub-saturacja         |
| PURE_TOPOLOGICAL_B1  | 0.0%                                    | 0.0%                              |             3 | sub-saturacja         |
| PURE_TOPOLOGICAL_B2  | 0.0%                                    | 0.0%                              |             3 | sub-saturacja         |
| DENSE_ECHO_B5        | 49.4%                                   | 51.3%                             |             3 | B>=k: arytmetyka okna |
| GRAPH_B5             | 33.3%                                   | 33.3%                             |             3 | B>=k: arytmetyka okna |
| SPARSE_B5            | 9.8%                                    | 10.0%                             |             3 | B>=k: arytmetyka okna |
| DENSE_B5             | 6.1%                                    | 5.0%                              |             3 | B>=k: arytmetyka okna |
| HYBRID_B5            | 6.1%                                    | 4.3%                              |             3 | B>=k: arytmetyka okna |
| BLACKBOX_B5          | 4.5%                                    | 1.3%                              |             3 | B>=k: arytmetyka okna |
| ENTITY_SWAP_B5       | 3.9%                                    | 1.0%                              |             3 | B>=k: arytmetyka okna |
| PURE_TOPOLOGICAL_B5  | 0.4%                                    | 0.0%                              |             3 | B>=k: arytmetyka okna |
| BLACKBOX_CATEGORY_B5 | 0.0%                                    | 0.0%                              |             3 | B>=k: arytmetyka okna |

---

## 5. Kluczowe Obserwacje i Wnioski Naukowe

1. **Analiza Użyteczności:** Zgodnie z bezwzględnym progiem użyteczności bazowej (Clean Recall@5 >= 50% mierzonym wyłącznie na czystym korpusie), architekturami spełniającymi kryterium użyteczności w domenie CTI są: **`Hybrid-Reranker`**, **`Sparse-BM25`**, **`GraphRAG`**. Strata użyteczne różnią się między silnikami, więc średnie z Sekcji 3 opisują różne grupy zapytań i nie ustalają kolejności architektur. Pozostałe silniki (Dense-FAISS (33.8%)) zostały sklasyfikowane jako `NON_VIABLE`.
2. **Użyteczność GraphRAG:** Po eliminacji błędu kolizji przestrzeni nazw (`doc:` vs `ent:`) GraphRAG osiąga Clean Recall@5 = **55.8%** oraz MRR = **0.48** (CVE Exact-Match (ID w pytaniu): 100.0%; CVE Descriptive (bez ID): 0.0%; ATT&CK Relational (graf): 67.3%).
3. **Profil Odporności GraphRAG (leksykalny vs strukturalny), w rozbiciu na strata użyteczne:**
   * **Keyword stuffing:** na stratach, na których GraphRAG ma użyteczność bazową, ładunek leksykalny zajmuje pozycję 1 w **12.0%** zapytań (zakres remisowy **0.0%–87.0%**). Średnia pozostałych silników użytecznych na ich własnych stratach użytecznych wynosi **7.0%**; obie wartości opisują różne grupy zapytań. Wartość nieograniczona do strat użytecznych wynosi 41.3% i jest zawyżona przez stratum o zerowym Recall bazowym. Uwaga: 87 zapytań rozstrzygnięto remisem na pozycji 1, więc wartość nieograniczona mieści się w przedziale **33.3%–91.3%** zależnie od kierunku rozstrzygnięcia remisu (patrz Sekcja 6).
   * **Atak topologiczny przy `bridge_count=40`:** poison@1 zagregowane = **18.0%**, ale w rozbiciu stratyfikacyjnym: CVE Exact-Match (ID w pytaniu): 0.0%; CVE Descriptive (bez ID): 54.0%; ATT&CK Relational (graf): 0.0%. Na stratach użytecznych poison@1 = **0.0%**. `poison@1 cond` = **0.0%**, `GT displaced@5` = **0.0%** (n=86). Zgodnie z regułą z Obserwacji 4 tezę o skuteczności ataku niosą te dwie ostatnie wielkości, więc **dane nie wykazują przejęcia GraphRAG przez atak czysto topologiczny na zapytaniach, na które ten silnik w ogóle odpowiada**. Wynik zależy od parametru `bridge_count` ataku, nie jest własnością architektury — patrz sweep progowy (`scripts/run_bridge_sweep.py`, `bridge_sweep_report.md`).
4. **Pozycja Ładunku a Wyparcie Odpowiedzi:** Uśredniając po scenariuszach ataku, silnikach użytecznych i stratach, na których dany silnik ma użyteczność bazową, ładunek zajmuje pozycję 1 w **11.6%** zapytań, ale odpowiedź znika z całego okna top-5 tylko w **4.4%** zapytań, dla których czysty silnik wcześniej ją znajdował. Te dwie liczby mierzą co innego: pierwsza mówi, gdzie w rankingu wylądował ładunek, druga — czy atak faktycznie usunął odpowiedź z kontekstu. **Wniosek o skuteczności ataku wolno opierać wyłącznie na drugiej**, i ta sama reguła obowiązuje w Obserwacji 3 i w Sekcji 4. Dla porównania: bez ograniczenia do strat użytecznych ta sama średnia poison@1 wynosi 28.5%, czyli różnica +16.9% pochodzi wyłącznie ze strat, na których silnik i tak nie znajdował odpowiedzi.
5. **Weryfikacja Protokołu Izolowanego (Recommendation 3) i Wrażliwości Budżetowej:** Eksperyment przeprowadzono w reżimie izolacji per zapytanie. Zerowe zanieczyszczenie obcymi ładunkami jest w tym protokole gwarantowane konstrukcyjnie, więc stanowi asercję poprawności implementacji, a nie wynik empiryczny. Krzywe budżetowe $B \in \{1, 2, 3, 5\}$ zmierzono pod kątem nasycenia. W **18 z 36** kombinacji silnik × wektor decyzje per-zapytanie są identyczne przy B=1 i B=5 - w tych komórkach wzrost budżetu nie zmienia niczego, a krzywa jest płaska z powodu nasycenia, nie z powodu odporności silnika.
6. **Silniki Poniżej Progu Użyteczności (wyniki diagnostyczne):** **`Dense-FAISS`** (Clean Recall@5 = 33.8%; CVE Exact-Match (ID w pytaniu): 0.0%, CVE Descriptive (bez ID): 96.0%, ATT&CK Relational (graf): 5.3%; 424 unikalnych dokumentów w 750 slotach top-k). Silnik zwracający niemal stałą listę niezwiązanych dokumentów ma wskaźniki `poison@1` opisujące zdegenerowany ranking, a nie odporność, dlatego jest wyłączony z międzysilnikowych średnich (Sekcja 4) i z testów istotności (Sekcja 3.1). Ta sama reguła jest stosowana per stratum, nie tylko per silnik (Sekcja 3, kolumna „Strata wyłączone"). Obserwacja domenowa: dla zapytań o identyfikatory CVE mały bi-encoder (`BAAI/bge-small-en-v1.5`) nie rozróżnia unikalnych numerów. **To jednak nie jest rozstrzygnięty wniosek o modelu:** dokumenty CVE są w tym korpusie budowane z jednego szablonu (`real_cti_loader.py`), więc hipoteza „bi-encoder nie koduje identyfikatorów" jest tu nieodróżnialna od hipotezy „jednorodny szablon dominuje w embeddingu". Rozstrzygnięcie wymaga wariantu korpusu bez wspólnego prefiksu; do tego czasu jest to obserwacja, nie wyjaśnienie. Praktyczna rekomendacja (indeksowanie leksykalne lub hybrydowe dla lookupu po identyfikatorze) obowiązuje niezależnie od tego, która hipoteza jest prawdziwa.

---

## 6. Limitations and Threats to Validity

1. **Autentyczny Korpus CTI:** Baza wiedzy bazuje na realnych, zweryfikowanych zbiorach: oficjalnym feedzie STIX 2.1 MITRE ATT&CK Enterprise (20k+ relacji encji), CTIBench (NeurIPS 2024 Spotlight), CISA KEV oraz publikowanych rekordach cvelistV5. Zbiór zapytań Gold Standard posiada zweryfikowane etykiety CWE i relacje ATT&CK.
2. **White-Box Attack Oracle vs Weakest Tested Adversary:** The benchmark evaluates white-box targeted adversaries with query access and a category-level adversary that never touches a victim identifier. Note that the targeted adversaries are handed `key_terms`, which for the relational stratum contain the *names of the answer documents* (`real_query_loader.py` builds them as `[entity] + gold`). Their payloads therefore repeat the gold answer, which is a stronger oracle than "access to the query and the target assertion". `entity_swap` deliberately filters the gold answer out of its anchors, so part of the `poison@1` gap between it and the lexical vectors is a difference in answer leakage, not only in attack construction.
2a. **No Defenses By Design:** No input filtering, deduplication, perplexity screening or index hygiene is enabled at any stage. This is a deliberate scope boundary, not an omission: every figure describes an undefended retrieval stage and is therefore an upper bound. Numbers here are not comparable to work that reports defended pipelines.
2b. **Retrieval-Stage Metrics:** `poison@1` and `poison@5` are payload-ranking measurements, not end-to-end attack success. `GT displaced@5` and `poison@1 cond` are the quantities that carry any claim about an attack "succeeding". Note that `poison@1 cond` is conditioned on each engine's *own* clean baseline, so its denominator differs per engine (Sparse-BM25: n=103, Dense-FAISS: n=53, Hybrid-Reranker: n=103, GraphRAG: n=86); the column compares rates computed on different subsets of queries and is not a like-for-like cross-engine comparison.
3. **GraphRAG Subgraph Traversal & Structural Attack Surface:** GraphRAG walks multi-hop subgraphs over STIX 2.1 networks. The purely topological attack reaches rank 1 on 18.0% of all queries at bridge_count=40, but that aggregate is carried by a stratum in which GraphRAG's own clean Recall@5 is below the utility floor. Restricted to the queries this engine actually answers, `poison@1 cond` = 0.0% and `GT displaced@5` = 0.0% (n=86). **This run therefore neither establishes nor refutes degree-normalization immunity**: `bridge_count` is a free parameter of the attack and the outcome is a function of where it sits relative to the crossover threshold n > 72 + sqrt(5184 + 144*deg0) (bridges have degree 3; the payload's score through one anchoring entity never exceeds 1/6). See `scripts/run_bridge_sweep.py` and `bridge_sweep_report.md`; any claim about GraphRAG's structural robustness has to cite the sweep, not a single point on it.
4. **Metrological Latency & Local Determinism:** Timing uses high-resolution monotonic `time.perf_counter()`, discarding the first query of each scenario, and is reported as median and IQR in Section 2.4. Retrieval is deterministic and the query and corpus samples are drawn with a fixed seed (42), so a re-run on this machine against the cached corpus reproduces every figure exactly.
5. **Evaluation Protocol & Context Isolation:** The benchmark was executed under the isolated per-query protocol (Recommendation 3), ensuring 0.0% foreign context contamination. All budget curves represent true marginal attack scaling.
6. **Nieoznaczoność remisów rankingowych (`poison@1` nie jest estymatorem punktowym dla silników remisujących):** silnik grafowy przypisuje wielu dokumentom identyczny wynik, a `sorted(key=(-score, doc_id))` rozstrzyga remis kolejnością identyfikatorów. Dla remisu przecinającego granicę poison/clean o wartości metryki decyduje więc porządek alfabetyczny (`POISON_…` vs `CVE-…`), a nie funkcja scoringu. Przedział Wilsona w Sekcji 2 obejmuje wyłącznie błąd próbkowania i **nie zawiera tej nieoznaczoności**; poniższa tabela podaje jej szerokość. Zakresy policzono na pełnych grupach remisowych: cała grupa na pozycji 1 oraz grupa na granicy pozycji 5 (przebieg z `--log-ties`).

| RAG Engine   | Najgorszy scenariusz   | poison@1 raportowane   | Zakres wg rozstrzygnięcia remisu   |   Zapytania z remisem |
|--------------|------------------------|------------------------|------------------------------------|-----------------------|
| GraphRAG     | BLACKBOX_B1            | 20.0%                  | 16.0%-76.7%                        |                    91 |

| RAG Engine   | Najgorszy scenariusz   | GT displaced@5 raportowane   | Zakres wg rozstrzygnięcia remisu   |
|--------------|------------------------|------------------------------|------------------------------------|
| Sparse-BM25  | SPARSE_B5              | 10.7%                        | 10.7%-11.7%                        |
| GraphRAG     | SPARSE_B5              | 16.3%                        | 14.0%-95.3%                        |
7. **Stałe sloty kontekstu (dokument obecny niezależnie od pytania, liczone w grupach jednego szablonu):** **Sparse-BM25** / CVE Exact-Match (ID w pytaniu) / szablon `RCM` (n=50): `CVE-2022-1419` w top-5 dla 100% pytań, nad złotym dokumentem w 0; **Sparse-BM25** / CVE Exact-Match (ID w pytaniu) / szablon `RCM` (n=50): `CVE-2024-41160` w top-5 dla 100% pytań, nad złotym dokumentem w 0; **Sparse-BM25** / CVE Exact-Match (ID w pytaniu) / szablon `RCM` (n=50): `CVE-2021-41490` w top-5 dla 100% pytań, nad złotym dokumentem w 0; **Sparse-BM25** / CVE Exact-Match (ID w pytaniu) / szablon `RCM` (n=50): `CVE-2015-8538` w top-5 dla 100% pytań, nad złotym dokumentem w 0; ponadto 16 przypadków w parach silnik–stratum poniżej progu użyteczności (Dense-FAISS, Hybrid-Reranker, Sparse-BM25), wyłączonych z agregatów (pełna lista: `scripts/audit_checks.py`, check K4). Gdy pytania grupy mają wspólne wszystkie słowa poza identyfikatorem, sloty poza złotym dokumentem zajmują dokumenty najlepiej pasujące do tych wspólnych słów, a więc te same przy każdym pytaniu. Przy wyszukiwaniu po kluczu z jednym złotym dokumentem jest to cecha strukturalna, nie wada silnika. Pomiar zniekształca dopiero stały dokument **nad** złotym. Żaden z nich nie wyprzedza złotego dokumentu w stratum użytecznym, więc nie zmienia żadnej raportowanej wielkości.
8. **Query-set construction (what the utility numbers actually measure):** The three strata are not equally hard, and two of the three are string-matching tasks. In the exact-match stratum the answer's own identifier appears verbatim in the question, making it a key lookup. In the descriptive stratum the question is a literal substring of the target document, making it near-duplicate matching. Only the relational stratum requires traversal, and its answer set is derived from the same STIX edges GraphRAG walks, so part of the graph engine's advantage there is built into the task. The relational query pool is additionally filtered to edges with at most 3 answer documents (`MAX_ANSWER_DOCS`), which removes the hardest attribution questions. Every baseline utility figure, and therefore the >= 50% viability floor and the comparisons resting on it, should be read against these constructions rather than as general CTI retrieval quality.
9. **Corpus composition and provenance:** The corpus is not uniform across the tasks it is used for: cve 22,158 (92.3%), malware 724 (3.0%), mitre_technique 697 (2.9%), threat_actor 176 (0.7%). A stratum whose answers live in a small document class is therefore a retrieval problem over that class, embedded in a much larger corpus of another class, and the headline corpus size overstates its difficulty. A third party rebuilding the corpus from the upstream sources will not obtain this exact snapshot: the MITRE bundle is fetched from a moving branch, and the cvelistV5 sample from whatever the latest release is at build time. The run manifest below records what this run actually used; without pinning those snapshots, cross-machine bit-identical replication is not claimed.

| Pozycja                         | Wartość                                                                                                                                                                 |
|---------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| attack_bridge_count             | 40                                                                                                                                                                      |
| attack_budgets                  | [1, 2, 3, 5]                                                                                                                                                            |
| corpus_doc_types                | {'campaign': 56, 'mitigation': 44, 'threat_actor': 176, 'malware': 724, 'tool': 95, 'mitre_technique': 697, 'cve': 22158, 'threat_report': 50}                          |
| corpus_documents                | 24000                                                                                                                                                                   |
| corpus_id_fingerprint_sha256_16 | 26aae4360692cf97                                                                                                                                                        |
| dense_model                     | BAAI/bge-small-en-v1.5                                                                                                                                                  |
| isolated_targets                | True                                                                                                                                                                    |
| log_ties                        | True                                                                                                                                                                    |
| package_versions                | {'torch': '2.14.0+cpu', 'transformers': '5.16.1', 'sentence-transformers': '6.0.1', 'faiss-cpu': '1.15.0', 'rank-bm25': '0.2.2', 'networkx': '3.6.1', 'numpy': '2.5.2'} |
| platform                        | Windows-11-10.0.26200-SP0                                                                                                                                               |
| python                          | 3.13.15                                                                                                                                                                 |
| queries                         | 150                                                                                                                                                                     |
| query_categories                | {'threat_actor_attribution': 20, 'cve_lookup': 50, 'cve_descriptive': 50, 'mitre_technique': 16, 'mitigation_lookup': 14}                                               |
| query_echo_default              | False                                                                                                                                                                   |
| query_fingerprint_sha256_16     | 33844417d9149977                                                                                                                                                        |
| query_set                       | v3                                                                                                                                                                      |
| reranker_model                  | cross-encoder/ms-marco-MiniLM-L-6-v2                                                                                                                                    |
| run_utc                         | 2026-09-27T14:14:52+00:00                                                                                                                                               |
| seed                            | 42                                                                                                                                                                      |
| top_k                           | 5                                                                                                                                                                       |

10. **Statistical reporting:** Wilson intervals are reported per row and are **not** corrected for the number of rows in Section 2; they describe sampling error over the query sample for that one cell, and should be read descriptively rather than as simultaneous coverage. Only the McNemar family in Section 3.1 carries a multiplicity correction (Holm-Bonferroni). All intervals cover sampling error only, never the tie indeterminacy in item 6 or the attack-parameter dependence in item 3.
