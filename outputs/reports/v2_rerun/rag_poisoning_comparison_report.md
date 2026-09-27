# 🔬 Raport z Badania Odporności Warstwy Wyszukiwania RAG na Ataki Corpus Poisoning (Retrieval Robustness - Real CTI STIX 2.1)

> [!IMPORTANT]
> ### Zakres pomiaru i co z niego nie wynika
> 
> * **Warstwa wyszukiwania, bez generacji.** Etap LLM nie jest uruchamiany (`llm_stage_ran = False`) — to świadoma granica zakresu. Dlatego metryki nazywają się `poison@1` / `poison@5`, a nie ASR: w literaturze (PoisonedRAG, Zou i in.) ASR to udział pytań, dla których **model wygenerował** odpowiedź atakującego. Tu mierzona jest pozycja ładunku w rankingu.
> * **Wyparcie odpowiedzi mierzone osobno.** `GT displaced@5` podaje, dla ilu zapytań odpowiedź znikęła z okna kontekstowego. Ładunek na pozycji 1 przy odpowiedzi wciąż obecnej na pozycji 2 nie odbiera generatorowi dostępu do prawdy. **Tezę o skuteczności ataku niosą wyłącznie `GT displaced@5` i `poison@1 cond`**, nie `poison@1`.
> * **Próg użyteczności obowiązuje per stratum.** Ładunek na pozycji 1 w stratum, w którym czysty silnik i tak nie znajdował odpowiedzi, niczego nie wypiera. Wszystkie średnie międzyscenariuszowe (Sekcja 3 i 4) liczone są wyłącznie na stratach, na których dany silnik osiąga Clean Recall@5 >= 50%; wartości nieograniczone pozostają w Sekcji 2.
> * **Brak obrony jest założeniem badania.** Żaden filtr wejściowy ani higiena indeksu nie są włączone. Wszystkie wartości opisują zatem system bez zabezpieczeń i stanowią **górne ograniczenie** podatności.
> * **Model adwersarza:** scenariusze celowane operują w reżimie wyroczni (*Worst-Case / Oracle*): atakujący zna treść zapytania, docelową asercję fałszującą **oraz `key_terms`, które dla zapytań relacyjnych zawierają nazwy dokumentów-odpowiedzi**. Wektor `blackbox_category` jest najsłabszym testowanym adwersarzem (zna wyłącznie kategorię pytań). Uwaga: „górna” i „dolna granica” opisują siłę modelu zagrożeń, a nie porządek zmierzonych wartości — wektory white-box o innej konstrukcji (`entity_swap`, `pure_topological`) wypadają miejscami niżej niż `blackbox_category`.
> * **Ramię query-echo jest osobnym testem skrajnym.** Dosłowne doklejenie pytania ofiary do ładunku raportowane jest jako odrębna kolumna górnego ograniczenia i **nie wchodzi** do uśrednionej odporności w rankingu.
> * **Arytmetyka okna:** przy budżecie B równym rozmiarowi okna k spadek Clean Recall@5 do zera jest konsekwencją zajęcia wszystkich slotów, a nie załamania algorytmu.

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

oraz walidacji krzyżowej (*cross-attack robustness*), analizy warunkowej $ASR_{\text{cond}}$ (*Conditional ASR*), a także ablacji echa zapytania (`query_echo=False`), izolacji warstwy grafowej (`PureTopologicalPoisonAttacker`).

**Protokół Ewaluacji: Izolowany Indeks per Zapytanie (Recommendation 3 / Isolated Target Protocol)**. Dla każdego zapytania testowego $Q_i$ indeks wyszukiwania zawiera wyłącznie czysty korpus oraz dedykowane ładunki zatrute wygenerowane dla tego zapytania ($B \in \{1, 2, 3, 5\}$). W indeksie nie znajdują się żadne ładunki zaadresowane do innych zapytań ($Q_j, j \ne i$), co całkowicie eliminuje sztuczną saturację okna kontekstowego obcym szumem (`retrieval_asr_untargeted = 0.0%`) i zapewnia niezakłócony pomiar wrażliwości na budżet ataku.

Procedura pomiarowa została zremediowana metrologicznie: wyeliminowano błędy kolizji przestrzeni nazw GraphRAG, zaimplementowano separację celowanego przejęcia (`retrieval_asr_targeted`) od obcego zanieczyszczenia, a ocenę odporności oparto na analizie frontu Pareto z bezwzględnym progiem użyteczności (Recall@5 $\ge$ 50%).

**Tryb Bezkosztowy (Cost-Free Local Benchmark / 100% Local Inference):** Wszystkie 4 silniki RAG (Sparse BM25, Dense FAISS, Hybrid z Rerankerem, GraphRAG) oraz symulacje ataków adwersalnych ewaluowane są w 100% lokalnie na CPU/RAM z wykorzystaniem precyzyjnego cache wektorowego. Koszt wykonania eksperymentu wynosi dokładnie **$0.00** (brak zewnętrznych wywołań płatnych API tokenów LLM).
Wyniki zawierają 95% przedziały ufności Wilsona (*Wilson Score Interval*) oraz testy istotności statystycznej McNemara.

---

## 2. Zbiorcza Macierz Wyników (Retrieval Robustness Benchmark)

*Kolumna **ASR_cond** ($ASR_{\text{cond}}$) mierzy skuteczność przejęcia pozycji Top-1 wraz z 95% przedziałem ufności Wilsona wyłącznie na podzbiorze zapytań ($n_{\text{cond}}$), dla których czysty silnik w warunkach bazowych odnalazł właściwy dokument Ground Truth (clean hit > 0).*

*Protokół izolowany (Recommendation 3): Indeks dla każdego zapytania testowego zawierał wyłącznie czysty korpus i ładunki wygenerowane dla tego zapytania. Wskaźnik zanieczyszczenia tła (`retrieval_asr_untargeted`) wynosi 0.0%.*

| RAG Engine      | Threat / Attack Vector   |   Queries | poison@1 (95% CI)     | poison@1 (zakres remisów)   | poison@1 cond (95% CI)        | poison@5   | GT displaced@5   | Clean Recall@5   |   Clean MRR |
|-----------------|--------------------------|-----------|-----------------------|-----------------------------|-------------------------------|------------|------------------|------------------|-------------|
| Sparse-BM25     | CLEAN_BASELINE           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | N/A                           | 0.0%       | N/A              | 68.1%            |        0.65 |
| Dense-FAISS     | CLEAN_BASELINE           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | N/A                           | 0.0%       | N/A              | 34.4%            |        0.31 |
| Hybrid-Reranker | CLEAN_BASELINE           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | N/A                           | 0.0%       | N/A              | 68.2%            |        0.59 |
| GraphRAG        | CLEAN_BASELINE           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | N/A                           | 0.0%       | N/A              | 55.8%            |        0.42 |
| Sparse-BM25     | SPARSE_B1                |       150 | 64.0% [56.1%-71.2%]   | brak remisów                | 54.8% [45.2%-64.0%] (n=104)   | 95.3%      | 1.9% (n=104)     | 67.2%            |        0.48 |
| Dense-FAISS     | SPARSE_B1                |       150 | 30.7% [23.8%-38.5%]   | brak remisów                | 37.0% [25.4%-50.4%] (n=54)    | 76.0%      | 5.6% (n=54)      | 32.9%            |        0.25 |
| Hybrid-Reranker | SPARSE_B1                |       150 | 6.0% [3.2%-11.0%]     | brak remisów                | 3.8% [1.5%-9.5%] (n=104)      | 59.3%      | 1.0% (n=104)     | 67.6%            |        0.61 |
| GraphRAG        | SPARSE_B1                |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 1.2% (n=86)      | 54.8%            |        0.41 |
| Sparse-BM25     | SPARSE_B2                |       150 | 62.7% [54.7%-70.0%]   | brak remisów                | 52.9% [43.4%-62.2%] (n=104)   | 95.3%      | 2.9% (n=104)     | 67.0%            |        0.42 |
| Dense-FAISS     | SPARSE_B2                |       150 | 30.7% [23.8%-38.5%]   | brak remisów                | 37.0% [25.4%-50.4%] (n=54)    | 76.0%      | 5.6% (n=54)      | 32.9%            |        0.25 |
| Hybrid-Reranker | SPARSE_B2                |       150 | 7.3% [4.1%-12.7%]     | brak remisów                | 3.8% [1.5%-9.5%] (n=104)      | 59.3%      | 1.9% (n=104)     | 67.2%            |        0.63 |
| GraphRAG        | SPARSE_B2                |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 8.1% (n=86)      | 50.8%            |        0.4  |
| Sparse-BM25     | SPARSE_B3                |       150 | 65.3% [57.4%-72.5%]   | brak remisów                | 56.7% [47.1%-65.8%] (n=104)   | 96.0%      | 2.9% (n=104)     | 67.0%            |        0.38 |
| Dense-FAISS     | SPARSE_B3                |       150 | 56.7% [48.7%-64.3%]   | brak remisów                | 40.7% [28.7%-54.0%] (n=54)    | 88.7%      | 9.3% (n=54)      | 31.9%            |        0.22 |
| Hybrid-Reranker | SPARSE_B3                |       150 | 8.7% [5.1%-14.3%]     | brak remisów                | 4.8% [2.1%-10.8%] (n=104)     | 61.3%      | 2.9% (n=104)     | 66.9%            |        0.63 |
| GraphRAG        | SPARSE_B3                |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 14.0% (n=86)     | 47.4%            |        0.39 |
| Sparse-BM25     | SPARSE_B5                |       150 | 70.0% [62.2%-76.8%]   | brak remisów                | 57.7% [48.1%-66.7%] (n=104)   | 96.7%      | 53.8% (n=104)    | 32.0%            |        0.29 |
| Dense-FAISS     | SPARSE_B5                |       150 | 56.7% [48.7%-64.3%]   | brak remisów                | 40.7% [28.7%-54.0%] (n=54)    | 90.0%      | 13.0% (n=54)     | 30.6%            |        0.22 |
| Hybrid-Reranker | SPARSE_B5                |       150 | 19.3% [13.8%-26.4%]   | brak remisów                | 4.8% [2.1%-10.8%] (n=104)     | 65.3%      | 6.7% (n=104)     | 64.2%            |        0.61 |
| GraphRAG        | SPARSE_B5                |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 16.3% (n=86)     | 46.1%            |        0.39 |
| Sparse-BM25     | DENSE_B1                 |       150 | 62.7% [54.7%-70.0%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 85.3%      | 1.9% (n=104)     | 67.2%            |        0.49 |
| Dense-FAISS     | DENSE_B1                 |       150 | 5.3% [2.7%-10.2%]     | brak remisów                | 5.6% [1.9%-15.1%] (n=54)      | 35.3%      | 3.7% (n=54)      | 33.6%            |        0.3  |
| Hybrid-Reranker | DENSE_B1                 |       150 | 9.3% [5.6%-15.1%]     | brak remisów                | 1.9% [0.5%-6.7%] (n=104)      | 50.7%      | 1.0% (n=104)     | 67.6%            |        0.64 |
| GraphRAG        | DENSE_B1                 |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 1.2% (n=86)      | 54.8%            |        0.41 |
| Sparse-BM25     | DENSE_B2                 |       150 | 62.7% [54.7%-70.0%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 85.3%      | 2.9% (n=104)     | 67.0%            |        0.44 |
| Dense-FAISS     | DENSE_B2                 |       150 | 6.0% [3.2%-11.0%]     | brak remisów                | 5.6% [1.9%-15.1%] (n=54)      | 36.7%      | 3.7% (n=54)      | 33.6%            |        0.3  |
| Hybrid-Reranker | DENSE_B2                 |       150 | 18.7% [13.2%-25.7%]   | brak remisów                | 1.9% [0.5%-6.7%] (n=104)      | 51.3%      | 1.9% (n=104)     | 67.2%            |        0.64 |
| GraphRAG        | DENSE_B2                 |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 8.1% (n=86)      | 50.8%            |        0.4  |
| Sparse-BM25     | DENSE_B3                 |       150 | 65.3% [57.4%-72.5%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 86.7%      | 3.8% (n=104)     | 66.3%            |        0.41 |
| Dense-FAISS     | DENSE_B3                 |       150 | 9.3% [5.6%-15.1%]     | brak remisów                | 11.1% [5.2%-22.2%] (n=54)     | 43.3%      | 3.7% (n=54)      | 33.6%            |        0.29 |
| Hybrid-Reranker | DENSE_B3                 |       150 | 28.7% [22.0%-36.4%]   | brak remisów                | 3.8% [1.5%-9.5%] (n=104)      | 54.7%      | 2.9% (n=104)     | 66.9%            |        0.64 |
| GraphRAG        | DENSE_B3                 |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 14.0% (n=86)     | 47.4%            |        0.39 |
| Sparse-BM25     | DENSE_B5                 |       150 | 65.3% [57.4%-72.5%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 86.0%      | 51.9% (n=104)    | 33.3%            |        0.33 |
| Dense-FAISS     | DENSE_B5                 |       150 | 9.3% [5.6%-15.1%]     | brak remisów                | 11.1% [5.2%-22.2%] (n=54)     | 48.7%      | 5.6% (n=54)      | 33.2%            |        0.29 |
| Hybrid-Reranker | DENSE_B5                 |       150 | 30.0% [23.2%-37.8%]   | brak remisów                | 3.8% [1.5%-9.5%] (n=104)      | 56.0%      | 45.2% (n=104)    | 38.0%            |        0.36 |
| GraphRAG        | DENSE_B5                 |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 16.3% (n=86)     | 46.1%            |        0.39 |
| Sparse-BM25     | DENSE_ECHO_B1            |       150 | 79.3% [72.2%-85.0%]   | brak remisów                | 70.2% [60.8%-78.1%] (n=104)   | 100.0%     | 1.9% (n=104)     | 67.2%            |        0.43 |
| Dense-FAISS     | DENSE_ECHO_B1            |       150 | 98.7% [95.3%-99.6%]   | brak remisów                | 98.1% [90.2%-99.7%] (n=54)    | 99.3%      | 5.6% (n=54)      | 32.9%            |        0.16 |
| Hybrid-Reranker | DENSE_ECHO_B1            |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [96.4%-100.0%] (n=104) | 100.0%     | 1.0% (n=104)     | 67.6%            |        0.31 |
| GraphRAG        | DENSE_ECHO_B1            |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 1.2% (n=86)      | 54.8%            |        0.41 |
| Sparse-BM25     | DENSE_ECHO_B2            |       150 | 79.3% [72.2%-85.0%]   | brak remisów                | 70.2% [60.8%-78.1%] (n=104)   | 100.0%     | 4.8% (n=104)     | 65.7%            |        0.35 |
| Dense-FAISS     | DENSE_ECHO_B2            |       150 | 98.7% [95.3%-99.6%]   | brak remisów                | 98.1% [90.2%-99.7%] (n=54)    | 99.3%      | 9.3% (n=54)      | 31.9%            |        0.12 |
| Hybrid-Reranker | DENSE_ECHO_B2            |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [96.4%-100.0%] (n=104) | 100.0%     | 1.9% (n=104)     | 67.2%            |        0.22 |
| GraphRAG        | DENSE_ECHO_B2            |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 8.1% (n=86)      | 50.8%            |        0.4  |
| Sparse-BM25     | DENSE_ECHO_B3            |       150 | 79.3% [72.2%-85.0%]   | brak remisów                | 70.2% [60.8%-78.1%] (n=104)   | 100.0%     | 4.8% (n=104)     | 65.7%            |        0.31 |
| Dense-FAISS     | DENSE_ECHO_B3            |       150 | 99.3% [96.3%-99.9%]   | brak remisów                | 100.0% [93.4%-100.0%] (n=54)  | 100.0%     | 11.1% (n=54)     | 31.2%            |        0.09 |
| Hybrid-Reranker | DENSE_ECHO_B3            |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [96.4%-100.0%] (n=104) | 100.0%     | 4.8% (n=104)     | 65.6%            |        0.16 |
| GraphRAG        | DENSE_ECHO_B3            |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 14.0% (n=86)     | 47.4%            |        0.39 |
| Sparse-BM25     | DENSE_ECHO_B5            |       150 | 79.3% [72.2%-85.0%]   | brak remisów                | 70.2% [60.8%-78.1%] (n=104)   | 100.0%     | 71.2% (n=104)    | 20.0%            |        0.2  |
| Dense-FAISS     | DENSE_ECHO_B5            |       150 | 99.3% [96.3%-99.9%]   | brak remisów                | 100.0% [93.4%-100.0%] (n=54)  | 100.0%     | 77.8% (n=54)     | 8.0%             |        0.02 |
| Hybrid-Reranker | DENSE_ECHO_B5            |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [96.4%-100.0%] (n=104) | 100.0%     | 100.0% (n=104)   | 0.0%             |        0    |
| GraphRAG        | DENSE_ECHO_B5            |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 16.3% (n=86)     | 46.1%            |        0.39 |
| Sparse-BM25     | HYBRID_B1                |       150 | 63.3% [55.4%-70.6%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 91.3%      | 1.9% (n=104)     | 67.2%            |        0.49 |
| Dense-FAISS     | HYBRID_B1                |       150 | 13.3% [8.8%-19.7%]    | brak remisów                | 7.4% [2.9%-17.6%] (n=54)      | 36.0%      | 3.7% (n=54)      | 33.6%            |        0.3  |
| Hybrid-Reranker | HYBRID_B1                |       150 | 8.0% [4.6%-13.5%]     | brak remisów                | 1.0% [0.2%-5.2%] (n=104)      | 55.3%      | 1.0% (n=104)     | 67.6%            |        0.64 |
| GraphRAG        | HYBRID_B1                |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 1.2% (n=86)      | 54.8%            |        0.41 |
| Sparse-BM25     | HYBRID_B2                |       150 | 63.3% [55.4%-70.6%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 91.3%      | 2.9% (n=104)     | 67.0%            |        0.44 |
| Dense-FAISS     | HYBRID_B2                |       150 | 13.3% [8.8%-19.7%]    | brak remisów                | 7.4% [2.9%-17.6%] (n=54)      | 36.0%      | 3.7% (n=54)      | 33.6%            |        0.29 |
| Hybrid-Reranker | HYBRID_B2                |       150 | 8.7% [5.1%-14.3%]     | brak remisów                | 1.0% [0.2%-5.2%] (n=104)      | 56.7%      | 1.9% (n=104)     | 67.2%            |        0.64 |
| GraphRAG        | HYBRID_B2                |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 8.1% (n=86)      | 50.8%            |        0.4  |
| Sparse-BM25     | HYBRID_B3                |       150 | 63.3% [55.4%-70.6%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 91.3%      | 2.9% (n=104)     | 67.0%            |        0.41 |
| Dense-FAISS     | HYBRID_B3                |       150 | 13.3% [8.8%-19.7%]    | brak remisów                | 7.4% [2.9%-17.6%] (n=54)      | 40.7%      | 5.6% (n=54)      | 33.2%            |        0.29 |
| Hybrid-Reranker | HYBRID_B3                |       150 | 13.3% [8.8%-19.7%]    | brak remisów                | 1.9% [0.5%-6.7%] (n=104)      | 56.7%      | 2.9% (n=104)     | 66.9%            |        0.64 |
| GraphRAG        | HYBRID_B3                |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 14.0% (n=86)     | 47.4%            |        0.39 |
| Sparse-BM25     | HYBRID_B5                |       150 | 63.3% [55.4%-70.6%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 91.3%      | 51.9% (n=104)    | 33.3%            |        0.33 |
| Dense-FAISS     | HYBRID_B5                |       150 | 13.3% [8.8%-19.7%]    | brak remisów                | 7.4% [2.9%-17.6%] (n=54)      | 45.3%      | 5.6% (n=54)      | 33.2%            |        0.29 |
| Hybrid-Reranker | HYBRID_B5                |       150 | 18.0% [12.7%-24.9%]   | brak remisów                | 1.9% [0.5%-6.7%] (n=104)      | 58.7%      | 51.0% (n=104)    | 34.0%            |        0.32 |
| GraphRAG        | HYBRID_B5                |       150 | 40.0% [32.5%-48.0%]   | 33.3%-78.7% (n=68)          | 7.0% [3.2%-14.4%] (n=86)      | 93.3%      | 16.3% (n=86)     | 46.1%            |        0.39 |
| Sparse-BM25     | GRAPH_B1                 |       150 | 62.7% [54.7%-70.0%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 84.7%      | 1.9% (n=104)     | 67.2%            |        0.49 |
| Dense-FAISS     | GRAPH_B1                 |       150 | 0.7% [0.1%-3.7%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 14.0%      | 1.9% (n=54)      | 34.2%            |        0.31 |
| Hybrid-Reranker | GRAPH_B1                 |       150 | 30.0% [23.2%-37.8%]   | brak remisów                | 2.9% [1.0%-8.1%] (n=104)      | 46.0%      | 1.0% (n=104)     | 67.6%            |        0.64 |
| GraphRAG        | GRAPH_B1                 |       150 | 100.0% [97.5%-100.0%] | brak remisów                | 100.0% [95.7%-100.0%] (n=86)  | 100.0%     | 4.7% (n=86)      | 53.0%            |        0.22 |
| Sparse-BM25     | GRAPH_B2                 |       150 | 62.7% [54.7%-70.0%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 84.7%      | 3.8% (n=104)     | 66.3%            |        0.43 |
| Dense-FAISS     | GRAPH_B2                 |       150 | 0.7% [0.1%-3.7%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 14.0%      | 1.9% (n=54)      | 34.2%            |        0.31 |
| Hybrid-Reranker | GRAPH_B2                 |       150 | 30.0% [23.2%-37.8%]   | brak remisów                | 2.9% [1.0%-8.1%] (n=104)      | 46.7%      | 1.9% (n=104)     | 67.2%            |        0.64 |
| GraphRAG        | GRAPH_B2                 |       150 | 98.7% [95.3%-99.6%]   | brak remisów                | 98.8% [93.7%-99.8%] (n=86)    | 100.0%     | 25.6% (n=86)     | 41.3%            |        0.13 |
| Sparse-BM25     | GRAPH_B3                 |       150 | 62.0% [54.0%-69.4%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 84.7%      | 3.8% (n=104)     | 66.3%            |        0.41 |
| Dense-FAISS     | GRAPH_B3                 |       150 | 0.7% [0.1%-3.7%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 14.0%      | 1.9% (n=54)      | 34.2%            |        0.31 |
| Hybrid-Reranker | GRAPH_B3                 |       150 | 30.0% [23.2%-37.8%]   | brak remisów                | 2.9% [1.0%-8.1%] (n=104)      | 48.0%      | 1.9% (n=104)     | 67.2%            |        0.64 |
| GraphRAG        | GRAPH_B3                 |       150 | 98.7% [95.3%-99.6%]   | brak remisów                | 98.8% [93.7%-99.8%] (n=86)    | 100.0%     | 33.7% (n=86)     | 36.9%            |        0.09 |
| Sparse-BM25     | GRAPH_B5                 |       150 | 61.3% [53.3%-68.8%]   | brak remisów                | 51.0% [41.5%-60.4%] (n=104)   | 84.0%      | 51.9% (n=104)    | 33.3%            |        0.33 |
| Dense-FAISS     | GRAPH_B5                 |       150 | 0.7% [0.1%-3.7%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 14.0%      | 1.9% (n=54)      | 34.2%            |        0.31 |
| Hybrid-Reranker | GRAPH_B5                 |       150 | 30.0% [23.2%-37.8%]   | brak remisów                | 2.9% [1.0%-8.1%] (n=104)      | 48.7%      | 51.0% (n=104)    | 34.0%            |        0.32 |
| GraphRAG        | GRAPH_B5                 |       150 | 88.0% [81.8%-92.3%]   | brak remisów                | 81.4% [71.9%-88.2%] (n=86)    | 100.0%     | 100.0% (n=86)    | 0.0%             |        0    |
| Sparse-BM25     | ENTITY_SWAP_B1           |       150 | 0.7% [0.1%-3.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 14.0%      | 0.0% (n=104)     | 68.1%            |        0.66 |
| Dense-FAISS     | ENTITY_SWAP_B1           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 0.7%       | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | ENTITY_SWAP_B1           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.9%            |        0.59 |
| GraphRAG        | ENTITY_SWAP_B1           |       150 | 33.3% [26.3%-41.2%]   | 32.7%-34.0% (n=2)           | 0.0% [0.0%-4.3%] (n=86)       | 56.0%      | 1.2% (n=86)      | 55.4%            |        0.42 |
| Sparse-BM25     | ENTITY_SWAP_B2           |       150 | 0.7% [0.1%-3.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 14.7%      | 0.0% (n=104)     | 68.1%            |        0.66 |
| Dense-FAISS     | ENTITY_SWAP_B2           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 0.7%       | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | ENTITY_SWAP_B2           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 2.0%       | 0.0% (n=104)     | 68.2%            |        0.59 |
| GraphRAG        | ENTITY_SWAP_B2           |       150 | 32.7% [25.7%-40.5%]   | 32.0%-33.3% (n=2)           | 0.0% [0.0%-4.3%] (n=86)       | 56.0%      | 10.5% (n=86)     | 50.1%            |        0.4  |
| Sparse-BM25     | ENTITY_SWAP_B3           |       150 | 0.7% [0.1%-3.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 14.0%      | 0.0% (n=104)     | 68.1%            |        0.66 |
| Dense-FAISS     | ENTITY_SWAP_B3           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 0.7%       | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | ENTITY_SWAP_B3           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 2.0%       | 0.0% (n=104)     | 68.2%            |        0.59 |
| GraphRAG        | ENTITY_SWAP_B3           |       150 | 30.0% [23.2%-37.8%]   | 29.3%-30.7% (n=2)           | 0.0% [0.0%-4.3%] (n=86)       | 56.0%      | 11.6% (n=86)     | 49.4%            |        0.4  |
| Sparse-BM25     | ENTITY_SWAP_B5           |       150 | 0.7% [0.1%-3.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 4.0%       | 0.0% (n=104)     | 68.1%            |        0.66 |
| Dense-FAISS     | ENTITY_SWAP_B5           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 0.7%       | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | ENTITY_SWAP_B5           |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 2.0%       | 0.0% (n=104)     | 68.2%            |        0.59 |
| GraphRAG        | ENTITY_SWAP_B5           |       150 | 30.0% [23.2%-37.8%]   | 29.3%-30.7% (n=2)           | 0.0% [0.0%-4.3%] (n=86)       | 54.7%      | 11.6% (n=86)     | 48.6%            |        0.4  |
| Sparse-BM25     | BLACKBOX_CATEGORY_B1     |       150 | 8.0% [4.6%-13.5%]     | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 21.3%      | 1.0% (n=104)     | 67.9%            |        0.65 |
| Dense-FAISS     | BLACKBOX_CATEGORY_B1     |       150 | 12.0% [7.7%-18.2%]    | brak remisów                | 1.9% [0.3%-9.8%] (n=54)       | 20.0%      | 3.7% (n=54)      | 33.6%            |        0.31 |
| Hybrid-Reranker | BLACKBOX_CATEGORY_B1     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.9%            |        0.59 |
| GraphRAG        | BLACKBOX_CATEGORY_B1     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 0.0%       | 0.0% (n=86)      | 55.8%            |        0.42 |
| Sparse-BM25     | BLACKBOX_CATEGORY_B2     |       150 | 8.0% [4.6%-13.5%]     | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 21.3%      | 1.9% (n=104)     | 67.7%            |        0.65 |
| Dense-FAISS     | BLACKBOX_CATEGORY_B2     |       150 | 12.0% [7.7%-18.2%]    | brak remisów                | 1.9% [0.3%-9.8%] (n=54)       | 20.0%      | 5.6% (n=54)      | 33.2%            |        0.31 |
| Hybrid-Reranker | BLACKBOX_CATEGORY_B2     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.2%            |        0.59 |
| GraphRAG        | BLACKBOX_CATEGORY_B2     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 0.0%       | 0.0% (n=86)      | 55.8%            |        0.42 |
| Sparse-BM25     | BLACKBOX_CATEGORY_B3     |       150 | 8.0% [4.6%-13.5%]     | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 21.3%      | 1.9% (n=104)     | 67.7%            |        0.65 |
| Dense-FAISS     | BLACKBOX_CATEGORY_B3     |       150 | 12.7% [8.3%-18.9%]    | brak remisów                | 1.9% [0.3%-9.8%] (n=54)       | 20.0%      | 5.6% (n=54)      | 33.2%            |        0.31 |
| Hybrid-Reranker | BLACKBOX_CATEGORY_B3     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.2%            |        0.59 |
| GraphRAG        | BLACKBOX_CATEGORY_B3     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 0.0%       | 0.0% (n=86)      | 55.8%            |        0.42 |
| Sparse-BM25     | BLACKBOX_CATEGORY_B5     |       150 | 8.0% [4.6%-13.5%]     | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 21.3%      | 2.9% (n=104)     | 67.3%            |        0.65 |
| Dense-FAISS     | BLACKBOX_CATEGORY_B5     |       150 | 14.0% [9.3%-20.5%]    | brak remisów                | 3.7% [1.0%-12.5%] (n=54)      | 20.0%      | 5.6% (n=54)      | 33.2%            |        0.31 |
| Hybrid-Reranker | BLACKBOX_CATEGORY_B5     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.2%            |        0.59 |
| GraphRAG        | BLACKBOX_CATEGORY_B5     |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 0.0%       | 0.0% (n=86)      | 55.8%            |        0.42 |
| Sparse-BM25     | BLACKBOX_B1              |       150 | 11.3% [7.2%-17.4%]    | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 56.7%      | 1.0% (n=104)     | 67.4%            |        0.65 |
| Dense-FAISS     | BLACKBOX_B1              |       150 | 10.7% [6.7%-16.6%]    | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 19.3%      | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | BLACKBOX_B1              |       150 | 2.0% [0.7%-5.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 23.3%      | 1.0% (n=104)     | 67.6%            |        0.64 |
| GraphRAG        | BLACKBOX_B1              |       150 | 18.7% [13.2%-25.7%]   | 16.0%-64.0% (n=72)          | 0.0% [0.0%-4.3%] (n=86)       | 88.0%      | 1.2% (n=86)      | 55.4%            |        0.42 |
| Sparse-BM25     | BLACKBOX_B2              |       150 | 11.3% [7.2%-17.4%]    | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 56.0%      | 1.0% (n=104)     | 67.4%            |        0.65 |
| Dense-FAISS     | BLACKBOX_B2              |       150 | 10.7% [6.7%-16.6%]    | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 19.3%      | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | BLACKBOX_B2              |       150 | 2.0% [0.7%-5.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 23.3%      | 1.0% (n=104)     | 67.6%            |        0.64 |
| GraphRAG        | BLACKBOX_B2              |       150 | 10.0% [6.2%-15.8%]    | 9.3%-48.0% (n=58)           | 0.0% [0.0%-4.3%] (n=86)       | 85.3%      | 8.1% (n=86)      | 51.4%            |        0.41 |
| Sparse-BM25     | BLACKBOX_B3              |       150 | 11.3% [7.2%-17.4%]    | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 23.3%      | 1.0% (n=104)     | 67.4%            |        0.65 |
| Dense-FAISS     | BLACKBOX_B3              |       150 | 10.7% [6.7%-16.6%]    | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 19.3%      | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | BLACKBOX_B3              |       150 | 2.0% [0.7%-5.7%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 23.3%      | 1.0% (n=104)     | 67.6%            |        0.59 |
| GraphRAG        | BLACKBOX_B3              |       150 | 8.7% [5.1%-14.3%]     | 8.0%-44.7% (n=55)           | 0.0% [0.0%-4.3%] (n=86)       | 82.0%      | 11.6% (n=86)     | 49.4%            |        0.4  |
| Sparse-BM25     | BLACKBOX_B5              |       150 | 11.3% [7.2%-17.4%]    | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 14.7%      | 1.0% (n=104)     | 67.4%            |        0.64 |
| Dense-FAISS     | BLACKBOX_B5              |       150 | 10.7% [6.7%-16.6%]    | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 19.3%      | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | BLACKBOX_B5              |       150 | 8.7% [5.1%-14.3%]     | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 23.3%      | 1.0% (n=104)     | 67.6%            |        0.59 |
| GraphRAG        | BLACKBOX_B5              |       150 | 8.7% [5.1%-14.3%]     | 8.0%-43.3% (n=53)           | 0.0% [0.0%-4.3%] (n=86)       | 80.7%      | 11.6% (n=86)     | 49.4%            |        0.41 |
| Sparse-BM25     | PURE_TOPOLOGICAL_B1      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.1%            |        0.65 |
| Dense-FAISS     | PURE_TOPOLOGICAL_B1      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 0.0%       | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | PURE_TOPOLOGICAL_B1      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.2%            |        0.59 |
| GraphRAG        | PURE_TOPOLOGICAL_B1      |       150 | 18.0% [12.7%-24.9%]   | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 79.3%      | 0.0% (n=86)      | 55.6%            |        0.42 |
| Sparse-BM25     | PURE_TOPOLOGICAL_B2      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.1%            |        0.65 |
| Dense-FAISS     | PURE_TOPOLOGICAL_B2      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 0.0%       | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | PURE_TOPOLOGICAL_B2      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.2%            |        0.59 |
| GraphRAG        | PURE_TOPOLOGICAL_B2      |       150 | 10.0% [6.2%-15.8%]    | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 71.3%      | 1.2% (n=86)      | 54.9%            |        0.42 |
| Sparse-BM25     | PURE_TOPOLOGICAL_B3      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.1%            |        0.65 |
| Dense-FAISS     | PURE_TOPOLOGICAL_B3      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 0.0%       | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | PURE_TOPOLOGICAL_B3      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.2%            |        0.59 |
| GraphRAG        | PURE_TOPOLOGICAL_B3      |       150 | 8.7% [5.1%-14.3%]     | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 57.3%      | 1.2% (n=86)      | 54.9%            |        0.42 |
| Sparse-BM25     | PURE_TOPOLOGICAL_B5      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.1%            |        0.65 |
| Dense-FAISS     | PURE_TOPOLOGICAL_B5      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-6.6%] (n=54)       | 0.0%       | 0.0% (n=54)      | 34.4%            |        0.31 |
| Hybrid-Reranker | PURE_TOPOLOGICAL_B5      |       150 | 0.0% [0.0%-2.5%]      | brak remisów                | 0.0% [0.0%-3.6%] (n=104)      | 0.0%       | 0.0% (n=104)     | 68.2%            |        0.59 |
| GraphRAG        | PURE_TOPOLOGICAL_B5      |       150 | 6.0% [3.2%-11.0%]     | brak remisów                | 0.0% [0.0%-4.3%] (n=86)       | 50.0%      | 2.3% (n=86)      | 54.2%            |        0.42 |

---

## 2.1 Pełna Macierz Podatności Krzyżowej (Cross-Vulnerability Matrix), B=1

Tabela przedstawia `poison@1` dla każdego silnika w zderzeniu z każdym wektorem ataku, **przy budżecie B=1**. Pozostałe budżety są w Sekcji 2.3. Wartości nie są ograniczone do strat użytecznych — rozbicie stratyfikacyjne jest w Sekcji 2.2, a wnioski agregowane w Sekcji 3 liczone są wyłącznie na stratach użytecznych.

| RAG Engine      | Clean Recall@5   | Sparse Keyword (poison@1)   | Dense Semantic (poison@1)   | Dense +Query Echo (poison@1)   | Hybrid Dual (poison@1)   | Graph Bridge Inject (poison@1)   | Graph Entity Swap (poison@1)   | BlackBox Category (poison@1)   | BlackBox Topic+Entity (poison@1)   | Pure Topological (poison@1)   |
|-----------------|------------------|-----------------------------|-----------------------------|--------------------------------|--------------------------|----------------------------------|--------------------------------|--------------------------------|------------------------------------|-------------------------------|
| Sparse-BM25     | 68.1%            | 64.0%                       | 62.7%                       | 79.3%                          | 63.3%                    | 62.7%                            | 0.7%                           | 8.0%                           | 11.3%                              | 0.0%                          |
| Dense-FAISS     | 34.4%            | 30.7%                       | 5.3%                        | 98.7%                          | 13.3%                    | 0.7%                             | 0.0%                           | 12.0%                          | 10.7%                              | 0.0%                          |
| Hybrid-Reranker | 68.2%            | 6.0%                        | 9.3%                        | 100.0%                         | 8.0%                     | 30.0%                            | 0.0%                           | 0.0%                           | 2.0%                               | 0.0%                          |
| GraphRAG        | 55.8%            | 40.0%                       | 40.0%                       | 40.0%                          | 40.0%                    | 100.0%                           | 33.3%                          | 0.0%                           | 18.7%                              | 18.0%                         |

---

## 2.2 Złożoność Domenowa CTI: Pełna Stratyfikacja Zadań (Domain Task Stratification)

W domenie CTI ewaluacja uśredniona zaciera diametralnie różne mechanizmy wyszukiwania. Poniżej przedstawiono pełną stratyfikację wyników na rozłączne zadania.

**Recall@5 i Hit@5 są raportowane osobno.** To dwie różne wielkości: Recall@5 jest ułamkowy (`|zwrócone ∩ GT| / |GT|`), a Hit@5 binarny (czy trafiono cokolwiek). Różnią się wszędzie tam, gdzie zapytanie ma więcej niż jeden dokument docelowy, więc podawanie jednej pod nazwą drugiej rozjeżdża tabelę zbiorczą z tabelami stratyfikacji.

**Kolumna `Max GT displaced@5`** podaje najwyższy w danym stratum odsetek zapytań, dla których czysty silnik znajdował odpowiedź, a po ataku nie ma jej nigdzie w oknie top-5. To jest miara faktycznego wyparcia odpowiedzi; `poison@1` mówi wyłącznie o tym, gdzie w rankingu wylądował ładunek.

**Kolumny `poison@1` w tabelach stratyfikacji podają wartości dla B=1.** Status `NON_VIABLE` stratum oznacza, że wszystkie wartości `poison@1` w tym wierszu opisują ranking, który i tak nie zawierał odpowiedzi — dlatego takie wiersze są wyłączone ze średnich w Sekcjach 3 i 4.

### A. Użyteczność Bazowa w Podziale na Zadania
| RAG Engine      | Overall Clean Recall@5   | CVE Exact-Match (ID w pytaniu) (Recall@5 / Hit@5)   | CVE Descriptive (bez ID) (Recall@5 / Hit@5)   | ATT&CK Relational (graf) (Recall@5 / Hit@5)   |
|-----------------|--------------------------|-----------------------------------------------------|-----------------------------------------------|-----------------------------------------------|
| Sparse-BM25     | 68.1%                    | 100.0% / 50/50                                      | 100.0% / 50/50                                | 4.3% / 4/50                                   |
| Dense-FAISS     | 34.4%                    | 0.0% / 0/50                                         | 96.0% / 48/50                                 | 7.3% / 6/50                                   |
| Hybrid-Reranker | 68.2%                    | 100.0% / 50/50                                      | 100.0% / 50/50                                | 4.7% / 4/50                                   |
| GraphRAG        | 55.8%                    | 100.0% / 50/50                                      | 0.0% / 0/50                                   | 67.3% / 36/50                                 |

### Stratum: CVE Exact-Match (ID w pytaniu) (50 zapytań)

*Identyfikator CVE występuje dosłownie w treści pytania, a dokumentem docelowym jest rekord o tym identyfikatorze. To zadanie wyszukiwania po kluczu, nie wyszukiwania semantycznego — sprzyja metodom leksykalnym i linkowaniu encji.*

| RAG Engine      | Clean Recall@5   | Clean Hit@5   | Sparse Keyword (poison@1)   | Dense Semantic (poison@1)   | Dense +Query Echo (poison@1)   | Hybrid Dual (poison@1)   | Graph Bridge Inject (poison@1)   | Graph Entity Swap (poison@1)   | BlackBox Category (poison@1)   | BlackBox Topic+Entity (poison@1)   | Pure Topological (poison@1)   | Max GT displaced@5   | Stratum Status             |
|-----------------|------------------|---------------|-----------------------------|-----------------------------|--------------------------------|--------------------------|----------------------------------|--------------------------------|--------------------------------|------------------------------------|-------------------------------|----------------------|----------------------------|
| Sparse-BM25     | 100.0%           | 50/50         | 100.0%                      | 100.0%                      | 100.0%                         | 100.0%                   | 100.0%                           | 0.0%                           | 0.0%                           | 0.0%                               | 0.0%                          | 2.0%                 | VIABLE                     |
| Dense-FAISS     | 0.0%             | 0/50          | 14.0%                       | 0.0%                        | 100.0%                         | 0.0%                     | 0.0%                             | 0.0%                           | 0.0%                           | 0.0%                               | 0.0%                          | -                    | NON_VIABLE (<50% Recall@5) |
| Hybrid-Reranker | 100.0%           | 50/50         | 0.0%                        | 0.0%                        | 100.0%                         | 0.0%                     | 0.0%                             | 0.0%                           | 0.0%                           | 0.0%                               | 0.0%                          | 2.0%                 | VIABLE                     |
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
| Sparse-BM25     | 4.3%             | 4/50          | 82.0%                       | 88.0%                       | 100.0%                         | 90.0%                    | 88.0%                            | 2.0%                           | 24.0%                          | 34.0%                              | 0.0%                          | 25.0%                | NON_VIABLE (<50% Recall@5) |
| Dense-FAISS     | 7.3%             | 6/50          | 42.0%                       | 14.0%                       | 100.0%                         | 36.0%                    | 2.0%                             | 0.0%                           | 36.0%                          | 32.0%                              | 0.0%                          | 33.3%                | NON_VIABLE (<50% Recall@5) |
| Hybrid-Reranker | 4.7%             | 4/50          | 10.0%                       | 28.0%                       | 100.0%                         | 24.0%                    | 90.0%                            | 0.0%                           | 0.0%                           | 6.0%                               | 0.0%                          | 0.0%                 | NON_VIABLE (<50% Recall@5) |
| GraphRAG        | 67.3%            | 36/50         | 20.0%                       | 20.0%                       | 20.0%                          | 20.0%                    | 100.0%                           | 2.0%                           | 0.0%                           | 2.0%                               | 0.0%                          | 11.1%                | VIABLE                     |

---

## 2.3 Krzywe Ataku (Attack Budget Curves)

Wpływ budżetu atakującego (liczby wstrzykniętych dokumentów per zapytanie $B$) na szansę przejęcia top-1 kontekstu:
* **Reżim sub-saturacji ($B \le 2$ przy oknie $k=5$):** Liczba wstrzykniętych ładunków zatrutych nie przekracza połowy okna kontekstowego wyszukiwania ($k=5$). Pozwala to zbadać naturalną selektywność silnika i zdolność do zachowania czystego dokumentu Ground Truth.
* **Reżim stress-testu saturacyjnego ($B \ge 3$ przy oknie $k=5$):** Większość okna kontekstowego ($>50\%$) może zostać zdominowana przez ładunki zatrute, testując odporność w warunkach bezpośredniej presji ilościowej.

W protokole izolowanym (Recommendation 3) krzywe budżetowe odzwierciedlają wrażliwość na liczbę wstrzykniętych wariantów ładunku ($B \in \{1, 2, 3, 5\}$) bez efektu saturacji okna obcymi zatruciami. W **21 z 36** kombinacji silnik × wektor decyzje per-zapytanie są identyczne przy B=1 i B=5 - w tych komórkach wzrost budżetu nie zmienia niczego, a krzywa jest płaska z powodu nasycenia, nie z powodu odporności silnika.

| RAG Engine      | Attack Vector     | Budget=1 (ASR@1)   | Budget=2 (ASR@1)   | Budget=3 (ASR@1)   | Budget=5 (ASR@1)   |
|-----------------|-------------------|--------------------|--------------------|--------------------|--------------------|
| Sparse-BM25     | SPARSE            | 64.0%              | 62.7%              | 65.3%              | 70.0%              |
| Sparse-BM25     | DENSE             | 62.7%              | 62.7%              | 65.3%              | 65.3%              |
| Sparse-BM25     | DENSE_ECHO        | 79.3%              | 79.3%              | 79.3%              | 79.3%              |
| Sparse-BM25     | HYBRID            | 63.3%              | 63.3%              | 63.3%              | 63.3%              |
| Sparse-BM25     | GRAPH             | 62.7%              | 62.7%              | 62.0%              | 61.3%              |
| Sparse-BM25     | ENTITY_SWAP       | 0.7%               | 0.7%               | 0.7%               | 0.7%               |
| Sparse-BM25     | BLACKBOX_CATEGORY | 8.0%               | 8.0%               | 8.0%               | 8.0%               |
| Sparse-BM25     | BLACKBOX          | 11.3%              | 11.3%              | 11.3%              | 11.3%              |
| Sparse-BM25     | PURE_TOPOLOGICAL  | 0.0%               | 0.0%               | 0.0%               | 0.0%               |
| Dense-FAISS     | SPARSE            | 30.7%              | 30.7%              | 56.7%              | 56.7%              |
| Dense-FAISS     | DENSE             | 5.3%               | 6.0%               | 9.3%               | 9.3%               |
| Dense-FAISS     | DENSE_ECHO        | 98.7%              | 98.7%              | 99.3%              | 99.3%              |
| Dense-FAISS     | HYBRID            | 13.3%              | 13.3%              | 13.3%              | 13.3%              |
| Dense-FAISS     | GRAPH             | 0.7%               | 0.7%               | 0.7%               | 0.7%               |
| Dense-FAISS     | ENTITY_SWAP       | 0.0%               | 0.0%               | 0.0%               | 0.0%               |
| Dense-FAISS     | BLACKBOX_CATEGORY | 12.0%              | 12.0%              | 12.7%              | 14.0%              |
| Dense-FAISS     | BLACKBOX          | 10.7%              | 10.7%              | 10.7%              | 10.7%              |
| Dense-FAISS     | PURE_TOPOLOGICAL  | 0.0%               | 0.0%               | 0.0%               | 0.0%               |
| Hybrid-Reranker | SPARSE            | 6.0%               | 7.3%               | 8.7%               | 19.3%              |
| Hybrid-Reranker | DENSE             | 9.3%               | 18.7%              | 28.7%              | 30.0%              |
| Hybrid-Reranker | DENSE_ECHO        | 100.0%             | 100.0%             | 100.0%             | 100.0%             |
| Hybrid-Reranker | HYBRID            | 8.0%               | 8.7%               | 13.3%              | 18.0%              |
| Hybrid-Reranker | GRAPH             | 30.0%              | 30.0%              | 30.0%              | 30.0%              |
| Hybrid-Reranker | ENTITY_SWAP       | 0.0%               | 0.0%               | 0.0%               | 0.0%               |
| Hybrid-Reranker | BLACKBOX_CATEGORY | 0.0%               | 0.0%               | 0.0%               | 0.0%               |
| Hybrid-Reranker | BLACKBOX          | 2.0%               | 2.0%               | 2.0%               | 8.7%               |
| Hybrid-Reranker | PURE_TOPOLOGICAL  | 0.0%               | 0.0%               | 0.0%               | 0.0%               |
| GraphRAG        | SPARSE            | 40.0%              | 40.0%              | 40.0%              | 40.0%              |
| GraphRAG        | DENSE             | 40.0%              | 40.0%              | 40.0%              | 40.0%              |
| GraphRAG        | DENSE_ECHO        | 40.0%              | 40.0%              | 40.0%              | 40.0%              |
| GraphRAG        | HYBRID            | 40.0%              | 40.0%              | 40.0%              | 40.0%              |
| GraphRAG        | GRAPH             | 100.0%             | 98.7%              | 98.7%              | 88.0%              |
| GraphRAG        | ENTITY_SWAP       | 33.3%              | 32.7%              | 30.0%              | 30.0%              |
| GraphRAG        | BLACKBOX_CATEGORY | 0.0%               | 0.0%               | 0.0%               | 0.0%               |
| GraphRAG        | BLACKBOX          | 18.7%              | 10.0%              | 8.7%               | 8.7%               |
| GraphRAG        | PURE_TOPOLOGICAL  | 18.0%              | 10.0%              | 8.7%               | 6.0%               |

---

## 2.4 Latencja Wyszukiwania (Clean Baseline)

Pomiar zegarem monotonicznym `time.perf_counter()`; podano medianę i rozstęp ćwiartkowy po odrzuceniu pierwszego zapytania scenariusza. **Uwaga:** w protokole izolowanym każdy pomiar zawiera również przebudowę indeksu dla danego zapytania, więc są to czasy end-to-end tego protokołu, a nie czysty czas wyszukiwania w indeksie utrzymywanym na stałe.

| RAG Engine      |   Mediana (ms) |   IQR (ms) |   Średnia (ms) |
|-----------------|----------------|------------|----------------|
| Sparse-BM25     |           30.8 |       55.1 |           50.5 |
| Dense-FAISS     |           18   |        3.7 |           19.2 |
| Hybrid-Reranker |          289.4 |      164.4 |          290.6 |
| GraphRAG        |           68   |        5.4 |           69   |

---

## 3. Empiryczny Ranking Odporności Architektur (Wyliczony Algorytmicznie)

*Zakres obowiązywania rankingu: wartości uśredniono **wyłącznie po stratach, na których dany silnik osiąga Clean Recall@5 ≥ 50%** (kolumna „Strata wyłączone" podaje, co odpadło) oraz **wyłącznie po ramieniu referencyjnym**; ramię query-echo, jako test skrajny, ma własną kolumnę i nie wchodzi do średniej. Sam podział zbioru zapytań (po ~1/3 na stratum) pozostaje arbitralny, więc ranking jest kompozytem poglądowym — rozstrzygające są tabele stratyfikacji w Sekcji 2.2.*

| Rank   | Engine          | Status Pareto (Recall >= 50%)   | Clean Recall@5 Bazowy (Wyższy=Lepszy)   | Średni poison@1, ramię referencyjne (Niższy=Lepszy)   | Średni targeted poison@5, ramię referencyjne (Niższy=Lepszy)   | poison@1, ramię echo (górne ograniczenie)   | Strata wyłączone (poniżej progu)                         |
|--------|-----------------|---------------------------------|-----------------------------------------|-------------------------------------------------------|----------------------------------------------------------------|---------------------------------------------|----------------------------------------------------------|
| #1     | Hybrid-Reranker | VIABLE (Pareto Optimal)         | 68.2%                                   | 0.7%                                                  | 16.6%                                                          | 100.0%                                      | ATT&CK Relational (graf)                                 |
| #2     | Sparse-BM25     | VIABLE                          | 68.1%                                   | 25.7%                                                 | 45.5%                                                          | 69.0%                                       | ATT&CK Relational (graf)                                 |
| #3     | GraphRAG        | VIABLE                          | 55.8%                                   | 15.8%                                                 | 68.9%                                                          | 10.0%                                       | CVE Descriptive (bez ID)                                 |
| #4     | Dense-FAISS     | NON_VIABLE                      | 34.4%                                   | 5.9%                                                  | 23.0%                                                          | 97.0%                                       | ATT&CK Relational (graf), CVE Exact-Match (ID w pytaniu) |

---

## 3.1 Statistical Significance of Pairwise Architecture Differences (McNemar's Test)

Pairwise McNemar comparisons are limited to scenarios sharing the same attack vector or baseline condition.

Rodzina testów: **75** po zwinięciu **36** replikatów budżetowych o identycznych wektorach wyników per zapytanie. Replikaty zwinięto, bo cztery wiersze opisujące ten sam wynik liczyłyby jedno ustalenie czterokrotnie i sztucznie zaostrzały korektę Holma. Hipoteza zerowa jest międzysilnikowa: test porównuje `poison@1` dwóch silników o różnej użyteczności bazowej, więc odrzucenie H0 oznacza różnicę w łącznym efekcie „kompetencja wyszukiwania + odporność", a nie w samej odporności. Silniki diagnostyczne są z testów wyłączone.

| Condition                        | Budżety (identyczne wyniki)   | Engine A        | Engine B        | Discordant (b, c)   | Test Variant            | Statistic   | Raw p-value   | Holm-Bonf p-value   | Significant?   |
|----------------------------------|-------------------------------|-----------------|-----------------|---------------------|-------------------------|-------------|---------------|---------------------|----------------|
| GRAPH (Retr ASR@1)               | B=1                           | Hybrid-Reranker | GraphRAG        | (0, 105)            | Asymptotic Chi² (CC)    | χ² = 103.01 | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| GRAPH (Retr ASR@1)               | B=2, B=3                      | Hybrid-Reranker | GraphRAG        | (2, 105)            | Asymptotic Chi² (CC)    | χ² = 97.23  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE_ECHO (Retr ASR@1)          | B=1, B=2, B=3, B=5            | Hybrid-Reranker | GraphRAG        | (90, 0)             | Asymptotic Chi² (CC)    | χ² = 88.01  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| HYBRID (Retr ASR@1)              | B=1                           | Sparse-BM25     | Hybrid-Reranker | (83, 0)             | Asymptotic Chi² (CC)    | χ² = 81.01  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| HYBRID (Retr ASR@1)              | B=2                           | Sparse-BM25     | Hybrid-Reranker | (82, 0)             | Asymptotic Chi² (CC)    | χ² = 80.01  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| SPARSE (Retr ASR@1)              | B=1                           | Sparse-BM25     | Hybrid-Reranker | (90, 3)             | Asymptotic Chi² (CC)    | χ² = 79.53  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE (Retr ASR@1)               | B=1                           | Sparse-BM25     | Hybrid-Reranker | (80, 0)             | Asymptotic Chi² (CC)    | χ² = 78.01  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| SPARSE (Retr ASR@1)              | B=3                           | Sparse-BM25     | Hybrid-Reranker | (89, 4)             | Asymptotic Chi² (CC)    | χ² = 75.87  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| SPARSE (Retr ASR@1)              | B=2                           | Sparse-BM25     | Hybrid-Reranker | (87, 4)             | Asymptotic Chi² (CC)    | χ² = 73.89  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| HYBRID (Retr ASR@1)              | B=3                           | Sparse-BM25     | Hybrid-Reranker | (75, 0)             | Asymptotic Chi² (CC)    | χ² = 73.01  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| SPARSE (Retr ASR@1)              | B=5                           | Sparse-BM25     | Hybrid-Reranker | (80, 4)             | Asymptotic Chi² (CC)    | χ² = 66.96  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| HYBRID (Retr ASR@1)              | B=5                           | Sparse-BM25     | Hybrid-Reranker | (68, 0)             | Asymptotic Chi² (CC)    | χ² = 66.01  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE (Retr ASR@1)               | B=2                           | Sparse-BM25     | Hybrid-Reranker | (66, 0)             | Asymptotic Chi² (CC)    | χ² = 64.02  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| GRAPH (Retr ASR@1)               | B=5                           | Hybrid-Reranker | GraphRAG        | (15, 102)           | Asymptotic Chi² (CC)    | χ² = 63.21  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| GRAPH (Retr ASR@1)               | B=1                           | Sparse-BM25     | GraphRAG        | (0, 56)             | Asymptotic Chi² (CC)    | χ² = 54.02  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE (Retr ASR@1)               | B=3                           | Sparse-BM25     | Hybrid-Reranker | (57, 2)             | Asymptotic Chi² (CC)    | χ² = 49.42  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| GRAPH (Retr ASR@1)               | B=3                           | Sparse-BM25     | GraphRAG        | (2, 57)             | Asymptotic Chi² (CC)    | χ² = 49.42  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| GRAPH (Retr ASR@1)               | B=2                           | Sparse-BM25     | GraphRAG        | (2, 56)             | Asymptotic Chi² (CC)    | χ² = 48.43  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (Retr ASR@1)         | B=1                           | Hybrid-Reranker | GraphRAG        | (0, 50)             | Asymptotic Chi² (CC)    | χ² = 48.02  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE (Retr ASR@1)               | B=5                           | Sparse-BM25     | Hybrid-Reranker | (55, 2)             | Asymptotic Chi² (CC)    | χ² = 47.44  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (Retr ASR@1)         | B=2                           | Hybrid-Reranker | GraphRAG        | (0, 49)             | Asymptotic Chi² (CC)    | χ² = 47.02  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (Retr ASR@1)         | B=1                           | Sparse-BM25     | GraphRAG        | (1, 50)             | Asymptotic Chi² (CC)    | χ² = 45.18  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (Retr ASR@1)         | B=2                           | Sparse-BM25     | GraphRAG        | (1, 49)             | Asymptotic Chi² (CC)    | χ² = 44.18  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (Retr ASR@1)         | B=3, B=5                      | Hybrid-Reranker | GraphRAG        | (0, 45)             | Asymptotic Chi² (CC)    | χ² = 43.02  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| SPARSE (Retr ASR@1)              | B=1                           | Hybrid-Reranker | GraphRAG        | (4, 55)             | Asymptotic Chi² (CC)    | χ² = 42.37  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| GRAPH (Retr ASR@1)               | B=1, B=2                      | Sparse-BM25     | Hybrid-Reranker | (53, 4)             | Asymptotic Chi² (CC)    | χ² = 40.42  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| ENTITY_SWAP (Retr ASR@1)         | B=3, B=5                      | Sparse-BM25     | GraphRAG        | (1, 45)             | Asymptotic Chi² (CC)    | χ² = 40.20  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| GRAPH (Retr ASR@1)               | B=3                           | Sparse-BM25     | Hybrid-Reranker | (52, 4)             | Asymptotic Chi² (CC)    | χ² = 39.45  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| SPARSE (Retr ASR@1)              | B=2                           | Hybrid-Reranker | GraphRAG        | (5, 54)             | Asymptotic Chi² (CC)    | χ² = 39.05  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| GRAPH (Retr ASR@1)               | B=5                           | Sparse-BM25     | Hybrid-Reranker | (52, 5)             | Asymptotic Chi² (CC)    | χ² = 37.12  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| SPARSE (Retr ASR@1)              | B=3                           | Hybrid-Reranker | GraphRAG        | (6, 53)             | Asymptotic Chi² (CC)    | χ² = 35.86  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| HYBRID (Retr ASR@1)              | B=1                           | Hybrid-Reranker | GraphRAG        | (8, 56)             | Asymptotic Chi² (CC)    | χ² = 34.52  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| HYBRID (Retr ASR@1)              | B=2                           | Hybrid-Reranker | GraphRAG        | (9, 56)             | Asymptotic Chi² (CC)    | χ² = 32.55  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE_ECHO (Retr ASR@1)          | B=1, B=2, B=3, B=5            | Sparse-BM25     | Hybrid-Reranker | (0, 31)             | Asymptotic Chi² (CC)    | χ² = 29.03  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE (Retr ASR@1)               | B=1                           | Hybrid-Reranker | GraphRAG        | (12, 58)            | Asymptotic Chi² (CC)    | χ² = 28.93  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| DENSE_ECHO (Retr ASR@1)          | B=1, B=2, B=3, B=5            | Sparse-BM25     | GraphRAG        | (90, 31)            | Asymptotic Chi² (CC)    | χ² = 27.80  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (Retr ASR@1)    | B=1                           | Sparse-BM25     | GraphRAG        | (0, 27)             | Asymptotic Chi² (CC)    | χ² = 25.04  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (Retr ASR@1)    | B=1                           | Hybrid-Reranker | GraphRAG        | (0, 27)             | Asymptotic Chi² (CC)    | χ² = 25.04  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| GRAPH (Retr ASR@1)               | B=5                           | Sparse-BM25     | GraphRAG        | (12, 52)            | Asymptotic Chi² (CC)    | χ² = 23.77  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| HYBRID (Retr ASR@1)              | B=3                           | Hybrid-Reranker | GraphRAG        | (13, 53)            | Asymptotic Chi² (CC)    | χ² = 23.05  | < 0.0001      | < 0.0001            | Yes (p<0.05)   |
| BLACKBOX (Retr ASR@1)            | B=1                           | Hybrid-Reranker | GraphRAG        | (3, 28)             | Asymptotic Chi² (CC)    | χ² = 18.58  | < 0.0001      | 0.0006              | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (Retr ASR@1)    | B=2                           | Sparse-BM25     | GraphRAG        | (0, 15)             | Exact Binomial          | |b-c| = 15  | < 0.0001      | 0.0021              | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (Retr ASR@1)    | B=2                           | Hybrid-Reranker | GraphRAG        | (0, 15)             | Exact Binomial          | |b-c| = 15  | < 0.0001      | 0.0021              | Yes (p<0.05)   |
| HYBRID (Retr ASR@1)              | B=5                           | Hybrid-Reranker | GraphRAG        | (17, 50)            | Asymptotic Chi² (CC)    | χ² = 15.28  | < 0.0001      | 0.0030              | Yes (p<0.05)   |
| SPARSE (Retr ASR@1)              | B=5                           | Sparse-BM25     | GraphRAG        | (88, 43)            | Asymptotic Chi² (CC)    | χ² = 14.78  | 0.0001        | 0.0037              | Yes (p<0.05)   |
| SPARSE (Retr ASR@1)              | B=5                           | Hybrid-Reranker | GraphRAG        | (15, 46)            | Asymptotic Chi² (CC)    | χ² = 14.75  | 0.0001        | 0.0037              | Yes (p<0.05)   |
| DENSE (Retr ASR@1)               | B=2                           | Hybrid-Reranker | GraphRAG        | (19, 51)            | Asymptotic Chi² (CC)    | χ² = 13.73  | 0.0002        | 0.0061              | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (Retr ASR@1)    | B=3                           | Sparse-BM25     | GraphRAG        | (0, 13)             | Exact Binomial          | |b-c| = 13  | 0.0002        | 0.0068              | Yes (p<0.05)   |
| PURE_TOPOLOGICAL (Retr ASR@1)    | B=3                           | Hybrid-Reranker | GraphRAG        | (0, 13)             | Exact Binomial          | |b-c| = 13  | 0.0002        | 0.0068              | Yes (p<0.05)   |
| BLACKBOX_CATEGORY (Retr ASR@1)   | B=1, B=2, B=3, B=5            | Sparse-BM25     | Hybrid-Reranker | (12, 0)             | Exact Binomial          | |b-c| = 12  | 0.0005        | 0.0127              | Yes (p<0.05)   |
| BLACKBOX_CATEGORY (Retr ASR@1)   | B=1, B=2, B=3, B=5            | Sparse-BM25     | GraphRAG        | (12, 0)             | Exact Binomial          | |b-c| = 12  | 0.0005        | 0.0127              | Yes (p<0.05)   |
| SPARSE (Retr ASR@1)              | B=3                           | Sparse-BM25     | GraphRAG        | (81, 43)            | Asymptotic Chi² (CC)    | χ² = 11.04  | 0.0009        | 0.0214              | Yes (p<0.05)   |
| BLACKBOX (Retr ASR@1)            | B=1, B=2, B=3                 | Sparse-BM25     | Hybrid-Reranker | (16, 2)             | Exact Binomial          | |b-c| = 14  | 0.0013        | 0.0302              | Yes (p<0.05)   |
| DENSE (Retr ASR@1)               | B=3, B=5                      | Sparse-BM25     | GraphRAG        | (88, 50)            | Asymptotic Chi² (CC)    | χ² = 9.92   | 0.0016        | 0.0360              | Yes (p<0.05)   |
| SPARSE (Retr ASR@1)              | B=1                           | Sparse-BM25     | GraphRAG        | (81, 45)            | Asymptotic Chi² (CC)    | χ² = 9.72   | 0.0018        | 0.0382              | Yes (p<0.05)   |
| HYBRID (Retr ASR@1)              | B=1, B=2, B=3, B=5            | Sparse-BM25     | GraphRAG        | (85, 50)            | Asymptotic Chi² (CC)    | χ² = 8.56   | 0.0034        | 0.0686              | No             |
| SPARSE (Retr ASR@1)              | B=2                           | Sparse-BM25     | GraphRAG        | (81, 47)            | Asymptotic Chi² (CC)    | χ² = 8.51   | 0.0035        | 0.0686              | No             |
| PURE_TOPOLOGICAL (Retr ASR@1)    | B=5                           | Sparse-BM25     | GraphRAG        | (0, 9)              | Exact Binomial          | |b-c| = 9   | 0.0039        | 0.0703              | No             |
| PURE_TOPOLOGICAL (Retr ASR@1)    | B=5                           | Hybrid-Reranker | GraphRAG        | (0, 9)              | Exact Binomial          | |b-c| = 9   | 0.0039        | 0.0703              | No             |
| DENSE (Retr ASR@1)               | B=1, B=2                      | Sparse-BM25     | GraphRAG        | (84, 50)            | Asymptotic Chi² (CC)    | χ² = 8.13   | 0.0044        | 0.0703              | No             |
| BLACKBOX (Retr ASR@1)            | B=2                           | Hybrid-Reranker | GraphRAG        | (3, 15)             | Exact Binomial          | |b-c| = 12  | 0.0075        | 0.1131              | No             |
| BLACKBOX (Retr ASR@1)            | B=3                           | Hybrid-Reranker | GraphRAG        | (3, 13)             | Exact Binomial          | |b-c| = 10  | 0.0213        | 0.2978              | No             |
| CLEAN_BASELINE (GT Recall@5 Hit) | -                             | Sparse-BM25     | GraphRAG        | (51, 33)            | Asymptotic Chi² (CC)    | χ² = 3.44   | 0.0636        | 0.8270              | No             |
| CLEAN_BASELINE (GT Recall@5 Hit) | -                             | Hybrid-Reranker | GraphRAG        | (51, 33)            | Asymptotic Chi² (CC)    | χ² = 3.44   | 0.0636        | 0.8270              | No             |
| DENSE (Retr ASR@1)               | B=3                           | Hybrid-Reranker | GraphRAG        | (32, 49)            | Asymptotic Chi² (CC)    | χ² = 3.16   | 0.0754        | 0.8298              | No             |
| DENSE (Retr ASR@1)               | B=5                           | Hybrid-Reranker | GraphRAG        | (34, 49)            | Asymptotic Chi² (CC)    | χ² = 2.36   | 0.1244        | 1.0000              | No             |
| BLACKBOX (Retr ASR@1)            | B=1                           | Sparse-BM25     | GraphRAG        | (17, 28)            | Asymptotic Chi² (CC)    | χ² = 2.22   | 0.1360        | 1.0000              | No             |
| BLACKBOX (Retr ASR@1)            | B=5                           | Sparse-BM25     | Hybrid-Reranker | (6, 2)              | Exact Binomial          | |b-c| = 4   | 0.2891        | 1.0000              | No             |
| BLACKBOX (Retr ASR@1)            | B=3, B=5                      | Sparse-BM25     | GraphRAG        | (17, 13)            | Asymptotic Chi² (CC)    | χ² = 0.30   | 0.5839        | 1.0000              | No             |
| BLACKBOX (Retr ASR@1)            | B=5                           | Hybrid-Reranker | GraphRAG        | (13, 13)            | Asymptotic Chi² (CC)    | χ² = 0.04   | 0.8445        | 1.0000              | No             |
| BLACKBOX (Retr ASR@1)            | B=2                           | Sparse-BM25     | GraphRAG        | (17, 15)            | Asymptotic Chi² (CC)    | χ² = 0.03   | 0.8597        | 1.0000              | No             |
| CLEAN_BASELINE (GT Recall@5 Hit) | -                             | Sparse-BM25     | Hybrid-Reranker | (1, 1)              | Exact Binomial          | |b-c| = 0   | 1.0000        | 1.0000              | No             |
| ENTITY_SWAP (Retr ASR@1)         | B=1, B=2, B=3, B=5            | Sparse-BM25     | Hybrid-Reranker | (1, 0)              | Exact Binomial          | |b-c| = 1   | 1.0000        | 1.0000              | No             |
| BLACKBOX_CATEGORY (Retr ASR@1)   | B=1, B=2, B=3, B=5            | Hybrid-Reranker | GraphRAG        | (0, 0)              | Brak niezgodności (n=0) | 0.00        | 1.0000        | 1.0000              | No             |
| PURE_TOPOLOGICAL (Retr ASR@1)    | B=1, B=2, B=3, B=5            | Sparse-BM25     | Hybrid-Reranker | (0, 0)              | Brak niezgodności (n=0) | 0.00        | 1.0000        | 1.0000              | No             |

---

## 4. Skuteczność Wektorów Ataków (Attack Vector Efficacy)

Uśrednione po silnikach nie-diagnostycznych i po stratach użytecznych każdego z nich. Tabela jest **uporządkowana według `GT displaced@5`**, czyli według tego, czy atak faktycznie usunął odpowiedź z okna kontekstowego; `poison@1` podano obok jako wielkość pomocniczą. Kolumna `Silniki (n)` podaje, ilu silników dotyczy średnia — jest to liczba jednocyfrowa, więc średnie te są orientacyjne.

**Wiersze w reżimie `B>=k` są wyłączone z porządkowania i zepchnięte na dół tabeli.** Przy budżecie równym rozmiarowi okna same ładunki wystarczą, by je zapełnić, więc wyparcie jest tam konsekwencją arytmetyki, a nie skuteczności ataku — mierzone na wspólnym wsparciu silników wyparcie skacze z ok. 2% przy B=3 do ok. 100% przy B=5, podczas gdy `poison@5` nie zmienia się wcale. Porównawcze twierdzenia o sile wektorów wolno opierać wyłącznie na wierszach sub-saturacyjnych.

| Attack Vector        | Avg GT displaced@5 (strata użyteczne)   | Avg poison@1 (strata użyteczne)   |   Silniki (n) | Reżim                 |
|----------------------|-----------------------------------------|-----------------------------------|---------------|-----------------------|
| GRAPH_B3             | 11.9%                                   | 49.3%                             |             3 | sub-saturacja         |
| GRAPH_B2             | 9.2%                                    | 49.3%                             |             3 | sub-saturacja         |
| DENSE_ECHO_B3        | 6.3%                                    | 59.7%                             |             3 | sub-saturacja         |
| SPARSE_B3            | 5.3%                                    | 24.0%                             |             3 | sub-saturacja         |
| DENSE_B3             | 5.3%                                    | 20.7%                             |             3 | sub-saturacja         |
| HYBRID_B3            | 5.3%                                    | 20.0%                             |             3 | sub-saturacja         |
| BLACKBOX_B3          | 4.5%                                    | 0.3%                              |             3 | sub-saturacja         |
| ENTITY_SWAP_B3       | 3.9%                                    | 0.3%                              |             3 | sub-saturacja         |
| DENSE_ECHO_B2        | 3.7%                                    | 59.7%                             |             3 | sub-saturacja         |
| ENTITY_SWAP_B2       | 3.5%                                    | 0.3%                              |             3 | sub-saturacja         |
| SPARSE_B2            | 3.4%                                    | 22.3%                             |             3 | sub-saturacja         |
| DENSE_B2             | 3.4%                                    | 20.0%                             |             3 | sub-saturacja         |
| HYBRID_B2            | 3.4%                                    | 20.0%                             |             3 | sub-saturacja         |
| BLACKBOX_B2          | 3.4%                                    | 0.3%                              |             3 | sub-saturacja         |
| GRAPH_B1             | 2.2%                                    | 50.0%                             |             3 | sub-saturacja         |
| DENSE_ECHO_B1        | 1.1%                                    | 59.7%                             |             3 | sub-saturacja         |
| SPARSE_B1            | 1.1%                                    | 23.0%                             |             3 | sub-saturacja         |
| DENSE_B1             | 1.1%                                    | 20.0%                             |             3 | sub-saturacja         |
| HYBRID_B1            | 1.1%                                    | 20.0%                             |             3 | sub-saturacja         |
| BLACKBOX_B1          | 1.1%                                    | 0.3%                              |             3 | sub-saturacja         |
| ENTITY_SWAP_B1       | 0.4%                                    | 0.3%                              |             3 | sub-saturacja         |
| PURE_TOPOLOGICAL_B2  | 0.4%                                    | 0.0%                              |             3 | sub-saturacja         |
| PURE_TOPOLOGICAL_B3  | 0.4%                                    | 0.0%                              |             3 | sub-saturacja         |
| BLACKBOX_CATEGORY_B1 | 0.0%                                    | 0.0%                              |             3 | sub-saturacja         |
| BLACKBOX_CATEGORY_B2 | 0.0%                                    | 0.0%                              |             3 | sub-saturacja         |
| BLACKBOX_CATEGORY_B3 | 0.0%                                    | 0.0%                              |             3 | sub-saturacja         |
| PURE_TOPOLOGICAL_B1  | 0.0%                                    | 0.0%                              |             3 | sub-saturacja         |
| GRAPH_B5             | 66.7%                                   | 44.0%                             |             3 | B>=k: arytmetyka okna |
| DENSE_ECHO_B5        | 62.1%                                   | 59.7%                             |             3 | B>=k: arytmetyka okna |
| HYBRID_B5            | 38.8%                                   | 20.0%                             |             3 | B>=k: arytmetyka okna |
| DENSE_B5             | 36.8%                                   | 20.7%                             |             3 | B>=k: arytmetyka okna |
| SPARSE_B5            | 24.8%                                   | 24.0%                             |             3 | B>=k: arytmetyka okna |
| BLACKBOX_B5          | 4.5%                                    | 0.3%                              |             3 | B>=k: arytmetyka okna |
| ENTITY_SWAP_B5       | 3.9%                                    | 0.3%                              |             3 | B>=k: arytmetyka okna |
| PURE_TOPOLOGICAL_B5  | 0.8%                                    | 0.0%                              |             3 | B>=k: arytmetyka okna |
| BLACKBOX_CATEGORY_B5 | 0.0%                                    | 0.0%                              |             3 | B>=k: arytmetyka okna |

---

## 5. Kluczowe Obserwacje i Wnioski Naukowe

1. **Analiza Użyteczności i Frontu Pareto:** Zgodnie z bezwzględnym progiem użyteczności bazowej (Clean Recall@5 >= 50% mierzonym wyłącznie na czystym korpusie), architekturami spełniającymi kryterium użyteczności w domenie CTI są: **`Hybrid-Reranker`**, **`Sparse-BM25`**, **`GraphRAG`**. Na niezdominowanym froncie Pareto w przestrzeni (Clean Recall bazowy ↑ vs średni targeted poison@5 na ramieniu referencyjnym i stratach użytecznych ↓) plasują się: **`Hybrid-Reranker`**. Pozostałe silniki (Dense-FAISS (34.4%)) zostały sklasyfikowane jako `NON_VIABLE`.
2. **Użyteczność GraphRAG:** Po eliminacji błędu kolizji przestrzeni nazw (`doc:` vs `ent:`) GraphRAG osiąga Clean Recall@5 = **55.8%** oraz MRR = **0.42** (CVE Exact-Match (ID w pytaniu): 100.0%; CVE Descriptive (bez ID): 0.0%; ATT&CK Relational (graf): 67.3%).
3. **Profil Odporności GraphRAG (leksykalny vs strukturalny), w rozbiciu na strata użyteczne:**
   * **Keyword stuffing:** na stratach, na których GraphRAG ma użyteczność bazową, ładunek leksykalny zajmuje pozycję 1 w **10.0%** zapytań — niżej niż średnia pozostałych silników użytecznych (**29.5%**). Wartość nieograniczona do strat użytecznych wynosi 40.0% i jest zawyżona przez stratum o zerowym Recall bazowym. Uwaga: 68 zapytań rozstrzygnięto remisem na pozycji 1, więc wartość nieograniczona mieści się w przedziale **33.3%–78.7%** zależnie od kierunku rozstrzygnięcia remisu (patrz Sekcja 6).
   * **Atak topologiczny przy `bridge_count=40`:** poison@1 zagregowane = **18.0%**, ale w rozbiciu stratyfikacyjnym: CVE Exact-Match (ID w pytaniu): 0.0%; CVE Descriptive (bez ID): 54.0%; ATT&CK Relational (graf): 0.0%. Na stratach użytecznych poison@1 = **0.0%**. `poison@1 cond` = **0.0%**, `GT displaced@5` = **0.0%** (n=86). Zgodnie z regułą z Obserwacji 4 tezę o skuteczności ataku niosą te dwie ostatnie wielkości, więc **dane nie wykazują przejęcia GraphRAG przez atak czysto topologiczny na zapytaniach, na które ten silnik w ogóle odpowiada**. Wynik zależy od parametru `bridge_count` ataku, nie jest własnością architektury — patrz sweep progowy (`scripts/run_bridge_sweep.py`, `bridge_sweep_report.md`).
4. **Pozycja Ładunku a Wyparcie Odpowiedzi:** Uśredniając po scenariuszach ataku, silnikach użytecznych i stratach, na których dany silnik ma użyteczność bazową, ładunek zajmuje pozycję 1 w **19.1%** zapytań, ale odpowiedź znika z całego okna top-5 tylko w **8.9%** zapytań, dla których czysty silnik wcześniej ją znajdował. Te dwie liczby mierzą co innego: pierwsza mówi, gdzie w rankingu wylądował ładunek, druga — czy atak faktycznie usunął odpowiedź z kontekstu. **Wniosek o skuteczności ataku wolno opierać wyłącznie na drugiej**, i ta sama reguła obowiązuje w Obserwacji 3 i w Sekcji 4. Dla porównania: bez ograniczenia do strat użytecznych ta sama średnia poison@1 wynosi 31.2%, czyli różnica +12.1% pochodzi wyłącznie ze strat, na których silnik i tak nie znajdował odpowiedzi.
5. **Weryfikacja Protokołu Izolowanego (Recommendation 3) i Wrażliwości Budżetowej:** Eksperyment przeprowadzono w reżimie izolacji per zapytanie. Zerowe zanieczyszczenie obcymi ładunkami jest w tym protokole gwarantowane konstrukcyjnie, więc stanowi asercję poprawności implementacji, a nie wynik empiryczny. Krzywe budżetowe $B \in \{1, 2, 3, 5\}$ zmierzono pod kątem nasycenia. W **21 z 36** kombinacji silnik × wektor decyzje per-zapytanie są identyczne przy B=1 i B=5 - w tych komórkach wzrost budżetu nie zmienia niczego, a krzywa jest płaska z powodu nasycenia, nie z powodu odporności silnika.
6. **Silniki Poniżej Progu Użyteczności (wyniki diagnostyczne):** **`Dense-FAISS`** (Clean Recall@5 = 34.4%; CVE Exact-Match (ID w pytaniu): 0.0%, CVE Descriptive (bez ID): 96.0%, ATT&CK Relational (graf): 7.3%; 351 unikalnych dokumentów w 750 slotach top-k). Silnik zwracający niemal stałą listę niezwiązanych dokumentów ma wskaźniki `poison@1` opisujące zdegenerowany ranking, a nie odporność, dlatego jest wyłączony z międzysilnikowych średnich (Sekcja 4) i z testów istotności (Sekcja 3.1). Ta sama reguła jest stosowana per stratum, nie tylko per silnik (Sekcja 3, kolumna „Strata wyłączone"). Obserwacja domenowa: dla zapytań o identyfikatory CVE mały bi-encoder (`BAAI/bge-small-en-v1.5`) nie rozróżnia unikalnych numerów. **To jednak nie jest rozstrzygnięty wniosek o modelu:** dokumenty CVE są w tym korpusie budowane z jednego szablonu (`real_cti_loader.py`), więc hipoteza „bi-encoder nie koduje identyfikatorów" jest tu nieodróżnialna od hipotezy „jednorodny szablon dominuje w embeddingu". Rozstrzygnięcie wymaga wariantu korpusu bez wspólnego prefiksu; do tego czasu jest to obserwacja, nie wyjaśnienie. Praktyczna rekomendacja (indeksowanie leksykalne lub hybrydowe dla lookupu po identyfikatorze) obowiązuje niezależnie od tego, która hipoteza jest prawdziwa.

---

## 6. Limitations and Threats to Validity

1. **Autentyczny Korpus CTI:** Baza wiedzy bazuje na realnych, zweryfikowanych zbiorach: oficjalnym feedzie STIX 2.1 MITRE ATT&CK Enterprise (20k+ relacji encji), CTIBench (NeurIPS 2024 Spotlight), CISA KEV oraz publikowanych rekordach cvelistV5. Zbiór zapytań Gold Standard posiada zweryfikowane etykiety CWE i relacje ATT&CK.
2. **White-Box Attack Oracle vs Weakest Tested Adversary:** The benchmark evaluates white-box targeted adversaries with query access and a category-level adversary that never touches a victim identifier. Note that the targeted adversaries are handed `key_terms`, which for the relational stratum contain the *names of the answer documents* (`real_query_loader.py` builds them as `[entity] + gold`). Their payloads therefore repeat the gold answer, which is a stronger oracle than "access to the query and the target assertion". `entity_swap` deliberately filters the gold answer out of its anchors, so part of the ASR gap between it and the lexical vectors is a difference in answer leakage, not only in attack construction.
2a. **No Defenses By Design:** No input filtering, deduplication, perplexity screening or index hygiene is enabled at any stage. This is a deliberate scope boundary, not an omission: every figure describes an undefended retrieval stage and is therefore an upper bound. Numbers here are not comparable to work that reports defended pipelines.
2b. **Retrieval-Stage Metrics:** `poison@1` and `poison@5` are payload-ranking measurements, not end-to-end attack success. `GT displaced@5` and `poison@1 cond` are the quantities that carry any claim about an attack "succeeding". Note that `poison@1 cond` is conditioned on each engine's *own* clean baseline, so its denominator differs per engine (Sparse-BM25: n=104, Dense-FAISS: n=54, Hybrid-Reranker: n=104, GraphRAG: n=86); the column compares rates computed on different subsets of queries and is not a like-for-like cross-engine comparison.
3. **GraphRAG Subgraph Traversal & Structural Attack Surface:** GraphRAG walks multi-hop subgraphs over STIX 2.1 networks. The purely topological attack reaches rank 1 on 18.0% of all queries at bridge_count=40, but that aggregate is carried by a stratum in which GraphRAG's own clean Recall@5 is below the utility floor. Restricted to the queries this engine actually answers, `poison@1 cond` = 0.0% and `GT displaced@5` = 0.0% (n=86). **This run therefore neither establishes nor refutes degree-normalization immunity**: `bridge_count` is a free parameter of the attack and the outcome is a function of where it sits relative to the crossover threshold n > 72 + sqrt(5184 + 144*deg0) (bridges have degree 3; the payload's score through one anchoring entity never exceeds 1/6). See `scripts/run_bridge_sweep.py` and `bridge_sweep_report.md`; any claim about GraphRAG's structural robustness has to cite the sweep, not a single point on it.
4. **Metrological Latency & Local Determinism:** Timing uses high-resolution monotonic `time.perf_counter()`, discarding the first query of each scenario, and is reported as median and IQR in Section 2.4. Retrieval is deterministic and the query and corpus samples are drawn with a fixed seed (42), so a re-run on this machine against the cached corpus reproduces every figure exactly.
5. **Evaluation Protocol & Context Isolation:** The benchmark was executed under the isolated per-query protocol (Recommendation 3), ensuring 0.0% foreign context contamination. All budget curves represent true marginal attack scaling.
6. **Nieoznaczoność remisów rankingowych (`poison@1` nie jest estymatorem punktowym dla silników remisujących):** silnik grafowy przypisuje wielu dokumentom identyczny wynik, a `sorted(key=(-score, doc_id))` rozstrzyga remis kolejnością identyfikatorów. Dla remisu przecinającego granicę poison/clean o wartości metryki decyduje więc porządek alfabetyczny (`POISON_…` vs `CVE-…`), a nie funkcja scoringu. Przedział Wilsona w Sekcji 2 obejmuje wyłącznie błąd próbkowania i **nie zawiera tej nieoznaczoności**; poniższa tabela podaje jej szerokość. Zakresy policzono na pełnych grupach remisowych: cała grupa na pozycji 1 oraz grupa na granicy pozycji 5 (przebieg z `--log-ties`).

| RAG Engine   | Najgorszy scenariusz   | poison@1 raportowane   | Zakres wg rozstrzygnięcia remisu   |   Zapytania z remisem |
|--------------|------------------------|------------------------|------------------------------------|-----------------------|
| GraphRAG     | BLACKBOX_B1            | 18.7%                  | 16.0%-64.0%                        |                    72 |

| RAG Engine   | Najgorszy scenariusz   | GT displaced@5 raportowane   | Zakres wg rozstrzygnięcia remisu   |
|--------------|------------------------|------------------------------|------------------------------------|
| Sparse-BM25  | SPARSE_B5              | 53.8%                        | 53.8%-54.8%                        |
| GraphRAG     | SPARSE_B5              | 16.3%                        | 14.0%-95.3%                        |
7. **Stałe sloty kontekstu (dokument obecny niezależnie od pytania, liczone w grupach jednego szablonu):** **Sparse-BM25** / CVE Exact-Match (ID w pytaniu) / szablon `RCM` (n=50): `CVE-2025-3385` w top-5 dla 100% pytań, nad złotym dokumentem w 3; **Sparse-BM25** / CVE Exact-Match (ID w pytaniu) / szablon `RCM` (n=50): `CVE-2024-27321` w top-5 dla 100% pytań, nad złotym dokumentem w 1; **Sparse-BM25** / CVE Exact-Match (ID w pytaniu) / szablon `RCM` (n=50): `CVE-2026-20158` w top-5 dla 100% pytań, nad złotym dokumentem w 1; **Sparse-BM25** / CVE Exact-Match (ID w pytaniu) / szablon `RCM` (n=50): `CVE-2026-2636` w top-5 dla 100% pytań, nad złotym dokumentem w 1; **Hybrid-Reranker** / CVE Exact-Match (ID w pytaniu) / szablon `RCM` (n=50): `CVE-2026-2636` w top-5 dla 100% pytań, nad złotym dokumentem w 20; **GraphRAG** / ATT&CK Relational (graf) / szablon `ATTR-MAL` (n=17): `T1587.001` w top-5 dla 100% pytań, nad złotym dokumentem w 17; **GraphRAG** / ATT&CK Relational (graf) / szablon `ATTR-MAL` (n=17): `T1588.001` w top-5 dla 100% pytań, nad złotym dokumentem w 17; ponadto 20 przypadków w parach silnik–stratum poniżej progu użyteczności (Dense-FAISS, Hybrid-Reranker, Sparse-BM25), wyłączonych z agregatów (pełna lista: `scripts/audit_checks.py`, check K4). Gdy pytania grupy mają wspólne wszystkie słowa poza identyfikatorem, sloty poza złotym dokumentem zajmują dokumenty najlepiej pasujące do tych wspólnych słów, a więc te same przy każdym pytaniu. Przy wyszukiwaniu po kluczu z jednym złotym dokumentem jest to cecha strukturalna, nie wada silnika. Pomiar zniekształca dopiero stały dokument **nad** złotym. W 7 z tych przypadków stały dokument wyprzedza złoty dokument w stratum użytecznym; tam atakujący potrzebuje o jeden ładunek mniej, by wypchnąć odpowiedź z okna top-5, a `GT displaced@5` jest zawyżone przez konstrukcję pytania, nie przez atak.
8. **Query-set construction (what the utility numbers actually measure):** The three strata are not equally hard, and two of the three are string-matching tasks. In the exact-match stratum the answer's own identifier appears verbatim in the question, making it a key lookup. In the descriptive stratum the question is a literal substring of the target document, making it near-duplicate matching. Only the relational stratum requires traversal, and its answer set is derived from the same STIX edges GraphRAG walks, so part of the graph engine's advantage there is built into the task. The relational query pool is additionally filtered to edges with at most 3 answer documents (`MAX_ANSWER_DOCS`), which removes the hardest attribution questions. Every baseline utility figure, and therefore the >= 50% viability floor and the Pareto front resting on it, should be read against these constructions rather than as general CTI retrieval quality.
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
| query_fingerprint_sha256_16     | 81d644fe435f03b8                                                                                                                                                        |
| query_set                       | v2                                                                                                                                                                      |
| reranker_model                  | cross-encoder/ms-marco-MiniLM-L-6-v2                                                                                                                                    |
| run_utc                         | 2026-09-27T12:38:02+00:00                                                                                                                                               |
| seed                            | 42                                                                                                                                                                      |
| top_k                           | 5                                                                                                                                                                       |

10. **Statistical reporting:** Wilson intervals are reported per row and are **not** corrected for the number of rows in Section 2; they describe sampling error over the query sample for that one cell, and should be read descriptively rather than as simultaneous coverage. Only the McNemar family in Section 3.1 carries a multiplicity correction (Holm-Bonferroni). All intervals cover sampling error only, never the tie indeterminacy in item 6 or the attack-parameter dependence in item 3.
