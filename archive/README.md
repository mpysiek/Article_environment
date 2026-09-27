# Archiwum

Materiał **nieużywany przez bieżący przebieg badania**, odłożony tutaj zamiast usuwania.
Nic w tym katalogu nie jest importowane ani wywoływane przez kod w `src/`, `scripts/`
ani `tests/` — sprawdzone analizą odwołań przed przeniesieniem. Katalog można skasować
w całości bez wpływu na benchmark, testy i generowanie raportu.

Porządkowanie: 2026-09-13. Uzupełnienie: 2026-09-27 (kopia kodu sprzed wydania 1.3.0, liczby
testów, usunięty bytecode).

---

## `agents_workflow/` — rusztowanie wielagentowego procesu pracy (96 plików)

Poprzednia zawartość `.agents/`: briefingi, dyspozycje, pliki postępu i przekazania dla
ról `orchestrator`, `explorer`, `challenger`, `auditor`, `reviewer`, `worker`, `sentinel`
i innych. To zapis procesu wytwórczego, nie artefakt badawczy. Zachowane, bo dokumentuje,
skąd wzięły się decyzje projektowe w kodzie.

## `outputs_v1/` — pierwszy przebieg, wycofany

`rag_poisoning_comparison_report.md` + `comparison_benchmark_results.json` +
`generation_traces.json` ze **100-zapytaniowego, dwustratowego** przebiegu.

Zastąpiony przez `outputs/reports/v2/` (150 zapytań, trzy strata). Liczby w v1 **nie są**
porównywalne z v2 i nie należy ich cytować: inny zbiór zapytań, inna stratyfikacja, inny
stan warstwy raportowania. Raport v1 zawiera też nagłówek z dyrektywą zakazującą analizy
metodologicznej, która została usunięta z projektu jako sprzeczna z celem badania.

## `pre_audit_backup/` — stan sprzed weryfikacji metodologicznej

Kopia `rag_poisoning_comparison_report.md` i `AGENTS.md` sprzed serii poprawek
wprowadzonych po audycie metodologicznym. Przydatne wyłącznie do porównania „przed/po":
wersja raportu, w której wnioski 3 i 6 były wewnętrznie sprzeczne z własnymi tabelami,
a średnie liczono na stratach o zerowej użyteczności silnika.

## `scripts_superseded/` — wcześniejsze warianty uruchamiania

| plik | dlaczego nieużywany |
|---|---|
| `run_benchmark.py` | pojedynczy silnik, bez protokołu izolowanego; zastąpiony przez `run_comparison_benchmark.py` |
| `run_large_benchmark.py` | wariant skalowy tego samego, ta sama uwaga |
| `run_enterprise_scale_benchmark.py` | pipeline A/B/C dla dużej skali, wymaga płatnego API |
| `run_cross_provider_benchmark.py` | porównanie dostawców LLM; etap LLM jest poza zakresem badania |
| `demo_interactive.py` | demo do prezentacji, nie ścieżka pomiarowa |
| `batch_smoke_test.py` | test dymny Batch API OpenRouter (etap sędziego, nieuruchamiany) |
| `validate_judge_agreement.py` | walidacja zgodności sędziego LLM z etykietami ludzkimi (etap sędziego, nieuruchamiany) |

Ostatnie cztery pozycje należą do **etapu LLM**, który jest świadomie poza zakresem
(`llm_stage_ran = False`). Kod `src/llm/` i `src/evaluation/llm_judge.py` **pozostaje**
w projekcie, bo jest importowany przez główny skrypt — zarchiwizowano tylko narzędzia
uruchomieniowe wokół niego. Gdyby etap LLM kiedyś wrócił, te skrypty wystarczy przenieść
z powrotem do `scripts/`.

## `status_reports/` — raporty statusu z zakończonych etapów

`TEST_READY.md`: raport gotowości zestawu E2E opisujący stan „225 testów: 184 zdane,
41 celowo niezdanych jako sygnatury defektów dla bramek M1–M5, STATUS: READY FOR
MILESTONE GATING". Ten stan już nie istnieje — remediacja została wykonana i wszystkie testy
przechodzą (13.09.2026: 397, 27.09.2026: 429). Dokument jest zapisem punktu w czasie,
nie opisem systemu.

Żywa dokumentacja zestawu testów została w `TEST_INFRA.md` (metodologia 4-warstwowa,
mapowanie funkcji na testy, własność plików).

## `src_infrastructure/` — moduły bez żadnych odwołań

`runpod_orchestrator.py` (zarządzanie podami GPU RunPod) i `scite_mcp_bridge.py` (most do
MCP scite). Zero importów w całym projekcie. Badanie działa w 100% lokalnie na CPU, więc
orkiestracja GPU nie ma zastosowania; literaturę obsługuje się bezpośrednio przez MCP,
nie przez ten most.

## `pre_v3_backup_2026-09-26/` — kod i dokumentacja sprzed wydania 1.3.0

Kopia 11 plików wykonana 26.09.2026, przed wprowadzeniem zapisu pełnych grup remisowych,
zestawu pytań v3, K4 liczonego per szablon i poprawionego wzoru progu mostów
(`CHANGELOG.md`, wydanie 1.3.0):

* `AGENTS.md`, `CHANGELOG.md`;
* `scripts/`: `audit_checks.py`, `run_bridge_sweep.py`, `run_comparison_benchmark.py`,
  `tie_audit.py`;
* `src/`: `corpus/real_query_loader.py`, `engines/retrievers.py`, `evaluation/metrics.py`,
  `evaluation/stages.py`, `visualization/reporter.py`.

Do odtworzenia wyników kopia nie jest potrzebna: bieżący kod odtwarza archiwalny przebieg v2
dokładnie (`outputs/reports/v2_rerun/`: 22 200 list top-5, 0 różnic w metrykach). Zostaje
jako zapis stanu „przed", bo tego stanu nie zatwierdzono w git. Do 27.09.2026 leżała poza
repozytorium, w `../_backup_przed_v3_2026-09-26/`.

---

## Co świadomie **nie** trafiło do archiwum

* `data/raw/` (568 MB) — dane źródłowe, wymagane do odtworzenia korpusu od zera
  (`cvelistV5_all.zip`, feed STIX MITRE, CTIBench, CISA KEV).
* `data/processed/real_cti_corpus_v2_{500,1000,24000}.json` — cache korpusu; 24000 to
  korpus przebiegów v2 i v3, 500 i 1000 służą szybkim przebiegom dymnym.
* `data/cache/embeddings/` — cache wektorów; bez niego pierwszy przebieg koduje korpus od nowa.
* `src/llm/`, `src/defense/`, `src/corpus/large_cti_generator.py` — nieużywane przez
  bieżący tryb, ale importowane lub pokryte testami.
* `TEST_INFRA.md` — dokumentacja żywego zestawu testów (429 od wydania 1.3.0; spis plików
  uzupełniony o nowsze, których pierwsza redakcja nie zawierała).
* `CHANGELOG.md` — historia wydań; z natury przyrostowa, więc zostaje w projekcie.

## Co zostało usunięte, nie zarchiwizowane

* 33 pliki `*:Zone.Identifier` (po 25 B, znacznik strefy pobierania Windows, łącznie 825 B).
* 11 katalogów `__pycache__` oraz `.pytest_cache/` — regenerowalny bytecode i cache testów.
* 2026-09-27: 10 katalogów `__pycache__` odtworzonych przez przebiegi z 27.09 oraz, poza
  repozytorium, folder `../_to_delete/` z pustym plikiem blokady git (`index.lock` z 26.09).
