import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt

from src.config import config
from src.corpus.dataset import build_cti_knowledge_base, build_gold_benchmark_queries
from src.engines.retrievers import BM25Retriever, DenseFAISSRetriever, HybridRerankRetriever, GraphRAGRetriever
from src.attacks.poisoning import CorpusPoisonManager
from src.defense.sanitizers import DefendedRetrievalPipeline

console = Console()

def main():
    console.print(Panel.fit("[bold cyan]🛡️ CTI RAG Corpus Poisoning & Defense Interactive CLI[/bold cyan]\n[dim]Narzędzie audytu odporności silników wyszukiwania na ataki zatruwania bazy wiedzy[/dim]", border_style="cyan"))

    # Load baseline
    console.print("[dim]Ładowanie bazy wiedzy CTI i modeli...[/dim]")
    clean_docs = build_cti_knowledge_base()
    gold_queries = build_gold_benchmark_queries()

    bm25 = BM25Retriever()
    dense = DenseFAISSRetriever(model_name=config.DENSE_MODEL_NAME)
    hybrid = HybridRerankRetriever(bm25, dense, reranker_name=config.RERANKER_MODEL_NAME)
    graph = GraphRAGRetriever()

    engines = {
        "1": ("Sparse-BM25", bm25, "sparse"),
        "2": ("Dense-FAISS", dense, "dense"),
        "3": ("Hybrid-Reranker", hybrid, "hybrid"),
        "4": ("GraphRAG", graph, "graph")
    }

    poison_mgr = CorpusPoisonManager()

    while True:
        console.print("\n[bold yellow]Wybierz zapytanie testowe:[/bold yellow]")
        for i, q in enumerate(gold_queries, 1):
            console.print(f"  [bold green]{i}.[/bold green] {q.query_text} [dim]({q.id})[/dim]")
        console.print("  [bold green]6.[/bold green] Wpisz własne zapytanie niestandardowe")
        console.print("  [bold red]0.[/bold red] Wyjście")

        choice = Prompt.ask("Twój wybór", default="1")
        if choice == "0":
            console.print("[green]Zakończono sesję.[/green]")
            break

        if choice in ["1", "2", "3", "4", "5"]:
            selected_query = gold_queries[int(choice) - 1]
            query_text = selected_query.query_text
        elif choice == "6":
            query_text = Prompt.ask("Wpisz zapytanie CTI")
            selected_query = gold_queries[0]
        else:
            console.print("[red]Nieprawidłowy wybór![/red]")
            continue

        console.print("\n[bold yellow]Wybierz silnik RAG:[/bold yellow]")
        console.print("  1. Sparse-BM25")
        console.print("  2. Dense-FAISS")
        console.print("  3. Hybrid + Cross-Encoder Reranker")
        console.print("  4. GraphRAG")
        eng_choice = Prompt.ask("Silnik", default="1")
        if eng_choice not in engines:
            console.print("[red]Nieprawidłowy silnik![/red]")
            continue

        eng_name, engine, attack_type = engines[eng_choice]

        # 1. Clean Run
        engine.build_index(clean_docs)
        clean_results = engine.retrieve(query_text, top_k=3)

        # 2. Poisoned Run
        poisoned_docs = poison_mgr.generate_poisoned_corpus(clean_docs, [selected_query], attack_type)
        engine.build_index(poisoned_docs)
        poisoned_results = engine.retrieve(query_text, top_k=3)

        # 3. Defended Run
        defended_pipeline = DefendedRetrievalPipeline(engine)
        defended_docs = defended_pipeline.filter_documents(poisoned_docs)
        engine.build_index(defended_docs)
        defended_results = defended_pipeline.retrieve(query_text, top_k=3)

        # Render Table
        table = Table(title=f"Porównanie wyników dla: {query_text[:60]}... ({eng_name})")
        table.add_column("Rank", justify="center", style="bold")
        table.add_column("🟢 Clean Baseline", justify="left")
        table.add_column("🔴 Under Attack (Poisoned)", justify="left")
        table.add_column("🛡️ With Defense Pipeline", justify="left")

        for rank in range(1, 4):
            c_doc = clean_results[rank-1].title if rank-1 < len(clean_results) else "[dim]brak[/dim]"
            
            p_doc = "[dim]brak[/dim]"
            if rank-1 < len(poisoned_results):
                r = poisoned_results[rank-1]
                p_doc = f"[bold red]⚠️ {r.title}[/bold red]" if r.is_poisoned else r.title

            d_doc = "[dim]brak[/dim]"
            if rank-1 < len(defended_results):
                r = defended_results[rank-1]
                d_doc = f"[bold red]⚠️ {r.title}[/bold red]" if r.is_poisoned else f"[bold green]✓ {r.title}[/bold green]"

            table.add_row(str(rank), c_doc, p_doc, d_doc)

        console.print(table)

if __name__ == "__main__":
    main()
