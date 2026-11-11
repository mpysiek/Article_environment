# Data

The source data is **not** stored in this repository (about 650 MB, third-party licences).
`src/corpus/real_cti_loader.py` downloads it into `data/raw/` on the first run and caches the
assembled corpus in `data/processed/real_cti_corpus_v2_<N>.json`.

## Sources used in the article

| File in `data/raw/` | Source | Version used | Licence / terms |
| :--- | :--- | :--- | :--- |
| `enterprise_attack_stix21.json` | [MITRE ATT&CK STIX 2.1 data](https://github.com/mitre-attack/attack-stix-data) | Enterprise ATT&CK v19.2, accessed 2 Sep 2026 | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) |
| `ctibench_rcm.tsv`, `ctibench_taa.tsv` | [CTIBench](https://huggingface.co/datasets/AI4Sec/cti-bench) (AI4Sec) | `main`, accessed 2 Sep 2026 | see dataset card |
| `cisa_kev.json` | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | accessed 6 Sep 2026 | public |
| `cvelistV5_all.zip` | [CVE Program cvelistV5](https://github.com/CVEProject/cvelistV5) | bulk release of 6 Sep 2026 | [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse) |

## Pinning the exact versions

The loader fetches the **current** files (`master` / `latest`). All four sources change over
time, so a fresh download will not give the same 24,000-document corpus. To reproduce the
article exactly, place the versions listed above in `data/raw/` before the first run:

* ATT&CK: `enterprise-attack/enterprise-attack-19.2.json` from the `attack-stix-data` repository,
  saved as `enterprise_attack_stix21.json`;
* cvelistV5: the bulk asset `…_all_CVEs_at_midnight.zip` of the release dated 2026-09-06,
  saved as `cvelistV5_all.zip`.

Then check the files against the SHA-256 sums below (`sha256sum -c data/SHA256SUMS`).
The run manifest (`outputs/reports/v3/run_manifest.json`) records a fingerprint of the corpus
document IDs (`corpus_id_fingerprint_sha256_16 = 26aae4360692cf97`); a run on the same corpus
reproduces it.

## SHA-256 of the files used for runs v2, v2_rerun and v3

See [`SHA256SUMS`](SHA256SUMS). The same file also lists the sums of the uncompressed
`comparison_benchmark_results.json` and `generation_traces.json` of each run.
