# Instructions hidden in log fields, measuring prompt injection against a local security assistant and two detector informed defences

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23410156.svg)](https://doi.org/10.5281/zenodo.23410156)

Code and data for the Open Research Europe article "Instructions hidden in log fields, measuring prompt injection against a local security assistant and two detector informed defences" by Nikolaos D. Tantaroudas, Ilias Karachalios and Andrew J. McCracken, a follow on study of the SentinelSphere platform carried out under the Horizon Europe project ResilMesh, Grant Agreement No. 101119681.

## Contents and how to reproduce

Code, synthetic data and every model output for "Can a log line talk a security assistant out of an alert? Prompt injection, quarantine and locked verdicts on a small local model".

`code/synth_logs.py` generates the synthetic access log corpus in `data/corpus.json`, `code/detector.py` is the rule based detector with its attack signatures and instruction markers, `code/run_injection.py` and `code/run_heldout.py` run the original and the reworded injections, `code/score_explanations.py` holds the stance rules for the explanations and `code/analyse.py` builds the tables and figures. `results/injection_runs.jsonl` and `results/injection_heldout.jsonl` hold every classification and explanation, `results/explanations_scored.csv` every explanation verbatim with its scores, and the `table*.csv` files the aggregated rates with Wilson intervals and the paired tests.

The logs are synthetic and the injection strings are short instruction markers without exploit code, meant for defensive testing. To reproduce, run `python3 code/synth_logs.py`, then `code/run_injection.py` and `code/run_heldout.py` with the model option pointing at a Phi-4-mini-instruct Q4_K_M GGUF file, then `python3 code/analyse.py`.

The analysis scripts import `figstyle.py` from the folder `code`, which sets the figure style used in the article, drawn at a display width of at most 150 mm and saved as EPS, PDF and 600 dpi PNG.

## Licence

The code is released under the MIT License, see `LICENSE`. The aggregated results and figures are released under the Creative Commons Zero 1.0 dedication, see `DATA_LICENSE.md`.

## Citation

Please cite the article, and this repository through its Zenodo DOI, https://doi.org/10.5281/zenodo.23410156, see `CITATION.cff`.
