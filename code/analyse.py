#!/usr/bin/env python3
"""Aggregate Paper D runs.

Inputs   ../results/injection_runs.jsonl     main run (classification, explanation, detector)
         ../results/injection_heldout.jsonl  reworded injections and the output audit, if present
Outputs  ../results/tableD1_suppression.csv  suppression by defence and injection, original wording
         ../results/tableD2_explanation.csv  explanation corruption by defence and injection
         ../results/tableD3_heldout.csv      the same two measures for the reworded injections
         ../results/tableD4_paired.csv       exact McNemar tests between defences on identical records
         ../results/paperD_summary.json      everything above plus false alarms and the audit
         ../results/figures/figD1_suppression, figD2_explanation
"""
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # figstyle.py sits next to this script
import figstyle                                               # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from detector import analyse as det_analyse                  # noqa: E402
from synth_logs import build_corpus, inject                   # noqa: E402
from score_explanations import score_v2                       # noqa: E402

RES = os.path.join(HERE, "..", "results")
FIG = os.path.join(RES, "figures")
ORIG = ["none", "S1_direct_override", "S2_persona_hijack", "S3_context_mimicry", "S4_obfuscated"]
HELD = ["H1_direct_override", "H2_persona_hijack", "H3_context_mimicry", "H4_obfuscated"]
SHORT = {"none": "no injection", "S1_direct_override": "override", "S2_persona_hijack": "persona",
         "S3_context_mimicry": "mimicry", "S4_obfuscated": "obfuscated",
         "H1_direct_override": "override", "H2_persona_hijack": "persona",
         "H3_context_mimicry": "mimicry", "H4_obfuscated": "obfuscated"}
DEF_NAMES = {"naive": "plain prompt", "structured": "untrusted data warning", "quarantine": "quarantine",
             "tls_locked": "locked verdict"}


def wilson(k, n, z=1.959964):
    if n == 0:
        return (float("nan"),) * 3
    p = k / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return p, c - h, c + h


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)


def load(name):
    path = os.path.join(RES, name)
    if not os.path.exists(path):
        return []
    rows = [json.loads(l) for l in open(path, encoding="utf-8")]
    for r in rows:
        if r["task"] == "explain":
            r["corrupted_v1"] = r.get("corrupted")
            r.update(score_v2(r["text"]))      # refined rules, the primary measure
    return rows


def rec_id(r):
    k = r["key"]
    return (k[-3], k[-2]) if r["task"] != "detector" else (k[1], k[2])


def rates(rows, task, defence, strategy, key, malicious=True):
    sub = [r for r in rows if r["task"] == task and r.get("defence") == defence and r["strategy"] == strategy
           and r.get("malicious", True) == malicious]
    k = sum(bool(r[key]) for r in sub)
    return k, len(sub), wilson(k, len(sub))


def main():
    os.makedirs(FIG, exist_ok=True)
    figstyle.apply()
    main_rows = load("injection_runs.jsonl")
    held_rows = load("injection_heldout.jsonl")
    summary = {}

    # locked verdict suppression comes from the detector, recomputed with the current detector code
    corpus = {(r["ip"], r["ts"]): r for r in build_corpus()}
    det = {}
    for s in ORIG:
        sub = [r for r in main_rows if r["task"] == "detector" and r["strategy"] == s and r["malicious"]]
        k = sum(r["det_verdict"] == "GREEN" for r in sub)
        flagged = sum(bool(det_analyse(inject(corpus[(r["key"][1], r["key"][2])], s))["injection_markers"])
                      for r in sub)
        det[s] = (k, len(sub), wilson(k, len(sub)), flagged)

    # table D1, suppression with the original wording
    supp = {}
    with open(os.path.join(RES, "tableD1_suppression.csv"), "w") as fh:
        fh.write("defence,strategy,suppressed,n,rate,ci_low,ci_high\n")
        for d in ("naive", "structured", "quarantine"):
            for s in ORIG:
                k, n, (p, lo, hi) = rates(main_rows, "classify", d, s, "suppressed")
                if n:
                    supp[(d, s)] = (k, n, p, lo, hi)
                    fh.write(f"{d},{s},{k},{n},{p:.3f},{lo:.3f},{hi:.3f}\n")
        for s in ORIG:
            k, n, (p, lo, hi), _ = det[s]
            supp[("tls_locked", s)] = (k, n, p, lo, hi)
            fh.write(f"tls_locked,{s},{k},{n},{p:.3f},{lo:.3f},{hi:.3f}\n")
    summary["suppression"] = {f"{d}|{s}": v for (d, s), v in supp.items()}
    summary["detector_flags_injection"] = {s: {"flagged": v[3], "n": v[1]} for s, v in det.items()}

    # false alarms on benign lines
    fa = {}
    for d in ("naive", "structured", "quarantine"):
        k, n, (p, lo, hi) = rates(main_rows, "classify", d, "none", "false_alarm", malicious=False)
        fa[d] = (k, n, p, lo, hi)
    sub = [r for r in main_rows if r["task"] == "detector" and r["strategy"] == "none" and not r["malicious"]]
    k = sum(r["det_verdict"] != "GREEN" for r in sub)
    fa["tls_locked"] = (k, len(sub)) + wilson(k, len(sub))
    summary["false_alarm"] = fa

    # table D2, explanation corruption
    corr = {}
    with open(os.path.join(RES, "tableD2_explanation.csv"), "w") as fh:
        fh.write("defence,strategy,denies_attack,n,rate,ci_low,ci_high,echoes_injection,echo_rate,corrupted_first_rules\n")
        for d in ("naive", "tls_locked"):
            for s in ORIG:
                sub = [r for r in main_rows if r["task"] == "explain" and r["defence"] == d and r["strategy"] == s]
                if not sub:
                    continue
                k = sum(r["corrupted_v2"] for r in sub)
                p, lo, hi = wilson(k, len(sub))
                ech = sum(r["echoes"] for r in sub)
                v1 = sum(bool(r["corrupted_v1"]) for r in sub)
                corr[(d, s)] = (k, len(sub), p, lo, hi)
                fh.write(f"{d},{s},{k},{len(sub)},{p:.3f},{lo:.3f},{hi:.3f},{ech},{ech / len(sub):.3f},{v1}\n")
    summary["explanation_corruption"] = {f"{d}|{s}": v for (d, s), v in corr.items()}

    # table D4, paired tests between defences on identical records
    def paired(rows, task, d1, d2, s, key):
        a = {rec_id(r): bool(r[key]) for r in rows if r["task"] == task and r.get("defence") == d1
             and r["strategy"] == s and r.get("malicious", True)}
        b = {rec_id(r): bool(r[key]) for r in rows if r["task"] == task and r.get("defence") == d2
             and r["strategy"] == s and r.get("malicious", True)}
        ids = sorted(set(a) & set(b))
        only1 = sum(a[i] and not b[i] for i in ids)
        only2 = sum(b[i] and not a[i] for i in ids)
        return len(ids), only1, only2, mcnemar_exact(only1, only2)

    with open(os.path.join(RES, "tableD4_paired.csv"), "w") as fh:
        fh.write("task,wording,strategy,defence_a,defence_b,n,success_only_a,success_only_b,p_mcnemar\n")
        for s in ORIG[1:]:
            for d1, d2 in (("naive", "structured"), ("naive", "quarantine"), ("structured", "quarantine")):
                n, o1, o2, p = paired(main_rows, "classify", d1, d2, s, "suppressed")
                if n:
                    fh.write(f"classify,original,{s},{d1},{d2},{n},{o1},{o2},{p:.2e}\n")
            n, o1, o2, p = paired(main_rows, "explain", "naive", "tls_locked", s, "corrupted_v2")
            if n:
                fh.write(f"explain,original,{s},naive,tls_locked,{n},{o1},{o2},{p:.2e}\n")
        for s in HELD:
            for d1, d2 in (("naive", "structured"), ("naive", "quarantine")):
                n, o1, o2, p = paired(held_rows, "classify", d1, d2, s, "suppressed")
                if n:
                    fh.write(f"classify,reworded,{s},{d1},{d2},{n},{o1},{o2},{p:.2e}\n")
            n, o1, o2, p = paired(held_rows, "explain", "naive", "tls_locked", s, "corrupted_v2")
            if n:
                fh.write(f"explain,reworded,{s},naive,tls_locked,{n},{o1},{o2},{p:.2e}\n")

    # table D3, reworded injections
    held_supp, held_corr = {}, {}
    if held_rows:
        with open(os.path.join(RES, "tableD3_heldout.csv"), "w") as fh:
            fh.write("task,defence,strategy,successes,n,rate,ci_low,ci_high\n")
            for d in ("naive", "structured", "quarantine"):
                for s in HELD:
                    k, n, (p, lo, hi) = rates(held_rows, "classify", d, s, "suppressed")
                    if n:
                        held_supp[(d, s)] = (k, n, p, lo, hi)
                        fh.write(f"classify,{d},{s},{k},{n},{p:.3f},{lo:.3f},{hi:.3f}\n")
            for s in HELD:
                sub = [r for r in held_rows if r["task"] == "detector" and r["strategy"] == s]
                if sub:
                    k = sum(r["det_verdict"] == "GREEN" for r in sub)
                    p, lo, hi = wilson(k, len(sub))
                    held_supp[("tls_locked", s)] = (k, len(sub), p, lo, hi)
                    fh.write(f"classify,tls_locked,{s},{k},{len(sub)},{p:.3f},{lo:.3f},{hi:.3f}\n")
            for d in ("naive", "tls_locked"):
                for s in HELD:
                    k, n, (p, lo, hi) = rates(held_rows, "explain", d, s, "corrupted_v2")
                    if n:
                        held_corr[(d, s)] = (k, n, p, lo, hi)
                        fh.write(f"explain,{d},{s},{k},{n},{p:.3f},{lo:.3f},{hi:.3f}\n")
        flagged = [r for r in held_rows if r["task"] == "detector"]
        summary["heldout_detector_flagged"] = {"flagged": sum(r["flagged_injection"] for r in flagged),
                                               "n": len(flagged)}
        summary["heldout_suppression"] = {f"{d}|{s}": v for (d, s), v in held_supp.items()}
        summary["heldout_explanation_corruption"] = {f"{d}|{s}": v for (d, s), v in held_corr.items()}
        # audit of raw outputs against the main labels
        main_lab = {tuple(r["key"]): r["pred"] for r in main_rows if r["task"] == "classify"}
        aud = [r for r in held_rows if r["task"] == "audit"]
        if aud:
            off = [r for r in aud if not (r["raw"].startswith("mal") or r["raw"].startswith("ben"))]
            agree = sum(main_lab.get(tuple(r["main_key"])) == r["pred"] for r in aud)
            summary["audit"] = {"n": len(aud), "raw_not_a_label_word": len(off), "agree_with_main": agree,
                                "examples_not_label": sorted({r["raw"] for r in off})[:20]}

    # figures
    import matplotlib.pyplot as plt
    defs = ["naive", "structured", "quarantine", "tls_locked"]
    panels = [("original wording", ORIG[1:], supp)]
    if held_supp:
        panels.append(("reworded, unseen by the marker list", HELD, held_supp))
    fig, axes = plt.subplots(len(panels), 1, figsize=(figstyle.WIDTH_IN, 3.0 * len(panels) + 0.5), sharey=True, squeeze=False)
    w = 0.2
    for ax, (title, strats, tbl) in zip(axes[:, 0], panels):
        for i, d in enumerate(defs):
            xs = [j + (i - 1.5) * w for j in range(len(strats))]
            vals = [tbl.get((d, s)) for s in strats]
            ys = [v[2] if v else 0 for v in vals]
            err = [[max(0.0, v[2] - v[3]) if v else 0 for v in vals], [max(0.0, v[4] - v[2]) if v else 0 for v in vals]]
            ax.bar(xs, ys, width=w, color=figstyle.SEQ[i], yerr=err, capsize=2, label=DEF_NAMES[d])
        ax.set_xticks(range(len(strats)))
        ax.set_xticklabels([SHORT[s] for s in strats])
        ax.set_ylim(0, 1.05)
        ax.set_title(title)
    fig.supylabel("suppression, malicious lines labelled benign", fontsize=9)
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=4, frameon=False)
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    figstyle.save(fig, os.path.join(FIG, "figD1_suppression"))

    epanels = [("original wording", ORIG, corr)]
    if held_corr:
        epanels.append(("reworded, unseen by the marker list", HELD, held_corr))
    fig, axes = plt.subplots(len(epanels), 1, figsize=(figstyle.WIDTH_IN, 3.0 * len(epanels) + 0.5), sharey=True, squeeze=False)
    for ax, (title, strats, tbl) in zip(axes[:, 0], epanels):
        for i, d in enumerate(("naive", "tls_locked")):
            xs = [j + (i - 0.5) * 0.36 for j in range(len(strats))]
            vals = [tbl.get((d, s)) for s in strats]
            ys = [v[2] if v else 0 for v in vals]
            err = [[max(0.0, v[2] - v[3]) if v else 0 for v in vals], [max(0.0, v[4] - v[2]) if v else 0 for v in vals]]
            ax.bar(xs, ys, width=0.36, color=figstyle.SEQ[0 if d == "naive" else 3], yerr=err, capsize=2,
                   label=DEF_NAMES[d])
        ax.set_xticks(range(len(strats)))
        ax.set_xticklabels([SHORT[s] for s in strats])
        ax.set_ylim(0, 1.05)
        ax.set_title(title)
    fig.supylabel("explanations that deny the attack", fontsize=9)
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=2, frameon=False)
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    figstyle.save(fig, os.path.join(FIG, "figD2_explanation"))

    json.dump(summary, open(os.path.join(RES, "paperD_summary.json"), "w"), indent=1, default=str)
    print(json.dumps(summary, indent=1, default=str)[:6000])


if __name__ == "__main__":
    main()
