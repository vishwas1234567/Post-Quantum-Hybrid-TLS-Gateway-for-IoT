#!/usr/bin/env python3
"""Turn results/*.csv into report figures (PNG+PDF) and LaTeX tables.

    python analysis/make_figures.py          # reads results/, writes report/figures + report/tables
"""
import csv
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RES, FIG, TAB = (os.path.join(ROOT, d) for d in ("results", "report/figures", "report/tables"))
os.makedirs(FIG, exist_ok=True)
os.makedirs(TAB, exist_ok=True)

# validated categorical slots 1-3 (blue, orange, aqua), light surface
COL = {"classical": "#2a78d6", "hybrid": "#eb6834", "pqc": "#1baf7a"}
LABEL = {"classical": "Classical (X25519)", "hybrid": "Hybrid (X25519MLKEM768)",
         "pqc": "Pure PQC (ML-KEM-768)"}
ORDER = ["classical", "hybrid", "pqc"]
INK, MUTED = "#0b0b0b", "#52514e"

plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": "#c9c8c2", "axes.labelcolor": MUTED,
    "xtick.color": MUTED, "ytick.color": MUTED, "text.color": INK,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": "#e8e7e2", "grid.linewidth": 0.6,
    "axes.axisbelow": True, "savefig.dpi": 200, "figure.facecolor": "white",
})


def load(name):
    with open(os.path.join(RES, name)) as fh:
        return list(csv.DictReader(fh))


def save(fig, name):
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(FIG, "%s.%s" % (name, ext)), bbox_inches="tight")
    plt.close(fig)


def bars(ax, vals, fmt="%.0f"):
    xs = range(len(ORDER))
    ax.bar(xs, vals, color=[COL[p] for p in ORDER], width=0.55)
    for x, v in zip(xs, vals):
        ax.text(x, v, fmt % v, ha="center", va="bottom", fontsize=9)
    ax.set_xticks(list(xs))
    ax.set_xticklabels(["Classical", "Hybrid", "Pure PQC"])
    ax.grid(axis="x", visible=False)


def fig_handshake(summ, hs):
    fig, axs = plt.subplots(1, 2, figsize=(9, 3.4))
    data = [[float(r["handshake_ms"]) for r in hs if r["profile"] == p] for p in ORDER]
    bp = axs[0].boxplot(data, patch_artist=True, showfliers=False, widths=0.5,
                        medianprops={"color": INK, "linewidth": 1.4})
    for patch, p in zip(bp["boxes"], ORDER):
        patch.set_facecolor(COL[p])
        patch.set_alpha(0.85)
    axs[0].set_xticklabels(["Classical", "Hybrid", "Pure PQC"])
    axs[0].set_ylabel("handshake latency (ms)")
    axs[0].set_title("Latency distribution", loc="left", fontsize=10)
    axs[0].grid(axis="x", visible=False)
    tot = [float(next(r for r in summ if r["profile"] == p)["total_bytes"]) for p in ORDER]
    bars(axs[1], tot)
    axs[1].set_ylabel("bytes on the wire (whole handshake)")
    axs[1].set_title("Handshake size", loc="left", fontsize=10)
    fig.tight_layout()
    save(fig, "fig_handshake")


def fig_cpu(summ):
    fig, axs = plt.subplots(1, 2, figsize=(9, 3.2))
    get = lambda k: [float(next(r for r in summ if r["profile"] == p).get(k) or 0) for p in ORDER]
    bars(axs[0], get("client_cpu_ms_per_hs"), "%.2f")
    axs[0].set_ylabel("client CPU per handshake (ms)")
    axs[0].set_title("Edge-node CPU", loc="left", fontsize=10)
    bars(axs[1], get("gw_cpu_ms_per_hs"), "%.2f")
    axs[1].set_ylabel("gateway CPU per handshake (ms)")
    axs[1].set_title("Gateway CPU", loc="left", fontsize=10)
    fig.tight_layout()
    save(fig, "fig_cpu")


def fig_sizes(prim):
    sel = [("X25519", "KEM"), ("ML-KEM-768", "KEM"), ("ECDSA-P256", "SIG"), ("ML-DSA-65", "SIG")]
    seen, rows = set(), []
    for alg, _ in sel:
        r = next(x for x in prim if x["algorithm"] == alg)
        rows.append(r)
        seen.add(alg)
    fig, ax = plt.subplots(figsize=(7, 3.2))
    xs = range(len(rows))
    w = 0.38
    ax.bar([x - w / 2 for x in xs], [int(r["pk_bytes"]) for r in rows], w,
           color="#2a78d6", label="public key")
    ax.bar([x + w / 2 for x in xs], [int(r["ct_or_sig_bytes"]) for r in rows], w,
           color="#eb6834", label="ciphertext / signature")
    for x, r in zip(xs, rows):
        ax.text(x - w / 2, int(r["pk_bytes"]), r["pk_bytes"], ha="center", va="bottom", fontsize=8)
        ax.text(x + w / 2, int(r["ct_or_sig_bytes"]), r["ct_or_sig_bytes"], ha="center",
                va="bottom", fontsize=8)
    ax.set_xticks(list(xs))
    ax.set_xticklabels([r["algorithm"] for r in rows])
    ax.set_ylabel("bytes")
    ax.legend(frameon=False)
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    save(fig, "fig_sizes")


def fig_ops(prim):
    ops = [("X25519", "exchange"), ("ML-KEM-768", "encaps"), ("ML-KEM-768", "decaps"),
           ("ECDSA-P256", "sign"), ("ECDSA-P256", "verify"),
           ("ML-DSA-65", "sign"), ("ML-DSA-65", "verify")]
    vals = [float(next(r for r in prim if r["algorithm"] == a and r["op"] == o)["mean_us"])
            for a, o in ops]
    fig, ax = plt.subplots(figsize=(8, 3.2))
    cols = ["#2a78d6" if a in ("X25519", "ECDSA-P256") else "#eb6834" for a, _ in ops]
    ax.bar(range(len(ops)), vals, color=cols, width=0.55)
    for i, v in enumerate(vals):
        ax.text(i, v, "%.0f" % v, ha="center", va="bottom", fontsize=8)
    ax.set_xticks(range(len(ops)))
    ax.set_xticklabels(["%s\n%s" % (a, o) for a, o in ops], fontsize=8)
    ax.set_ylabel("mean time (\u00b5s)")
    ax.set_title("Classical (blue) vs post-quantum (orange) primitives", loc="left", fontsize=10)
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    save(fig, "fig_ops")


def tex_tables(summ, prim):
    def num(r, k, f="%.2f"):
        v = r.get(k)
        return f % float(v) if v not in (None, "") else "--"
    with open(os.path.join(TAB, "handshake_table.tex"), "w") as fh:
        fh.write("\\begin{tabular}{lrrrrrrr}\n\\toprule\n"
                 "Profile & Median (ms) & p95 (ms) & ClientHello (B) & Total (B) & "
                 "Client CPU (ms) & GW CPU (ms) & GW RSS (MB)\\\\\n\\midrule\n")
        for p in ORDER:
            r = next(x for x in summ if x["profile"] == p)
            rss = "%.1f" % (float(r["gw_rss_kb"]) / 1024) if r.get("gw_rss_kb") else "--"
            fh.write("%s & %s & %s & %s & %s & %s & %s & %s\\\\\n" % (
                p, num(r, "lat_median_ms"), num(r, "lat_p95_ms"),
                r["client_hello_bytes"], r["total_bytes"],
                num(r, "client_cpu_ms_per_hs"), num(r, "gw_cpu_ms_per_hs"), rss))
        fh.write("\\bottomrule\n\\end{tabular}\n")
    with open(os.path.join(TAB, "primitive_table.tex"), "w") as fh:
        fh.write("\\begin{tabular}{llrrrr}\n\\toprule\n"
                 "Algorithm & Operation & Mean (\\textmu s) & Public key (B) & "
                 "Ciphertext/sig (B) & \\\\\n\\midrule\n")
        for r in prim:
            fh.write("%s & %s & %.1f & %s & %s & \\\\\n" % (
                r["algorithm"], r["op"], float(r["mean_us"]), r["pk_bytes"], r["ct_or_sig_bytes"]))
        fh.write("\\bottomrule\n\\end{tabular}\n")


def main():
    summ, hs, prim = load("summary.csv"), load("handshakes.csv"), load("primitives.csv")
    fig_handshake(summ, hs)
    fig_cpu(summ)
    fig_sizes(prim)
    fig_ops(prim)
    tex_tables(summ, prim)
    print("figures ->", FIG, "| tables ->", TAB)


if __name__ == "__main__":
    main()
