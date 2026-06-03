"""
gui.py — Interface graphique (Tkinter) du Password Analyzer.

Affiche en temps réel : la jauge de robustesse, l'entropie, le détail du
jeu de caractères, les avertissements, les temps de crack estimés, et le
résultat de la vérification HaveIBeenPwned (sur demande, en arrière-plan).
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk

import analyzer
import hibp


# Palette « Midnight » sombre.
BG = "#11151c"
BG_CARD = "#1b212b"
FG = "#e6e9ef"
FG_DIM = "#8a93a6"
ACCENT = "#4dabf7"


class PasswordAnalyzerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Password Strength Analyzer")
        self.geometry("640x720")
        self.minsize(560, 680)
        self.configure(bg=BG)

        self._build_styles()
        self._build_widgets()
        self._current_password = ""

    # -- Style -------------------------------------------------------------
    def _build_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=BG_CARD)
        style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=BG_CARD, foreground=FG, font=("Segoe UI", 10))
        style.configure("Dim.TLabel", background=BG_CARD, foreground=FG_DIM, font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=BG, foreground=FG, font=("Segoe UI Semibold", 18))
        style.configure("Verdict.TLabel", background=BG_CARD, font=("Segoe UI Semibold", 16))
        style.configure(
            "TButton", background=ACCENT, foreground="#08121f",
            font=("Segoe UI Semibold", 10), borderwidth=0, focuscolor=BG,
        )
        style.map("TButton", background=[("active", "#74c0fc")])
        style.configure("TCheckbutton", background=BG, foreground=FG_DIM)
        style.map("TCheckbutton", background=[("active", BG)])

    # -- Widgets -----------------------------------------------------------
    def _build_widgets(self) -> None:
        root = ttk.Frame(self, padding=24)
        root.pack(fill="both", expand=True)

        ttk.Label(root, text="🔐  Password Strength Analyzer", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            root,
            text="Analyse locale de la robustesse. Le mot de passe ne quitte jamais votre machine.",
            style="TLabel", foreground=FG_DIM,
        ).pack(anchor="w", pady=(2, 18))

        # Champ de saisie
        entry_card = ttk.Frame(root, style="Card.TFrame", padding=16)
        entry_card.pack(fill="x")
        ttk.Label(entry_card, text="Mot de passe à tester", style="Dim.TLabel").pack(anchor="w")

        row = ttk.Frame(entry_card, style="Card.TFrame")
        row.pack(fill="x", pady=(6, 0))
        self.var_password = tk.StringVar()
        self.var_password.trace_add("write", self._on_change)
        self.entry = tk.Entry(
            row, textvariable=self.var_password, show="•",
            bg="#0d1117", fg=FG, insertbackground=FG,
            relief="flat", font=("Consolas", 13),
        )
        self.entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self.entry.focus()

        self.var_show = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            row, text="Afficher", variable=self.var_show,
            command=self._toggle_show, style="TCheckbutton",
        ).pack(side="left")

        # Jauge + verdict
        gauge_card = ttk.Frame(root, style="Card.TFrame", padding=16)
        gauge_card.pack(fill="x", pady=(12, 0))
        self.lbl_verdict = ttk.Label(gauge_card, text="—", style="Verdict.TLabel", foreground=FG_DIM)
        self.lbl_verdict.pack(anchor="w")
        self.canvas_gauge = tk.Canvas(gauge_card, height=14, bg=BG_CARD, highlightthickness=0)
        self.canvas_gauge.pack(fill="x", pady=(8, 6))
        self.lbl_entropy = ttk.Label(gauge_card, text="Entropie : —", style="Dim.TLabel")
        self.lbl_entropy.pack(anchor="w")

        # Détail jeu de caractères
        self.charset_card = ttk.Frame(root, style="Card.TFrame", padding=16)
        self.charset_card.pack(fill="x", pady=(12, 0))
        ttk.Label(self.charset_card, text="Composition", style="Dim.TLabel").pack(anchor="w")
        self.lbl_charset = ttk.Label(self.charset_card, text="—", style="Card.TLabel")
        self.lbl_charset.pack(anchor="w", pady=(4, 0))

        # Temps de crack
        crack_card = ttk.Frame(root, style="Card.TFrame", padding=16)
        crack_card.pack(fill="x", pady=(12, 0))
        ttk.Label(crack_card, text="Temps de crack estimé", style="Dim.TLabel").pack(anchor="w")
        self.crack_labels: dict[str, ttk.Label] = {}
        for scenario in analyzer.ATTACK_SCENARIOS:
            line = ttk.Frame(crack_card, style="Card.TFrame")
            line.pack(fill="x", pady=1)
            ttk.Label(line, text=scenario, style="Dim.TLabel").pack(side="left")
            lbl = ttk.Label(line, text="—", style="Card.TLabel")
            lbl.pack(side="right")
            self.crack_labels[scenario] = lbl

        # Avertissements
        self.warn_card = ttk.Frame(root, style="Card.TFrame", padding=16)
        self.warn_card.pack(fill="x", pady=(12, 0))
        ttk.Label(self.warn_card, text="Faiblesses détectées", style="Dim.TLabel").pack(anchor="w")
        self.lbl_warnings = ttk.Label(self.warn_card, text="—", style="Card.TLabel", justify="left", wraplength=560)
        self.lbl_warnings.pack(anchor="w", pady=(4, 0))

        # HIBP
        hibp_card = ttk.Frame(root, style="Card.TFrame", padding=16)
        hibp_card.pack(fill="x", pady=(12, 0))
        top = ttk.Frame(hibp_card, style="Card.TFrame")
        top.pack(fill="x")
        ttk.Label(top, text="Vérification des fuites (HaveIBeenPwned)", style="Dim.TLabel").pack(side="left")
        self.btn_hibp = ttk.Button(top, text="Vérifier", command=self._check_hibp)
        self.btn_hibp.pack(side="right")
        self.lbl_hibp = ttk.Label(hibp_card, text="Vérification à la demande (k-anonymity).", style="Card.TLabel")
        self.lbl_hibp.pack(anchor="w", pady=(8, 0))

    # -- Comportement ------------------------------------------------------
    def _toggle_show(self) -> None:
        self.entry.config(show="" if self.var_show.get() else "•")

    def _on_change(self, *_args) -> None:
        password = self.var_password.get()
        self._current_password = password
        self.lbl_hibp.config(text="Vérification à la demande (k-anonymity).", foreground=FG)

        if not password:
            self._reset_display()
            return

        result = analyzer.analyze(password)
        self._render(result)

    def _reset_display(self) -> None:
        self.lbl_verdict.config(text="—", foreground=FG_DIM)
        self.lbl_entropy.config(text="Entropie : —")
        self.lbl_charset.config(text="—")
        self.lbl_warnings.config(text="—")
        self.canvas_gauge.delete("all")
        for lbl in self.crack_labels.values():
            lbl.config(text="—")

    def _render(self, result: analyzer.AnalysisResult) -> None:
        self.lbl_verdict.config(text=result.verdict.label, foreground=result.verdict.color)
        self.lbl_entropy.config(
            text=f"Entropie : {result.entropy_bits} bits  ·  score {result.score}/100  ·  "
                 f"{result.password_length} caractères, alphabet de {result.charset_size}"
        )

        # Jauge colorée
        self.canvas_gauge.delete("all")
        self.update_idletasks()
        width = self.canvas_gauge.winfo_width() or 560
        self.canvas_gauge.create_rectangle(0, 0, width, 14, fill="#0d1117", outline="")
        fill_w = width * result.score / 100
        self.canvas_gauge.create_rectangle(0, 0, fill_w, 14, fill=result.verdict.color, outline="")

        # Composition
        present = [k for k, v in result.charset_detail.items() if v]
        self.lbl_charset.config(text="  ·  ".join(present) if present else "aucune")

        # Temps de crack
        for scenario, value in result.crack_times.items():
            self.crack_labels[scenario].config(text=value)

        # Avertissements
        if result.warnings:
            self.lbl_warnings.config(text="\n".join("⚠  " + w for w in result.warnings), foreground="#ffd43b")
        else:
            self.lbl_warnings.config(text="✓  Aucune faiblesse structurelle détectée.", foreground="#69db7c")

    def _check_hibp(self) -> None:
        password = self._current_password
        if not password:
            self.lbl_hibp.config(text="Saisissez d'abord un mot de passe.", foreground=FG_DIM)
            return
        self.btn_hibp.config(state="disabled")
        self.lbl_hibp.config(text="Vérification en cours…", foreground=FG_DIM)
        threading.Thread(target=self._hibp_worker, args=(password,), daemon=True).start()

    def _hibp_worker(self, password: str) -> None:
        try:
            count = hibp.check_password(password)
        except hibp.HIBPError:
            self.after(0, lambda: self._hibp_result(None, error=True))
            return
        self.after(0, lambda: self._hibp_result(count))

    def _hibp_result(self, count: int | None, error: bool = False) -> None:
        self.btn_hibp.config(state="normal")
        if error:
            self.lbl_hibp.config(text="Erreur réseau — impossible de joindre l'API HIBP.", foreground="#ff8787")
        elif count:
            txt = f"⚠  Trouvé {count:,} fois dans des fuites connues. À ne jamais utiliser.".replace(",", " ")
            self.lbl_hibp.config(text=txt, foreground="#ff8787")
        else:
            self.lbl_hibp.config(text="✓  Absent des fuites connues à ce jour.", foreground="#69db7c")


def main() -> None:
    app = PasswordAnalyzerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
