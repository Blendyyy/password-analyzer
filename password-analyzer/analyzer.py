"""
analyzer.py — Moteur d'analyse de la robustesse d'un mot de passe.

Calcule l'entropie, détecte les faiblesses structurelles (mots du dictionnaire,
dates, motifs clavier, répétitions, leetspeak) et estime le temps de crack
sous différents scénarios d'attaque.

Aucune dépendance externe : 100% bibliothèque standard Python.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Données de référence
# ---------------------------------------------------------------------------

# Petit dictionnaire des mots de passe les plus courants (extrait).
# Dans un vrai projet on chargerait rockyou.txt ; ici on garde un échantillon
# représentatif pour rester léger et hors-ligne.
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "azerty", "12345678",
    "111111", "1234567", "sunshine", "iloveyou", "princess", "admin",
    "welcome", "monkey", "abc123", "football", "dragon", "letmein",
    "motdepasse", "bonjour", "soleil", "loulou", "doudou", "chouchou",
    "00000000", "password1", "qwerty123", "azerty123",
}

# Mots courants susceptibles d'apparaître dans un mot de passe.
COMMON_WORDS = {
    "love", "god", "money", "secret", "summer", "winter", "hello", "world",
    "amour", "soleil", "chat", "chien", "maison", "geneve", "suisse",
    "paris", "france", "computer", "internet", "master", "ninja", "shadow",
}

# Séquences clavier classiques (QWERTY + AZERTY) et numériques.
KEYBOARD_SEQUENCES = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "azertyuiop", "qsdfghjklm", "wxcvbn",
    "1234567890", "0987654321",
]

# Table de désubstitution leetspeak la plus courante.
LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a", "$": "s", "!": "i",
})

# Vitesses de cracking (essais/seconde) selon le scénario d'attaque.
# Ordres de grandeur réalistes (hashcat sur GPU moderne).
ATTACK_SCENARIOS = {
    "Attaque en ligne (rate-limited)": 100,                 # 100 essais/s
    "Attaque en ligne (sans limite)": 10_000,               # 10 k/s
    "Hors-ligne, hash lent (bcrypt)": 10_000_000,           # 10 M/s
    "Hors-ligne, hash rapide (SHA-256, GPU)": 100_000_000_000,  # 100 G/s
}


# ---------------------------------------------------------------------------
# Modèle de résultat
# ---------------------------------------------------------------------------

class Verdict(Enum):
    TRES_FAIBLE = ("Très faible", "#e74c3c")
    FAIBLE = ("Faible", "#e67e22")
    MOYEN = ("Moyen", "#f1c40f")
    FORT = ("Fort", "#2ecc71")
    TRES_FORT = ("Très fort", "#27ae60")

    @property
    def label(self) -> str:
        return self.value[0]

    @property
    def color(self) -> str:
        return self.value[1]


@dataclass
class AnalysisResult:
    password_length: int
    charset_size: int
    entropy_bits: float
    verdict: Verdict
    score: int                      # 0-100
    warnings: list[str] = field(default_factory=list)
    crack_times: dict[str, str] = field(default_factory=dict)
    charset_detail: dict[str, bool] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Calculs
# ---------------------------------------------------------------------------

def _charset_size(password: str) -> tuple[int, dict[str, bool]]:
    """Taille de l'espace de caractères utilisé + détail par catégorie."""
    detail = {
        "minuscules": bool(re.search(r"[a-z]", password)),
        "majuscules": bool(re.search(r"[A-Z]", password)),
        "chiffres": bool(re.search(r"[0-9]", password)),
        "symboles": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }
    size = 0
    if detail["minuscules"]:
        size += 26
    if detail["majuscules"]:
        size += 26
    if detail["chiffres"]:
        size += 10
    if detail["symboles"]:
        size += 33  # symboles ASCII imprimables courants
    return size, detail


def _theoretical_entropy(length: int, charset_size: int) -> float:
    """Entropie théorique en bits : longueur × log2(taille de l'alphabet)."""
    if charset_size <= 1 or length == 0:
        return 0.0
    return length * math.log2(charset_size)


def _shannon_entropy(password: str) -> float:
    """Entropie de Shannon basée sur la fréquence réelle des caractères.

    Donne une mesure de la diversité interne (un 'aaaaaa' a une entropie
    de Shannon très basse même si l'alphabet théorique est grand)."""
    if not password:
        return 0.0
    freq: dict[str, int] = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(password)
    return -sum((c / n) * math.log2(c / n) for c in freq.values()) * n


def _detect_weaknesses(password: str) -> tuple[list[str], float]:
    """Détecte les motifs faibles. Renvoie (avertissements, pénalité en bits)."""
    warnings: list[str] = []
    penalty = 0.0
    lower = password.lower()
    deleet = lower.translate(LEET_MAP)

    if lower in COMMON_PASSWORDS or deleet in COMMON_PASSWORDS:
        warnings.append("Figure dans la liste des mots de passe les plus courants.")
        penalty += 25

    for word in COMMON_WORDS:
        if word in deleet and len(word) >= 4:
            warnings.append(f"Contient un mot courant : « {word} ».")
            penalty += 8
            break

    # Substitution leetspeak détectée
    if deleet != lower and (deleet in COMMON_PASSWORDS or
                            any(w in deleet for w in COMMON_WORDS if len(w) >= 4)):
        warnings.append("Utilise une substitution leetspeak (ex. @ pour a, 3 pour e) — facilement devinée.")
        penalty += 6

    # Dates / années
    if re.search(r"(19|20)\d{2}", password):
        warnings.append("Contient une année (ex. 1999, 2024) — motif très prévisible.")
        penalty += 6
    if re.search(r"\b\d{2}[/.\-]\d{2}[/.\-]\d{2,4}\b", password):
        warnings.append("Contient une date complète.")
        penalty += 6

    # Répétitions
    if re.search(r"(.)\1{2,}", password):
        warnings.append("Contient des caractères répétés (ex. aaa, 111).")
        penalty += 5

    # Séquences clavier / numériques
    for seq in KEYBOARD_SEQUENCES:
        for size in range(4, len(seq) + 1):
            for i in range(len(seq) - size + 1):
                chunk = seq[i:i + size]
                if chunk in lower:
                    warnings.append(f"Contient une séquence clavier/numérique : « {chunk} ».")
                    penalty += 6
                    break
            else:
                continue
            break
        else:
            continue
        break

    # Tout en minuscules ou tout en chiffres
    if password.isdigit():
        warnings.append("Composé uniquement de chiffres.")
        penalty += 10
    elif password.isalpha() and password.islower():
        warnings.append("Composé uniquement de lettres minuscules.")
        penalty += 6

    # Longueur insuffisante
    if len(password) < 8:
        warnings.append("Trop court : visez au moins 12 caractères.")
        penalty += 10
    elif len(password) < 12:
        warnings.append("Longueur acceptable mais améliorable (12+ recommandé).")
        penalty += 3

    return warnings, penalty


def _format_duration(seconds: float) -> str:
    """Transforme une durée en secondes en texte lisible."""
    if seconds < 1:
        return "instantané"
    units = [
        ("siècle", 60 * 60 * 24 * 365 * 100),
        ("an", 60 * 60 * 24 * 365),
        ("mois", 60 * 60 * 24 * 30),
        ("jour", 60 * 60 * 24),
        ("heure", 60 * 60),
        ("minute", 60),
        ("seconde", 1),
    ]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if value >= 1e9:
                return f"{value:.1e} {name}s"
            value = round(value)
            plural = "s" if value > 1 and name != "mois" else ""
            return f"{value:,} {name}{plural}".replace(",", " ")
    return "instantané"


def _verdict_from_entropy(entropy: float, penalty: float) -> tuple[Verdict, int]:
    """Détermine le verdict et un score 0-100 à partir de l'entropie effective."""
    effective = max(0.0, entropy - penalty)
    # Score : on plafonne à 100 autour de 90 bits (très solide).
    score = max(0, min(100, round(effective / 90 * 100)))
    if effective < 28:
        verdict = Verdict.TRES_FAIBLE
    elif effective < 36:
        verdict = Verdict.FAIBLE
    elif effective < 60:
        verdict = Verdict.MOYEN
    elif effective < 80:
        verdict = Verdict.FORT
    else:
        verdict = Verdict.TRES_FORT
    return verdict, score


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------

def analyze(password: str) -> AnalysisResult:
    """Analyse complète d'un mot de passe et renvoie un AnalysisResult."""
    charset_size, charset_detail = _charset_size(password)
    theoretical = _theoretical_entropy(len(password), charset_size)
    shannon = _shannon_entropy(password)
    # On prend l'entropie la plus prudente entre théorique et Shannon.
    entropy = min(theoretical, shannon) if password else 0.0

    warnings, penalty = _detect_weaknesses(password)
    verdict, score = _verdict_from_entropy(entropy, penalty)

    # Estimation du temps de crack : 2^entropy combinaisons, en moyenne la
    # moitié de l'espace est explorée avant de trouver.
    combinations = 2 ** max(0.0, entropy - penalty)
    crack_times: dict[str, str] = {}
    for scenario, rate in ATTACK_SCENARIOS.items():
        seconds = (combinations / 2) / rate
        crack_times[scenario] = _format_duration(seconds)

    return AnalysisResult(
        password_length=len(password),
        charset_size=charset_size,
        entropy_bits=round(entropy, 1),
        verdict=verdict,
        score=score,
        warnings=warnings,
        crack_times=crack_times,
        charset_detail=charset_detail,
    )


if __name__ == "__main__":
    # Démonstration rapide en ligne de commande.
    for pwd in ["123456", "Password1", "Tr0ub4dour", "9$kL!2pVx#mQ7zR"]:
        r = analyze(pwd)
        print(f"\n{'=' * 50}\nMot de passe : {pwd}")
        print(f"Entropie : {r.entropy_bits} bits — {r.verdict.label} ({r.score}/100)")
        for w in r.warnings:
            print(f"  ⚠ {w}")
        print(f"  Crack (hash rapide GPU) : {r.crack_times['Hors-ligne, hash rapide (SHA-256, GPU)']}")
