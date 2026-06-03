"""
cli.py — Interface en ligne de commande du Password Analyzer.

Usage :
    python cli.py                 # saisie interactive masquée
    python cli.py --check-breach  # ajoute la vérification HaveIBeenPwned
"""

from __future__ import annotations

import argparse
import getpass
import sys

import analyzer
import hibp


# Codes couleur ANSI -> joli rendu terminal.
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    "Très faible": "\033[91m",
    "Faible": "\033[33m",
    "Moyen": "\033[93m",
    "Fort": "\033[92m",
    "Très fort": "\033[32m",
}


def _bar(score: int, width: int = 30) -> str:
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def run(check_breach: bool) -> int:
    try:
        password = getpass.getpass("Mot de passe à analyser (saisie masquée) : ")
    except (KeyboardInterrupt, EOFError):
        print()
        return 1

    if not password:
        print("Aucun mot de passe saisi.")
        return 1

    result = analyzer.analyze(password)
    color = COLORS.get(result.verdict.label, "")

    print(f"\n{BOLD}Résultat de l'analyse{RESET}")
    print("─" * 50)
    print(f"Verdict    : {color}{BOLD}{result.verdict.label}{RESET}  [{_bar(result.score)}] {result.score}/100")
    print(f"Entropie   : {result.entropy_bits} bits")
    print(f"Longueur   : {result.password_length} caractères "
          f"(alphabet de {result.charset_size} symboles)")

    present = [k for k, v in result.charset_detail.items() if v]
    print(f"Composition: {', '.join(present) if present else 'aucune'}")

    print(f"\n{BOLD}Temps de crack estimé{RESET}")
    print("─" * 50)
    for scenario, value in result.crack_times.items():
        print(f"  {scenario:<42} {value}")

    print(f"\n{BOLD}Faiblesses détectées{RESET}")
    print("─" * 50)
    if result.warnings:
        for w in result.warnings:
            print(f"  {COLORS['Faible']}⚠{RESET} {w}")
    else:
        print(f"  {COLORS['Fort']}✓{RESET} Aucune faiblesse structurelle détectée.")

    if check_breach:
        print(f"\n{BOLD}Vérification des fuites (HaveIBeenPwned){RESET}")
        print("─" * 50)
        print(f"  {DIM}Envoi du préfixe de hash uniquement (k-anonymity)…{RESET}")
        try:
            count = hibp.check_password(password)
            if count:
                print(f"  {COLORS['Très faible']}⚠ Trouvé {count:,} fois dans des fuites — "
                      f"à ne jamais utiliser.{RESET}".replace(",", " "))
            else:
                print(f"  {COLORS['Fort']}✓ Absent des fuites connues à ce jour.{RESET}")
        except hibp.HIBPError as e:
            print(f"  Erreur réseau : {e}")

    print()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyseur de robustesse de mot de passe.")
    parser.add_argument(
        "--check-breach", action="store_true",
        help="vérifie si le mot de passe figure dans des fuites (HaveIBeenPwned)",
    )
    args = parser.parse_args()
    sys.exit(run(args.check_breach))


if __name__ == "__main__":
    main()
