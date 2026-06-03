"""
main.py — Point d'entrée du Password Strength Analyzer.

Par défaut, lance l'interface graphique.
Avec --cli, bascule en mode terminal.

    python main.py                      # interface graphique
    python main.py --cli                # mode terminal
    python main.py --cli --check-breach # terminal + vérif fuites
"""

import sys


def main() -> None:
    if "--cli" in sys.argv:
        sys.argv.remove("--cli")
        import cli
        cli.main()
    else:
        import gui
        gui.main()


if __name__ == "__main__":
    main()
