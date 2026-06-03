# Password Strength Analyzer & Breach Checker

Analyseur de robustesse de mots de passe basé sur l'**entropie** et la **détection de motifs faibles**, couplé à une vérification de fuites via l'API **HaveIBeenPwned** en mode *k-anonymity*.

Tout fonctionne en local : le mot de passe en clair **ne quitte jamais votre machine**, et même son hash complet n'est jamais transmis.

---

## Fonctionnalités

- **Calcul d'entropie** — combinaison de l'entropie théorique (longueur × log₂ de l'alphabet) et de l'entropie de Shannon, en retenant la mesure la plus prudente.
- **Détection de faiblesses structurelles** :
  - mots de passe les plus courants
  - mots du dictionnaire (y compris après désubstitution leetspeak : `@→a`, `3→e`…)
  - dates et années
  - répétitions (`aaa`, `111`)
  - séquences clavier et numériques (`qwerty`, `1234`)
  - composition trop pauvre (chiffres seuls, minuscules seules)
- **Estimation du temps de crack** sous 4 scénarios d'attaque réalistes, de l'attaque en ligne *rate-limited* au cassage hors-ligne sur GPU.
- **Vérification des fuites (HaveIBeenPwned)** via le modèle *k-anonymity* : seuls les **5 premiers caractères** d'un hash SHA-1 sont envoyés.
- **Deux interfaces** : GUI Tkinter en temps réel, ou CLI coloré pour le terminal.

---

## Aperçu

```
Résultat de l'analyse
──────────────────────────────────────────────────
Verdict    : Moyen  [█████████████░░░░░░░░░░░░░░░░░] 42/100
Entropie   : 44.1 bits
Longueur   : 13 caractères (alphabet de 84 symboles)
Composition: minuscules, majuscules, chiffres, symboles

Temps de crack estimé
──────────────────────────────────────────────────
  Attaque en ligne (rate-limited)            5.5e+05 siècles
  Hors-ligne, hash rapide (SHA-256, GPU)     instantané

Faiblesses détectées
──────────────────────────────────────────────────
  ⚠ Contient une année (ex. 1999, 2024) — motif très prévisible.
```

---

## Installation & utilisation

Aucune dépendance externe obligatoire — le projet tourne sur la **bibliothèque standard de Python** (Tkinter inclus avec Python sur Windows/macOS).

```bash
git clone https://github.com/<votre-compte>/password-analyzer.git
cd password-analyzer

# Interface graphique
python main.py

# Mode terminal
python main.py --cli

# Mode terminal + vérification des fuites
python main.py --cli --check-breach
```

---

## Comment marche le calcul d'entropie ?

L'entropie mesure l'imprévisibilité d'un mot de passe, en **bits**. Un mot de passe de `N` caractères tirés d'un alphabet de taille `R` a une entropie théorique de :

```
H = N × log₂(R)
```

Chaque bit supplémentaire **double** le nombre de combinaisons à tester. Le temps de crack est ensuite estimé à partir de `2^H` combinaisons et d'une vitesse d'attaque donnée (en moyenne, la moitié de l'espace est explorée avant de trouver).

Le moteur applique aussi une **pénalité** quand il détecte un motif prévisible : `Password2024!` a beau sembler complexe, son entropie effective chute fortement une fois le mot courant et l'année repérés.

---

## Confidentialité — le modèle k-anonymity

La vérification de fuites n'envoie **jamais** votre mot de passe :

1. on calcule le SHA-1 du mot de passe en local ;
2. on n'envoie à l'API que les **5 premiers caractères** du hash ;
3. l'API renvoie tous les suffixes connus pour ce préfixe ;
4. la comparaison finale se fait **en local**.

L'API ne peut donc ni connaître votre mot de passe, ni même son hash complet.

---

## Structure du projet

```
password-analyzer/
├── main.py            — point d'entrée (GUI par défaut, --cli pour le terminal)
├── analyzer.py        — moteur : entropie, détection de motifs, temps de crack
├── hibp.py            — vérification HaveIBeenPwned (k-anonymity)
├── gui.py             — interface graphique Tkinter
├── cli.py             — interface en ligne de commande
├── test_analyzer.py   — tests unitaires
└── requirements.txt
```

---

## Tests

```bash
python -m unittest test_analyzer -v
```

---

## Avertissement

Ce projet est conçu à des fins **éducatives** et pour aider à évaluer ses **propres** mots de passe. Ne l'utilisez jamais pour tester ou attaquer des comptes qui ne vous appartiennent pas. Les estimations de temps de crack sont des ordres de grandeur indicatifs, pas des garanties.

---

## Licence

MIT — voir [LICENSE](LICENSE).
