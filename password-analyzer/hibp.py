"""
hibp.py — Vérification de fuites via l'API HaveIBeenPwned (HIBP).

Implémente le modèle k-anonymity : on calcule le SHA-1 du mot de passe,
puis on envoie UNIQUEMENT les 5 premiers caractères du hash à l'API.
Celle-ci renvoie tous les suffixes de hash connus pour ce préfixe ; la
comparaison finale se fait en local.

=> Le mot de passe en clair n'est jamais transmis, et même son hash complet
   ne quitte jamais la machine. C'est le principe qui rend la vérification
   sûre et respectueuse de la vie privée.

Référence : https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

from __future__ import annotations

import hashlib
import urllib.request
import urllib.error

API_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "Password-Analyzer-Educational-Project"


class HIBPError(Exception):
    """Erreur réseau ou API lors de la vérification HIBP."""


def check_password(password: str, timeout: float = 6.0) -> int:
    """Renvoie le nombre de fois où le mot de passe apparaît dans des fuites.

    0 signifie qu'il n'a (à ce jour) jamais été vu dans une fuite connue.
    Lève HIBPError en cas de problème réseau.
    """
    if not password:
        return 0

    # 1. SHA-1 du mot de passe, en majuscules (format attendu par l'API).
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    # 2. On n'envoie QUE le préfixe de 5 caractères.
    request = urllib.request.Request(
        API_URL + prefix,
        headers={"User-Agent": USER_AGENT},
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except urllib.error.URLError as exc:
        raise HIBPError(f"Impossible de contacter l'API HIBP : {exc}") from exc

    # 3. La réponse liste des « SUFFIXE:nombre ». On compare en local.
    for line in body.splitlines():
        candidate_suffix, _, count = line.partition(":")
        if candidate_suffix == suffix:
            return int(count)
    return 0


if __name__ == "__main__":
    for pwd in ["password", "9$kL!2pVx#mQ7zR-unique-xyz"]:
        try:
            n = check_password(pwd)
            if n:
                print(f"« {pwd} » : vu {n:,} fois dans des fuites ⚠".replace(",", " "))
            else:
                print(f"« {pwd} » : non trouvé dans les fuites connues ✓")
        except HIBPError as e:
            print(f"Erreur : {e}")
