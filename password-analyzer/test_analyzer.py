"""
test_analyzer.py — Tests unitaires du moteur d'analyse.

Lancer avec :  python -m unittest test_analyzer
"""

import unittest

import analyzer


class TestAnalyzer(unittest.TestCase):

    def test_empty_password(self):
        r = analyzer.analyze("")
        self.assertEqual(r.entropy_bits, 0.0)
        self.assertEqual(r.score, 0)

    def test_common_password_flagged(self):
        r = analyzer.analyze("password")
        self.assertEqual(r.verdict, analyzer.Verdict.TRES_FAIBLE)
        self.assertTrue(any("courant" in w for w in r.warnings))

    def test_digits_only_flagged(self):
        r = analyzer.analyze("8473625190")
        self.assertTrue(any("chiffres" in w for w in r.warnings))

    def test_strong_password_high_score(self):
        r = analyzer.analyze("9$kL!2pVx#mQ7zR4wB^")
        self.assertGreaterEqual(r.score, 70)
        self.assertIn(r.verdict, (analyzer.Verdict.FORT, analyzer.Verdict.TRES_FORT))

    def test_charset_detection(self):
        r = analyzer.analyze("Abc123!@")
        self.assertTrue(r.charset_detail["minuscules"])
        self.assertTrue(r.charset_detail["majuscules"])
        self.assertTrue(r.charset_detail["chiffres"])
        self.assertTrue(r.charset_detail["symboles"])

    def test_repetition_flagged(self):
        r = analyzer.analyze("aaaaaa111")
        self.assertTrue(any("répétés" in w for w in r.warnings))

    def test_keyboard_sequence_flagged(self):
        r = analyzer.analyze("qwerty098")
        self.assertTrue(any("séquence" in w for w in r.warnings))

    def test_year_flagged(self):
        r = analyzer.analyze("Maison2024xY")
        self.assertTrue(any("année" in w for w in r.warnings))

    def test_entropy_monotonic_with_length(self):
        short = analyzer.analyze("Ab3!")
        long = analyzer.analyze("Ab3!Ab3!Ab3!")
        self.assertGreater(long.entropy_bits, short.entropy_bits)


if __name__ == "__main__":
    unittest.main()
