import unittest
import regex_group_extractor as rge


class RegexCategorizerTest(unittest.TestCase):
    def test_small_file(self):
        groups = rge.extract_groups_from("test_rules.rules")
        print(groups)

if __name__ == "__main__":
    unittest.main()
