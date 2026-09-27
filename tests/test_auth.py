import random
import unittest

from carbide.sensor.auth import AuthPolicy


class AuthTest(unittest.TestCase):
    def test_allow_list_always_accepts(self):
        conn = AuthPolicy(["honey"], 0.0).for_connection()
        self.assertEqual(conn.attempt("root", "honey"), (True, True))
        self.assertEqual(conn.attempt("root", "nope"), (False, False))

    def test_zero_probability_rejects(self):
        conn = AuthPolicy([], 0.0).for_connection(random.Random(1))
        for user in ("a", "b", "root"):
            self.assertEqual(conn.attempt(user, "x"), (False, False))

    def test_roll_sticks_per_username(self):
        conn = AuthPolicy([], 0.5).for_connection(random.Random(7))
        first = conn.attempt("root", "a")
        for _ in range(20):
            self.assertEqual(conn.attempt("root", "whatever"), first)

    def test_usernames_roll_independently(self):
        # find a seed where two users disagree, proving independent rolls
        seen_split = False
        for seed in range(50):
            conn = AuthPolicy([], 0.5).for_connection(random.Random(seed))
            a = conn.attempt("alice", "x")[0]
            b = conn.attempt("bob", "x")[0]
            if a != b:
                seen_split = True
                break
        self.assertTrue(seen_split)

    def test_distribution_matches_probability(self):
        rng = random.Random(1234)
        accepts = 0
        trials = 2000
        for i in range(trials):
            conn = AuthPolicy([], 0.1).for_connection(random.Random(rng.randrange(1 << 30)))
            accepts += conn.attempt(f"u{i}", "x")[0]
        self.assertTrue(100 < accepts < 320, accepts)


if __name__ == "__main__":
    unittest.main()
