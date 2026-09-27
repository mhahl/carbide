"""D2 auth policy: allow-listed passwords always accept; otherwise one roll
per username per connection, decided on the first attempt with that username.
"""
import random


class AuthPolicy:
    def __init__(self, passwords, accept_probability):
        self.passwords = set(passwords)
        self.accept_probability = accept_probability

    def for_connection(self, rng=None):
        return ConnectionAuth(self, rng or random.Random())


class ConnectionAuth:
    def __init__(self, policy: AuthPolicy, rng):
        self._policy = policy
        self._rng = rng
        self._rolls: dict[str, bool] = {}
        self.attempts = 0

    def attempt(self, username: str, password: str) -> tuple[bool, bool]:
        """Returns (accepted, matched_allow_list)."""
        self.attempts += 1
        if password in self._policy.passwords:
            return True, True
        if username not in self._rolls:
            self._rolls[username] = (
                self._rng.random() < self._policy.accept_probability
            )
        return self._rolls[username], False
