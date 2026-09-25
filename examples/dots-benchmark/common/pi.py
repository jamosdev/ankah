"""The one Pi implementation shared by the FastAPI and Django backends.

Midpoint-rule integration of 4 / (1 + x^2) over [0, 1] in a plain Python
loop. It is deterministic, CPU bound, holds the GIL for its whole run and
allocates nothing per step, so both frameworks do identical work for the
same n.
"""

DEFAULT_N = 200_000
MAX_N = 2_000_000


def parse_n(raw):
    """Returns n for a query value, or None when it is not acceptable."""
    if raw is None or raw == "":
        return DEFAULT_N
    if not raw.isdigit() or len(raw) > 8:
        return None
    n = int(raw)
    return n if 1 <= n <= MAX_N else None


def compute_pi(n):
    step = 1.0 / n
    total = 0.0
    for i in range(n):
        x = (i + 0.5) * step
        total += 4.0 / (1.0 + x * x)
    return total * step


def client_class(user_agent):
    """Bounded metric label from the demo's fixed User-Agent values."""
    agent = user_agent or ""
    if agent.startswith("dots-demo-attacker"):
        return "attacker"
    if agent.startswith("dots-demo-legit"):
        return "legit"
    if agent.startswith("dots-demo-ready"):
        return "ready"
    return "other"
