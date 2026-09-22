"""RansomGuard IR VM detection agent (defensive, read-only monitoring).

This package monitors exactly one validated demo directory, applies
behavioral ransomware heuristics to directory snapshots, and reports a single
aggregated detection event to the FastAPI backend. It never modifies,
deletes, or renames any file. Python stdlib only.
"""

__version__ = "1.0.0"
