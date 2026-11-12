# Approved wordlists

The agentic ffuf step only accepts a wordlist path that resolves inside this folder
(see `APPROVED_WORDLIST_DIR` in `sanitiser.py`). Anything outside it is dropped.

Put vetted wordlists here, for example a path-discovery list from SecLists. Keep
files small and reviewed; the model may name any file in this folder.
