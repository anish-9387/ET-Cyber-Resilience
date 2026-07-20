"""Test suite for the Sentinel backend.

These are the repository's first tests. They target correctness properties that
the project's claims actually depend on:

* ``test_world_model``  - the Bayesian belief update behaves like a Bayesian
  belief update (evidence raises P, contradicting evidence lowers it,
  confidence grows with independent corroboration).
* ``test_detection``    - the detector emits well-formed, bounded output.
* ``test_evaluation``   - evaluation metrics are in range, internally
  consistent, and every automated decision leaves an audit record.
"""
