# Migrating Draft 1.x Artifacts to Candidate 2.0

Candidate 2.0 is intentionally breaking. Do not relabel an old assessment by
changing only its version header.

Required migration:

1. Reassess EX. Version 2.0 classifies the enforceability of the reachable
   extension boundary; it no longer treats the number of mechanism types as a
   risk measure.
2. Reassess SR. Empirical values now use independent full-budget attack
   episodes and one-sided 95% Wilson bounds. Raw success percentages and
   independence assumptions from individual retries are not accepted.
3. Change the extension header from `AIVSS:1.2` to `AIVSS:2.0` only after EX
   and SR have been reassessed.
4. Add an RFC 3339 `provenance.assessed_at` timestamp.
5. Validate inputs and reports against the 2.0 schemas. Reports now disclose
   `agentic_effect_class_status`, and incomplete calculations report the
   zero-impact invariant as null because no adjustment ran.
6. For KEV-listed CVEs, supply CISA-published Automatable and Technical Impact
   data. Candidate 2.0 does not apply missing-metadata defaults to KEV entries.

The experimental adjustment keeps the same numeric constants, but its weight
set identifier changed because the EX construct changed. Scores from the old
and new weight-set identifiers must not be compared as if they used identical
semantics.
