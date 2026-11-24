# ADR-003: Random Forest Classifier

**Status:** Proposed; operational validation pending

## Context
The system aims to estimate the likelihood that a water point is non-functional.

## Decision
Use a Random Forest classifier as the initial prediction algorithm.

## Consequences
- Supports mixed numerical and categorical features through preprocessing.
- Can model nonlinear relationships.
- Requires sufficient labelled data and independent evaluation.
- Predictions must not be treated as reliable until validation is completed.
