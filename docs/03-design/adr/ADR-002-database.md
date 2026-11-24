# ADR-002: SQLite Database

**Status:** Accepted for the current implementation

## Context
The existing application needs persistent storage for users, boreholes and maintenance records.

## Decision
Retain SQLite for the current project implementation.

## Consequences
- Simple local deployment.
- No separate database server required.
- Concurrent access and production scaling must be evaluated.
