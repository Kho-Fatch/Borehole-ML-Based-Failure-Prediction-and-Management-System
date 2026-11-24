# ADR-004: Role-Based Access Control

**Status:** Accepted

## Context
District Officers, Experts and Trainees have different responsibilities and must not access unauthorized information.

## Decision
Use role-based access control with server-side authorization checks.

## Consequences
- Separates responsibilities.
- Restricts access to protected routes.
- Requires authorization tests for every protected role.
