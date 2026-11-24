# Project Risk Register

**Project:** Rural Water Point Functionality Prediction Using Machine Learning
**Module:** Software Engineering – 351 CS 3201
**Date:** 24 November 2026

| ID | Risk | Likelihood | Impact | Mitigation | Status |
|---|---|---|---|---|---|
| R01 | Insufficient labelled borehole records | High | High | Collect and verify genuine field records; prevent unsupported model training | Open |
| R02 | Missing historical inspection dates | High | High | Introduce dated inspection records and document the limitation | Open |
| R03 | Incorrect or inconsistent borehole status labels | High | High | Apply controlled status values and data validation | Open |
| R04 | Incorrect GPS coordinates | Medium | High | Validate coordinates against Malawi geographic boundaries | Open |
| R05 | Model produces poorly calibrated probabilities | High | High | Evaluate calibration and reliability before operational use | Open |
| R06 | Unauthorized access to user information | Medium | High | Enforce role-based authorization and secure password storage | Open |
| R07 | Database loss or corruption | Medium | High | Schedule backups and test database restoration | Open |
| R08 | Slow dashboard response | Medium | Medium | Measure response times and optimize database queries | Open |
| R09 | Internet connectivity interruptions | High | Medium | Provide clear error handling and preserve submitted records safely | Open |
| R10 | Incorrect maintenance prioritization | Medium | High | Include risk, population served, repair lead time and human review | Open |
| R11 | Insufficient automated test coverage | High | High | Add unit, integration and functional tests | Open |
| R12 | Project delivery delays | High | High | Prioritize critical requirements and track tasks against the deadline | Open |
| R13 | Exposure of passwords or private user data | Medium | High | Exclude databases, secrets and private uploads from Git | Open |
| R14 | Unverified predictions are treated as confirmed failures | Medium | High | Label predictions clearly and communicate uncertainty | Open |
| R15 | Incomplete documentation and release evidence | High | Medium | Maintain the requirements, design, testing and release records | Open |

## Risk review

Risks should be reviewed throughout development. Likelihood and impact ratings are initial qualitative assessments and must be updated when evidence becomes available.

No risk is considered closed until its mitigation has been implemented and verified.
