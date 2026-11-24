# Software Requirements and Traceability

**Project:** Rural Water Point Functionality Prediction Using Machine Learning
**Module:** 351 CS 3201
**Baseline:** 24 November 2026

Status definitions:
- Built: Functionality exists in the current application.
- Partial: Some implementation exists, but it needs improvement or verification.
- New: Not yet implemented or not yet demonstrated.

| ID | Requirement | Status | Evidence or remaining work |
|---|---|---|---|
| FR-01 | Users shall log in using registered credentials. | Built | Flask authentication |
| FR-02 | The system shall support Trainee, Expert and District Officer roles. | Built | Role-based application |
| FR-03 | Users shall only access pages permitted for their roles. | Partial | Verify every protected route |
| FR-04 | District Officers shall manage system users. | Partial | Test add, edit, view and delete |
| FR-05 | Experts shall register and examine borehole information. | Built | Borehole management |
| FR-06 | Trainees shall record maintenance work. | Built | Maintenance task functionality |
| FR-07 | District Officers shall monitor field activities. | Partial | Verify monitoring and progress reports |
| FR-08 | Experts shall request an ML risk prediction. | Partial | Requires a trained, valid model |
| FR-09 | The system shall store risk calculations and the responsible Expert. | Partial | Verify successful prediction records |
| FR-10 | The system shall notify District Officers when risk reaches 60% or higher. | Partial | Verify notification behaviour |
| FR-11 | Maintenance activities shall update borehole risk information. | Partial | Automatic recalculation requires verification |
| FR-12 | The system shall train a model using labelled borehole records. | Partial | Current database has only two labelled records |
| FR-13 | The system shall predict non-functionality within four weeks. | New | Define and validate the prediction target |
| FR-14 | The system shall perform rolling-origin backtesting. | New | Implement weekly evaluation origins |
| FR-15 | The system shall perform leave-one-district-out validation. | New | Implement district-level validation |
| FR-16 | The system shall report PR-AUC, F1 and Brier scores. | New | Implement evaluation metrics |
| FR-17 | The system shall provide calibrated probabilities and uncertainty estimates. | New | Calibration and conformal prediction |
| FR-18 | The system shall identify and report poor-quality input records. | New | Cleaning report and rejected-row quarantine |
| FR-19 | The system shall rank maintenance priorities using risk and service factors. | New | Include population and repair constraints |
| FR-20 | The system shall provide automated tests and performance evidence. | Partial | Build test suite and record measured results |

## Current limitations

The current database does not contain enough labelled historical records for reliable model training or four-week backtesting. The new requirements must be implemented and tested before they can be marked Built.

No test results, participant responses or model performance figures are claimed in this document.
