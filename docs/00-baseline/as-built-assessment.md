# As-Built System Baseline

**Project:** Rural Water Point Functionality Prediction Using Machine Learning
**Module:** Software Engineering – 351 CS 3201
**Baseline date:** 24 November 2026

## 1. Existing system

The existing application is a Flask-based borehole management system.
It provides role-based access for District Officers, Experts and Trainees.

Existing functionality includes:
- User authentication and role-based access.
- Borehole registration and monitoring.
- Expert-initiated risk calculation.
- District Officer model training.
- High-risk notifications using a 60% threshold.
- Maintenance task management.

## 2. Baseline database findings

The inspected GitHub project database contains:
- Total borehole records: 8.
- Labelled borehole records: 2.
- Unknown-condition records: 6.
- Risk calculations: 0.
- Historical risk records: No risk_history table.
- Field inspection records: No field_inspections table.

Only two records are currently eligible for supervised model training.

## 3. Machine-learning limitations

The existing model uses a Random Forest classifier and a random train/test split.

The system requires at least 20 labelled boreholes and examples from both functionality classes.

The current dataset is insufficient for reliable model training.

The existing implementation does not yet provide:
- Rolling-origin backtesting.
- Leave-one-district-out validation.
- PR-AUC, F1 and Brier score reporting.
- Probability calibration and reliability diagrams.
- Conformal prediction intervals or sets.

## 4. Data limitations

The current database does not contain sufficient historical inspection records to establish four-week failure outcomes.

Historical backtesting and empirical uncertainty coverage therefore cannot currently be verified.

No synthetic records will be represented as genuine field observations.

## 5. Immediate improvement priorities

1. Preserve and consolidate the existing application.
2. Improve model evaluation and validation.
3. Introduce transparent data-quality reporting.
4. Add automated unit and functional tests.
5. Improve documentation, diagrams and traceability.
6. Record outstanding limitations honestly.

## 6. Baseline conclusion

The existing application provides a working foundation for borehole management.
However, its predictive capability has not yet been adequately validated.
Further real labelled field data and historical inspection records are required
before the system can claim reliable failure prediction.
