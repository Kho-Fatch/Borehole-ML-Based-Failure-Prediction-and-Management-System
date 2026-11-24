# UC-02: Calculate Borehole Failure Risk

**Primary Actor:** Expert

**Goal:** Estimate the probability that a borehole is non-functional.

**Preconditions:**
- Expert is authenticated.
- Borehole exists.
- A trained model is available.

**Main Flow:**
1. Expert opens borehole records.
2. Expert selects a borehole.
3. System displays available information.
4. Expert selects Calculate Risk.
5. System validates the borehole information.
6. System loads the trained model.
7. Model estimates the probability of non-functionality.
8. System saves the result and calculation time.
9. System associates the calculation with the Expert.
10. System displays the result.

**Alternative Flows:**
- If no trained model exists, the system reports that prediction is unavailable.
- Invalid information is rejected.
- Model errors are reported without inventing a score.
- A score of at least 60% triggers a District Officer notification.

**Postconditions:** A successful prediction is stored and can be reviewed by authorized users.

**Acceptance Criteria:** Only Experts can calculate risk, and predictions are identified as estimates.
