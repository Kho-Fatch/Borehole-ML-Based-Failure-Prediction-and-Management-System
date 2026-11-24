# UC-03: Record Borehole Maintenance

**Primary Actor:** Trainee

**Goal:** Record repairs or equipment installations.

**Preconditions:**
- Trainee is authenticated.
- Borehole exists.
- Trainee has permission to record maintenance.

**Main Flow:**
1. Trainee opens the maintenance module.
2. System displays available assigned work.
3. Trainee selects a borehole.
4. Trainee enters repair or installation details.
5. Trainee enters the work date.
6. System validates the information.
7. System saves the maintenance record.
8. System updates maintenance progress.
9. Authorized District Officers can review progress.

**Alternative Flows:**
- Missing information is rejected with a message.
- Unknown boreholes are rejected.
- Saving errors are reported.

**Postconditions:** A successful maintenance activity is recorded.

**Acceptance Criteria:** The responsible Trainee is recorded, and Trainees cannot view Experts' private work progress.
