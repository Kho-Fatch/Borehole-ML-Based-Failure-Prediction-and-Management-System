# UC-01: Manage System Users

**Primary Actor:** District Officer

**Goal:** Create, view, update and delete user accounts.

**Preconditions:**
- District Officer is authenticated.
- User management is available.

**Main Flow:**
1. District Officer opens Manage Users.
2. System displays registered users.
3. District Officer selects Add User.
4. District Officer enters full name, username, password and role.
5. System validates the information.
6. System checks username uniqueness.
7. System hashes the password.
8. System saves the account.
9. System confirms successful registration.

**Alternative Flows:**
- Missing information produces a validation message.
- Duplicate usernames are rejected.
- Existing accounts can be updated or deleted.

**Postconditions:** The requested account operation is completed.

**Acceptance Criteria:** Only District Officers can manage users, and passwords are securely hashed.
