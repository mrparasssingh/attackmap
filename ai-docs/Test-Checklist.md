# Test Checklist

Concrete commands to run and expected output before any change counts as done.

## Phase 1 Checks

1. **Clean Test Execution**:
   - Command: `mvn -q test`
   - Expected Output: Exit code 0, 0 failures, 0 errors.

2. **Parser Coverage Checks (JUnit 5)**:
   - `StixParserTest`:
     - Parses standard `attack-pattern` objects into `Technique`.
     - Extracts MITRE ID (`T1059`, `T1059.001`), name, description, tactics from `kill_chain_phases`.
     - Skips objects where `type != "attack-pattern"`.
     - Skips objects marked `revoked: true`.
     - Skips objects marked `x_mitre_deprecated: true`.
     - Includes sub-techniques when `includeSubTechniques = true`.
     - Excludes sub-techniques when `includeSubTechniques = false`.
     - Edge Cases:
       - Empty JSON / empty bundle objects list (`[]`).
       - Malformed JSON handling (throws descriptive parsing exception).
       - Attack pattern missing description or tactics (graceful defaults: empty list / empty string, never null pointer crash).
       - Non-ASCII / Unicode characters in description and names (e.g. smart quotes, em-dashes, accented characters).
       - Objects with unknown external references or missing `mitre-attack` source (skipped safely).

3. **Compiler & Warnings Check**:
   - Command: `mvn clean test-compile`
   - Expected: Compiles cleanly with no warnings or errors.

