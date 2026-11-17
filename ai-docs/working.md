# Working State
Last updated: 2026-11-18 01:53 | Gemini 3.8 Flash | Status: ACTIVE

## Task
Phase 4: Evaluation package (com.team.attackmap.eval). Handoff to Shambhavi.

## Approval status
- Plan approved by user? YES
- Exact scope approved: Step A completed, audited, and pushed to remote; ready for Step B upon "next".

## Plan (checklist)
- [x] Step A — GoldRecord + GoldCsvLoader (COMPLETED, 43 tests green, pushed)
- [ ] Step B — RetrievalMetrics tests, stubs, show failing; implement; green (NEXT)
- [ ] Step C — Evaluator + CSV writer tests, stubs, show failing; implement; green
- [ ] Step D — README, ai-docs, working.md IDLE

## Files touched
- `src/main/java/com/team/attackmap/eval/LabelType.java`
- `src/main/java/com/team/attackmap/eval/GoldFormatException.java`
- `src/main/java/com/team/attackmap/eval/GoldRecord.java`
- `src/main/java/com/team/attackmap/eval/GoldCsvLoader.java`
- `src/test/java/com/team/attackmap/eval/GoldCsvLoaderTest.java`
- `ai-docs/Handover.md`

## Current repo state
- Branch: main / commit e04a054 (synced with origin/main)
- Uncommitted changes: none (all clean)
- Tests: 182 passing, 0 failures, 0 errors, 1 skipped

## Last action and result
Audited codebase (compiler `-Xlint:all -Werror`, full test suite, security/secrets review, RFC 4180 parsing checks). Pushed to `origin/main`. Prepared handoff documentation for Shambhavi.

## Next action (resume here)
Proceed with **Phase 4 Step B: RetrievalMetrics**:
1. Implement pure static functions in `com.team.attackmap.eval.RetrievalMetrics`:
   - `bestGoldRank(List<String> rankedIds, Set<String> gold)`: 1-based rank of the first predicted ID that is in gold; 0 if none.
   - `topK accuracy`: fraction of ranked sentences with `1 <= rank <= k`.
   - `MRR`: mean of `1/rank`, 0 for rank 0.
   - `detection precision/recall/F1 at threshold t`: predicted positive iff the top prediction score >= t (empty ranking = negative); gold positive iff `technique_ids` is non-empty. Any technique counts, correctness not checked.
   - Zero division returns 0.0 explicitly. Results are records carrying sample size n (empty input gives n=0 and metrics 0.0).
   - Javadoc stating exact mathematical formulas.
2. Unit tests in `RetrievalMetricsTest` (write tests first, show failing against stub, then implement):
   - S1 gold {A} ranking [A,B,C] -> rank 1; S2 gold {B} ranking [A,B,C] -> 2; S3 gold {C} ranking [A,B] -> 0; S4 gold {A,C} ranking [B,C,A] -> 2. top-1 = 0.25; top-2 = 0.75; MRR = (1+0.5+0+0.5)/4 = 0.5.
   - Detection: negatives N1 top score 0.1, N2 empty ranking; positives P1 0.8, P2 0.3, P3 empty. At t = 0.25: TP=2, FP=0, FN=1 -> precision 1.0, recall 2/3, F1 0.8.
   - 4+ additional hand-computed cases, empty input, k <= 0, and ties in rank.
3. Rules: no magic numbers outside Config; zero -Xlint:all warnings; never weaken a test.

## Blockers / open questions
None. Shambhavi can say "next" or start directly on Step B.

## Do not redo
Phases 1, 1b, 2, 3, and Phase 4 Step A are completed, green, and pushed to GitHub.
