# Learning notes

Lessons written after a non-trivial piece of work lands. Each one explains what
was built, the decision behind it, the code that carries the decision, and what
would have broken had it gone the other way. ADRs record *what was decided*;
these record *what there is to learn from having decided it*.

Numbering is sequential at creation (`NNNN-kebab-title.md`), matching
[`docs/adr/`](../adr/README.md).

| # | Lesson | Subject |
| --- | --- | --- |
| [0001](0001-a-check-that-never-ran-and-a-claim-that-was-never-true.md) | A check that never ran, and a claim that was never true | Verification discipline: healthchecks that assert more than the system promises, and tests that assert an artifact instead of a verdict (ADR-0030, ADR-0031) |
