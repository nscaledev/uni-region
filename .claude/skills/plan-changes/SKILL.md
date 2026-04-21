---
name: plan changes
description: 
---

When starting an implementation from a design, before making edits,
first work out with the user a series of commits to achieve the
design.

**Plan as commits**

The plan consists of a series of commits that are self-contained, and
when all applied, implement the design. The plan does not have to
specify each diff exactly, just the series of steps.

Each commit should make a single logical change. For example, a
refactor, or the addition of interrelated API definitions.

**Generated code**

Changes to generated code should go in the commit that provoked the
regeneration. A common example is
pkg/openapi/router.go, generated from server.spec.yaml in the same
directory.

To make the code compile after regenerating code, it may
be necessary to fill in stubs.

**Ordering the changes**

Think about which steps depend on which others. It may be necessary to
refactor a package or introduce an abstraction, to make a later change
possible. Prefer refactoring to adding abstractions.

A commit should come with proof that it works, or at least a
justification. This will often be a test. With each step the plan
should include an outline of how to test the change made in the
commit.

Refactors may need additional tests to prove they have not changed
behaviour. You should think about what it is necessary to demonstrate.

The code should compile and pass tests after each commit. Strive to
make each commit safe to merge to main branch on its own. This may not
always be possible: when not, explain why not and work on mitigations
with the user.

**Backward-compatibility**

Most changes should be backward-compatible. In practice this may mean
introducing new API or struct fields alongside old ones, and
converting between them. Migrations generally go like this:

1. Introduce a new field or API surface, and convert between it and
   the old one
2. Port callers to the new API or field
3. Deprecate the old API
