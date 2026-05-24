// Borderline-clean: ``$where`` with a STATIC string (no template
// interpolation, no user input). Codex Phase 2-I diff review pin —
// the secscan-js-mongo-where-template-injection rule must NOT fire
// here. If it does, that's a false positive on legitimate MongoDB
// query DSL.

const safeQueryDescription = "this.x == 1 && this.y > 2";

function safeWhereStaticString() {
  // Not a template literal — no `${...}`. Safe.
  return { $where: "this.x == 1 && this.y > 2" };
}

function safeWhereStaticTemplate() {
  // Template literal but with NO interpolation — safe.
  return { $where: `this.x == 1` };
}

// A property of an object that happens to use ``$where`` as a key
// inside a builder DSL but where the value is precomputed and not
// a template literal at all.
const dslQuery = { $where: safeQueryDescription };

module.exports = { safeWhereStaticString, safeWhereStaticTemplate, dslQuery };
