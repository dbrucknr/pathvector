# Project instructions

## RFC-governed behavior: implementation and testing discipline

This project implements BGP and related protocols across many RFCs
(4271, 4724, 7606, 9234, 5492, 6793, 6396, and more — see
`RFC_REQUIREMENTS.md`). A systematic clause-by-clause audit (`RFC_AUDIT.md`)
found multiple real, previously-undetected bugs in code that had passing
tests and looked correct — including cases where a test's own name cited
the correct RFC while asserting behavior that RFC actually prohibits. The
root cause in nearly every case: the implementation and its test were
derived from memory or from a plausible-sounding mental model of the
protocol, not from an independent, fresh read of the primary RFC text.

When implementing or modifying BGP wire-format or protocol-error-handling
behavior governed by an RFC:

1. **Fetch and read the specific RFC section directly** (e.g. via
   `curl https://www.rfc-editor.org/rfc/rfcNNNN.txt`) before writing code
   or tests. Do not rely on trained-in memory of "how BGP generally
   works" — quote the actual clause being implemented against.

2. **Check whether a later RFC amends that exact clause** before finalizing
   behavior. RFC 7606, RFC 8654, RFC 9234, RFC 9003, and RFC 6608 all
   revise specific clauses of RFC 4271 — a clause that's correct per
   RFC 4271 alone can be wrong once its amending RFC is checked. This
   project's own bug history includes exactly this failure mode: a
   correctly-implemented-per-RFC-4271 behavior that RFC 7606 silently
   revises.

3. **Derive each test's expected behavior independently from the RFC
   text, not from what the implementation currently does.** A test that
   merely characterizes existing code behavior will pass forever even if
   that behavior is wrong — it provides zero evidence of spec compliance.
   Cite the specific clause the test is proving.

4. **For any field that's nominally singular but the wire format allows
   repetition** (a capability, a path attribute, an optional parameter),
   explicitly identify and test the duplicate/conflict policy the spec
   requires. Do not let `.find()`/`.find_map()`'s implicit "first match
   wins" stand in for a real decision — check whether the spec wants the
   first instance, the last instance, or rejection on conflicting values.
   (This exact bug shape was found independently in both the Graceful
   Restart and BGP Role capability handling.)

5. **Test well-formed-but-policy-violating input, not just malformed
   bytes.** Fuzzing and malformed-input tests catch corrupted wire
   format; they do not catch a technically well-formed message from a
   technically-valid peer that violates a semantic/policy rule (e.g. an
   eBGP peer sending a LOCAL_PREF attribute that must be ignored). These
   need their own deliberately-constructed test cases informed by the
   RFC's error-handling and security-considerations sections.

See `RFC_AUDIT.md` for the full log of findings this discipline is meant
to prevent going forward, and `TODO.md` for the specific gaps still open.
