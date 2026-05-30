# pathvector-policy

BGP route policy engine for the [pathvector](https://github.com/dbrucknr/pathvector) ecosystem.

---

## What is a BGP route policy?

Every route entering or leaving a BGP router runs through a *policy* — a program that inspects the route's attributes and decides what to do with it. In Junos these are called policy-statements; in IOS they are route-maps. In pathvector they are [`Policy`] values made up of [`Term`]s.

A policy is an ordered list of terms. Each term has two parts:

- **Condition** — does this route match? (prefix in a list, community present, AS path length, etc.)
- **Action** — what do we do if it matches? (accept, reject, set local-pref, prepend AS path, etc.)

Evaluation is **first-match-wins**: terms are checked in order. The first term whose condition matches has its action applied, and evaluation stops. If no term matches, a configurable **default action** (`Accept` or `Reject`) applies.

```text
                 route
                   │
          ┌────────▼────────┐
          │     Term 1      │  condition matches? ──no──▶ next term
          │  condition      │
          │  action         │  yes
          └────────┬────────┘
                   │ Action: Accept / Reject / Next (fall through)
                   ▼
             final decision
```

A real example — "prefer routes from ISP-A, deprioritise ISP-B, reject everything else":

```text
term prefer-isp-a:
  if community == 65001:100 → set local-pref 200, accept

term deprioritise-isp-b:
  if community == 65002:100 → set local-pref 50, accept

term default-reject:
  (no condition — matches everything)  → reject
```

---

## Dispatch design

The policy engine uses a **hybrid dispatch** model that keeps the common-case fast while remaining ergonomic.

`Term<C, A>` is fully generic (monomorphized). The condition type `C` and action type `A` are resolved at compile time — zero vtable overhead inside a term's match/action logic.

`Policy<R>` holds `Vec<Box<dyn EvaluateTerm<R>>>`. There is exactly **one vtable call per term** when iterating the policy. BGP is a control-plane protocol (thousands of route updates per second, not millions per microsecond), so this single indirection is negligible compared to the actual attribute inspection work.

---

## Core types

| Type | Description |
|---|---|
| [`BgpRoute`] | Trait that route types implement to participate in policy evaluation |
| [`Decision`] | What a policy returns: `Accept`, `Reject`, or `Next` |
| [`DefaultAction`] | What happens when no term matches |
| [`Condition`] | Trait for match logic; inspects a route by reference |
| [`Action`] | Trait for action logic; modifies a route via `&mut` and returns a `Decision` |
| [`Term`] | A condition paired with an action |
| [`Policy`] | An ordered list of terms with a default action |

---

## Built-in conditions

| Type | Matches when… |
|---|---|
| [`AnyCondition`] | Always — useful as a catch-all final term |
| [`Not<C>`] | The inner condition does not match |
| [`PrefixListCondition<A>`] | The route's prefix falls within an [`IpSet`](ipnetx::ipset::IpSet) |
| [`CommunityCondition`] | The route carries a specific standard community |
| [`LargeCommunityCondition`] | The route carries a specific large community |
| [`AsPathContainsCondition`] | The AS path contains a specific ASN |
| [`AsPathLengthCondition`] | The AS path length satisfies a comparison |
| [`LocalPrefCondition`] | `LOCAL_PREF` satisfies a comparison |
| [`MedCondition`] | `MED` satisfies a comparison |
| [`OriginCondition`] | `ORIGIN` equals a specific value |

---

## Built-in actions

| Type | Effect |
|---|---|
| [`Accept`] | Accept the route — terminal |
| [`Reject`] | Reject the route — terminal |
| [`Next`] | Fall through to the next term without modifying |
| [`SetLocalPref`] | Set (or clear) `LOCAL_PREF` |
| [`SetMed`] | Set (or clear) `MED` |
| [`SetOrigin`] | Set `ORIGIN` |
| [`PrependAsPath`] | Prepend an ASN one or more times |
| [`AddCommunity`] | Add a standard community |
| [`RemoveCommunity`] | Remove a specific standard community |
| [`SetCommunities`] | Replace the full community list |
| [`AddLargeCommunity`] | Add a large community |
| [`RemoveLargeCommunity`] | Remove a specific large community |
| [`SetNextHop`] | Set `NEXT_HOP` |
| [`ActionSequence`] | Run a sequence of actions in order |

---

## License

MIT
