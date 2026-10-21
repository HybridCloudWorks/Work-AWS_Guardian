# Cedar-first authorization

This page describes the single most important safety rule in the project. If you
remember nothing else, remember this: **the system is only allowed to change a
cloud resource after an outside policy engine says "yes."** Everything below
explains what that means and why it matters. Take your time with it.

## A few terms, explained simply

- **Authorization** means deciding whether an action is allowed. ("Is this
  request permitted?")
- **A dangerous action** (also called a "mutation") is anything that *changes*
  a cloud resource — for example, editing a firewall rule, turning on
  encryption, or rotating an access key. Reading or listing things is not
  dangerous; changing things is.
- **Cedar** is a policy language from AWS. You write rules in it that say what is
  allowed and what is forbidden, and a separate engine evaluates them. Think of
  it as the rulebook plus a referee that is independent of the application.
  ([Cedar docs](https://www.cedarpolicy.com/en) ·
  [AWS AgentCore policy + Cedar](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-understanding-cedar.html))
- **The Gateway / policy boundary** is that independent referee sitting between
  the application and the cloud. Every dangerous action must pass through it.

## The rules (please do not weaken any of these)

1. **Every dangerous action must go through the Gateway/policy boundary.**
   The application is never allowed to change a cloud resource directly. It must
   ask the Gateway, and the Gateway asks Cedar. This is what "Cedar-first" means.

2. **Never let the application authorize itself.** The decision must come from
   Cedar — never from any of these shortcuts:
   - a *prompt* (text sent to an AI model),
   - *memory* (something the system remembered from earlier),
   - *UI state* (what a toggle or button looks like on the screen), or
   - an *application boolean* (a simple true/false flag inside the code).

   These can all be wrong, spoofed, or manipulated, so none of them is allowed
   to grant permission. Only the external policy engine decides.

3. **"Forbid" always beats "permit."** In Cedar you can write both "permit"
   rules (allow this) and "forbid" rules (never allow this). If both match the
   same request, the **forbid wins** and the action is denied. There is no
   override.

4. **"Default deny" is the starting point.** If no rule explicitly permits an
   action, the answer is **no**. Silence means denied, never allowed.

5. **These two behaviors must be covered by tests.** Specifically, you must have
   automated tests proving that (a) a forbid rule overrides a permit, and (b) an
   action with no matching permit is denied. Do not consider the work done until
   those tests exist and pass.

## The sandbox tag rules

Two resource tags act as hard safety gates. ("Tags" are simple key-value labels
you attach to a cloud resource.)

- **Only allow a change when the target has the tag `CCGDemo=true`.** If a
  resource is not clearly marked as a demo/sandbox resource, the system must
  refuse to change it.
- **Always deny any change to a resource tagged `Environment=prod`.** Production
  resources are off-limits, no exceptions. Even if some other rule would permit
  the action, a `prod` tag means deny.

## Why this matters

This project's whole purpose is to *prove* that remediation is safe because an
independent policy engine authorizes it. If anyone bypasses the boundary — even
with good intentions, even "just for testing" — that proof is broken. So if you
are ever tempted to add a quick flag or shortcut that grants permission inside
the app, do not. Instead, express the rule in Cedar, or ask a maintainer how to
model it.

## If you are unsure

Security rules are exactly the kind of thing where guessing is risky. If a change
you are making touches authorization, policy, the Gateway, or these tags, pause
and ask a maintainer to review it before you go further.