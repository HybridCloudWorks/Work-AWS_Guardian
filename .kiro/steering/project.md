# Project conventions

Welcome! This page explains how we like code to be written in this project. If
you are new here, read it once before you make changes — it will save you a lot
of back-and-forth in code review. Nothing here is complicated once it is spelled
out, so let us go through it in plain language.

## What each part of the project is built with

This project has three pieces, and each one uses a specific technology. Please
stick to these so everything stays consistent:

- **The agents** (the background logic that does the compliance checks) are
  written in **Python, version 3.14**. "Agents" here just means small programs
  that run on their own to inspect things. Use 3.14 specifically — not an older
  or newer version — because the rest of the tooling is set up for it.
  ([Python 3.14 docs](https://docs.python.org/3.14/))
- **The console** (the web page an admin looks at) is written in
  **TypeScript** using the **Next.js** framework. TypeScript is JavaScript with
  type-checking added so mistakes get caught early; Next.js is a popular
  framework for building web apps in React.
  ([Next.js docs](https://nextjs.org/docs) · [TypeScript docs](https://www.typescriptlang.org/docs/))
- **The infrastructure** (the cloud resources themselves — storage, permissions,
  and so on) is defined with **Terraform**. Terraform lets you describe cloud
  resources in text files instead of clicking around a console, which is called
  "Infrastructure as Code" (IaC).
  ([Terraform docs](https://developer.hashicorp.com/terraform/docs))

## How to write the code

When you add or change code, please follow these habits. Each one has a short
reason so it is clear why we ask for it:

- **Use typed contracts.** A "contract" is a clearly defined shape for the data
  that moves between parts of the system (for example, exactly which fields a
  "finding" has). Writing these down as types means the computer checks them for
  you and other developers know what to expect.
- **Write structured JSON logging.** When the code records what it did (a
  "log"), write it as JSON (a structured, machine-readable format) rather than
  plain sentences. This makes logs searchable and easy to analyze later.
- **Include correlation IDs.** A correlation ID is a unique label attached to
  one request as it travels through the system. If something goes wrong, this ID
  lets you follow that single request across all the logs. Always carry it
  through.
- **Follow least privilege.** "Least privilege" means every part of the system
  should have the smallest set of permissions it needs to do its job, and
  nothing more. If a component only needs to read, do not give it permission to
  write or delete.
- **Add unit tests.** A unit test is a small automated check that proves one
  piece of code behaves correctly. Add tests when you add behavior, so future
  changes do not quietly break it.
- **Use interfaces and test doubles.** An "interface" is an agreed-upon set of
  methods a component promises to provide. A "test double" is a stand-in used
  during testing (for example, a fake version of a cloud service) so tests can
  run quickly and safely without touching real systems.
- **Never put secrets or state in Git.** "Secrets" are passwords, API keys,
  tokens, or account IDs. "State" is Terraform's record of your real
  infrastructure. Neither should ever be committed to the repository — this is a
  public repo, and leaking a secret is a serious incident. If you are unsure
  whether something is sensitive, treat it as sensitive and ask before
  committing.

## If you are not sure

When something here is unclear or seems to conflict with what you are trying to
do, stop and ask a maintainer rather than guessing. It is always cheaper to ask
first than to undo a mistake later.