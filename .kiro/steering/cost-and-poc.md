# Cost and POC

This project is a **proof of concept** (POC) — a small, inexpensive version built
to prove an idea works, not a full production system. Because of that, keeping it
cheap and simple is a real requirement, not just a nice-to-have. This page lists
the cost and design rules. Please follow them so we do not get a surprise cloud
bill or accidentally build something heavier than intended.

## The budget

- **Keep the running cost under $150 per month.** If a change you are making
  could push spending above that, stop and raise it with a maintainer before
  proceeding. When in doubt about what something costs, check the provider's
  pricing page or ask.

## Use serverless, event-driven resources

- **Prefer "event-driven" and "serverless" resources.** "Event-driven" means
  things run in response to an event (like a scheduled timer firing) rather than
  running all the time. "Serverless" means you do not manage an always-on
  server; the cloud provider runs your code on demand and you only pay for what
  you use. Both keep costs low because nothing idles while waiting for work.
  ([AWS serverless overview](https://aws.amazon.com/serverless/))

## Things to avoid (these cost too much for a POC)

Do **not** add any of the following unless a maintainer has explicitly approved
it, because each one adds ongoing cost or complexity a POC should not carry:

- **No NAT Gateway.** A NAT Gateway is a networking component that lets private
  resources reach the internet; it bills per hour and per gigabyte, so it is
  expensive to leave running. Avoid designs that need one.
- **No provisioned-capacity DynamoDB.** DynamoDB is AWS's NoSQL database. It has
  two billing modes: "on-demand" (pay per request) and "provisioned" (pay for
  reserved capacity around the clock). Use on-demand; provisioned capacity costs
  money even when idle.
- **No always-on compute.** Do not run servers or containers that stay up 24/7.
  Use the on-demand, serverless options instead.
- **No multi-AZ topology.** "Multi-AZ" means running copies across several
  Availability Zones (separate data centers) for high availability. That is
  great for production but doubles or triples cost, so it is out of scope for
  this POC.

## Data retention (how long we keep logs and records)

- **Logs are kept for 7 days.** "Logs" are the records of what the system did.
  Seven days is enough to debug a POC without paying to store them forever.
- **S3 audit data expires after 30 days.** S3 is AWS's object storage. The audit
  records we write there should be set to automatically delete after 30 days
  using a "lifecycle rule" (a setting that expires old objects for you).

## Voice is off by default

- **The voice feature starts turned off.** The project has an optional
  voice-briefing feature. It must default to **off** and only turn on when
  someone deliberately enables it and grants consent. Leaving it off by default
  avoids both cost and privacy surprises.

## If you are unsure

If a change might increase cost, add an always-on resource, or change how long
data is kept, check with a maintainer first. Catching it before it ships is far
easier than cleaning up afterward.