# SEMP

SEMP is an Erlang application implementing TRUST (Trusted, Rapid, Unmodifiable, Secure Topology) as a custom, DNS-based, **non-EPMD** distribution overlay. Each RPC uses connect→(token path)→call→close.

- TLS 1.3 mTLS with client certs
- Whitelist via SHA-512 of TBSCertificate
- Token-accelerated reconnect (short TTL)
- Per-node permissions (modules/functions) + suspicion levels
- No errors are sent to clients; server logs + adjusts suspicion and closes

## Layout

- `src/` modules (incl. `trust_dist.erl` carrier)
- `include/semp.hrl`
- `priv/certs/` (dev-only)
- `rebar.config`, `.gitignore`, `LICENSE.md`, `README.md`

## Build

```bash
rebar3 compile
rebar3 shell




# TEMPUS + Cyclon: Secure, Unbiased Peer Sampling

TEMPUS is a secure peer–sampling and membership layer that uses the **Cyclon** gossip protocol to keep three **independent** peer sets fresh and unbiased—**within a single process**. Each peer set (“type”) has its own Cyclon view, capacity, and shuffle cadence. There is **no cross-type shuffle**.

The goal: a highly and robustly secure system where peers are cryptographically verifiable, churn is handled gracefully, and sampling remains uniform **within** each population.

---

## Peer Types (three isolated Cyclon views)

We track three populations side-by-side:

- **Type 1 — `tempus_edge` (ephemeral)**  
  High-churn, short-lived peers (formerly called `tempus`). These form the bulk of the mesh and do standard Cyclon shuffles among themselves.

- **Type 2 — `tempus_bridge` (non-ephemeral)**  
  Longer-lived peers that **bridge** to separate **TRUST** overlays/instances. They shuffle **only** with other `tempus_bridge` peers. Application logic uses them to reach TRUST—Cyclon state stays isolated.

- **Type 3 — `tempus_sentinel` (non-ephemeral; membership guardians)**  
  Longer-lived peers that ephemeral nodes use to **prove producer-authorized membership**. They run Cyclon among themselves for availability, and act as admission guardians (see “Identity & Admission”).

> You may run different counts of each type. The only invariant is **no cross-type mixing**.

---

## How Cyclon is used in TEMPUS

- One TEMPUS server maintains **three independent Cyclon stores**:  
  `tempus_edge`, `tempus_bridge`, `tempus_sentinel`.
- Each store has: fixed **capacity**, shuffle size **l**, independent **tick** (periodic timer), and maintains `(peer, age)` entries.
- **Within a store** on each tick:
  1. Increment ages.
  2. Pick the **oldest** neighbor as the shuffle partner.
  3. Prepare an outgoing buffer (include `{self, age=0}`), remove sent entries from the local view.
  4. On merge, prefer **younger** entries; **evict oldest** to respect capacity.
- **Across stores**: there is **no exchange** of entries; each population remains unbiased relative to itself.

---

## Identity & Admission (security model)

TEMPUS separates **sampling** (Cyclon) from **trust** (admission). A peer only enters a store after proving it’s an authorized instance of your product—**without any shared secret** among peers.

**Core elements:**

1) **Per-install asymmetric identity**  
Each node generates an **Ed25519** keypair on first run and derives a `peer_id` from the public key. No symmetric keys are shared between peers.

2) **Producer-signed, short-lived tokens**  
Your backend (“producer”) issues **very short-lived** tokens (e.g., 2–5 minutes) that bind to the peer’s public key (`sub`) and include role/type (`typ ∈ {tempus_edge, tempus_bridge, tempus_sentinel}`).

3) **No-overlap key rotation (strict)**  
Verifiers pin to the **current** signing key via `kid` (key id). At rotation, tokens signed with an old key are **rejected** with a precise “rotated key” error; legitimate peers immediately re-fetch a token under the new key. Tight TTLs + proactive refresh (`TTL/2`) keep recovery fast.

4) **Proof-of-Possession (POP)**  
When presenting a token, the peer signs a fresh challenge with its **own** private key (the same public key carried in `sub`). Replay of copied tokens fails without the private key.

5) **Platform attestation for app-store builds**  
On iOS use **App Attest** (and on Android **Play Integrity**) during token issuance so your backend only signs tokens for genuine, unmodified builds on real devices.

**Outcome:** Only peers with **valid, current** producer signatures **and** POP are admitted to the appropriate Cyclon store. Bad actors without both are excluded.

---

## Sequence (high level)

```mermaid
sequenceDiagram
    participant P as Peer (tempus_edge / bridge / sentinel)
    participant A as Platform Attestation (App Attest / Play Integrity)
    participant I as Producer Issuer (Token Service)
    participant V as Verifier Peer
    participant C as TEMPUS (Cyclon Store)

    Note over P: Generate Ed25519 keypair → derive peer_id
    P->>A: Request attestation for this app/device
    A-->>I: Attestation evidence (to be validated)
    P->>I: {peer_pub, typ} + attestation proof
    I-->>I: Validate attestation; check policy
    I-->>P: Short-lived token (kid=current, sub=peer_pub, typ, nbf/exp)

    Note over P: Build advert {peer_id, peer_pub, token, typ}
    P->>V: Advert + POP challenge response on request

    V-->>V: Check kid==current; verify token signature; check nbf/exp; sub==peer_pub
    V->>P: POP challenge (fresh nonce)
    P-->>V: Signature over (nonce || token) using peer_priv
    V-->>V: Verify POP with peer_pub (from token.sub)
    V->>C: Admit peer into store by typ (no cross-type mixing)
