# LumerinDiamond approval findings — Foundry fork PoC

Local fork testing only. No mainnet transactions, no real funds, no emails.
All state changes happen on a local Foundry fork of Base; `deal()` mints
fork-local MOR/ETH to throwaway test accounts. Nothing is broadcast.

Target: LumerinDiamond `0x6aBE1d282f72B474E54527D93b979A4f64d3030a` (Base),
SessionRouter facet `0x3a3952f0E57b343F00b31F7dA039eF16389B7260`.
Full analysis: `../audit-lumerin.md`.

## Run

```bash
forge test
```

No setup beyond an RPC URL if you want to override the default:

```bash
BASE_RPC_URL=https://base-rpc.publicnode.com FORK_BLOCK_NUMBER=58179707 forge test
```

Defaults: RPC `https://base-rpc.publicnode.com`, pinned fork block **58179707**
(2026-11-16 ~10:52 UTC). Verified working from this sandbox; `mainnet.base.org`
and `base.meowrpc.com` also answered `eth_blockNumber` at build time.
`base.llamarpc.com` returned HTTP 525, `1rpc.io/base` is rate-limited — not used.

First run ≈ 40 s (fetches fork state); later runs use the local cache (~1 s).
Result: **4 passed, 0 failed.**

## Method note (read this before citing the PoC)

The live bid's provider key is unknown, and `openSession` verifies the approval
signature against `bid.provider` — so the victim's approval cannot be forged
for a *live* bid. The vulnerability is in the deployed SessionRouter facet code,
which is identical for every bid. The PoC therefore:

1. reads and asserts a **real live bid on the fork** in every `setUp`
   (deepseek-v4-flash-0731: bid `0x59fffb…bdfc`, provider
   `0xfF460118796438Aa9c6BEE56B99e300b95E42dbB`, price 52,777,777,777,778 wei/s,
   provider stake 150,000 MOR — all asserted on-chain in the test);
2. registers its **own provider/model/bid on the forked diamond** at that live
   price, with a provider key the test controls;
3. attacks that bid. All stipend / funding-account / MOR accounting uses live
   fork state (real `computeBalance`, `totalSupply`, funding-account balance
   and allowance).

What this proves: the *contract* accepts a mis-bound / expired approval and
pays out of the funding account. What it does not prove: anything about a
specific live provider's off-chain behaviour (e.g. whether a given provider
would ever issue an approval an attacker could observe).

## Results

### Finding 1 — HIGH: approval not bound to user — REPRODUCED (PASS)

`test_F1_ApprovalForVictimUsableByAttacker`

- Provider signs an approval for **victim** only, in the exact production
  format `abi.encode(bidId, chainId=8453, user=victim, timestamp)` with a
  millisecond timestamp, signed as an EIP-191 message — the same construction
  as `InitiateSessionResponse` in `proxy-router/.../mor_rpc.go`.
- **Attacker** (fresh EOA, own 10,000 MOR stake + allowance) calls
  `openSession(user=attacker, …, isDirectPaymentFromUser=false)` with the
  victim's approval: **succeeds**. Session `0x1bf001fb…c983`, user = attacker,
  duration 553,552 s (~6.4 days).
- Victim's own `openSession` with the same approval then **reverts
  `SessionDuplicateApproval`** — the approval is burned, victim must re-request.
- After warping to `endsAt`, `claimForProvider` pays the provider
  **29.215244444444565 MOR** — exactly `(endsAt - openedAt) × price`, i.e. the
  full stipend for a 10,000 MOR stake (stipend 29.215286882124133 MOR; the
  0.00004 MOR gap is the <1 s integer-division rounding in `getSessionEnd`).
  The whole 29.215… MOR comes **from the funding account**
  (`0x5160C0311A95E0A1072FA85Df23712A7BA1cD4b1`, balance 85,224 MOR at the fork
  block). The provider never agreed to serve the attacker.
- Scaling at live rates: 100,000 MOR staked ⇒ ~292.15 MOR per stolen approval.

### Finding 2 — MEDIUM: approval TTL dead in production (ms vs seconds) — REPRODUCED (PASS)

`test_F2_MsTimestampApprovalNeverExpires` + control
`test_F2_Control_SecondsTimestampDoesExpire`

- Approval with timestamp **7 days old, in milliseconds** (as the production
  Go signer emits via `UnixMilli()`): `openSession` **succeeds**, session active.
  The 10-minute TTL never fires because `block.timestamp` (seconds, ~1.79e9)
  is compared against a millisecond value (~1.79e12).
- Control: the identical approval with a timestamp **11 minutes old, in
  seconds**, correctly **reverts `SessionApproveExpired`**. The check exists;
  only the unit mismatch kills it. Combined with finding 1, an observed
  approval is a perpetual bearer token until the bid is deleted or spent.

### Finding 3 — LOW: `claimForProvider` underflow — REPRODUCED (PASS)

`test_F3_ClaimForProviderUnderflowsAfterLateDisputedClose`

- Second provider, 500 MOR stake, max-price bid (1e16 wei/s); user stake
  342,286 MOR ⇒ session reward ≈ 999 MOR (≫ 500 MOR stake).
- Session closed **late** (past `endsAt`) **with a dispute** (receipt signed by
  a wrong key — well-formed 65-byte signature, so the dispute path is taken,
  not the I-2 revert). Close-time claim is capped by the stake limiter:
  paid at close **500 MOR**, remainder owed **≈ 499 MOR**.
- Same-day `claimForProvider`: **reverts with `Panic(0x11)`** (arithmetic
  underflow) — `_getProviderRewards` (≈ 499 MOR) minus the same-day holdback
  (86,399 s × 1e16 wei/s = **863.99 MOR**), which the close-time code had
  skipped for a late close.
- After warping past the next UTC day boundary, `claimForProvider` **succeeds**
  (no revert). Note: it pays 0 in this setup because the 365-day stake
  limiter is already exhausted by the 500 MOR paid at close — so what
  self-heals at the boundary is the *revert*, and the remainder stays
  unclaimable until the limiter period rolls over. No funds are lost by the
  underflow itself; the claim is blocked for up to ~24 h.

## Live values at the fork block (58179707)

| Value | Amount |
|---|---|
| `computeBalance` | 3,007,958 MOR |
| `totalMORSupply` | 10,295,836 MOR |
| Live bid provider stake | 150,000 MOR |
| Funding-account MOR balance | 85,224 MOR |
| Funding-account allowance to diamond | ~99,825,113 MOR |
| Stipend per 10,000 MOR staked | ~29.215 MOR |

## Limits

- Fork-local provider/bid (see method note); the live bid itself is only read,
  never attacked, because its provider key is unknown.
- Tests use deterministic throwaway keys (`0x1111…0x4444`); no real accounts.
- Finding 3's post-boundary claim pays 0 due to the stake limiter (see above);
  the PoC asserts the revert-then-no-revert behaviour, not a post-boundary payout.
- `forge test` needs network access to the Base RPC for the first run (fork
  state fetch); afterwards it runs from cache.
