# TODO

- [ ] Make ROAST history available across a committee transition with no overlapping members.
  Bind an old-quorum-certified ROAST archive endpoint into handoff/state-import consensus,
  transfer and verify its artifact graph before target readiness, and retain authenticated
  abandoned-family key-image watch metadata so the successor can settle transactions which
  confirm after abandonment. Cover a disjoint old/new committee, unavailable Byzantine sources,
  late settlement, and target restart on Regtest.
- [ ] Add auditable network reserves for the consolidated Monero wallet using its private view
  key. Define a least-privilege export/auditor flow that can discover incoming outputs and verify
  balances without exposing the private spend key; document view-key limitations (including spent
  output/key-image visibility), authenticate the reported chain height, and add Regtest acceptance
  coverage.
