# TODO

- [ ] Add auditable network reserves for the consolidated Monero wallet using its private view
  key. Define a least-privilege export/auditor flow that can discover incoming outputs and verify
  balances without exposing the private spend key; document view-key limitations (including spent
  output/key-image visibility), authenticate the reported chain height, and add regtest plus
  public-testnet acceptance coverage.
