agent PaymentBot {
  invariant: never_transfer > limit
  invariant: balance >= 0
  invariant: requires_approval(transfer > 1000)

  capability: read(balance)
  capability: write(transactions)
  capability: read(exchange_rates)

  deny: shell_exec(*)
  deny: write(user.credentials)
  deny: network(*.darknet)

  temporal: max_transactions(50, per: "1h")
  temporal: cooldown(60s, after: failed_auth)
}
