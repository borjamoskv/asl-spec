agent Orchestrator {
  compose: PaymentBot with {
    channel: encrypted(aes-256-gcm)
    trust: verify_output(schema: payment_response)
    deny: delegate(shell_exec)
    deny: delegate(write, user.credentials)
  }

  compose: ETLWorker with {
    channel: internal
    trust: verify_output(schema: etl_result)
    deny: delegate(network, *.external)
  }

  invariant: all_children_verified
  temporal: heartbeat(30s, per: child_agent)
}
