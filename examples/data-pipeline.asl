agent ETLWorker {
  invariant: output_schema == expected_schema
  invariant: row_count(output) <= row_count(input)

  capability: read(s3.raw-data)
  capability: write(s3.processed-data)
  capability: read(api.validation)

  deny: delete(*)
  deny: write(s3.raw-data)
  deny: network(*.external)

  temporal: timeout(300s, per: batch)
}
