# mock-hec

A tiny stand-in for Splunk's **HTTP Event Collector**, for testing plugger's
`splunk` output without a real Splunk. Stdlib Python only — no install, no deps.

It accepts `POST /services/collector/event`, validates the
`Authorization: Splunk <token>` header, and pretty-prints every event it
receives (single or newline-delimited batch), with severity highlighting.

## Run it

```bash
python3 mock_hec.py                    # :8088, accept any token
PORT=9000 python3 mock_hec.py          # custom port
HEC_TOKEN=secret python3 mock_hec.py   # require this exact token
```

## Point plugger at it

In the environment where plugger runs:

```bash
export HEC_TOKEN=secret          # match the mock (omit if the mock accepts any)

plugger output add mock --type splunk \
  --hec-url http://localhost:8088 \
  --hec-token-env HEC_TOKEN \
  --plugins pce-expiry-watch

plugger reload                   # pick up the new output
plugger output test mock         # fire a test report at the mock
```

Watch the `mock_hec.py` terminal — the test report (and any real
`pce-expiry-watch` findings) appear immediately. `http://` needs no TLS; to
exercise `tlsSkipVerify`, front the mock with a TLS proxy or an `https://` URL.
