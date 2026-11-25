## 2026-11-25 (pathvector-rpki: Error Reports for undecodable RTR PDUs)

An unknown PDU type, an unknown protocol version or a wrong Length ended the RTR session
without telling the cache why. Each is now answered as RFC 8210 §§7 and 12 require before
the connection is closed.

| Received | Error Report | Resume serial |
|---|---|---|
| Unknown PDU type | 5 "Unsupported PDU Type" | forgotten: next query is a Reset Query |
| Wrong Length | 0 "Corrupt Data" | forgotten |
| Unknown version during negotiation | 4 "Unsupported Protocol Version" | kept |
| Unknown version after negotiation | 8 "Unexpected Protocol Version" | kept |
| Malformed PDU of the other version after negotiation | 8 | kept |
| Any broken Error Report | none (§5.11) | kept |

The installed VRPs are kept in every case, and nothing of a failed transfer is published.

- **Behaviour change:** after an unknown type or wrong Length the client used to resume
  with a Serial Query; it now sends a Reset Query, as it already did for a forbidden prefix
  tuple, since the same serial would draw the same change set.
- **Behaviour change:** a malformed prefix at the *other* protocol version in an agreed
  session is now code 8 and keeps the serial (it was code 0).
- **Also fixed:** a Serial Notify of an unknown version during negotiation ended the
  session. §7 says to ignore it "regardless of the Protocol Version field".
- An unknown type or version is now refused once its declared Length has arrived (at most
  64 KiB), so the report can echo the whole PDU; before, the header alone ended the session.
- The v1 to v0 fallback is unchanged. The decode path for valid PDUs is unchanged.
- Proof: nine black-box tests over raw wire bytes, v0 and v1, in negotiation,
  mid-transfer and idle, all failing before; guard tests for "never answer an Error
  Report" and for the fallback; a property test of the same §5.11 rule.
