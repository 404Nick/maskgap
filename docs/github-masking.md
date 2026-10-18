# What the GitHub Actions runner actually masks

maskgap's whole value proposition rests on one factual claim: *the platform
masks a fixed, literal list of encodings of a secret, and everything else
survives.* This document shows where that list comes from, what it contains, and
what it does not.

All source references were read from `actions/runner` on branch `main` on
2026-10-18. GitHub owns the Actions service, not just the runner, and the service
is closed source, so this is the strongest public evidence that exists — treat
the model as *source-derived*, not as a guarantee by GitHub.

## How masking works in the runner

`SecretMasker` (`src/Sdk/DTLogging/Logging/SecretMasker.cs`) keeps a set of
literal strings:

* `AddValue(value)` registers the value itself **plus the output of every
  registered value encoder** for that value (empty encoder outputs are dropped);
* `AddRegex(pattern)` registers a regular expression.

Every log line then goes through `MaskSecrets`, which finds *literal
occurrences* of those strings, merges overlapping ranges, and replaces them with
`***`. There is no normalisation of any kind: matching is case-sensitive,
whitespace-sensitive, and encoding-sensitive. If a transformed form of the
secret is not in the literal set, it is printed in the clear.

The encoders are registered once, in the `HostContext` constructor
(`src/Runner.Common/HostContext.cs`):

```csharp
this.SecretMasker.AddValueEncoder(ValueEncoders.Base64StringEscape);
this.SecretMasker.AddValueEncoder(ValueEncoders.Base64StringEscapeShift1);
this.SecretMasker.AddValueEncoder(ValueEncoders.Base64StringEscapeShift2);
this.SecretMasker.AddValueEncoder(ValueEncoders.CommandLineArgumentEscape);
this.SecretMasker.AddValueEncoder(ValueEncoders.ExpressionStringEscape);
this.SecretMasker.AddValueEncoder(ValueEncoders.JsonStringEscape);
this.SecretMasker.AddValueEncoder(ValueEncoders.UriDataEscape);
this.SecretMasker.AddValueEncoder(ValueEncoders.XmlDataEscape);
this.SecretMasker.AddValueEncoder(ValueEncoders.TrimDoubleQuotes);
this.SecretMasker.AddValueEncoder(ValueEncoders.PowerShellPreAmpersandEscape);
this.SecretMasker.AddValueEncoder(ValueEncoders.PowerShellPostAmpersandEscape);
```

Where a secret value comes from matters too (`src/Runner.Worker/Worker.cs`,
`InitializeSecretMasker`):

* secret *variables* (the `secrets` context) are registered as
  `value.Trim()` — surrounding whitespace is not part of the secret — **and**
  every non-empty line of the value is registered individually
  (`Split('\r', '\n', RemoveEmptyEntries | TrimEntries)`);
* `::add-mask::` does the same: the whole value plus each line
  (`src/Runner.Worker/ActionCommandManager.cs`);
* the only whitelisted variables are `ACTIONS_STEP_DEBUG` and
  `ACTIONS_RUNNER_DEBUG`.

A multi-line secret (a PEM key, for example) is therefore covered line by line —
indentation and trailing whitespace included, because per-line hints are trimmed
before registration.

## The covered encodings

`ValueEncoders.cs` defines exactly the transformations below in the shipped
code. maskgap marks these encoders `covered_by_runner=True` and names the symbol
in `maskgap encoders` / `maskgap audit`.

| maskgap encoder | runner symbol | exact semantics |
| --- | --- | --- |
| `raw` | `SecretMasker.AddValue` | `value.Trim()` itself |
| `base64` | `Base64StringEscape` | `Convert.ToBase64String(UTF8(value))`, padding kept |
| `base64-shift1` | `Base64StringEscapeShift1` | base64 of the value with its first byte dropped |
| `base64-shift2` | `Base64StringEscapeShift2` | base64 of the value with its first two bytes dropped |
| `json` | `JsonStringEscape` | Newtonsoft `JsonConvert.ToString` without the quotes |
| `uri` | `UriDataEscape` | `Uri.EscapeDataString`, upper-case `%XX`, unreserved set `A-Za-z0-9-._~` |
| `xml` | `XmlDataEscape` | `SecurityElement.Escape` (`&` `<` `>` `"` `'`) |
| `cmd` | `CommandLineArgumentEscape` | `"` becomes `\"` |
| `expression` | `ExpressionStringEscape` | `'` becomes `''` |
| `powershell-pre` | `PowerShellPreAmpersandEscape` | leading `&`/`&+` section, at least 6 characters |
| `powershell-post` | `PowerShellPostAmpersandEscape` | trailing section past the last `&`/`&+`, at least 6 characters |
| `trim-quotes` | `TrimDoubleQuotes` | inner value of a quoted value longer than 8 characters |
| `lines` | `Worker.InitializeSecretMasker` | every non-empty, trimmed line of a multi-line value |

Two details worth knowing when reading the source:

* the shift encoders fall back to base64 of the *whole* value when the value is
  shorter than the shift; that literal is already registered by
  `Base64StringEscape`, so it adds nothing new;
* `docs/adrs/0297-base64-masking-trailing-characters.md` proposes trimming `=`
  padding and the last data character from base64 hints, but the shipped
  `ValueEncoders.cs` does **not** implement it (status: Proposed). Padded base64
  is covered; the unpadded form is not.

## The gaps

Everything else maskgap searches for is not registered by the runner. The
high-value ones observed in real logs:

| maskgap encoder | why it survives |
| --- | --- |
| `base64-no-pad` | hints carry `=` padding; `base64(x).rstrip("=")` is a different literal |
| `base64url` | `-`/`_` alphabet differs whenever the padded form contains `+`/`/` |
| `base64-double` | base64 of base64, e.g. tokens stored encoded |
| `base64-linewrap` | `base64 -w 76` / MIME output contains newlines inside the literal |
| `hex`, `hex-upper` | never registered |
| `uri-lower` | `%2b` vs `%2B`; one bit of case is enough |
| `json-ascii` | `\uXXXX` escaping, e.g. Python `json.dumps` defaults |
| `upper`, `lower` | case folding is never applied |
| `base32`, `fold-64`, `char-space`, `reverse`, `rot13` | exotic but real in logs and debugging tools |
| `prefix-32`, `suffix-32` | truncated values in error messages ("first 32 chars of key") |

## Honest caveats

1. **The model can lag the runner.** If GitHub adds an encoder, maskgap would
   report a false gap until `docs` and `encoders.py` are updated. The registry
   is data, the fix is a one-line entry, and `maskgap audit` exists precisely so
   you can disagree with it cheaply.
2. **The service is not the runner.** GitHub may add masking when it renders
   logs; that code is closed. maskgap deliberately assumes *less* masking than
   the platform might do — false confidence is the failure mode that writes
   secrets into artefacts.
3. **Per-line registration applies to secret variables and `add-mask` values.**
   Values injected through other channels (for example service-endpoint
   credentials) are registered whole, without the per-line split.
4. **`maskgap` models value coverage, not patterns.** The runner's
   `AddRegex` hints come from the service and are not published; they can only
   make masking *stronger*, so treating them as absent is conservative.

If you find a discrepancy, please open an issue with the source link — the
mapping table in `src/maskgap/encoders.py` is the single place that needs to
change.
