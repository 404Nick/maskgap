# Examples

The files here use a **deliberately fake secret** that is public on purpose:

```
DEPLOY_KEY = S3cret-Example!Value+Specials-DemoOnly-2026-PaddingToWrap12
```

`leaky-build.log` looks like a build log where the key reached stdout in several
encodings. Run the demo:

```console
$ export DEPLOY_KEY='S3cret-Example!Value+Specials-DemoOnly-2026-PaddingToWrap12'

# report every form; exit code 1 because the log leaks
$ maskgap scan --env DEPLOY_KEY --limit 0 examples/leaky-build.log

# only the forms GitHub Actions would print in the clear
$ maskgap scan --env DEPLOY_KEY --only-gaps examples/leaky-build.log

# show the coverage matrix for this secret
$ maskgap audit --env DEPLOY_KEY --extended

# scrub the log; no form of the key survives
$ maskgap redact --env DEPLOY_KEY --report examples/leaky-build.log > clean.log
```

`workflow-redact.yml` is a template for wiring the same idea into a real
pipeline: gate on `scan --only-gaps`, redact artefacts before upload.
