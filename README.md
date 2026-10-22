# OSINT Alert Check

A client-side heuristic QA for OSINT alert pipelines, built with Sentinel Defense Technologies' problem in mind: gated, geolocated, offline-first threat alerts for civilians in conflict zones - where a wrong alert is worse than no alert.

Paste alert payloads, one per line as `severity | source | lat,lon | text`, and the tool flags:

- **MISSING_GEOLOCATION** - no usable coordinates on the alert
- **SOURCE_UNVERIFIED** - missing, anonymous or unverified source (error level on high/critical severity)
- **HIGH_SEVERITY_NO_REVIEW_HINT** - high/critical alert with no verification or review hint in its text
- **DUPLICATE_ALERT** - same text pushed more than once
- **PAYLOAD_HEAVY** - long text that may strain offline-first clients on slow links
- **UNPARSED** - lines that do not match the expected format

Plain HTML, CSS and JavaScript. No build step, no external services.

## Run

Open `index.html` in a browser, paste alert lines, click "Run alert check".

## Test

```
npm test
```

## Limitations

This is a payload-shape heuristic screen, not intelligence analysis:

- It checks that alerts carry coordinates, named sources and review hints; it cannot judge whether the underlying information is true. Every finding says "verify".
- A review hint in text is not proof a human gate ran - it only inspects what you paste.
- The 280-character payload threshold is a rough proxy for slow-link budgets, not a measured limit.
- Tests verify the rules match their intended sample patterns; they do not prove real alert feeds are assessed correctly.
