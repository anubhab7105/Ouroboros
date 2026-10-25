# ADR 0008: ReportLab for case reports, generated server-side

- **Status:** accepted
- **Date:** 2026-02-12
- **Deciders:** MULEGUARD contributors

## Context

An investigation ends in a document somebody else reads — a colleague, a
supervisor, occasionally an external body. It has to be self-contained,
fixed, and carry the same qualifications the interface shows, because a
report that quotes a risk score without the caveat is how a lead becomes a
finding in somebody else's filing cabinet.

It also has to be auditable: who generated it, when, over which case, and
whether the copy in hand is the one that was generated.

## Decision

> We will generate PDFs server-side with ReportLab, return metadata rather
> than bytes from the generation endpoint, and record a SHA-256 of the
> document in the audit trail.

The endpoint returns filename, size, digest, section summaries and bounds. The
bytes come from a separate download. Every generation is audited.

## Alternatives considered

### HTML to PDF via a headless browser (wkhtmltopdf, Puppeteer, WeasyPrint)

Nicer output, and the template could be shared with the interface.

Rejected on the deployment cost: a browser engine or a GTK stack in the
container, which roughly doubles the image and brings a class of CVE that has
nothing to do with this application. For a prototype somebody installs on a
laptop, that is the wrong trade.

There is also a correctness argument. An HTML-to-PDF pipeline renders whatever
the template produces, including a caveat block that a future template change
drops. ReportLab's document is assembled in Python, so the caveat section is
code and a test can assert it is present.

### Client-side generation in the browser

Rejected. The digest would be computed on data the client already has, which
makes it worthless as an integrity check, and the report would reflect
whatever the client had loaded rather than what the server held. It also puts
the document outside the audit trail entirely.

### Return the PDF bytes from the generation endpoint

Rejected in favour of metadata plus a separate download. Generation is the
audited event and should be recorded even if the download never happens or
fails midway. Splitting them also keeps the response small enough to log, and
lets the client show "generated, 412 KB, 6 sections" before a byte moves.

## Consequences

### What this makes easy

- A small container with no browser engine.
- Asserting the report's content in a test, including that the limitations
  section exists.
- An audit record per generation, with a digest that identifies the document.
- Bounded output: page and item limits, with truncation reported in the
  metadata rather than silently applied.

### What this makes hard

- Layout. ReportLab is assembled in code, so a design change is a code change,
  and the result is plainer than an HTML template would give.
- Sharing presentation with the interface. The two are written separately and
  can drift in wording; the caveat text is the part held in common and it is
  asserted in tests on both sides.

### What would make us revisit this

A requirement for a specific document template — a regulator's format, say —
that is more practically expressed as HTML than as Python.

## Notes

Implemented in `app/reports/`; the endpoints are in
`app/api/v1/endpoints/reports.py`. `GET /api/v1/reports/limitations` returns
the disclaimer text as data, so the interface and the PDF render the same
words from one source. Tested in `backend/tests/test_reports.py`.
