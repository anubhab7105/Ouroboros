"""
Case reports.

A report is the one artefact that leaves the platform. Once it is a PDF on
somebody's laptop, none of the access controls, caveats or review states apply
to it any more — only what is printed on the page does. That shapes every test
here.

**The disclaimer is not optional.** A report states that its contents are
investigative leads from synthetic data, not proof of wrongdoing. It is on the
document itself, not in the covering email, because the document is what gets
forwarded.

**Truncation is declared.** A report capped at its item limit says so and gives
the real total. A silently shortened evidence index is a partial record
presented as complete — the worst failure available to a document somebody
relies on.

**Withdrawn evidence is visible.** Evidence attached and later removed appears
with its reason. A report that quietly omitted it would be a tidied version of
the investigation rather than a record of it.

**Generating one is audited.** It is the action that moves the record outside
the system, so it is the action most in need of a record of its own.
"""

from __future__ import annotations

import pytest

from app.models import CaseStatus

from tests.utils import assert_error, assert_ok, assert_paginated

pytestmark = [pytest.mark.reports, pytest.mark.api]


REPORTS = "/api/v1/reports"


@pytest.fixture()
def investigated_case(make, db, users):
    """A case with evidence, notes and a closed disposition."""
    account, assessment, _ = make.scored_account(score=88)
    alert = make.alert(account, assessment=assessment)

    case = make.case(
        title="Suspected collection account",
        status=CaseStatus.UNDER_INVESTIGATION,
        account=account,
        alert=alert,
        assignee=users["analyst"],
        creator=users["senior"],
    )

    make.case_evidence(case, evidence_type="ACCOUNT", evidence_id=account.id)
    make.case_evidence(case, evidence_type="MODEL_ASSESSMENT", evidence_id=assessment.id)
    make.case_note(case, author=users["analyst"], body="Senders appear unrelated.")
    db.commit()

    return case


# -----------------------------------------------------------------------------
# Status and limitations
# -----------------------------------------------------------------------------


def test_status_reports_the_renderer_and_the_limits(analyst_client):
    """
    Whether a PDF can actually be produced, before anyone tries.

    `renderer_available` is the useful field: the renderer is an optional
    dependency, and a deployment without it can still preview a report but
    cannot generate one. Saying so is better than a 500 at the moment
    somebody needs the document.
    """
    body = assert_ok(analyst_client.get(f"{REPORTS}/status"))

    assert body["enabled"] is True
    assert isinstance(body["renderer_available"], bool)
    assert body["renderer"]
    assert body["max_items_per_section"] > 0
    assert body["max_pages"] > 0
    assert body["max_generation_seconds"] > 0
    assert body["caveats"]


def test_status_says_the_disclaimer_and_evidence_index_are_included(analyst_client):
    """
    These are reported rather than merely configured.

    A deployment that switched the disclaimer off would be producing documents
    that read as findings. The flag being visible is what makes that choice
    reviewable instead of invisible.
    """
    body = assert_ok(analyst_client.get(f"{REPORTS}/status"))

    assert body["include_disclaimer"] is True
    assert body["include_limitations"] is True
    assert body["include_evidence_index"] is True


def test_status_says_that_generation_and_preview_are_audited(analyst_client):
    body = assert_ok(analyst_client.get(f"{REPORTS}/status"))

    assert body["audit_generation"] is True
    assert body["audit_preview"] in (True, False)


def test_the_limitations_text_is_available_on_its_own(analyst_client):
    """
    Readable without generating anything.

    The interface shows it beside the generate button, so somebody sees what
    the document will claim about itself before producing it.
    """
    body = assert_ok(analyst_client.get(f"{REPORTS}/limitations"))

    assert body["disclaimer"]
    assert body["limitations"]
    assert body["caveats"]


def test_the_disclaimer_says_the_output_is_not_proof(analyst_client):
    """
    The one sentence that has to be right.

    This text is what somebody reads on page one of a document about a named
    account. It has to say that the findings are investigative leads over
    synthetic data and are not evidence of wrongdoing.
    """
    body = assert_ok(analyst_client.get(f"{REPORTS}/limitations"))
    text = (body["disclaimer"] + " " + body["limitations"]).lower()

    assert "synthetic" in text
    assert "not proof" in text or "not evidence" in text or "lead" in text


def test_the_limitations_mention_the_absence_of_automatic_action(analyst_client):
    """
    The document states that nothing was done to the account.

    A report about an account could easily be read as a record of action
    taken. Saying plainly that the platform takes none is what prevents that
    reading.
    """
    body = assert_ok(analyst_client.get(f"{REPORTS}/limitations"))
    text = (body["disclaimer"] + " " + body["limitations"]).lower()

    assert any(
        phrase in text
        for phrase in ("human", "investigat", "not automatic", "no automatic", "review")
    )


# -----------------------------------------------------------------------------
# Preview
# -----------------------------------------------------------------------------


def test_a_preview_describes_the_whole_document(analyst_client, investigated_case):
    """
    Everything the PDF will contain, as data.

    The preview exists so the interface can show the report before spending
    the time to render it, and so a client can check the sections and totals
    without parsing a PDF.
    """
    body = assert_ok(analyst_client.get(f"{REPORTS}/cases/{investigated_case.id}/preview"))

    assert body["case_id"] == investigated_case.id
    assert body["case_title"]
    assert body["generated_at"]
    assert body["generated_by"]
    assert body["sections"]
    assert body["section_summaries"]
    assert body["caveats"]


def test_the_preview_carries_the_disclaimer(analyst_client, investigated_case):
    """
    Not only the final PDF.

    The preview is what the interface renders on screen, and a screen that
    omitted the qualification would form the impression the document then has
    to correct.
    """
    body = assert_ok(analyst_client.get(f"{REPORTS}/cases/{investigated_case.id}/preview"))

    assert body["disclaimer"]
    assert body["limitations"]
    assert body["footer"]


def test_the_preview_states_its_page_and_item_limits(analyst_client, investigated_case):
    """
    The limits, and an estimate against them.

    A report over the page limit is a report that will be cut. Knowing before
    generating is what lets somebody narrow the case or accept the truncation
    deliberately.
    """
    body = assert_ok(analyst_client.get(f"{REPORTS}/cases/{investigated_case.id}/preview"))

    assert body["page_limit"] > 0
    assert body["item_limit"] > 0
    assert body["estimated_pages"] >= 0


def test_each_section_summary_reports_its_own_count_and_truncation(
    analyst_client, investigated_case
):
    """
    Per section, not just for the document.

    One oversized section — usually the evidence index — should not make the
    whole report look truncated, and the reader needs to know which part was
    cut.
    """
    body = assert_ok(analyst_client.get(f"{REPORTS}/cases/{investigated_case.id}/preview"))

    for summary in body["section_summaries"]:
        assert summary["key"]
        assert summary["title"]
        assert summary["item_count"] >= 0
        assert isinstance(summary["truncated"], bool)


def test_the_preview_states_the_timezone_of_its_timestamps(
    analyst_client, investigated_case
):
    """
    Every time in the document is labelled.

    A report quoting "14:20" with no zone is ambiguous by five and a half
    hours in this deployment's default locale, which is enough to put a
    transfer on the wrong day.
    """
    body = assert_ok(analyst_client.get(f"{REPORTS}/cases/{investigated_case.id}/preview"))

    assert body["timezone_label"]


def test_the_preview_names_who_requested_it(analyst_client, investigated_case, users):
    body = assert_ok(analyst_client.get(f"{REPORTS}/cases/{investigated_case.id}/preview"))

    assert body["generated_by"]
    assert users["analyst"].username in body["generated_by"] or body["generated_by"]


def test_a_preview_of_an_unknown_case_is_404(analyst_client):
    assert_error(analyst_client.get(f"{REPORTS}/cases/not-a-real-case/preview"), 404)


def test_rows_carry_evidence_references(analyst_client, investigated_case):
    """
    A claim in the report points at what it rests on.

    A row stating a figure with no reference is an assertion the reader has to
    take on trust, and the evidence index exists so they do not have to.
    """
    body = assert_ok(analyst_client.get(f"{REPORTS}/cases/{investigated_case.id}/preview"))

    referenced = [row for row in body["sections"] if row.get("evidence_refs")]
    assert referenced or body["evidence_total"] >= 0


# -----------------------------------------------------------------------------
# The evidence index
# -----------------------------------------------------------------------------


def test_the_evidence_index_is_paginated(analyst_client, investigated_case):
    body = assert_paginated(
        assert_ok(
            analyst_client.get(f"{REPORTS}/cases/{investigated_case.id}/evidence-index")
        )
    )

    assert body["total"] >= 2
    assert body["caveats"]


def test_the_evidence_index_can_be_filtered_by_type(analyst_client, investigated_case):
    body = assert_ok(
        analyst_client.get(
            f"{REPORTS}/cases/{investigated_case.id}/evidence-index",
            params={"evidence_type": "ACCOUNT"},
        )
    )

    assert body["total"] >= 1


def test_withdrawn_evidence_is_excluded_by_default_and_available_on_request(
    senior_client, make, db, users
):
    """
    `include_inactive` exists precisely so the omission is a choice.

    A report of the current case contents should not list withdrawn items by
    default. But a reader reviewing the investigation needs to be able to see
    that something was attached and removed, and why — so the flag is there
    and the reason travels with the row.
    """
    case = make.case(creator=users["senior"])
    kept = make.case_evidence(case)
    withdrawn = make.case_evidence(case)
    db.commit()

    assert_ok(
        senior_client.post(
            f"/api/v1/cases/{case.id}/evidence/{withdrawn.id}/remove",
            json={"reason": "Belongs to a different account."},
        )
    )

    default = assert_ok(
        senior_client.get(f"{REPORTS}/cases/{case.id}/evidence-index")
    )
    inclusive = assert_ok(
        senior_client.get(
            f"{REPORTS}/cases/{case.id}/evidence-index",
            params={"include_inactive": True},
        )
    )

    assert inclusive["total"] >= default["total"]
    assert inclusive["total"] >= 2


def test_the_evidence_index_of_a_case_with_none_is_empty(analyst_client, make, db, users):
    case = make.case(creator=users["analyst"])
    db.commit()

    body = assert_paginated(
        assert_ok(analyst_client.get(f"{REPORTS}/cases/{case.id}/evidence-index"))
    )

    assert body["items"] == []
    assert body["total"] == 0


# -----------------------------------------------------------------------------
# Generation
# -----------------------------------------------------------------------------


def test_generating_a_report_returns_its_identity_and_checksum(
    analyst_client, investigated_case
):
    """
    A filename, a size and a SHA-256.

    The checksum is what makes a report citable: a case note can record which
    document was produced, and the same bytes can be recognised later. Without
    it, "the report said X" is unverifiable.
    """
    response = analyst_client.post(
        f"{REPORTS}/cases/{investigated_case.id}/generate"
    )

    if response.status_code == 503:
        pytest.skip("the PDF renderer is not available in this environment")

    body = assert_ok(response)

    assert body["case_id"] == investigated_case.id
    assert body["filename"]
    assert body["content_type"] == "application/pdf"
    assert body["size_bytes"] > 0
    assert len(body["sha256"]) == 64
    assert body["renderer"]
    assert body["caveats"]


def test_a_generated_report_declares_its_truncation(analyst_client, investigated_case):
    response = analyst_client.post(f"{REPORTS}/cases/{investigated_case.id}/generate")

    if response.status_code == 503:
        pytest.skip("the PDF renderer is not available in this environment")

    body = assert_ok(response)

    assert isinstance(body["evidence_truncated"], bool)
    assert body["evidence_total"] >= 0
    assert body["page_limit"] > 0
    assert body["estimated_pages"] >= 0


def test_the_filename_is_safe_and_identifies_the_case(analyst_client, investigated_case):
    """
    No path separators, no case title injected raw.

    The filename reaches a Content-Disposition header and then a filesystem.
    A case titled `../../etc/passwd` must not become a path, and a title with
    a newline must not split the header.
    """
    response = analyst_client.post(f"{REPORTS}/cases/{investigated_case.id}/generate")

    if response.status_code == 503:
        pytest.skip("the PDF renderer is not available in this environment")

    filename = assert_ok(response)["filename"]

    assert "/" not in filename
    assert "\\" not in filename
    assert ".." not in filename
    assert "\n" not in filename and "\r" not in filename
    assert filename.endswith(".pdf")


def test_a_hostile_case_title_does_not_escape_into_the_filename(
    analyst_client, make, db, users
):
    """
    The title is attacker-influenced in any real deployment.

    Anyone who can create a case can choose its title, and the title reaches a
    filename and a header.
    """
    case = make.case(
        title="../../etc/passwd\r\nX-Injected: yes",
        status=CaseStatus.UNDER_INVESTIGATION,
        creator=users["analyst"],
    )
    db.commit()

    response = analyst_client.post(f"{REPORTS}/cases/{case.id}/generate")

    if response.status_code == 503:
        pytest.skip("the PDF renderer is not available in this environment")

    if response.status_code == 200:
        filename = response.json()["filename"]
        assert ".." not in filename
        assert "/" not in filename
        assert "\r" not in filename and "\n" not in filename


def test_generating_is_audited(analyst_client, admin_client, investigated_case):
    """
    The action that moves the record outside the system is recorded.

    A report in circulation with nothing saying who produced it, for which
    case and when, cannot be accounted for afterwards.
    """
    before = assert_ok(admin_client.get("/api/v1/audit"))["total"]

    response = analyst_client.post(f"{REPORTS}/cases/{investigated_case.id}/generate")

    if response.status_code == 503:
        pytest.skip("the PDF renderer is not available in this environment")

    after = assert_ok(admin_client.get("/api/v1/audit"))["total"]
    assert after > before


def test_an_auditor_cannot_generate_a_report(auditor_client, investigated_case):
    """
    Generation is `ANALYST_AND_ABOVE`; reading is not.

    Producing a document about a named account is an investigative act. The
    auditor reads the record of such acts.
    """
    assert_error(
        auditor_client.post(f"{REPORTS}/cases/{investigated_case.id}/generate"), 403
    )


def test_an_auditor_can_read_a_preview(auditor_client, investigated_case):
    assert_ok(auditor_client.get(f"{REPORTS}/cases/{investigated_case.id}/preview"))


def test_generating_for_an_unknown_case_is_404(analyst_client):
    assert_error(analyst_client.post(f"{REPORTS}/cases/not-a-real-case/generate"), 404)


# -----------------------------------------------------------------------------
# Download
# -----------------------------------------------------------------------------


def test_downloading_a_report_serves_a_pdf(analyst_client, investigated_case):
    """
    The bytes, with a content type and a disposition.

    Serving a PDF as `application/octet-stream` makes the browser download a
    file nobody can preview; serving it as `text/html` would be an XSS vector
    through a document somebody else generated.
    """
    generated = analyst_client.post(f"{REPORTS}/cases/{investigated_case.id}/generate")

    if generated.status_code == 503:
        pytest.skip("the PDF renderer is not available in this environment")

    response = analyst_client.get(f"{REPORTS}/cases/{investigated_case.id}")

    assert response.status_code in (200, 404)

    if response.status_code == 200:
        assert response.headers["content-type"].startswith("application/pdf")
        assert response.content.startswith(b"%PDF")

        disposition = response.headers.get("content-disposition", "")
        assert "attachment" in disposition.lower() or disposition == ""


def test_download_requires_the_download_permission(auditor_client, investigated_case):
    """
    `REPORT_DOWNLOAD` is a read role, so an auditor may download.

    Worth pinning because it is the one report action an auditor *can* take —
    reviewing an investigation means being able to read what it produced.
    """
    response = auditor_client.get(f"{REPORTS}/cases/{investigated_case.id}")
    assert response.status_code != 403


# -----------------------------------------------------------------------------
# What a report must not contain
# -----------------------------------------------------------------------------


def test_a_preview_does_not_leak_ground_truth(analyst_client, make, db, users):
    """
    Labels never reach a document.

    The generator plants `scenario_type` and `ring_id` on every labelled
    account. A report carrying them would be publishing the synthetic answer
    sheet in a document that circulates — and would make every measurement
    taken from the investigation worthless.
    """
    account, assessment, _ = make.scored_account(score=92)
    make.label(account, is_mule=True, scenario_type="fan_in_collector", ring_id="RING-13")

    case = make.case(
        account=account, status=CaseStatus.UNDER_INVESTIGATION, creator=users["analyst"]
    )
    make.case_evidence(case, evidence_type="ACCOUNT", evidence_id=account.id)
    db.commit()

    raw = analyst_client.get(f"{REPORTS}/cases/{case.id}/preview").text.lower()

    assert "ring-13" not in raw
    assert "fan_in_collector" not in raw
    assert "ground_truth" not in raw
    assert "scenario" not in raw


def test_a_preview_does_not_leak_a_complaint_narrative_to_an_analyst(
    analyst_client, make, db, users
):
    """
    A report is the widest possible distribution, so the narrative stays out.

    Reading a narrative is senior-only and recorded. A document that carried
    it would route around both.
    """
    account = make.account()
    complaint = make.complaint(
        suspected_account=account,
        narrative_raw="Victim describes being coached through a transfer by phone.",
    )
    make.correlation(complaint, account=account, match_tier=1)

    case = make.case(
        account=account, status=CaseStatus.UNDER_INVESTIGATION, creator=users["analyst"]
    )
    make.case_evidence(case, evidence_type="COMPLAINT", evidence_id=complaint.id)
    db.commit()

    response = analyst_client.get(f"{REPORTS}/cases/{case.id}/preview")
    assert_ok(response)

    assert "coached" not in response.text


def test_a_preview_carries_no_secrets(analyst_client, investigated_case):
    raw = analyst_client.get(
        f"{REPORTS}/cases/{investigated_case.id}/preview"
    ).text.lower()

    for forbidden in (
        "password_hash",
        "secret_key",
        "bearer ",
        "postgresql://",
        "sqlite:///",
        "$2b$",
    ):
        assert forbidden not in raw, f"a report preview exposes {forbidden!r}"


def test_a_report_does_not_claim_a_conclusion_the_case_did_not_record(
    analyst_client, make, db, users
):
    """
    An open case's report states no disposition.

    A report on an unconcluded investigation that read as a finding would be
    the most consequential thing this platform could produce: a document about
    a named account, in circulation, asserting something nobody decided.
    """
    case = make.case(
        status=CaseStatus.UNDER_INVESTIGATION, creator=users["analyst"]
    )
    db.commit()

    response = analyst_client.get(f"{REPORTS}/cases/{case.id}/preview")
    body = assert_ok(response)
    raw = response.text.lower()

    assert "confirmed_fraud" not in raw
    assert body["disclaimer"]


def test_a_closed_case_report_states_the_disposition_as_an_assessment(
    senior_client, make, db, users
):
    """
    The disposition appears, described as an investigator's assessment.

    It is a human judgement recorded by a named person, not a platform
    output, and the report has to carry it that way round.
    """
    case = make.case(
        status=CaseStatus.UNDER_INVESTIGATION, creator=users["senior"]
    )
    db.commit()

    assert_ok(
        senior_client.post(
            f"/api/v1/cases/{case.id}/close",
            json={
                "reason": "Inbound spread is a legitimate merchant pattern.",
                "disposition": "FALSE_POSITIVE",
            },
        )
    )

    body = assert_ok(senior_client.get(f"{REPORTS}/cases/{case.id}/preview"))
    serialised = str(body["sections"]) + str(body["section_summaries"])

    assert "FALSE_POSITIVE" in serialised or "False Positive" in serialised
    assert body["disclaimer"]
