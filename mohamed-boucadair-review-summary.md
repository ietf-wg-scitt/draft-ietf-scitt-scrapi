# Mohamed Boucadair Review Summary

Milestone: [Address Review from Mohamed Boucadair](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/milestone/2?closed=1)

Mailing list email: [Mohamed Boucadair review on the SCITT mailing list](https://mailarchive.ietf.org/arch/msg/scitt/aynYWkU1mIR1CD8YF5YHXi7S7jI/)

## [#148 Clarify characterization of "normative requirements" of SCITT](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/issues/148)

Quote from Mohamed:

> 1. It is not clear what the "normative requirements" refer to. There is no mapping with specific parts in the architecture document.
> 2. Assuming those are characterized, does this spec cover all "requirements" or a subset? Are there requirements that are not normative?
> 3. Some text is needed to help walk through the intended goal and how the current specification meets it.

Fix PR: [#168 Clarify characterization of "normative requirements" of SCITT](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/pull/168)

PR #168 modified the Abstract and the Introduction by adding the "Scope and Relation to the SCITT Architecture" subsection.

## [#149 NIST.SP.800-57pt1r5 reference: clarify mapping, consider making normative, and note operational implications](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/issues/149)

Quote from Mohamed:

> 1. Which part of Section 5.3.4 is being referred to? There are some normative uses in that section but not a 1:1 mapping with the language used here.
> 2. Since that reference backs this recommendation and its citation strengthens the "best practice" claim, this reference is normative (per IESG Statement on Normative and Informative References).
> 3. There are operational implications for storing such keys that should be called out. Likewise, there may be operational disruption if the SHOULD is not followed. Please consider flagging this in the spec.

Fix PR: [#167 Clarify NIST SP 800-57 reference, promote to normative, and document key-retention operational implications](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/pull/167)

PR #167 modified the references metadata and the Transparency Service Keys section's retired-key retention guidance.

## [#150 MAY conflicts with MUST in error handling requirements](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/issues/150)

Quote from Mohamed:

> The construct "MUST be returned ... MAY return other errors" appears contradictory and needs adjustment. The combination of MUST and MAY in these constructs creates ambiguity about the actual requirements.

Fix PR: [#166 Resolve MUST/MAY conflict in error handling requirements](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/pull/166)

PR #166 modified the Individual Transparency Service Key, Register Signed Statement, and Query Registration Status error-handling subsections.

## [#151 RFC9921 reference should be normative](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/issues/151)

Quote from Mohamed:

> Per the IESG Statement on Normative and Informative References: "Even references that are relevant only for optional features must be classified as normative if they meet the above conditions for normative references."
>
> Since RFC9921 is used with normative language (MAY), it should be classified as a normative reference.

Fix PR: [#169 Move RFC9921 to normative references and clarify timestamp mechanisms](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/pull/169)

PR #169 modified the references metadata and the Replay Attacks subsection of Security Considerations.

## [#152 Move normative content from IANA Section 5.1.1 to the main body](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/issues/152)

Quote from Mohamed:

> Section 5.1.1 (Resource Definition) provides normative behavior that is not appropriate in an IANA considerations section. Only the registration itself belongs there.

Fix PR: [#165 Move normative content from IANA §5.1.1 to main body](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/pull/165)

PR #165 modified the Transparency Service Keys and Individual Transparency Service Key sections, and simplified the Well-Known URI for Key Discovery subsection of IANA Considerations.

## [#153 Expand SCITT acronym in the document title](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/issues/153)

Quote from Mohamed:

> Please expand SCITT in the title (Supply Chain Integrity, Transparency, and Trust).

Fix PR: [#164 Expand SCITT acronym in document title](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/pull/164)

PR #164 modified the document front matter title.

## [#154 Review normative language for compliance with BCP56 (RFC 9205 Section 4.6)](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/issues/154)

Quote from Mohamed:

> Please check the use of normative language (and requiring some status codes) for compliance with the guidance in Section 4.6 of RFC 9205 (BCP 56). Some of the current usage may not be compliant.

Fix PR: [#163 Audit normative HTTP status code language for BCP 56 / RFC 9205 §4.6 compliance](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/pull/163)

PR #163 modified the references metadata, the Resources section's client status-code guidance, Register Signed Statement, Query Registration Status, Resolve Receipt, Individual Transparency Service Key, and the IANA key-discovery text.

## [#155 Add Operational Considerations section for retry behavior and rate limiting](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/issues/155)

Quote from Mohamed:

> The current text leaves retry behavior and rate limiting entirely to implementations. However, there are operational impacts if clients adopt an aggressive retry time.

Fix PR: [#162 Add Operational Considerations section for retry behavior and rate limiting](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/pull/162)

PR #162 added the Operational Considerations section, including Client Retry Behavior, Server-Side Retry Configuration, and Rate Limiting subsections.

## [#156 Add cross-references for conformance resources and deduplicate MUST requirements](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/issues/156)

Quote from Mohamed:

> 1. Consider adding cross-references to correlate each conformance item with the section(s) that define them.
> 2. The conformance MUST appears in both the Introduction and Section 2. Please keep the MUST in one single place to avoid duplication and potential inconsistency.

Fix PR: [#161 Add cross-references for conformance resources and deduplicate MUST](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/pull/161)

PR #161 modified the Introduction's conformance resource list and the Resources section preamble.

## [#157 Add justification for COSE Key Thumbprint (RFC 9679) recommendation](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/issues/157)

Quote from Mohamed:

> Adding some justification or explanation of why this mechanism is recommended would be helpful for those who will deploy the system to make their decision.

Fix PR: [#160 Add justification for COSE Key Thumbprint (RFC 9679) recommendation](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/pull/160)

PR #160 modified the Individual Transparency Service Key section's guidance on assigning `kid` values to Transparency Service keys.

## [#158 Fix inappropriate normative language: "MAY fail" should be "may fail"](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/issues/158)

Quote from Mohamed:

> This is an inappropriate use of normative language. The uppercase "MAY" (RFC 2119 keyword) is not correct here — this is a statement of fact about what can happen, not a grant of permission to an implementer.

Fix PR: [#159 Fix inappropriate normative language: "MAY fail" → "may fail"](https://github.com/ietf-wg-scitt/draft-ietf-scitt-scrapi/pull/159)

PR #159 modified the Query Registration Status section, specifically the Status 302 - Registration is running text.
