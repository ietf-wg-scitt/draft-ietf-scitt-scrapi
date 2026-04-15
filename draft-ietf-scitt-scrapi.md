---
v: 3

title: SCITT Reference APIs
abbrev: SCRAPI
docname: draft-ietf-scitt-scrapi-latest
stand_alone: true
area: Security
wg: SCITT
kw: Internet-Draft
cat: std
consensus: yes
submissiontype: IETF
ipr: trust200902
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

kramdown_options:
  auto_id_prefix: sec-

venue:
  group: SCITT
  mail: scitt@ietf.org
  github: ietf-wg-scitt/draft-ietf-scitt-scrapi

author:
- name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@ietf.contact
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: J. Geater
  name: Jon Geater
  organization: Bowball Technologies Ltd
  email: jonathan@bowball-tech.com
  country: United Kingdom
- name: Antoine Delignat-Lavaud
  organization: Microsoft Research
  street: 21 Station Road
  code: 'CB1 2FB'
  city: Cambridge
  email: antdl@microsoft.com
  country: UK

contributor:
  - ins: O. Steele
    name: Orie Steele
    organization: Transmute
    email: orie@transmute.industries
    country: United States
    contribution: >
      Orie contributed examples, text, and URN structure to early version of this draft.
  - ins: A. Chamayou
    name: Amaury Chamayou
    organization: Microsoft
    email: amaury.chamayou@microsoft.com
    country: United Kingdom
    contribution: >
      Amaury contributed crucial content to ensure interoperability between implementations, improve example expressiveness and consistency, as well as overall document quality.
  - ins: D. Brooks
    name: Dick Brooks
    organization: Business Cyber Guardian
    email: dick@businesscyberguardian.com
    country: United States
    contribution: >
      Dick contributed use cases and helped improve example expressiveness and consistency.
  - ins: R. A. Martin
    name: Robert Martin
    organization: MITRE Corporation
    email: ramartin@mitre.org
    country: United States
    contribution: >
      Bob contributed use cases and helped with authoring and improving the document.
  - ins: S. Lasker
    name: Steve Lasker
    email: stevenlasker@hotmail.com
    contribution: >
      Steve contributed architectural insights, particularly around asynchronous operations and participated in the initial writing of the document.
  - ins: N. Bates
    name: Nicole Bates
    organization: Microsoft
    email: nicolebates@microsoft.com
    country: United States
    contribution: >
      Nicole contributed reviews and edits that improved the quality of the text.
  - ins: R. Williams
    name: Roy Williams
    country: USA
    email: roywill@msn.com
    contribution: >
      Roy contributed the receipt refresh use case and associated resource definition.

normative:
  RFC2119:
  RFC8174:
  I-D.draft-ietf-scitt-architecture: SCITT-ARCH
  RFC8615:
  RFC9052:
  RFC9110:
  RFC9290:
  RFC7515:
  RFC4648:
  RFC9679:

informative:
  RFC8792:
  NIST.SP.800-57pt1r5:
    title: "Recommendation for Key Management: Part 1 - General"
    author:
      - ins: E. Barker
        name: Elaine Barker
    date: 2020-05
    seriesinfo:
      NIST: Special Publication 800-57 Part 1 Revision 5
    target: https://doi.org/10.6028/NIST.SP.800-57pt1r5

entity:
  SELF: "RFCthis"

--- abstract

This document describes a REST API that supports the normative requirements of the SCITT Architecture.

--- middle

# Introduction

The SCITT Architecture {{-SCITT-ARCH}} defines the core objects, identifiers and workflows necessary to interact with a SCITT Transparency Service:

- Signed Statements
- Receipts
- Transparent Statements
- Registration Policies

SCRAPI defines HTTP resources for a Transparency Service using COSE ({{RFC9052}}).
The following resources MUST be implemented for conformance to this specification:

- Registration of Signed Statements
- Issuance and resolution of Receipts
- Discovery of Transparency Service Keys

## Terminology

{::boilerplate bcp14-tagged}

This specification uses the terms "Signed Statement", "Receipt", "Transparent Statement", "Artifact Repositories", "Transparency Service" and "Registration Policy" as defined in {{-SCITT-ARCH}}.

This specification uses "payload" as defined in {{RFC9052}}.

# Authentication

Authentication is out of scope for this document.
Implementations MAY authenticate clients, for example for the purposes of authorization or preventing denial of service attacks.
If Authentication is not implemented, rate limiting or other denial of service mitigations MUST be implemented.

# Resources

All messages are sent as HTTP GET or POST requests.

If the Transparency Service cannot process a client's request, it MUST return either:

1. an HTTP 3xx code, indicating to the client additional action they must take to complete the request, such as follow a redirection, or
1. an HTTP 4xx or 5xx status code, and the body MUST be a Concise Problem Details object (application/concise-problem-details+cbor) {{RFC9290}} containing:

- title: A human-readable string identifying the error that prevented the Transparency Service from processing the request, ideally short and suitable for inclusion in log messages.
- detail: A human-readable string describing the error in more depth, ideally with sufficient detail enabling the error to be rectified.

SCRAPI is not a CoAP API, but Constrained Problem Details objects {{RFC9290}} provide a useful encoding for problem details and avoid the need to mix CBOR and JSON in resource or client implementations.

NOTE: Examples use '\\' line wrapping per {{RFC8792}}

Examples of errors may include:

~~~ cbor-diag
{
  / title /         -1: \
            "Bad Signature Algorithm",
  / detail /        -2: \
            "Signing algorithm 'WalnutDSA' not supported"
}
~~~

Most error types are specific to the type of request and are defined in the respective subsections below.
The one exception is the "malformed" error type, which indicates that the Transparency Service could not parse the client's request because it did not comply with this document:

~~~ cbor-diag
{
  / title /         -1: \
            "Malformed request",
  / detail /        -2: \
            "The request could not be parsed"
}
~~~

Clients SHOULD treat 500 and 503 HTTP status code responses as transient failures and MAY retry the same request without modification at a later date.

Note that in the case of any error response, the Transparency Service MAY include a `Retry-After` header field per {{RFC9110}} in order to request a minimum time for the client to wait before retrying the request.
In the absence of this header field, this document does not specify a minimum.

The following HTTP resources MUST be implemented to enable conformance to this specification.

## Transparency Service Keys

This resource is used to discover the public keys that can be used by relying parties to verify Receipts issued by the Transparency Service.

The Transparency Service responds with a COSE Key Set, as defined in {{Section 7 of RFC9052}}.

Request:

~~~ http-message
GET /.well-known/scitt-keys HTTP/1.1
Host: transparency.example
Accept: application/cbor
~~~

Response:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/cbor

Body (in CBOR diagnostic notation)

[
  {
    -1:1,
    -2:h'65eda5a1...9c08551d',
    -3:h'1e52ed75...0084d19c',
    1:2,
    2:'kid1'
  },
  {
    -1:1,
    -2:h'bac5b11c...d6a09eff',
    -3:h'20138bf8...bbfc117e',
    1:2,
    2:'kid2'
  }
]
~~~

The Transparency Service MAY stop returning at that resource the keys it no longer uses to issue Receipts, following a reasonable delay.
A delay is considered reasonable if it is sufficient for relying parties to have obtained the key needed to verify any previously issued Receipt.
Consistent with key management best practices described in {{NIST.SP.800-57pt1r5}} (Section 5.3.4), retired keys SHOULD remain available for as long as any Receipts signed with them may still need to be verified.

## Individual Transparency Service Key

This resource is used to resolve a single public key, from a `kid` value contained in a Receipt previously issued by the Transparency Service.

Request:

~~~ http-message
GET /.well-known/scitt-keys/{kid_value} HTTP/1.1
Host: transparency.example
Accept: application/cbor
~~~

Response:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/cbor

Body (in CBOR diagnostic notation)

[
  {
    -1:1,
    -2:h'bac5b11c...d6a09eff',
    -3:h'20138bf8...bbfc117e',
    1:2,
    2:'kid_value'
  }
]
~~~

The following expected error is defined:

~~~ http-message
HTTP/1.1 404 Not Found
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: "No such key",
  / detail /        -2: "No key could be found for this kid value"
}
~~~

Implementations MAY return other errors, so long as they are valid {{RFC9290}} objects.

If the `kid` values used by the service (`{kid_value}` in the request above) are not URL-safe, the resource MUST accept the base64url encoding of the `kid` value, without padding, in the URL instead.

{{Section 2 of RFC7515}} specifies Base64Url encoding as follows:

{{RFC7515}} specifies Base64url encoding as follows:

"Base64 encoding using the URL- and filename-safe character set
defined in Section 5 of RFC 4648 {{RFC4648}}, with all trailing '='
characters omitted and without the inclusion of any line breaks,
whitespace, or other additional characters.  Note that the base64url
encoding of the empty octet sequence is the empty string.
(See Appendix C of {{RFC7515}} for notes on implementing base64url
encoding without padding.)"

It is RECOMMENDED to use COSE Key Thumbprint, as defined in {{RFC9679}} as the mechanism to assign a `kid` to Transparency Service keys.

## Register Signed Statement

This resource instructs a Transparency Service to register a Signed Statement on its log.
Since log implementations may take many seconds or longer to reach finality, this API provides an asynchronous mode that returns a locator that can be used to check the registration's status asynchronously.

The following is a non-normative example of an HTTP request to register a Signed Statement:

Request:

~~~http
POST /entries HTTP/1.1
Host: transparency.example
Accept: application/cbor
Accept: application/cose
Content-Type: application/cose

Body (in CBOR diagnostic notation)

18([ / COSE Sign1           /
  <<{
    / signature alg         / 1:  -35, # ES384
    / key identifier        / 4:   h'75726e3a...32636573',
    / cose sign1 type       / 16:  "application/example+cose",
    / payload-hash-alg      / 258: -16, # sha-256
    / preimage-content-type / 259: "application/spdx+json",
    / payload-location      / 260: "https://.../manifest.json",
    / CWT Claims            / 15: {
      / Issuer  / 1: "vendor.example",
      / Subject / 2: "vendor.product.example",
    }
  }>>,                          / Protected Header   /
  {},                           / Unprotected Header /
  / Payload, sha-256 digest of file stored at payload-location /
  h'935b5a91...e18a588a',
  h'269cd68f4211dffc...0dcb29c' / Signature /
])
~~~

A Transparency Service depends on the verification of the Signed Statement in the Registration Policy.

The Registration Policy for the Transparency Service MUST be applied before any additional processing.
The details of Registration Policies are out of scope for this document.

Response:

One of the following:

### Status 201 - Registration is successful

If the Transparency Service is able to produce a Receipt within a reasonable time, it MAY return it directly.

Along with the receipt the Transparency Service MAY return a locator in the HTTP response `Location` header, provided the locator is a valid URL.

~~~ http-message
HTTP/1.1 201 Created
Location: https://transparency.example/entries/67ed...befe
Content-Type: application/cose

Body (in CBOR diagnostic notation)

/ cose-sign1 / 18([
  / protected   / <<{
    / key / 4 : "mxA4KiOkQFZ-dkLebSo3mLOEPR7rN8XtxkJe45xuyJk",
    / algorithm / 1 : -7,  # ES256
    / vds       / 395 : 1, # RFC9162 SHA-256
    / claims / 15 : {
      / issuer  / 1 : "https://blue.notary.example",
      / subject / 2 : "https://green.software.example/cli@v1.2.3",
    },
  }>>,
  / unprotected / {
    / proofs / 396 : {
      / inclusion / -1 : [
        <<[
          / size / 9, / leaf / 8,
          / inclusion path /
          h'7558a95f...e02e35d6'
        ]>>
      ],
    },
  },
  / payload     / null,
  / signature   / h'02d227ed...ccd3774f'
])
~~~

The response contains the Receipt for the Signed Statement.
Fresh Receipts may be requested through the resource identified in the Location header.

### Status 303 - Registration is running

In cases where the registration request is accepted but the Transparency Service is not able to produce a Receipt in a reasonable time, it MAY return a locator for the registration operation, as in this non-normative example:

~~~ http
HTTP/1.1 303 See Other
Location: https://transparency.example/entries/67ed...befe
Content-Type: application/cose
Content-Length: 0
Retry-After: <seconds>
~~~

The location MAY be temporary, and the service may not serve a relevant response at this Location after a reasonable delay.

The Transparency Service MAY include a `Retry-After` header in the HTTP response to help with polling.

### Status 400 - Invalid Client Request

The following expected errors are defined.
Implementations MAY return other errors, so long as they are valid {{RFC9290}} objects.

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: \
          "Bad Signature Algorithm",
  / detail /        -2: \
          "Signed Statement contained a non supported algorithm"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: "\
          Confirmation Missing",
  / detail /        -2: \
          "Signed Statement did not contain proof of possession"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: \
          "Payload Missing",
  / detail /        -2: \
          "Signed Statement payload must be present"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: \
          "Rejected",
  / detail /        -2: \
          "Signed Statement not accepted by the current\
          Registration Policy"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: "Invalid locator",
  / detail /        -2: "Operation locator is not in a valid form"
}
~~~

## Query Registration Status

This resource lets a client query a Transparency Service for the registration status of a Signed Statement they have submitted earlier, and for which they have received a 303 or 302 - Registration is running response.

Request:

~~~http
GET /entries/67ed...befe HTTP/1.1
Host: transparency.example
Accept: application/cbor
Accept: application/cose
Content-Type: application/cose
~~~

Response:

One of the following:

### Status 302 - Registration is running

Registration requests MAY fail, in which case the Location MAY return an error when queried.

If the client requests (GET) the location when the registration is still in progress, the TS MAY return a 302 Found, as in this non-normative example:

~~~ http-message
HTTP/1.1 302 Found
Location: https://transparency.example/entries/67ed...befe
Content-Type: application/cose
Content-Length: 0
Retry-After: <seconds>
~~~

The location MAY be temporary, and the service may not serve a relevant response at this Location after a reasonable delay.

The Transparency Service MAY include a `Retry-After` header in the HTTP response to help with polling.

### Status 200 - Asynchronous registration is successful

Along with the receipt the Transparency Service MAY return a locator in the HTTP response `Location` header, provided the locator is a valid URL.

~~~ http-message
HTTP/1.1 200 OK
Location: https://transparency.example/entries/67ed...befe
Content-Type: application/cose

Body (in CBOR diagnostic notation)

/ cose-sign1 / 18([
  / protected   / <<{
    / key / 4 : "mxA4KiOkQFZ-dkLebSo3mLOEPR7rN8XtxkJe45xuyJk",
    / algorithm / 1 : -7,  # ES256
    / vds       / 395 : 1, # RFC9162 SHA-256
    / claims / 15 : {
      / issuer  / 1 : "https://blue.notary.example",
      / subject / 2 : "https://green.software.example/cli@v1.2.3",
    },
  }>>,
  / unprotected / {
    / proofs / 396 : {
      / inclusion / -1 : [
        <<[
          / size / 9, / leaf / 8,
          / inclusion path /
          h'7558a95f...e02e35d6'
        ]>>
      ],
    },
  },
  / payload     / null,
  / signature   / h'02d227ed...ccd3774f'
])
~~~

The response contains the Receipt for the Signed Statement.
Fresh Receipts may be requested through the resource identified in the Location header.

As an example, a successful asynchronous follows the following sequence:

~~~
Initial exchange:

Client --- POST /entries (Signed Statement) --> TS
Client <-- 303 Location: .../entries/tmp123 --- TS

May happen zero or more times:

Client --- GET .../entries/tmp123           --> TS
Client <-- 302 Location: .../entries/tmp123 --- TS

Finally:

Client --- GET .../entries/tmp123           --> TS
Client <-- 200 (Receipt)                    --- TS
           Location: .../entries/final123
~~~


### Status 400 - Invalid Client Request

The following expected errors are defined.
Implementations MAY return other errors, so long as they are valid {{RFC9290}} objects.

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: \
          "Bad Signature Algorithm",
  / detail /        -2: \
          "Signed Statement contained a non supported algorithm"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: "\
          Confirmation Missing",
  / detail /        -2: \
          "Signed Statement did not contain proof of possession"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: \
          "Payload Missing",
  / detail /        -2: \
          "Signed Statement payload must be present"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: \
          "Rejected",
  / detail /        -2: \
          "Signed Statement not accepted by the current\
          Registration Policy"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: "Invalid locator",
  / detail /        -2: "Operation locator is not in a valid form"
}
~~~

### Status 404 - Operation Not Found

If no record of the specified running operation is found, the Transparency Service returns a 404 response.

~~~ http-message
HTTP/1.1 404 Not Found
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: \
          "Operation Not Found",
  / detail /        -2: \
          "No running operation was found matching the requested ID"
}
~~~

### Status 429 - Too Many Requests

If a client is polling for an in-progress registration too frequently then the Transparency Service MAY, in addition to implementing rate limiting, return a 429 response:

~~~ http-message
HTTP/1.1 429 Too Many Requests
Content-Type: application/concise-problem-details+cbor
Retry-After: <seconds>

{
  / title /         -1: \
          "Too Many Requests",
  / detail /        -2: \
          "Only <number> requests per <period> are allowed."
}
~~~

## Resolve Receipt

Request:

~~~ http-message
GET /entries/67ed41f1de6a...cfc158694ed0befe HTTP/1.1
Host: transparency.example
Accept: application/cose
~~~

Response:

### Status 200 - OK

If the Receipt is found:

~~~ http-message
HTTP/1.1 200 OK
Location: https://transparency.example/entries/67ed...befe
Content-Type: application/cose

Body (in CBOR diagnostic notation)

/ cose-sign1 / 18([
  / protected   / <<{
    / key / 4 : "mxA4KiOkQFZ-dkLebSo3mLOEPR7rN8XtxkJe45xuyJk",
    / algorithm / 1 : -7,  # ES256
    / vds       / 395 : 1, # RFC9162 SHA-256
    / claims / 15 : {
      / issuer  / 1 : "https://blue.notary.example",
      / subject / 2 : "https://green.software.example/cli@v1.2.3",
    },
  }>>,
  / unprotected / {
    / proofs / 396 : {
      / inclusion / -1 : [
        <<[
          / size / 9, / leaf / 8,
          / inclusion path /
          h'7558a95f...e02e35d6'
        ]>>
      ],
    },
  },
  / payload     / null,
  / signature   / h'02d227ed...ccd3774f'
])
~~~

### Status 404 - Not Found

If there is no Receipt found for the specified `EntryID` the Transparency Service returns a 404 response:

~~~ http-message
HTTP/1.1 404 Not Found
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: \
          "Not Found",
  / detail /        -2: \
          "Receipt with entry ID <id> not known \
          to this Transparency Service"
}
~~~

# Privacy Considerations

The privacy considerations section of {{-SCITT-ARCH}} applies to this document.

# Security Considerations

## General Scope

This document describes the interoperable API for client calls to, and implementations of, a Transparency Service as specified in {{-SCITT-ARCH}}.
As such the security considerations in this section are concerned only with security considerations that are relevant at that implementation layer.
All questions of security of the related COSE formats, algorithm choices, cryptographic envelopes, verifiable data structures and the like are handled elsewhere and out of scope for this document.

## Applicable Environment

SCITT is concerned with issues of cross-boundary supply-chain-wide data integrity and as such must assume a very wide range of deployment environments.
Thus, no assumptions can be made about the security of the computing environment in which any client implementation of this specification runs.

## Threat Model

### In Scope

The most serious threats to implementations on Transparency Services are ones that would cause the failure of their main promises, to wit:

- Threats to strong identification, for example representing the Statements from one issuer as those of another
- Threats to payload integrity, for example changing the contents of a Signed Statement before making it transparent
- Threats to non-equivocation, for example attacks that would enable the presentation or verification of divergent proofs for the same Statement payload

#### Denial of Service Attacks

While denial of service attacks are very hard to defend against completely, and Transparency Services are unlikely to be in the critical path of any safety-liable operation, any attack which could cause the _silent_ failure of Signed Statement registration, for example, should be considered in scope.

In principle DoS attacks are easily mitigated by the client checking that the Transparency Service has registered any submitted Signed Statement and returned a Receipt.
Since verification of Receipts does not require the involvement of the Transparency Service DoS attacks are not a major issue.

Clients to Transparency Services SHOULD ensure that Receipts are available for their registered Statements, either on a periodic or needs-must basis, depending on the use case.

Beyond this, implementers of Transparency Services MUST implement general good practice around network attacks, flooding, rate limiting etc.

#### Eavesdropping

Since the purpose of this API is to ultimately put the message payloads on a Transparency Log there is limited risk to eavesdropping.
Nonetheless transparency may mean 'within a limited community' rather than 'in full public', so implementers MUST add protections against man-in-the-middle and network eavesdropping, such as TLS.

#### Message Modification Attacks

Modification attacks are mitigated by the use of the Issuer signature on the Signed Statement.

#### Message Insertion Attacks

Insertion attacks are mitigated by the use of the Issuer signature on the Signed Statement, therefore care must be taken in the protection of Issuer keys and credentials to avoid theft and impersonation.

Transparency Services MAY also implement additional protections such as anomaly detection or rate limiting in order to mitigate the impact of any breach.

### Out of Scope

#### Replay Attacks

Replay attacks are not particularly concerning for SCITT or SCRAPI:
Once a statement is made, it is intended to be immutable and non-repudiable, so making it twice should not lead to any particular issues.
There could be issues at the payload level (for instance, the statement "it is raining" may be true when first submitted but not when replayed), but being payload-agnostic implementations of SCITT services cannot be required to worry about that.

If the semantic content of the payload are time-dependent and susceptible to replay attacks in this way then timestamps MAY be added to the protected header signed by the Issuer.

#### Message Deletion Attacks

Once registered with a Transparency Service, Registered Signed Statements cannot be deleted.
Thus, any message deletion attack must occur prior to registration else it is indistinguishable from a man-in-the-middle or denial-of-service attack on this interface.

#### Use of Unauthenticated HTTP Metadata

Implementations that serve multiple application profiles MAY use unauthenticated HTTP-layer signals, such as request headers or distinct registration endpoints, to route incoming Signed Statements to
profile-specific processing.

However, these signals are not signed, are not committed to the Verifiable Data Structure, and cannot be replayed by Auditors.

Implementations MUST NOT use unauthenticated signals as authoritative inputs to the registration decision.

Implementations that use such signals for early dispatch MUST ensure that any processing decisions that affect the outcome of registration are fully determined by authenticated inputs, or are otherwise captured in the Verifiable Data Structure, such that the registration process remains deterministic and replayable by Auditors.

The authoritative identification of the application profile is carried within the protected header or payload of the Signed Statement, and MUST be verified after signature authentication.

# IANA Considerations

## Well-Known URI for Key Discovery

The following value is requested to be registered in the "Well-Known URIs" registry (using the template from {{RFC8615}}):

URI suffix: scitt-keys
Change controller: IETF
Specification document(s): {{&SELF}}
Status: Permanent
Related information: {{-SCITT-ARCH}}

--- back
