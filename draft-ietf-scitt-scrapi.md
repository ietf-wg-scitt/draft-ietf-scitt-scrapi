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
  organization: DataTrails Inc.
  email: jon.geater@datatrails.ai
  country: United States

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

normative:
  I-D.draft-ietf-scitt-architecture: SCITT-ARCH
  RFC8615:
  RFC9052:
  RFC9110:
  RFC9290:

informative:
  I-D.draft-ietf-oauth-sd-jwt-vc: SD-JWT-VC
  RFC2046:
  RFC6838:
  RFC8792:

--- abstract

This document describes a REST API that supports the normative requirements of the SCITT Architecture.
Optional key discovery and query interfaces are provided to support interoperability with X.509 Certificates, alternative methods commonly used to support public key discovery and Artifact Repositories.

--- middle

# Introduction

The SCITT Architecture {{-SCITT-ARCH}} defines the core objects, identifiers and workflows necessary to interact with a SCITT Transparency Service:

- Signed Statements
- Receipts
- Transparent Statements
- Registration Policies

SCRAPI defines the operations necessary to support supply chain transparency using COSE {{RFC9052}}:

- Issuance of Signed Statements
- Registration of Signed Statements
- Verification of Signed Statements
- Issuance of Receipts
- Verification of Receipts
- Production of Transparent Statements
- Verification of Transparent Statements

In addition to these operational HTTP endpoints, this specification defines supporting endpoints:

- Resolving Verification Keys for Issuers
- Retrieving Receipts Asynchronously
- Retrieving Signed Statements from an Artifact Repository
- Retrieving Statements from an Artifact Repository
- Exchanging Receipts for refreshed Receipts

## Terminology

{::boilerplate bcp14-tagged}

This specification uses the terms "Signed Statement", "Receipt", "Transparent Statement", "Artifact Repositories", "Transparency Service" and "Registration Policy" as defined in {{-SCITT-ARCH}}.

This specification uses "payload" as defined in {{RFC9052}}.

# Endpoints

Authentication is out of scope for this document.
Implementations MAY authenticate clients, for example for the purposes of authorization or preventing denial of service attacks.
If Authentication is not implemented, rate limiting or other denial of service mitigation MUST be implemented.

All messages are sent as HTTP GET or POST requests.

If the Transparency Service cannot process a client's request, it MUST return either:

1. an HTTP 3xx code, indicating to the client additional action they must take to complete the request, such as follow a redirection, or
1. an HTTP 4xx or 5xx status code, and the body SHOULD be a Concise Problem Details object (application/concise-problem-details+cbor) {{RFC9290}} containing:

- title: A human-readable string identifying the error that prevented the Transparency Service from processing the request, ideally short and suitable for inclusion in log messages.
- detail: A human-readable string describing the error in more depth, ideally with sufficient detail enabling the error to be rectified.

SCRAPI is not a CoAP API, but Constrained Problem Details objects {{RFC9290}} provide a useful encoding for problem details and avoid the need to mix CBOR and JSON in endpoint or client implementations.

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

```
Error code: `malformed` (The request could not be parsed)
```

Clients SHOULD treat 500 and 503 HTTP status code responses as transient failures and MAY retry the same request without modification at a later date.

Note that in the case of any error response, the Transparency Service MAY include a `Retry-After` header field per {{RFC9110}} in order to request a minimum time for the client to wait before retrying the request.
In the absence of this header field, this document does not specify a minimum.

## Mandatory

The following HTTP endpoints are mandatory to implement to enable conformance to this specification.

### Transparency Configuration

This endpoint is used to discover the capabilities and current configuration of a transparency service implementing this specification.

The Transparency Service responds with a CBOR map of configuration elements.
These elements are Transparency-Service specific.

Contents of bodies are informative examples only.

Request:

~~~ http-message
GET /.well-known/transparency-configuration HTTP/1.1
Host: transparency.example
Accept: application/cbor
~~~

Response:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/cbor

Body (in CBOR diagnostic notation)

{
  "issuer": "https://transparency.example",
  "cose_keys_uri": "https://transparency.example/cose-keys"
}
~~~

Responses to this message are vendor-specific.
Fields that are not understood MUST be ignored.

### Transparency Service Keys

This endpoint is used to discover the public keys that can be used by relying parties to verify Receipts issued by the Transparency Service.

The Transparency Service responds with a COSE Key Set, as defined in {{Section 7 of RFC9052}}.

Request:

~~~ http-message
GET /cose-keys HTTP/1.1
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
    -2:h'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d',
    -3:h'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c',
    1:2,
    2:'kid1'
  },
  {
    -1:1,
    -2:h'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff',
    -3:h'20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e',
    1:2,
    2:'kid2'
  }
]
~~~

### Register Signed Statement

This endpoint instructs a Transparency Service to register a Signed Statement on its log.
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

18([                            / COSE Sign1                                           /
  <<{
    / signature alg         / 1:  -35, # ES384
    / key identifier        / 4:   h'75726e3a...32636573',
    / cose sign1 type       / 16:  "application/example+cose",
    / payload-hash-alg      / 258: -16, # sha-256
    / preimage-content-type / 259: "application/spdx+json",
    / payload-location      / 260: "https://.../manifest.json"
  }>>,                          / Protected Header                                     /
  {},                           / Unprotected Header                                   /
  h'935b5a91...e18a588a',       / Payload, sha-256 digest of file stored at Location   /
  h'269cd68f4211dffc...0dcb29c' / Signature                                            /
])
~~~

A Transparency Service depends on both the client's authentication context (if present) and the verification of the Signed Statement in the Registration Policy.

The Registration Policy for the Transparency Service MUST be applied before any additional processing.
The details of Registration Policies are out of scope for this document.

Response:

One of the following:

#### Status 201 - Registration is successful

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

#### Status 303 - Registration is running

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

### Query Registration Status

This endpoint lets a client query a Transparency Service for the registration status of a Signed Statement they have submitted earlier, and for which they have received a 303 or 302 - Registration is running response.

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

#### Status 302 - Registration is running

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

#### Status 200 - Asynchronous registration is successful

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
Client <-- 200 (Transparent Statement)      --- TS
           Location: .../entries/final123
~~~


#### Status 400 - Invalid Client Request

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

#### Status 400 - Invalid Client Request

The following expected errors are defined.
Implementations MAY return other errors, so long as they are valid {{RFC9290}} objects.

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: "Invalid locator",
  / detail /        -2: "Operation locator is not in a valid form"
}
~~~

#### Status 404 - Operation Not Found

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

#### Status 429 - Too Many Requests

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

### Resolve Receipt

Authentication SHOULD be implemented for this endpoint.

Request:

~~~ http-message
GET entries/67ed41f1de6a...cfc158694ed0befe HTTP/1.1
Host: transparency.example
Accept: application/cose
~~~

Response:

#### Status 200 - OK

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

#### Status 404 - Not Found

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

## Optional Endpoints

### Exchange Receipt

Authentication SHOULD be implemented for this endpoint.

Request:

~~~ http-message
POST receipt-exchange HTTP/1.1
Host: transparency.example
Accept: application/cose

Body (in CBOR diagnostic notation)

/ cose-sign1 / 18([
  / protected   / <<{
    / key / 4 : "mxA4KiOkQFZ-dkLebSo3mLOEPR7rN8XtxkJe45xuyJk",
    / algorithm / 1 : -7,  # ES256
    / vds       / 395 : 1, # RFC9162 SHA-256
    / claims / 15 : {
      / issuer  / 1 : "https://blue.example",
      / subject / 2 : "https://green.example/cli@v1.2.3",
      / iat / 6: 1443944944
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

Response:

#### Status 200 - OK

If a new Receipt can be issued for the given submitted Receipt:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/cose
Location: https://transparency.example/entries/67ed...befe

Body (in CBOR diagnostic notation)

/ cose-sign1 / 18([
  / protected   / <<{
    / key / 4 : "0vx7agoebGc...9nndrQmbX",
    / algorithm / 1 : -35,  # ES384
    / vds       / 395 : 1,  # RFC9162 SHA-256
    / claims / 15 : {
      / issuer  / 1 : "https://blue.example",
      / subject / 2 : "https://green.example/cli@v1.2.3",
      / iat / 6: 2443944944,
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
  / signature   / h'123227ed...ccd37123'
])
~~~
A TS may limit how often a new receipt can be issued, and respond with a 503 if a client requests new receipts too frequently.

The following HTTP endpoints are optional to implement.

### Resolve Signed Statement

This endpoint enables Transparency Service APIs to act like Artifact Repositories, and serve Signed Statements directly, instead of indirectly through Receipts.

Request:

~~~ http-message
GET /signed-statements/9e4f...688a HTTP/1.1
Host: transparency.example
Accept: application/cose
~~~

Response:

One of the following:

#### Status 200 - Success

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/cose

Body (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
~~~

#### Status 404 - Not Found

The following expected errors are defined.
Implementations MAY return other errors, so long as they are valid {{RFC9290}} objects.

~~~ http-message
HTTP/1.1 404 Not Found
Content-Type: application/concise-problem-details+cbor

{
  / title /         -1: \
          "Not Found",
  / detail /        -2: \
          "No Signed Statement found with the specified ID"
~~~

#### Eventual Consistency

For all responses additional eventually consistent operation details MAY be present.
Support for eventually consistent Receipts is implementation specific, and out of scope for this specification.

### Exchange Receipt

This endpoint is used to exchange old or expiring Receipts for fresh ones.

The `iat`, `exp` and `kid` claims can change each time a Receipt is exchanged.

This means that fresh Receipts can have more recent issued at times, further in the future expiration times, and be signed with new signature algorithms.

Request:

~~~ http-message
POST /exchange/receipt HTTP/1.1
Host: transparency.example
Accept: application/cose
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
      / iat     / 6 : 1750683311 # Pre-refresh
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

#### Status 200

A new Receipt:

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
      / iat     / 6 : 1750683573 # Post-refresh
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
  / signature   / h'48f67a8b...b474bb3a'
])
~~~

### Resolve Issuer

This endpoint is inspired by {{-SD-JWT-VC}}.

The following is a non-normative example of a HTTP request for the Issuer Metadata configuration when `iss` is set to `https://transparency.example/tenant/1234`:

Request:

~~~ http-message
GET /.well-known/issuer/tenant/1234 HTTP/1.1
Host: transparency.example
Accept: application/json
~~~

Response:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json

{
  "issuer": "https://transparency.example/tenant/1234",
  "jwks": {
    "keys": [
      {
        "kid": "urn:ietf:params:oauth\
                 :jwk-thumbprint:sha-256:Dgyo...agRo",
        "alg": "ES256",
        "use": "sig",
        "kty": "EC",
        "crv": "P-256",
        "x": "p-kZ4uOASt9IjQRTrWikGnlbGb-z3LU1ltwRjZaOS9w",
        "y": "ymXE1yltJPXgjQSRe9NweN3TLlSUALYZTzy83NVfdg0"
      },
      {
        "kid": "urn:ietf:params:oauth\
                 :jwk-thumbprint:sha-256:4Fzx...0ClE",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "use": "enc",
        "kty": "EC",
        "crv": "P-256",
        "x": "Vreuil95vzR6ixutgBBf2ota-rj97MvKfuJWB4qqp5w",
        "y": "NkUTeaoNlLRRsVRxHGDA-RsA0ex2tSpcd3G-4SmKXbs"
      }
    ]
  }
}
~~~

# Privacy Considerations

TODO

# Security Considerations

## General Scope

This document describes the interoperable API for client calls to, and implementations of, a Transparency Service as specified in {{-SCITT-ARCH}}.
As such the security considerations in this section are concerned only with security considerations that are relevant at that implementation layer.
All questions of security of the related COSE formats, algorithm choices, cryptographic envelopes, verifiable data structures and the like are handled elsewhere and out of scope for this document.

## Applicable Environment

SCITT is concerned with issues of cross-boundary supply-chain-wide data integrity and as such must assume a very wide range of deployment environments.
Thus, no assumptions can be made about the security of the computing environment in which any client implementation of this specification runs.

## User-host Authentication

{{-SCITT-ARCH}} defines 2 distinct roles that require authentication:
Issuers who sign Statements, and Clients that submit API calls on behalf of Issuers.
While Issuer authentication and signing of Statements is very important for the trustworthiness of systems implementing the SCITT building blocks, it is out of scope of this document.
This document is only concerned with authentication of API clients.

For those endpoints that require client authentication, Transparency Services MUST support at least one of the following options:

- HTTP Authorization header with a JWT
- domain-bound API key
- TLS client authentication

Where authentication methods rely on long term secrets, both clients and Transparency Services implementing this specification SHOULD allow for the revocation and rolling of authentication secrets.

## Primary Threats

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

Beyond this, implementers of Transparency Services SHOULD implement general good practice around network attacks, flooding, rate limiting etc.

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
There could be issues at the payload level (for instance, the statement "it is raining" may true when first submitted but not when replayed), but being payload-agnostic implementations of SCITT services cannot be required to worry about that.

If the semantic content of the payload are time-dependent and susceptible to replay attacks in this way then timestamps MAY be added to the protected header signed by the Issuer.

#### Message Deletion Attacks

Once registered with a Transparency Service, Registered Signed Statements cannot be deleted.
Thus, any message deletion attack must occur prior to registration else it is indistinguishable from a man-in-the-middle or denial-of-service attack on this interface.

# IANA Considerations

## Well-Known URI for Transparency Configuration

The following value is requested to be registered in the "Well-Known URIs" registry (using the template from {{RFC8615}}):

URI suffix: transparency-configuration
Change controller: IETF
Specification document(s): RFCthis.
Related information: N/A

TODO: Register them from here.

--- back
