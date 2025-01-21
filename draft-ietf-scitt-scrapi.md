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
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: J. Geater
  name: Jon Geater
  organization: DataTrails Inc.
  email: jon.geater@datatrails.ai
  country: UK
  country: United States

contributor:
  - ins: O. Steele
    name: Orie Steele
    organization: Transmute
    email: orie@transmute.industries
    country: United States
    contribution: >
      Orie contributed examples, text, and URN structure to early version of this draft.

normative:
  I-D.draft-ietf-scitt-architecture: SCITT-ARCH
  RFC3553:
  RFC8615:
  RFC9052:
  RFC9110:
  RFC9290:
  IANA.params:

informative:
  I-D.draft-demarco-oauth-nonce-endpoint: Nonce-Endpoint
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

- Issuances of Signed Statements
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

## Terminology

{::boilerplate bcp14-tagged}

This specification uses the terms "Signed Statement", "Receipt", "Transparent Statement", "Artifact Repositories", "Transparency Service", "Append-Only Log" and "Registration Policy" as defined in {{-SCITT-ARCH}}.

This specification uses "payload" as defined in {{RFC9052}}.

# Endpoints

Authentication is out of scope for this document.
Implementations MAY authenticate clients, for example authorization or preventing denial of service attacks.
If Authentication is not implemented, rate limiting or other denial of service mitigation MUST be implemented.

All messages are sent as HTTP GET or POST requests.

If the Transparency Service cannot process a client's request, it MUST return an HTTP 4xx or 5xx status code, and the body SHOULD be a Concise Problem Details object {{RFC9290}} containing:

- title: A human-readable string identifying the error that prevented the Transparency Service from processing the request, ideally short and suitable for inclusion in log messages.
- detail: A human-readable string describing the error in more depth, ideally with sufficient detail enabling the error to be rectified.
- instance: A URN reference identifying the problem.
To facilitate automated response to errors, this document defines a set of standard tokens for use in the type field within the URN namespace of: "urn:ietf:params:scitt:error:".

TODO: RESOLVE this dangling media-type

application/concise-problem-details+cbor

NOTE: SCRAPI is not a CoAP API.
Nonetheless Constrained Problem Details objects {{RFC9290}} provide a useful CBOR encoding for problem details and avoids the need for mixing CBOR and JSON in endpoint implementations.

NOTE: Examples use '\\' line wrapping per {{RFC8792}}

Examples of errors may include:

~~~ cbor-diag
{
  / title /         -1: \
            "Bad Signature Algorithm",
  / detail /        -2: \
            "Signing algorithm 'WalnutDSA' not supported",
  / instance /      -3: \
            "urn:ietf:params:scitt:error:badSignatureAlgorithm"
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
Accept: application/cose
~~~

Response:

~~~ http-message
HTTP/1.1 200 Ok
Content-Type: application/cose

Payload (in CBOR diagnostic notation)

18([                   ; COSE_Sign1 structure with tag 18
    h'44A123BEEFFACE', ; Protected header (example bytes)
    {},                ; Unprotected header
    {                  ; Payload - CBOR map
        "issuer": "https://transparency.example",
        "base_url": "https://transparency.example/v1/scrapi",
        "oidc_auth_endpoint": "https://transparency.example/auth",
        "registration_policy": "https://transparency.example/statements/\
urn:ietf:params:scitt:statement:sha-256:base64url:5i6UeRzg1...qnGmr1o"
    },
    h'ABCDEF1234567890ABCDEF1234567890'  ; Signature
])
~~~

Responses to this message are vendor-specific.
Fields that are not understood MUST be ignored.

### Register Signed Statement

See notes on detached payloads below.

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
Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
~~~

If the `payload` is detached, the Transparency Service depends on the client's authentication context in the Registration Policy.
If the `payload` is attached, the Transparency Service depends on both the client's authentication context (if present) and the verification of the Signed Statement in the Registration Policy.

The Registration Policy for the Transparency Service MUST be applied before any additional processing.
The details of Registration Policies are out of scope for this document.

Response:

One of the following:

#### Status 201 - Registration is successful

If the Transparency Service is able to mint receipts within a reasonable time, it may return the receipt directly.

Along with the receipt the Transparency Service MAY return a locator in the HTTP response `Location` header, provided the locator is a valid URL.

~~~ http-message
HTTP/1.1 201 Created

Location: https://transparency.example/entries\
/67ed41f1de6a...cfc158694ed0befe

Content-Type: application/cose

Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
~~~

The response contains the Receipt for the Signed Statement.
Fresh Receipts may be requested through the resource identified in the Location header.

#### Status 202 - Registration is running

In cases where the registration request is accepted but the Transparency Service is not able to mint Receipts in a reasonable time, it returns a locator for the registration operation and a status code indicating the status of the operation, as in this non-normative example:

~~~ cbor-diag
{
  / locator / "OperationID": "67f89d5f0042e3ad42...35a1f190",
  / status /  "Status": "running",
}
~~~

`Status` must be one of the following:

- "running" - the operation is still in progress
- "succeeded" - the operation succeeded and the Receipt is ready

`OperationID` is Transparency Service-specific and MUST not be used for querying status in any Transparency Service other than the one that returned it.

If the `OperationID` is a valid URL, it MAY be included as a `Location` header in the HTTP response.

Transparency Services do not guarantee the retention of operation IDs for the entirety of their lifecycle.
A Transparency MAY delete operation records, and some operation ID lookups MAY return error 404, even though they were valid in the past.
The length of validity of the `OperationID` is Transparency Service specific.
Still, the Transparency Service MUST maintain a record of every running or successful operation until at least one client has fetched the completed Receipt.

The Transparency Service MAY include a `Retry-After` header in the HTTP response to help with polling.

~~~ http-message
HTTP/1.1 202 Accepted

Location: https://transparency.example/operations/67f8...f190

Content-Type: application/cbor
Retry-After: <seconds>

{
  / locator / "OperationID": "67f89d5f0042e3ad42...35a1f190",
  / status /  "Status": "running",
}
~~~

The response contains an ID referencing the running operation for Signed Statement Registration.

If 202 is returned, then clients should wait until Registration succeeded or failed by polling the Check Operation endpoint using the `OperationID` returned in the response.

#### Status 400 - Invalid Client Request

The following expected errors are defined.
Implementations MAY return other errors, so long as they are valid {{RFC9290}} objects.

~~~ http-message
HTTP/1.1 400 Bad Request
application/concise-problem-details+cbor

{
  / title /         -1: \
          "Bad Signature Algorithm",
  / detail /        -2: \
          "Signed Statement contained a non supported algorithm",
  / instance /      -3: \
          "urn:ietf:params:scitt:error:badSignatureAlgorithm"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
application/concise-problem-details+cbor

{
  / title /         -1: "\
          Confirmation Missing",
  / detail /        -2: \
          "Signed Statement did not contain proof of possession",
  / instance /      -3: \
          "urn:ietf:params:scitt:error:signed-statement:\
          confirmation-missing"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
application/concise-problem-details+cbor

{
  / title /         -1: \
          "Payload Missing",
  / detail /        -2: \
          "Signed Statement payload must be attached \
          (must be present)",
  / instance /      -3: \
          "urn:ietf:params:scitt:error:signed-statement:\
          payload-missing"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
application/concise-problem-details+cbor

{
  / title /         -1: \
          "Payload Forbidden",
  / detail /        -2: \
          "Signed Statement payload must be detached \
          (must not be present)",
  / instance /      -3: \
          "urn:ietf:params:scitt:error:signed-statement:\
          payload-forbidden"
}
~~~

~~~ http-message
HTTP/1.1 400 Bad Request
application/concise-problem-details+cbor

{
  / title /         -1: \
          "Rejected",
  / detail /        -2: \
          "Signed Statement not accepted by the current\
          Registration Policy",
  / instance /      -3: \
          "urn:ietf:params:scitt:error:signed-statement:\
          rejected-by-registration-policy"
}
~~~

### Check Registration

Authentication MAY be implemented for this endpoint.

This endpoint is used to check the progress of a long-running registration.

The following is a non-normative example of an HTTP request for the status of a running registration:

Request:

~~~ http-message
GET /operations/67f89d5f0042e3ad42...35a1f190, HTTP/1.1
Host: transparency.example
Accept: application/cbor
~~~

Response:

One of the following:

#### Status 200 - Operation complete

_Success case_

If the operation is complete and it _succeeded_, the Transparency Service returns a `status` of "succeeded" along with a locator that can fetch the Receipt.

`EntryID` is Transparency Service specific and MUST not be used for fetching Receipts in any Transparency Service other than the one that returned it.

If the `EntryID` is a valid URL, it MAY be included as a `Location` header in the HTTP response.

~~~ http-message
HTTP/1.1 200 Ok

Location: https://transparency.example/entries/67ed...befe

Content-Type: application/cbor

{
  / locator / "EntryID": "67f89d5f0042e3ad42...35a1f190",
  / status /  "Status": "succeeded",
}
~~~

_Failure case_

If the operation is complete and it _failed_, the Transparency Service returns a `status` of "failed" and an optional {{RFC9290}} Concise Problem Details object to explain the failure.

~~~ http-message
HTTP/1.1 200 Ok

Content-Type: application/cbor

{
  / status / "Status": "failed",
  / error /  "Error": {
    / title /         -1: \
            "Bad Signature Algorithm",
    / detail /        -2: \
            "Signed Statement contained a non supported algorithm",
    / instance /      -3: \
            "urn:ietf:params:scitt:error:badSignatureAlgorithm",
  }
}
~~~

#### Status 202 - Registration is (still) running

~~~ http-message
HTTP/1.1 202 Accepted

Location: https://transparency.example/operations/67f8...f190

Retry-After: <seconds>
~~~

If 202 is returned, then clients should continue polling the Check Operation endpoint using the operation identifier.

#### Status 400 - Invalid Client Request

The following expected errors are defined.
Implementations MAY return other errors, so long as they are valid {{RFC9290}} objects.

~~~ http-message
HTTP/1.1 400 Bad Request
application/concise-problem-details+cbor

{
  / title /         -1: "Invalid locator",
  / detail /        -2: "Operation locator is not in a valid form",
  / instance /      -3: "urn:ietf:params:scitt:error:invalidRequest"
}
~~~

#### Status 404 - Operation Not Found

If no record of the specified running operation is found, the Transparency Service returns a 404 response.

~~~ http-message
HTTP/1.1 404 Not Found
application/concise-problem-details+cbor

{
  / title /         -1: \
          "Operation Not Found",
  / detail /        -2: \
          "No running operation was found matching the requested ID",
  / instance /      -3: \
          "urn:ietf:params:scitt:error:notFound"
}
~~~

#### Status 429

If a client is polling for an in-progress registration too frequently then the Transparency Service MAY, in addition to implementing rate limiting, return a 429 response:

~~~ http-message
HTTP/1.1 429 Too Many Requests
Content-Type: application/concise-problem-details+cbor
Retry-After: <seconds>

{
  / title /         -1: \
          "Too Many Requests",
  / detail /        -2: \
          "Only <number> requests per <period> are allowed.",
  / instance /      -3: \
          "urn:ietf:params:scitt:error:tooManyRequests"
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

#### Status 200

If the Receipt is found:

~~~ http-message
HTTP/1.1 200 Ok
Location: https://transparency.example/entries/67ed...befe
Content-Type: application/cose

Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
~~~

#### Status 404

If there is no Receipt found for the specified `EntryID` the Transparency Service returns a 404 response:

~~~ http-message
HTTP/1.1 404 Not Found
application/concise-problem-details+cbor

{
  / title /         -1: \
          "Not Found",
  / detail /        -2: \
          "Receipt with entry ID <id> not known \
          to this Transparency Service",
  / instance /      -3: \
          "urn:ietf:params:scitt:error:receipt:not-found"
}
~~~

## Optional Endpoints

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
HTTP/1.1 200 Ok
Content-Type: application/cose

Payload (in CBOR diagnostic notation)

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
application/concise-problem-details+cbor

{
  / title /         -1: \
          "Not Found",
  / detail /        -2: \
          "No Signed Statement found with the specified ID",
  / instance /      -3: \
          "urn:ietf:params:scitt:error:notFound"
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
Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
~~~

#### Status 200

A new Receipt:

~~~ http-message
HTTP/1.1 200 Ok
Location: https://transparency.example/entries/67ed...befe

Content-Type: application/cose

Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
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
HTTP/1.1 200 Ok
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

### Request Nonce

This endpoint in inspired by {{-Nonce-Endpoint}}.

Authentication SHOULD NOT be implemented for this endpoint.
This endpoint is used to demonstrate proof of possession, which is the reason that authentication is not required.
Client holding signed statements that require demonstrating proof of possession MUST use this endpoint to obtain a nonce.

Request:

~~~ http-message
GET /nonce HTTP/1.1
Host: transparency.example
Accept: application/json
~~~

Response:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json

{
  "nonce": "d2JhY2NhbG91cmVqdWFuZGFt"
}
~~~

# Privacy Considerations

TODO

# Security Considerations

## General Scope

This document describes the interoperable API for client calls to, and implementations of, a Transparency Service as specified in {{-SCITT-ARCH}}.
As such the security considerations in this section are concerned only with security considerations that are relevant at that implementation layer.
All questions of security of the related COSE formats, algorithm choices, cryptographic envelopes,verifiable data structures and the like are handled elsewhere and out of scope of this document.

## Applicable Environment

SCITT is concerned with issues of cross-boundary supply-chain-wide data integrity and as such must assume a very wide range of deployment environments.
Thus, no assumptions can be made about the security of the computing environment in which any client implementation of this specification runs.

## User-host Authentication

{{-SCITT-ARCH}} defines 2 distinct roles that require authentication:
Issuers who sign Statements, and clients that submit API calls on behalf of Issuers.
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

Insertion attacks are mitigated by the use of the Issuer signature on the Signed Statement, therefore care must be taken in the protection of Issuer keys and credentials to avoid theft Issuer and impersonation.

Transparency Services MAY also implement additional protections such as anomaly detection or rate limiting in order to mitigate the impact of any breach.

### Out of Scope

#### Replay Attacks

Replay attacks are not particularly concerning for SCITT or SCRAPI:
Once a statement is made, it is intended to be immutable and non-repudiable, so making it twice should not lead to any particular issues.
There could be issues at the payload level (for instance, the statement "it is raining" may true when first submitted but not when replayed), but being payload-agnostic implementations of SCITT services cannot be required to worry about that.

If the semantic content of the payload are time dependent and susceptible to replay attacks in this way then timestamps MAY be added to the protected header signed by the Issuer.

#### Message Deletion Attacks

Once registered with a Transparency Service, Registered Signed Statements cannot be deleted.
Thus, any message deletion attack must occur prior to registration else it is indistinguishable from a man-in-the-middle or denial-of-service attack on this interface.

# TODO

TODO: Consider negotiation for Receipt as "JSON" or "YAML".
TODO: Consider impact of media type on "Data URIs" and QR Codes.

# IANA Considerations

## URN Sub-namespace for SCITT (urn:ietf:params:scitt)

IANA is requested to register the URN sub-namespace `urn:ietf:params:scitt` in the "IETF URN Sub-namespace for Registered Protocol Parameter Identifiers" Registry {{IANA.params}}, following the template in {{RFC3553}}:

~~~ output
   Registry name:  scitt
   Specification:  [RFCthis]
   Repository:  http://www.iana.org/assignments/scitt
   Index value:  No transformation needed.
~~~

## Well-Known URI for Issuers

The following value is requested to be registered in the "Well-Known URIs" registry (using the template from {{RFC8615}}):

URI suffix: issuer
Change controller: IETF
Specification document(s): RFCthis.
Related information: N/A

## Well-Known URI for Transparency Configuration

The following value is requested to be registered in the "Well-Known URIs" registry (using the template from {{RFC8615}}):

URI suffix: transparency-configuration
Change controller: IETF
Specification document(s): RFCthis.
Related information: N/A

TODO: Register them from here.

## Media Type Registration

This section requests registration of the "application/scitt.receipt+cose" media type {{RFC2046}} in the "Media Types" registry in the manner described in {{RFC6838}}.

To indicate that the content is a SCITT Receipt:

- Type name: application
- Subtype name: scitt.receipt+cose
- Required parameters: n/a
- Optional parameters: n/a
- Encoding considerations: TODO
- Security considerations: TODO
- Interoperability considerations: n/a
- Published specification: this specification
- Applications that use this media type: TBD
- Fragment identifier considerations: n/a
- Additional information:
  - Magic number(s): n/a
  - File extension(s): n/a
  - Macintosh file type code(s): n/a
- Person & email address to contact for further information: TODO
- Intended usage: COMMON
- Restrictions on usage: none
- Author: TODO
- Change Controller: IESG
- Provisional registration?  No

--- back
