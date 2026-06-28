---
id: fhir
technology: "HL7 FHIR / SMART-on-FHIR"
domain: IT
safety_class: safe
severity: high
life_safety: false
match:
  ports: []
  banners: ["fhir", "CapabilityStatement", "application/fhir+json", "application/fhir+xml", "SMART", "smart-configuration"]
  markers: ["resourceType\":\"CapabilityStatement\"", "fhirVersion", "/.well-known/smart-configuration", "rest\":[{\"mode\":\"server\""]
quick_wins:
  - { cmd: "curl -sk https://{host}/metadata -H 'Accept: application/fhir+json' | python3 -m json.tool | head -80", safety: safe, note: "Fetch CapabilityStatement — reveals FHIR version, resource types, search params, and auth requirements. Read-only, unauthenticated." }
  - { cmd: "curl -sk https://{host}/.well-known/smart-configuration | python3 -m json.tool", safety: safe, note: "Retrieve SMART-on-FHIR authorization endpoints, grant types, and supported scopes. Unauthenticated disclosure." }
  - { cmd: "curl -sk https://{host}/metadata -H 'Accept: application/fhir+json' | python3 -c \"import sys,json; cs=json.load(sys.stdin); [print(r.get('type')) for r in cs.get('rest',[{}])[0].get('resource',[])]\"", safety: safe, note: "Parse and list all exposed resource types from the CapabilityStatement without touching patient data." }
  - { cmd: "curl -sk https://{host}/Patient/{id} -H 'Accept: application/fhir+json' -H 'Authorization: Bearer <token>'", safety: intrusive, note: "BOLA/IDOR probe — attempt to fetch a patient record by substituting another patient's ID. Requires a valid bearer token from a legitimate session. Active, generates audit log entries." }
  - { cmd: "curl -sk 'https://{host}/Patient?_count=1' -H 'Accept: application/fhir+json' -H 'Authorization: Bearer <token>'", safety: intrusive, note: "Search Patient bundle with minimal count to confirm unauthenticated or over-privileged search. Active — audit-logged by conformant servers." }
references: ["CVE-2022-3202", "CVE-2023-28432", "ICSMA-21-049-01"]
mitre: "T1530"
---
# HL7 FHIR / SMART-on-FHIR

HL7 FHIR (Fast Healthcare Interoperability Resources) is the dominant REST-based standard for
exchanging electronic health records. FHIR servers expose a structured HTTP API at a base URL
(e.g. `https://ehr.example.com/fhir/R4/`) and advertise their capabilities via a mandatory
`/metadata` endpoint that returns a `CapabilityStatement` JSON/XML document — no authentication
required by the spec. SMART-on-FHIR layered on top provides OAuth2/OIDC for delegated access;
authorization server metadata is published at `/.well-known/smart-configuration`. Both unauthenticated
endpoints are rich reconnaissance targets, disclosing FHIR version, all resource types, search
parameter names, and the full OAuth2 grant-type surface without any credential.

**BOLA / IDOR on `/Patient/{id}`.** FHIR resource URLs are predictable: integer or UUID patient
identifiers are often sequential or guessable. A correctly-scoped SMART token grants access only to
the launching patient (`patient/*.read`), but misconfigured servers may accept any bearer token to
fetch any Patient resource — a textbook Broken Object-Level Authorization (BOLA/IDOR) vulnerability
that exposes PHI at scale. Test by substituting a different patient `id` in the path while using a
token issued for a known patient. Conformant servers must enforce the token's patient context and
return HTTP 403; returning data for a different patient is a finding. Observation, AllergyIntolerance,
Condition, MedicationRequest, and DiagnosticReport endpoints carry the same risk pattern.

**Safe-first testing.** Begin with the two unauthenticated read-only endpoints (`/metadata` and
`/.well-known/smart-configuration`) to map the attack surface before using any credentials. These
calls are specified to be publicly accessible and generate no PHI exposure. All subsequent probes
that use a bearer token are intrusive — they generate audit-log entries on any HIPAA-compliant
server and should only be executed against in-scope targets with explicit written authorization.
Never issue write-capable methods (POST/PUT/PATCH/DELETE on FHIR resources) without scoped
authorization; creating or altering clinical resources can corrupt patient records and violate
HIPAA safe-harbor requirements.

**Remediation.** Enforce token-bound patient context on every resource read; return HTTP 403 (not
404) for out-of-scope resources. Validate `launch/patient` and `patient` claims server-side on
every request. Implement SMART scopes (`patient/Patient.read`, not `user/Patient.read`) for
patient-portal clients. Require PKCE for all authorization code flows. Restrict `/metadata` to
internal networks if organizational policy permits. Audit logs must capture resource-level access
per the HIPAA Audit Controls standard (§ 164.312(b)). Map EHR API misconfigurations against
MITRE ATT&CK T1530 (Data from Cloud Storage) and relevant ONC/CISA healthcare advisories.
