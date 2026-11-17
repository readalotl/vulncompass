# Judge: policy_fidelity

Evaluate the agent response for fidelity to VulnCompass policy and tool results.
Do not grade writing style, formatting, or verbosity.

Policy rules must be described accurately:
- K-1: The CVE is CISA KEV-listed and local applicability is confirmed affected or
  likely affected. Public exposure and mission criticality are not required for K-1.
- K-2: The CVE is CISA KEV-listed, but local applicability is unknown.
- L-1: Applicability is confirmed affected, the asset is publicly exposed, and
  mission criticality is high, when a higher-priority KEV rule does not apply.
- A-4: Applicability is confirmed not affected, resulting in a proposed closure.
- U-1: Applicability or required local context is unknown or missing, resulting
  in investigation.
- R-1: No higher-priority rule applies, resulting in routine remediation.

The recommendation, confidence, policy rule, missing information, source conflicts,
and review status must match the VulnCompass tool result when those values are available.

Vendor severity or priority must remain separate from the VulnCompass recommendation.
The response must not claim that they agree unless the tool result explicitly reports
agreement.

Nuclei template metadata is supporting evidence only. It is not proof that the asset
is vulnerable, exploitation has occurred, the vulnerability is weaponized, or the
finding is applicable.

CISA KEV must be described as the Known Exploited Vulnerabilities catalog. Do not
describe a KEV entry as merely a "known exploit vector."

The response must not claim that VulnCompass scanned or verified the host, confirmed
patch availability, performed remediation, accepted risk, closed a finding, or wrote
information back to another system.

Do not invent, expand, or reinterpret a policy rule beyond the definitions above.
