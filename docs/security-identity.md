# Security boundaries and identity

## Caller access

The active Gateway and Report routes use anonymous Azure Function authentication and have no application-layer caller authentication. JWT verification, quotas, and ownership checks are deferred. Possession of a scan ID is not an authorization mechanism.

A deployment should not expose these endpoints as a production multitenant service based solely on this implementation. The historical study does not validate isolation between users.

## Internal identities

Source and Terraform use managed identities and Azure role assignments for internal resources. A credential chain can select different credentials by environment, so configuration is not proof of the credential used in every historical request.

| Principal | Declared access | Interpretation |
| --- | --- | --- |
| Gateway | Service Bus Data Sender | Supports enqueueing |
| Worker | Service Bus Data Receiver; Cosmos data contributor | Supports consumption and persistence |
| Report | Custom Cosmos reader actions | Supports metadata/read/query/change-feed actions; active endpoint uses point reads |
| Gateway | Custom Cosmos reader/create role | Still declared although active intake no longer writes queued documents |
| Worker | Storage Table Data Contributor | Advisory cache read/write |
| Function identities | Scoped deployment-container blob access | Artifact access; not caller authentication |

Unused declared access is a review item, not evidence that the application uses that path. “Managed identity everywhere” and “zero secrets” are stronger claims than the evidence supports.

## Network configuration

The current Function App resource definitions enable public network access. Cosmos defines a private endpoint and disables public network access. Service Bus uses the selected SKU without proving a private network boundary merely through its existence. Subnet integration and private endpoints have distinct effects; outbound VNet integration does not by itself make an HTTP service private.

## SSRF and outbound traffic

The Worker includes URL/address checks; Gateway has an optional secondary check that can fail open when unavailable or errored. These controls do not establish complete protection for redirects, DNS rebinding, every resource fetch, registry lookup, or subprocess path. The archived batch was not an adversarial SSRF validation.

## Finding and report confidentiality

Evidence, target URLs, identifiers, and logs can be sensitive even when a detector masks some values. The Worker logs message content; report retrieval returns saved documents. Do not assume blanket redaction or publish raw records as documentation examples.

## Responsible use

Read-oriented probing still makes additional requests. Limit scope and traffic under an appropriate authorization boundary. Public reachability, a blocklist, or use of GET/HEAD/OPTIONS does not establish permission. See [historical ethics disclosure](ethics.md) for what happened in the recorded study.


## Implementation and evidence

- [src/api/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/api/function_app.py)
- [src/report/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/report/function_app.py)
- [src/worker/main_scanner.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/main_scanner.py)
- [src/worker/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/function_app.py)
- [terraform/iam.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/iam.tf)
- [terraform/modules/function_app/main.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/modules/function_app/main.tf)
- [terraform/modules/cosmos_db/main.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/modules/cosmos_db/main.tf)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
