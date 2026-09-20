# Safeory AWS Infrastructure Baseline

Status: **approved implementation baseline**

This document records the infrastructure choices for Safeory. `PLAN.md` remains
the development sequence and product/security gate. This file defines how the
product is deployed on AWS, how infrastructure authentication works, how the
initial deployment stays inexpensive, and how it scales without requiring an
application rewrite.

The governing objective is:

> Start with the lowest practical AWS operating cost that still gives Safeory a
> fast, reliable user experience and a production-shaped architecture, while
> making later capacity, redundancy, and deployment expansion incremental rather
> than a migration to a different platform.

The initial target is not maximum redundancy. It is **maximum useful performance
per dollar with no architectural dead end**.

---

## 1. Finalized platform choices

Safeory will run on AWS.

Initial production baseline:

| Concern | Selected service / approach |
|---|---|
| Container orchestration | Amazon ECS |
| Initial ECS capacity | One Graviton EC2 instance, target `t4g.medium` class |
| Container registry | Amazon ECR |
| Public API ingress | Application Load Balancer |
| Static Safeory web app | S3 + CloudFront |
| TLS certificates | AWS Certificate Manager |
| DNS | Route 53 |
| Durable relational data | Amazon RDS for PostgreSQL |
| Ephemeral coordination/cache | Local Valkey container initially |
| Encrypted attachments/blobs | Amazon S3 |
| Transactional email | Amazon SES |
| Application/infra secrets | Secrets Manager and/or SSM Parameter Store |
| AWS workload authorization | IAM roles, not embedded access keys |
| Human AWS administration | IAM Identity Center / IAM with MFA and least privilege |
| CI -> AWS authentication | GitHub Actions OIDC -> short-lived AWS role |
| Monitoring/logging | CloudWatch |
| AWS control-plane audit | CloudTrail |
| Infrastructure as code | Terraform |
| Primary application database | PostgreSQL only |
| Product account identity | Adapted Bitwarden foundation auth/session/device model |
| Separate AWS identity provider for users | **None; do not add Cognito** |

The Bitwarden-derived foundation is backend/core infrastructure only. Safeory's
web frontend and browser-extension UI remain Safeory-owned as required by
`PLAN.md`.

---

## 2. Why ECS on EC2 is the starting compute model

We deliberately do **not** start on Kubernetes/EKS, and we do not use a
Lightsail-only architecture for the production baseline.

One ECS cluster backed by one Graviton EC2 node gives us:

- low fixed monthly cost;
- enough RAM/CPU headroom for the adapted foundation API, Safeory Coordinator,
  ephemeral Valkey, and small background workloads;
- container health checks and rolling deployments;
- ECR-backed immutable images;
- the same ECS service model we can later run on multiple EC2 nodes or Fargate;
- a clean path to Auto Scaling Groups and multiple Availability Zones;
- no requirement to redesign application services as the user base grows.

The initial host target is `t4g.medium` or the current equivalent Graviton class
providing roughly 2 vCPU and 4 GiB RAM. Exact instance generation/size may be
adjusted from load measurements without changing the architecture.

Build production images for both:

```text
linux/arm64
linux/amd64
```

Production should prefer ARM/Graviton after the complete foundation adaptation
suite proves the retained .NET/Rust/native dependencies work correctly on ARM.
AMD64 remains a supported fallback so Safeory is not locked to one CPU
architecture.

---

## 3. Initial topology

```text
                                      Internet
                                         |
                               Route 53 + ACM TLS
                                         |
                         +---------------+---------------+
                         |                               |
                    CloudFront                     Public ALB
                         |                               |
                    S3 web origin                       |
                (Safeory static export)                 |
                                                         v
                                               ECS on one EC2 node
                                              (Graviton, 4 GiB target)
                                                         |
                           +-----------------------------+-------------------+
                           |                             |                   |
                    Foundation API               Safeory Coordinator       Valkey
                      container                       container          ephemeral
                           |                             |
                           +--------------+--------------+
                                          |
                                  RDS PostgreSQL
                                          |
                     +--------------------+--------------------+
                     |                                         |
                 S3 ciphertext                              SES
                  attachments                         generic notifications
```

The current Safeory web application is already configured as a Next.js static
export (`output: "export"`). It should therefore be built once and served from S3
through CloudFront rather than consuming application-server CPU for frontend
asset delivery.

---

## 4. Initial network design: low cost without a dead end

The initial VPC should be created by Terraform with at least two Availability
Zones represented in the subnet layout even though only one application node and
one Single-AZ database instance are initially running.

Initial layout:

- two public subnets for the internet-facing ALB;
- two private database subnets for the RDS subnet group;
- one ECS/EC2 application node initially;
- RDS reachable only from the application security group;
- no direct public RDS access;
- no SSH ingress to the EC2 host;
- operator access through AWS Systems Manager Session Manager;
- security groups permit application ingress only from the ALB;
- outbound access is kept minimal and reviewed.

### No NAT Gateway initially

NAT Gateway has a meaningful fixed cost relative to a sub-100-user deployment.
Do not add it merely because it is a common reference architecture.

The initial ECS/EC2 node may use a tightly controlled public-subnet/public-egress
layout while all inbound application traffic still goes through the ALB and
administrative access uses SSM. The host security group must not expose SSH or
application ports directly to the Internet.

When Safeory moves to multiple application nodes and stronger multi-AZ isolation,
move ECS capacity to private application subnets and introduce the smallest
appropriate combination of NAT and/or VPC endpoints based on measured traffic
and actual AWS-service dependencies.

This is an infrastructure evolution, not an application rewrite.

---

## 5. Public ingress and TLS

### Web application

```text
User -> Route 53 -> CloudFront -> S3 static Safeory web build
```

Benefits:

- global edge caching;
- very low origin load;
- fast static UI delivery independent of API capacity;
- inexpensive scaling for JavaScript/CSS/icons/images;
- simple immutable deploy/rollback through versioned artifacts.

The S3 web bucket must not be generally public. CloudFront should be the intended
read path using the appropriate origin-access control.

### APIs

```text
User / extension -> HTTPS -> ALB -> ECS services
```

ACM supplies public TLS certificates. HTTP should redirect to HTTPS or be
disabled where practical.

The ALB remains in the design from the first live deployment even though one ECS
node could technically serve traffic directly. The fixed cost buys a stable
service boundary for:

- health-based target registration;
- rolling deployments;
- later multi-node scaling;
- cross-AZ targets;
- WAF attachment when enabled;
- future blue/green or weighted deployment strategies.

Do not couple client configuration to an EC2 IP address.

---

## 6. Authentication and identity

### 6.1 Safeory user/account authentication

Safeory does **not** introduce Cognito as a second product identity plane.

Product authentication, sessions, device identity, device/session revocation,
and account-level password-manager identity come from the cleaned and adapted
Bitwarden server + Rust SDK/core foundation.

Safeory-owned clients integrate with that foundation through reviewed Safeory
contracts. The frontend must not receive raw vault/account/content private keys
merely to make authentication easier.

Required properties:

- authenticated account sessions;
- device-aware sessions/credentials;
- explicit session/device revocation;
- server-side authentication state contains no usable vault content key;
- account/session logic remains compatible with zero-knowledge vault behavior;
- TOTP/passkey/password-manager cryptographic behavior is taken from or adapted
  from the reviewed foundation where appropriate;
- Safeory UI remains fully Safeory-owned.

### 6.2 Foundation -> Safeory Coordinator authentication

The Coordinator is a separate Safeory service and must not trust arbitrary
account/device identifiers supplied by a caller.

The foundation issues a **short-lived signed assertion** to the Coordinator.
The assertion must be:

- audience-bound to the Safeory Coordinator;
- account-bound;
- device/session-bound;
- explicitly scoped to permitted Coordinator operations;
- short lived;
- non-refreshable by the Coordinator;
- rejected when the originating foundation session/device is revoked;
- validated against issuer/signature/time/audience/scope before use.

Do not create a second long-lived Coordinator password/token for end users.

The exact token representation should reuse a mature signing/token mechanism
already available in the retained foundation or standard platform libraries. Do
not invent custom authentication cryptography.

### 6.3 AWS workload authentication

AWS workloads use IAM roles:

- ECS/EC2 instance role for ECS agent/host needs;
- ECS task/service role where supported for service-specific permissions;
- least-privilege access to S3, SES, Secrets Manager/SSM, CloudWatch, etc.;
- separate roles for deployment automation.

Do not place long-lived AWS access keys in images, repositories, `.env` files, or
CI secrets.

### 6.4 Human/operator authentication

Production AWS access requires:

- named human identities;
- MFA;
- least-privilege roles;
- no shared root/admin credentials;
- root account protected with strong MFA and not used for routine work;
- CloudTrail visibility for control-plane changes.

### 6.5 GitHub Actions authentication

GitHub Actions should authenticate to AWS through OIDC and assume a narrowly
scoped deployment role.

No long-lived AWS access key should be stored in GitHub Actions secrets.

---

## 7. PostgreSQL

Safeory standardizes on **Amazon RDS for PostgreSQL**.

Initial state:

- Single-AZ;
- small burstable Graviton-compatible instance class where supported;
- gp3/general-purpose storage sized conservatively;
- encrypted storage;
- automated backups and point-in-time recovery enabled;
- deletion protection enabled for production once operational workflows are
  established;
- public access disabled;
- TLS connections required where supported by the adapted foundation;
- application connection pools bounded.

Do not deploy MySQL or SQLite as production server database alternatives simply
because upstream Bitwarden supports them. `PLAN.md` requires pruning those
unused provider/migration surfaces after PostgreSQL equivalence is proven.

### Database ownership boundaries

Foundation durable state and Safeory Coordinator durable state must have clear
ownership boundaries.

Preferred early arrangement:

- one RDS PostgreSQL instance to control cost;
- separate databases or schemas as appropriate;
- separate database roles with least privilege;
- Coordinator cannot modify unrelated foundation tables;
- foundation cannot silently become owner of Coordinator policy state.

At larger scale the Coordinator may move to a separate RDS instance/cluster
without changing the logical contract.

### Do not add RDS Proxy initially

Use normal bounded application connection pooling first. Add RDS Proxy only if
connection churn, scale-out, failover behavior, or measured database pressure
justifies its cost.

---

## 8. Valkey / cache / ephemeral coordination

Valkey is **never a source of durable truth**.

Initial deployment:

- one small Valkey container on the ECS/EC2 node;
- no separate managed-cache bill;
- use only for ephemeral cache, rate limits, short-lived deduplication,
  coordination, or disposable work state.

Anything whose loss would corrupt a vault, lose an accepted user operation,
change a continuity policy, lose an authorization decision, or prevent recovery
must be committed to PostgreSQL/S3 or another explicitly durable store first.

When multiple application nodes make local Valkey insufficient, move it to
Amazon ElastiCache for Valkey (or the then-approved managed AWS Valkey service)
without changing product data semantics.

---

## 9. S3

S3 stores:

- encrypted attachment/blob payloads;
- static Safeory web deployment artifacts/origin content;
- selected infrastructure artifacts where appropriate;
- backup/export artifacts only when their encryption and retention model is
  explicitly approved.

Vault attachments must already be client-side/foundation encrypted before S3 is
treated as their durable object store. AWS server-side encryption is defense in
depth, not the zero-knowledge boundary.

Requirements:

- block public access on private-data buckets;
- least-privilege bucket policies;
- encryption at rest;
- versioning where required by the recovery model;
- lifecycle policies for obsolete deployment artifacts/versions;
- separate static-web and encrypted-user-data buckets/prefix policies;
- presigned/signed object operations should be scoped and short-lived when used;
- object keys must not leak unnecessary sensitive human-readable metadata.

---

## 10. SES

SES sends account/security/generic workflow notifications.

Email must not contain decrypted vault content, record names, secret values, or
other sensitive life-vault information by default.

Email may say, for example, that attention is required and direct the user to
open Safeory securely.

Configure SPF, DKIM, DMARC, bounce handling, complaint handling, and production
sending limits before public launch.

---

## 11. Secrets and key management

Use IAM + Secrets Manager/SSM for infrastructure/application secrets such as:

- database credentials when password auth remains necessary;
- third-party service credentials;
- signing material that is specifically server-side by design;
- deployment/runtime configuration that must not be committed to Git.

Use KMS-managed encryption for AWS infrastructure encryption where appropriate.

This does **not** make KMS the Safeory vault-key authority. User vault, record,
Space, attachment, and trustee private keys must continue to follow the
zero-knowledge/client-side architecture defined by `PLAN.md`.

---

## 12. Logging, monitoring, and auditing

Use CloudWatch for:

- ECS/EC2 CPU/memory/health;
- ALB request/latency/5xx health;
- RDS CPU, connections, free storage, latency and memory signals;
- application health/error counters;
- Coordinator queue/workflow health;
- deployment alarms;
- backup/maintenance alarms where available.

Use CloudTrail for AWS account/control-plane audit visibility.

### Logging prohibitions

Do not log:

- passwords;
- vault plaintext;
- decrypted attachments;
- raw vault/content/Space/trustee private keys;
- authentication bearer tokens;
- session secrets;
- full request/response bodies by default;
- sensitive form/autofill data;
- secret-bearing query parameters.

Ciphertext should also not be logged merely because it is encrypted; it adds
cost and unnecessary retained material.

Initial CloudWatch retention should be intentionally bounded. Increase retention
only for logs/metrics with a demonstrated operational/security requirement.

---

## 13. Deployment pipeline

Production deployment flow:

```text
GitHub
  |
  v
CI / complete required test gates
  |
  v
Build multi-arch container images
  |
  v
Amazon ECR
  |
  v
ECS rolling deployment
  |
  +--> ALB health checks
  +--> application readiness checks
  +--> automatic/controlled rollback on failed deployment
```

Static web deployment:

```text
Safeory Next.js static build
  |
  v
versioned S3 deployment
  |
  v
CloudFront
  |
  v
cache invalidation / immutable asset rollout
```

Production deployments must never skip the Foundation Adaptation & Stability
Gate or later release gates defined in `PLAN.md`.

Do not deploy directly from a developer laptop as the normal production path.

---

## 14. Terraform

Terraform is the selected infrastructure-as-code system.

Terraform should manage, at minimum:

- VPC/subnets/routes;
- security groups;
- ECS cluster/capacity/services;
- EC2 launch template/Auto Scaling configuration when introduced;
- ALB/listeners/target groups;
- ECR repositories;
- RDS/subnet groups/parameter configuration;
- S3 buckets/policies/lifecycle/versioning;
- CloudFront distribution;
- Route 53 records;
- ACM integration where practical;
- IAM roles/policies;
- CloudWatch alarms/log groups;
- SES infrastructure that can be safely automated;
- Secrets Manager/SSM resource definitions without committing secret values;
- WAF when enabled;
- later managed Valkey and multi-AZ resources.

Rules:

- no undocumented click-ops for durable production infrastructure;
- `terraform plan` must be reviewable before production changes;
- production state stored remotely with locking/versioning and restricted access;
- never commit Terraform state or plaintext secrets;
- keep environment differences parameterized rather than copying entire stacks.

---

## 15. Initial cost target

Pricing varies by AWS region and changes over time. The numbers below are
**engineering budget targets**, not a contractual AWS quote. Verify current
regional pricing before each production milestone.

For roughly 0-100 early users, design toward:

| Cost area | Initial monthly planning target |
|---|---:|
| One Graviton ECS/EC2 node | ~$20-30 |
| EBS for app host | ~$2-5 |
| Small Single-AZ RDS PostgreSQL | ~$15-25 |
| ALB and low request volume | ~$16-25 |
| Public IPv4 charges | region/current-pricing dependent |
| S3 + CloudFront at low usage | ~$0-3 |
| SES at low usage | ~$0-1 |
| Route 53 | ~$1 |
| ECR + Secrets/SSM + lean CloudWatch | ~$3-8 |
| **Initial target** | **roughly $65-85/month in a low-cost region** |

For a higher-priced region, allow additional headroom. The infrastructure should
be optimized against actual launch-region pricing rather than compromising
security or performance to hit an artificial exact dollar figure.

### Budget objective

For the first ~100 users:

> Keep the recurring AWS baseline below approximately $80/month where regional
> pricing permits, with a practical ceiling around $100/month in a higher-cost
> launch region, before taxes and unusual data-transfer/storage usage.

The expected difference between zero users and 100 users should be small because
the early bill is dominated by fixed compute/database/ingress costs rather than
requests, email, or encrypted-object storage.

---

## 16. What we deliberately do not buy initially

Do not add these until measurements, reliability requirements, or user/revenue
growth justify them:

- EKS/Kubernetes;
- multiple always-on ECS nodes;
- RDS Multi-AZ;
- Aurora;
- RDS Proxy;
- NAT Gateway merely by convention;
- dedicated managed Valkey;
- read replicas;
- multi-region active/active services;
- Global Accelerator;
- large WAF managed-rule bundles;
- excessive CloudWatch log retention;
- enterprise observability platforms duplicating existing needs;
- oversized instances "for future growth";
- a second product identity plane such as Cognito.

This is cost discipline, not a prohibition on future use. Add a service when a
measured need or explicit security/availability requirement justifies it.

---

## 17. Scaling path

The application architecture must make each stage an infrastructure change, not
a product rewrite.

### Stage A - development / pre-launch

- same containers and Terraform modules;
- smaller/non-continuous resources where safe;
- production-like PostgreSQL behavior for integration testing;
- no claim of HA.

### Stage B - approximately 0-100 users

- 1 ECS/EC2 Graviton node;
- 1 ALB;
- Single-AZ small RDS PostgreSQL;
- local ephemeral Valkey;
- S3/CloudFront/SES/Route 53;
- lean CloudWatch;
- automated backups;
- one region.

### Stage C - hundreds to low thousands of active users

Scale only when metrics require it:

- vertically resize ECS node and/or RDS first if that is the simplest solution;
- add a second ECS capacity node when availability or concurrent load justifies
  horizontal scaling;
- convert ECS capacity to an Auto Scaling Group/capacity provider;
- run at least two copies of critical stateless services;
- move Valkey to managed ElastiCache when cross-node coordination is required;
- increase RDS size/storage/IOPS based on measurements.

### Stage D - meaningful revenue / stronger HA requirement

- ECS capacity across at least two Availability Zones;
- critical ECS services desired count >= 2;
- RDS Multi-AZ;
- private application subnets;
- deliberate NAT/VPC endpoint design;
- managed Valkey if needed;
- WAF rules driven by measured attack/abuse patterns;
- stronger deployment/rollback and observability budgets.

### Stage E - large scale

Only after measurement:

- larger/independent service capacity pools;
- read replicas where read pressure actually exists;
- RDS/Aurora changes only if PostgreSQL limits or operational needs justify them;
- queue/event infrastructure when synchronous/background workload separation
  demonstrably needs it;
- multi-region disaster recovery or serving architecture when recovery/latency
  objectives require it;
- Fargate may replace or complement EC2 capacity if operational simplicity is
  worth the cost at that stage.

Never shard, introduce distributed databases, or create multi-region write
complexity in anticipation of a problem that measurements have not shown.

---

## 18. Scaling signals

Do not scale because of user-count milestones alone. Scale from measured service
health.

Track at minimum:

- ALB p50/p95/p99 target response latency;
- ALB 4xx/5xx and target health;
- ECS/EC2 CPU saturation and memory headroom;
- container restart/OOM frequency;
- RDS CPU, free memory, connections and storage;
- database query latency/slow queries;
- attachment request throughput and transfer volume;
- Coordinator work backlog/latency;
- Valkey memory and command latency;
- login/session/sync latency;
- sync failure/retry rates;
- deployment health and rollback rate.

The user experience, not arbitrary utilization vanity metrics, is the primary
scaling signal.

---

## 19. Availability and recovery progression

The earliest live deployment is intentionally not full HA. That limitation must
be understood internally and improved as the product becomes material.

From the beginning:

- RDS automated backups/PITR;
- encrypted S3 storage;
- infrastructure reproducible from Terraform;
- application containers reproducible from ECR/Git;
- no durable user state on the ECS/EC2 host;
- deployment rollback capability;
- periodic restore testing.

Later add:

- RDS Multi-AZ;
- multiple ECS nodes/services across AZs;
- managed distributed Valkey if needed;
- stronger backup-retention/recovery objectives;
- region-loss recovery drills;
- formal RTO/RPO targets based on actual customer/business requirements.

If the initial EC2 application node disappears, user vault truth must still be
recoverable from RDS/S3 and the application must be recreatable from Terraform +
ECR. The host itself is disposable.

---

## 20. Region strategy

Do not hard-code AWS region assumptions into application code.

The Terraform stack must accept the primary region as configuration.

Launch-region selection should favor the dominant first real-user cohort because
API round-trip latency matters more to user experience than saving a few dollars
on an instance. CloudFront handles global static frontend delivery, but dynamic
authentication/sync API latency still follows the primary backend region.

Use current AWS pricing and latency measurements to choose the initial region
before production launch. Adding a disaster-recovery or second serving region is
a later operational decision, not an initial requirement.

---

## 21. Security boundaries that infrastructure must preserve

Infrastructure changes must never violate these product guarantees:

- AWS does not receive usable vault/content keys merely because AWS hosts the
  services;
- RDS stores only the server-visible data/ciphertext allowed by the product
  architecture;
- S3 stores encrypted vault attachments/blobs;
- server logs do not become a plaintext side channel;
- Secrets Manager/KMS does not become a company-side vault-decryption backdoor;
- Coordinator policy state is separated from foundation authorization state;
- Coordinator trusts foundation-issued scoped assertions, not caller-provided
  account IDs;
- AWS administrators must not gain application decryption capability through
  infrastructure access alone;
- backups preserve the same zero-knowledge assumptions as primary storage;
- infrastructure convenience must never move raw user private keys into server
  components.

---

## 22. Performance principles

For the early product, performance should come primarily from architecture, not
oversized servers:

- serve the Safeory UI globally from CloudFront;
- keep APIs stateless where possible;
- keep expensive vault cryptography client-side;
- use bounded connection pools;
- avoid chatty API designs;
- compress/cache safe static content;
- upload/download encrypted attachments directly through scoped object flows
  where the security model permits;
- index PostgreSQL from measured queries;
- do not make Valkey a correctness dependency;
- deploy near the initial user cohort;
- measure p95/p99 latency before adding capacity.

A single 2-vCPU/4-GiB application node should have substantial headroom for the
first ~100 users if the adapted services are behaving correctly. If it does not,
profile and fix the bottleneck before assuming expensive infrastructure is the
answer.

---

## 23. Infrastructure acceptance gates

Before calling the initial AWS deployment production-ready, verify:

- [ ] Terraform can create the environment from a clean account/environment.
- [ ] Terraform plan is reviewable and contains no plaintext secrets.
- [ ] GitHub OIDC deploy role works with no stored long-lived AWS key.
- [ ] Multi-arch foundation/Coordinator images build and push to ECR.
- [ ] ECS service deployment and rollback work.
- [ ] ALB health checks reject unhealthy tasks.
- [ ] Safeory static web deploys through private S3 origin + CloudFront.
- [ ] ACM/TLS and Route 53 work for production domains.
- [ ] RDS is private, encrypted, backed up, and restorable.
- [ ] Foundation and Coordinator database permissions are separated.
- [ ] Encrypted attachment upload/download works through S3.
- [ ] SES production-domain authentication and bounce/complaint handling work.
- [ ] No SSH port is publicly exposed.
- [ ] SSM operator access works.
- [ ] CloudWatch alerts cover the critical service/database failure modes.
- [ ] CloudTrail is enabled for required account/control-plane visibility.
- [ ] Logging inspection finds no plaintext secrets, tokens, vault data, or raw
      user cryptographic keys.
- [ ] Coordinator rejects missing/expired/wrong-audience/wrong-scope assertions.
- [ ] Revoked foundation sessions/devices cannot continue Coordinator operations.
- [ ] Killing the application host does not destroy durable user state.
- [ ] A replacement host can be provisioned and services restored from IaC/ECR.
- [ ] RDS restore has been rehearsed.
- [ ] Current regional monthly cost estimate is recorded before launch.
- [ ] Foundation Adaptation & Stability Gate in `PLAN.md` is green.

Only after these checks should the initial environment be treated as the live
Safeory infrastructure baseline.

---

## 24. Sources to re-check before implementation milestones

AWS capabilities and pricing change. Before provisioning or materially scaling,
verify the current official documentation/pricing for:

- Amazon ECS pricing and EC2 launch type;
- EC2 Graviton instance specifications/pricing;
- Elastic Load Balancing pricing;
- RDS for PostgreSQL pricing and Multi-AZ behavior;
- S3 pricing;
- CloudFront pricing;
- SES pricing;
- Route 53 pricing;
- public IPv4 pricing;
- ElastiCache for Valkey pricing;
- CloudWatch/CloudTrail pricing;
- NAT Gateway and VPC endpoint pricing.

Do not preserve a stale architecture solely because a historical monthly-dollar
estimate was written here. Preserve the architectural goals: low fixed cost,
excellent latency, zero-knowledge boundaries, disposable stateless compute, and
incremental scaling without a product rewrite.
