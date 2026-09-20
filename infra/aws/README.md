# AWS infrastructure

AWS is Safeory's production hosting target. The service-level architecture,
security boundary, launch topology, scale-up path, and production-ready gate are
defined in `docs/architecture/aws.md`.

The deployed system must also satisfy the combined consumer-product and sync
contracts in `docs/architecture/combined-product.md` and
`docs/architecture/sync.md`, including account/household/private-and-shared
spaces, Account Secret review, key-envelope rotation, collaboration,
SecureLinks, generic reminders, and Trust Engine coordination.

Infrastructure as code will live in this directory. Do not treat manual AWS
console configuration as the source of truth.

The first implementation should create, at minimum:

- Route 53 + ACM;
- CloudFront with a private S3 static-web origin and `/api/*` API origin;
- ECR plus a small Graviton EC2 API/worker host;
- RDS PostgreSQL in private database subnets;
- a private S3 ciphertext-object bucket;
- Cognito User Pool account identity;
- SES notification email;
- IAM roles and Secrets Manager/SSM configuration;
- CloudWatch logging/metrics/alarms and backup policies.

`docker-compose.yml` remains the local development/integration environment and
is not the production deployment model.
