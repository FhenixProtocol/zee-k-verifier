variable "compute_project_id" {
  type        = string
  description = "GCP project where the TEE VM runs (operated by the workload owner)"
}

variable "region" {
  type    = string
  default = "europe-west4"
}

variable "zone" {
  type    = string
  default = "europe-west4-b"
}

variable "image_digest" {
  type        = string
  description = "Image digest (sha256:...) that the launcher will run. Must match the digest pinned in the keys-side WIP condition."
}

variable "image_reference" {
  type        = string
  description = "Full image reference (path without @digest)"
}

# --- Multi-partner Shamir reconstruction of the zk-signer -----------------
variable "env" {
  type        = string
  description = <<-EOT
    Blessed environment selector, passed to the workload as tee-env-COFHE_ENV — the
    ONLY reader-source input. The partner set, per-partner WIF audiences, and
    the public-material bucket/object are BAKED into the binary (cofhe-keys env
    map) and selected by this value, fail-closed: an env the binary
    does not know aborts at boot. There are no partner/bucket/SA/audience
    variables to set here anymore.
  EOT
  validation {
    # Every value here must have a triplet in cofhe-keys' ENVIRONMENTS map, or
    # the reader fails closed at boot. Adding one is a rebuild by design.
    condition     = contains(["staging", "testnet", "mainnet"], var.env)
    error_message = "env must be one of: staging, testnet, mainnet."
  }
}

variable "store_cts_endpoint" {
  type        = string
  description = "The ct-server endpoint the verifier writes stored cts to, passed as STORE_CTS_ENDPOINT and injected into the baked config at boot. The one operator-supplied endpoint (mirrors teecryptor's CT_SOURCE_URL); everything else in config.toml is baked per-env into the image. The Shamir threshold is baked in the cofhe-keys env map (selected by `env`), no longer set here."
}

variable "gke_pod_cidr" {
  type        = string
  description = "GKE pod CIDR of the caller cluster"
}

variable "proofs_bucket" {
  type        = string
  description = "Name of the GCS bucket where zee-k writes verified zk proof inputs. The compute SA is granted the append-only zeeKProofsAppender custom role (storage.objects.create plus storage.objects.get for the health probe)."
}

variable "create_proofs_bucket" {
  type        = bool
  default     = false
  description = "Create the proofs bucket in this project. Leave false when the bucket already exists (e.g. provisioned per tdx-signer/DEPLOY.md); Terraform then only grants IAM on it."
}

variable "audit_logs_bucket" {
  type        = string
  default     = ""
  description = "Name of the bucket that keeps the routed proofs-bucket audit logs. Empty means \"<proofs_bucket>-audit-logs\". Terraform always creates this bucket."
}

variable "audit_logs_retention_days" {
  type = number
  # 24855 days is the provider's int32 ceiling for retention_period. GCS allows 100 years.
  default     = 24855
  description = "Retention period of the audit-log bucket, in days: the floor below which GCS refuses to delete an entry. 24855 (68 years) is the most the provider accepts, so the logs never expire in practice. The policy is unlocked, so a teardown can set this to 0, apply, and then delete the bucket. 0 means no retention policy at all."

  validation {
    condition     = var.audit_logs_retention_days >= 0 && var.audit_logs_retention_days <= 24855
    error_message = "audit_logs_retention_days must be between 0 and 24855, the provider's int32 ceiling."
  }
}

variable "audit_logs_retention_locked" {
  type        = bool
  default     = false
  description = "Lock the audit-log bucket retention policy. Off by default, which is what keeps the bucket deletable. The lock is permanent once applied: the period can be lengthened and never shortened or removed, and the bucket cannot be deleted until every entry ages out — at the default period, never in practice. Ignored when audit_logs_retention_days = 0."
}

variable "audit_logs_force_destroy" {
  type        = bool
  default     = false
  description = "Let `terraform destroy` delete the audit-log bucket while it still holds entries. False, the default, makes that destroy fail instead. Set it true for a deliberate teardown."
}

variable "machine_type" {
  type        = string
  default     = "c3-standard-22"
  description = "VM machine type. c3-standard-22 is the default — TFHE ServerKey deserialization is memory-heavy."
}

variable "verify_concurrency" {
  type        = number
  default     = null
  description = <<-EOT
    Override the /verify CPU gate (max concurrent TFHE proof verifies) via
    tee-env-VERIFY_CONCURRENCY. null => the binary auto-picks ceil(vCPUs / 32),
    the number of independent tfhe verification pools (one verify already
    saturates a pool's worth of cores). On <=32-vCPU machines (e.g.
    c3-standard-8) that is 1; raise only if a benchmark shows headroom. Scale
    throughput horizontally (mig_target_size), not by raising this.
  EOT
}

variable "max_inflight" {
  type        = number
  default     = null
  description = <<-EOT
    Override the /verify admission cap (max total in-flight requests before
    shedding 503) via tee-env-MAX_INFLIGHT. null => binary default (256). With a
    small CPU gate, admitted-but-queued requests only hold memory (a deserialized
    proof each) while waiting, so on a 32 GB / low-vCPU box prefer ~32-64.
  EOT
}

variable "mig_target_size" {
  type        = number
  default     = 1
  description = "Number of instances the MIG maintains."
}

# --- Networking (optional VPC creation) ------------------------------------
variable "network" {
  type        = string
  default     = "default"
  description = "VPC network (name or self-link) for the VM NIC and firewall. Ignored when create_network = true."
}

variable "subnetwork" {
  type        = string
  default     = ""
  description = "Subnetwork (name or self-link) for the VM NIC. Required when `network` is a custom-mode VPC. Ignored when create_network = true."
}

variable "create_network" {
  type        = bool
  default     = false
  description = "When true, create a dedicated VPC and subnet and ignore var.network / var.subnetwork."
}

variable "vpc_name" {
  type        = string
  default     = "zee-k-verifier-vpc"
  description = "Name of the VPC to create (used when create_network = true)."
}

variable "subnet_name" {
  type        = string
  default     = "zee-k-verifier-subnet"
  description = "Name of the subnet to create (used when create_network = true)."
}

variable "subnet_cidr" {
  type        = string
  default     = "10.0.0.0/24"
  description = "Primary CIDR for the created subnet (used when create_network = true)."
}

# --- Load balancer ----------------------------------------------------------
# Exactly one of ssl_certificate_id, ssl_certificate_map, ssl_domains, or wildcard_domain must be set.
variable "ssl_certificate_id" {
  type        = string
  default     = ""
  description = "Self-link of an existing classic Compute SSL certificate (google_compute_ssl_certificate). Mutually exclusive with the other SSL options."
}

variable "ssl_certificate_map" {
  type        = string
  default     = ""
  description = "Name of an existing Certificate Manager certificate map in this project, managed by a separate Terraform flow. The proxy will reference it via certificate_map. Mutually exclusive with the other SSL options."
}

variable "ssl_domains" {
  type        = list(string)
  default     = []
  description = "Domain names for a new Google-managed SSL certificate. Used only when ssl_certificate_id and wildcard_domain are both empty."
}

variable "wildcard_domain" {
  type        = string
  default     = ""
  description = "Base domain for a Google-managed wildcard certificate via Certificate Manager (e.g. \"example.com\" issues a cert for *.example.com). Requires adding the CNAME from dns_auth_cname_* outputs to your DNS. Mutually exclusive with ssl_certificate_id and ssl_domains."
}

variable "armor_rules_file" {
  type        = string
  default     = ""
  description = "Path to a JSON file containing Cloud Armor rules to add to the security policy. When empty, only the default allow-all rule applies. See armor_rules.json.example for the expected schema."
}

variable "armor_adaptive_protection" {
  type        = bool
  default     = true
  description = "Enable Cloud Armor Adaptive Protection. It learns the normal traffic pattern and reports layer 7 DDoS attacks in Cloud Logging, with a suggested mitigation rule."
}

variable "armor_rate_limit_enabled" {
  type        = bool
  default     = true
  description = "Add a per-source-IP rate limit rule to the security policy. A client above the threshold receives HTTP 429 for the ban duration."
}

variable "armor_rate_limit_threshold_count" {
  type        = number
  default     = 90
  description = "Requests one source IP may send per armor_rate_limit_interval_sec before Cloud Armor throttles it. Callers behind one egress IP count as a single client."
}

variable "armor_rate_limit_ban_threshold_count" {
  type        = number
  default     = 180
  description = "Requests one source IP may send per armor_rate_limit_interval_sec before Cloud Armor bans it for armor_rate_limit_ban_duration_sec."

  validation {
    condition     = var.armor_rate_limit_ban_threshold_count >= var.armor_rate_limit_threshold_count
    error_message = "The ban threshold must be greater than or equal to the throttle threshold."
  }
}

variable "armor_rate_limit_interval_sec" {
  type        = number
  default     = 60
  description = "Length of the sliding window for the rate limit counters, in seconds. Cloud Armor accepts 60, 120, 180, 300, 600, 1200, 1800, 2700 or 3600."

  validation {
    condition     = contains([60, 120, 180, 300, 600, 1200, 1800, 2700, 3600], var.armor_rate_limit_interval_sec)
    error_message = "Cloud Armor accepts only 60, 120, 180, 300, 600, 1200, 1800, 2700 or 3600 seconds."
  }
}

variable "armor_rate_limit_ban_duration_sec" {
  type        = number
  default     = 300
  description = "Time a banned source IP stays blocked, in seconds. It also sets the expiry of an auto-deployed Adaptive Protection rule."
}

# --- PSC consumer endpoint -------------------------------------------------
variable "enable_psc" {
  type        = bool
  default     = false
  description = "When true, Terraform creates the full PSC path: NAT subnet, service attachment (producer), and consumer endpoint + DNS in the Confidential Space VPC."
}

variable "gke_network" {
  type        = string
  default     = ""
  description = "Name of the GKE VPC network. Used to create the PSC NAT subnet on the producer side. Required when enable_psc = true."
}

variable "gke_ilb_forwarding_rule" {
  type        = string
  default     = ""
  description = "Name of the internal LB forwarding rule created by the ct-server-ilb k8s Service. Required when enable_psc = true. Find it with: gcloud compute forwarding-rules list --regions=<psc_region> --project=<project>"
}

variable "psc_nat_subnet_cidr" {
  type        = string
  default     = "10.0.128.0/29"
  description = "CIDR for the PSC NAT subnet created in the GKE VPC. Must not overlap with existing subnets."
}

variable "psc_consumer_subnet_cidr" {
  type        = string
  default     = "10.0.2.0/29"
  description = "CIDR for the PSC consumer subnet created in the Confidential Space VPC in psc_region. Must not overlap with existing subnets (var.subnet_cidr is 10.0.1.0/24)."
}

variable "psc_region" {
  type        = string
  default     = ""
  description = "Region for all PSC resources (NAT subnet, service attachment, consumer endpoint). Must match the GKE cluster region. Defaults to var.region when empty."
}

variable "psc_endpoint_port" {
  type        = number
  default     = 8080
  description = "Port the GKE service listens on. Passed to the workload as tee-env-GKE_SERVICE_PORT."
}

variable "enable_psc_dns" {
  type        = bool
  default     = false
  description = "When true, create a private Cloud DNS zone and A record resolving psc_dns_zone to the PSC endpoint IP. When false, tee-env-GKE_SERVICE_HOST is set to the endpoint IP directly."
}

variable "psc_dns_zone" {
  type        = string
  default     = "ct-server.internal."
  description = "DNS zone name (must end with '.') for the private zone created in the Confidential Space VPC. Only used when enable_psc_dns = true."
}

# NOTE: the GitHub Actions WIF (github_repository / github_workflow_ref) moved to
# the shared artifact-registry project (fhenix-artifacts-registry). This compute
# module no longer hosts a registry or WIF — the VM pulls from the artifact
# registry by digest.

