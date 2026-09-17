# zee-k-verifier — COMPUTE side (workload owner). Deploy target: a per-env
# compute project.
#
# Owns the Confidential TDX VM (in a MIG for template-based rolling updates),
# its firewall, the runtime SA, and an HTTPS load balancer. The VM attests,
# then federates per-partner (attest -> STS) to read each Shamir share directly
# from the partner projects' Secret Manager. It PULLS its image from the shared
# fhenix-artifacts-registry project.
#
# Applied AFTER the keys module (consumes its outputs) and AFTER the image
# exists (the digest is pinned on both sides). State lives in the COMPUTE
# project's GCS bucket.

terraform {
  required_version = ">= 1.5"
  # Partial backend config passed at init. compute-module state lives in the
  # COMPUTE project's bucket:
  #   terraform init -backend-config="bucket=<compute-project>-tfstate" \
  #                  -backend-config="prefix=zeek/compute"
  backend "gcs" {}
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.compute_project_id
  region  = var.region
  zone    = var.zone
}

locals {
  apis = toset(concat(
    [
      "cloudresourcemanager.googleapis.com",
      "compute.googleapis.com",
      "confidentialcomputing.googleapis.com",
      "artifactregistry.googleapis.com",
      "iam.googleapis.com",
      "iamcredentials.googleapis.com",
      "sts.googleapis.com",
      "logging.googleapis.com",
      "storage.googleapis.com",
    ],
    var.wildcard_domain != "" ? ["certificatemanager.googleapis.com"] : [],
    var.enable_psc ? ["dns.googleapis.com"] : [],
  ))
}

resource "google_project_service" "apis" {
  for_each           = local.apis
  service            = each.value
  disable_on_destroy = false
}

# --- Compute SA ---------------------------------------------------------
# Pulls the image from the shared Artifact Registry, writes logs, calls the
# Confidential Computing API. Does NOT touch keys — key access goes through
# attestation -> per-partner WIF federation (each partner's own SM token).
resource "google_service_account" "compute" {
  account_id   = "zee-k-verifier-compute"
  display_name = "zee-k-verifier — compute SA"
  description  = "Attached to the TEE VM. Pulls image, writes logs, calls CC API. Does NOT touch keys."
  depends_on   = [google_project_service.apis]
}

resource "google_project_iam_member" "log_writer" {
  project = var.compute_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.compute.email}"
}

# The verifier pushes its metrics to the Telemetry API as this SA. Metrics-only
# on purpose: telemetry.writer would also grant trace and log write.
resource "google_project_iam_member" "telemetry_writer" {
  project = var.compute_project_id
  role    = "roles/telemetry.metricsWriter"
  member  = "serviceAccount:${google_service_account.compute.email}"
}

resource "google_project_iam_member" "confidential_workload" {
  project = var.compute_project_id
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.compute.email}"
}

# Holds zk proof inputs the workload writes at verify time. Created here only
# when create_proofs_bucket = true; otherwise the bucket is assumed to already
# exist and Terraform only grants IAM on it.
resource "google_storage_bucket" "proofs" {
  count                       = var.create_proofs_bucket ? 1 : 0
  name                        = var.proofs_bucket
  project                     = var.compute_project_id
  location                    = var.region
  uniform_bucket_level_access = true
  depends_on                  = [google_project_service.apis]
}

# Append-only access to the proofs bucket. GCS needs objects.delete to replace a
# live object, so create-without-delete makes every write a new object: the
# workload can add verified inputs and can never remove or rewrite one.
# objects.get is here because the boot probe and the health probe both read a
# synthetic key and expect a 404 — without get, GCS answers 403 and the VM
# fails to start.
resource "google_project_iam_custom_role" "proofs_appender" {
  role_id     = "zeeKProofsAppender"
  title       = "zee-k verifier — proofs appender"
  description = "Append-only writes to the verified-inputs bucket. No delete, no overwrite."
  stage       = "GA"
  permissions = [
    "storage.objects.create",
    "storage.objects.get",
  ]
}

resource "google_storage_bucket_iam_member" "proofs_writer" {
  bucket     = var.proofs_bucket
  role       = google_project_iam_custom_role.proofs_appender.id
  member     = "serviceAccount:${google_service_account.compute.email}"
  depends_on = [google_storage_bucket.proofs]
}

# --- Proofs-bucket audit trail ------------------------------------------
# Admin Activity logs are always on. Data Access logs are off by default, so
# turn them on for GCS and route the proofs-bucket entries to their own bucket,
# which the workload SA cannot reach.
#
# This resource is authoritative for storage.googleapis.com in the project: it
# replaces any audit config already set for that service. Data Access logging
# is per-service, not per-bucket, so it covers every bucket in the project; the
# sink filter is what narrows the persisted copy to the proofs bucket.
resource "google_project_iam_audit_config" "storage" {
  project = var.compute_project_id
  service = "storage.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

locals {
  audit_logs_bucket = var.audit_logs_bucket != "" ? var.audit_logs_bucket : "${var.proofs_bucket}-audit-logs"
}

# Keeps the routed audit entries forever. Two separate things hold that:
#   * no lifecycle rule, so nothing ages the entries out — GCS deletes an object
#     only when a rule says to;
#   * a retention policy at the GCS maximum, so a delete is refused outright,
#     whatever the caller's IAM says.
# The policy stays UNLOCKED, which is what keeps the bucket deletable. An
# unlocked policy can be removed, so a deliberate teardown is a two-step: set
# audit_logs_retention_days = 0 and apply, then destroy. A locked policy is the
# one-way version — nobody can shorten or remove it, and the bucket cannot go
# away until every entry ages out, which at this period is never in practice.
resource "google_storage_bucket" "audit_logs" {
  name                        = local.audit_logs_bucket
  project                     = var.compute_project_id
  location                    = var.region
  uniform_bucket_level_access = true

  # false keeps `terraform destroy` from emptying the audit trail: the destroy
  # fails while entries remain. Flip it in the tfvars for a deliberate teardown.
  force_destroy = var.audit_logs_force_destroy

  versioning {
    enabled = true
  }

  dynamic "retention_policy" {
    for_each = var.audit_logs_retention_days > 0 ? [1] : []
    content {
      retention_period = var.audit_logs_retention_days * 86400
      is_locked        = var.audit_logs_retention_locked
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_logging_project_sink" "proofs_audit" {
  name        = "zee-k-proofs-audit"
  project     = var.compute_project_id
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"

  filter = <<-EOT
    resource.type="gcs_bucket"
    resource.labels.bucket_name="${var.proofs_bucket}"
    (log_id("cloudaudit.googleapis.com/activity") OR log_id("cloudaudit.googleapis.com/data_access") OR log_id("cloudaudit.googleapis.com/system_event") OR log_id("cloudaudit.googleapis.com/policy"))
  EOT

  # Gives the sink its own service identity instead of the shared project one,
  # so the grant below reaches this sink alone.
  unique_writer_identity = true
}

# The sink writes as its own identity, and appends only, like the workload.
resource "google_storage_bucket_iam_member" "audit_sink_writer" {
  bucket = google_storage_bucket.audit_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.proofs_audit.writer_identity
}

# --- VPC + subnet (optional) --------------------------------------------
resource "google_compute_network" "zee_k_verifier" {
  count                   = var.create_network ? 1 : 0
  name                    = var.vpc_name
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "zee_k_verifier" {
  count         = var.create_network ? 1 : 0
  name          = var.subnet_name
  region        = var.region
  network       = google_compute_network.zee_k_verifier[0].self_link
  ip_cidr_range = var.subnet_cidr
  # Private Google Access lets instances reach Google APIs (attestation, Secret
  # Manager, Artifact Registry) without an external IP.
  private_ip_google_access = true
}

locals {
  network    = var.create_network ? google_compute_network.zee_k_verifier[0].self_link : var.network
  subnetwork = var.create_network ? google_compute_subnetwork.zee_k_verifier[0].self_link : (var.subnetwork != "" ? var.subnetwork : null)
  psc_region = var.psc_region != "" ? var.psc_region : var.region
  # Google's fixed IAP TCP-forwarding range. Hardcoded rather than a variable:
  # it is the same everywhere, and the metrics debug rule must never be widened
  # by an operator into a scrape path.
  iap_range = "35.235.240.0/20"
}

# --- Firewall -----------------------------------------------------------
resource "google_compute_firewall" "allow_signer_from_gke" {
  name          = "allow-zee-k-verifier-from-gke"
  network       = local.network
  source_ranges = [var.gke_pod_cidr]
  target_tags   = ["zee-k-verifier"]
  allow {
    protocol = "tcp"
    ports    = ["3001"]
  }
  depends_on = [google_project_service.apis]
}

# The text exposition on :9090 — a DEBUG surface, not a scrape target. Metrics
# reach Cloud Monitoring by OTLP push; this rule exists so an operator can read
# the in-process counters through `gcloud compute start-iap-tunnel` when a push
# looks wrong. Deliberately narrower than the GKE pod range: only IAP.
resource "google_compute_firewall" "allow_metrics_debug_over_iap" {
  name          = "allow-zee-k-verifier-metrics-debug-iap"
  network       = local.network
  direction     = "INGRESS"
  source_ranges = [local.iap_range]
  target_tags   = ["zee-k-verifier"]
  allow {
    protocol = "tcp"
    ports    = ["9090"]
  }
  depends_on = [google_project_service.apis]
}

# GCP health-check probes come from these two ranges; allow them to :3001.
resource "google_compute_firewall" "allow_health_checks" {
  name          = "allow-zee-k-verifier-health-checks"
  network       = local.network
  direction     = "INGRESS"
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["zee-k-verifier"]
  allow {
    protocol = "tcp"
    ports    = ["3001"]
  }
  depends_on = [google_project_service.apis]
}

# --- PSC (Confidential Space → GKE ct-server:9451) ----------------------
# Producer side (GKE VPC): PSC NAT subnet + service attachment.
# Consumer side (CS VPC):  reserved IP + forwarding rule + private DNS.

resource "google_compute_subnetwork" "psc_nat" {
  count         = var.enable_psc ? 1 : 0
  name          = "ct-server-psc-nat"
  region        = local.psc_region
  network       = var.gke_network
  ip_cidr_range = var.psc_nat_subnet_cidr
  purpose       = "PRIVATE_SERVICE_CONNECT"
  depends_on    = [google_project_service.apis]

  lifecycle {
    precondition {
      condition     = var.gke_network != ""
      error_message = "gke_network must be set when enable_psc = true."
    }
  }
}

resource "google_compute_service_attachment" "ct_server" {
  count                 = var.enable_psc ? 1 : 0
  name                  = "ct-server-attachment"
  region                = local.psc_region
  enable_proxy_protocol = false
  connection_preference = "ACCEPT_AUTOMATIC"
  nat_subnets           = [google_compute_subnetwork.psc_nat[0].self_link]
  target_service        = "https://www.googleapis.com/compute/v1/projects/${var.compute_project_id}/regions/${local.psc_region}/forwardingRules/${var.gke_ilb_forwarding_rule}"
  depends_on            = [google_project_service.apis]

  lifecycle {
    precondition {
      condition     = var.gke_ilb_forwarding_rule != ""
      error_message = "gke_ilb_forwarding_rule must be set when enable_psc = true."
    }
  }
}

resource "google_compute_subnetwork" "psc_consumer" {
  count         = var.enable_psc ? 1 : 0
  name          = "zee-k-verifier-psc-consumer"
  region        = local.psc_region
  network       = local.network
  ip_cidr_range = var.psc_consumer_subnet_cidr
  depends_on    = [google_project_service.apis]
}

resource "google_compute_address" "psc_endpoint" {
  count        = var.enable_psc ? 1 : 0
  name         = "zee-k-verifier-psc-ip"
  region       = local.psc_region
  subnetwork   = google_compute_subnetwork.psc_consumer[0].self_link
  address_type = "INTERNAL"
  depends_on   = [google_project_service.apis]
}

resource "google_compute_forwarding_rule" "psc_endpoint" {
  count                 = var.enable_psc ? 1 : 0
  name                  = "zee-k-verifier-psc-endpoint"
  region                = local.psc_region
  network               = local.network
  subnetwork            = google_compute_subnetwork.psc_consumer[0].self_link
  ip_address            = google_compute_address.psc_endpoint[0].id
  target                = google_compute_service_attachment.ct_server[0].self_link
  load_balancing_scheme = ""
  # Required: the Confidential Space VM is in europe-west4 but the PSC endpoint
  # is in europe-west1. Without this, PSC only accepts traffic from the same region.
  allow_psc_global_access = true
  depends_on              = [google_project_service.apis]
}

resource "google_dns_managed_zone" "psc" {
  count      = var.enable_psc && var.enable_psc_dns ? 1 : 0
  name       = "zee-k-verifier-psc-zone"
  dns_name   = var.psc_dns_zone
  visibility = "private"

  private_visibility_config {
    networks {
      network_url = local.network
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_dns_record_set" "psc" {
  count        = var.enable_psc && var.enable_psc_dns ? 1 : 0
  name         = var.psc_dns_zone
  type         = "A"
  ttl          = 300
  managed_zone = google_dns_managed_zone.psc[0].name
  rrdatas      = [google_compute_address.psc_endpoint[0].address]
}

# --- Instance template --------------------------------------------------
# create_before_destroy lets rolling updates build the new template before
# tearing down the old one — the MIG will never reference a deleted template.
resource "google_compute_instance_template" "zee_k_verifier" {
  name_prefix  = "zee-k-verifier-"
  machine_type = var.machine_type
  region       = var.region
  tags         = ["zee-k-verifier"]

  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = "TDX"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  # Confidential VMs cannot live-migrate.
  scheduling {
    on_host_maintenance = "TERMINATE"
  }

  # Instance templates use disk{} not boot_disk{}.
  disk {
    auto_delete  = true
    boot         = true
    source_image = "projects/confidential-space-images/global/images/family/confidential-space"
    disk_size_gb = 100
    disk_type    = "pd-balanced"
  }

  network_interface {
    network    = local.network
    subnetwork = local.subnetwork
    access_config {}
  }

  service_account {
    email  = google_service_account.compute.email
    scopes = ["cloud-platform"]
  }

  # No data disk: Confidential Space's tee-mount is tmpfs-only. The TFHE artifacts
  # are fetched from the baked public bucket at boot; the runtime config is baked
  # into the image per-env and merged in memory (no config fetch, no /app/config).
  # Base metadata + the two optional concurrency knobs, emitted only when set
  # (null => omit the tee-env, letting the binary use its built-in default).
  # NOTE: tee-env-VERIFY_CONCURRENCY / MAX_INFLIGHT / STORE_CTS_ENDPOINT are only
  # honoured because they are in the Dockerfile's allow_env_override label —
  # otherwise the launcher silently drops them.
  metadata = merge(
    {
      "tee-image-reference"        = "${var.image_reference}@${var.image_digest}"
      "tee-restart-policy"         = "OnFailure"
      "tee-container-log-redirect" = "true"
      "tee-mount"                  = "type=tmpfs,source=tmpfs,destination=/app/keys"

      # Only vars listed in the Dockerfile's allow_env_override label are passed
      # through by the Confidential Space launcher — all others are silently ignored.
      # ENV selects the blessed environment; the partner set, per-partner WIF
      # audiences, the public-material location, the Shamir threshold, AND the whole
      # runtime config.toml are BAKED into the binary (cofhe-keys env map + baked
      # config) and resolved fail-closed. The zk-signer secret NAME is likewise a
      # committed const. STORE_CTS_ENDPOINT is the one operator-supplied endpoint
      # (the ct-server the verifier writes to) — a setMetadata-capable operator can
      # set that endpoint but cannot point the reader at partners/buckets they control.
      "tee-env-COFHE_ENV"          = var.env
      "tee-env-STORE_CTS_ENDPOINT" = var.store_cts_endpoint
    },
    var.verify_concurrency == null ? {} : { "tee-env-VERIFY_CONCURRENCY" = tostring(var.verify_concurrency) },
    var.max_inflight == null ? {} : { "tee-env-MAX_INFLIGHT" = tostring(var.max_inflight) },
  )

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    google_project_iam_member.log_writer,
    google_project_iam_member.confidential_workload,
    google_compute_firewall.allow_signer_from_gke,
  ]
}

# --- Managed Instance Group ---------------------------------------------
# Updates are MANUAL by design. OPPORTUNISTIC means the MIG never rolls a
# running instance on its own: bumping image_digest and `terraform apply`
# only re-points the template — the live VM keeps the old image until an
# operator explicitly rolls it:
#   gcloud compute instance-groups managed rolling-action replace zee-k-verifier-mig \
#     --zone=<zone> --max-surge=1 --max-unavailable=0
# REPLACE (not RESTART/REFRESH): a Confidential VM's boot image can't change
# in place, so the instance is recreated — which also forces fresh attestation.
resource "google_compute_instance_group_manager" "zee_k_verifier" {
  name               = "zee-k-verifier-mig"
  base_instance_name = "zee-k-verifier"
  zone               = var.zone

  version {
    instance_template = google_compute_instance_template.zee_k_verifier.id
  }

  target_size = var.mig_target_size

  update_policy {
    type                  = "OPPORTUNISTIC"
    minimal_action        = "REPLACE"
    max_surge_fixed       = 1
    max_unavailable_fixed = 0
  }

  # Health-gate rolling updates and autoheal dead instances. Combined with
  # max_unavailable=0 above, a `rolling-action replace` now waits for the new
  # instance to PASS this health check before deleting the old one — automatic
  # zero-downtime rolls, no manual surge/verify/drop. initial_delay_sec must
  # exceed worst-case boot: VM start + TDX attestation + Secret Manager key
  # fetch + (memory-heavy) ServerKey deserialize; 300s leaves ample margin so a
  # still-booting-but-healthy instance is never killed mid-start.
  auto_healing_policies {
    health_check      = google_compute_health_check.zee_k_verifier.id
    initial_delay_sec = 300
  }

  named_port {
    name = "http"
    port = 3001
  }
}

# --- Load balancer ------------------------------------------------------

resource "google_compute_global_address" "lb" {
  name = "zee-k-verifier-lb-ip"
}

# Created only when using the classic Compute-managed cert path (no existing cert, no wildcard).
resource "google_compute_managed_ssl_certificate" "lb" {
  count = var.ssl_certificate_id == "" && var.wildcard_domain == "" && var.ssl_certificate_map == "" ? 1 : 0
  name  = "zee-k-verifier-cert"
  managed {
    domains = var.ssl_domains
  }
  lifecycle {
    precondition {
      condition     = length(var.ssl_domains) > 0
      error_message = "ssl_domains must be set when both ssl_certificate_id and wildcard_domain are empty."
    }
  }
}

# Certificate Manager path — supports wildcard DNS (*.example.com).
# After apply, create the CNAME record from the dns_auth_cname_* outputs in
# your DNS provider before the certificate can be provisioned by Google.
resource "google_certificate_manager_dns_authorization" "wildcard" {
  count       = var.wildcard_domain != "" ? 1 : 0
  name        = "zee-k-verifier-wildcard-auth"
  description = "DNS authorization for wildcard domain"
  domain      = var.wildcard_domain
  depends_on  = [google_project_service.apis]
}

resource "google_certificate_manager_certificate" "wildcard" {
  count       = var.wildcard_domain != "" ? 1 : 0
  name        = "zee-k-verifier-wildcard-cert"
  description = "Google-managed wildcard certificate for *.${var.wildcard_domain}"
  managed {
    domains            = ["*.${var.wildcard_domain}", var.wildcard_domain]
    dns_authorizations = [google_certificate_manager_dns_authorization.wildcard[0].id]
  }
}

resource "google_certificate_manager_certificate_map" "lb" {
  count = var.wildcard_domain != "" ? 1 : 0
  name  = "zee-k-verifier-cert-map"
}

resource "google_certificate_manager_certificate_map_entry" "wildcard" {
  count        = var.wildcard_domain != "" ? 1 : 0
  name         = "zee-k-verifier-wildcard-entry"
  map          = google_certificate_manager_certificate_map.lb[0].name
  certificates = [google_certificate_manager_certificate.wildcard[0].id]
  matcher      = "PRIMARY"
}

locals {
  use_cert_map    = var.wildcard_domain != "" || var.ssl_certificate_map != ""
  ssl_certificate = var.ssl_certificate_id != "" ? var.ssl_certificate_id : try(google_compute_managed_ssl_certificate.lb[0].id, null)
  cert_map_ref = (
    var.ssl_certificate_map != ""
    ? "//certificatemanager.googleapis.com/projects/${var.compute_project_id}/locations/global/certificateMaps/${var.ssl_certificate_map}"
    : (var.wildcard_domain != "" ? "//certificatemanager.googleapis.com/${google_certificate_manager_certificate_map.lb[0].id}" : null)
  )
  # Cloud Armor: decode rules from the JSON file, or use an empty list (allow-all default only).
  armor_rules = var.armor_rules_file != "" ? jsondecode(file(var.armor_rules_file)) : []
}

# Cloud Armor security policy. It applies three layers, in priority order:
#   1. Custom rules from var.armor_rules_file (IP allow and deny lists).
#   2. A per-client rate limit that bans abusive source IPs.
#   3. The default rule, which allows the remaining traffic.
# Adaptive Protection watches the backend and reports layer 7 DDoS attacks.
resource "google_compute_security_policy" "zee_k_verifier" {
  name        = "zee-k-verifier-armor"
  description = "Cloud Armor policy for the zee-k-verifier HTTPS load balancer."
  type        = "CLOUD_ARMOR"

  # Adaptive Protection builds a traffic baseline and flags layer 7 DDoS
  # attacks in Cloud Logging, with a suggested mitigation rule. Automatic
  # deployment of that rule is out of scope here; the google provider does not
  # expose it for this resource. Review the alert and add the rule to
  # armor_rules_file, or turn auto-deploy on in the console.
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable          = var.armor_adaptive_protection
      rule_visibility = "STANDARD"
    }
  }

  # Verbose logging records which rule matched each request. It makes attack
  # traffic visible in the load balancer logs.
  advanced_options_config {
    log_level = "VERBOSE"
  }

  dynamic "rule" {
    for_each = local.armor_rules
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      description = lookup(rule.value, "description", "")
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = rule.value.src_ip_ranges
        }
      }
    }
  }

  # Per-client rate limit. Cloud Armor counts requests for each source IP over
  # a sliding interval. A client above the threshold is banned for
  # armor_rate_limit_ban_duration_sec and receives HTTP 429. The priority sits
  # below the custom rules, so an explicit allow or deny still wins.
  #
  # The threshold counts one source IP. Callers that share an egress IP, a GKE
  # cluster behind Cloud NAT for example, count as one client, so size the
  # threshold against the whole caller's rate and not a single pod's.
  dynamic "rule" {
    for_each = var.armor_rate_limit_enabled ? [1] : []
    content {
      action      = "rate_based_ban"
      priority    = "2000000000"
      description = "DDoS: rate limit each source IP"

      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = ["*"]
        }
      }

      rate_limit_options {
        conform_action   = "allow"
        exceed_action    = "deny(429)"
        enforce_on_key   = "IP"
        ban_duration_sec = var.armor_rate_limit_ban_duration_sec

        rate_limit_threshold {
          count        = var.armor_rate_limit_threshold_count
          interval_sec = var.armor_rate_limit_interval_sec
        }

        ban_threshold {
          count        = var.armor_rate_limit_ban_threshold_count
          interval_sec = var.armor_rate_limit_interval_sec
        }
      }
    }
  }

  # Priority 2147483647 is the required default rule.
  rule {
    action      = "allow"
    priority    = "2147483647"
    description = "Default: allow all"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

resource "google_compute_health_check" "zee_k_verifier" {
  name                = "zee-k-verifier-health"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port         = 3001
    request_path = "/signerAddress"
  }
}

resource "google_compute_backend_service" "zee_k_verifier" {
  name                  = "zee-k-verifier-backend"
  protocol              = "HTTP"
  port_name             = "http"
  load_balancing_scheme = "EXTERNAL"
  timeout_sec           = 300

  backend {
    group           = google_compute_instance_group_manager.zee_k_verifier.instance_group
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }

  health_checks   = [google_compute_health_check.zee_k_verifier.id]
  security_policy = google_compute_security_policy.zee_k_verifier.id

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "zee_k_verifier" {
  name            = "zee-k-verifier-lb"
  default_service = google_compute_backend_service.zee_k_verifier.id
}

resource "google_compute_target_https_proxy" "zee_k_verifier" {
  name    = "zee-k-verifier-https-proxy"
  url_map = google_compute_url_map.zee_k_verifier.id
  # certificate_map and ssl_certificates are mutually exclusive on the proxy.
  ssl_certificates = local.use_cert_map ? [] : [local.ssl_certificate]
  certificate_map  = local.cert_map_ref
}

resource "google_compute_global_forwarding_rule" "zee_k_verifier" {
  name                  = "zee-k-verifier-https"
  ip_address            = google_compute_global_address.lb.id
  port_range            = "443"
  target                = google_compute_target_https_proxy.zee_k_verifier.id
  load_balancing_scheme = "EXTERNAL"
}

# --- Outputs ------------------------------------------------------------
output "mig_name" {
  description = "Name of the Managed Instance Group."
  value       = google_compute_instance_group_manager.zee_k_verifier.name
}

output "mig_self_link" {
  description = "Self-link of the Managed Instance Group."
  value       = google_compute_instance_group_manager.zee_k_verifier.self_link
}

output "mig_instance_group" {
  description = "Instance group URL."
  value       = google_compute_instance_group_manager.zee_k_verifier.instance_group
}

output "compute_sa_email" {
  description = "VM's attached SA. Grant it artifactregistry.reader on the shared artifact registry (done in the ops project)."
  value       = google_service_account.compute.email
}

output "lb_ip" {
  description = "Static external IP of the HTTPS load balancer. Point your DNS A record here."
  value       = google_compute_global_address.lb.address
}

output "dns_auth_cname_name" {
  description = "DNS CNAME record name to add when using wildcard_domain. null in other modes."
  value       = var.wildcard_domain != "" ? google_certificate_manager_dns_authorization.wildcard[0].dns_resource_record[0].name : null
}

output "dns_auth_cname_value" {
  description = "DNS CNAME record value (target) to add when using wildcard_domain. null in other modes."
  value       = var.wildcard_domain != "" ? google_certificate_manager_dns_authorization.wildcard[0].dns_resource_record[0].data : null
}

output "psc_endpoint_ip" {
  description = "Internal IP of the PSC consumer endpoint. null when enable_psc = false."
  value       = var.enable_psc ? google_compute_address.psc_endpoint[0].address : null
}

output "network_self_link" {
  description = "Self-link of the VPC in use (created or pre-existing)."
  value       = local.network
}

output "subnetwork_self_link" {
  description = "Self-link of the subnet in use (created or pre-existing). null when using the default network without an explicit subnet."
  value       = local.subnetwork
}

output "proofs_appender_role_id" {
  description = "Full id of the append-only custom role bound to the compute SA on the proofs bucket."
  value       = google_project_iam_custom_role.proofs_appender.id
}

output "audit_logs_bucket" {
  description = "Bucket that keeps the routed proofs-bucket audit logs."
  value       = google_storage_bucket.audit_logs.name
}
