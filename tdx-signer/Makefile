# ---------------------------------------------------------------------------
# Compute-side deploy (the WORKLOAD OWNER):
#   compute/ : the Confidential VM, firewall, load balancer.
#
# Images + the CI image-push WIF live in the shared fhenix-artifacts-registry project
# (images only); this repo's per-env compute project only runs the VM (which pulls
# from that registry by digest). Key release is partner-side: each partner's
# attested-reader policy pins the digest. Terraform state lives per-project:
# compute-module state in the COMPUTE project's bucket (gs://<project>-tfstate).
# See the gitops repo for deploy steps.
# ---------------------------------------------------------------------------

ARTIFACTS_PROJECT ?= fhenix-artifacts-registry
COMPUTE_PROJECT   ?= REPLACE-COMPUTE-PROJECT-ID

REGION           ?= europe-west4
ZONE             ?= europe-west4-b
REPO             ?= zee-k-verifier
# Image lives in the shared artifact registry; every env's VM pulls the same digest.
IMAGE_REF        := $(REGION)-docker.pkg.dev/$(ARTIFACTS_PROJECT)/$(REPO)/zee-k-verifier
TAG              ?= v1

# Firewall source for the VM (GKE caller). GKE_POD_CIDR overrides the CALLER_* lookup.
CALLER_CLUSTER   ?= REPLACE-CALLER-GKE-CLUSTER
CALLER_REGION    ?= REPLACE-CALLER-GKE-REGION
CALLER_PROJECT   ?= REPLACE-CALLER-GKE-PROJECT
GKE_POD_CIDR     ?=

NETWORK          ?= default
SUBNETWORK       ?=

# Bucket where zee-k writes verified zk proof inputs (compute SA gets objectCreator).
PROOFS_BUCKET ?= REPLACE-PROOFS-BUCKET

# Reader source selector (D6): ENV picks the baked triplet — the partner set, each
# partner's WIF audience, and the public-material bucket/object — from cofhe-keys'
# env map, fail-closed. There are no PARTNERS/PUBLIC_BUCKET/PUBLIC_OBJECT vars
# anymore. The Shamir threshold T is baked in cofhe-keys too, not passed here.
ENV              ?= testnet

# Backend = per-project state bucket (gs://<project>-tfstate), one prefix per module.
#
# The compute prefix MUST be zee-k-verifier/compute: that is where the live state
# for every deployed env actually is (gs://fhenix-dev-tfstate/zee-k-verifier/compute,
# gs://fhenix-testnet-tfstate/zee-k-verifier/compute). The old `zeek/compute` prefix
# points at an empty 181-byte stub, so initing there plans to CREATE the whole stack
# from scratch against a live project.
TF_INIT_COMPUTE = terraform init -backend-config="bucket=$(COMPUTE_PROJECT)-tfstate" -backend-config="prefix=zee-k-verifier/compute"

.PHONY: compute-apply build-image-dev test-verify compute-destroy

# =========================================================================
#  COMPUTE SIDE  (run by the WORKLOAD OWNER)
# =========================================================================

# DEVELOPER-ONLY local build. Pushes to the shared artifact registry. Key release
# requires the partners to pin the digest in their attested-reader policies.
build-image-dev:
	gcloud auth configure-docker $(REGION)-docker.pkg.dev --quiet
	docker build -f tdx-signer/Dockerfile --platform linux/amd64 -t $(IMAGE_REF):$(TAG) ..
	docker push $(IMAGE_REF):$(TAG)
	@DIGEST=$$(docker inspect --format='{{index .RepoDigests 0}}' $(IMAGE_REF):$(TAG) | cut -d@ -f2) ; \
	echo "" ; \
	echo "Pushed to the shared artifact registry:" ; \
	echo "  $(IMAGE_REF)@$$DIGEST" ; \
	echo "" ; \
	echo "Pin per env: partners re-apply their attested-reader policy with IMAGE_DIGEST=$$DIGEST, then  make compute-apply ..."

# Apply the compute-side terraform (the VM, which pulls from the artifact registry).
# The reader source AND the Shamir threshold are selected by ENV (baked triplet) —
# no WIP audience / SA email / partner list / threshold to pass. The runtime config
# is baked into the image too; only the ct-server endpoint stays operator-supplied.
# REQUIRES: COMPUTE_PROJECT, IMAGE_DIGEST, ENV, STORE_CTS_ENDPOINT, PROOFS_BUCKET.
compute-apply:
	@test -n "$(COMPUTE_PROJECT)"    || (echo "set COMPUTE_PROJECT" && exit 1)
	@test -n "$(IMAGE_DIGEST)"       || (echo "missing IMAGE_DIGEST" && exit 1)
	@test -n "$(ENV)"                || (echo "missing ENV (staging|testnet|mainnet)" && exit 1)
	@test -n "$(STORE_CTS_ENDPOINT)" || (echo "missing STORE_CTS_ENDPOINT (the ct-server endpoint)" && exit 1)
	@test -n "$(PROOFS_BUCKET)" -a "$(PROOFS_BUCKET)" != "REPLACE-PROOFS-BUCKET" || (echo "set PROOFS_BUCKET" && exit 1)
	cd compute && $(TF_INIT_COMPUTE) && terraform apply \
	  -var="compute_project_id=$(COMPUTE_PROJECT)" \
	  -var="zone=$(ZONE)" \
	  -var="image_digest=$(IMAGE_DIGEST)" \
	  -var="image_reference=$(IMAGE_REF)" \
	  -var="env=$(ENV)" \
	  -var="store_cts_endpoint=$(STORE_CTS_ENDPOINT)" \
	  -var="proofs_bucket=$(PROOFS_BUCKET)" \
	  -var="network=$(NETWORK)" \
	  -var="subnetwork=$(SUBNETWORK)" \
	  -var="gke_pod_cidr=$$( if [ -n "$(GKE_POD_CIDR)" ]; then echo "$(GKE_POD_CIDR)"; else gcloud container clusters describe $(CALLER_CLUSTER) --region=$(CALLER_REGION) --project=$(CALLER_PROJECT) --format='value(clusterIpv4Cidr)'; fi )"
	@echo ""
	@echo "VM external IP:"
	@cd compute && terraform output -raw vm_external_ip

compute-destroy:
	@test -n "$(COMPUTE_PROJECT)" || (echo "set COMPUTE_PROJECT" && exit 1)
	cd compute && $(TF_INIT_COMPUTE) && terraform destroy \
	  -var="compute_project_id=$(COMPUTE_PROJECT)" \
	  -var="zone=$(ZONE)" \
	  -var="image_digest=sha256:0000000000000000000000000000000000000000000000000000000000000000" \
	  -var="image_reference=$(IMAGE_REF)" \
	  -var="env=$(ENV)" \
	  -var="store_cts_endpoint=unused-for-destroy" \
	  -var="proofs_bucket=$(PROOFS_BUCKET)" \
	  -var="network=$(NETWORK)" \
	  -var="subnetwork=$(SUBNETWORK)" \
	  -var="gke_pod_cidr=0.0.0.0/0"

# =========================================================================
#  SMOKE TEST  (run after compute-apply, same shell/state)
# =========================================================================

# Hits /signerAddress (cheap; no proof verification) to confirm the attested
# boot reached the verifier and the reconstructed signer address matches the
# manifest's zk_signer_address.
# Pass EXPECTED_SIGNER_ADDRESS=0x... to assert. Case-insensitive compare.
#
# Goes through the HTTPS load balancer, not the instance. The instances are
# MIG-managed (ephemeral names/IPs) and the firewall only admits
# 35.235.240.0/20 (IAP TCP forwarding) on 3001/9090, so an operator laptop
# cannot reach a VM directly. VERIFY_HOST just has to match the LB's wildcard
# cert for SNI — the url_map has no host rules and default-routes everything to
# the zee-k backend — and is pinned to the LB IP with --resolve so this works
# without depending on public DNS.
VERIFY_HOST ?= zee-k.sw-dom.co
test-verify:
	@LB_IP=$$(cd compute && terraform output -raw lb_ip) ; \
	echo ">> hitting https://$(VERIFY_HOST)/signerAddress (via $$LB_IP)" ; \
	RESP=$$(curl -sfm 10 --resolve "$(VERIFY_HOST):443:$$LB_IP" "https://$(VERIFY_HOST)/signerAddress") ; \
	echo "$$RESP" | jq . ; \
	GOT=$$(echo "$$RESP" | jq -r .address) ; \
	if [ -n "$(EXPECTED_SIGNER_ADDRESS)" ]; then \
	  GOT_LC=$$(echo "$$GOT" | tr 'A-F' 'a-f') ; \
	  EXP_LC=$$(echo "$(EXPECTED_SIGNER_ADDRESS)" | tr 'A-F' 'a-f') ; \
	  if [ "$$GOT_LC" = "$$EXP_LC" ]; then echo PASS ; \
	  else echo "FAIL: got $$GOT, expected $(EXPECTED_SIGNER_ADDRESS)" ; exit 1 ; fi ; \
	else \
	  echo "(no EXPECTED_SIGNER_ADDRESS set; address shown above)" ; \
	fi
