# NOTE: This root composition is intended to be consumed by an environment
# wrapper (environments/staging) which OWNS the provider configuration and
# passes it down implicitly. Declaring a `provider` block here would make this
# module non-reusable (Terraform forbids provider blocks in modules called with
# for_each/count and warns otherwise), so the provider is configured by the
# calling environment. See environments/staging/providers.tf.
#
# This file is intentionally left without a provider block.
