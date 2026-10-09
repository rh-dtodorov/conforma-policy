# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# METADATA
# title: BTS output presence
# description: >-
#   On promote, check that a PipelineRun attestation for this artifact
#   contains a bts-sign task result naming this artifact. This checks
#   output presence, not the signature of a file inside the RPM.
package bts_presence

import rego.v1

import data.lib
import data.lib.image
import data.lib.metadata
import data.lib.rule_data
import data.lib.tekton

# This policy is opt-in through bts_required from the managed RPA.
# Without that value it produces no violations, so it has no effective_on.

# METADATA
# title: BTS output recorded for promoted RPM
# description: >-
#   Require a bts-sign result in a PipelineRun attestation whose subject
#   is the promoted artifact when the RPA requires build-time signing.
# custom:
#   short_name: output_present
#   failure_msg: "No attested BTS output found for %s"
#   solution: >-
#     Sign the RPM payload on import and attest the resulting artifact.
#   collections:
#   - redhat_rpms
deny contains result if {
	rule_data.get("bts_required") == "true"
	rule_data.get("bts_release_phase") == "promote"
	not _output_matches_image
	ref := object.get(object.get(input, "image", {}), "ref", "<missing>")
	result := metadata.result_helper(rego.metadata.chain(), [ref])
}

# METADATA
# title: BTS rule data valid
# description: >-
#   An explicitly configured BTS requirement must use true or false.
#   Required BTS must be evaluated on either import or promote.
# custom:
#   short_name: rule_data_valid
#   failure_msg: "Invalid BTS rule data: %s"
#   solution: Set bts_required to true or false and bts_release_phase to import or promote.
#   collections:
#   - redhat_rpms
#   - policy_data
deny contains result if {
	some error in _data_errors
	result := metadata.result_helper(rego.metadata.chain(), [error])
}

_data_errors contains "bts_required must be true or false" if {
	required := rule_data.get("bts_required")
	required != []
	not required in {"true", "false"}
}

_data_errors contains "bts_release_phase must be import or promote" if {
	rule_data.get("bts_required") == "true"
	not rule_data.get("bts_release_phase") in {"import", "promote"}
}

_output_matches_image if {
	ref := image.parse(input.image.ref)
	regex.match(`^sha256:[a-f0-9]{64}$`, ref.digest)
	some attestation in lib.pipelinerun_attestations
	some subject in object.get(attestation.statement, "subject", [])
	subject.digest.sha256 == split(ref.digest, ":")[1]
	some task in tekton.tasks(attestation)
	tekton.pipeline_task_name(task) == "bts-sign"
	some task_result in tekton.task_results(task)
	task_result.name == "BTS_OUTPUT"
	output := lib.unmarshal(task_result.value)
	is_string(output)
	image.equal_ref(output, input.image.ref)
}
