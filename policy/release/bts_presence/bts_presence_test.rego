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

package bts_presence_test

import rego.v1

import data.bts_presence
import data.lib.assertions
import data.lib.tekton_test
import data.lib_test

_ref := "registry.example/rpm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_other_ref := "registry.example/rpm@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_image := {"image": {"ref": _ref}}
_required_promote := {"bts_required": "true", "bts_release_phase": "promote"}
_required_import := {"bts_required": "true", "bts_release_phase": "import"}
_disabled_promote := {"bts_required": "false", "bts_release_phase": "promote"}

_subject(ref) := [{
	"name": "registry.example/rpm",
	"digest": {"sha256": split(ref, "sha256:")[1]},
}]

_v02(task_name, output, subject) := json.patch(
	lib_test.att_mock_helper_ref_plain_result("BTS_OUTPUT", output, task_name, ""),
	[{"op": "add", "path": "/statement/subject", "value": _subject(subject)}],
)

_v1(task_name, output, subject) := json.patch(
	tekton_test.slsav1_attestation([tekton_test.with_results(tekton_test.slsav1_task(task_name), [{
		"name": "BTS_OUTPUT",
		"value": output,
	}])]),
	[{"op": "add", "path": "/statement/subject", "value": _subject(subject)}],
)

_missing := {{
	"code": "bts_presence.output_present",
	"msg": sprintf("No attested BTS output found for %s", [_ref]),
}}

test_import_skips_bts_presence if {
	assertions.assert_empty(bts_presence.deny) with data.rule_data as _required_import
		with input as _image
}

test_pipeline_extra_rule_data_overrides_policy_data if {
	assertions.assert_equal_results(bts_presence.deny, _missing) with data.rule_data as _required_import
		with data.rule_data__configuration__ as _required_promote
		with input as _image
}

test_unconfigured_or_disabled_skips_bts_presence if {
	assertions.assert_empty(bts_presence.deny) with data.rule_data as {}
		with input as _image
	assertions.assert_empty(bts_presence.deny) with data.rule_data as _disabled_promote
		with input as _image
}

test_promote_requires_attested_output if {
	assertions.assert_equal_results(bts_presence.deny, _missing) with data.rule_data as _required_promote
		with input as _image
}

test_promote_accepts_v02_and_v1_provenance if {
	assertions.assert_empty(bts_presence.deny) with data.rule_data as _required_promote
		with input as object.union(_image, {"attestations": [_v02("bts-sign", _ref, _ref)]})
	assertions.assert_empty(bts_presence.deny) with data.rule_data as _required_promote
		with input as object.union(_image, {"attestations": [_v1("bts-sign", _ref, _ref)]})
}

test_promote_rejects_other_output_or_subject if {
	assertions.assert_equal_results(bts_presence.deny, _missing) with data.rule_data as _required_promote
		with input as object.union(_image, {"attestations": [_v1("bts-sign", _other_ref, _ref)]})
	assertions.assert_equal_results(bts_presence.deny, _missing) with data.rule_data as _required_promote
		with input as object.union(_image, {"attestations": [_v1("bts-sign", _ref, _other_ref)]})
	assertions.assert_equal_results(bts_presence.deny, _missing) with data.rule_data as _required_promote
		with input as object.union(_image, {"attestations": [_v1("not-bts-sign", _ref, _ref)]})
}

test_bad_rule_data_is_rejected if {
	assertions.assert_equal_results(bts_presence.deny, {{
		"code": "bts_presence.rule_data_valid",
		"msg": "Invalid BTS rule data: bts_required must be true or false",
	}}) with data.rule_data as {"bts_required": "yes", "bts_release_phase": "promote"}

	assertions.assert_equal_results(bts_presence.deny, {{
		"code": "bts_presence.rule_data_valid",
		"msg": "Invalid BTS rule data: bts_release_phase must be import or promote",
	}}) with data.rule_data as {"bts_required": "true", "bts_release_phase": "unknown"}
}
