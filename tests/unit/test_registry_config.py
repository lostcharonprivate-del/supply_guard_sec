"""Registry configuration parsing.

These files encode the resolution intent that dependency confusion exploits,
so distinguishing a private registry from the public one is load-bearing.
"""

from __future__ import annotations

from supplyguard.ecosystems.registry_config import is_public_registry, parse_registry_config


class TestNpmrc:
    def test_scoped_registries_and_credentials(self) -> None:
        config = parse_registry_config(
            ".npmrc",
            "registry=https://registry.npmjs.org/\n"
            "@acme:registry=https://npm.internal.acme.com/\n"
            "@oss:registry=https://registry.npmjs.org/\n"
            "//npm.internal.acme.com/:_authToken=${TOKEN}\n",
        )
        assert config.private_scopes == {"@acme"}
        assert config.has_credentials is True

    def test_comments_are_ignored(self) -> None:
        config = parse_registry_config(
            ".npmrc", "# @evil:registry=https://evil.example\nregistry=https://registry.npmjs.org/\n"
        )
        assert config.scoped_registries == {}


class TestPipConf:
    def test_extra_index_alongside_private_index_is_visible(self) -> None:
        config = parse_registry_config(
            "pip.conf",
            "[global]\n"
            "index-url = https://pypi.internal.acme.com/simple\n"
            "extra-index-url = https://pypi.org/simple\n",
        )
        assert config.extra_indexes == ["https://pypi.org/simple"]
        assert config.private_registries == {"https://pypi.internal.acme.com/simple"}

    def test_underscore_key_spelling_is_accepted(self) -> None:
        config = parse_registry_config(
            "pip.conf", "[global]\nextra_index_url = https://pypi.org/simple\n"
        )
        assert config.extra_indexes == ["https://pypi.org/simple"]

    def test_inline_credentials_are_noticed(self) -> None:
        config = parse_registry_config(
            "pip.conf", "[global]\nindex-url = https://user:tok@pypi.internal/simple\n"
        )
        assert config.has_credentials is True


class TestYarnBerry:
    def test_npm_scopes_are_read(self) -> None:
        config = parse_registry_config(
            ".yarnrc.yml",
            'npmScopes:\n  acme:\n    npmRegistryServer: "https://npm.internal.acme.com"\n'
            '    npmAuthToken: "xyz"\n',
        )
        assert config.private_scopes == {"@acme"}
        assert config.has_credentials is True


def test_public_registry_recognition() -> None:
    assert is_public_registry("https://registry.npmjs.org/")
    assert is_public_registry("https://pypi.org/simple")
    assert not is_public_registry("https://npm.internal.acme.com/")
    assert not is_public_registry(None)


def test_unknown_config_filename_returns_none() -> None:
    assert parse_registry_config("random.txt", "content") is None
