from steadystate.sources.base import StateSource
from steadystate.sources.docker_compose import (
    DockerComposeSource,
    resources_from_compose_config,
)

SAMPLE_CONFIG = {
    "services": {
        "web": {
            "image": "nginx:1.27",
            "ports": ["80:80"],
            "depends_on": ["db"],
        },
        "db": {
            "image": "postgres:16",
            "environment": {"POSTGRES_PASSWORD": "secret"},
            "volumes": ["pgdata:/var/lib/postgresql/data"],
        },
    },
    "volumes": {"pgdata": {}},
}


def test_resources_from_compose_config():
    resources = resources_from_compose_config(SAMPLE_CONFIG)
    assert len(resources) == 2

    by_id = {r.identity: r for r in resources}
    assert set(by_id) == {"web", "db"}

    web = by_id["web"]
    assert web.kind == "docker_compose_service"
    assert web.provenance.source == "docker-compose"
    assert web.provenance.address == "web"
    assert web.properties["image"] == "nginx:1.27"
    assert web.properties["depends_on"] == ["db"]


def test_empty_config_yields_nothing():
    assert resources_from_compose_config({}) == []
    assert resources_from_compose_config({"services": None}) == []


def test_source_satisfies_protocol_and_collects():
    source = DockerComposeSource(config=SAMPLE_CONFIG)
    assert isinstance(source, StateSource)
    assert source.name == "docker-compose"

    resources = source.collect_declared()
    assert {r.identity for r in resources} == {"web", "db"}


def test_source_requires_config_or_working_dir():
    source = DockerComposeSource()
    try:
        source.collect_declared()
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError without config or working_dir")
