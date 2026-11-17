"""A YAML loader that tolerates kongctl's custom tags.

kongctl declarative files carry `!lookup`, `!env` and `!ref`, which a stock
SafeLoader refuses to construct. Every tool in this repository that reads the
configs needs the same tolerance, so it lives here once rather than being
re-derived -- and the tags are preserved as typed objects rather than discarded,
so a checker can tell "this value is resolved at apply time" from "this value is
a literal the schema should validate".
"""
# PyYAML is the only third-party dependency in this repository's tooling.
# Install it with: python3 -m pip install pyyaml
import yaml


class Tagged:
    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value

    def __repr__(self):
        return f"{self.tag} {self.value!r}"


class KongctlLoader(yaml.SafeLoader):
    pass


def _tagged(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node)
    else:
        value = loader.construct_sequence(node)
    return Tagged("!" + suffix, value)


KongctlLoader.add_multi_constructor("!", _tagged)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.load(fh, Loader=KongctlLoader)
