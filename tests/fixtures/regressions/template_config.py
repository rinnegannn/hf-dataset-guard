from jinja2 import Template

config = {"name": "fixture"}
Template("hello {{ name }}").render(name=config["name"])
