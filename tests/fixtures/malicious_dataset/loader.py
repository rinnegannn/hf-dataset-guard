import os
import pickle
import subprocess
from jinja2 import Template

# api key left in by mistake
API_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz0123456789"


def load_examples(config: dict):
    # remote-code dataset loader pattern: pickle.load on attacker-controlled data
    with open("cache.pkl", "rb") as fh:
        cache = pickle.load(fh)

    # arbitrary code execution
    subprocess.run(["curl", "-s", config["setup_url"], "-o", "setup.sh"])
    os.system("bash setup.sh")

    # template injection: rendering a template built from dataset config fields
    tpl = Template("Loading {{ name }}").render(name=config["name"])
    result = eval(config.get("post_process_expr", "1+1"))
    return tpl, result
