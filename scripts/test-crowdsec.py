#!/usr/bin/env python3
"""Run isolated real CrowdSec Hub tests; never touches /etc, a service or firewall."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hub", required=True, type=Path, help="checkout of crowdsecurity/hub with test templates and dateparse-enrich")
    parser.add_argument("--cscli", default="cscli")
    parser.add_argument("--crowdsec", default="crowdsec")
    args = parser.parse_args()
    cscli, crowdsec = shutil.which(args.cscli), shutil.which(args.crowdsec)
    if not cscli or not crowdsec:
        parser.error("cscli and crowdsec binaries are required")
    templates = ["template_config2.yaml", "template_profiles.yaml", "template_simulation.yaml"]
    enrich = args.hub / "parsers/s02-enrich/crowdsecurity/dateparse-enrich.yaml"
    for source in [args.hub / ".tests" / name for name in templates] + [enrich]:
        if not source.is_file():
            parser.error(f"required official Hub file not found: {source}")
    with tempfile.TemporaryDirectory(prefix="caddy-ts3-awg-crowdsec-") as temp:
        work = Path(temp)
        hub, conf, data = work / "hub", work / "config", work / "data"
        for directory in (hub / ".tests", conf / "hub", conf / "patterns", data):
            directory.mkdir(parents=True, exist_ok=True)
        for name in templates:
            shutil.copy(args.hub / ".tests" / name, hub / ".tests" / name)
        for directory in ("parsers", "scenarios"):
            shutil.copytree(ROOT / "crowdsec" / directory, hub / directory)
        destination = hub / "parsers/s02-enrich/crowdsecurity/dateparse-enrich.yaml"
        destination.parent.mkdir(parents=True)
        shutil.copy(enrich, destination)
        (hub / ".index.json").write_text("{}")
        (conf / "hub/.index.json").write_text("{}")
        (conf / "simulation.yaml").write_text("simulation: false\nexclusions: []\n")
        (conf / "local_api_credentials.yaml").write_text("url: http://127.0.0.1:18080\nlogin: test\npassword: test\n")
        (conf / "acquis.yaml").write_text("filenames: []\nlabels:\n  type: caddy-ts3-awg\n")
        settings = work / "config.yaml"
        settings.write_text(f"""common:
  daemonize: false
  log_media: stdout
  log_level: info
config_paths:
  config_dir: {conf}
  data_dir: {data}
  hub_dir: {conf}/hub
  index_path: {conf}/hub/.index.json
crowdsec_service:
  acquisition_path: {conf}/acquis.yaml
  parser_routines: 1
cscli:
  output: human
db_config:
  type: sqlite
  db_path: {data}/crowdsec.db
api:
  client:
    credentials_path: {conf}/local_api_credentials.yaml
  server:
    enable: false
prometheus:
  enabled: false
""")
        for name, fixture, benign in (("ts3-awg-positive", "events.jsonl", False), ("ts3-awg-benign", "benign.jsonl", True)):
            test = hub / ".tests" / name
            test.mkdir()
            shutil.copy(ROOT / "crowdsec/tests" / fixture, test / "events.log")
            (test / "config.yaml").write_text("""parsers:
  - ./parsers/s01-parse/0urr-acid/caddy-ts3-awg.yaml
  - ./parsers/s02-enrich/crowdsecurity/dateparse-enrich.yaml
scenarios:
  - ./scenarios/0urr-acid/ts3-awg-connection-flood.yaml
postoverflows: []
log_file: events.log
log_type: caddy-ts3-awg
ignore_parsers: false
""")
            assertions = ['len(results["s01-parse"]["0urr-acid/caddy-ts3-awg"]) == 3']
            for index in range(3):
                assertions.append(f'results["s01-parse"]["0urr-acid/caddy-ts3-awg"][{index}].Success == {str(not benign).lower()}')
            (test / "parser.assert").write_text("\n".join(assertions) + "\n")
            (test / "scenario.assert").write_text(f"len(results) == {0 if benign else 1}\n")
        result = subprocess.run([cscli, "-c", str(settings), "hubtest", "--hub", str(hub),
                                 "--crowdsec", crowdsec, "--cscli", cscli, "run", "--all", "--max-jobs", "1", "--report-success"],
                                text=True, capture_output=True, timeout=120)
        print(result.stdout, end="")
        if result.returncode:
            print(result.stderr, end="")
            raise SystemExit(result.returncode)
        print("CrowdSec: suspicious events overflow; benign events do not match or alert")


if __name__ == "__main__":
    main()
