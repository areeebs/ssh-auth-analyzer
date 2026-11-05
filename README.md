# SSH Auth Log Analyzer

Find source-level SSH authentication bursts and successful logins after failure clusters.

Parses common RFC 3164 sshd auth.log lines using an explicitly supplied year, groups failures by source and host, and highlights a subsequent accepted login from that source. Timestamps are local-naive because traditional syslog lines carry no timezone; provide one host's log at a time and account for log rotation before drawing conclusions.

## Install and run

Requires Python 3.10+. This repository uses only the standard library.

~~~sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
ssh-auth-analyze examples/auth.log --year 2026 --threshold 5
~~~

Run the offline regression suite:

~~~sh
python -m unittest discover -s tests -v
~~~

## Safety and limits

Use only for systems, domains, data, and accounts you own or are authorized to assess. Provider matches and local detections are leads for analyst review, not proof of compromise or safety. For tools that query an external provider, review the submitted value and provider terms before running it.

## References

- [OpenSSH sshd manual](https://man.openbsd.org/sshd)
- The tool consumes local log text only; timestamps in traditional syslog do not include a timezone.

## License

MIT. See LICENSE.
