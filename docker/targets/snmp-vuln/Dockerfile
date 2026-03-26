FROM python:3.12-slim
LABEL description="Fake SNMPd — GetBulk response (~65x amplification)"

COPY snmp_vuln.py /snmp_vuln.py

EXPOSE 161/udp

CMD ["python3", "/snmp_vuln.py"]
