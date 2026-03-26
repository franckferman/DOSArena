FROM python:3.12-slim
LABEL description="Fake NTPd — mode 7 monlist response (~550x amplification)"

COPY ntp_vuln.py /ntp_vuln.py

EXPOSE 123/udp

CMD ["python3", "/ntp_vuln.py"]
