FROM python:3.12-slim
LABEL description="DOSArena Judge Service"
RUN pip install --no-cache-dir aiohttp
WORKDIR /judge
COPY judge.py hints.py writeups.py ./
EXPOSE 8888
ENV JUDGE_PORT=8888 JUDGE_SECRET=change-me-in-production FLAG_TTL=300
CMD ["python3", "judge.py"]
