# Official Playwright image: Python + Chromium + all system libraries it needs.
# Keep the tag in sync with the playwright version in requirements.txt.
FROM mcr.microsoft.com/playwright/python:v1.56.0-noble

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY index.html run-viewer.py ./

ENV PYTHONUNBUFFERED=1
# Render sets PORT at runtime; the server binds 0.0.0.0 and blocks private networks when it is set.
CMD ["python", "run-viewer.py"]
