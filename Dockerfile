# syntax=docker/dockerfile:1.7
# Update this digest through the normal dependency-review process when CPython
# publishes security updates. The digest keeps builds reproducible between reviews.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2

FROM ${PYTHON_IMAGE} AS build

WORKDIR /build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY pyproject.toml README.md LICENSE ./
COPY adaf_redteam ./adaf_redteam
RUN python -m pip wheel --wheel-dir /wheels ".[all]"

FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="ADAF-RedTeam" \
      org.opencontainers.image.description="Authorization-first Active Directory validation CLI" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ADAF_REDTEAM_SCHEMA_DIR=/opt/adaf-redteam/schemas

RUN groupadd --system adaf && useradd --system --gid adaf --create-home --home-dir /home/adaf adaf \
    && install --directory --owner=adaf --group=adaf --mode=0750 /out \
    && install --directory --owner=adaf --group=adaf --mode=0755 /opt/adaf-redteam

COPY --from=build /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels "adaf-redteam[all]" \
    && rm -rf /wheels

COPY --chown=adaf:adaf schemas /opt/adaf-redteam/schemas
COPY --chown=adaf:adaf examples /opt/adaf-redteam/examples
COPY --chown=adaf:adaf pyproject.toml README.md LICENSE /opt/adaf-redteam/
COPY --chown=adaf:adaf docs/guides /opt/adaf-redteam/docs/guides

USER adaf
WORKDIR /opt/adaf-redteam
VOLUME ["/out"]
ENTRYPOINT ["adaf-redteam"]
CMD ["doctor", "--out", "/out"]
