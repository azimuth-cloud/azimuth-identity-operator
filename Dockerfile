FROM ubuntu:24.04 AS helm

RUN apt-get update && \
    apt-get install -y wget && \
    rm -rf /var/lib/apt/lists/*

ARG HELM_VERSION=v3.18.4
RUN set -ex; \
    OS_ARCH="$(uname -m)"; \
    case "$OS_ARCH" in \
        x86_64) helm_arch=amd64 ;; \
        aarch64) helm_arch=arm64 ;; \
        *) false ;; \
    esac; \
    wget -q -O - https://get.helm.sh/helm-${HELM_VERSION}-linux-${helm_arch}.tar.gz | \
      tar -xz --strip-components 1 -C /usr/bin linux-${helm_arch}/helm; \
    helm version

# Pull and unpack the Dex chart
ARG DEX_CHART_NAME=dex
ARG DEX_CHART_REPO=https://charts.dexidp.io
ARG DEX_CHART_VERSION=0.23.0
RUN helm pull ${DEX_CHART_NAME} \
      --repo ${DEX_CHART_REPO} \
      --version ${DEX_CHART_VERSION} \
      --untar \
      --untardir /charts


FROM ubuntu:24.04 AS python-builder

RUN apt-get update && \
    apt-get install -y python3 python3-venv && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv && \
    /venv/bin/pip install -U pip setuptools

COPY requirements.txt /app/requirements.txt
RUN  /venv/bin/pip install --requirement /app/requirements.txt

COPY . /app
RUN /venv/bin/pip install /app


FROM ubuntu:24.04

# Create the user that will be used to run the app
ENV APP_UID=1001
ENV APP_GID=1001
ENV APP_USER=app
ENV APP_GROUP=app
RUN groupadd --gid $APP_GID $APP_GROUP && \
    useradd \
      --no-create-home \
      --no-user-group \
      --gid $APP_GID \
      --shell /sbin/nologin \
      --uid $APP_UID \
      $APP_USER

RUN apt-get update && \
    apt-get install -y ca-certificates python3 && \
    rm -rf /var/lib/apt/lists/*

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED=1

# Make httpx use the system trust roots
# By default, this means we use the CAs from the ca-certificates package
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Tell Helm to use /tmp for mutable data
ENV HELM_CACHE_HOME=/tmp/helm/cache
ENV HELM_CONFIG_HOME=/tmp/helm/config
ENV HELM_DATA_HOME=/tmp/helm/data

COPY --from=helm /usr/bin/helm /usr/bin/helm
COPY --from=helm /charts/dex /charts/dex
COPY --from=python-builder /venv /venv

USER $APP_UID
CMD ["/venv/bin/python", "-m", "azimuth_identity"]
