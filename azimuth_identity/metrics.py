import asyncio
import datetime
import functools

from aiohttp import web

import easykube

from .config import settings


class Metric:
    # The prefix for the metric
    prefix = None
    # The suffix for the metric
    suffix = None
    # The type of the metric - info or guage
    type = "info"
    # The description of the metric
    description = None

    def __init__(self):
        self._objs = []

    def add_obj(self, obj):
        self._objs.append(obj)

    @property
    def name(self):
        return f"{self.prefix}_{self.suffix}"

    def labels(self, obj):
        """The labels for the given object."""
        return {}

    def value(self, obj):
        """The value for the given object."""
        return 1

    def records(self):
        """Returns the records for the metric, i.e. a list of (labels, value) tuples."""
        for obj in self._objs:
            yield self.labels(obj), self.value(obj)


class RealmMetric(Metric):
    prefix = "azimuth_identity_realm"

    def labels(self, obj):
        return {
            "realm_namespace": obj.metadata.namespace,
            "realm_name": obj.metadata.name,
        }


class PlatformMetric(Metric):
    prefix = "azimuth_identity_platform"

    def labels(self, obj):
        return {
            "platform_namespace": obj.metadata.namespace,
            "platform_name": obj.metadata.name,
            "realm_name": obj.spec["realmName"],
        }


class RealmPhase(RealmMetric):
    suffix = "phase"
    description = "Realm phase"

    def labels(self, obj):
        return {
            **super().labels(obj),
            "phase": obj.get("status", {}).get("phase", "Unknown"),
        }


class PlatformPhase(PlatformMetric):
    suffix = "phase"
    description = "Platform phase"

    def labels(self, obj):
        return {
            **super().labels(obj),
            "phase": obj.get("status", {}).get("phase", "Unknown"),
        }


class PlatformService(PlatformMetric):
    suffix = "service"
    description = "The services for the platform"

    def records(self):
        for obj in self._objs:
            labels = super().labels(obj)
            for name, service in obj.spec.get("zenithServices", {}).items():
                service_labels = {
                    **labels,
                    "service_name": name,
                    "service_subdomain": service["subdomain"],
                    "service_fqdn": service["fqdn"],
                }
                yield service_labels, 1


def escape(content):
    """Escape the given content for use in metric output."""
    return content.replace("\\", r"\\").replace("\n", r"\n").replace('"', r"\"")


def format_value(value):
    """Formats a value for output, e.g. using Go formatting."""
    formatted = repr(value)
    dot = formatted.find('.')
    if value > 0 and dot > 6:
        mantissa = f"{formatted[0]}.{formatted[1:dot]}{formatted[dot + 1:]}".rstrip("0.")
        return f"{mantissa}e+0{dot - 1}"
    else:
        return formatted


def render_openmetrics(*metrics):
    """Renders the metrics using OpenMetrics text format."""
    output = []
    for metric in metrics:
        if metric.description:
            output.append(f"# HELP {metric.name} {escape(metric.description)}\n")
        output.append(f"# TYPE {metric.name} {metric.type}\n")

        for labels, value in metric.records():
            if labels:
                labelstr = "{{{0}}}".format(
                    ",".join([f'{k}="{escape(v)}"' for k, v in sorted(labels.items())])
                )
            else:
                labelstr = ""
            output.append(f"{metric.name}{labelstr} {format_value(value)}\n")
    output.append("# EOF\n")

    return (
        "application/openmetrics-text; version=1.0.0; charset=utf-8",
        "".join(output).encode("utf-8"),
    )


METRICS = {
    settings.api_group: {
        "realms": [
            RealmPhase,
        ],
        "platforms": [
            PlatformPhase,
            PlatformService,
        ],
    },
}


async def metrics_handler(ekclient, request):
    """Produce metrics for the operator."""
    metrics = []
    for api_group, resources in METRICS.items():
        ekapi = await ekclient.api_preferred_version(api_group)
        for resource, metric_classes in resources.items():
            ekresource = await ekapi.resource(resource)
            resource_metrics = [klass() for klass in metric_classes]
            async for obj in ekresource.list(all_namespaces = True):
                for metric in resource_metrics:
                    metric.add_obj(obj)
            metrics.extend(resource_metrics)

    content_type, content = render_openmetrics(*metrics)
    return web.Response(headers={"Content-Type": content_type}, body=content)


async def metrics_server():
    """Launch a lightweight HTTP server to serve the metrics endpoint."""
    ekclient = easykube.Configuration.from_environment().async_client()

    app = web.Application()
    app.add_routes([web.get("/metrics", functools.partial(metrics_handler, ekclient))])

    runner = web.AppRunner(app, handle_signals = False)
    await runner.setup()

    site = web.TCPSite(runner, "0.0.0.0", "8080", shutdown_timeout = 1.0)
    await site.start()

    # Sleep until we need to clean up
    try:
        await asyncio.Event().wait()
    finally:
        await asyncio.shield(runner.cleanup())
