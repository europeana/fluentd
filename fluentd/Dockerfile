# Image pushed as europeana/fluentd
# For versions of the base image see https://hub.docker.com/r/fluent/fluentd-kubernetes-daemonset/
FROM fluent/fluentd-kubernetes-daemonset:v1.19-debian-elasticsearch7-1

LABEL Author="Europeana Foundation <development@europeana.eu>"

USER root

# Install geo-ip plugin (see also https://docs.fluentd.org/filter/geoip),
# and multi-format-parser plugin (https://github.com/repeatedly/fluent-plugin-multi-format-parser)
# and jwt plugin (https://github.com/jwt/ruby-jwt)
RUN buildDeps="build-essential libgeoip-dev libtool automake autoconf wget" \
    && apt-get update \
    && apt-get install -y --no-install-recommends $buildDeps \
    && fluent-gem install fluent-plugin-geoip fluent-plugin-multi-format-parser jwt \
    && rm -rf /var/lib/apt/lists/* \
    # Removes GeoIP database so we re-download below
    && gem sources --clear-all \
    && rm -rf /tmp/* /var/tmp/* /usr/lib/ruby/gems/*/cache/*.gem \
    # Download latest version of GeoLite database
    && mkdir -p /usr/share/geoip \
    && wget -P /usr/share/geoip/ https://git.io/GeoLite2-City.mmdb

# By default fluentd will read plugin files from /fluentd/plugins/ folder (see also Docker containers entrypoint.sh)
COPY plugin_auth/** /fluentd/plugins/


