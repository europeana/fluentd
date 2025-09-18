This folder contains a copy of the current fluentd configuration located in folder /fluentd/kustomize/base/conf, but 
then tailored to be run in a local environment. For local testing there is no need to setup a kubernetes cluster or ELK,
only Ruby and Fluentd need to be installed. Furthermore the following fluentd plugins need to be installed.
  * fluent-plugin-concat
  * fluent-plugin-multi-format-parser
  * fluent-plugin-rewrite-tag-filter
  * fluent-plugin-kubernetes_metadata_filter
  * jwt

We recommend setting the following environment variables

    export EANA_K8S_CLUSTER=localtest
    export EXCLUDE_HOST_REGEX="/.dev.eanadev.org|^(portal-js|contribute|contentful-proxy|proxy|style|www|classic|blog)/"

The EXCLUDE_HOST_REGEX filters out often-used services for which we don't want to capture logs.

To run open a terminal, go to this folder and run `fluentd -c local.conf -p ../fluentd/plugin_auth`.

The results will be written to files in the `result` folder.
To retry delete the generated result folder and restart using the same command.