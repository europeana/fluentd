# FluentD Deployment

This directory contains resources for deploying the FluentD log collector deamonset to the Kubernetes cluster.

## Requirements
- [Kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/) for generating Kubernetes manifests and managing environment-specific configurations.
- [envsubst](https://linux.die.net/man/1/envsubst) for generating customization files.

## File Structure
This folder consists of a Kustomize base layer and two patch layers: for local development (`dev`) and cloud deployment (`cloud`).
The files below are required for deployment:

```
    fluentd:
      ├── base
      │    ├── fluentd.properties.yaml#           
      │    ├── fluentd.properties.yaml.template
      │    ├── kustomization.yaml
      │    └── conf
      │         ├── apps.conf
      │         ├── fluent.conf                
      │         ├── ingress.conf
      │         ├── keycloak.conf
      │         └── output.conf
      │           
      └── overlays
           ├── cloud
           │    ├── deamonset_volume_patch.yaml
           │    └── kustomization.yaml 
           └── dev
                ├── fluentd-ns.yaml
                ├── fluentd-rbac.yaml
                └── kustomization.yaml 
 ```
_# indicates a file not in version control_

_For the Keycloak app, access logs are separated and parsed using keycloak.conf due to a different log location, log structure, and internal routing of calls._


### File naming scheme
File names have the following structure:

- `*.properties.yaml.template` contain environment variables that need to be substituted. These are used for generating YAML files read by Kustomize.
- `*.properties.yaml` are generated from a template by interpolating the environment variables within the template. These contain configurable settings and are not checked in to git.
- `*_patch*.yaml` "patch" resources created in the base layer. These don't have to configurable, eg. `overlays/cloud/daemonset_volume_patch.yaml`
- `*.yaml` are plain Kubernetes YAML files that don't require any customization; however they could be "patched" in an overlay. eg. `base/deployment.yaml` is patched by both overlays.
- `*.conf` files contain the FluentD configuration

## Deployment Instructions
- Export the environment variables that need to be substituted into `fluentd.properties.yaml`:

```
export ELASTIC_SEARCH_HOSTS=${ELASTICSEARCH_HOSTS}
export ELASTIC_SEARCH_INDEX=${ELASTICSEARCH_INDEX}
```
where `${ELASTICSEARCH_HOSTS}` is a comma-separated list of URLs to Elasticsearch instances and `${ELASTICSEARCH_INDEX}` is a string prefix to be used for indices for logs in Elasticsearch.

- run the envsubst command:
```
envsubst < ./fluentd/base/fluentd.properties.yaml.template > ./fluentd/base/fluentd.properties.yaml
```

### Local Deployment
```
kustomize build ./fluentd/base
kubectl apply -k ./fluentd/base
```
or use go to the `local_test` folder and run the local copy of the configuration (see instructions there)

### IBM Cloud Deployment
```
kustomize build ./fluentd/overlays/cloud
kubectl apply -k ./fluentd/overlays/cloud
```

### Wait for daemonset to rollout

```kubectl rollout status daemonset/fluentd -n fluentd -w```
