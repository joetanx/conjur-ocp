## Integrate Openshift with Conjur Enterprise using the JWT authenticator

Overview:
- Construct the JWT authenticator for Openshift
- Deploy Conjur follower in Openshift
- Deploy demonstration application `cityapp` in different modes: hard-code, secrets provider and secretless

### Software Versions

- RHEL 9.2
- Conjur Enterprise 13.0
- Openshift 4.13

### Servers

| Hostname  | Role |
| --- | --- |
| conjur.vx  | Conjur master  |
| mysql.vx  | MySQL server  |
| sno.vx  | Single-node Openshift  |

## 1. Setup

### 1.1. Single-node Openshift

Setup a single-node Openshift: <https://github.com/joetanx/setup/blob/main/single-node-openshift.md>

### 1.2. Setup MySQL database

Setup MySQL database according to this guide: <https://github.com/joetanx/setup/blob/main/mysql.md>

### 1.3. Setup Conjur master

Setup Conjur master according to this guide: <https://github.com/joetanx/setup/blob/main/conjur.md>

## 2. Preparing necessary configurations for the JWT authenticator

### 2.1. Configure and enable JWT authenticator

The policy `authn-jwt-ocp.yaml` performs the following:

1. Define the JWT authenticator endpoint in Conjur

- Ref: [2. Define the JWT Authenticator endpoint in Conjur](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)
- Creates `conjur/authn-jwt/ocp` policy with the necessary variables
- Creates the `webservice` for the authenticator with `consumers` group allowed to authenticate to the webservice

2. Enable the seed generation service

- Ref: [Enable the seed generation service](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Deployment/cnj-seedservice.htm)
- Creates `conjur/seed-generation` policy
- Creates the `webservice` for the seed generation with `consumers` group allowed to authenticate to the webservice

3. Define `jwt-apps/ocp` policy with:

- Conjur Follower in Kubernetes identified by `system:serviceaccount:conjur:follower`
  - Ref: [2. Define an identity in Conjur for the Conjur Follower](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-conjfollower.htm)
  - The Conjur Follower is granted access to the JWT authenticator `conjur/authn-jwt/ocp` and seed generation `conjur/seed-generation` webservices by adding it into `consumers` group of respective webservices
- Demo application `cityapp-secretsprovider` and `cityapp-secretless` identified by `system:serviceaccount:cityapp:cityapp-secretsprovider` and `system:serviceaccount:cityapp:cityapp-secretless`
  - Ref: [2. Define the application as a Conjur host in policy + 3.Grant access to secrets](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/cjr-k8s-authn-client-authjwt.htm#Setuptheapplicationtoretrievesecrets)
  - The demo applications are granted access to the JWT authenticator `conjur/authn-jwt/ocp` and demo database secrets `db_cityapp` by adding them to `consumers` group of respective webservice and policy

> **Note**: `authn-jwt-ocp.yaml` builds on top of `app-vars.yaml` in <https://github.com/joetanx/conjur-master>
> 
> Loading `authn-jwt-ocp.yaml` without having `app-vars.yaml` loaded previously will not work

Download and load the Conjur policy:

```console
curl -O https://raw.githubusercontent.com/joetanx/conjur-ocp/main/authn-jwt-ocp.yaml
conjur policy load -f authn-jwt-ocp.yaml -b root && rm -f authn-jwt-ocp.yaml
```

### 2.2. Populate the variables required by the JWT Authenticator

Ref: [3. Populate the policy variables](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)

Retrieve the JWKS public keys and JWT issuer information from Openshift:

```console
oc get --raw $(oc get --raw /.well-known/openid-configuration | jq -r '.jwks_uri') > jwks.json
oc get --raw /.well-known/openid-configuration | jq -r '.issuer'
```

Populate the variables with the information retrieved from Openshift

```console
conjur variable set -i conjur/authn-jwt/ocp/public-keys -v "{\"type\":\"jwks\", \"value\":$(cat jwks.json)}" && rm -f jwks.json
conjur variable set -i conjur/authn-jwt/ocp/issuer -v https://kubernetes.default.svc
conjur variable set -i conjur/authn-jwt/ocp/token-app-property -v sub
conjur variable set -i conjur/authn-jwt/ocp/identity-path -v jwt-apps/ocp
conjur variable set -i conjur/authn-jwt/ocp/audience -v vxlab
```

### 2.3. Allowlist the JWT authenticator in Conjur

Ref:
- [4. Allowlist the JWT Authenticator in Conjur](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)
- [Step 1: Allowlist the authenticators](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Operations/Services/authentication-types.htm#Allowlis)

> **Note**: This step requires that the `authenticators` section in `/etc/conjur/config/conjur.yml` to be configured
> 
> Ref: [2.5. Allowlist the Conjur default authenticator](https://github.com/joetanx/setup/blob/main/conjur.md#25-allowlist-the-conjur-default-authenticator)

```console
podman exec conjur sed -i -e '/authenticators:/a\  - authn-jwt/k8s' /etc/conjur/config/conjur.yml
podman exec conjur evoke configuration apply
```

Verify that the Kubernetes authenticator is configured and allowlisted:

```console
curl -k https://conjur.vx/info
```

### 2.4. Prepare the ConfigMaps

The Conjur master and follower information is passed to the follower and application pods using ConfigMaps

#### 2.4.1. Prepare the environment in Kubernetes

Prepare the projects `conjur` and `cityapp`, and service account `follower`:

```console
oc new-project conjur
oc new-project cityapp
oc -n conjur create serviceaccount follower
oc -n conjur adm policy add-scc-to-user -z follower privileged
```

> **Note**: Conjur Follower needs to run as a privileged container
>
> Ref: [How to run privileged container in Openshift 4](https://access.redhat.com/solutions/6375251)
> 
> If non-root container is required, consider deploying the [Kubernetes Follower](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-k8sfollower-dply.htm) instead

#### 2.4.2. Prepare the necessary values as environments variables to be loaded into ConfigMaps:

```console
CA_CERT="$(curl https://raw.githubusercontent.com/joetanx/conjur-k8s/main/central.pem)"
CONJUR_MASTER_URL=https://conjur.vx
CONJUR_FOLLOWER_URL=https://follower.conjur.svc.cluster.local
AUTHENTICATOR_ID=ocp
CONJUR_ACCOUNT=cyberark
CONJUR_SEED_FILE_URL=$CONJUR_MASTER_URL/configuration/$CONJUR_ACCOUNT/seed/follower
CONJUR_AUTHN_URL=$CONJUR_FOLLOWER_URL/authn-jwt/ocp
```

> **Note** on `CONJUR_SSL_CERTIFICATE`:
> - `dap-seedfetcher` container needs to verify the Conjur **master** certificate
> - `conjur-authn-k8s-client` and `secretless-broker` containers need to verify the Conjur **follower** certificate
> - Since both the master and follower certificates in this demo are signed by the same CA `central.pem`, using the CA certificate will suffice

#### 2.4.3. Create ConfigMap `follower-cm` for follower

Ref: [3. Set up a ConfigMap](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-follower.htm)):

```console
oc -n conjur create configmap follower-cm \
--from-literal CONJUR_ACCOUNT=$CONJUR_ACCOUNT \
--from-literal CONJUR_APPLIANCE_URL=$CONJUR_MASTER_URL \
--from-literal CONJUR_SEED_FILE_URL=$CONJUR_SEED_FILE_URL \
--from-literal AUTHENTICATOR_ID=$AUTHENTICATOR_ID \
--from-literal "CONJUR_SSL_CERTIFICATE=${CA_CERT}"
```

#### 2.4.4. Create ConfigMap `apps-cm` for applications

Ref:
- [Prepare the application namespace, raw Kubernetes manifest](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-set-up-apps.htm#Preparetheapplicationnamespace)
- [CyberArk raw manifest repository](https://github.com/cyberark/conjur-authn-k8s-client/blob/master/helm/conjur-config-namespace-prep/generated/conjur-config-namespace-prep.yaml)

```console
oc -n cityapp create configmap apps-cm \
--from-literal CONJUR_ACCOUNT=$CONJUR_ACCOUNT \
--from-literal CONJUR_APPLIANCE_URL=$CONJUR_FOLLOWER_URL \
--from-literal CONJUR_AUTHN_URL=$CONJUR_AUTHN_URL \
--from-literal "CONJUR_SSL_CERTIFICATE=${CA_CERT}"
```

## 3. Deploy the follower

### 3.1. Setup the Conjur Follower image in Openshift

The Conjur appliance image need to be pushed to the Openshift image registry

Ref: [Accessing the registry](https://docs.openshift.com/container-platform/4.13/registry/accessing-the-registry.html)

```console
podman load -i conjur-appliance-Rls-v13.0.tar.gz && rm -f conjur-appliance-Rls-v13.0.tar.gz
podman tag registry.tld/conjur-appliance:13.0.0.1 image-registry.openshift-image-registry.svc:5000/conjur/conjur-appliance:13.0.0.1
oc login -u kubeadmin -p <password_from_install_log> https://api-int.<cluster_name>.<base_domain>:6443
podman login -u kubeadmin -p $(oc whoami -t) image-registry.openshift-image-registry.svc:5000
podman push image-registry.openshift-image-registry.svc:5000/conjur/conjur-appliance:13.0.0.1
```

### 3.2. Apply the follower deployment

The `follower.yaml` manifest defines the necessary configurations to deploy the Conjur Follower into Kubernetes; review the file and read the ref link to understand how it works

Ref: [4. Set up the Follower service and deployment manifest](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-conjfollower.htm)

Deploy the manifest file into the Kubernetes cluster:

```console
kubectl -n conjur apply -f https://raw.githubusercontent.com/joetanx/conjur-ocp/main/follower.yaml
```

## 4. Preparing for cityapp deployment

The cityapp application is used to demostrate the various scenarios: hard-coded, secrets-provider, and secretless methods to consume the secrets

The deployment manifest files in this repo is configured use `docker.io/joetanx/cityapp:php`

### 4.1. Optional - using Openshift Source-to-Image S2I) to build cityapp container image

To build the container image from [source](https://github.com/joetanx/cityapp-php)

The BuildConfig `cityapp-buildconfig.yaml` provided in this repository defines the S2I manifest

Apply it and `start-build` to build the image and push it to the Openshift image registry:

```console
oc -n cityapp apply -f https://raw.githubusercontent.com/joetanx/conjur-ocp/main/cityapp-buildconfig.yaml
oc start-build cityapp
```

> **Note**: Change the image definition in the `cityapp-<type>.yaml` manifests from `docker.io/joetanx/cityapp:php` to `image-registry.openshift-image-registry.svc:5000/cityapp/cityapp:latest` to use the S2I image

## 5. Deploy cityapp-hardcode

```console
oc -n cityapp apply -f https://raw.githubusercontent.com/joetanx/conjur-ocp/main/cityapp-hardcode.yaml
```

Verify that the application is deployed successfully:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/264f80eb-beaf-4033-baab-4048069b9108)

Open the application location (e.g. `http://hardcode-cityapp.apps.sno.vx/`)
- The cityapp connects to the MySQL world database to display random city information
- The database, username and password information is displayed for debugging, and the application is using the credentials hardcoded in the pod environment variables

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/42c3759f-b6a7-4eef-8be4-32169b5c4c92)

Rotate the password on the MySQL server and update the new password in Conjur:

| Target | Command |
| --- | --- |
| MySQL Server | `mysql -u root -e "ALTER USER 'cityapp'@'%' IDENTIFIED BY 'VkDv6FctHvUp';"` |
| Conjur | `conjur variable set -i db_cityapp/password -v VkDv6FctHvUp` |

> **Note** Conjur can integrate with CyberArk PAM for automatic [secrets rotation](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Operations/Services/rotate-secrets.htm)

Refresh the cityapp-hardcode page: the page will throw an authentication error, since the hard-coded credentials are no longer valid:

```console
SQLSTATE[HY000] [1045] Access denied for user 'cityapp'@'10.244.0.6' (using password: YES)
```

## 6. Retrieving credentials using Secrets Provider for Kubernetes

Ref: [Secrets Provider - Push-to-File mode](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/cjr-k8s-jwt-sp-ic-p2f.htm)

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/d9f2798e-8dba-488e-9d8e-d741fbf0443f)

```console
oc -n cityapp apply -f https://raw.githubusercontent.com/joetanx/conjur-ocp/main/cityapp-secretsprovider.yaml
```

Verify that the application is deployed successfully:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/81343f3a-ac03-41b1-9228-087419523cce)

Open the application location (e.g. `http://secretsprovider-cityapp.apps.sno.vx/`)

Notice that the database connection details list the credentials retrieved from Conjur:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/53c3903b-a4de-46ae-af24-ab7d9bb525ae)

## 7. Deploy cityapp-secretless

### 7.1. Avoiding secrets from ever touching your application - Secretless Broker

The [Secretless Broker](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-secretless-sidecar.htm) enables applications to connect securely to services without ever having to fetch secrets

In this demo, `secretless broker` will run as a sidecar container alongside with the `cityapp` container

The Secretless Broker will:
- Authenticate to Conjur
- Retreive the secrets
- Connect to the database
- Enable a database listener for the application to connect to

Application connection flow with Secretless Broker:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/5551f339-6508-404a-8ca7-6d87b99d346c)

### 7.2. Prepare the ConfigMap to be used by Secretless Broker

Secretless Broker needs some configuration to determine where to listen for new connection requests, where to route those connections, and where to get the credentials for each connection

- Ref: [Prepare the Secretless configuration](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-secretless-sidecar.htm#PreparetheSecretlessconfiguration)

We will map the `secretless-cm.yaml` to the `cityapp` container using a ConfigMap

☝️ Secretless Broker also need to locate Conjur to authenticate and retrieve credentials, this was done in the previous step where we loaded the `apps-cm` ConfigMap

```console
curl -O https://raw.githubusercontent.com/joetanx/conjur-k8s/main/secretless-cm.yaml
oc -n cityapp create configmap secretless-cm --from-file=secretless-cm.yaml && rm -f secretless-cm.yaml
```

### 7.3. Deploy the Secretless-based cityapp

```console
oc -n cityapp apply -f https://raw.githubusercontent.com/joetanx/conjur-ocp/main/cityapp-secretless.yaml
```

Verify that the application is deployed successfully:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/0d745d1a-c5f6-424f-99ad-ecd2fd53673d)

Open the application location (e.g. `http://secretless-cityapp.apps.sno.vx/`)

Notice that the database connection details list that the application is connecting to `127.0.0.1` using empty credentials

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/99afe1d1-705a-4682-bdaa-b55ba81786c8)

