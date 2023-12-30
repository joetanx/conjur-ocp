## 1. Overview

### 1.1. How does Kubernetes integration with Conjur using JWT work?

The Kubernetes cluster API implements an OpenID Connect authentication (OIDC) endpoint at `https://<cluster-url>/.well-known/openid-configuration`
- Service accounts are issued with ServiceAccount tokens, which are in JSON Web Token (JWT) format
- Pods of Deployments can be associated with a ServiceAccount and are issued JWTs via [downward API](https://kubernetes.io/docs/concepts/workloads/pods/downward-api/)
  - Example JWT:
  ```json
  {
    "aud": [
      "https://conjur.vx/"
    ],
    "exp": 1703900734,
    "iat": 1703894734,
    "iss": "https://kubernetes.default.svc",
    "kubernetes.io": {
      "namespace": "cityapp",
      "pod": {
        "name": "p2f-7b547b59b8-8xt6t",
        "uid": "38eb189f-dd93-40e1-ae48-3fd8ff59e6e7"
      },
      "serviceaccount": {
        "name": "p2f",
        "uid": "55843bdd-de5b-453c-9d08-31b5f384b7f9"
      }
    },
    "nbf": 1703894734,
    "sub": "system:serviceaccount:cityapp:p2f"
  }
  ```

- The public keys of the JSON Web Key Set (JWKS) on the authentication endpoint can be used to validate the tokens
  - The public keys of the JWKS can be retrieve by running: `kubectl get --raw $(kubectl get --raw /.well-known/openid-configuration | jq -r '.jwks_uri')`
  - Example JWKS:
  ```json
  {
    "keys": [
      {
        "use": "sig",
        "kty": "RSA",
        "kid": "6ippk97POfJn9gzM-9p3AfPY7CpqfR746up9UmiUn6M",
        "alg": "RS256",
        "n": "zwm_NAL8Y5rzvLwWsAvTNYRW3-vFSz3-MJuCctS73dlIGBZZN45iq_9OkUv0DSVEfrqFq43z7gyTcRSF3fcDWNPhUqphMsst-mMIRSyo3rXnrc8zNXgyNwjDN_fzZHKL1zupbJqHXdGE74c98pFFtqPqHHboNSgMHRgdgPJDab6-GbAvz_raZvGOj-M7tIRxM04b1-wteHf1VpCvFGmG2K-FyMmhGKxIfixuSkUYPnJh6Be_grLiLUp1ivfzRjzLhC9WW8qcoZ_cf9vHhqNZqsjV9kX7k1h2r1xqygdgOgyVe9w9uqYoq4VPdmw9kTO2bAukOlHzuCZhLXr2gwZ0dQ",
        "e": "AQAB"
      },
      {
        "use": "sig",
        "kty": "RSA",
        "kid": "kTYEH_K6sBjGHwcrhRTuR2hQFkN44okgeTq5Th9dBTM",
        "alg": "RS256",
        "n": "xrg7VpAPfaZ8cbV8-lM5SxPqTFE9GDO99KDBhTlTA2bDgwrM1R1oJV1zvXIaDF1UiSl0UvpoQb7iIrxgdPFr416x6k0M2WCQk5GTc9Fyy4s2HJHaDtOR92Q85EcsGzd-yHC-Cm8WMN3TiaJbmz7pTrkp1zyhA1R7T1NjuCbAoyx0_RNIc1OtwFtpYqnD6AOjbMSKKLpkX59VdXrWl1VgdNRDph9Vwjzq8lEHongc_yuVXyWfvWl_EsGbPzBDJ6qdxVPvaeVX3cwEJihJMKWBN2PcrwpHZrNLsYwfOUTbOXIkUCVlytzx49JdK0LtTQyymGDD36P0vMOFikoDbx8FjpESp3F9opCOA7bHi9EMlxr0cNwb2Grfwc08v83Ot3RF7sps8S5zg92gvTCrooT2hUUdb6W3BuYaSMlW24tYwFvjuElozGIBsuwjZt6nWWrwD9GRo2-_orHLpkcV-M9xP-S67UOk2opPQLnK0TkxhZn9jJ_p2eQTbjf5XCgVnT7XDMPkyzGnMi1P1usPu3UhdwFj_nhKoturcLOslui5KHturcbgLmmsIHV5Bimf8DnvXrEWgloFMztPfYdgpBAk8fO7zNVfjr07BoZb58ql5EbcLxTQg7s5__zkCq347aMur26b8OrGyup0Fx8tIJK0PQidldH3v_PcDptrbD8f1Yk",
        "e": "AQAB"
      },
      {
        "use": "sig",
        "kty": "RSA",
        "kid": "suObVj97dCNHNDR37TJNZCJfdxz6r8ABjh6cTdKetqU",
        "alg": "RS256",
        "n": "zE56x4D7Tb6h_fmIegPhjewNahNwsryAdAoGGsOh-HjhAbQCO2pxsHpUm6ySJC_LcG7dKLqKqJdQCH4yP6MfHLNOwq88yniz0YSeBbuFGR5Kj-PUxcowWk2uD4A3Bw2OB9s11nmSa0sGTNvTbut4SvKuwDGO93e-qQZVCuUMJie3H-FbdBtMxLJkFaBVipVArd2rq_csP2w1eQCeUpV1arZXU-zhRNGOQNV2N_-knaHtd5dBxvkdcMbEwdhhBQzZJC34AGJD9dZTgZxtqGZpnWCQH37vVdr0rbtDl9stf71k0VQOXmMW1Sg_grTYedx9DvfefPqpwjlvYM5aK12PItIDisYn4kV3DDDcZY_nyYodQr0qmTuSE4uU_7jEXP0JmXQgW5xmmmZmjL_qiOlu-mZdQPRJ_UU1rLOkvfcInHPC6NRe6v0vqkmUoCz50kaTwuIKkouESrHp7Kw1xrmzJPy_nib8_FaHlnDoJI2YySKY9syRaJpfBoxgcNp1RdXGI2XRHQedkjVwcTNACod5teLz53bLVa3hpfKo7f1CCBCVXdj-AhVdthqjeOdWfcCWy4X7HSr2D47Hx-L7EHHhCv19kZc3W-jxTCbNdMZDh6dTiXul_NFtftAznFi2_W04T9CpYD4HoGC31D5151du_-xVcbLLK1mmOSOUXcsCpDM",
        "e": "AQAB"
      }
    ]
  }
  ```

Ref: https://kubernetes.io/docs/reference/access-authn-authz/authentication/

Conjur leverages on the Kubernetes OIDC authentication endpoint as an Identity Provider (IdP) to authenticate workloads
- Validity of the JWTs can be verified against the JWKS
- Claims in the JWTs can be verified against configured host annotations for authorization checks

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/5868f354-4fff-46bb-8271-6b2dce45462a)

## 2. Setting up the integration

### 2.1. Lab details

#### Software versions

- RHEL 9.3
- Conjur Enterprise 13.1
- Openshift 4.14

### 2.2. Openshift cluster

There are 2 methods to setup a single-node Openshift for testing:
1. OpenShift Local (formerly CodeReady Containers (CRC)) https://developers.redhat.com/products/openshift-local/overview
2. Installing OpenShift on a single node (SNO) https://docs.openshift.com/container-platform/4.14/installing/installing_sno/install-sno-installing-sno.html

A guide to setup SNO is available here: https://github.com/joetanx/setup/blob/main/single-node-openshift.md

### 2.3. Setup MySQL database

- Setup MySQL database according to this guide: https://github.com/joetanx/setup/blob/main/mysql.md

### 2.4. Setup Conjur master

- Setup Conjur master according to this guide: https://github.com/joetanx/setup/blob/main/conjur.md

#### Servers

|Hostname|Role|
|---|---|
|conjur.vx|Conjur master|
|mysql.vx|MySQL server|
|sno.vx|Single-node Kubernetes Openshift|

## 3. Preparing Conjur configurations

There are 2 Conjur policies provider in the [`policies`](./policies) directory of this repository: `authn-jwt-ocp.yaml` and `ocp-hosts.yaml`

### 3.1. JWT authenticator policy

The policy [`authn-jwt-ocp.yaml`](./policies/authn-jwt-ocp.yaml) performs the following:

1. Define the JWT authenticator endpoint in Conjur

- Ref: [2. Define the JWT Authenticator endpoint in Conjur](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)
- Creates `conjur/authn-jwt/ocp` policy with the necessary variables
- Creates the `webservice` for the authenticator with `consumers` group allowed to authenticate to the webservice

2. Enable the seed generation service

- Ref: [6. Enable the seed generation service](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)
- Creates `conjur/seed-generation` policy
- Creates the `webservice` for the seed generation with `consumers` group allowed to request for seed

### 3.2. Host identity policy

The policy [`ocp-hosts.yaml`](./policies/ocp-hosts.yaml) performs the following:

1. Define `jwt-apps/ocp` policy with:

- Host identities for:
  - Conjur Follower in Kubernetes identified by `system:serviceaccount:conjur:follower`
    - Ref: [2. Define an identity in Conjur for the Conjur Follower](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/k8s-conjfollower.htm)
  - Demo applications
    |Host identity|Service account|
    |---|---|
    |`p2f`|`system:serviceaccount:cityapp:p2f`|
    |`p2s-env`|`system:serviceaccount:cityapp:p2s-env`|
    |`p2s-vol`|`system:serviceaccount:cityapp:p2s-vol`|
    |`sl`|`system:serviceaccount:cityapp:sl`|
    - Ref: [2. Define the application as a Conjur host in policy + 3.Grant access to secrets](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/cjr-k8s-authn-client-authjwt.htm#Setuptheapplicationtoretrievesecrets)

2. The follower and demo applications are granted access the following permissions by adding them to the respective `consumers` group:
    |Host identity|Authorization|
    |---|---|
    |Follower|• Allowed to authenticate to `auth-jwt/ocp`<br>• Allowed to request seed|
    |Demo applications|• Allowed to authenticate to `auth-jwt/ocp`<br>• Allowed to retrieve secrets from `db_cityapp`|

> [!Note]
> 
> `ocp-hosts.yaml` builds on top of `app-vars.yaml` in <https://github.com/joetanx/setup/blob/main/conjur.md>
> 
> Loading `ocp-hosts.yaml` without having `app-vars.yaml` loaded previously will not work

Download and load the Conjur policy:

```sh
curl -sLO https://github.com/joetanx/conjur-ocp/raw/main/policies/authn-jwt-ocp.yaml
curl -sLO https://github.com/joetanx/conjur-ocp/raw/main/policies/ocp-hosts.yaml
conjur policy load -b root -f authn-jwt-ocp.yaml
conjur policy load -b root -f ocp-hosts.yaml
```

### 3.3. Populate the variables required by the JWT Authenticator

Ref: [3. Populate the policy variables](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)

Retrieve the JWKS public keys and JWT issuer information from Openshift:

```sh
oc get --raw $(oc get --raw /.well-known/openid-configuration | jq -r '.jwks_uri') > jwks.json
oc get --raw /.well-known/openid-configuration | jq -r '.issuer'
```

```sh
conjur variable set -i conjur/authn-jwt/ocp/public-keys -v "{\"type\":\"jwks\", \"value\":$(cat <jwks.json-file-from-oc)}"
conjur variable set -i conjur/authn-jwt/ocp/issuer -v <issuer-info-from-oc>
conjur variable set -i conjur/authn-jwt/k8s/token-app-property -v sub
conjur variable set -i conjur/authn-jwt/k8s/identity-path -v jwt-apps/ocp
conjur variable set -i conjur/authn-jwt/k8s/audience -v https://conjur.vx/
```

### 3.4. Allowlist the JWT authenticator in Conjur

Ref:
- [4. Enable the JWT Authenticator in Conjur](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)
- [Step 2: Allowlist the authenticators](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Operations/Services/authentication-types.htm#Allowlis)

> [!Note]
> 
> This step requires that the `authenticators` section in `/etc/conjur/config/conjur.yml` to be configured
> 
> Ref: [2.5. Allowlist the Conjur default authenticator](https://github.com/joetanx/setup/blob/main/conjur.md#25-allowlist-the-conjur-default-authenticator)

```sh
podman exec conjur sed -i -e '/authenticators:/a\  - authn-jwt/ocp' /etc/conjur/config/conjur.yml
podman exec conjur evoke configuration apply
```

Verify that the Kubernetes authenticator is configured and allowlisted:

```sh
curl -k https://conjur.vx/info
```

## 4. Deploy the follower

There are 2 methods for deploying followers insider the Kubernetes cluster:

|Method|Description|
|---|---|
|Operator|This is known as **Conjur Kubernetes Follower**. Conjur is dissected into individual component containers (nginx, postgres, syslog-ng, etc) and Custom Resource Definitions (CRDs) are defined to create the **ConjurFollower** operator object in the cluster.|
|Appliance|This is known as **Conjur Follower**. This uses the Conjur appliance container image.|

Ref: https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/k8s-follower-lp.htm

Regardless of the method selected, this guide deploys the followers in the `conjur` namespace

```sh
oc create namespace conjur
```

### 4.1. Method 1 - operator-based follower

#### 4.1.1. Install the Conjur Kubernetes Follower operator from OperatorHub

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/5ba3f15f-c34d-45fd-8b4b-8129486012a5)

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/900a74ff-836e-4338-8e36-f07e774f64d9)

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/1842a68b-f8bd-4570-94e3-623bcef8da1f)

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/7161efc9-b9ca-4521-b7c7-c81b0c92b759)

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/254d3aa3-5fa0-48e6-97c4-1dd1aed24892)

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/52301bb5-fde6-4d94-90b1-f39c8cfe61c0)

> [!Note]
> 
> The Conjur Kubernetes Follower operator can also be manually installed with the images manually imported to the image registry
>
> Ref: https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/k8s-k8sfollower-dply.htm

#### 4.1.2. Create ConfigMap for the Conjur certificate

```sh
curl -sLO https://github.com/joetanx/lab-certs/raw/main/ca/lab_root.pem
oc -n conjur create configmap ca-cert --from-file=conjur-ca.pem=lab_root.pem
```

> [!Note]
> 
> The follower operator verifies the Conjur Master against this ConfigMap
>
> The master certificate in this example is signed by the lab CA `lab_root.pem`

#### 4.1.3. Create ConfigMap for Conjur config file

```sh
cat << EOF > conjur.yml
authenticators:
  - authn-jwt/k8s
  - authn
EOF
oc -n conjur create configmap conjur-config --from-file=conjur.yml
```

> [!Note]
> 
> Without a Conjur config file, only the basic `authn` authenticator will be enabled on the follower operator

#### 4.1.4. Deploy an instance of ConjurFollower operator

Create ConjurFollower from the `InstalledOperator` page (ensure that the correct project (`conjur` in this example) is selected):

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/01b63b75-bb91-4157-8e48-0092cbf8fe95)

Enter the settings of the ConjurFollower to be created:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/0a61367c-8165-4721-a7b2-13cf1c986901)

The create page is updated live between `From view` and `YAML view`

Instead of manually entering the parameters, the yaml manifest can be pasted into `YAML view` to populate all required settings

Example manifest for a ConjurFollower instance:

https://github.com/joetanx/conjur-ocp/blob/be7176385a0ba868fca9641f44f10820af9f7c1e/manifests/ConjurFollowerInstance.yaml#L1-L47

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/efe72adf-1485-432d-bf1a-e16e18bf4c94)

> [!Important]
>
> The `Application Identity` (or `authnLogin`) parameter is to be left empty for JWT authentication
>
> The host identity is picked up from the JWT token automatically
>
> Filling in this parameter for JWT authentication results in `CAKC016 Failed to authenticate` error in the `configurator` container, with a corresponding `USERNAME_MISSING failed to authenticate with authenticator authn-jwt service cyberark:webservice:conjur/authn-jwt/ocp: CONJ00098E JWT identity configuration is invalid` error from the Conjur webservice side

Example successful ConjurFollower instance output:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/25365c03-2eba-4a87-90be-d9ddeac8470d)

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/b174a472-453c-47f3-8a08-1082c2849da2)

```console
[core@sno ~]$ kubectl -n conjur get all
Warning: apps.openshift.io/v1 DeploymentConfig is deprecated in v4.14+, unavailable in v4.10000+
NAME                            READY   STATUS    RESTARTS   AGE
pod/follower-86b8b64f85-826zv   6/6     Running   0          51s

NAME               TYPE        CLUSTER-IP    EXTERNAL-IP   PORT(S)   AGE
service/follower   ClusterIP   172.30.39.5   <none>        443/TCP   51s

NAME                       READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/follower   1/1     1            1           51s

NAME                                  DESIRED   CURRENT   READY   AGE
replicaset.apps/follower-86b8b64f85   1         1         1       51s
```

### 4.2. Method 2 - appliance-based follower

Ref: [4. Set up the Follower service and deployment manifest](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/k8s-conjfollower.htm)

#### 4.2.1. Allow follower container to run privileged

The appliance-based follower needs to run as a privileged container

Ref: [How to run privileged container in Openshift 4](https://access.redhat.com/solutions/6375251)

```
oc -n conjur adm policy add-scc-to-user -z follower privileged
```

If non-root container is required, use the operator-based follower in previous section instead

#### 4.2.2. Create ConfigMap required by the appliance-based follower

Prepare the Conjur Master information:

```sh
CA_CERT="$(curl -sL https://github.com/joetanx/lab-certs/raw/main/ca/lab_root.pem)"
CONJUR_MASTER_URL=https://conjur.vx
AUTHENTICATOR_ID=ocp
CONJUR_ACCOUNT=cyberark
CONJUR_SEED_FILE_URL=$CONJUR_MASTER_URL/configuration/$CONJUR_ACCOUNT/seed/follower
```

> [!Note]
> 
> The follower operator verifies the Conjur Master against `CA_CERT`
>
> The master certificate in this example is signed by the lab CA `lab_root.pem`

Create the ConfigMap:

```sh
oc -n conjur create configmap follower-cm \
--from-literal CONJUR_ACCOUNT=$CONJUR_ACCOUNT \
--from-literal CONJUR_APPLIANCE_URL=$CONJUR_MASTER_URL \
--from-literal CONJUR_SEED_FILE_URL=$CONJUR_SEED_FILE_URL \
--from-literal AUTHENTICATOR_ID=$AUTHENTICATOR_ID \
--from-literal "CONJUR_SSL_CERTIFICATE=${CA_CERT}"
```

#### 4.2.3. Import the Conjur appliance image to the Openshift image registry

Ref: [Accessing the registry](https://docs.openshift.com/container-platform/4.13/registry/accessing-the-registry.html)

```console
podman load -i conjur-appliance-Rls-v13.1.0.tar.gz && rm -f conjur-appliance-Rls-v13.1.0.tar.gz
podman tag registry.tld/conjur-appliance:13.1.0 image-registry.openshift-image-registry.svc:5000/conjur/conjur-appliance:13.1.0
oc login -u kubeadmin -p <password_from_install_log> https://api-int.<cluster_name>.<base_domain>:6443
podman login -u kubeadmin -p $(oc whoami -t) image-registry.openshift-image-registry.svc:5000
podman push image-registry.openshift-image-registry.svc:5000/conjur/conjur-appliance:13.1.0
```

#### 4.2.4. Prepare manifest file for the appliance-based follower

Download the [sample appliance follower manifest file](./manifests/appliance-follower.yaml)

Update the `<image-registry>` and `<conjur-version>` in the manifest file to the appropriate values

#### 4.2.5. Apply the manifest file to deploy the appliance-based follower

```sh
oc apply -f appliance-follower.yaml
```

## 5. Deploy the cityapp test application

### 5.1. Preparing for cityapp deployment

The cityapp application is used to demostrate the various scenarios: hard-coded, secrets-provider, and secretless methods to consume the secrets

The deployment manifest files in this repo is configured use `docker.io/joetanx/cityapp:php`

<details><summary><b>OPTIONAL:</b> using Openshift Source-to-Image S2I) to build cityapp container image</summary>

To build the container image from [source](https://github.com/joetanx/cityapp-php)

The BuildConfig `cityapp-buildconfig.yaml` provided in this repository defines the S2I manifest

Apply it and `start-build` to build the image and push it to the Openshift image registry:

```console
oc -n cityapp apply -f https://raw.githubusercontent.com/joetanx/conjur-ocp/main/cityapp-buildconfig.yaml
oc start-build cityapp
```

> [!Note]
>
> Change the image definition in the `cityapp-<type>.yaml` manifests from `docker.io/joetanx/cityapp:php` to `image-registry.openshift-image-registry.svc:5000/cityapp/cityapp:latest` to use the S2I image

</details>

### 5.2. Deploy cityapp-hardcode

Create the `cityapp` namespace

```sh
oc create namespace cityapp
```

```sh
oc apply -f https://github.com/joetanx/conjur-ocp/raw/main/manifests/hc.yaml
```

Verify that the application is deployed successfully:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/9a52588d-6663-4a7c-9b27-e9217b50cfe5)

Open the application location (e.g. `http://hc-cityapp.apps.sno.vx/`)
- The cityapp connects to the MySQL world database to display random city information
- The database, username and password information is displayed for debugging, and the application is using the credentials hardcoded in the pod environment variables

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/82a6b1d1-78c2-49bf-b112-9134f214c017)

Rotate the password on the MySQL server and update the new password in Conjur:

|Task|Command|
|---|---|
|Generate random string|`NEWPASS=$(openssl rand -base64 12)`|
|MySQL Server|`mysql -u root -e "ALTER USER 'cityapp'@'%' IDENTIFIED BY '$NEWPASS';"`|
|Conjur|`conjur variable set -i db_cityapp/password -v $NEWPASS`|

> **Note** Conjur can integrate with CyberArk PAM for automatic [secrets rotation](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Operations/Services/rotate-secrets.htm)

Refresh the cityapp-hardcode page: the page will throw an authentication error, since the hard-coded credentials are no longer valid:

```
SQLSTATE[HY000] [1045] Access denied for user 'cityapp'@'192.168.17.93' (using password: YES)
```

## 6. Retrieving secrets from Conjur with [secrets provider for k8s](https://github.com/cyberark/secrets-provider-for-k8s)

### 6.0. Preparation for cityapp : secrets provider deployment

Create ConfigMap required by the secrets provider

Ref:
- [Prepare the Kubernetes cluster and Golden ConfigMap](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/k8s-jwt-set-up-apps.htm#PreparetheKubernetesclusterandGoldenConfigMap)
- [CyberArk raw manifest repository](https://github.com/cyberark/conjur-authn-k8s-client/blob/master/helm/conjur-config-namespace-prep/generated/conjur-config-namespace-prep.yaml)

Prepare the follower information:

```sh
CA_CERT="$(curl -sL https://github.com/joetanx/lab-certs/raw/main/ca/lab_root.pem)"
CONJUR_FOLLOWER_URL=https://follower.conjur.svc.cluster.local
CONJUR_ACCOUNT=cyberark
CONJUR_AUTHN_URL=$CONJUR_FOLLOWER_URL/authn-jwt/ocp
```

> [!Note]
> 
> The secrets provider verifies the Conjur follower against `CA_CERT`
>
> The follower certificate in this example is signed by the lab CA `lab_root.pem`

Create the ConfigMap:

```sh
oc -n cityapp create configmap apps-cm \
--from-literal CONJUR_ACCOUNT=$CONJUR_ACCOUNT \
--from-literal CONJUR_APPLIANCE_URL=$CONJUR_FOLLOWER_URL \
--from-literal CONJUR_AUTHN_URL=$CONJUR_AUTHN_URL \
--from-literal "CONJUR_SSL_CERTIFICATE=${CA_CERT}"
```

### 6.1. Push to file (p2f)

Ref: [Secrets Provider - Push-to-File mode](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/cjr-k8s-jwt-sp-ic-p2f.htm)

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/9feff6d2-cfae-4bdc-a936-beb9478dfef5)

```sh
oc apply -f https://github.com/joetanx/conjur-ocp/raw/main/manifests/p2f.yaml
```

Verify that the application is deployed successfully:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/0b5c94c1-2878-4072-804d-0171e31da8b6)

Open the application location (e.g. `http://p2f-cityapp.apps.sno.vx/`)

- Notice that the database connection details list the credentials retrieved from Conjur:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/42f8c870-2a0b-4f4d-9f90-572dc45b2fa4)

### 6.2. Push to Kubernetes secrets (p2s)

Ref [Secrets Provider - Kubernetes Secrets mode](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/cjr-k8s-jwt-sp-ic.htm)

#### 6.2.1. Environment variables mode

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/cfbc27ed-6543-428f-a95f-619fec1d310f)

```sh
oc apply -f https://github.com/joetanx/conjur-ocp/raw/main/manifests/p2s-env.yaml
```

Verify that the application is deployed successfully:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/e4444f8d-68ec-49d0-ac4a-4a38740e9313)

Open the application location (e.g. `http://p2s-env-cityapp.apps.sno.vx/`)

- Notice that the database connection details list the credentials retrieved from Conjur:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/022a20d5-2d64-43cb-ad7e-20ed133b1846)

#### 6.2.2. Volume mount mode

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/8f97df3f-181f-46c5-af04-33c7303e39f4)

```sh
oc apply -f https://github.com/joetanx/conjur-ocp/raw/main/manifests/p2s-vol.yaml
```

Verify that the application is deployed successfully:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/6c3b1797-b9e6-4790-82e7-1ba407bb1d80)

Open the application location (e.g. `http://p2s-vol-cityapp.apps.sno.vx/`)

- Notice that the database connection details list the credentials retrieved from Conjur:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/9ee27832-f814-4d76-89ce-feabb5b15027)

### 6.3. Differences between P2F, P2S-Env and P2S-Vol design patterns

#### 6.3.1. P2F behaviour

**Secrets provider push destination:** File in volume shared with application

**Application consume secrets from:** File in volume shared with secrets provider

**Rotation behaviour:** File in shared volume gets updated by the secrets provider periodically (in sidecar mode), deployment restart is not required.

#### 6.3.2. P2S-Env behaviour

**Secrets provider push destination:** Kubernetes secrets

**Application consume secrets from:** Environment variables

**Rotation behaviour:**

Kubernetes secrets get updated by the secrets provider periodically (in sidecar mode).

However, Kubernetes secrets are only pushed to the pods environment during pods start-up, the rotated secret is not updated in the pod's environment variables.

Hence, deployment restart is required to get updated secrets

#### 6.3.3. P2S-Vol behaviour

**Secrets provider push destination:** Kubernetes secrets

**Application consume secrets from:** Files in volume mount

**Rotation behaviour:**

Kubernetes secrets get updated by the secrets provider periodically (in sidecar mode).

However, updates to the files in the volume mount is dependent on the Kubernetes cluster:
- The kubelet keeps a cache of the current keys and values for the Secrets that are used in volumes for pods on that node.
- Updates to Secrets can be either propagated by an API watch mechanism (the default), based on a cache with a defined time-to-live, or polled from the cluster API server on each kubelet synchronisation loop.
- As a result, the total delay from the moment when the Secret is updated to the moment when new keys are projected to the Pod can be as long as the kubelet sync period + cache propagation delay, where the cache propagation delay depends on the chosen cache type (following the same order listed in the previous paragraph, these are: watch propagation delay, the configured cache TTL, or zero for direct polling).
- Ref: https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod

<details><summary><h2>7. ARCHIVED: Deploy cityapp-secretless</h2></summary>

> [!Note]
> 
> Requires [6.0. Preparation for cityapp : secrets provider deployment](#60-preparation-for-cityapp--secrets-provider-deployment)

### 7.1. Avoiding secrets from ever touching your application - Secretless Broker

The [Secretless Broker](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/k8s-secretless-sidecar.htm) enables applications to connect securely to services without ever having to fetch secrets

In the provided [`sl.yaml`](./manifests/sl.yaml) manifest, the `secretless broker` runs as a sidecar container alongside with the `cityapp` container

The Secretless Broker will:
- Authenticate to Conjur
- Retreive the secrets
- Connect to the database
- Enable a database listener for the application to connect to

Application connection flow with Secretless Broker:

![sl](https://github.com/joetanx/conjur-k8s/assets/90442032/dadde68b-b6d7-429a-a14e-c31489f6924e)

### 7.2. Prepare the ConfigMap to be used by Secretless Broker

Secretless Broker needs some configuration to determine where to listen for new connection requests, where to route those connections, and where to get the credentials for each connection

- Ref: [Prepare the Secretless configuration](https://docs.cyberark.com/conjur-enterprise/latest/en/Content/Integrations/k8s-ocp/k8s-secretless-sidecar.htm#PreparetheSecretlessconfiguration)

We will map the `sl-cm.yaml` to the `cityapp` container using a ConfigMap

☝️ Secretless Broker also need to locate Conjur to authenticate and retrieve credentials, this was done in the [previous step](#44-create-configmap-apps-cm-for-applications) where we loaded the `apps-cm` ConfigMap

```sh
curl -sLO https://github.com/joetanx/conjur-k8s/raw/main/manifests/sl-cm.yaml
oc -n cityapp create configmap sl-cm --from-file=sl-cm.yaml && rm -f sl-cm.yaml
```

### 7.3. Deploy the Secretless-based cityapp

```sh
oc apply -f https://github.com/joetanx/conjur-ocp/raw/main/manifests/sl.yaml
```

Verify that the application is deployed successfully:

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/74d9fac0-f103-4f51-83c1-81e7f9632272)

Open the application location (e.g. `http://sl-cityapp.apps.sno.vx/`)

- Notice that the database connection details list that the application is connecting to `127.0.0.1` using empty credentials

![image](https://github.com/joetanx/conjur-ocp/assets/90442032/29bd8ce8-9bf4-4a00-b7a1-76c3929bccb2)

</details>
