# go-morpheus-sdk

- Website: https://www.morpheusdata.com/
- Docs: [Morpheus Documentation](https://docs.morpheusdata.com)
- Support: [Morpheus Support](https://support.morpheusdata.com)

<img src="https://www.morpheusdata.com/wp-content/uploads/2018/06/cropped-morpheus_highres.png" width="600px">

This package provides the official [Go](https://golang.org/) library for the [Morpheus API](https://bertramdev.github.io/morpheus-apidoc/).

This is being developed in conjunction with the [Morpheus Terraform Provider](https://github.com/gomorpheus/morpheus-terraform-provider).

## Setup

Install Go, export environment variables, go get the morpheus package and begin executing requests.

## Requirements

* [Go](https://golang.org/dl/) | 1.13

### Environment Variables

Be sure to setup your Go environment variables.

```bash
export GOPATH=$HOME/gocode
export PATH=$PATH:$GOPATH/bin
```

### Installation

Use go get to retrieve the SDK to add it to your GOPATH workspace, or project's Go module dependencies.

```sh
go get github.com/gomorpheus/morpheus-go-sdk
```

To update the SDK use go get -u to retrieve the latest version of the SDK.

```sh
go get -u github.com/gomorpheus/morpheus-go-sdk
```

## Usage

Here are some examples of how to use `morpheus.Client`.

### New Client

Instantiate a new client and authenticate.

```go
import "github.com/gomorpheus/morpheus-go-sdk"
client := morpheus.NewClient("https://yourmorpheus.com")
client.SetUsernameAndPassword("username", "password")
resp, err := client.Login()
if err != nil {
    fmt.Println("LOGIN ERROR: ", err)
}
fmt.Println("LOGIN RESPONSE:", resp)
```

You can also create a client with a valid access token, instead of authenticating with a username and password.

```go
import "github.com/gomorpheus/morpheus-go-sdk"
client := morpheus.NewClient("https://yourmorpheus.com")
client.SetAccessToken("a3a4c6ea-fb54-42af-109b-63bdd19e5ae1", "", 0, "write")
resp, err := client.Whoami()
if err != nil {
    fmt.Println("WHOAMI ERROR: ", err)
}
fmt.Println("WHOAMI RESPONSE:", resp)
```

**NOTE** It is not necessary to call `client.Login()` explicitely. The client will attempt to authenticate, if needed, whenever `Execute()` is called.

### Execute Any Request

You can also use the `Execute` method to execute an arbitrary api request, using any http method, path parameters, and body.

```go
resp, err := client.Execute(&morpheus.Request{
    Method: "GET",
    Path: "/api/instances",
    QueryParams:map[string]string{
        "name": "tftest",
    },
})
if err != nil {
    fmt.Println("API ERROR: ", err)
}
fmt.Println("API RESPONSE:", resp)
```

### List Instances

Fetch a list of instances.

```go
resp, err := client.ListInstances(&morpheus.Request{})
// parse JSON and fetch the first one by ID
listInstancesResult := resp.Result.(*morpheus.ListInstancesResult)
instancesCount := listInstancesResult.Meta.Total
fmt.Sprintf("Found %d Instances.", instancesCount)
```

**NOTE:** This may be simplified so that typecasting the result is not always needed.

## Testing

You can execute the latest tests using:

```sh
go test
```

The above command will (ideally) print results like this:

```
Initializing test client for tfplugin @ https://yourmorpheus.com
PASS
ok      github.com/gomorpheus/morpheus-go-sdk   1.098s
```

Running `go test` will fail with a panic right away if you have not yet setup your test environment variables.  

```bash
export MORPHEUS_TEST_URL=https://yourmorpheus.com
export MORPHEUS_TEST_USERNAME=gotest
export MORPHEUS_TEST_PASSWORD=19830B3f489
```
**Be Careful running this test suite**. It creates and destroys data. Never point at any URL other than a test environment. Although, in reality, tests will not modify or destroy any pre-existing data. It could still orphan some test some data, or cause otherwise undesired effects.

You can run an individual test like this:

```sh
go test -run TestGroupsCRUD
```


```bash
go test -v
```

## Contribution

This library is currently under development.  Eventually every API endpoint will have a corresponding method defined by [Client](client.go) with the request and response types defined.

Feel free to contribute by implementing the list of missing endpoints. See [Coverage](#coverage).

### Code Structure

The main type this package exposes is [Client](../blob/master/client.go), implemented in client.go.  

Each resource is defined in its own file eg. [instances.go](../blob/master/instances.go)  which extends the `Client` type by defining a function for each endpoint the resource has, such as GetInstance(), ListInstances(), CreateInstance(), UpdateInstance, DeleteInstance(), etc. The request and response payload types used by those methods are also defined here.

#### Test Files

Be sure to add a `_test.go` file with unit tests for each new resource that is implemented.

### External Resources

Link | Description
--------- | -----------
[Morpheus API](https://bertramdev.github.io/morpheus-apidoc/) | The Morpheus API documentation.


## Coverage

API | Available?
--------- | -----------
account_groups | n/a
accounts | n/a
appliance_settings | n/a
apps | n/a
archive_buckets | n/a
archive_files | n/a
auth | n/a
blueprints | n/a
cloud_datastores | n/a
cloud_folders | n/a
cloud_policies | n/a
cloud_resource_pools | n/a
clouds | [Clouds](clouds.go)
clusters | n/a
containers | n/a
custom_instance_types | n/a
cypher | n/a
dashboard | n/a
deploy | n/a
deployments | n/a
environments | n/a
execute_schedules | n/a
execution_request | n/a
file_copy_request | n/a
group_policies | n/a
groups | [Groups](groups.go)
image_builder | n/a
instance_types | n/a
instances | [Instances](instances.go)
key_pairs | n/a
library_compute_type_layouts | n/a
library_container_scripts | n/a
library_container_templates | n/a
library_container_types | n/a
library_container_upgrades | n/a
library_instance_types | n/a
library_layouts | n/a
license | n/a
load_balancers | n/a
logs | n/a
log_settings | n/a
monitoring | n/a
monitoring.checks | n/a
monitoring.groups | n/a
monitoring.apps | n/a
monitoring.incidents | n/a
monitoring.alerts | n/a
monitoring.contacts | n/a
network_domain_records | n/a
network_domains | [Network Domains](network_domains.go)
network_groups | n/a
network_pool_ips | n/a
network_pool_servers | n/a
network_pools | n/a
network_proxies | n/a
network_services | n/a
network_subnet_types | n/a
network_subnets | n/a
network_types | n/a
networks | [Networks](networks.go)
option_type_lists | n/a
option_types | n/a
policies | n/a
power_schedules | n/a
processes | n/a
provision_types | n/a
refresh_token | n/a
reports | n/a
roles | n/a
security_group_rules | n/a
security_groups | n/a
server_types | n/a
servers | n/a
service_plans | n/a
setup | n/a
storage_providers | n/a
subnets | n/a
task_sets | n/a
tasks | n/a
user_groups | n/a
user_settings | n/a
user_sources | n/a
users | n/a
virtual_images | n/a
whoami | n/a
whitelabel_settings | n/a
wiki | n/a
