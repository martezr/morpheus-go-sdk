package morpheus

import (
	"fmt"
	"time"
)

var (
	// LicensePath is the API endpoint for license configuration
	LicensePath = "/api/license"
)

// GetLicenseResult structures for use in request and response payloads
type GetLicenseResult struct {
	License struct {
		ID                    int       `json:"id"`
		KeyID                 string    `json:"keyId"`
		Hash                  string    `json:"hash"`
		LicenseVersion        int       `json:"licenseVersion"`
		ProductTier           string    `json:"productTier"`
		StartDate             time.Time `json:"startDate"`
		EndDate               time.Time `json:"endDate"`
		MaxInstances          int       `json:"maxInstances"`
		MaxMemory             int       `json:"maxMemory"`
		MaxStorage            int       `json:"maxStorage"`
		LimitType             string    `json:"limitType"`
		MaxManagedServers     int       `json:"maxManagedServers"`
		MaxDiscoveredServers  int       `json:"maxDiscoveredServers"`
		MaxHosts              int       `json:"maxHosts"`
		MaxMvm                int       `json:"maxMvm"`
		MaxMvmSockets         int       `json:"maxMvmSockets"`
		MaxSockets            int       `json:"maxSockets"`
		MaxIac                int       `json:"maxIac"`
		MaxXaas               int       `json:"maxXaas"`
		MaxExecutions         int       `json:"maxExecutions"`
		MaxDistributedWorkers int       `json:"maxDistributedWorkers"`
		MaxDiscoveredObjects  int       `json:"maxDiscoveredObjects"`
		HardLimit             bool      `json:"hardLimit"`
		MultiTenant           bool      `json:"multiTenant"`
		WhiteLabel            bool      `json:"whiteLabel"`
		ReportStatus          bool      `json:"reportStatus"`
		SupportLevel          string    `json:"supportLevel"`
		AccountName           string    `json:"accountName"`
		Config                string    `json:"config"`
		AmazonProductCodes    string    `json:"amazonProductCodes"`
		Features              struct {
			Dashboard                bool `json:"dashboard"`
			Guidance                 bool `json:"guidance"`
			Discovery                bool `json:"discovery"`
			Analytics                bool `json:"analytics"`
			Scheduling               bool `json:"scheduling"`
			Approvals                bool `json:"approvals"`
			Usage                    bool `json:"usage"`
			Activity                 bool `json:"activity"`
			Instances                bool `json:"instances"`
			Apps                     bool `json:"apps"`
			Templates                bool `json:"templates"`
			Automation               bool `json:"automation"`
			VirtualImages            bool `json:"virtualImages"`
			Library                  bool `json:"library"`
			Migrations               bool `json:"migrations"`
			Deployments              bool `json:"deployments"`
			Groups                   bool `json:"groups"`
			Clouds                   bool `json:"clouds"`
			Hosts                    bool `json:"hosts"`
			Network                  bool `json:"network"`
			LoadBalancers            bool `json:"loadBalancers"`
			Storage                  bool `json:"storage"`
			KeyPairs                 bool `json:"keyPairs"`
			SslCertificates          bool `json:"sslCertificates"`
			Boot                     bool `json:"boot"`
			Backups                  bool `json:"backups"`
			Cypher                   bool `json:"cypher"`
			Archives                 bool `json:"archives"`
			ImageBuilder             bool `json:"imageBuilder"`
			Tenants                  bool `json:"tenants"`
			Plans                    bool `json:"plans"`
			Pricing                  bool `json:"pricing"`
			Users                    bool `json:"users"`
			UserGroups               bool `json:"userGroups"`
			Monitoring               bool `json:"monitoring"`
			Logging                  bool `json:"logging"`
			MonitoringServices       bool `json:"monitoringServices"`
			LoggingServices          bool `json:"loggingServices"`
			BackupServices           bool `json:"backupServices"`
			DNSServices              bool `json:"dnsServices"`
			CodeService              bool `json:"codeService"`
			BuildServices            bool `json:"buildServices"`
			LoadBalancerServices     bool `json:"loadBalancerServices"`
			IpamServices             bool `json:"ipamServices"`
			ApprovalServices         bool `json:"approvalServices"`
			CmdbServices             bool `json:"cmdbServices"`
			DeploymentServices       bool `json:"deploymentServices"`
			AutomationServices       bool `json:"automationServices"`
			ServiceDiscoveryServices bool `json:"serviceDiscoveryServices"`
			IdentityServices         bool `json:"identityServices"`
			TrustServices            bool `json:"trustServices"`
			SecurityServices         bool `json:"securityServices"`
			MvmClusters              bool `json:"mvmClusters"`
			Tasks                    bool `json:"tasks"`
			Workflows                bool `json:"workflows"`
			Thresholds               bool `json:"thresholds"`
			Jobs                     bool `json:"jobs"`
			Vdi                      bool `json:"vdi"`
			ServiceCatalog           bool `json:"serviceCatalog"`
			Personas                 bool `json:"personas"`
			Reports                  bool `json:"reports"`
			Costing                  bool `json:"costing"`
			Clusters                 bool `json:"clusters"`
			Policies                 bool `json:"policies"`
			Integrations             bool `json:"integrations"`
			Packages                 bool `json:"packages"`
			Plugins                  bool `json:"plugins"`
			DistributedWorkers       bool `json:"distributedWorkers"`
			Health                   bool `json:"health"`
			Clients                  bool `json:"clients"`
			Export                   bool `json:"export"`
			Ansible                  bool `json:"ansible"`
			SecurityGroups           bool `json:"securityGroups"`
			NetworkRegistryServices  bool `json:"networkRegistryServices"`
			SoftwareLicenses         bool `json:"softwareLicenses"`
			Environments             bool `json:"environments"`
			Motd                     bool `json:"motd"`
			Profiles                 bool `json:"profiles"`
			Wiki                     bool `json:"wiki"`
			PowerScheduling          bool `json:"powerScheduling"`
			ExecuteScheduling        bool `json:"executeScheduling"`
			Executions               bool `json:"executions"`
			EnvironmentVariables     bool `json:"environmentVariables"`
			LifecycleExtend          bool `json:"lifecycleExtend"`
			DhcpRelays               bool `json:"dhcpRelays"`
			DhcpServers              bool `json:"dhcpServers"`
			StaticRoutes             bool `json:"staticRoutes"`
			ScriptEngines            bool `json:"scriptEngines"`
			MoveServers              bool `json:"moveServers"`
		} `json:"features"`
		ZoneTypes         []string  `json:"zoneTypes"`
		ZoneTypesExcluded string    `json:"zoneTypesExcluded"`
		TaskTypes         []string  `json:"taskTypes"`
		TaskTypesExcluded string    `json:"taskTypesExcluded"`
		LastUpdated       time.Time `json:"lastUpdated"`
		DateCreated       time.Time `json:"dateCreated"`
		RecalculationDate time.Time `json:"recalculationDate"`
	} `json:"license"`
	InstalledLicenses []struct {
		ID                    int       `json:"id"`
		KeyID                 string    `json:"keyId"`
		Hash                  string    `json:"hash"`
		LicenseVersion        int       `json:"licenseVersion"`
		ProductTier           string    `json:"productTier"`
		StartDate             time.Time `json:"startDate"`
		EndDate               time.Time `json:"endDate"`
		MaxInstances          int       `json:"maxInstances"`
		MaxMemory             int       `json:"maxMemory"`
		MaxStorage            int       `json:"maxStorage"`
		LimitType             string    `json:"limitType"`
		MaxManagedServers     int       `json:"maxManagedServers"`
		MaxDiscoveredServers  int       `json:"maxDiscoveredServers"`
		MaxHosts              int       `json:"maxHosts"`
		MaxMvm                int       `json:"maxMvm"`
		MaxMvmSockets         int       `json:"maxMvmSockets"`
		MaxSockets            int       `json:"maxSockets"`
		MaxIac                int       `json:"maxIac"`
		MaxXaas               int       `json:"maxXaas"`
		MaxExecutions         int       `json:"maxExecutions"`
		MaxDistributedWorkers int       `json:"maxDistributedWorkers"`
		MaxDiscoveredObjects  int       `json:"maxDiscoveredObjects"`
		HardLimit             bool      `json:"hardLimit"`
		MultiTenant           bool      `json:"multiTenant"`
		WhiteLabel            bool      `json:"whiteLabel"`
		ReportStatus          bool      `json:"reportStatus"`
		SupportLevel          string    `json:"supportLevel"`
		AccountName           string    `json:"accountName"`
		Config                string    `json:"config"`
		AmazonProductCodes    string    `json:"amazonProductCodes"`
		Features              struct {
			Dashboard                bool `json:"dashboard"`
			Guidance                 bool `json:"guidance"`
			Discovery                bool `json:"discovery"`
			Analytics                bool `json:"analytics"`
			Scheduling               bool `json:"scheduling"`
			Approvals                bool `json:"approvals"`
			Usage                    bool `json:"usage"`
			Activity                 bool `json:"activity"`
			Instances                bool `json:"instances"`
			Apps                     bool `json:"apps"`
			Templates                bool `json:"templates"`
			Automation               bool `json:"automation"`
			VirtualImages            bool `json:"virtualImages"`
			Library                  bool `json:"library"`
			Migrations               bool `json:"migrations"`
			Deployments              bool `json:"deployments"`
			Groups                   bool `json:"groups"`
			Clouds                   bool `json:"clouds"`
			Hosts                    bool `json:"hosts"`
			Network                  bool `json:"network"`
			LoadBalancers            bool `json:"loadBalancers"`
			Storage                  bool `json:"storage"`
			KeyPairs                 bool `json:"keyPairs"`
			SslCertificates          bool `json:"sslCertificates"`
			Boot                     bool `json:"boot"`
			Backups                  bool `json:"backups"`
			Cypher                   bool `json:"cypher"`
			Archives                 bool `json:"archives"`
			ImageBuilder             bool `json:"imageBuilder"`
			Tenants                  bool `json:"tenants"`
			Plans                    bool `json:"plans"`
			Pricing                  bool `json:"pricing"`
			Users                    bool `json:"users"`
			UserGroups               bool `json:"userGroups"`
			Monitoring               bool `json:"monitoring"`
			Logging                  bool `json:"logging"`
			MonitoringServices       bool `json:"monitoringServices"`
			LoggingServices          bool `json:"loggingServices"`
			BackupServices           bool `json:"backupServices"`
			DNSServices              bool `json:"dnsServices"`
			CodeService              bool `json:"codeService"`
			BuildServices            bool `json:"buildServices"`
			LoadBalancerServices     bool `json:"loadBalancerServices"`
			IpamServices             bool `json:"ipamServices"`
			ApprovalServices         bool `json:"approvalServices"`
			CmdbServices             bool `json:"cmdbServices"`
			DeploymentServices       bool `json:"deploymentServices"`
			AutomationServices       bool `json:"automationServices"`
			ServiceDiscoveryServices bool `json:"serviceDiscoveryServices"`
			IdentityServices         bool `json:"identityServices"`
			TrustServices            bool `json:"trustServices"`
			SecurityServices         bool `json:"securityServices"`
			MvmClusters              bool `json:"mvmClusters"`
			Tasks                    bool `json:"tasks"`
			Workflows                bool `json:"workflows"`
			Thresholds               bool `json:"thresholds"`
			Jobs                     bool `json:"jobs"`
			Vdi                      bool `json:"vdi"`
			ServiceCatalog           bool `json:"serviceCatalog"`
			Personas                 bool `json:"personas"`
			Reports                  bool `json:"reports"`
			Costing                  bool `json:"costing"`
			Clusters                 bool `json:"clusters"`
			Policies                 bool `json:"policies"`
			Integrations             bool `json:"integrations"`
			Packages                 bool `json:"packages"`
			Plugins                  bool `json:"plugins"`
			DistributedWorkers       bool `json:"distributedWorkers"`
			Health                   bool `json:"health"`
			Clients                  bool `json:"clients"`
			Export                   bool `json:"export"`
			Ansible                  bool `json:"ansible"`
			SecurityGroups           bool `json:"securityGroups"`
			NetworkRegistryServices  bool `json:"networkRegistryServices"`
			SoftwareLicenses         bool `json:"softwareLicenses"`
			Environments             bool `json:"environments"`
			Motd                     bool `json:"motd"`
			Profiles                 bool `json:"profiles"`
			Wiki                     bool `json:"wiki"`
			PowerScheduling          bool `json:"powerScheduling"`
			ExecuteScheduling        bool `json:"executeScheduling"`
			Executions               bool `json:"executions"`
			EnvironmentVariables     bool `json:"environmentVariables"`
			LifecycleExtend          bool `json:"lifecycleExtend"`
			DhcpRelays               bool `json:"dhcpRelays"`
			DhcpServers              bool `json:"dhcpServers"`
			StaticRoutes             bool `json:"staticRoutes"`
			ScriptEngines            bool `json:"scriptEngines"`
			MoveServers              bool `json:"moveServers"`
		} `json:"features"`
		ZoneTypes         []string  `json:"zoneTypes"`
		ZoneTypesExcluded string    `json:"zoneTypesExcluded"`
		TaskTypes         []string  `json:"taskTypes"`
		TaskTypesExcluded string    `json:"taskTypesExcluded"`
		LastUpdated       time.Time `json:"lastUpdated"`
		DateCreated       time.Time `json:"dateCreated"`
		RecalculationDate string    `json:"recalculationDate"`
	} `json:"installedLicenses"`
	CurrentUsage struct {
		Memory                          int64 `json:"memory"`
		Storage                         int64 `json:"storage"`
		Workloads                       int   `json:"workloads"`
		ManagedServers                  int   `json:"managedServers"`
		DiscoveredServers               int   `json:"discoveredServers"`
		Hosts                           int   `json:"hosts"`
		Mvm                             int   `json:"mvm"`
		MvmSockets                      int   `json:"mvmSockets"`
		HypervisorSocketCount           int   `json:"hypervisorSocketCount"`
		PublicVirtualMachineCount       int   `json:"publicVirtualMachineCount"`
		PublicVirtualMachineSocketCount int   `json:"publicVirtualMachineSocketCount"`
		Sockets                         int   `json:"sockets"`
		MvmVirtualMachines              int   `json:"mvmVirtualMachines"`
		Iac                             int   `json:"iac"`
		Xaas                            int   `json:"xaas"`
		Executions                      int   `json:"executions"`
		DistributedWorkers              int   `json:"distributedWorkers"`
		DiscoveredObjects               int   `json:"discoveredObjects"`
	} `json:"currentUsage"`
	LicenseLimits []struct {
		Code         string  `json:"code"`
		Max          int     `json:"max"`
		Used         int     `json:"used"`
		PercentUsed  float64 `json:"percentUsed"`
		Warning      bool    `json:"warning"`
		LimitReached bool    `json:"limitReached"`
	} `json:"licenseLimits"`
	LimitReached bool `json:"limitReached"`
}
type UninstallLicenseResult struct {
	DeleteResult
}

// Client request methods
func (client *Client) GetLicense(req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "GET",
		Path:        LicensePath,
		QueryParams: req.QueryParams,
		Result:      &GetLicenseResult{},
	})
}

func (client *Client) InstallLicense(req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "POST",
		Path:        LicensePath,
		QueryParams: req.QueryParams,
		Body:        req.Body,
		Result:      &GetLicenseResult{},
	})
}

func (client *Client) TestLicense(req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "POST",
		Path:        fmt.Sprintf("%s/test", LicensePath),
		QueryParams: req.QueryParams,
		Body:        req.Body,
		Result:      &GetLicenseResult{},
	})
}

func (client *Client) UninstallLicense(id int64, req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "DELETE",
		Path:        LicensePath,
		QueryParams: req.QueryParams,
		Body:        req.Body,
		Result:      &UninstallLicenseResult{},
	})
}
