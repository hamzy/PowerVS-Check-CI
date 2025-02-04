// Copyright 2024 IBM Corp
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/IBM/go-sdk-core/v5/core"
	// https://raw.githubusercontent.com/IBM/platform-services-go-sdk/main/resourcecontrollerv2/resource_controller_v2.go
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	// https://raw.githubusercontent.com/IBM/platform-services-go-sdk/refs/heads/main/resourcemanagerv2/resource_manager_v2.go
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"k8s.io/apimachinery/pkg/util/wait"
	"math"
	gohttp "net/http"
	"strings"
	"time"
)

const (
	// resource ID for Power Systems Virtual Server in the Global catalog.
	virtualServerResourceID = "f165dd34-3a40-423b-9d95-e90a23f724dd"
)

type ServiceInstanceOptions struct {
	ApiKey  string
	Region  string
	Zone    string
	Name    string
	GroupID string
	Exclude string
}

type ServiceInstance struct {
	options         ServiceInstanceOptions
	controllerSvc   *resourcecontrollerv2.ResourceControllerV2
	innerSi         *resourcecontrollerv2.ResourceInstance
	resourceGroupID string
	piSession       *ibmpisession.IBMPISession
	networkClient   *instance.IBMPINetworkClient
	keyClient       *instance.IBMPIKeyClient
	imageClient     *instance.IBMPIImageClient
	dhcpClient      *instance.IBMPIDhcpClient
	instanceClient  *instance.IBMPIInstanceClient
	jobClient       *instance.IBMPIJobClient
}

func initServiceInstance(options ServiceInstanceOptions) (*resourcecontrollerv2.ResourceControllerV2, error) {

	var (
		authenticator core.Authenticator = &core.IamAuthenticator{
			ApiKey: options.ApiKey,
		}
		controllerSvc *resourcecontrollerv2.ResourceControllerV2
		err           error
	)

	// Instantiate the service with an API key based IAM authenticator
	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
		ServiceName:   "cloud-object-storage",
		URL:           "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		log.Fatalf("Error: resourcecontrollerv2.NewResourceControllerV2 returns %v", err)
		return nil, err
	}

	return controllerSvc, nil
}

// convertResourceGroupNameToID converts a resource group name/id to an id.
func convertResourceGroupNameToID(options ServiceInstanceOptions) (string, error) {

	var (
		authenticator core.Authenticator = &core.IamAuthenticator{
			ApiKey: options.ApiKey,
		}
		managementSvc *resourcemanagerv2.ResourceManagerV2
		err           error
	)

	log.Debugf("convertResourceGroupNameToID: options.GroupID = %s", options.GroupID)

	// Instantiate the service with an API key based IAM authenticator
	managementSvc, err = resourcemanagerv2.NewResourceManagerV2(&resourcemanagerv2.ResourceManagerV2Options{
		Authenticator: authenticator,
	})
	if err != nil {
		return "", fmt.Errorf("Error: resourcemanagerv2.NewResourceManagerV2 returns %w", err)
	}

	listResourceGroupsOptions := managementSvc.NewListResourceGroupsOptions()

	resourceGroups, _, err := managementSvc.ListResourceGroups(listResourceGroupsOptions)
	if err != nil {
		return "", err
	}

	for _, resourceGroup := range resourceGroups.Resources {
		if *resourceGroup.Name == options.GroupID {
			log.Debugf("convertResourceGroupNameToID: FOUND NAME = %s, id = %s", *resourceGroup.Name, *resourceGroup.ID)

			return *resourceGroup.ID, nil
		} else if *resourceGroup.ID == options.GroupID {
			log.Debugf("convertResourceGroupNameToID: FOUND name = %s, ID = %s", *resourceGroup.Name, *resourceGroup.ID)

			return *resourceGroup.ID, nil
		}

		log.Debugf("convertResourceGroupNameToID: SKIP Name = %s, Id = %s", *resourceGroup.Name, *resourceGroup.ID)
	}

	return "", fmt.Errorf("failed to find resource group %v", options.GroupID)
}

func leftInContext(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return math.MaxInt64
	}

	duration := time.Until(deadline)

	return duration
}

func NewServiceInstance(siOptions ServiceInstanceOptions) (*ServiceInstance, error) {

	var (
		controllerSvc   *resourcecontrollerv2.ResourceControllerV2
		resourceGroupID string
		si              *ServiceInstance
		err             error
	)

	log.Debugf("NewServiceInstance: siOptions = %+v", siOptions)

	controllerSvc, err = initServiceInstance(siOptions)
	log.Debugf("NewServiceInstance: controllerSvc = %v", controllerSvc)
	if err != nil {
		log.Fatalf("Error: NewServiceInstance: initServiceInstance returns %v", err)
		return nil, err
	}

	resourceGroupID, err = convertResourceGroupNameToID(siOptions)
	if err != nil {
		log.Fatalf("Error: convertResourceGroupNameToID returns %v", err)
		return nil, err
	}

	si = &ServiceInstance{
		options:         siOptions,
		controllerSvc:   controllerSvc,
		innerSi:         nil,
		resourceGroupID: resourceGroupID,
	}

	// Kinda hacky since the class is not fully initialized yet.
	si.innerSi, err = si.findServiceInstance()
	if err != nil {
		err = fmt.Errorf("Error: findServiceInstance returns %v", err)
		return nil, err
	}
	if si.innerSi == nil {
		err = fmt.Errorf("Error: findServiceInstance innerSi is nil!")
		return nil, err
	}

	err = si.createClients()
	if err != nil {
		log.Fatalf("Error: createClients returns %v", err)
		return nil, err
	}

	return si, nil
}

type User struct {
	ID         string
	Email      string
	Account    string
	cloudName  string
	cloudType  string
	generation int
}

func fetchUserDetails(bxSession *bxsession.Session, generation int) (*User, error) {

	var (
		bluemixToken string
	)

	config := bxSession.Config
	user := User{}

	if strings.HasPrefix(config.IAMAccessToken, "Bearer") {
		bluemixToken = config.IAMAccessToken[7:len(config.IAMAccessToken)]
	} else {
		bluemixToken = config.IAMAccessToken
	}

	token, err := jwt.Parse(bluemixToken, func(token *jwt.Token) (interface{}, error) {
		return "", nil
	})
	if err != nil && !strings.Contains(err.Error(), "key is of invalid type") {
		return &user, err
	}

	claims := token.Claims.(jwt.MapClaims)
	if email, ok := claims["email"]; ok {
		user.Email = email.(string)
	}
	user.ID = claims["id"].(string)
	user.Account = claims["account"].(map[string]interface{})["bss"].(string)
	iss := claims["iss"].(string)
	if strings.Contains(iss, "https://iam.cloud.ibm.com") {
		user.cloudName = "bluemix"
	} else {
		user.cloudName = "staging"
	}
	user.cloudType = "public"
	user.generation = generation

	log.Debugf("user.ID         = %v", user.ID)
	log.Debugf("user.Email      = %v", user.Email)
	log.Debugf("user.Account    = %v", user.Account)
	log.Debugf("user.cloudType  = %v", user.cloudType)
	log.Debugf("user.generation = %v", user.generation)

	return &user, nil
}

func (si *ServiceInstance) createPiSession() (*ibmpisession.IBMPISession, error) {

	var (
		bxSession             *bxsession.Session
		tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
		authenticator         *core.IamAuthenticator
		piOptions             *ibmpisession.IBMPIOptions
		piSession             *ibmpisession.IBMPISession
		err                   error
	)

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         si.options.ApiKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return nil, fmt.Errorf("Error bxsession.New: %v", err)
	}
	log.Debugf("bxSession = %v", bxSession)

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	log.Debugf("tokenRefresher = %v", tokenRefresher)
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return nil, fmt.Errorf("Error tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	user, err := fetchUserDetails(bxSession, 2)
	if err != nil {
		return nil, fmt.Errorf("Error fetchUserDetails: %v", err)
	}

	authenticator = &core.IamAuthenticator{
		ApiKey: si.options.ApiKey,
	}
	piOptions = &ibmpisession.IBMPIOptions{
		Authenticator: authenticator,
		Debug:         false,
		Region:        si.options.Region,
		URL:           fmt.Sprintf("https://%s.power-iaas.cloud.ibm.com", si.options.Region),
		UserAccount:   user.Account,
		Zone:          si.options.Zone,
	}

	piSession, err = ibmpisession.NewIBMPISession(piOptions)
	if err != nil {
		return nil, fmt.Errorf("Error ibmpisession.New: %v", err)
	}
	log.Debugf("piSession = %v", piSession)

	return piSession, nil
}

func (si *ServiceInstance) findServiceInstance() (*resourcecontrollerv2.ResourceInstance, error) {

	var (
		ctx        context.Context
		cancel     context.CancelFunc
		options    *resourcecontrollerv2.ListResourceInstancesOptions
		resources  *resourcecontrollerv2.ResourceInstancesList
		err        error
		perPage    int64 = 64
		moreData         = true
		nextURL    *string
		getOptions *resourcecontrollerv2.GetResourceInstanceOptions
		foundSi    *resourcecontrollerv2.ResourceInstance
	)

	ctx, cancel = context.WithTimeout(context.Background(), 15 * time.Minute)
	defer cancel()

	options = si.controllerSvc.NewListResourceInstancesOptions()
	// options.SetType("resource_instance")
	options.SetResourceGroupID(si.resourceGroupID)
	options.SetResourcePlanID(virtualServerResourceID)
	options.SetLimit(perPage)

	for moreData {
		if options.Start != nil {
			log.Debugf("findServiceInstance: options = %+v, options.Limit = %v, options.Start = %v, options.ResourceGroupID = %v", options, *options.Limit, *options.Start, *options.ResourceGroupID)
		} else {
			log.Debugf("findServiceInstance: options = %+v, options.Limit = %v, options.ResourceGroupID = %v", options, *options.Limit, *options.ResourceGroupID)
		}

		resources, _, err = si.controllerSvc.ListResourceInstancesWithContext(ctx, options)
		if err != nil {
			log.Fatalf("Error: ListResourceInstancesWithContext returns %v", err)
			return nil, err
		}

		log.Debugf("findServiceInstance: resources.RowsCount = %v", *resources.RowsCount)

		for _, resource := range resources.Resources {
			var (
				getResourceOptions *resourcecontrollerv2.GetResourceInstanceOptions
				resourceInstance   *resourcecontrollerv2.ResourceInstance
				response           *core.DetailedResponse
			)

			getResourceOptions = si.controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

			resourceInstance, response, err = si.controllerSvc.GetResourceInstance(getResourceOptions)
			if err != nil {
				log.Fatalf("Error: GetResourceInstance returns %v", err)
				return nil, err
			}
			if response != nil && response.StatusCode == gohttp.StatusNotFound {
				log.Debugf("findServiceInstance: gohttp.StatusNotFound")

				continue
			} else if response != nil && response.StatusCode == gohttp.StatusInternalServerError {
				log.Debugf("findServiceInstance: gohttp.StatusInternalServerError")

				continue
			}

			if resourceInstance.Type == nil || resourceInstance.GUID == nil {
				continue
			}
			if *resourceInstance.Type != "service_instance" && *resourceInstance.Type != "composite_instance" {
				continue
			}

			if *resource.Name == si.options.Name {
				log.Debugf("listServiceInstances: FOUND *Name = %s, GUID = %s", *resource.Name, *resource.GUID)

				getOptions = si.controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

				foundSi, response, err = si.controllerSvc.GetResourceInstanceWithContext(ctx, getOptions)
				if err != nil {
					log.Fatalf("Error: GetResourceInstanceWithContext: response = %v, err = %v", response, err)
					return nil, err
				}

				return foundSi, nil
			} else if *resource.GUID == si.options.Name {
				log.Debugf("listServiceInstances: FOUND Name = %s, *GUID = %s", *resource.Name, *resource.GUID)

				getOptions = si.controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

				foundSi, response, err = si.controllerSvc.GetResourceInstanceWithContext(ctx, getOptions)
				if err != nil {
					log.Fatalf("Error: GetResourceInstanceWithContext: response = %v, err = %v", response, err)
					return nil, err
				}

				return foundSi, nil
			} else {
				log.Debugf("listServiceInstances: SKIP Name = %s, GUID = %s", *resource.Name, *resource.GUID)
			}
		}

		// Based on: https://cloud.ibm.com/apidocs/resource-controller/resource-controller?code=go#list-resource-instances
		nextURL, err = core.GetQueryParam(resources.NextURL, "start")
		if err != nil {
			log.Fatalf("Error: GetQueryParam returns %v", err)
			return nil, err
		}
		if nextURL == nil {
			// log.Debugf("nextURL = nil")
			options.SetStart("")
		} else {
			// log.Debugf("nextURL = %v", *nextURL)
			options.SetStart(*nextURL)
		}

		moreData = *resources.RowsCount == perPage
	}

	return nil, nil
}

func (si *ServiceInstance) createClients() error {

	var (
		piSession *ibmpisession.IBMPISession
		err       error
	)

	if si.piSession == nil {
		piSession, err = si.createPiSession()
		if err != nil {
			log.Fatalf("Error: createPiSession returns %v", err)
			return err
		}
		log.Debugf("createServiceInstance: piSession = %+v", piSession)
		si.piSession = piSession
	}
	if si.piSession == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil piSession!")
	}

	if si.networkClient == nil {
		si.networkClient = instance.NewIBMPINetworkClient(context.Background(), si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: networkClient = %v", si.networkClient)
	}
	if si.networkClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil networkClient!")
	}

	if si.keyClient == nil {
		si.keyClient = instance.NewIBMPIKeyClient(context.Background(), si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: keyClient = %v", si.keyClient)
	}
	if si.keyClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil keyClient!")
	}

	if si.imageClient == nil {
		si.imageClient = instance.NewIBMPIImageClient(context.Background(), si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: imageClient = %v", si.imageClient)
	}
	if si.imageClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil imageClient!")
	}

	if si.dhcpClient == nil {
		si.dhcpClient = instance.NewIBMPIDhcpClient(context.Background(), si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: dhcpClient = %v", si.dhcpClient)
	}
	if si.dhcpClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil dhcpClient!")
	}

	if si.instanceClient == nil {
		si.instanceClient = instance.NewIBMPIInstanceClient(context.Background(), si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: instanceClient = %v", si.instanceClient)
	}
	if si.instanceClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil instanceClient!")
	}

	if si.jobClient == nil {
		si.jobClient = instance.NewIBMPIJobClient(context.Background(), si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: jobClient = %v", si.jobClient)
	}
	if si.jobClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil jobClient!")
	}

	return nil
}

func (si *ServiceInstance) findDhcpServers() error {

	var (
		dhcpServers      models.DHCPServers
		dhcpServer       *models.DHCPServer
//		dhcpServerDetail *models.DHCPServerDetail
		err              error
	)

	if si.innerSi == nil {
		return fmt.Errorf("Error: findDhcpServers called on nil ServiceInstance")
	}
	if si.dhcpClient == nil {
		return fmt.Errorf("Error: findDhcpServers has nil dhcpClient")
	}

	dhcpServers, err = si.dhcpClient.GetAll()
	if err != nil {
		return fmt.Errorf("Error: si.dhcpClient.GetAll returns %v", err)
	}

	for _, dhcpServer = range dhcpServers {
		if dhcpServer.ID == nil {
			log.Debugf("findDhcpServers: SKIP nil(ID)")
			continue
		}
		if dhcpServer.Network == nil {
			log.Debugf("findDhcpServers: SKIP %s nil(Network)", *dhcpServer.ID)
			continue
		}

		var field1, field2 string

		if dhcpServer.ID == nil {
			field1 = "nil-ID"
		} else {
			field1 = *dhcpServer.ID
		}
		if dhcpServer.Network.Name == nil {
			field2 = "nil-Network-Name"
		} else {
			field2 = *dhcpServer.Network.Name
		}

		if si.options.Exclude != "" && strings.Contains(field2, si.options.Exclude) {
			fmt.Printf("findDhcpServers: EXCLUDING %s %s\n", field1, field2)
			continue
		}

		fmt.Printf("findDhcpServers: FOUND %s %s\n", field1, field2)

//		dhcpServerDetail, err = si.dhcpClient.Get(*dhcpServer.ID)
//		if err != nil {
//			return fmt.Errorf("Error: si.dhcpClient.Get returns %v", err)
//		}

		if shouldDelete {
			err = si.dhcpClient.Delete(*dhcpServer.ID)
			if err != nil {
				fmt.Printf("Warning: si.dhcpClient.Delete(%s) returns %v\n", *dhcpServer.ID, err)
				continue
//				return fmt.Errorf("Error: si.dhcpClient.Delete(%s) returns %v", *dhcpServer.ID, err)
			}

			err = si.waitForDhcpServerDelete(*dhcpServer.ID)
			if err != nil {
				log.Fatalf("Error: waitForDhcpServerDelete returns %v", err)
				return err
			}
		}
	}

	return nil
}

func (si *ServiceInstance) waitForDhcpServerDelete(id string) error {

	var (
		ctx    context.Context
		cancel context.CancelFunc
		err    error
	)

	if si.innerSi == nil {
		return fmt.Errorf("waitForDhcpServerDelete innerSi is nil")
	}

	ctx, cancel = context.WithTimeout(context.Background(), 15 * time.Minute)
	defer cancel()

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		var (
			detail *models.DHCPServerDetail

			err2 error
		)

		detail, err2 = si.dhcpClient.Get(id)
		if err2 != nil {
			if strings.Contains(err2.Error(), "dhcp server does not exist") {
				return true, nil
			}
			return true, err2
		}
		log.Debugf("waitForDhcpServerDelete: Status = %s", *detail.Status)
		switch *detail.Status {
		case "ACTIVE":
			return false, nil
		case "BUILD":
			return false, nil
		default:
			return true, fmt.Errorf("waitForDhcpServerDelete: unknown state: %s", *detail.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: waitForDhcpServerDelete: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func (si *ServiceInstance) findNetworks() error {

	var (
		networks   *models.Networks
		networkRef *models.NetworkReference
//		network    *models.Network
		err        error
	)

	if si.innerSi == nil {
		return fmt.Errorf("Error: findNetwork called on nil ServiceInstance")
	}
	if si.networkClient == nil {
		return fmt.Errorf("Error: findNetwork has nil networkClient")
	}

	networks, err = si.networkClient.GetAll()
	if err != nil {
		return fmt.Errorf("Error: si.networkClient.GetAll returns %v", err)
	}

	for _, networkRef = range networks.Networks {
		if strings.Contains(*networkRef.Name, "public-") {
			continue
		}
		if si.options.Exclude != "" && strings.Contains(*networkRef.Name, si.options.Exclude) {
			fmt.Printf("findNetwork: EXCLUDING: %s\n", *networkRef.Name)
			continue
		}

		fmt.Printf("findNetwork: FOUND: %s, %s\n", *networkRef.NetworkID, *networkRef.Name)

		if shouldDelete {
			err = si.networkClient.Delete(*networkRef.NetworkID)
			if err != nil {
				fmt.Printf("findNetwork: WARNING si.networkClient.Delete(%s) returns %v\n", *networkRef.NetworkID, err)
//				return fmt.Errorf("Error: si.networkClient.Delete(%s) returns %v", *networkRef.NetworkID, err)
			}
		}
	}

	return nil
}

func (si *ServiceInstance) findSshKeys() error {

	var (
		keys *models.SSHKeys
		key  *models.SSHKey
		err  error
	)

	if si.innerSi == nil {
		return fmt.Errorf("Error: findSshKey called on nil ServiceInstance")
	}
	if si.keyClient == nil {
		return fmt.Errorf("Error: findSshKey has nil keyClient")
	}

	keys, err = si.keyClient.GetAll()
	if err != nil {
		return fmt.Errorf("Error: si.keyClient.GetAll returns %v", err)
	}

	for _, key = range keys.SSHKeys {
		var (
			matches = []string {
				"p-px-",
				"p2-",
				"mac-",
				"cicd-key-",
				"p-mad02-powervs-5-",
				"p-syd04-",
				"p-syd05-",
			}
			found = false
		)

		for _, match := range matches {
			if strings.Contains(*key.Name, match) {
				found = true
			}
		}
		if found {
			if si.options.Exclude != "" && strings.Contains(*key.Name, si.options.Exclude) {
				fmt.Printf("findSshKey: EXCLUDING: %s\n", *key.Name)
				continue
			}

			fmt.Printf("findSshKey: FOUND: %s\n", *key.Name)
			if shouldDelete {
				err = si.keyClient.Delete(*key.Name)
				if err != nil {
					return fmt.Errorf("Error: si.keyClient.Delete(%s) returns %v", *key.Name, err)
				}
			}
		}
	}

	return nil
}

func (si *ServiceInstance) findImages() error {

	var (
		images   *models.Images
		imageRef *models.ImageReference
		err      error
	)

	if si.innerSi == nil {
		return fmt.Errorf("Error: findImages called on nil ServiceInstance")
	}
	if si.imageClient == nil {
		return fmt.Errorf("Error: findImages has nil imageClient")
	}

	images, err = si.imageClient.GetAll()
	if err != nil {
		log.Fatalf("Error: findImage: GetAll returns %v", err)
		return err
	}

	for _, imageRef = range images.Images {
		if si.options.Exclude != "" && strings.Contains(*imageRef.Name, si.options.Exclude) {
			fmt.Printf("findImage: EXCLUDING: %s\n", *imageRef.Name)
			continue
		}

		fmt.Printf("findImage: FOUND %s %s\n", *imageRef.Name, *imageRef.State)

		if shouldDelete {
			err = si.imageClient.Delete(*imageRef.Name)
			if err != nil {
				return fmt.Errorf("Error: si.imageClient.Delete(%s) returns %v", *imageRef.Name, err)
			}
		}
	}

	return nil
}

func (si *ServiceInstance) findPVMInstance() error {

	var (
		instances   *models.PVMInstances
		instanceRef *models.PVMInstanceReference
//		instance    *models.PVMInstance
		err         error
	)

	if si.innerSi == nil {
		return fmt.Errorf("Error: findPVMInstance called on nil ServiceInstance")
	}
	if si.instanceClient == nil {
		return fmt.Errorf("Error: findPVMInstance has nil instanceClient")
	}

	instances, err = si.instanceClient.GetAll()
	if err != nil {
		log.Fatalf("Error: findPVMInstance: GetAll returns %v", err)
		return err
	}

	for _, instanceRef = range instances.PvmInstances {
		if si.options.Exclude != "" && strings.Contains(*instanceRef.ServerName, si.options.Exclude) {
			fmt.Printf("findPVMInstance: EXCLUDING: %s\n", *instanceRef.ServerName)
			continue
		}

		fmt.Printf("findPVMInstance: FOUND %s\n", *instanceRef.ServerName)

		if shouldDelete {
			err = si.instanceClient.Delete(*instanceRef.PvmInstanceID)
			if err != nil {
				return fmt.Errorf("Error: si.instanceClient.Delete(%s) returns %v", *instanceRef.PvmInstanceID, err)
			}

			err = si.waitForPVMInstanceDelete(*instanceRef.PvmInstanceID)
			if err != nil {
			}
		}
	}

	return nil
}

func (si *ServiceInstance) waitForPVMInstanceDelete(pvmInstanceId string) error {

	var (
		ctx      context.Context
		cancel   context.CancelFunc
		instance *models.PVMInstance
		err      error
	)

	if si.innerSi == nil {
		return fmt.Errorf("waitForPVMInstanceReady innerSi is nil")
	}

	ctx, cancel = context.WithTimeout(context.Background(), 15 * time.Minute)
	defer cancel()

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {

		instance, err = si.instanceClient.Get(pvmInstanceId)
		if err != nil {
			if strings.Contains(err.Error(), "unable to get attached volumes") {
				log.Debugf("Error: Wait instanceClient.Get: SKIPPING err = %v", err)
				return false, nil
			}
			log.Fatalf("Error: Wait instanceClient.Get: err = %v", err)
			return false, err
		}
		log.Debugf("waitForPVMInstanceReady: Status = %s", *instance.Status)
		switch *instance.Status {
		case "ACTIVE":
			return true, nil
		case "BUILD":
			return false, nil
		default:
			return true, fmt.Errorf("waitForPVMInstanceReady: unknown state: %s", *instance.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}
