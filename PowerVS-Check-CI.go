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

// (cd PowerVS-Check-CI/; /bin/rm go.*; go mod init example/user/PowerVS-Check-CI; go mod tidy)
// (cd PowerVS-Check-CI/; echo "vet:"; go vet || exit 1; echo "build:"; go build *.go || exit 1; echo "run:"; ./PowerVS-Check-CI -apiKey "$(cat /var/run/powervs-ipi-cicd-secrets/powervs-creds/IBMCLOUD_API_KEY)" -resourceGroup "..." -name "..." -shouldDebug true)

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/IBM-Cloud/bluemix-go/crn"
	"github.com/IBM/go-sdk-core/v5/core"
	// https://raw.githubusercontent.com/IBM/platform-services-go-sdk/refs/heads/main/globalsearchv2/global_search_v2.go
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/sirupsen/logrus"
	"io"
	"k8s.io/utils/ptr"
	"os"
	"strings"
	"time"
)

var (
	shouldDebug    = false
	shouldDelete   = false
	log            *logrus.Logger
	defaultTimeout = 5 * time.Minute
	// Map of regions to a zone
	Regions      = map[string][]string{
		"dal":      { "dal10",   "dal12"   },
		"eu-de":    { "eu-de-1", "eu-de-2" },
		"eu-gb":    { "eu-gb",   },
		"lon":      { "lon04",   "lon06"   },
		"mad":      { "mad02",   "mad04"   },
		"mon":      { "mon01"    },
		"osa":      { "osa21"    },
		"sao":      { "sao01",   "sao04"   },
		"syd":      { "syd04",   "syd05"   },
		"tok":      { "tok04"    },
		"tor":      { "tor01"    },
		"us-east":  { "us-east"  },
		"us-south": { "us-south" },
		"wdc":      { "wdc06",   "wdc07"   },
	}
)

func contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultTimeout)
}

type resourceSearchResult struct {
	Name      string
	Crn       string
	crnStruct crn.CRN
}

func resourceSearchServiceInstances(apiKey string) ([]resourceSearchResult, error) {
	return resourceSearch(apiKey, "family:resource_controller AND type:resource-instance AND crn:crn\\:v1\\:bluemix\\:public\\:power-iaas*", "ocp-ipi-ci-")
}

func resourceSearchCloudObjectStorages(apiKey string) ([]resourceSearchResult, error) {
	return resourceSearch(apiKey, "family:resource_controller AND type:resource-instance AND crn:crn\\:v1\\:bluemix\\:public\\:cloud-object-storage*", "")
}

func resourceSearchTransitGateways(apiKey string) ([]resourceSearchResult, error) {
	return resourceSearch(apiKey, "family:resource_controller AND type:gateway", "")
}

func resourceSearch(apiKey string, query string, skip string) ([]resourceSearchResult, error) {
	var (
		ctx                 context.Context
		cancel              context.CancelFunc
		authenticator       core.Authenticator = &core.IamAuthenticator{
			ApiKey: apiKey,
		}
		globalSearchOptions *globalsearchv2.GlobalSearchV2Options
		searchService       *globalsearchv2.GlobalSearchV2
		moreData                  = true
		perPage             int64 = 100
		searchCursor        string
		searchOptions       *globalsearchv2.SearchOptions
		scanResult          *globalsearchv2.ScanResult
		response            *core.DetailedResponse
		properties          map[string]interface{}
		propertyName        string
		ok                  bool
		crnStruct           crn.CRN
		result              []resourceSearchResult
		err                 error
	)

	log.Debugf("resourceSearch: query = %s", query)

	ctx, cancel = context.WithTimeout(context.Background(), 15 * time.Minute)
	defer cancel()

	globalSearchOptions = &globalsearchv2.GlobalSearchV2Options{
		URL:           globalsearchv2.DefaultServiceURL,
		Authenticator: authenticator,
	}

	searchService, err = globalsearchv2.NewGlobalSearchV2(globalSearchOptions)
	if err != nil {
		return nil, fmt.Errorf("resourceSearch: globalsearchv2.NewGlobalSearchV2: %w", err)
	}

	result = make([]resourceSearchResult, 0, 10)

	for moreData {
		searchOptions = &globalsearchv2.SearchOptions{
			Query: &query,
			Limit: ptr.To(perPage),
			// default Fields: []string{"account_id", "name", "type", "family", "crn"},
			// all     Fields: []string{"*"},
		}
		if searchCursor != "" {
			searchOptions.SetSearchCursor(searchCursor)
		}
		log.Debugf("resourceSearch: searchOptions = %+v", searchOptions)

		scanResult, response, err = searchService.SearchWithContext(ctx, searchOptions)
		if err != nil {
			return nil, fmt.Errorf("resourceSearch: searchService.SearchWithContext: err = %w, response = %v", err, response)
		}
		if scanResult.SearchCursor != nil {
			log.Debugf("resourceSearch: scanResult = %+v, scanResult.SearchCursor = %+v, len scanResult.Items = %d", scanResult, *scanResult.SearchCursor, len(scanResult.Items))
		} else {
			log.Debugf("resourceSearch: scanResult = %+v, scanResult.SearchCursor = nil, len scanResult.Items = %d", scanResult, len(scanResult.Items))
		}

		for _, item := range scanResult.Items {
			crnStruct, err = crn.Parse(*item.CRN)
			if err != nil {
				log.Debugf("resourceSearch: could not parse crn = %s", *item.CRN)

				return nil, fmt.Errorf("resourceSearch: could not parse CRN property")
			}

			properties = item.GetProperties()

			propertyName, ok = properties["name"].(string)
			if !ok {
				return nil, fmt.Errorf("resourceSearch: name property not found")
			}

			if skip != "" && !strings.Contains(propertyName, skip) {
				log.Debugf("resourceSearch: SKIPPING %s", propertyName)

				continue
			}
			log.Debugf("resourceSearch: FOUND    %s", propertyName)

			result = append(result, resourceSearchResult{
				Name:      propertyName,
				Crn:       *item.CRN,
				crnStruct: crnStruct,
			})
		}

		moreData = int64(len(scanResult.Items)) == perPage
		if moreData {
			if scanResult.SearchCursor != nil {
				searchCursor = *scanResult.SearchCursor
			}
		}
	}

	return result, err
}

func mapZoneToRegion(zone string) string {
	var (
		foundRegion string
	)

	for regionName, zoneValues := range Regions {
		for _, z := range zoneValues {
			if z == zone {
				foundRegion = regionName
			}
		}
	}

	return foundRegion
}

func main() {

	var (
		out                 io.Writer
		ptrApiKey           *string
		ptrShouldDebug      *string
		ptrShouldDelete     *string
		ptrResourceGroup    *string
		ptrZone             *string
		ptrRegion           *string
		ptrName             *string
		ptrExclude          *string
		siOptions           ServiceInstanceOptions
		si                  *ServiceInstance
		tgOptions           TransitGatewayOptions
		tg                  *TransitGateway
		rsrCISIs            []resourceSearchResult
		rsrCISI             resourceSearchResult
		rsrCITGs            []resourceSearchResult
		rsrCITG             resourceSearchResult
		handle              = false
		err                 error
	)

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")
	ptrShouldDelete = flag.String("shouldDelete", "false", "Should delete resources")
	ptrResourceGroup = flag.String("resourceGroup", "", "The resource group to use")
	ptrZone = flag.String("zone", "", "The zone to use")
	ptrRegion = flag.String("region", "", "The region to use")
	ptrName = flag.String("name", "", "The service instance name or GUID to use")
	ptrExclude = flag.String("exclude", "", "The pattern to exclude from matches")

	flag.Parse()

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		err = fmt.Errorf("Error: shouldDebug is not true/false (%s)\n", *ptrShouldDebug)
		fmt.Println(err)
		os.Exit(1)
	}

	if shouldDebug {
		out = os.Stderr
	} else {
		out = io.Discard
	}
	log = &logrus.Logger{
		Out: out,
		Formatter: new(logrus.TextFormatter),
		Level: logrus.DebugLevel,
	}

	switch strings.ToLower(*ptrShouldDelete) {
	case "true":
		shouldDelete = true
	case "false":
		shouldDelete = false
	default:
		err = fmt.Errorf("Error: shouldDelete is not true/false (%s)\n", *ptrShouldDelete)
		fmt.Println(err)
		os.Exit(1)
	}

	if *ptrApiKey == "" {
		fmt.Println("Error: No API key set, use -apiKey")
		os.Exit(1)
	}

	if false {
		log.Printf("WARNING: Not handling %s", *ptrZone)
		log.Printf("WARNING: Not handling %s", *ptrRegion)
	}

	log.Printf("Begin")

	//
	// Handle Service Instances
	//
	rsrCISIs, err = resourceSearchServiceInstances(*ptrApiKey)
	if err != nil {
		fmt.Printf("Error: resourceSearchServiceInstances returns %v\n", err)
		os.Exit(1)
	}
//	log.Printf("rsrCISIs = %+v", rsrCISIs)

	for _, rsrCISI = range rsrCISIs {
		// If the user passed in a name, then only handle that name/GUID
		if *ptrName != "" {
			if rsrCISI.Name == *ptrName {
				handle = true
			} else if rsrCISI.crnStruct.ServiceInstance == *ptrName {
				handle = true
			} else {
				handle = false
			}
		} else {
			handle = true
		}

		if !handle {
			continue
		}

		// The CRN only has a region which is a PowerVS zone.  So also find a PowerVS region.
		foundRegion := mapZoneToRegion(rsrCISI.crnStruct.Region)

		if foundRegion == "" {
			fmt.Printf("Error: Could not map zone %s\n", rsrCISI.crnStruct.Region)
			os.Exit(1)
		}

		fmt.Printf("Handling %s (%s) in region %s and zone %s\n", rsrCISI.Name, rsrCISI.crnStruct.ServiceInstance, foundRegion, rsrCISI.crnStruct.Region)

		// Create a Service Instance
		siOptions = ServiceInstanceOptions{
			ApiKey:  *ptrApiKey,
			Name:    rsrCISI.crnStruct.ServiceInstance,
			Region:  foundRegion,
			Zone:    rsrCISI.crnStruct.Region,
			GroupID: *ptrResourceGroup,
			Exclude: *ptrExclude,
		}

		si, err = NewServiceInstance(siOptions)
		if err != nil {
			fmt.Printf("Error: NewServiceInstance returns %v\n", err)
			os.Exit(1)
		}
		log.Printf("si = %+v", si)

		err = si.findDhcpServers()
		if err != nil {
			fmt.Printf("Error: si.DhcpServers returns %v\n", err)
			os.Exit(1)
		}

		err = si.findNetworks()
		if err != nil {
			fmt.Printf("Error: si.Networks returns %v\n", err)
			os.Exit(1)
		}

		err = si.findSshKeys()
		if err != nil {
			fmt.Printf("Error: si.findSshKeys returns %v\n", err)
			os.Exit(1)
		}

		err = si.findImages()
		if err != nil {
			fmt.Printf("Error: si.findImages returns %v\n", err)
			os.Exit(1)
		}

		err = si.findPVMInstance()
		if err != nil {
			fmt.Printf("Error: si.findPVMInstance returns %v\n", err)
			os.Exit(1)
		}
	}

	//
	// Handle Transit Gateways
	//
	rsrCITGs, err = resourceSearchTransitGateways(*ptrApiKey)
	if err != nil {
		fmt.Printf("Error: resourceSearchTransitGateways returns %v\n", err)
		os.Exit(1)
	}
//	log.Printf("rsrCITGs = %+v", rsrCITGs)

	for _, rsrCITG = range rsrCITGs {
		// If the user passed in a name, then only handle that name/GUID
		if *ptrName != "" {
			if rsrCITG.Name == *ptrName {
				handle = true
			} else if rsrCITG.crnStruct.Resource == *ptrName {
				handle = true
			} else {
				handle = false
			}
		} else {
			handle = true
		}

		if !handle {
			continue
		}

		// The CRN only has a region which is a PowerVS zone.  So also find a PowerVS region.
		foundRegion := mapZoneToRegion(rsrCITG.crnStruct.Region)

		if foundRegion == "" {
			fmt.Printf("Error: Could not map zone %s\n", rsrCITG.crnStruct.Region)
			os.Exit(1)
		}

		fmt.Printf("Handling %s in region %s and zone %s\n", rsrCITG.Name, foundRegion, rsrCITG.crnStruct.Region)

		// Create a Transit Gateway
		tgOptions = TransitGatewayOptions{
			ApiKey:  *ptrApiKey,
			Name:    rsrCITG.Name,
			Region:  foundRegion,
		}

		tg, err = NewTransitGateway(tgOptions)
		if err != nil {
			fmt.Printf("Error: NewTransitGateway returns %v\n", err)
			os.Exit(1)
		}
		log.Printf("tg = %+v", tg)

		err = tg.findTransitGatewayConnections()
		if err != nil {
			fmt.Printf("Error: tg.findTransitGatewayConnections returns %v\n", err)
			os.Exit(1)
		}
	}
}
