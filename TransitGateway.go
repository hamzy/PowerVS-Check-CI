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
	"math"
//	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	// https://raw.githubusercontent.com/IBM/networking-go-sdk/master/transitgatewayapisv1/transit_gateway_apis_v1.go
	"github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
)

type TransitGatewayNetworkType int

const (
	NETWORK_TYPE_PVS TransitGatewayNetworkType = iota
	NETWORK_TYPE_VPC
)

type TransitGatewayOptions struct {
	ApiKey string
	Region string
	Name   string
}

type TransitGateway struct {
	options  TransitGatewayOptions
	tgClient *transitgatewayapisv1.TransitGatewayApisV1
	innerTg  *transitgatewayapisv1.TransitGateway
}

func initTransitGateway(options TransitGatewayOptions) (*transitgatewayapisv1.TransitGatewayApisV1, error) {

	var (
		authenticator core.Authenticator = &core.IamAuthenticator{
			ApiKey: options.ApiKey,
		}
		versionDate                      = "2024-07-16"
		tgClient                         *transitgatewayapisv1.TransitGatewayApisV1
		err                              error
	)

	tgClient, err = transitgatewayapisv1.NewTransitGatewayApisV1(&transitgatewayapisv1.TransitGatewayApisV1Options{
		Authenticator: authenticator,
		Version:       ptr.To(versionDate),
	})
	if err != nil {
		log.Fatalf("Error: transitgatewayapisv1.NewTransitGatewayApisV1 returns %v", err)
		return nil, err
	}

	return tgClient, nil
}

func NewTransitGateway(tgOptions TransitGatewayOptions) (*TransitGateway, error) {

	var (
		tgClient *transitgatewayapisv1.TransitGatewayApisV1
		tg       *TransitGateway
		err      error
	)

	log.Debugf("NewTransitGateway: tgOptions = %+v", tgOptions)

	tgClient, err = initTransitGateway(tgOptions)
	if err != nil {
		log.Fatalf("Error: NewTransitGateway: initTransitGateway returns %v", err)
		return nil, err
	}

	tg = &TransitGateway{
		options:  tgOptions,
		tgClient: tgClient,
		innerTg:  nil,
	}

	// Kinda hacky since the class is not fully initialized yet.
	tg.innerTg, err = tg.findTransitGateway()
	if err != nil {
		err = fmt.Errorf("Error: findTransitGateway returns %v", err)
		return nil, err
	}
	if tg.innerTg == nil {
		err = fmt.Errorf("Error: findTransitGateway innerTg is nil!")
		return nil, err
	}

	return tg, nil
}

func (tg *TransitGateway) findTransitGateway() (*transitgatewayapisv1.TransitGateway, error) {

	var (
		ctx                        context.Context
		cancel                     context.CancelFunc
		listTransitGatewaysOptions *transitgatewayapisv1.ListTransitGatewaysOptions
		gatewayCollection          *transitgatewayapisv1.TransitGatewayCollection
		gateway                    transitgatewayapisv1.TransitGateway
		response                   *core.DetailedResponse
		perPage                    int64 = 32
		moreData                         = true
		err                        error
	)

	ctx, cancel = contextWithTimeout()
	defer cancel()

	listTransitGatewaysOptions = tg.tgClient.NewListTransitGatewaysOptions()
	listTransitGatewaysOptions.Limit = &perPage

	for moreData {
		// https://github.com/IBM/networking-go-sdk/blob/master/transitgatewayapisv1/transit_gateway_apis_v1.go#L184
		gatewayCollection, response, err = tg.tgClient.ListTransitGatewaysWithContext(ctx, listTransitGatewaysOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to list transit gateways: %w and the respose is: %s", err, response)
		}

		for _, gateway = range gatewayCollection.TransitGateways {
			if *gateway.Name == tg.options.Name {
				var (
					getOptions *transitgatewayapisv1.GetTransitGatewayOptions

					foundTg *transitgatewayapisv1.TransitGateway
				)

				getOptions = tg.tgClient.NewGetTransitGatewayOptions(*gateway.ID)

				foundTg, response, err = tg.tgClient.GetTransitGatewayWithContext(ctx, getOptions)
				if err != nil {
					log.Fatalf("Error: GetTransitGateway: response = %v, err = %v", response, err)
					return nil, err
				}

				log.Debugf("findTransitGateway: FOUND Name = %s", *gateway.Name)

				return foundTg, nil
			} else {
				log.Debugf("findTransitGateway: SKIP Name = %s", *gateway.Name)
			}
		}

		if gatewayCollection.First != nil {
			log.Debugf("findTransitGateway: First = %+v", *gatewayCollection.First.Href)
		} else {
			log.Debugf("findTransitGateway: First = nil")
		}
		if gatewayCollection.Limit != nil {
			log.Debugf("findTransitGateway: Limit = %v", *gatewayCollection.Limit)
		}
		if gatewayCollection.Next != nil {
			start, err := gatewayCollection.GetNextStart()
			if err != nil {
				log.Debugf("findTransitGateway: err = %v", err)
				return nil, fmt.Errorf("findTransitGateway: failed to GetNextStart: %w", err)
			}
			if start != nil {
				log.Debugf("findTransitGateway: start = %v", *start)
				listTransitGatewaysOptions.SetStart(*start)
			}
		} else {
			log.Debugf("findTransitGateway: Next = nil")
			moreData = false
		}
	}

	return nil, nil
}

func (tg *TransitGateway) findTransitGatewayConnections() error {

	var (
		ctx                                   context.Context
		cancel                                context.CancelFunc
		listConnectionsOptions                *transitgatewayapisv1.ListConnectionsOptions
		transitConnectionCollections          *transitgatewayapisv1.TransitConnectionCollection
		transitConnection                     transitgatewayapisv1.TransitConnection
		deleteTransitGatewayConnectionOptions *transitgatewayapisv1.DeleteTransitGatewayConnectionOptions
		response                              *core.DetailedResponse
		err                                   error
		perPage                               int64 = 32
		moreData                                    = true
	)

	if tg.innerTg == nil {
		return fmt.Errorf("findTransitGatewayConnections innerTg is nil")
	}

	ctx, cancel = contextWithTimeout()
	defer cancel()

	listConnectionsOptions = tg.tgClient.NewListConnectionsOptions()
	listConnectionsOptions.SetLimit(perPage)

	for moreData {
		transitConnectionCollections, response, err = tg.tgClient.ListConnectionsWithContext(ctx, listConnectionsOptions)
		if err != nil {
			log.Debugf("findTransitGatewayConnections: ListTransitGatewayConnectionsWithContext returns %v and the response is: %s", err, response)
			return err
		}
		for _, transitConnection = range transitConnectionCollections.Connections {
			if *transitConnection.TransitGateway.ID != *tg.innerTg.ID {
				continue
			}

			fmt.Printf("findTransitGatewayConnections: FOUND %s\n", *transitConnection.Name)

			if !shouldDelete {
				continue
			}

			deleteTransitGatewayConnectionOptions = tg.tgClient.NewDeleteTransitGatewayConnectionOptions(
				*transitConnection.TransitGateway.ID,
				*transitConnection.ID,
			)

			response, err = tg.tgClient.DeleteTransitGatewayConnectionWithContext(ctx, deleteTransitGatewayConnectionOptions)
			if err != nil {
				log.Fatalf("deleteTransitGatewayConnections: DeleteTransitGatewayConnectionWithContext returns %v with response %v", err, response)
				return err
			}

			err = tg.waitForTransitGatewayConnectionReady(*transitConnection.ID)
			if err != nil {
				log.Fatalf("deleteTransitGatewayConnections: waitForTransitGatewayConnectionReady returns %v", err)
				return err
			}
		}

		if transitConnectionCollections.First != nil {
			log.Debugf("findTransitGatewayConnections: First = %+v", *transitConnectionCollections.First)
		} else {
			log.Debugf("findTransitGatewayConnections: First = nil")
		}
		if transitConnectionCollections.Limit != nil {
			log.Debugf("findTransitGatewayConnections: Limit = %v", *transitConnectionCollections.Limit)
		}
		if transitConnectionCollections.Next != nil {
			start, err := transitConnectionCollections.GetNextStart()
			if err != nil {
				log.Debugf("findTransitGatewayConnections: err = %v", err)
				return fmt.Errorf("findTransitGatewayConnections: failed to GetNextStart: %w", err)
			}
			if start != nil {
				log.Debugf("findTransitGatewayConnections: start = %v", *start)
				listConnectionsOptions.SetStart(*start)
			}
		} else {
			log.Debugf("findTransitGatewayConnections: Next = nil")
			moreData = false
		}
	}

	return nil
}

func (tg *TransitGateway) waitForTransitGatewayConnectionReady(id string) error {

	var (
		ctx             context.Context
		cancel          context.CancelFunc
		getOptions      *transitgatewayapisv1.GetTransitGatewayConnectionOptions
		foundConnection *transitgatewayapisv1.TransitGatewayConnectionCust
		response        *core.DetailedResponse
		err             error
	)

	if tg.innerTg == nil {
		return fmt.Errorf("waitForTransitGatewayConnectionReady innerTg is nil")
	}

	ctx, cancel = contextWithTimeout()
	defer cancel()

	getOptions = tg.tgClient.NewGetTransitGatewayConnectionOptions(*tg.innerTg.ID, id)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		var err2 error

		foundConnection, response, err2 = tg.tgClient.GetTransitGatewayConnectionWithContext(ctx, getOptions)
		if err != nil {
			log.Fatalf("Error: Wait waitForTransitGatewayConnectionReady: response = %v, err = %v", response, err2)
			return false, err2
		}
		if foundConnection == nil {
			log.Debugf("waitForTransitGatewayConnectionReady: foundConnection is nil")
			return true, nil
		}
		log.Debugf("waitForTransitGatewayConnectionReady: Status = %s", *foundConnection.Status)
		switch *foundConnection.Status {
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Attached:
			return true, nil
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Deleting:
			return false, nil
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Pending:
			return false, nil
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Detached:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: detached status")
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Detaching:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: detaching status")
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Failed:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: failed status")
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Suspended:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: suspended status")
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Suspending:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: suspending status")
		default:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: unknown status: %s", *foundConnection.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}
