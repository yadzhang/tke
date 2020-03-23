/*
 * Tencent is pleased to support the open source community by making TKEStack
 * available.
 *
 * Copyright (C) 2012-2019 Tencent. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://opensource.org/licenses/Apache-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 */

// Code generated by informer-gen. DO NOT EDIT.

package internalversion

import (
	time "time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
	auth "tkestack.io/tke/api/auth"
	clientsetinternalversion "tkestack.io/tke/api/client/clientset/internalversion"
	internalinterfaces "tkestack.io/tke/api/client/informers/internalversion/internalinterfaces"
	internalversion "tkestack.io/tke/api/client/listers/auth/internalversion"
)

// ProjectPolicyInformer provides access to a shared informer and lister for
// ProjectPolicies.
type ProjectPolicyInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() internalversion.ProjectPolicyLister
}

type projectPolicyInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewProjectPolicyInformer constructs a new informer for ProjectPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewProjectPolicyInformer(client clientsetinternalversion.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredProjectPolicyInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredProjectPolicyInformer constructs a new informer for ProjectPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredProjectPolicyInformer(client clientsetinternalversion.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.Auth().ProjectPolicies().List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.Auth().ProjectPolicies().Watch(options)
			},
		},
		&auth.ProjectPolicy{},
		resyncPeriod,
		indexers,
	)
}

func (f *projectPolicyInformer) defaultInformer(client clientsetinternalversion.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredProjectPolicyInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *projectPolicyInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&auth.ProjectPolicy{}, f.defaultInformer)
}

func (f *projectPolicyInformer) Lister() internalversion.ProjectPolicyLister {
	return internalversion.NewProjectPolicyLister(f.Informer().GetIndexer())
}
