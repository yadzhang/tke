/*
 * Tencent is pleased to support the open source community by making TKEStack
 * available.
 *
 * Copyright (C) 2012-2019 Tencent. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://opensource.org/licenses/Apache-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS, WITHOUT
 * WARRANTIES OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 */

package storage

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"tkestack.io/tke/pkg/apiserver/filter"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	"tkestack.io/tke/api/auth"
	authinternalclient "tkestack.io/tke/api/client/clientset/internalversion/typed/auth/internalversion"
	"tkestack.io/tke/pkg/auth/util"
	"tkestack.io/tke/pkg/util/log"
)

// BindingREST implements the REST endpoint.
type BindingREST struct {
	authClient authinternalclient.AuthInterface
}

var _ = rest.Creater(&BindingREST{})

// New returns an empty object that can be used with Create after request data
// has been put into it.
func (r *BindingREST) New() runtime.Object {
	return &auth.ProjectPolicy{}
}

func (r *BindingREST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	requestInfo, ok := request.RequestInfoFrom(ctx)
	if !ok {
		return nil, errors.NewBadRequest("unable to get request info from context")
	}

	bind := obj.(*auth.ProjectPolicy)
	if bind.Spec.PolicyID == "" {
		return nil, errors.NewBadRequest("must specify policyID")
	}

	policy, err := r.authClient.Policies().Get(bind.Spec.PolicyID, metav1.GetOptions{})
	if err != nil {
		log.Error("get policy failed", log.String("policy", bind.Spec.PolicyID), log.Err(err))
		return nil, err
	}

	if policy.Spec.Scope != auth.PolicyProject {
		return nil, errors.NewBadRequest("unable bind subject to platform-scoped policy in project")
	}

	projectID := filter.ProjectIDFrom(ctx)
	if projectID == "" {
		projectID = requestInfo.Name
	}
	
	projectPolicy, err := r.authClient.ProjectPolicies().Get(util.ProjectPolicyName(projectID, policy.Name), metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		// if projectPolicy not exist, create a new one
		projectPolicy, err = r.authClient.ProjectPolicies().Create(&auth.ProjectPolicy{
			Spec: auth.ProjectPolicySpec{
				TenantID:  policy.Spec.TenantID,
				ProjectID: projectID,
				PolicyID:  policy.Name,
			},
		})
		if err != nil {
			if apierrors.IsAlreadyExists(err) {
				projectPolicy, err = r.authClient.ProjectPolicies().Get(util.ProjectPolicyName(projectID, policy.Name), metav1.GetOptions{})
			}
		}
	}

	if err != nil {
		return nil, err
	}

	for _, sub := range bind.Spec.Users {
		if !util.InSubjects(sub, projectPolicy.Spec.Users) {
			projectPolicy.Spec.Users = append(projectPolicy.Spec.Users, sub)
		}
	}

	for _, sub := range bind.Spec.Groups {
		if !util.InSubjects(sub, projectPolicy.Spec.Groups) {
			sub.Name = ""
			projectPolicy.Spec.Groups = append(projectPolicy.Spec.Groups, sub)
		}
	}

	log.Info("bind project policy subjects", log.String("policy", policy.Name), log.Any("users", projectPolicy.Spec.Users), log.Any("groups", projectPolicy.Spec.Groups))
	return r.authClient.ProjectPolicies().Update(projectPolicy)
}
