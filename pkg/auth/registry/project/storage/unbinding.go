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

	"tkestack.io/tke/pkg/apiserver/filter"

	"tkestack.io/tke/pkg/auth/util"

	"tkestack.io/tke/pkg/util/log"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	"tkestack.io/tke/api/auth"
	authinternalclient "tkestack.io/tke/api/client/clientset/internalversion/typed/auth/internalversion"
)

// UnBindingREST implements the REST endpoint.
type UnBindingREST struct {
	authClient authinternalclient.AuthInterface
}

var _ = rest.Creater(&UnBindingREST{})

// New returns an empty object that can be used with Create after request data
// has been put into it.
func (r *UnBindingREST) New() runtime.Object {
	return &auth.ProjectPolicy{}
}

func (r *UnBindingREST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
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

	projectPolicyBinding, err := r.authClient.ProjectPolicies().Get(util.ProjectPolicyName(projectID, policy.Name), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	remainedUsers := make([]auth.Subject, 0)
	for _, sub := range projectPolicyBinding.Spec.Users {
		if !util.InSubjects(sub, bind.Spec.Users) {
			remainedUsers = append(remainedUsers, sub)
		}
	}

	projectPolicyBinding.Spec.Users = remainedUsers
	remainedGroups := make([]auth.Subject, 0)
	for _, sub := range projectPolicyBinding.Spec.Groups {
		if !util.InSubjects(sub, bind.Spec.Groups) {
			remainedGroups = append(remainedGroups, sub)
		}
	}

	projectPolicyBinding.Spec.Groups = remainedGroups
	log.Info("unbind policy subjects", log.String("policy", projectPolicyBinding.Name), log.Any("users", projectPolicyBinding.Spec.Users), log.Any("groups", projectPolicyBinding.Spec.Groups))
	return r.authClient.ProjectPolicies().Update(projectPolicyBinding)
}

