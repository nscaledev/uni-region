/*
Copyright 2026 Nscale.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package handlertest provides helpers for handler unit tests.
package handlertest

import (
	"context"
	"reflect"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// StaleRead wraps cli so the first Get of one of the stale objects returns
// that copy. This models a write landing right after a guard's read: that one
// read sees the pre-write copy, so a write derived from it carries a stale
// resource version, while every later read and every write goes to cli. The
// retry after the conflict therefore sees the current state, as a direct read
// would.
func StaleRead(cli client.WithWatch, stale ...client.Object) client.WithWatch {
	byKey := map[client.ObjectKey]client.Object{}
	served := map[client.ObjectKey]bool{}

	for _, object := range stale {
		copied, _ := object.DeepCopyObject().(client.Object)
		byKey[client.ObjectKeyFromObject(object)] = copied
	}

	return interceptor.NewClient(cli, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			object, ok := byKey[key]
			if !ok || served[key] || reflect.TypeOf(object) != reflect.TypeOf(obj) {
				return c.Get(ctx, key, obj, opts...)
			}

			served[key] = true

			reflect.ValueOf(obj).Elem().Set(reflect.ValueOf(object.DeepCopyObject()).Elem())

			return nil
		},
	})
}
