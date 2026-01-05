/*
Copyright 2026 the Unikorn Authors.

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

package unit

import "k8s.io/apimachinery/pkg/api/resource"

// BytesToGB converts bytes to gigabytes (GB) using decimal conversion (1 GB = 1,000,000,000 bytes).
// If the value is not an exact multiple of 1,000,000,000, it rounds down to the nearest whole number.
func BytesToGB(value int64) int64 {
	return value / 1000000000
}

// GBToBytes converts gigabytes (GB) to bytes using decimal conversion (1 GB = 1,000,000,000 bytes).
func GBToBytes(value int64) int64 {
	return value * 1000000000
}

// BytesToGiB converts bytes to gibibytes (GiB) using binary conversion (1 GiB = 1,073,741,824 bytes).
// If the value is not an exact multiple of 1,073,741,824, it rounds down to the nearest whole number.
func BytesToGiB(value int64) int64 {
	return value >> 30
}

// GiBToBytes converts gibibytes (GiB) to bytes using binary conversion (1 GiB = 1,073,741,824 bytes).
func GiBToBytes(value int64) int64 {
	return value << 30
}

func ResourceQuantityGB(value int64) *resource.Quantity {
	return resource.NewQuantity(GBToBytes(value), resource.DecimalSI)
}

func ResourceQuantityGiB(value int64) *resource.Quantity {
	return resource.NewQuantity(GiBToBytes(value), resource.BinarySI)
}
