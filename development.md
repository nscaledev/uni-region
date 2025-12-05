# Development
This aims to serve as a resource for all things regarding developing locally and contributing pull requests.

Disclaimer: Contributions are only allowed from `nscaledev` organization members. 

## Linters
To ensure code quality throughout the `nscaledev` organization we have configured various linters, [shown here](https://github.com/nscaledev/uni-region/blob/main/.golangci.yam).

### GCI Sections
For "GCI" all imports in a Go file must be in a [particular order](https://golangci-lint.run/docs/formatters/configuration/#gci):
- Standard (contains all imports from the standard library)
- Default (contains all imports that could not be matched to another section)
- Prefix (github.com/unikorn-cloud)
- Prefix (k8s.io)
- Prefix (sigs.k8s.io)

### TestPackage
The [maratori testpackage](https://github.com/maratori/testpackage) focuses on "black box testing", or testing primarily 
exported functionality. This means all test files must be in a package that 
has "*_test" appended to it. For example:
```
package store_test
```

If testing exported functionality is necessary for the contribution, then
adding the following above the imports section will allow bypassing this.
```
//nolint:testpackage
```