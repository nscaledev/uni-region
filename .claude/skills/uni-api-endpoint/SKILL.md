---
name: uni-api-endpoint
description: Add an API endpoint to UNI, with supporting handler and client code
version: 0.1
author: Michael Bridgen
allowed-tools: Read, Write, Edit, Bash(go test:*), Bash(golangci-lint:*), Bash(cat:*), Bash(make:*)
---

# UNI API endpoint generator

Add an endpoint to the OpenAPI schema and add supporting code, like a handler.

## Workflow

### Design the API endpoint

Look at pkg/openapi/server.spec.yaml to see the existing API endpoints.

Suggest a shape for the API as requested, giving a rationale for the
path and parameters.

- take note that v1 APIs tend to be scoped in the path, while v2 APIs
  will have the scope (organization, project) in the request body

- follow the usual HTTP API conventions: POST is for creating new
  objects, PUT is for updating an object

- use existing schemas, either in the server.spec.yaml file or as
  referenced by analogous endpoints.

Once the API endpoint is settled, record it in the OpenAPI spec file
and generate the types, router and client from it:

    make -W pkg/openapi/server.spec.yaml

If it doesn't compile you may need to adjust the spec until it does.

Running `make validate` will check the schema matches internal
standards, too.

### Add a stub handler

Adding an endpoint to the specification will generate an extra method
for the handler. Add a stub for this method, so that everything
compiles.

 - if you run `make`, the compiler error will tell you the missing
   method.

 - the method should go on an appropriate handler struct. There are
   separate handlers for some things like images and servers, and for
   v1 and v2 endpoints, for example.
   
 - If there is not an appropriate handler, create one with the minimal
   fields needed (possibly none), and make sure it's added to the
   Handler struct and initialized.

 - the stub method can write an error to the response and exit.

Pause to describe what's been done and suggest the next steps.

### Add a client for handler logic

In UNI the handler method unpacks and validates a request, then uses a
client (subpackages of pkg/handler) to actuate it.

The clients can come in two flavours:

 - ones that query, create or update Kubernetes objects, which a
   controller will then deal with;
 - in uni-region, clients that deal directly with the region provider
   (OpenStack) as a source of truth. For example, the image APIs deal
   with the region provider.

It may be possible to implement the handler in terms of existing
client methods. If not, evaluate whether a new client is needed.

### Write tests then make them pass

Now write a test that constructs a handler of the appropriate type,
and calls the handler method with an appropriate response. There are
examples in pkg/handler/*_test.go files.

You may need to inject dependencies, specifically a Kubernetes client
(you can use fakeclient), or a region provider (mock the interface
needed, like pkg/handler/server/mock does).
