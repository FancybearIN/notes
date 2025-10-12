# GraphQL API vulnerabilities

/*GraphQL vulnerabilities generally arise due to implementation and design flaws.*/

GraphQL attacks usually take the form of malicious requests that can enable an attacker to obtain data or perform unauthorized actions. These attacks can have a severe impact, especially if the user is able to gain admin privileges by manipulating queries or executing a CSRF exploit. 

##  Finding GraphQL endpoints 

##Common endpoint names

GraphQL services often use similar endpoint suffixes. When testing for GraphQL endpoints, you should look to send universal queries to the following locations:

    /graphql
    /api
    /api/graphql
    /graphql/api
    /graphql/graphql
    /graphql/api/graphql
    /graphql/api/graphql/api
    /graphql/api/graphql/graphql

# Unique Graphql queris 





### What is a GraphQL schema?

In GraphQL, the schema represents a contract between the frontend and backend of the service. It defines the data available as a series of types, using a human-readable schema definition language. These types can then be implemented by a service.

Most of the types defined are object types. which define the objects available and the fields and arguments they have. Each field has its own type, which can either be another object or a scalar, enum, union, interface, or custom type. 

###  What are GraphQL queries?

GraphQL queries retrieve data from the data store. They are roughly equivalent to GET requests in a REST API.

Queries usually have the following key components:

    - A query operation type. This is technically optional but encouraged, as it explicitly tells the server that the incoming request is a query.
    - A query name. This can be anything you want. The query name is optional, but encouraged as it can help with debugging.
    - A data structure. This is the data that the query should return. 

###  What are GraphQL mutations?

Mutations change data in some way, either adding, deleting, or editing it. They are roughly equivalent to a REST API's POST, PUT, and DELETE methods.

Like queries, mutations have an operation type, name, and structure for the returned data. However, mutations always take an input of some type. This can be an inline value, but in practice is generally provided as a variable. 

## Aliases

Aliases enable you to bypass this restriction by explicitly naming the properties you want the API to return. You can use aliases to return multiple instances of the same type of object in one request. This helps to reduce the number of API calls neede

## Fragments

Fragments are reusable parts of queries or mutations. They contain a subset of the fields belonging to the associated type. 

## Subscriptions

Subscriptions are a special type of query. They enable clients to establish a long-lived connection with a server so that the server can then push real-time updates to the client without the need to continually poll for data. They are primarily useful for small changes to large objects and for functionality that requires small real-time updates (like chat systems or collaborative editing). 

## Introspection

Introspection is a built-in GraphQL function that enables you to query a server for information about the schema. It is commonly used by applications such as GraphQL IDEs and documentation generation tools. 

#### Article help you graphql

- https://blog.cybervelia.com/p/graphql-exploitation-all-you-need-to-know

- https://lucasconstantino.github.io/graphiql-online/?source=post_page-----72bb3dd22efa-------------------------------- # practical users case

-# Scenarios

[](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application#scenarios)

- **Reconnaissance**
    - Discovering GraphQL
    - Fingerprinting GraphQL
- **Denial of Service**
    - [Batch Query Attack](dossattack1)
    - Deep Recursion Query Attack
    - Resource Intensive Query Attack
    - Field Duplication Attack
    - Aliases based Attack
- **Information Disclosure**
    - GraphQL Introspection
    - GraphiQL Interface
    - GraphQL Field Suggestions
    - Server Side Request Forgery
    - Stack Trace Errors
- **Code Execution**
    - OS Command Injection #1
    - OS Command Injection #2
- **Injection**
    - Stored Cross Site Scripting
    - Log spoofing / Log Injection
    - HTML Injection
    - SQL Injection
- **Authorization Bypass**
    - GraphQL JWT Token Forge
    - GraphQL Interface Protection Bypass
    - GraphQL Query Deny List Bypass
- **Miscellaneous**
    - GraphQL Query Weak Password Protection
    - Arbitrary File Write // Path Traversal

