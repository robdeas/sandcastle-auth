# sandcastle-auth
Sandcastle-Auth
Sandcastle-Auth is an authentication server designed for demo, testing, and educational use. It is not intended to be used in full production environments. Instead, it shows how a Spring Boot–based JWT authentication solution might work and allows you to experiment, learn, and test in a safe sandbox. The project is dual-licensed under both the Apache License 2.0 and the MIT License, making it easy for users to pick whichever license suits their needs.

https://robd.tech/sandcastle-auth-authentication-for-testing-and-education/

# Overview
   • Purpose: Provide a simplified Spring Boot JWT authentication service to test user logins, domains, roles.
   1. Testing authentication flows.
   2. Educational demos of JWT with Spring Boot
   3. System test situations (e.g., debugging issues on Kubernetes with a simple auth server).


# Features:
   1. Basic username/password authentication
   2. Domain-based user segregation
   3. Simple role-based access control
   4. JWT token generation & validation
   5. H2 in-memory database support (for quick demos)
   Disclaimer: This server includes example configurations and minimal security controls. Do not deploy it as-is in production. By design it is not intended for production – more robust solutions already exist

    Basic Usage / Endpoints
# Sandcastle-Auth exposes a few REST endpoints:
## 1 POST /authenticate
Purpose: Validates user credentials, issues a JWT token.
Request Body (JSON):
json
CopyEdit
{
  "username": "testuser",
  "password": "testpass",
  "domain": "example.com"
}
Response:
    • 200 OK with a JSON body containing: 
      json
      CopyEdit
      {
        "token": "eyJhbGciOi..."
      }
    • 401 Unauthorized if credentials fail. 
## 2 GET /api/isUserValid
Purpose: Checks if the current user’s JWT is valid.
Headers:
    • Authorization: Bearer <jwt-token> 
Response (JSON):
json
CopyEdit
{
  "isValid": true,
  "username": "testuser",
  "message": "User is authenticated and valid.",
  "version": "1",
  "usernameFromToken": "testuser",
  "domain": "example.com",
  "role1": "ADMIN"
}
If missing/invalid token, returns an error field.
## 3 GET /api/isLocalAdmin
Purpose: Tests if the user is a local authentication domain admin.
Headers:
    • Authorization: Bearer <jwt-token> 
Response:
    • 200 OK if user is an admin in the specified domain. 
    • 403 Forbidden or 401 Unauthorized otherwise. 
## 4 Additional Endpoints
Depending on your config, you might also have:
    • /api/rest/users/**, /api/rest/roles/**, the Spring REST endponits and so on 

# Testing with cURL
Example: Authenticate and get a token
bash
CopyEdit
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass","domain":"example.com"}' \
  http://localhost:8080/authenticate
Response:
json
CopyEdit
{
  "token": "eyJhbGciOiJI..."
}
Use the token:
bash
CopyEdit
TOKEN=<paste JWT here>
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/isUserValid
Response:
json
CopyEdit
{
  "isValid": true,
  "username": "testuser",
  "message": "User is authenticated and valid.",
  ...
}

# Logging & Debugging
    • Logback is configured to log events to: 
        ◦ Console → All logs 
        ◦ application.log → General logs 
        ◦ app-security.log → Only logs with a security_message marker 
    • You can adjust logging levels in application.properties: 
      properties
      CopyEdit
      logging.level.tech.robd.jwt=DEBUG
    • For advanced filtering, see logback-spring.xml or logback.xml. 

#  JWT Insights
    • Sandcastle-Auth issues JWT tokens that include: 
        ◦ Subject = username 
        ◦ Claims = roles, domain 
        ◦ Expiration = based on jwt.token.validity 
    • Secret Key is loaded from config/jwt-key.txt. 
    • You can decode JWT tokens at jwt.io for debugging. 

# Purpose & Philosophy
This project exists to address 2 common problems: 
1. JWT authentication is conceptually simple but often poorly implemented. By providing a transparent implementation that can be run locally, debugged step by step, and configured on the fly, Sandcastle Auth helps developers truly understand how JWT authentication works.
2. Testing


# License
   Sandcastle-Auth is dual-licensed under:
   • Apache License 2.0
   • MIT License
   Users may choose either license (or whichever is more convenient) to govern their use of this code.
   
