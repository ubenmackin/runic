# Runic API Documentation

This directory contains the OpenAPI 3.0 specification for the Runic firewall management API.

## OpenAPI Specification

The API is documented in `openapi.yaml` using the OpenAPI 3.0 specification format.

### Quick Start

1. **View the spec**: Open `openapi.yaml` in any text editor or IDE with YAML support.

2. **Validate the spec**: Use the Swagger CLI validator:
   ```bash
   npm install -g swagger-cli
   swagger-cli validate openapi.yaml
   ```

3. **Generate client code**: Use OpenAPI Generator:
   ```bash
   # Go client
   openapi-generator generate -i openapi.yaml -g go -o ./generated/go-client
   
   # TypeScript client
   openapi-generator generate -i openapi.yaml -g typescript-axios -o ./generated/typescript-client
   
   # Python client
   openapi-generator generate -i openapi.yaml -g python -o ./generated/python-client
   ```

## Using Swagger UI

### Option 1: Online Editor (Easiest)

1. Go to [Swagger Editor](https://editor.swagger.io/)
2. Click "File" > "Import URL"
3. Enter: `https://raw.githubusercontent.com/your-repo/main/docs/api/openapi.yaml`
4. View and test endpoints interactively

### Option 2: Local Development Server

1. Install Node.js dependencies:
   ```bash
   cd docs/api
   npm init -y
   npm install swagger-ui-dist
   ```

2. Create an `index.html` file:
   ```html
   <!DOCTYPE html>
   <html>
   <head>
       <title>Runic API</title>
       <link rel="stylesheet" type="text/css" href="node_modules/swagger-ui-dist/swagger-ui.css" />
   </head>
   <body>
       <div id="swagger-ui"></div>
       <script src="node_modules/swagger-ui-dist/swagger-ui-bundle.js"></script>
       <script>
           SwaggerUI({
               url: "openapi.yaml",
               dom_id: "#swagger-ui"
           });
       </script>
   </body>
   </html>
   ```

3. Serve the files:
   ```bash
   npx http-server .
   ```

4. Open `http://localhost:8080` in your browser.

### Option 3: Docker

```bash
docker run -p 8080:8080 -v $(pwd):/usr/share/nginx/html nginx
# Create a simple HTML file that loads Swagger UI with openapi.yaml
```

## API Overview

### Authentication

Most endpoints require Bearer token authentication. Include the token in the Authorization header:

```http
Authorization: Bearer <your-token>
```

The auth endpoints (`/auth/login`, `/auth/logout`, `/auth/verify`) do not require authentication.

### Base URL

- Development: `http://localhost:8080/api/v1`
- Production: `/api/v1` (relative path)

### Endpoints Summary

| Category | Endpoints |
|----------|-----------|
| **Peers** | List, Create, Get, Update, Delete, Get Bundle, Compile, Rotate Key |
| **Groups** | List, Create, Get, Update, Delete, List Members, Add Member, Remove Member |
| **Services** | List, Create, Get, Update, Delete |
| **Policies** | List, Create, Get, Update, Delete, Push All |
| **Auth** | Login, Logout, Verify |
| **Dashboard** | Stats, Logs, Pending Changes, Approve/Reject |

### Error Responses

All endpoints may return error responses:

```json
{
  "error": "error message"
}
```

Common HTTP status codes:
- `400`: Bad Request - Invalid input
- `401`: Unauthorized - Missing or invalid token
- `403`: Forbidden - Insufficient permissions
- `404`: Not Found - Resource not found
- `409`: Conflict - Resource in use
- `500`: Internal Server Error

## Code Generation Examples

### Go Client

```bash
# Install OpenAPI Generator
brew install openapi-generator

# Generate Go client
openapi-generator generate \
  -i openapi.yaml \
  -g go \
  -o ./client/go \
  --additional-properties=packageName=runic

# Use in your Go code
import runic "github.com/your-org/runic/client/go"
```

### TypeScript/JavaScript

```bash
# Using openapi-generator
openapi-generator generate \
  -i openapi.yaml \
  -g typescript-axios \
  -o ./client/typescript
```

### Python

```bash
openapi-generator generate \
  -i openapi.yaml \
  -g python \
  -o ./client/python
```

## Tools & Resources

- [Swagger Editor](https://editor.swagger.io/) - Online OpenAPI editor
- [OpenAPI Generator](https://openapi-generator.tech/) - Code generation CLI
- [Postman](https://www.postman.com/) - API testing with OpenAPI import
- [Insomnia](https://insomnia.rest/) - API client with OpenAPI support

## License

MIT