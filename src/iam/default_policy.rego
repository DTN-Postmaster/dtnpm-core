package dtn.ham.iam

import future.keywords.in

default allow = false

# 1. Open station mode ("none") allows all local/development traffic.
allow {
    input.context.auth_mode == "none"
}

# 2. Public authentication & capability discovery endpoints.
allow {
    input.request.interface == "http"
    input.request.path in [
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/capabilities",
        "/api/v1/capabilities",
    ]
}

# Static frontend assets (SPA shell, PWA manifest, icons) are readable so login UI can render.
allow {
    input.request.interface == "http"
    input.request.method in ["GET", "HEAD"]
    not startswith(input.request.path, "/api/")
}

# 3. Admin role: full access across HTTP and gRPC interfaces.
allow {
    input.user.authenticated == true
    "Admin" in input.user.roles
}

# 4. Operator role: read-only visibility across HTTP APIs + operational messaging/bundles.
allow {
    input.user.authenticated == true
    "Operator" in input.user.roles
    input.request.interface == "http"
    input.request.method in ["GET", "HEAD"]
}

allow {
    input.user.authenticated == true
    "Operator" in input.user.roles
    input.request.interface == "http"
    input.request.method == "POST"
    operator_allowed_post(input.request.path)
}

operator_allowed_post(path) {
    path in [
        "/api/v1/bundles",
        "/api/v1/bundles/inject",
        "/api/v1/chat/messages",
        "/api/v1/files/upload",
        "/api/chat/v1/messages",
        "/api/chat/v1/conversations",
        "/api/chat/v1/read",
        "/api/files/v1/upload",
    ]
}

operator_allowed_post(path) {
    startswith(path, "/api/chat/v1/conversations/")
}

operator_allowed_post(path) {
    startswith(path, "/api/chat/v1/messages/")
}

operator_allowed_post(path) {
    startswith(path, "/api/files/v1/")
    endswith(path, "/read")
}

operator_allowed_post(path) {
    startswith(path, "/api/files/v1/")
    endswith(path, "/sticky")
}

# 5. Operator role: operational gRPC actions (applications/services/bundles); CLA control stays Admin-only.
allow {
    input.user.authenticated == true
    "Operator" in input.user.roles
    input.request.interface == "grpc"
    input.request.action in [
        "grpc:service:register",
        "grpc:application:register",
        "grpc:bundle:inject",
        "grpc:bundle:receive",
        "grpc:routing:register",
    ]
}
