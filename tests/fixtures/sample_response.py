"""Sample response data for testing."""

SAMPLE_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <meta name="description" content="Test">
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <h1>Welcome</h1>
    <a href="/page1">Page 1</a>
    <a href="https://api.target.com/v1/users">API Link</a>
    <a href="http://192.168.1.1/admin">Internal Link</a>
    <a href="https://s3.amazonaws.com/mybucket">S3 Link</a>
    <script src="/js/app.js"></script>
    <script src="https://cdn.example.com/lib.js"></script>
    <form action="/login" method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
        <input name="redirect_url" type="hidden" value="https://evil.com">
        <input name="callback" type="hidden" value="http://169.254.169.254/latest/meta-data/">
    </form>
    <!-- TODO: Remove debug endpoint /api/debug -->
    <!-- Internal: http://10.0.0.1:8080 -->
</body>
</html>
"""

SAMPLE_JSON = """{
    "api_version": "v2",
    "endpoint": "https://api.internal.com/v1/users",
    "callback_url": "http://169.254.169.254/latest/meta-data/",
    "config": {
        "database_url": "postgresql://user:password@10.0.0.1:5432/db",
        "redis_host": "redis.internal:6379",
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    },
    "webhook": "https://hooks.internal.com/events",
    "image_url": "https://cdn.cloudfront.net/images/logo.png",
    "proxy": "http://proxy.internal:8080"
}
"""

SAMPLE_JS = """// Application bundle v2.1.0
const API_BASE = 'https://api.internal.com/v2';
const WS_URL = 'wss://ws.internal.com/socket';
const STORAGE = 'https://storage.googleapis.com/my-app-data';
const S3_BUCKET = 'https://my-bucket.s3.us-east-1.amazonaws.com';

const config = {
    endpoint: '/api/users/${userId}',
    adminUrl: 'http://admin.internal:3000',
    env: process.env.API_SECRET_KEY,
    featureFlags: {
        debug: true,
        newUI: false
    }
};

async function fetchUser(id) {
    const response = await fetch(`/api/v1/users/${id}`);
    return response.json();
}

// AWS credentials - DO NOT COMMIT
const AWS = {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
};
"""

SAMPLE_HEADERS = {
    "server": "nginx/1.24.0",
    "x-powered-by": "Express",
    "access-control-allow-origin": "*",
    "access-control-allow-credentials": "true",
    "content-security-policy": "default-src 'self' 'unsafe-inline' https://*.googleapis.com; connect-src *",
    "strict-transport-security": "max-age=31536000",
    "x-frame-options": "SAMEORIGIN",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "x-backend-server": "app-server-01.internal",
}

SAMPLE_URLS = [
    "https://example.com/page?redirect_url=https://evil.com",
    "https://example.com/api/fetch?url=http://169.254.169.254/latest/meta-data/",
    "https://example.com/image?img_url=https://internal.cdn.com/logo.png",
    "https://example.com/proxy?endpoint=http://10.0.0.1:9200/",
    "https://example.com/webhook?callback=https://attacker.com/hook",
    "https://example.com/normal?q=search&page=1",
]
