"""За замовчуванням усі /api-запити захищені; демонстрація Keycloak."""
import os
import jwt
from jwt import PyJWKClient
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

ISSUER = os.getenv('OIDC_ISSUER', 'http://localhost:8180/realms/biolims')
JWKS = os.getenv('OIDC_JWKS_URL', 'http://keycloak:8080/realms/biolims/protocol/openid-connect/certs')
AUDIENCE = 'biolims-api'
jwks_client = PyJWKClient(JWKS, timeout=5, cache_keys=True, lifespan=300)


def validate_access_token(token, required_scope):
    key = jwks_client.get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=['RS256'], audience=AUDIENCE, issuer=ISSUER,
                        options={'require': ['exp', 'iat', 'iss', 'aud', 'sub']})
    if claims.get('typ') != 'Bearer':
        raise jwt.InvalidTokenError('Access token required')
    if required_scope not in claims.get('scope', '').split():
        raise PermissionError('insufficient_scope')
    return claims


def protect(app, scope_for):
    @app.middleware('http')
    async def authorization(request: Request, call_next):
        # Доступні лише health endpoint і CORS preflight; документацію вимкнено.
        if request.url.path == '/health' or request.method == 'OPTIONS':
            return await call_next(request)
        required = scope_for(request)
        if not required:
            return JSONResponse({'detail': 'Forbidden'}, status_code=403)
        scheme, _, token = request.headers.get('authorization', '').partition(' ')
        if scheme.lower() != 'bearer' or not token.strip():
            return JSONResponse({'detail': 'Bearer token required'}, status_code=401,
                                headers={'WWW-Authenticate':'Bearer'})
        try:
            await run_in_threadpool(validate_access_token, token.strip(), required)
        except PermissionError:
            return JSONResponse({'detail': 'Insufficient scope', 'required_scope': required}, status_code=403,
                                headers={'WWW-Authenticate': f'Bearer error="insufficient_scope", scope="{required}"'})
        except jwt.PyJWKClientConnectionError:
            return JSONResponse({'detail': 'Identity provider unavailable'}, status_code=503)
        except Exception as exc:
            print('JWT validation error:', type(exc).__name__, flush=True)
            return JSONResponse({'detail': 'Invalid token or identity provider unavailable'}, status_code=401,
                                headers={'WWW-Authenticate':'Bearer error="invalid_token"'})
        return await call_next(request)
    # CORS має бути зовнішнім шаром, щоб включати заголовки і для помилок 401/403.
    app.add_middleware(CORSMiddleware,
        allow_origins=['https://cad.kpi.ua', 'http://localhost:8080'],
        allow_credentials=False, allow_methods=['GET','POST','OPTIONS'],
        allow_headers=['Authorization','Content-Type'])
