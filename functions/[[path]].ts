/**
 * B2 Proxy for Cloudflare Pages (S3 Compatible + Verification)
 * 
 * S3 兼容代理服务
 * - 验证客户端 S3 签名 (确保只有授权用户能操作)
 * - 代理请求到 B2 (使用 Worker 凭证重新签名)
 * - 智能缓存 (遵循源站 Cache-Control)
 */

interface Env {
    B2_BUCKET_NAME: string;
    B2_ENDPOINT: string;
    B2_ACCESS_KEY_ID: string;
    B2_SECRET_ACCESS_KEY: string;
}

// --- Crypto Helpers ---

async function sha256Hex(message: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function hmac(key: BufferSource, message: string): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    return crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message));
}

async function hmacHex(key: BufferSource, message: string): Promise<string> {
    const result = await hmac(key, message);
    return Array.from(new Uint8Array(result))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function getSignatureKey(
    secretKey: string,
    dateStamp: string,
    region: string,
    service: string
): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    const kDate = await hmac(encoder.encode('AWS4' + secretKey), dateStamp);
    const kRegion = await hmac(kDate, region);
    const kService = await hmac(kRegion, service);
    return hmac(kService, 'aws4_request');
}

// --- Verification Logic ---

interface AuthData {
    algorithm: string;
    credential: string;
    signedHeaders: string[];
    signature: string;
    accessKeyId: string;
    dateStamp: string;
    region: string;
    service: string;
}

function parseAuthHeader(auth: string): AuthData | null {
    try {
        const spaceIndex = auth.indexOf(' ');
        if (spaceIndex === -1) return null;

        const algorithm = auth.slice(0, spaceIndex);
        const params = auth.slice(spaceIndex + 1);

        // Handle 'Credential=..., SignedHeaders=..., Signature=...'
        const parts: Record<string, string> = {};
        params.split(',').forEach(part => {
            const [key, value] = part.trim().split('=');
            parts[key] = value;
        });

        const credentialParts = parts['Credential'].split('/');

        return {
            algorithm,
            credential: parts['Credential'],
            signedHeaders: parts['SignedHeaders'].split(';'),
            signature: parts['Signature'],
            accessKeyId: credentialParts[0],
            dateStamp: credentialParts[1],
            region: credentialParts[2],
            service: credentialParts[3]
        };
    } catch (e) {
        return null;
    }
}

interface VerifyResult {
    isValid: boolean;
    debugInfo?: any;
}

async function verifyRequest(request: Request, env: Env): Promise<VerifyResult> {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader) return { isValid: false, debugInfo: 'No Authorization header' };

    const authData = parseAuthHeader(authHeader);
    if (!authData) return { isValid: false, debugInfo: 'Failed to parse Auth header' };

    if (authData.accessKeyId !== env.B2_ACCESS_KEY_ID) {
        return { isValid: false, debugInfo: `AccessKey mismatch. Expected: ${env.B2_ACCESS_KEY_ID}, Got: ${authData.accessKeyId}` };
    }

    const url = new URL(request.url);

    const canonicalHeadersList = authData.signedHeaders.map(key => {
        // Headers must be trimmed and lowercased
        const value = request.headers.get(key) || '';
        return `${key}:${value.trim().replace(/\s+/g, ' ')}`;
    });
    const canonicalHeaders = canonicalHeadersList.join('\n') + '\n';

    const signedHeadersString = authData.signedHeaders.join(';');

    const payloadHash = request.headers.get('x-amz-content-sha256') || 'UNSIGNED-PAYLOAD';

    const canonicalQueryString = Array.from(url.searchParams.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&');

    // S3 Canonical URI requires strict encoding
    // request.url path is usually decoded. We need to re-encode it cautiously.
    // AWS Signature V4 requires all characters to be encoded except unreserved: A-Z a-z 0-9 - . _ ~
    // And forward slashes '/' should not be encoded (if they are path separators).

    const path = url.pathname;
    const canonicalUri = path.split('/').map(segment =>
        encodeURIComponent(decodeURIComponent(segment)).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())
    ).join('/');

    const canonicalRequest = [
        request.method.toUpperCase(),
        canonicalUri,
        canonicalQueryString,
        canonicalHeaders,
        signedHeadersString,
        payloadHash
    ].join('\n');

    const amzDate = request.headers.get('x-amz-date') || '';
    if (!amzDate) return { isValid: false, debugInfo: 'Missing x-amz-date' };

    const credentialScope = `${authData.dateStamp}/${authData.region}/${authData.service}/aws4_request`;

    const canonicalRequestHash = await sha256Hex(canonicalRequest);
    const stringToSign = [
        'AWS4-HMAC-SHA256',
        amzDate,
        credentialScope,
        canonicalRequestHash
    ].join('\n');

    const signingKey = await getSignatureKey(
        env.B2_SECRET_ACCESS_KEY,
        authData.dateStamp,
        authData.region,
        authData.service
    );

    const calculatedSignature = await hmacHex(signingKey, stringToSign);

    const isValid = calculatedSignature === authData.signature;

    return {
        isValid,
        debugInfo: isValid ? null : {
            message: 'Signature mismatch',
            clientSignature: authData.signature,
            calculatedSignature,
            stringToSign,
            canonicalRequest,
            canonicalHeaders,
            credentialScope
        }
    };
}

// --- Outgoing Signing Logic ---

async function signRequest(
    method: string,
    url: URL,
    headers: Headers,
    contentHash: string,
    accessKeyId: string,
    secretAccessKey: string,
    region: string = 'auto'
): Promise<Headers> {
    const service = 's3';
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);

    // Set necessary headers
    headers.set('x-amz-date', amzDate);
    headers.set('host', url.host);
    headers.set('x-amz-content-sha256', contentHash);

    const signedHeadersList = Array.from(headers.keys())
        .filter(k => k.startsWith('x-amz-') || k === 'host' || k === 'content-type')
        .sort();
    const signedHeaders = signedHeadersList.join(';');

    const canonicalHeaders = signedHeadersList
        .map(k => `${k}:${headers.get(k)?.trim()}`)
        .join('\n') + '\n';

    const canonicalQueryString = Array.from(url.searchParams.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join('&');

    const canonicalRequest = [
        method,
        url.pathname,
        canonicalQueryString,
        canonicalHeaders,
        signedHeaders,
        contentHash
    ].join('\n');

    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    const canonicalRequestHash = await sha256Hex(canonicalRequest);
    const stringToSign = [
        'AWS4-HMAC-SHA256',
        amzDate,
        credentialScope,
        canonicalRequestHash
    ].join('\n');

    const signingKey = await getSignatureKey(secretAccessKey, dateStamp, region, service);
    const signature = await hmacHex(signingKey, stringToSign);

    const authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    headers.set('Authorization', authorization);

    return headers;
}

// --- Main Handler ---

export const onRequest: PagesFunction<Env> = async (context) => {
    const { request, env } = context;
    const url = new URL(request.url);

    if (!env.B2_BUCKET_NAME || !env.B2_ENDPOINT || !env.B2_ACCESS_KEY_ID || !env.B2_SECRET_ACCESS_KEY) {
        return new Response(JSON.stringify({ error: 'Missing configuration' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    const method = request.method.toUpperCase();

    // 1. Verify Inbound Request
    const hasAuth = request.headers.has('Authorization');
    const isWrite = ['PUT', 'POST', 'DELETE'].includes(method);

    if (isWrite && !hasAuth) {
        return new Response(JSON.stringify({ error: 'Authentication required' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', 'WWW-Authenticate': 'AWS4-HMAC-SHA256' }
        });
    }

    if (hasAuth) {
        const { isValid, debugInfo } = await verifyRequest(request, env);
        if (!isValid) {
            return new Response(JSON.stringify({
                error: 'SignatureDoesNotMatch',
                detail: 'The request signature we calculated does not match the signature you provided. Check your key and signing method.',
                debug: debugInfo
            }, null, 2), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    // 2. Prepare Outbound Request
    const b2Url = new URL(`https://${env.B2_ENDPOINT}/${env.B2_BUCKET_NAME}${url.pathname}`);
    url.searchParams.forEach((value, key) => {
        b2Url.searchParams.set(key, value);
    });

    const headers = new Headers();
    const allowedHeaders = ['content-type', 'content-length', 'content-disposition', 'cache-control', 'range', 'if-match', 'if-none-match', 'if-modified-since', 'if-unmodified-since'];
    for (const [key, value] of request.headers) {
        if (allowedHeaders.includes(key.toLowerCase()) || key.toLowerCase().startsWith('x-amz-')) {
            headers.set(key, value);
        }
    }

    // 3. Sign Outbound Request
    let contentHash = 'UNSIGNED-PAYLOAD';
    if (method === 'GET' || method === 'HEAD') {
        contentHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    } else if (request.headers.has('x-amz-content-sha256')) {
        contentHash = 'UNSIGNED-PAYLOAD';
    }

    await signRequest(
        method,
        b2Url,
        headers,
        contentHash,
        env.B2_ACCESS_KEY_ID,
        env.B2_SECRET_ACCESS_KEY
    );

    // 4. Fetch
    const fetchOptions: RequestInit & { cf?: any } = {
        method,
        headers,
        body: (method === 'GET' || method === 'HEAD') ? null : request.body,
    };

    if (method === 'GET' || method === 'HEAD') {
        fetchOptions.cf = {
            cacheEverything: true
        };
    }

    const b2Response = await fetch(b2Url.toString(), fetchOptions);

    const responseHeaders = new Headers(b2Response.headers);
    responseHeaders.set('X-Proxy', 'b2-pages-verified');
    responseHeaders.delete('x-amz-request-id');
    responseHeaders.delete('x-amz-id-2');

    return new Response(b2Response.body, {
        status: b2Response.status,
        statusText: b2Response.statusText,
        headers: responseHeaders
    });
};
