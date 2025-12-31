# B2 Pages Proxy (S3 Compatible)

这是一个基于 Cloudflare Pages (Workers) 的高性能反向代理，用于将 Backblaze B2 存储桶暴露为标准的 S3 兼容 API。

**特点**:
- 🚀 **免费带宽**: 利用 Cloudflare 与 Backblaze 的 Bandwidth Alliance，实现零出口流量费用。
- 🔐 **安全写入**: 实现了完整的 AWS S3 Signature V4 验证。只有持有正确密钥的客户端才能进行 PUT/DELETE 操作。
- ⚡ **智能缓存**: 自动遵循 B2 源站返回的 `Cache-Control` 头，实现 CDN 级缓存。
- 📂 **S3 兼容**: 支持标准 S3 客户端（如 AWS CLI, Rclone, Cyberduck）直接连接。
- 📦 **流式上传**: 支持大文件流式上传（使用 `UNSIGNED-PAYLOAD` 模式转发）。

## 架构

`Client` -> `Cloudflare Pages (Worker)` -> `Backblaze B2`

1. **读取 (GET)**: Worker 检查签名（可选），如果没有签名且文件公开，则直接通过 CDN 返回文件。
2. **写入 (PUT/DELETE)**: Worker **强制验证** 客户端的 S3 签名。验证通过后，Worker 使用内部凭证重新签名并转发给 B2。

## 部署教程

### 1. 准备工作
- 一个 Backblaze B2 存储桶 (Bucket)。
- 获取 B2 的 `Application Key ID` 和 `Application Key`。
- 获取 B2 的 S3 Endpoint (例如 `s3.us-west-004.backblazeb2.com`)。

### 2. 部署到 Cloudflare Pages
1. Fork 或 Clone 本仓库。
2. 在 Cloudflare Dashboard 中创建新的 Pages 项目，连接你的 Git 仓库。
3. **构建设置**:
   - Framework preset: `None`
   - Build command: `npm run build` (或者留空，我们主要部署 Functions)
   - Output directory: `public` (仓库里包含一个空的 public 目录即可，或者让构建脚本生成)
4. **环境变量 (必须)**:
   在 Pages 项目设置 > Environment variables 中添加:
   - `B2_BUCKET_NAME`: 你的 B2 桶名称
   - `B2_ENDPOINT`: 你的 B2 S3 Endpoint
   - `B2_ACCESS_KEY_ID`: 你的 B2 Key ID
   - `B2_SECRET_ACCESS_KEY`: 你的 B2 Secret Key

### 3. 本地开发 (可选)
```bash
npm install
npm run dev
```

## 客户端配置

### Rclone
```ini
[b2-pages]
type = s3
provider = Other
env_auth = false
access_key_id = <你的 B2_ACCESS_KEY_ID>
secret_access_key = <你的 B2_SECRET_ACCESS_KEY>
endpoint = https://your-project.pages.dev
acl = private
```

### AWS CLI
```bash
aws s3 cp test.jpg s3://<bucket-name>/test.jpg --endpoint-url https://your-project.pages.dev
```

## 注意事项
- 本项目设计为 **单租户** 模式。Worker 验证签名时使用的是环境变量中的同一套密钥。
- 请确保 B2 桶的权限设置正确（通常设为 Private，由 Worker 控制访问）。

## License
MIT
