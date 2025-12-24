使用方法
在使用 Minio Uploader 之前，请确保设置了以下环境变量：
MINIO_ACCESS_KEY: Minio 访问密钥 ID
MINIO_SECRET_KEY: Minio 秘密访问密钥
然后，您可以使用以下命令运行 Minio Uploader：


minio-uploader -endpoint=<minio-server-url> -bucket=<bucket-name> -file=<path-to-local-file> [-prefix=<object-prefix>] [-use-ssl]

参数说明
-endpoint: Minio 服务器地址（默认为 "localhost:9000"）
-use-ssl: 使用 SSL 连接（默认为 false）
-bucket: Minio bucket 名称（必需）
-prefix: 对象名称前缀（可选）
-file: 要上传的本地文件路径（必需）

示例
上传文件 example.txt 到 my-bucket bucket，对象前缀为 uploads/：
export MINIO_ACCESS_KEY=your-access-key
export MINIO_SECRET_KEY=your-secret-key
minio-uploader -endpoint=play.min.io -bucket=my-bucket -file=./example.txt -prefix=uploads/ -use-ssl
