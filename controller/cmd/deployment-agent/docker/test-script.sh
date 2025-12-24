#!/bin/bash

# 运行部署代理
/usr/local/bin/deployment-agent \
    --deployment-id=$DEPLOYMENT_ID \
    --agent-code=$AGENT_CODE \
    --app-id=$APP_ID \
    --version=$VERSION \
    --controller-url=$CONTROLLER_URL \
    --minio-endpoint=$MINIO_ENDPOINT \
    --minio-access-key=$MINIO_ACCESS_KEY \
    --minio-secret-key=$MINIO_SECRET_KEY \
    --minio-bucket=$MINIO_BUCKET \
    --minio-object=$MINIO_OBJECT \
    --minio-use-ssl=$MINIO_USE_SSL