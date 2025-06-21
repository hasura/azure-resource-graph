#!/bin/bash

# Simple script to get Azure environment variables

TARGET_SUBSCRIPTION="49f7baee-e718-431b-9572-30c1af2cc09e"

# Set subscription
az account set --subscription "$TARGET_SUBSCRIPTION"

# Get tenant and subscription info
TENANT_ID=$(az account show --query tenantId -o tsv)
SUBSCRIPTION_ID=$(az account show --query id -o tsv)

# Create service principal and get credentials
SP_OUTPUT=$(az ad sp create-for-rbac \
    --name "ResourceGraphReader-$(date +%s)" \
    --role "Reader" \
    --scopes "/subscriptions/$SUBSCRIPTION_ID" \
    --output json)

CLIENT_ID=$(echo "$SP_OUTPUT" | jq -r '.appId')
CLIENT_SECRET=$(echo "$SP_OUTPUT" | jq -r '.password')

# Print the 4 environment variables
echo "AZURE_TENANT_ID=$TENANT_ID"
echo "AZURE_CLIENT_ID=$CLIENT_ID"
echo "AZURE_CLIENT_SECRET=$CLIENT_SECRET"
echo "AZURE_SUBSCRIPTION_IDS=$SUBSCRIPTION_ID"
