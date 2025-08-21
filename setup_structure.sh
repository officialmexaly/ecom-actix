#!/bin/bash

# Base directory
BASE_DIR="src"

# Create base directory
mkdir -p $BASE_DIR

# Create root files
touch $BASE_DIR/main.rs
touch $BASE_DIR/lib.rs

# RBAC
mkdir -p $BASE_DIR/rbac
touch $BASE_DIR/rbac/{mod.rs,engine.rs,role.rs,permission.rs,delegation.rs,session.rs,policy.rs}

# ABAC
mkdir -p $BASE_DIR/abac
touch $BASE_DIR/abac/{mod.rs,attribute.rs,policy.rs,condition.rs}

# Hybrid
mkdir -p $BASE_DIR/hybrid
touch $BASE_DIR/hybrid/{mod.rs,engine.rs,policy.rs}

# Middleware
mkdir -p $BASE_DIR/middleware
touch $BASE_DIR/middleware/{mod.rs,access.rs,context.rs}

# Types
mkdir -p $BASE_DIR/types
touch $BASE_DIR/types/{mod.rs,common.rs,time.rs}

# Handlers
mkdir -p $BASE_DIR/handlers
touch $BASE_DIR/handlers/{mod.rs,user.rs,document.rs,health.rs}

echo "✅ Folder structure created successfully."
