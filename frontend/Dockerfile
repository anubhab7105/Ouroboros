# =============================================================================
# MULEGUARD frontend
# -----------------------------------------------------------------------------
# Two stages: a Node build that produces static files, and an nginx image that
# serves them. The runtime image contains no Node, no npm and no source — only
# the built assets and a config file.
#
# The VITE_ variables are build args rather than runtime environment, because
# Vite inlines them into the bundle at build time. Changing one means
# rebuilding the image; there is no way around that short of shipping a runtime
# config file, and for an internal tool rebuilt from compose that is the
# simpler trade.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: build
# -----------------------------------------------------------------------------
FROM node:26-alpine AS build

# Fail the build on a lockfile that disagrees with package.json rather than
# quietly resolving something else.
ENV CI=true

WORKDIR /app

# Dependencies first, so a source change does not re-resolve the tree.
COPY package.json package-lock.json* ./

# `npm ci` requires a lockfile. Fall back to `npm install` so the image builds
# in a fresh checkout that has not been installed yet, and say which happened.
RUN if [ -f package-lock.json ]; then \
      echo "Installing from package-lock.json" && npm ci --no-audit --no-fund; \
    else \
      echo "No package-lock.json found; resolving with npm install" && \
      npm install --no-audit --no-fund; \
    fi

COPY . .

ARG NODE_ENV=production
ARG VITE_API_BASE_URL=/api/v1
ARG VITE_API_TIMEOUT_MS=30000
ARG VITE_APP_NAME=MuleGuard
ARG VITE_APP_VERSION=1.0.0
ARG VITE_ENVIRONMENT_LABEL="DOCKER SYNTHETIC DEMO"
ARG VITE_ENVIRONMENT=development
ARG VITE_SHOW_SYNTHETIC_BANNER=true
ARG VITE_SHOW_SCORE_DISCLAIMER=true
ARG VITE_SHOW_LIMITATIONS=true
ARG VITE_DEFAULT_CURRENCY=INR
ARG VITE_DEFAULT_LOCALE=en-IN
ARG VITE_TIMEZONE=UTC

ENV VITE_API_BASE_URL=$VITE_API_BASE_URL \
    VITE_API_TIMEOUT_MS=$VITE_API_TIMEOUT_MS \
    VITE_APP_NAME=$VITE_APP_NAME \
    VITE_APP_VERSION=$VITE_APP_VERSION \
    VITE_ENVIRONMENT_LABEL=$VITE_ENVIRONMENT_LABEL \
    VITE_ENVIRONMENT=$VITE_ENVIRONMENT \
    VITE_SHOW_SYNTHETIC_BANNER=$VITE_SHOW_SYNTHETIC_BANNER \
    VITE_SHOW_SCORE_DISCLAIMER=$VITE_SHOW_SCORE_DISCLAIMER \
    VITE_SHOW_LIMITATIONS=$VITE_SHOW_LIMITATIONS \
    VITE_DEFAULT_CURRENCY=$VITE_DEFAULT_CURRENCY \
    VITE_DEFAULT_LOCALE=$VITE_DEFAULT_LOCALE \
    VITE_TIMEZONE=$VITE_TIMEZONE

# Type-check and build. `npm run build` runs tsc first, so a type error fails
# the image rather than shipping a bundle that crashes in the browser.
RUN npm run build

# -----------------------------------------------------------------------------
# Stage 2: serve
# -----------------------------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

LABEL org.opencontainers.image.title="MuleGuard frontend" \
      org.opencontainers.image.description="Investigation interface for mule account detection. Synthetic data only." \
      org.opencontainers.image.licenses="MIT"

# nginx:alpine already ships a non-root `nginx` user and a config that writes
# its pid to /var/run. Nothing here needs to run as root.
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

# wget is used by the compose healthcheck and is already present in alpine.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=6 \
    CMD wget --spider -q http://127.0.0.1/ || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
