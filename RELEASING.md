# Publishing

Docker images publish through GitHub Actions.

## Docker Hub

Under **GitHub Settings → Secrets and variables → Actions**, add:

| Name | Kind | Value |
| --- | --- | --- |
| `DOCKERHUB_USERNAME` | Variable | Docker Hub login with push access |
| `DOCKERHUB_TOKEN` | Secret | Docker Hub token with write permission |
| `DOCKERHUB_IMAGE` | Optional variable | Default `cubesystems/persona-idp` |

Pushes and pull requests run formatting, lint, tests, `cargo audit` and a container build. Successful pushes publish amd64/arm64 images; pull requests do not publish.

| Git ref | Image tags |
| --- | --- |
| Branch `master` | `master` |
| Branch `feature/example` | `feature-example` |
| Tag `v1.0.1` | `v1.0.1` |

Only branch and Git tag names are published. Tags starting with `v` must match `version` in `Cargo.toml`.
