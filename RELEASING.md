# Releasing

Releases are created only from reviewed commits merged to `main`. Never tag an open pull-request branch or an intermediate branch in a stacked change.

## Prepare

1. Merge the complete pull-request stack in dependency order.
2. Pull `main`, confirm the worktree is clean, and verify that the intended release commit is the remote `main` head.
3. Run `make ci` and `make smoke` from that exact commit.
4. Replace `Unreleased` in `CHANGELOG.md` with the UTC release date and commit that change through review.

## Publish

Create and push one annotated semantic-version tag from the verified `main` commit:

```bash
git tag -a v0.2.0 -m "Synthient MCP v0.2.0"
git push origin v0.2.0
```

The `Publish release` workflow validates the tag, scans for secrets, repeats the full Go and container checks, publishes the multi-architecture container with SBOM and provenance, and creates a GitHub release containing native archives and `SHA256SUMS`. Prerelease tags such as `v0.2.0-rc.1` do not update stable container tags.

## Verify

1. Confirm all workflow jobs used the same tag, commit, version, and build date.
2. Compare the reported container digest with Docker Hub.
3. Download one native archive and verify it with `SHA256SUMS`.
4. Run `synthient-mcp --version` from the archive and a `/healthz` check against the released container.
5. Confirm stable releases updated `latest`; confirm prereleases did not.

If any publication step fails, keep the tag immutable, diagnose the failure, and publish a new patch or prerelease version rather than moving or overwriting the tag.
