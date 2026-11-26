#!/bin/sh
# Renders Jenkins Configuration as Code, then starts the stock Jenkins entrypoint.
# The pipeline script is read directly from the mounted Jenkinsfile at job creation
# time, so editing Jenkinsfile only needs a Jenkins restart to take effect.
set -eu

PIPELINE=/workspace/deploy/jenkins/Jenkinsfile

if [ ! -f "$PIPELINE" ]; then
  echo "Missing $PIPELINE - is the project mounted at /workspace?" >&2
  exit 1
fi

mkdir -p /var/jenkins_home

cat > /var/jenkins_home/casc.yaml <<'YAML'
jenkins:
  securityRealm:
    local:
      users:
        - id: "admin"
          password: "${JENKINS_ADMIN_PASSWORD}"
  authorizationStrategy:
    loggedInUsersCanDoAnything:
      allowAnonymousRead: false

jobs:
  - script: |
      pipelineJob("secureshare-deploy") {
        displayName("Deploy SecureShareFR (Docker)")
        description("Build, test, scan and deploy the full stack from the mounted source tree.")
        parameters {
          booleanParam('RUN_TESTS', true, 'Run npm ci, lint, tests, build before building images')
          booleanParam('RUN_AUDIT', true, 'Run npm audit for production dependencies')
          booleanParam('AUDIT_FAILS_BUILD', true, 'Fail the build on HIGH/CRITICAL advisories (otherwise mark UNSTABLE)')
          booleanParam('DEPLOY', true, 'Deploy the stack after the images are built and scanned (untick for CI-only runs)')
          booleanParam('RUN_SMOKE', true, 'Run the end-to-end smoke test after deployment')
          booleanParam('FAIL_ON_VULNS', false, 'Fail the build when Trivy reports HIGH/CRITICAL vulnerabilities')
          stringParam('DEPLOY_TAG', '', 'Optional image tag; leave blank for jenkins-$BUILD_NUMBER')
        }
        definition {
          cps {
            script(new File("/workspace/deploy/jenkins/Jenkinsfile").text)
            sandbox()
          }
        }
      }
YAML

echo "Wrote /var/jenkins_home/casc.yaml"
exec /usr/local/bin/jenkins.sh "$@"
