// Malimite Security Scan — Jenkins Declarative Pipeline template
//
// This file lives in Malimite-Core as a reference. Copy the 'Malimite Security Scan' stage (or
// the whole pipeline) into the MOBILE APP repository's own Jenkinsfile — this is NOT meant to
// run as-is against the Malimite-Core repo itself. Build your APK/IPA in an earlier stage, then
// run this stage against the resulting artifact.
//
// Uses tools/malimite-ci (a zero-dependency Python client, stdlib only) to upload the built
// app to a running malimite-web server, wait for the scan, and fail the build if a finding at
// or above $FAIL_ON is present. The server itself does the actual Ghidra/JADX analysis — see
// deploy/EC2_DEPLOYMENT.md in Malimite-Core for how to stand one up.
//
// Required Jenkins credentials/parameters:
//   - A "Secret text" credential holding the server's API_KEY, referenced below as
//     MALIMITE_API_KEY_CRED_ID (configure once in Manage Jenkins -> Credentials, then set the
//     credential ID into that env var, or hardcode it below).
//   - MALIMITE_URL: base URL of the malimite-web server (set below, or as a Jenkins global
//     environment variable so every job that includes this stage doesn't repeat it).
//   - (optional) A "Secret text" credential holding a Slack Incoming Webhook URL, referenced
//     below as MALIMITE_SLACK_WEBHOOK_CRED_ID. When FAIL_ON is set to NONE ("monitoring mode" —
//     the scan still runs and is reviewable in the web UI, but never fails the build), pair it
//     with this so the security team is still notified of every scan — see
//     tools/malimite-ci/README.md's "Monitoring mode" section. Leave the credential ID blank (or
//     remove the withCredentials block below) if you don't want Slack notifications at all.
//
// malimite_ci.py auto-detects BUILD_URL/GIT_COMMIT from Jenkins' own built-in env vars and tags
// the scan with them — no extra configuration needed for that part.
//
// TRIGGER STRATEGY: release-tags-only (chosen over scanning every commit/PR). A full scan can
// take minutes on a large IPA, and the server has a bounded concurrency budget
// (MAX_CONCURRENT_SCANS, default 3) — scanning every commit across several teams' repos would
// compete for those slots and slow down everyone's build feedback loop. The `when { tag "v*" }`
// below means this stage only runs when the build is for a tag matching v* (e.g. v1.2.0); plain
// branch/PR builds skip it entirely. This requires the job be a "Multibranch Pipeline" (or
// Pipeline-from-SCM with tag discovery enabled) so Jenkins populates env.TAG_NAME for tag
// builds — a plain "Pipeline" job never sets TAG_NAME and this stage would never run.

pipeline {
    agent any

    parameters {
        string(name: 'APP_PATH', defaultValue: 'app.apk',
               description: 'Path to the built .apk/.ipa/.xapk, relative to the workspace')
        choice(name: 'FAIL_ON', choices: ['HIGH', 'MEDIUM', 'LOW', 'NONE'],
               description: 'Fail the build if a finding at/above this severity is present')
    }

    environment {
        MALIMITE_URL = 'http://malimite.internal:7070'   // point at your deployed instance
        MALIMITE_API_KEY_CRED_ID = 'malimite-api-key'     // Jenkins credential ID, Secret text
        // Blank = no Slack notifications. Set to a real credential ID to enable them (required
        // if FAIL_ON is NONE and you still want the security team notified of every scan).
        MALIMITE_SLACK_WEBHOOK_CRED_ID = ''
    }

    stages {
        stage('Malimite Security Scan') {
            when {
                tag "v*"   // only runs for a build triggered by a tag matching v* — see note above
            }
            steps {
                script {
                    if (!fileExists(params.APP_PATH)) {
                        error "error: ${params.APP_PATH} not found — build your app before this stage, or set APP_PATH"
                    }
                }
                script {
                    // withCredentials errors if given a blank/nonexistent credential ID, so the
                    // Slack binding is conditional — the common case (no Slack configured) must
                    // not require a dummy credential to exist just to satisfy this block.
                    def creds = [string(credentialsId: env.MALIMITE_API_KEY_CRED_ID, variable: 'MALIMITE_API_KEY')]
                    if (env.MALIMITE_SLACK_WEBHOOK_CRED_ID) {
                        creds.add(string(credentialsId: env.MALIMITE_SLACK_WEBHOOK_CRED_ID, variable: 'MALIMITE_SLACK_WEBHOOK_URL'))
                    }
                    withCredentials(creds) {
                        sh '''
                            set -euo pipefail
                            curl -fsSL -o malimite_ci.py \
                                "https://raw.githubusercontent.com/insomn14/Malimite-Core/main/tools/malimite-ci/malimite_ci.py"
                            python3 malimite_ci.py \
                                --url "$MALIMITE_URL" \
                                --api-key "$MALIMITE_API_KEY" \
                                --file "$APP_PATH" \
                                --fail-on "$FAIL_ON" \
                                --slack-webhook-url "${MALIMITE_SLACK_WEBHOOK_URL:-}" \
                                --json-out malimite-result.json
                        '''
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'malimite-result.json', allowEmptyArchive: true
                }
            }
        }
    }
}
