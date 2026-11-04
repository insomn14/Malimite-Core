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
//
// malimite_ci.py auto-detects BUILD_URL/GIT_COMMIT from Jenkins' own built-in env vars and tags
// the scan with them — no extra configuration needed for that part.

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
    }

    stages {
        stage('Malimite Security Scan') {
            steps {
                script {
                    if (!fileExists(params.APP_PATH)) {
                        error "error: ${params.APP_PATH} not found — build your app before this stage, or set APP_PATH"
                    }
                }
                withCredentials([string(credentialsId: env.MALIMITE_API_KEY_CRED_ID, variable: 'MALIMITE_API_KEY')]) {
                    sh '''
                        set -euo pipefail
                        curl -fsSL -o malimite_ci.py \
                            "https://raw.githubusercontent.com/insomn14/Malimite-Core/main/tools/malimite-ci/malimite_ci.py"
                        python3 malimite_ci.py \
                            --url "$MALIMITE_URL" \
                            --api-key "$MALIMITE_API_KEY" \
                            --file "$APP_PATH" \
                            --fail-on "$FAIL_ON" \
                            --json-out malimite-result.json
                    '''
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
