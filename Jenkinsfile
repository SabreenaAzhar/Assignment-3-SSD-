pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Building the project...'
            }
        }

        stage('Test') {
            steps {
                echo 'Running tests...'
            }
        }

        stage('Deploy') {
            steps {
                echo 'Deployment step...'
            }
        }
    }
    post{
        always{
            echo'Post build condition running'
        }failure{
            echo'Post action if build failed"
        }
    }
}
