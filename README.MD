# Deploy log drainer serverless #

1. Configure aws-cli
2. Install serverless

    npm install -g serverless
    npm install
    
3. Install pyenv

    curl https://pyenv.run | bash
    pyenv install 3.7.3
    pyenv virtualenv 3.7.3 log-drainer-for-heroku-to-stackdriver
    pyenv activate log-drainer-for-heroku-to-stackdriver

4. Deploy

    serverless deploy

5. Add drain to your heroku app

    heroku drains:add https://<your-cloud-function-name>.cloudfunctions.net/stackdriver_handler -a your-app
